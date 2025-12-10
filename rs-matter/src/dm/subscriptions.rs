/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

use core::num::NonZeroU8;
use core::ops::Deref;

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_time::Instant;

use crate::Matter;
use crate::dm::IMBuffer;
use crate::dm::{ClusterId, EndptId};
use crate::error::Error;
use crate::fabric::MAX_FABRICS;
use crate::im::SubscribeReq;
use crate::tlv::TLVElement;
use crate::utils::cell::RefCell;
use crate::utils::init::IntoFallibleInit;
use crate::utils::init::{init, Init};
use crate::utils::storage::Vec;
use crate::utils::storage::pooled::BufferAccess;
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::Notification;

/// The maximum number of subscriptions that can be tracked at the same time by default.
///
/// According to the Matter spec, at least 3 subscriptions per fabric should be supported.
pub const DEFAULT_MAX_SUBSCRIPTIONS: usize = MAX_FABRICS * 3;

const MAX_CHANGED_CLUSTERS: usize = 4;

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub(crate) struct SubscriptionIds {
    pub(crate) fabric_idx: NonZeroU8,
    pub(crate) peer_node_id: u64,
    pub(crate) session_id: Option<u32>,
    pub(crate) id: u32,
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub(crate) struct SubscriptionReport<'a, B> {
    pub(crate) fabric_idx: NonZeroU8,
    pub(crate) peer_node_id: u64,
    pub(crate) session_id: Option<u32>,
    pub(crate) id: u32,
    pub(crate) changes: SubscriptionChanges,
    pub(crate) buffer: Option<&'a B>,
}

impl<'a, B> SubscriptionReport<'a, B> {
    pub(crate) fn new() -> Self {
        Self {
            fabric_idx: NonZeroU8::new(1).unwrap(),
            peer_node_id: 0,
            session_id: None,
            id: 0,
            changes: SubscriptionChanges::new(),
            buffer: None,
        }
    }

    // pub(crate) fn init() -> impl Init<Self> {
    //     init!(Self {
    //         fabric_idx: NonZeroU8::new(1).unwrap(),
    //         peer_node_id: 0,
    //         session_id: None,
    //         id: 0,
    //         changed_clusters <- Vec::init(),
    //         changed_all: false,
    //     })
    // }

    fn load(&mut self, sub: &Subscription<B>) {
        self.fabric_idx = sub.fabric_idx;
        self.peer_node_id = sub.peer_node_id;
        self.session_id = sub.session_id;
        self.id = sub.id;
        self.changes.load(sub.changes());
    }
}

/// The changes tracked for a subscription.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub(crate) struct SubscriptionChanges {
    /// The clusters that had changed for the subscription.
    ///
    /// If this is empty and `changed_all` is false, then no changes had occurred.
    /// If `changed_all` is true, then the content of this field is ignored.
    changed_clusters: Vec<(EndptId, ClusterId), MAX_CHANGED_CLUSTERS>,
    /// Whether all clusters are considered changed for the subscription.
    changed_all: bool,
}

impl SubscriptionChanges {
    /// Create the instance.
    pub fn new() -> Self {
        Self {
            changed_clusters: Vec::new(),
            changed_all: false,
        }
    }

    /// Return an in-place initializer for the instance.
    pub fn init() -> impl Init<Self> {
        init!(Self {
            changed_clusters <- Vec::init(),
            changed_all: false,
        })
    }

    /// Load the state from another instance.
    /// 
    /// # Arguments
    /// - `other`: The other instance to load the state from.
    pub fn load(&mut self, other: &Self) {
        self.changed_clusters.clear();
        self.changed_clusters
            .extend_from_slice(&other.changed_clusters)
            .unwrap();
        self.changed_all = other.changed_all;
    }

    /// Return `true` if the subscription to which this instance belongs has changes to report.
    pub fn changed(&self) -> bool {
        self.changed_all || !self.changed_clusters.is_empty()
    }

    /// Return `true` if the subscription to which this instance belongs can skip reporting for the given cluster
    /// because the cluster had not changed.
    pub fn skip(&self, endpoint: EndptId, cluster: ClusterId) -> bool {
        !self.changed_all && !self.changed_clusters.contains(&(endpoint, cluster))
    }

    /// Clear all tracked changes.
    fn clear(&mut self) {
        self.changed_clusters.clear();
        self.changed_all = false;
    }

    /// Notify the instance that the data of a specific cluster had changed.
    ///
    /// # Arguments
    /// - `endpoint_id`: The endpoint ID of the cluster that had changed.
    /// - `cluster_id`: The cluster ID of the cluster that had changed.
    /// - `rx`: The subscription buffer of the subscription to evaluate.
    fn notify_cluster_changed(&mut self, endpoint_id: EndptId, cluster_id: ClusterId, rx: &[u8]) {
        if !self.changed_all
            && !self.changed_clusters.contains(&(endpoint_id, cluster_id))
            && Self::contains_cluster(endpoint_id, cluster_id, rx).unwrap_or(false)
        {
            if self.changed_clusters.len() < self.changed_clusters.capacity() {
                unwrap!(self.changed_clusters.push((endpoint_id, cluster_id)));
            } else {
                // No space to track individual changed clusters anymore, mark the whole subscription as changed
                self.changed_all = true;
            }
        }
    }

    /// Check whether the subscription described by the given buffer contains the given cluster.
    /// 
    /// # Arguments
    /// - `endpoint_id`: The endpoint ID of the cluster to check.
    /// - `cluster_id`: The cluster ID of the cluster to check.
    /// - `rx`: The subscription buffer to check.
    fn contains_cluster(
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        rx: &[u8],
    ) -> Result<bool, Error> {
        let sub_req = SubscribeReq::new(TLVElement::new(rx));

        let requests = sub_req.attr_requests()?;
        if let Some(requests) = requests {
            for attr_req in requests {
                let attr_req = attr_req?;

                if attr_req.endpoint.map(|e| e == endpoint_id).unwrap_or(true)
                    && attr_req.cluster.map(|c| c == cluster_id).unwrap_or(true)
                {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}

/// A subscription tracked by the data model.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
struct Subscription<B> {
    /// The internal, unique ID of the subscription.
    ///
    /// Subscription IDs are unique per `Subscriptions` instance.
    id: u32,
    /// The fabric index of the subscription.
    fabric_idx: NonZeroU8,
    /// The peer node ID of the subscription.
    peer_node_id: u64,
    /// The session ID of the subscription.
    session_id: Option<u32>,
    /// The minimum reporting interval in seconds.
    // We use u16 instead of embassy::Duration to save some storage
    min_int_secs: u16,
    /// The maximum reporting interval in seconds.
    // Ditto
    max_int_secs: u16,
    /// The instant when the subscription was last reported.
    // TODO: Change to `Option<Instant>` to avoid using `Instant::MAX` as a sentinel value
    reported_at: Instant,
    /// The changes tracked for the subscription.
    changes: SubscriptionChanges,
    buffer: B,
}

impl<B> Subscription<B>
where 
    B: Deref<Target = [u8]>,
{
    fn init(
        id: u32,
        fabric_idx: NonZeroU8,
        peer_node_id: u64,
        session_id: u32,
        min_int_secs: u16,
        max_int_secs: u16,
        buffer: B,
    ) -> impl Init<Self> {
        init!(Subscription {
            id,
            fabric_idx,
            peer_node_id,
            session_id: Some(session_id),
            min_int_secs,
            max_int_secs,
            reported_at: Instant::MAX,
            changes <- SubscriptionChanges::init(),
            buffer,
        })
    }

    /// Get the changes tracked for the subscription.
    pub const fn changes(&self) -> &SubscriptionChanges {
        &self.changes
    }

    pub fn rx(&self) -> &[u8] {
        self.buffer.deref()
    }

    /// Check whether a report is due for the subscription at the given instant.
    pub fn report_due(&self, now: Instant) -> bool {
        // Either the data for the subscription had changed and therefore we need to report,
        // or the data for the subscription had not changed yet, however the report interval is due
        self.changes().changed() && self.expired_at(self.min_int_secs, now)
            || self.expired_at(self.min_int_secs.max(self.max_int_secs / 2), now)
    }

    /// Check whether the subscription is expired at the given instant.
    pub fn expired(&self, now: Instant) -> bool {
        self.expired_at(self.max_int_secs, now)
    }

    /// Check whether the subscription is expired at the given instant, using the given seconds as interval.
    fn expired_at(&self, secs: u16, now: Instant) -> bool {
        self.reported_at
            .checked_add(embassy_time::Duration::from_secs(secs as _))
            .map(|expiry| expiry <= now)
            .unwrap_or(false)
    }
}

/// The internal state of the `Subscriptions` type.
struct SubscriptionsInner<B, const N: usize> {
    /// The next subscription ID to use.
    /// 
    /// Subscription IDs are unique per `Subscriptions` instance.
    next_subscription_id: u32,
    /// The tracked subscriptions.
    subscriptions: Vec<Subscription<B>, N>,
}

impl<B, const N: usize> SubscriptionsInner<B, N> 
where 
    B: Deref<Target = [u8]>,
{
    /// Create the instance.
    #[inline(always)]
    const fn new() -> Self {
        Self {
            next_subscription_id: 1,
            subscriptions: Vec::new(),
        }
    }

    /// Return an in-place initializer for the instance.
    fn init() -> impl Init<Self> {
        init!(Self {
            next_subscription_id: 1,
            subscriptions <- crate::utils::storage::Vec::init(),
        })
    }

    /// Notify the instance that the data of a specific cluster had changed and that it should re-evaluate the subscriptions
    /// and report on those that are interested in the changed data.
    ///
    /// # Arguments
    /// - `endpoint_id`: The endpoint ID of the cluster that had changed.
    /// - `cluster_id`: The cluster ID of the cluster that had changed.
    /// - `subscriptions_buffers`: The subscription buffers of all active subscriptions.
    fn notify_cluster_changed(
        &mut self,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
    ) -> bool {
        let mut changed = false;

        for sub in self.subscriptions.iter_mut() {
            sub.changes
                .notify_cluster_changed(endpoint_id, cluster_id, sub.buffer.deref());

            changed |= sub.changes().changed();
        }

        changed
    }

    /// Add a new subscription.
    /// 
    /// # Arguments
    /// - `fabric_idx`: The fabric index of the subscription.
    /// - `peer_node_id`: The peer node ID of the subscription.
    /// - `session_id`: The session ID of the subscription.
    /// - `min_int_secs`: The minimum reporting interval in seconds.
    /// - `max_int_secs`: The maximum reporting interval in seconds.
    /// 
    /// # Returns
    /// - `Some(id)`: The ID of the newly added subscription.
    /// - `None`: The subscription could not be added because the maximum number of subscriptions has been reached.
    fn add(
        &mut self,
        subscription: Subscription<B>,
    ) -> Option<u32> {
        let id = self.next_subscription_id;
        self.next_subscription_id += 1;

        let id = self.subscriptions
            .push_init(
                init!(Subscription {
                    fabric_idx,
                    peer_node_id,
                    session_id: Some(session_id),
                    id,
                    min_int_secs,
                    max_int_secs,
                    reported_at: Instant::MAX,
                    changes <- SubscriptionChanges::init(),
                    buffer,
                })
                .into_fallible(),
                || (),
            )
            .map(|_| id)
            .map_err(|_| ())
            .ok()
    }

    /// Remove subscriptions matching the given criteria.
    /// 
    /// # Arguments
    /// - `fabric_idx`: The fabric index of the subscriptions to remove. If `None`, matches any fabric index.
    /// - `peer_node_id`: The peer node ID of the subscriptions to remove. If `None`, matches any peer node ID.
    /// - `id`: The ID of the subscriptions to remove. If `None`, matches any ID.
    fn remove(
        &mut self,
        fabric_idx: Option<NonZeroU8>,
        peer_node_id: Option<u64>,
        id: Option<u32>,
    ) {
        while let Some(index) = self.subscriptions.iter().position(|sub| {
            sub.fabric_idx == fabric_idx.unwrap_or(sub.fabric_idx)
                && sub.peer_node_id == peer_node_id.unwrap_or(sub.peer_node_id)
                && sub.id == id.unwrap_or(sub.id)
        }) {
            self.subscriptions.swap_remove(index);
        }
    }

    /// Mark the subscription with the given ID as reported.
    ///
    /// Will return `false` if the subscription with the given ID does no longer exist, as it might be
    /// removed by a concurrent transaction while being reported on.
    fn mark_reported(&mut self, id: u32) -> bool {
        if let Some(sub) = self.subscriptions.iter_mut().find(|sub| sub.id == id) {
            sub.reported_at = Instant::now();
            sub.changes.clear();

            true
        } else {
            false
        }
    }

    fn find_report_due<B>(
        &mut self, 
        now: Instant, 
        matter: &Matter<'_>,
        buffers: &mut heapless::Vec<B, N>,
        report: &mut SubscriptionReport<'_, B>) -> bool
    {

    }
    
    /// Find a subscription whose session ID has been removed.
    /// 
    /// # Arguments
    /// - `session_removed`: A closure that takes a session ID and returns `true` if the session has been removed.
    fn find_removed_session<F>(&self, session_removed: F, report: &mut SubscriptionReport<'_, B>) -> bool
    where
        F: Fn(u32) -> bool,
    {
        self.find(|sub| sub.session_id.map(&session_removed).unwrap_or(false), report)
    }

    /// Find a subscription that is expired at the given instant.
    /// 
    /// # Arguments
    /// - `now`: The instant to check for expiration.
    fn find_expired<B>(&self, now: Instant, report: &mut SubscriptionReport<'_, B>) -> bool {
        self.find(|sub| sub.expired(now), report)
    }

    /// Note that this method has a side effect:
    /// it updates the `reported_at` field of the subscription that is returned.
    fn find_report_due<B>(&self, now: Instant, report: &mut SubscriptionReport<'_, B>) -> bool {
        self.find(|sub| sub.report_due(now), report)
    }

    fn find<F, B>(&self, pred: F, report: &mut SubscriptionReport<'_, B>) -> bool
    where
        F: Fn(&Subscription) -> bool,
    {
        if let Some(sub) = self.subscriptions.iter().find(|sub|pred(sub)) {
            report.load(sub);

            true
        } else {
            false
        }
    }
}

/// A utility for tracking subscriptions accepted by the data model.
///
/// The `N` type parameter specifies the maximum number of subscriptions that can be tracked at the same time.
/// Additional subscriptions are rejected by the data model with a "resource exhausted" IM status message.
pub struct Subscriptions<const N: usize = DEFAULT_MAX_SUBSCRIPTIONS, M = NoopRawMutex>
where
    M: RawMutex,
{
    state: Mutex<M, RefCell<SubscriptionsInner<N>>>,
    pub(crate) notification: Notification<M>,
}

impl<const N: usize, M> Subscriptions<N, M>
where
    M: RawMutex,
{
    /// Create the instance.
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(RefCell::new(SubscriptionsInner::new())),
            notification: Notification::new(),
        }
    }

    /// Create an in-place initializer for the instance.
    pub fn init() -> impl Init<Self> {
        init!(Self {
            state <- Mutex::init(RefCell::init(SubscriptionsInner::init())),
            notification: Notification::new(),
        })
    }

    /// Notify the instance that the data of a specific cluster had changed and that it should re-evaluate the subscriptions
    /// and report on those that are interested in the changed data.
    ///
    /// This method is supposed to be called by the application code whenever it changes the data of a cluster.
    ///
    /// # Arguments
    /// - `endpoint_id`: The endpoint ID of the cluster that had changed.
    /// - `cluster_id`: The cluster ID of the cluster that had changed.
    /// - `subscriptions_buffers`: The subscription buffers of all active subscriptions.
    pub(crate) fn notify_cluster_changed<'a>(
        &self,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        subscriptions_rx: impl Iterator<Item = &'a [u8]>,
    ) {
        let changed = self.state.lock(|internal| {
            internal
                .borrow_mut()
                .notify_cluster_changed(endpoint_id, cluster_id, subscriptions_rx)
        });

        if changed {
            self.notification.notify();
        }
    }

    pub(crate) fn add<B>(
        &self,
        buffers: &mut heapless::Vec<B, N>,
        fabric_idx: NonZeroU8,
        peer_node_id: u64,
        session_id: u32,
        min_int_secs: u16,
        max_int_secs: u16,
        rx: B,
    ) -> Option<u32> {
        self.state.lock(|internal| {
            internal.borrow_mut().add(
                buffers,
                fabric_idx,
                peer_node_id,
                session_id,
                min_int_secs,
                max_int_secs,
                rx,
            )
        })
    }

    pub(crate) fn remove<B>(
        &self,
        buffers: &mut heapless::Vec<B, N>,
        fabric_idx: Option<NonZeroU8>,
        peer_node_id: Option<u64>,
        id: Option<u32>,
    ) {
        self.state
            .lock(|internal| internal.borrow_mut().remove(buffers, fabric_idx, peer_node_id, id))
    }

    pub(crate) fn process<B, F, R>(&self, buffers: &mut heapless::Vec<B, N>, mut f: F) -> Option<R>
    where
        F: FnMut(&mut Subscription, &mut B) -> Option<R>,
    {
        self.state
            .lock(|internal| {
                let mut internal = internal.borrow_mut();
                for (sub, buffer) in internal.iter(buffers) {
                    if let Some(result) = f(sub, buffer) {
                        return Some(result);
                    }
                }

                None
            })
    }

    /// Mark the subscription with the given ID as reported.
    ///
    /// Will return `false` if the subscription with the given ID does no longer exist, as it might be
    /// removed by a concurrent transaction while being reported on.
    pub(crate) fn mark_reported(&self, id: u32) -> bool {
        self.state
            .lock(|internal| internal.borrow_mut().mark_reported(id))
    }

    pub(crate) fn find_expired(&self, now: Instant, report: &mut SubscriptionReport) -> bool {
        self.state
            .lock(|internal| internal.borrow().find_expired(now, report))
    }

    /// Note that this method has a side effect:
    /// it updates the `reported_at` field of the subscription that is returned.
    pub(crate) fn find_report_due(&self, now: Instant, report: &mut SubscriptionReport) -> bool {
        self.state
            .lock(|internal| internal.borrow().find_report_due(now, report))
    }
}

impl<const N: usize, M> Default for Subscriptions<N, M>
where
    M: RawMutex,
{
    fn default() -> Self {
        Self::new()
    }
}
