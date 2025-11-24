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

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_time::Instant;

use crate::dm::IMBuffer;
use crate::dm::SubscriptionBuffer;
use crate::dm::{ClusterId, EndptId};
use crate::error::Error;
use crate::fabric::MAX_FABRICS;
use crate::im::SubscribeReq;
use crate::tlv::TLVElement;
use crate::utils::cell::RefCell;
use crate::utils::init::IntoFallibleInit;
use crate::utils::init::{init, Init};
use crate::utils::storage::pooled::BufferAccess;
use crate::utils::storage::Vec;
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::Notification;

/// The maximum number of subscriptions that can be tracked at the same time by default.
///
/// According to the Matter spec, at least 3 subscriptions per fabric should be supported.
pub const DEFAULT_MAX_SUBSCRIPTIONS: usize = MAX_FABRICS * 3;

/// A type alias for `Subscriptions` with the default maximum number of subscriptions.
pub type DefaultSubscriptions = Subscriptions<DEFAULT_MAX_SUBSCRIPTIONS>;

pub(crate) struct SubscriptionReport {
    pub(crate) fabric_idx: NonZeroU8,
    pub(crate) peer_node_id: u64,
    pub(crate) session_id: Option<u32>,
    pub(crate) id: u32,
    pub(crate) changed_clusters: Vec<(EndptId, ClusterId), 4>,
    pub(crate) changed_all: bool,
}

impl SubscriptionReport {
    pub(crate) fn new() -> Self {
        Self {
            fabric_idx: NonZeroU8::new(1).unwrap(),
            peer_node_id: 0,
            session_id: None,
            id: 0,
            changed_clusters: Vec::new(),
            changed_all: false,
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

    pub(crate) fn skip(&self, endpoint: EndptId, cluster: ClusterId) -> bool {
        !self.changed_all && !self.changed_clusters.contains(&(endpoint, cluster))
    }
}

struct Subscription {
    fabric_idx: NonZeroU8,
    peer_node_id: u64,
    session_id: Option<u32>,
    id: u32,
    // We use u16 instead of embassy::Duration to save some storage
    min_int_secs: u16,
    // Ditto
    max_int_secs: u16,
    // TODO: Change to `Option<Instant>` to avoid using `Instant::MAX` as a sentinel value
    reported_at: Instant,
    changed_clusters: Vec<(EndptId, ClusterId), 4>,
    changed_all: bool,
}

impl Subscription {
    pub fn changed(&self) -> bool {
        self.changed_all || !self.changed_clusters.is_empty()
    }

    pub fn report_due(&self, now: Instant) -> bool {
        // Either the data for the subscription had changed and therefore we need to report,
        // or the data for the subscription had not changed yet, however the report interval is due
        self.changed() && self.expired(self.min_int_secs, now)
            || self.expired(self.min_int_secs.max(self.max_int_secs / 2), now)
    }

    pub fn is_expired(&self, now: Instant) -> bool {
        self.expired(self.max_int_secs, now)
    }

    fn expired(&self, secs: u16, now: Instant) -> bool {
        self.reported_at
            .checked_add(embassy_time::Duration::from_secs(secs as _))
            .map(|expiry| expiry <= now)
            .unwrap_or(false)
    }
}

struct SubscriptionsInner<const N: usize> {
    next_subscription_id: u32,
    subscriptions: Vec<Subscription, N>,
}

impl<const N: usize> SubscriptionsInner<N> {
    /// Create the instance.
    #[inline(always)]
    const fn new() -> Self {
        Self {
            next_subscription_id: 1,
            subscriptions: Vec::new(),
        }
    }

    /// Create an in-place initializer for the instance.
    fn init() -> impl Init<Self> {
        init!(Self {
            next_subscription_id: 1,
            subscriptions <- crate::utils::storage::Vec::init(),
        })
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
    pub(crate) fn notify_cluster_changed<B>(
        &self,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        subscriptions_buffers: &[SubscriptionBuffer<B::Buffer<'_>>],
    ) where
        B: BufferAccess<IMBuffer>,
    {
        self.state.lock(|internal| {
            let subscriptions = &mut internal.borrow_mut().subscriptions;
            for (sub, buffer) in subscriptions.iter_mut().zip(subscriptions_buffers.iter()) {
                if !sub.changed_all
                    && !sub.changed_clusters.contains(&(endpoint_id, cluster_id))
                    && Self::contains_cluster::<B>(buffer, endpoint_id, cluster_id).unwrap_or(false)
                {
                    if sub.changed_clusters.len() < sub.changed_clusters.capacity() {
                        sub.changed_clusters
                            .push((endpoint_id, cluster_id))
                            .unwrap();
                    } else {
                        // No space to track individual changed clusters anymore, mark the whole subscription as changed
                        sub.changed_all = true;
                    }
                }
            }
        });

        self.notification.notify();
    }

    fn contains_cluster<B>(
        subscription_buffer: &SubscriptionBuffer<B::Buffer<'_>>,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
    ) -> Result<bool, Error>
    where
        B: BufferAccess<IMBuffer>,
    {
        let sub_req = SubscribeReq::new(TLVElement::new(&subscription_buffer.buffer));

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

    pub(crate) fn add(
        &self,
        fabric_idx: NonZeroU8,
        peer_node_id: u64,
        session_id: u32,
        min_int_secs: u16,
        max_int_secs: u16,
    ) -> Option<u32> {
        self.state.lock(|internal| {
            let mut state = internal.borrow_mut();
            let id = state.next_subscription_id;
            state.next_subscription_id += 1;

            state
                .subscriptions
                .push_init(
                    init!(Subscription {
                        fabric_idx,
                        peer_node_id,
                        session_id: Some(session_id),
                        id,
                        min_int_secs,
                        max_int_secs,
                        reported_at: Instant::MAX,
                        changed_clusters <- Vec::init(),
                        changed_all: false,
                    })
                    .into_fallible(),
                    || (),
                )
                .map(|_| id)
                .map_err(|_| ())
                .ok()
        })
    }

    /// Mark the subscription with the given ID as reported.
    ///
    /// Will return `false` if the subscription with the given ID does no longer exist, as it might be
    /// removed by a concurrent transaction while being reported on.
    pub(crate) fn mark_reported(&self, id: u32) -> bool {
        self.state.lock(|internal| {
            let subscriptions = &mut internal.borrow_mut().subscriptions;

            if let Some(sub) = subscriptions.iter_mut().find(|sub| sub.id == id) {
                sub.reported_at = Instant::now();
                sub.changed_clusters.clear();
                sub.changed_all = false;

                true
            } else {
                false
            }
        })
    }

    pub(crate) fn remove(
        &self,
        fabric_idx: Option<NonZeroU8>,
        peer_node_id: Option<u64>,
        id: Option<u32>,
    ) {
        self.state.lock(|internal| {
            let subscriptions = &mut internal.borrow_mut().subscriptions;
            while let Some(index) = subscriptions.iter().position(|sub| {
                sub.fabric_idx == fabric_idx.unwrap_or(sub.fabric_idx)
                    && sub.peer_node_id == peer_node_id.unwrap_or(sub.peer_node_id)
                    && sub.id == id.unwrap_or(sub.id)
            }) {
                subscriptions.swap_remove(index);
            }
        })
    }

    pub(crate) fn find_removed_session<F>(
        &self,
        session_removed: F,
    ) -> Option<(NonZeroU8, u64, u32, u32)>
    where
        F: Fn(u32) -> bool,
    {
        self.state.lock(|internal| {
            internal.borrow_mut().subscriptions.iter().find_map(|sub| {
                sub.session_id
                    .map(&session_removed)
                    .unwrap_or(false)
                    .then_some((
                        sub.fabric_idx,
                        sub.peer_node_id,
                        unwrap!(sub.session_id),
                        sub.id,
                    ))
            })
        })
    }

    pub(crate) fn find_expired(&self, now: Instant) -> Option<(NonZeroU8, u64, Option<u32>, u32)> {
        self.state.lock(|internal| {
            internal.borrow_mut().subscriptions.iter().find_map(|sub| {
                sub.is_expired(now).then_some((
                    sub.fabric_idx,
                    sub.peer_node_id,
                    sub.session_id,
                    sub.id,
                ))
            })
        })
    }

    /// Note that this method has a side effect:
    /// it updates the `reported_at` field of the subscription that is returned.
    pub(crate) fn find_report_due(&self, now: Instant, report: &mut SubscriptionReport) -> bool {
        self.state.lock(|internal| {
            let mut internal = internal.borrow_mut();

            for sub in &mut internal.subscriptions {
                if sub.report_due(now) {
                    sub.reported_at = now;

                    report.fabric_idx = sub.fabric_idx;
                    report.peer_node_id = sub.peer_node_id;
                    report.session_id = sub.session_id;
                    report.id = sub.id;
                    report.changed_clusters.clear();
                    report
                        .changed_clusters
                        .extend_from_slice(&sub.changed_clusters)
                        .unwrap();
                    report.changed_all = sub.changed_all;

                    sub.changed_clusters.clear();
                    sub.changed_all = false;

                    return true;
                }
            }

            false
        })
    }
}

impl<const N: usize> Default for Subscriptions<N> {
    fn default() -> Self {
        Self::new()
    }
}
