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

use embassy_time::Instant;

use crate::dm::{AttrChangeNotifier, AttrId, ClusterId, EndptId, EventId};
use crate::fabric::MAX_FABRICS;
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init};
use crate::utils::storage::Vec;
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::{DynBase, Notification};

/// The maximum number of subscriptions that can be tracked at the same time by default.
///
/// According to the Matter spec, at least 3 subscriptions per fabric should be supported.
pub const DEFAULT_MAX_SUBSCRIPTIONS: usize = MAX_FABRICS * 3;

/// The maximum number of changed-attribute entries tracked simultaneously.
///
/// When the table is full, entries are coalesced ("promoted") to coarser-grained
/// wildcards so that new changes can always be recorded.
pub const MAX_CHANGED_ATTRS: usize = 16;

/// A record of one recently changed attribute.
///
/// A `None` field acts as a wildcard. Wildcards appear only as a result of
/// "promotion" when the `changed_attrs` table becomes full and several
/// concrete entries need to be coalesced into a coarser one.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct ChangedAttr {
    endpoint: Option<EndptId>,
    cluster: Option<ClusterId>,
    attr: Option<AttrId>,
    change_id: u64,
}

impl ChangedAttr {
    const fn concrete(endpoint: EndptId, cluster: ClusterId, attr: AttrId, change_id: u64) -> Self {
        Self {
            endpoint: Some(endpoint),
            cluster: Some(cluster),
            attr: Some(attr),
            change_id,
        }
    }

    /// Whether this record covers the concrete attribute triple
    /// `(endpoint, cluster, attr)`.
    fn matches(&self, endpoint: EndptId, cluster: ClusterId, attr: AttrId) -> bool {
        self.endpoint.map(|x| x == endpoint).unwrap_or(true)
            && self.cluster.map(|x| x == cluster).unwrap_or(true)
            && self.attr.map(|x| x == attr).unwrap_or(true)
    }

    /// Whether `other` is semantically covered by `self` (i.e. `self` is as
    /// coarse as or coarser than `other` on every axis).
    fn covers(&self, other: &ChangedAttr) -> bool {
        fn cov<T: Eq>(a: Option<T>, b: Option<T>) -> bool {
            match (a, b) {
                (None, _) => true,        // self wildcard covers anything
                (Some(_), None) => false, // concrete doesn't cover wildcard
                (Some(a), Some(b)) => a == b,
            }
        }
        cov(self.endpoint, other.endpoint)
            && cov(self.cluster, other.cluster)
            && cov(self.attr, other.attr)
    }

    /// Build the coarsened wildcard entry representing `pivot`'s group at the
    /// given level. Returns `None` if `pivot` cannot be promoted at that level
    /// (e.g. its endpoint is already a wildcard for level 1 or 2).
    fn coarsen(&self, level: u8) -> Option<Self> {
        let (endpoint, cluster) = match level {
            1 => (self.endpoint?, self.cluster?),
            2 => {
                return Some(Self {
                    endpoint: Some(self.endpoint?),
                    cluster: None,
                    attr: None,
                    change_id: 0,
                })
            }
            _ => unreachable!(),
        };

        Some(Self {
            endpoint: Some(endpoint),
            cluster: Some(cluster),
            attr: None,
            change_id: 0,
        })
    }
}

/// A table of recently-changed attribute triples, each tagged with an
/// ever-increasing `change_id`.
///
/// Subscriptions consult this table to decide which attributes they should
/// re-emit on their next report: only attributes with a matching entry whose
/// `change_id` is strictly greater than the subscription's own watermark
/// (`last_change_id`) need to be reported.
///
/// The table has a fixed capacity of [`MAX_CHANGED_ATTRS`] entries. When it
/// fills up, existing entries are coalesced to coarser-grained wildcards
/// (`(endpoint, cluster, *)` → `(endpoint, *, *)` → `(*, *, *)`) so that a new change can always
/// be recorded. A wildcard entry over-covers and will therefore cause the
/// affected subscriptions to emit a slightly wider set of attributes on their
/// next report, but this is a bounded loss of precision that preserves
/// correctness.
pub(crate) struct ChangedAttributes {
    /// Monotonically increasing ID assigned to every recorded change.
    /// The first assigned ID is 1; `0` is reserved as the "no change seen yet"
    /// sentinel used by fresh subscriptions.
    next_change_id: u64,
    /// The actual table of recent changes, ordered from oldest to newest.
    /// The newest change has `change_id == next_change_id - 1`.
    entries: Vec<ChangedAttr, MAX_CHANGED_ATTRS>,
}

impl ChangedAttributes {
    /// Create the instance.
    #[inline(always)]
    const fn new() -> Self {
        Self {
            next_change_id: 1,
            entries: Vec::new(),
        }
    }

    /// Return an in-place initializer for the instance.
    fn init() -> impl Init<Self> {
        init!(Self {
            next_change_id: 1,
            entries <- Vec::init(),
        })
    }

    /// The largest change ID that has been assigned so far. A subscription
    /// whose max seen change ID is equal to the watermark has seen every change.
    #[inline]
    fn watermark(&self) -> u64 {
        self.next_change_id.wrapping_sub(1)
    }

    /// Record a change to the attribute triple `(endpoint, cluster, attr)`.
    /// Returns the newly assigned change ID.
    fn record(&mut self, endpoint: EndptId, cluster: ClusterId, attr: AttrId) -> u64 {
        let change_id = self.next_change_id;
        self.next_change_id = self.next_change_id.wrapping_add(1).max(1);

        // If an existing entry already covers (endpoint, cluster, attr) we just
        // refresh its change ID.
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|x| x.matches(endpoint, cluster, attr))
        {
            existing.change_id = change_id;
            return change_id;
        }

        let new = ChangedAttr::concrete(endpoint, cluster, attr, change_id);

        if let Err(new) = self.entries.push(new) {
            // The table is full - promote entries to coarser wildcards to free a slot.
            self.promote_and_insert(new);
        }

        change_id
    }

    /// Returns `true` if the table contains at least one entry covering
    /// `(endpoint, cluster, attr)` with `change_id > since`.
    fn contains_since(
        &self,
        endpoint: EndptId,
        cluster: ClusterId,
        attr: AttrId,
        since: u64,
    ) -> bool {
        self.entries
            .iter()
            .any(|x| x.change_id > since && x.matches(endpoint, cluster, attr))
    }

    /// Returns `true` if the table contains at least one entry with
    /// `change_id > since` (of any path).
    fn any_since(&self, since: u64) -> bool {
        self.entries.iter().any(|x| x.change_id > since)
    }

    /// Drop all entries with `change_id <= threshold`.
    fn purge_up_to(&mut self, threshold: u64) {
        if threshold == 0 {
            return;
        }

        let mut i = 0;
        while i < self.entries.len() {
            if self.entries[i].change_id <= threshold {
                self.entries.swap_remove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Drop every recorded change. Used when no subscriptions exist.
    fn clear(&mut self) {
        self.entries.clear();
    }

    /// Coalesce existing entries to coarser wildcards so that `new` can be inserted.
    ///
    /// The strategy is to promote as little as possible: on each iteration we
    /// collapse the single largest collapsible group at the finest available
    /// level into one coarser wildcard entry, freeing at least one slot. Only
    /// once no fine-grained group of two or more entries exists do we escalate
    /// to the next level, and finally to a global wildcard as a last resort.
    fn promote_and_insert(&mut self, new: ChangedAttr) {
        loop {
            // If an existing (possibly just-promoted) entry already covers `new`,
            // refresh its change ID and we're done.
            if let Some(existing) = self.entries.iter_mut().find(|x| x.covers(&new)) {
                existing.change_id = new.change_id;
                return;
            }

            if self.entries.push(new.clone()).is_ok() {
                return;
            }

            // Full - promote exactly one group at the finest granularity that
            // actually yields compaction. Levels:
            // - 1: (endpoint, cluster, *)
            // - 2: (endpoint, *, *)
            if !self.promote_largest_group(1) && !self.promote_largest_group(2) {
                // No collapsible group at either level - last-ditch fallback:
                // collapse the whole table into a single global wildcard entry.
                self.entries.clear();

                unwrap!(self.entries.push(ChangedAttr {
                    endpoint: None,
                    cluster: None,
                    attr: None,
                    change_id: new.change_id,
                }));

                return;
            }
        }
    }

    /// Find the largest group of entries (>= 2) that share the same key at the
    /// given promotion level, and collapse it into one coarser wildcard entry.
    ///
    /// Returns `true` if any promotion happened.
    fn promote_largest_group(&mut self, level: u8) -> bool {
        // Pick a pivot whose group is largest.
        let mut best_pivot: Option<ChangedAttr> = None;
        let mut best_count = 1usize;

        for i in 0..self.entries.len() {
            let pivot = &self.entries[i];
            let Some(coarsened) = pivot.coarsen(level) else {
                continue;
            };

            let count = self.entries.iter().filter(|e| coarsened.covers(e)).count();
            if count > best_count {
                best_count = count;
                best_pivot = Some(pivot.clone());
            }
        }

        let Some(pivot) = best_pivot else {
            return false;
        };
        // `coarsen` already returned `Some` above for this pivot.
        let mut coarsened = pivot.coarsen(level).unwrap();

        // Remove all entries covered by `coarsened`, keeping the largest
        // change_id to preserve recency.
        let mut max_change_id = 0u64;
        let mut i = 0;
        while i < self.entries.len() {
            if coarsened.covers(&self.entries[i]) {
                if self.entries[i].change_id > max_change_id {
                    max_change_id = self.entries[i].change_id;
                }
                self.entries.swap_remove(i);
            } else {
                i += 1;
            }
        }
        coarsened.change_id = max_change_id;
        // Safe: we just removed `best_count >= 2` entries, so there is room.
        unwrap!(self.entries.push(coarsened));
        true
    }
}

struct Subscription {
    /// The ID of the subscription. Uniquely identifies the subscription across all of them.
    id: u32,
    /// The fabric index of the subscriber. Used to route reports and to remove all subscriptions of a fabric when it gets removed.
    fabric_idx: NonZeroU8,
    /// The node ID of the subscriber. Used to route reports and to remove all subscriptions of a peer when it gets removed.
    peer_node_id: u64,
    /// The session ID of the subscriber, if known. Used to route reports and to remove subscriptions with a removed session. May be `None` for subscriptions created before the session is fully established; such subscriptions are only removed when the whole peer or fabric gets removed.
    session_id: Option<u32>,
    /// The minimum interval in seconds. The subscription should not receive reports more frequently than this interval, but may receive them less frequently.
    /// We use u16 instead of embassy::Duration to save some storage
    min_int_secs: u16,
    /// The maximum interval in seconds. The subscription should receive reports at least this frequently, even if there are no changes to report (i.e. it is a liveness deadline).
    /// We use u16 instead of embassy::Duration to save some storage
    max_int_secs: u16,
    /// The timestamp of the last report sent to this subscription. Used to decide when the next report is due based on the min/max intervals.
    /// Set to `Instant::MAX` when the subscription is created to indicate that no report has been sent yet, so the first report is due immediately. After the first report, it is updated to the actual timestamp of the last report.
    reported_at: Instant,
    /// The largest attribute change ID from the [`ChangedAttributes`] table this subscription
    /// has already reported on. Entries with a larger change ID represent pending changes the subscription still needs to emit.
    max_seen_attr_change_id: u64,
    /// The largest event number this subscription has already reported on. Events with a larger event number represent pending events the subscription still needs to emit.
    max_seen_event_number: u64,
}

impl Subscription {
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
    changed_attrs: ChangedAttributes,
}

impl<const N: usize> SubscriptionsInner<N> {
    /// Create the instance.
    #[inline(always)]
    const fn new() -> Self {
        Self {
            next_subscription_id: 1,
            subscriptions: Vec::new(),
            changed_attrs: ChangedAttributes::new(),
        }
    }

    /// Create an in-place initializer for the instance.
    fn init() -> impl Init<Self> {
        init!(Self {
            next_subscription_id: 1,
            subscriptions <- Vec::init(),
            changed_attrs <- ChangedAttributes::init(),
        })
    }

    /// Remove entries that every subscription has already reported on.
    fn purge_reported_changes(&mut self) {
        match self
            .subscriptions
            .iter()
            .map(|s| s.max_seen_attr_change_id)
            .min()
        {
            None => self.changed_attrs.clear(),
            Some(min) => self.changed_attrs.purge_up_to(min),
        }
    }
}

/// Per-subscription context for an in-progress report.
///
/// Small, `Copy` scalar struct produced by [`Subscriptions::begin_report`]:
/// it captures the `since` watermark (the subscription's `last_change_id` at
/// the moment reporting began) and the `watermark` to be committed via
/// [`Subscriptions::mark_reported`] on success, plus a couple of flags used
/// to decide whether filtering and/or the whole report can be skipped.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct ReportContext {
    /// The subscription's `last_change_id` at the moment this report began.
    /// Only changes with `change_id > since` need to be reported.
    since: u64,
    /// The watermark to persist as `last_change_id` after a successful report.
    /// Set to the largest assigned `change_id` observed when the report began;
    /// any change that arrives during reporting gets a strictly larger
    /// `change_id` and is therefore deferred to the next report cycle.
    watermark: u64,
    /// The subscription's current `min_event_number` at the moment this
    /// report began. The responder uses it as the initial value of its
    /// `EventReader` watermark; the final value is persisted back via
    /// [`Subscriptions::mark_reported`].
    min_event_number: u64,
    /// `true` if this is the initial priming report (subscribe / read);
    /// priming reports emit everything unconditionally.
    priming: bool,
    /// `true` if at least one changed-attrs entry satisfies `change_id > since`
    /// at the moment reporting began. Used as a coarse "is there anything to
    /// report?" short-circuit.
    any_pending: bool,
}

impl ReportContext {
    /// The watermark to persist as `last_change_id` after a successful report.
    #[inline]
    pub(crate) const fn watermark(&self) -> u64 {
        self.watermark
    }

    /// The `since` watermark: only changes with `change_id > since` are new
    /// for this report.
    #[inline]
    pub(crate) const fn since(&self) -> u64 {
        self.since
    }

    /// The subscription's `min_event_number` as captured when this report began.
    #[inline]
    pub(crate) const fn min_event_number(&self) -> u64 {
        self.min_event_number
    }

    /// Whether per-attribute filtering should be applied to this report.
    #[inline]
    pub(crate) const fn filter_active(&self) -> bool {
        !self.priming
    }

    /// Whether there might be pending attribute changes for this report.
    ///
    /// A priming report always has "work to do" from the responder's point of
    /// view (it must emit everything). For incremental reports this reflects
    /// the state of the changed-attrs table at the time the report began.
    #[inline]
    pub(crate) const fn any_pending(&self) -> bool {
        self.priming || self.any_pending
    }
}

/// A filter consulted by the IM reporting code to decide whether an expanded
/// attribute triple should be emitted as part of a subscription update.
pub trait AttrChangeFilter {
    /// Returns `true` if `(endpoint_id, cluster_id, attr_id)` should be
    /// emitted in this report.
    fn includes(&self, endpoint_id: EndptId, cluster_id: ClusterId, attr_id: AttrId) -> bool;
}

impl<T: AttrChangeFilter + ?Sized> AttrChangeFilter for &T {
    fn includes(&self, endpoint: EndptId, cluster: ClusterId, attr: AttrId) -> bool {
        (**self).includes(endpoint, cluster, attr)
    }
}

/// A filter that defers to a [`Subscriptions`] instance and a subscription-
/// specific `since` watermark. Per-attribute decisions re-acquire the
/// subscriptions mutex briefly; no copy of the changed-attrs table is made.
///
/// Note that between successive [`AttrChangeFilter::includes`] calls the
/// underlying changed-attrs table may grow (the responder is async and does
/// not hold the mutex across awaits). This can cause mild over-reporting
/// (an attribute changed _during_ the report may be emitted in this report
/// instead of the next one), but never loss.
pub(crate) struct SubAttrChangeFilter<'a, const N: usize> {
    subscriptions: &'a Subscriptions<N>,
    since: u64,
}

impl<'a, const N: usize> SubAttrChangeFilter<'a, N> {
    #[inline]
    pub(crate) const fn new(subscriptions: &'a Subscriptions<N>, since: u64) -> Self {
        Self {
            subscriptions,
            since,
        }
    }
}

impl<const N: usize> AttrChangeFilter for SubAttrChangeFilter<'_, N> {
    fn includes(&self, endpoint: EndptId, cluster: ClusterId, attr: AttrId) -> bool {
        self.subscriptions.state.lock(|s| {
            s.borrow()
                .changed_attrs
                .contains_since(endpoint, cluster, attr, self.since)
        })
    }
}

/// A utility for tracking subscriptions accepted by the data model.
///
/// The `N` type parameter specifies the maximum number of subscriptions that can be tracked at the same time.
/// Additional subscriptions are rejected by the data model with a "resource exhausted" IM status message.
pub struct Subscriptions<const N: usize = DEFAULT_MAX_SUBSCRIPTIONS> {
    state: Mutex<RefCell<SubscriptionsInner<N>>>,
    pub(crate) notification: Notification,
}

impl<const N: usize> Subscriptions<N> {
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

    /// Notify the instance that the data of a specific attribute has changed and that it should re-evaluate the subscriptions
    /// and report on those that are interested in the changed data.
    ///
    /// This method is supposed to be called by the application code whenever it changes the data of an attribute.
    ///
    /// # Arguments
    /// - `endpoint_id`: The endpoint ID of the cluster that had changed.
    /// - `cluster_id`: The cluster ID of the cluster that had changed.
    /// - `attr_id`: The attribute ID of the attribute that changed.
    pub fn notify_attribute_changed(
        &self,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        attr_id: AttrId,
    ) {
        self.state.lock(|internal| {
            internal
                .borrow_mut()
                .changed_attrs
                .record(endpoint_id, cluster_id, attr_id);
        });

        // The per-subscription decision of whether anything needs to be reported is
        // computed on-the-fly by `find_report_due` (and by the responder's filter)
        // by consulting the live `changed_attrs` table, so there is no per-sub flag
        // to flip here. We just wake the reporter task.
        self.notification.notify();
    }

    pub fn notify_event_emitted(
        &self,
        _endpoint_id: EndptId,
        _cluster_id: ClusterId,
        _event_id: EventId,
    ) {
        // Events are filtered at report time by `min_event_number` + event path matching.
        // Whether a subscription is due to report because of new events is recomputed on
        // the fly in `find_report_due`, so here we only need to kick the reporter task.
        self.notification.notify();
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

            // Start with the current watermark so that only changes happening AFTER the
            // subscription was accepted will be reported as incremental updates.
            let last_change_id = state.changed_attrs.watermark();

            state
                .subscriptions
                .push(Subscription {
                    fabric_idx,
                    peer_node_id,
                    session_id: Some(session_id),
                    id,
                    min_int_secs,
                    max_int_secs,
                    reported_at: Instant::MAX,
                    max_seen_attr_change_id: last_change_id,
                    max_seen_event_number: 0,
                })
                .map(|_| id)
                .ok()
        })
    }

    /// Begin a report for the subscription with the given ID.
    ///
    /// Returns a small [`ReportContext`] capturing the subscription's current
    /// `since` watermark and the watermark to commit via [`Self::mark_reported`]
    /// on success. Unlike a snapshot, the `changed_attrs` table itself is not
    /// copied; the report uses a [`SubAttrChangeFilter`] that consults the
    /// live table one attribute at a time.
    ///
    /// `priming = true` produces a context with filtering disabled; it is
    /// used for the initial ("priming") report delivered right after a
    /// subscription is accepted.
    pub(crate) fn begin_report(&self, id: u32, priming: bool) -> Option<ReportContext> {
        self.state.lock(|internal| {
            let state = internal.borrow();
            let sub = state.subscriptions.iter().find(|s| s.id == id)?;

            Some(ReportContext {
                since: sub.max_seen_attr_change_id,
                watermark: state.changed_attrs.watermark(),
                min_event_number: sub.max_seen_event_number,
                priming,
                any_pending: !priming && state.changed_attrs.any_since(sub.max_seen_attr_change_id),
            })
        })
    }

    /// Mark the subscription with the given ID as reported.
    ///
    /// Persists the change-id `watermark` and the current `min_event_number`
    /// on the subscription. Will return `false` if the subscription with the
    /// given ID does no longer exist, as it might be removed by a concurrent
    /// transaction while being reported on.
    pub(crate) fn mark_reported(&self, id: u32, watermark: u64, min_event_number: u64) -> bool {
        self.state.lock(|internal| {
            let subscriptions = &mut internal.borrow_mut().subscriptions;

            if let Some(sub) = subscriptions.iter_mut().find(|sub| sub.id == id) {
                sub.reported_at = Instant::now();
                // Note: we deliberately do NOT clear a "changed" flag here. Whether the
                // subscription has further pending work is recomputed on the fly by
                // `find_report_due` from the live `changed_attrs` table and the event
                // buffer, so there is no race window where a change arriving during the
                // in-flight report could be silently dropped.
                if watermark > sub.max_seen_attr_change_id {
                    sub.max_seen_attr_change_id = watermark;
                }
                if min_event_number > sub.max_seen_event_number {
                    sub.max_seen_event_number = min_event_number;
                }

                true
            } else {
                false
            }
        })
    }

    /// Purge changed-attribute entries that have been reported by every subscription.
    /// Called periodically by the data model to keep the table small.
    pub(crate) fn purge_reported_changes(&self) {
        self.state.lock(|internal| {
            internal.borrow_mut().purge_reported_changes();
        })
    }

    /// Remove subscriptions matching the given filter criteria.
    ///
    /// A `None` component matches every subscription. For every removed
    /// subscription, `on_removed` is invoked with its id so that callers can
    /// keep side-tables (e.g. per-subscription buffers) in sync without
    /// having to duplicate identity fields outside of [`Subscription`] itself.
    pub(crate) fn remove(
        &self,
        fabric_idx: Option<NonZeroU8>,
        peer_node_id: Option<u64>,
        id: Option<u32>,
        mut on_removed: impl FnMut(u32),
    ) {
        self.state.lock(|internal| {
            let mut state = internal.borrow_mut();
            let subscriptions = &mut state.subscriptions;
            while let Some(index) = subscriptions.iter().position(|sub| {
                sub.fabric_idx == fabric_idx.unwrap_or(sub.fabric_idx)
                    && sub.peer_node_id == peer_node_id.unwrap_or(sub.peer_node_id)
                    && sub.id == id.unwrap_or(sub.id)
            }) {
                let removed = subscriptions.swap_remove(index);
                on_removed(removed.id);
            }

            // Removing a subscription may raise the `min(last_change_id)` watermark,
            // so opportunistically purge stale entries.
            state.purge_reported_changes();
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

    /// Find a subscription whose next report is due.
    ///
    /// A subscription is considered "report due" when either:
    /// - the minimum interval has elapsed and the subscription has pending work
    ///   (a change in [`ChangedAttributes`] beyond its `last_change_id`, or the
    ///   `events_pending` closure returns `true` for its current
    ///   `min_event_number`), or
    /// - the liveness deadline (`max(min_int, max_int / 2)`) has elapsed.
    ///
    /// Whether the subscription is "changed" is therefore recomputed on every
    /// call from the live state, rather than being tracked as a boolean that
    /// can race with concurrent attribute/event updates arriving while a
    /// report is in flight.
    ///
    /// Note that this method has a side effect:
    /// it updates the `reported_at` field of the subscription that is returned.
    pub(crate) fn find_report_due(
        &self,
        now: Instant,
        mut events_pending: impl FnMut(u64) -> bool,
    ) -> Option<(NonZeroU8, u64, Option<u32>, u32)> {
        self.state.lock(|internal| {
            let mut state = internal.borrow_mut();
            let state = &mut *state;
            let changed_attrs = &state.changed_attrs;

            let sub = state.subscriptions.iter_mut().find(|sub| {
                let min_int_expired = sub.expired(sub.min_int_secs, now);
                let liveness_expired = sub.expired(sub.min_int_secs.max(sub.max_int_secs / 2), now);

                let has_pending = |events_pending: &mut dyn FnMut(u64) -> bool| {
                    changed_attrs.any_since(sub.max_seen_attr_change_id)
                        || events_pending(sub.max_seen_event_number)
                };

                liveness_expired || (min_int_expired && has_pending(&mut events_pending))
            })?;

            sub.reported_at = now;
            Some((sub.fabric_idx, sub.peer_node_id, sub.session_id, sub.id))
        })
    }
}

impl<const N: usize> Default for Subscriptions<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> AttrChangeNotifier for Subscriptions<N> {
    fn notify_attr_changed(&self, endpt: EndptId, clust: ClusterId, attr: AttrId) {
        Subscriptions::<N>::notify_attribute_changed(self, endpt, clust, attr);
    }
}

impl<const N: usize> DynBase for Subscriptions<N> {}

#[cfg(test)]
mod tests {
    use super::*;

    use embassy_time::Duration;

    // ---------- ChangedAttributes ----------

    #[test]
    fn changed_attrs_starts_empty() {
        let attrs = ChangedAttributes::new();
        assert_eq!(attrs.watermark(), 0);
        assert!(!attrs.any_since(0));
        assert!(!attrs.contains_since(1, 2, 3, 0));
    }

    #[test]
    fn changed_attrs_record_assigns_monotonic_ids() {
        let mut attrs = ChangedAttributes::new();
        let id1 = attrs.record(1, 2, 3);
        let id2 = attrs.record(1, 2, 4);
        let id3 = attrs.record(2, 2, 3);
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
        assert_eq!(attrs.watermark(), 3);
    }

    #[test]
    fn changed_attrs_contains_since_and_any_since() {
        let mut attrs = ChangedAttributes::new();
        attrs.record(1, 2, 3);
        attrs.record(1, 2, 4);

        assert!(attrs.any_since(0));
        assert!(attrs.any_since(1));
        assert!(!attrs.any_since(2));

        assert!(attrs.contains_since(1, 2, 3, 0));
        assert!(attrs.contains_since(1, 2, 4, 1));
        // After watermark 2 there are no more changes
        assert!(!attrs.contains_since(1, 2, 3, 2));
        // A never-recorded triple is not covered
        assert!(!attrs.contains_since(9, 9, 9, 0));
    }

    #[test]
    fn changed_attrs_duplicate_refreshes_change_id() {
        let mut attrs = ChangedAttributes::new();
        attrs.record(1, 2, 3);
        attrs.record(1, 2, 4);
        // Same triple as first record - should refresh, not add a new entry.
        let id3 = attrs.record(1, 2, 3);
        assert_eq!(id3, 3);
        assert_eq!(attrs.entries.len(), 2);
        // The (1, 2, 3) entry now has change_id 3, so it is visible from since=2
        assert!(attrs.contains_since(1, 2, 3, 2));
        // But it was originally at id=1, which is now lost - `since=0` still sees it
        // through the refreshed id.
        assert!(attrs.contains_since(1, 2, 3, 0));
    }

    #[test]
    fn changed_attrs_purge_up_to_removes_old_entries() {
        let mut attrs = ChangedAttributes::new();
        attrs.record(1, 2, 3); // id 1
        attrs.record(1, 2, 4); // id 2
        attrs.record(2, 2, 3); // id 3

        attrs.purge_up_to(2);

        assert!(!attrs.contains_since(1, 2, 3, 0));
        assert!(!attrs.contains_since(1, 2, 4, 0));
        assert!(attrs.contains_since(2, 2, 3, 0));

        // Purging with 0 is a no-op.
        attrs.purge_up_to(0);
        assert!(attrs.contains_since(2, 2, 3, 0));
    }

    #[test]
    fn changed_attrs_clear_empties_table_but_keeps_watermark() {
        let mut attrs = ChangedAttributes::new();
        attrs.record(1, 2, 3);
        attrs.record(1, 2, 4);
        let wm_before = attrs.watermark();
        attrs.clear();
        assert!(!attrs.any_since(0));
        // Watermark is preserved so subsequent records remain strictly monotonic.
        assert_eq!(attrs.watermark(), wm_before);
        let id = attrs.record(5, 5, 5);
        assert_eq!(id, wm_before + 1);
    }

    #[test]
    fn changed_attrs_promotion_on_overflow_same_cluster() {
        let mut attrs = ChangedAttributes::new();
        // Fill the table with distinct concrete entries on the same (endpoint, cluster).
        for attr in 0..MAX_CHANGED_ATTRS as u32 {
            attrs.record(1, 2, attr);
        }
        assert_eq!(attrs.entries.len(), MAX_CHANGED_ATTRS);

        // One more record must still succeed - the existing entries get promoted.
        let overflow_id = attrs.record(1, 2, 9999);
        assert_eq!(overflow_id as usize, MAX_CHANGED_ATTRS + 1);

        // The table must never overflow its capacity.
        assert!(attrs.entries.len() <= MAX_CHANGED_ATTRS);

        // Every originally-recorded concrete attribute must still be reported as
        // "changed" when queried from since=0 (possibly via a coarser wildcard).
        for attr in 0..MAX_CHANGED_ATTRS as u32 {
            assert!(
                attrs.contains_since(1, 2, attr, 0),
                "attr {} lost after promotion",
                attr
            );
        }
        assert!(attrs.contains_since(1, 2, 9999, 0));

        // The new overflow entry is visible from the previous watermark.
        assert!(attrs.contains_since(1, 2, 9999, MAX_CHANGED_ATTRS as u64));
    }

    #[test]
    fn changed_attrs_promotion_to_global_wildcard() {
        let mut attrs = ChangedAttributes::new();
        // Entries spread across many endpoints/clusters/attrs to force promotion
        // past the (endpoint, cluster, *) and (endpoint, *, *) levels.
        for i in 0..(MAX_CHANGED_ATTRS as u16 + 5) {
            attrs.record(i, i as u32, i as u32);
        }
        assert!(attrs.entries.len() <= MAX_CHANGED_ATTRS);
        // All previously-recorded triples must still report as changed.
        for i in 0..(MAX_CHANGED_ATTRS as u16 + 5) {
            assert!(attrs.contains_since(i, i as u32, i as u32, 0));
        }
        // And an arbitrary never-recorded triple may or may not be covered
        // (over-reporting is allowed), but `any_since(0)` must be true.
        assert!(attrs.any_since(0));
    }

    #[test]
    fn promotion_prefers_largest_level_1_group() {
        // 10 entries on (1, 1, *) and 5 singletons on (1, k, 0) for k=2..=6
        // (= 15 entries total). One extra record fills the table, then an
        // overflowing record forces exactly ONE level-1 promotion which must
        // collapse the big (1, 1, *) group while leaving singletons concrete.
        let mut attrs = ChangedAttributes::new();
        for attr in 0..10u32 {
            attrs.record(1, 1, attr);
        }
        for cluster in 2..=6u32 {
            attrs.record(1, cluster, 0);
        }
        // Fill exactly to capacity without overflow.
        attrs.record(1, 1, 100);
        assert_eq!(attrs.entries.len(), MAX_CHANGED_ATTRS);

        // Now overflow to trigger promotion.
        attrs.record(2, 2, 2);
        assert!(attrs.entries.len() <= MAX_CHANGED_ATTRS);

        // The big (1, 1, *) group became exactly one wildcard entry.
        let wild_11 = attrs
            .entries
            .iter()
            .filter(|e| e.endpoint == Some(1) && e.cluster == Some(1) && e.attr.is_none())
            .count();
        assert_eq!(wild_11, 1);
        // No concrete (1, 1, _) entries survived.
        let concrete_11 = attrs
            .entries
            .iter()
            .filter(|e| e.endpoint == Some(1) && e.cluster == Some(1) && e.attr.is_some())
            .count();
        assert_eq!(concrete_11, 0);
        // Singletons on (1, k, 0) for k=2..=6 remain concrete.
        for cluster in 2..=6u32 {
            let n = attrs
                .entries
                .iter()
                .filter(|e| {
                    e.endpoint == Some(1) && e.cluster == Some(cluster) && e.attr == Some(0)
                })
                .count();
            assert_eq!(n, 1, "singleton (1, {}, 0) should remain concrete", cluster);
        }
        // The new (2, 2, 2) entry is present as a concrete entry.
        assert!(attrs
            .entries
            .iter()
            .any(|e| e.endpoint == Some(2) && e.cluster == Some(2) && e.attr == Some(2)));

        // All original triples still report as changed.
        for attr in 0..10u32 {
            assert!(attrs.contains_since(1, 1, attr, 0));
        }
        for cluster in 2..=6u32 {
            assert!(attrs.contains_since(1, cluster, 0, 0));
        }
        assert!(attrs.contains_since(1, 1, 100, 0));
        assert!(attrs.contains_since(2, 2, 2, 0));
    }

    #[test]
    fn promotion_is_minimal_only_one_group_collapsed_per_overflow() {
        // Two big level-1 groups of equal size. A single overflow must collapse
        // only ONE of them, not both (minimal promotion).
        let mut attrs = ChangedAttributes::new();
        // Group A: (1, 1, 0..8) = 8 entries
        for attr in 0..8u32 {
            attrs.record(1, 1, attr);
        }
        // Group B: (2, 2, 0..8) = 8 entries
        for attr in 0..8u32 {
            attrs.record(2, 2, attr);
        }
        assert_eq!(attrs.entries.len(), MAX_CHANGED_ATTRS);

        // Overflow with an unrelated entry.
        attrs.record(9, 9, 9);

        // Exactly one of the groups got collapsed into a wildcard.
        let a_wild = attrs
            .entries
            .iter()
            .any(|e| e.endpoint == Some(1) && e.cluster == Some(1) && e.attr.is_none());
        let b_wild = attrs
            .entries
            .iter()
            .any(|e| e.endpoint == Some(2) && e.cluster == Some(2) && e.attr.is_none());
        assert!(
            a_wild ^ b_wild,
            "expected exactly one of the groups to be collapsed (A: {}, B: {})",
            a_wild,
            b_wild
        );
        // The un-collapsed group still has all 8 concrete entries.
        let a_concrete = attrs
            .entries
            .iter()
            .filter(|e| e.endpoint == Some(1) && e.cluster == Some(1) && e.attr.is_some())
            .count();
        let b_concrete = attrs
            .entries
            .iter()
            .filter(|e| e.endpoint == Some(2) && e.cluster == Some(2) && e.attr.is_some())
            .count();
        assert!(
            (a_wild && a_concrete == 0 && b_concrete == 8)
                || (b_wild && b_concrete == 0 && a_concrete == 8)
        );
    }

    #[test]
    fn promotion_falls_back_to_level_2_when_no_level_1_group() {
        // All (endpoint, cluster) pairs are unique (level-1 groups are all
        // singletons) but endpoints repeat, so level-2 groups are non-trivial.
        let mut attrs = ChangedAttributes::new();
        for cluster in 0..8u32 {
            attrs.record(1, cluster, 0);
        }
        for cluster in 0..8u32 {
            attrs.record(2, cluster, 0);
        }
        assert_eq!(attrs.entries.len(), MAX_CHANGED_ATTRS);

        attrs.record(3, 9, 9);
        assert!(attrs.entries.len() <= MAX_CHANGED_ATTRS);

        // No level-1 wildcard (endpoint, cluster, *) was produced.
        let lvl1_wild = attrs
            .entries
            .iter()
            .filter(|e| e.endpoint.is_some() && e.cluster.is_some() && e.attr.is_none())
            .count();
        assert_eq!(lvl1_wild, 0);
        // Exactly one level-2 wildcard on endpoint 1 or 2 was produced.
        let ep1_wild = attrs
            .entries
            .iter()
            .any(|e| e.endpoint == Some(1) && e.cluster.is_none() && e.attr.is_none());
        let ep2_wild = attrs
            .entries
            .iter()
            .any(|e| e.endpoint == Some(2) && e.cluster.is_none() && e.attr.is_none());
        assert!(ep1_wild ^ ep2_wild);
        // No global wildcard was produced either.
        assert!(!attrs
            .entries
            .iter()
            .any(|e| e.endpoint.is_none() && e.cluster.is_none() && e.attr.is_none()));

        // All originals still visible.
        for cluster in 0..8u32 {
            assert!(attrs.contains_since(1, cluster, 0, 0));
            assert!(attrs.contains_since(2, cluster, 0, 0));
        }
        assert!(attrs.contains_since(3, 9, 9, 0));
    }

    #[test]
    fn promotion_falls_back_to_global_only_when_no_lower_group() {
        // All-distinct endpoints AND (endpoint, cluster) pairs: no level-1 or
        // level-2 group has >=2 entries. Overflow must collapse everything to
        // a single global wildcard.
        let mut attrs = ChangedAttributes::new();
        for i in 0..MAX_CHANGED_ATTRS as u16 {
            attrs.record(i, i as u32, i as u32);
        }
        assert_eq!(attrs.entries.len(), MAX_CHANGED_ATTRS);

        attrs.record(100, 200, 300);
        assert_eq!(attrs.entries.len(), 1);
        let only = &attrs.entries[0];
        assert!(only.endpoint.is_none() && only.cluster.is_none() && only.attr.is_none());

        // Every previously-recorded triple is still covered.
        for i in 0..MAX_CHANGED_ATTRS as u16 {
            assert!(attrs.contains_since(i, i as u32, i as u32, 0));
        }
        assert!(attrs.contains_since(100, 200, 300, 0));
    }

    #[test]
    fn promotion_preserves_max_change_id_in_coarsened_entry() {
        // After collapsing a (1, 1, *) group, the resulting wildcard's
        // change_id must equal the max change_id of the collapsed entries.
        let mut attrs = ChangedAttributes::new();
        for attr in 0..MAX_CHANGED_ATTRS as u32 {
            attrs.record(1, 1, attr);
        }
        let max_before = attrs.watermark();

        attrs.record(2, 2, 2);
        let wild = attrs
            .entries
            .iter()
            .find(|e| e.endpoint == Some(1) && e.cluster == Some(1) && e.attr.is_none())
            .expect("(1, 1, *) wildcard was produced");
        assert_eq!(wild.change_id, max_before);

        // contains_since respects that watermark exactly.
        assert!(attrs.contains_since(1, 1, 0, max_before - 1));
        assert!(!attrs.contains_since(1, 1, 0, max_before));
    }

    #[test]
    fn promotion_with_existing_wildcard_refreshes_instead_of_promoting_again() {
        // Build a state where (1, 1, *) wildcard already exists via a forced
        // promotion. Recording another (1, 1, k) must refresh that wildcard's
        // change_id without producing any new entry.
        let mut attrs = ChangedAttributes::new();
        for attr in 0..MAX_CHANGED_ATTRS as u32 {
            attrs.record(1, 1, attr);
        }
        attrs.record(2, 2, 2); // forces (1, 1, *) promotion

        // Now the table has 2 entries: (1, 1, *) and (2, 2, 2).
        assert_eq!(attrs.entries.len(), 2);
        let wm_after_promo = attrs.watermark();

        let new_id = attrs.record(1, 1, 42);
        // No new entry: still 2 entries. Wildcard's change_id advanced.
        assert_eq!(attrs.entries.len(), 2);
        assert_eq!(new_id, wm_after_promo + 1);
        let wild = attrs
            .entries
            .iter()
            .find(|e| e.endpoint == Some(1) && e.cluster == Some(1) && e.attr.is_none())
            .unwrap();
        assert_eq!(wild.change_id, new_id);
    }

    #[test]
    fn promotion_capacity_invariant_under_sustained_churn() {
        // Sustained mixed churn must never let the table exceed its capacity,
        // and every freshly-recorded triple must remain visible immediately
        // after recording.
        let mut attrs = ChangedAttributes::new();
        for i in 0..1000u32 {
            let endpoint = (i % 7) as u16;
            let cluster = i % 13;
            let attr = i;
            attrs.record(endpoint, cluster, attr);
            assert!(
                attrs.entries.len() <= MAX_CHANGED_ATTRS,
                "capacity exceeded at i={}",
                i
            );
            assert!(
                attrs.contains_since(endpoint, cluster, attr, 0),
                "just-recorded triple lost at i={}",
                i
            );
        }
    }

    #[test]
    fn promotion_iterated_into_same_existing_wildcard() {
        // Once (1, 1, *) exists, repeated inserts on that group must never
        // grow the table, and never trigger further promotion.
        let mut attrs = ChangedAttributes::new();
        for attr in 0..MAX_CHANGED_ATTRS as u32 {
            attrs.record(1, 1, attr);
        }
        attrs.record(2, 2, 2); // -> [(1,1,*), (2,2,2)]
        assert_eq!(attrs.entries.len(), 2);

        for attr in 100..200u32 {
            attrs.record(1, 1, attr);
            assert_eq!(attrs.entries.len(), 2);
        }
    }

    #[test]
    fn promotion_escalates_when_level_1_group_still_insufficient() {
        // Pathological case: a single level-1 group of size 2 exists, the rest
        // are singletons. After the first overflow, that group collapses
        // (freeing 1 slot), but the table is still full once the new record
        // tries to be inserted on a fresh singleton location. Subsequent
        // overflows must escalate to level-2 / global.
        let mut attrs = ChangedAttributes::new();
        // 2 entries sharing (1, 1, *) -- a single level-1 group of size 2.
        attrs.record(1, 1, 0);
        attrs.record(1, 1, 1);
        // Fill the rest with unique (endpoint, cluster) pairs.
        for i in 0..(MAX_CHANGED_ATTRS as u16 - 2) {
            attrs.record(10 + i, 100 + i as u32, i as u32);
        }
        assert_eq!(attrs.entries.len(), MAX_CHANGED_ATTRS);

        // First overflow: the only level-1 group collapses; then the new entry
        // gets inserted.
        attrs.record(50, 50, 50);
        assert!(attrs.entries.len() <= MAX_CHANGED_ATTRS);
        // The (1, 1, *) wildcard is present.
        assert!(attrs
            .entries
            .iter()
            .any(|e| e.endpoint == Some(1) && e.cluster == Some(1) && e.attr.is_none()));

        // Keep feeding: eventually we must fall back to level-2 or global
        // without breaking correctness.
        for i in 0..200u32 {
            let endpoint = 200 + (i % 5) as u16;
            let cluster = 300 + (i % 3);
            let attr = i;
            attrs.record(endpoint, cluster, attr);
            assert!(attrs.entries.len() <= MAX_CHANGED_ATTRS);
            assert!(attrs.contains_since(endpoint, cluster, attr, 0));
        }
        // Historical triples still covered.
        assert!(attrs.contains_since(1, 1, 0, 0));
        assert!(attrs.contains_since(1, 1, 1, 0));
        assert!(attrs.contains_since(50, 50, 50, 0));
    }

    #[test]
    fn changed_attr_covers_wildcards() {
        let concrete = ChangedAttr::concrete(1, 2, 3, 1);
        let any_attr = ChangedAttr {
            endpoint: Some(1),
            cluster: Some(2),
            attr: None,
            change_id: 1,
        };
        let any_cluster = ChangedAttr {
            endpoint: Some(1),
            cluster: None,
            attr: None,
            change_id: 1,
        };
        let global = ChangedAttr {
            endpoint: None,
            cluster: None,
            attr: None,
            change_id: 1,
        };

        assert!(any_attr.covers(&concrete));
        assert!(any_cluster.covers(&concrete));
        assert!(global.covers(&concrete));
        // Concrete does not cover wildcards.
        assert!(!concrete.covers(&any_attr));
        assert!(!concrete.covers(&global));
        // Concrete matches itself.
        assert!(concrete.matches(1, 2, 3));
        assert!(!concrete.matches(1, 2, 4));
        // Wildcards match any concrete triple on the wildcarded axis.
        assert!(any_attr.matches(1, 2, 99));
        assert!(!any_attr.matches(1, 9, 99));
        assert!(global.matches(99, 99, 99));
    }

    // ---------- Subscriptions ----------

    fn fab(i: u8) -> NonZeroU8 {
        NonZeroU8::new(i).unwrap()
    }

    #[test]
    fn add_returns_monotonic_ids_and_rejects_when_full() {
        let subs: Subscriptions<2> = Subscriptions::new();
        let id1 = subs.add(fab(1), 10, 100, 1, 60).unwrap();
        let id2 = subs.add(fab(1), 10, 100, 1, 60).unwrap();
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        // Third add exceeds N=2.
        assert!(subs.add(fab(1), 10, 100, 1, 60).is_none());
    }

    #[test]
    fn begin_report_snapshots_watermark_and_pending() {
        let subs: Subscriptions<2> = Subscriptions::new();
        subs.notify_attribute_changed(1, 2, 3);
        let id = subs.add(fab(1), 10, 100, 1, 60).unwrap();

        // A fresh subscription starts at the current watermark, so nothing is
        // pending for it even though the table has an entry.
        let ctx = subs.begin_report(id, false).unwrap();
        assert_eq!(ctx.since(), 1);
        assert_eq!(ctx.watermark(), 1);
        assert!(!ctx.any_pending());
        assert!(ctx.filter_active());

        // A new change bumps the watermark and becomes pending.
        subs.notify_attribute_changed(1, 2, 4);
        let ctx2 = subs.begin_report(id, false).unwrap();
        assert_eq!(ctx2.since(), 1);
        assert_eq!(ctx2.watermark(), 2);
        assert!(ctx2.any_pending());
    }

    #[test]
    fn begin_report_priming_has_no_filter_and_is_always_pending() {
        let subs: Subscriptions<2> = Subscriptions::new();
        let id = subs.add(fab(1), 10, 100, 1, 60).unwrap();

        let ctx = subs.begin_report(id, true).unwrap();
        assert!(!ctx.filter_active());
        assert!(ctx.any_pending());
    }

    #[test]
    fn mark_reported_advances_watermarks_monotonically() {
        let subs: Subscriptions<2> = Subscriptions::new();
        let id = subs.add(fab(1), 10, 100, 1, 60).unwrap();

        assert!(subs.mark_reported(id, 5, 7));
        let ctx = subs.begin_report(id, false).unwrap();
        assert_eq!(ctx.since(), 5);
        assert_eq!(ctx.min_event_number(), 7);

        // Smaller values must not regress.
        assert!(subs.mark_reported(id, 3, 2));
        let ctx2 = subs.begin_report(id, false).unwrap();
        assert_eq!(ctx2.since(), 5);
        assert_eq!(ctx2.min_event_number(), 7);

        // Larger values advance.
        assert!(subs.mark_reported(id, 10, 20));
        let ctx3 = subs.begin_report(id, false).unwrap();
        assert_eq!(ctx3.since(), 10);
        assert_eq!(ctx3.min_event_number(), 20);

        // Unknown id -> false.
        assert!(!subs.mark_reported(id + 999, 100, 100));
    }

    #[test]
    fn remove_invokes_callback_and_purges_changes() {
        let subs: Subscriptions<3> = Subscriptions::new();
        let id1 = subs.add(fab(1), 10, 100, 1, 60).unwrap();
        let id2 = subs.add(fab(1), 10, 101, 1, 60).unwrap();
        let id3 = subs.add(fab(2), 20, 102, 1, 60).unwrap();

        // Record a change that every subscription should see as pending.
        subs.notify_attribute_changed(1, 2, 3);

        let mut removed: std::vec::Vec<u32> = std::vec::Vec::new();
        subs.remove(Some(fab(1)), None, None, |id| removed.push(id));
        removed.sort();
        assert_eq!(removed, std::vec![id1, id2]);

        // Only (fab 2) remains; further removals are no-ops.
        subs.remove(Some(fab(1)), None, None, |_| unreachable!());

        // id3 is still present.
        assert!(subs.begin_report(id3, false).is_some());
    }

    #[test]
    fn purge_reported_changes_respects_slowest_subscriber() {
        let subs: Subscriptions<3> = Subscriptions::new();
        let fast = subs.add(fab(1), 10, 100, 1, 60).unwrap();
        let slow = subs.add(fab(1), 10, 101, 1, 60).unwrap();

        subs.notify_attribute_changed(1, 2, 3); // id 1
        subs.notify_attribute_changed(1, 2, 4); // id 2

        // Fast subscriber catches up to watermark 2.
        subs.mark_reported(fast, 2, 0);
        subs.purge_reported_changes();

        // Slow one has not seen anything yet -> its `contains_since(..., 0)` must
        // still see both changes.
        let filter_for_slow = SubAttrChangeFilter::new(&subs, 0);
        assert!(filter_for_slow.includes(1, 2, 3));
        assert!(filter_for_slow.includes(1, 2, 4));
        let _ = slow;

        // Now the slow one also catches up, and a purge should drop both entries.
        subs.mark_reported(slow, 2, 0);
        subs.purge_reported_changes();
        let filter_after = SubAttrChangeFilter::new(&subs, 0);
        assert!(!filter_after.includes(1, 2, 3));
        assert!(!filter_after.includes(1, 2, 4));
    }

    #[test]
    fn sub_attr_change_filter_honors_since_watermark() {
        let subs: Subscriptions<2> = Subscriptions::new();
        subs.notify_attribute_changed(1, 2, 3); // id 1
        subs.notify_attribute_changed(1, 2, 4); // id 2

        let f_all = SubAttrChangeFilter::new(&subs, 0);
        assert!(f_all.includes(1, 2, 3));
        assert!(f_all.includes(1, 2, 4));

        let f_recent = SubAttrChangeFilter::new(&subs, 1);
        assert!(!f_recent.includes(1, 2, 3));
        assert!(f_recent.includes(1, 2, 4));

        // A non-recorded attribute is never included.
        assert!(!f_all.includes(9, 9, 9));
    }

    #[test]
    fn find_report_due_picks_subscription_with_pending_changes() {
        let subs: Subscriptions<2> = Subscriptions::new();
        let id = subs.add(fab(1), 10, 100, 1, 60).unwrap();

        // Prime the subscription's `reported_at` to a real instant. After this the
        // `min_int` interval has not yet elapsed.
        subs.mark_reported(id, 0, 0);

        // No changes, no events -> nothing is due.
        assert!(subs.find_report_due(Instant::now(), |_| false).is_none());

        // A change is recorded but the min_int has not elapsed yet.
        subs.notify_attribute_changed(1, 2, 3);
        assert!(subs.find_report_due(Instant::now(), |_| false).is_none());

        // Advance past min_int (1 second). Now the subscription is due.
        let later = Instant::now() + Duration::from_secs(2);
        let due = subs.find_report_due(later, |_| false).unwrap();
        assert_eq!(due.3, id);
        // Side effect: `reported_at` was updated; a second immediate call finds nothing.
        assert!(subs.find_report_due(later, |_| false).is_none());
    }

    #[test]
    fn find_report_due_triggers_on_events_pending() {
        let subs: Subscriptions<2> = Subscriptions::new();
        let id = subs.add(fab(1), 10, 100, 1, 60).unwrap();
        subs.mark_reported(id, 0, 0);

        let later = Instant::now() + Duration::from_secs(2);

        // No attr change, and `events_pending` says no -> not due.
        assert!(subs.find_report_due(later, |_| false).is_none());

        // Events-pending closure now returns true -> due.
        let due = subs.find_report_due(later, |_| true).unwrap();
        assert_eq!(due.3, id);
    }

    #[test]
    fn find_report_due_triggers_on_liveness_even_without_changes() {
        let subs: Subscriptions<2> = Subscriptions::new();
        // max_int = 20 -> liveness at max(min_int, max_int/2) = 10s.
        let id = subs.add(fab(1), 10, 100, 1, 20).unwrap();
        subs.mark_reported(id, 0, 0);

        // Short of liveness: not due.
        let short = Instant::now() + Duration::from_secs(5);
        assert!(subs.find_report_due(short, |_| false).is_none());

        // Past liveness: due even without any changes or events.
        let long = Instant::now() + Duration::from_secs(20);
        let due = subs.find_report_due(long, |_| false).unwrap();
        assert_eq!(due.3, id);
    }

    #[test]
    fn find_report_due_events_pending_receives_subscription_watermark() {
        let subs: Subscriptions<2> = Subscriptions::new();
        let id = subs.add(fab(1), 10, 100, 1, 60).unwrap();
        subs.mark_reported(id, 0, 42);

        let later = Instant::now() + Duration::from_secs(2);
        let seen = core::cell::Cell::new(0u64);
        let _ = subs.find_report_due(later, |n| {
            seen.set(n);
            false
        });
        assert_eq!(seen.get(), 42);
    }

    #[test]
    fn is_expired_uses_max_int() {
        let subs: Subscriptions<1> = Subscriptions::new();
        let id = subs.add(fab(1), 10, 100, 1, 5).unwrap();
        subs.mark_reported(id, 0, 0);

        // Before max_int: not expired.
        assert!(subs
            .find_expired(Instant::now() + Duration::from_secs(2))
            .is_none());
        // After max_int: expired.
        let exp = subs
            .find_expired(Instant::now() + Duration::from_secs(10))
            .unwrap();
        assert_eq!(exp.3, id);
    }

    #[test]
    fn find_removed_session_matches_predicate() {
        let subs: Subscriptions<2> = Subscriptions::new();
        let id1 = subs.add(fab(1), 10, 100, 1, 60).unwrap();
        let _id2 = subs.add(fab(1), 10, 101, 1, 60).unwrap();

        let found = subs.find_removed_session(|sid| sid == 100).unwrap();
        assert_eq!(found.3, id1);
        assert_eq!(found.2, 100);

        // No matching predicate -> None.
        assert!(subs.find_removed_session(|_| false).is_none());
    }
}
