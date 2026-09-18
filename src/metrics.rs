//! Always-on performance instrumentation: one snapshot of plain integer
//! counters, readable by kittest tests and the baseline harness.
//!
//! Ownership: the app owns the [`MetricsHandle`] and records frame intervals
//! and (in later versions) work/resource counters; the runtime thread records
//! control-plane tick durations through its clone of the handle. Tests and
//! the baseline harness read a copy via [`MetricsHandle::snapshot`]. The
//! interior mutability is deliberate — the UI thread and the runtime thread
//! genuinely share this one cell.
//!
//! Rules:
//! - Counters are plain integers. Frame-time and tick duration counters
//!   accumulate a count plus a ns total; work counters bump by one per real
//!   event and must never be tied to frame count (idle-frame purity); resource
//!   counters hold current collection sizes, set on change.
//! - The read path is one lock plus a struct copy; recording is one
//!   uncontended lock plus integer increments. Nothing here allocates or does
//!   I/O. ns totals are `u64`; overflow would need centuries of continuous
//!   accumulation, so plain `+=` is safe.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

/// Control-plane poll arms timed by the runtime (`rt::Runtime::run`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickArm {
    /// Core readiness clock (Starting phase, `READY_POLL` cadence).
    Ready,
    /// 1 Hz traffic stats while Running.
    Stats,
    /// 5 s observatory statuses while Running.
    Observatory,
}

/// Named work counters for memoized UI structures. Bumped by the owning code
/// when a real event happens (a rebuild, a parse, a search, an enumeration) —
/// never per frame. Later work extends this list as new
/// memoized structures land.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkCounter {
    /// Full UI-context snapshot rebuilds.
    UiCtxRebuilds,
    /// Dashboard throughput-plot series rebuilds.
    PlotRebuilds,
    /// Raw JSON editor parse runs.
    RawEditorParses,
    /// Geodata picker search result rebuilds.
    GeodataSearches,
    /// TUN screen adapter enumerations.
    AdapterEnumerations,
    /// Logs screen filtered-view rebuilds.
    LogFilterRebuilds,
    /// Routing screen tag-vector rebuilds.
    RoutingTagRebuilds,
    /// Routing screen rule-row format passes.
    RoutingRuleFormats,
    /// Servers editor / add-draft validation-sweep rebuilds:
    /// one sweep per draft (generation, language) change, never per frame.
    EditorValidationRebuilds,
    /// Advanced-tab chain-target option rebuilds: one pass per
    /// profile-set (or edited-profile) change, never per frame.
    AdvancedTagRebuilds,
    /// Top-bar speed-readout string rebuilds: formatted once per stats
    /// tick / traffic-unit / language / version / viewport change, never
    /// per frame.
    TopbarSpeedRebuilds,
}

/// Named resource counters holding current collection sizes (and the rare
/// current per-frame layout quantity). Set on change (after an insert/evict,
/// a byte accounting pass, or a layout band change), never per frame —
/// idle frames never write them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceCounter {
    /// Raw-editor cache entry count.
    RawEditorCacheEntries,
    /// Balancer runtime map entry count.
    BalancerRuntimeMapEntries,
    /// Log-buffer byte total.
    LogBufferBytes,
    /// Servers list visible-band row count: profile rows the
    /// virtualized list actually laid out last frame (never all N). A
    /// per-frame layout quantity, so it is a resource set only when the count
    /// changes — never bumped per frame, and idle frames never write it.
    ServerListRowsLaidOut,
}

/// One snapshot of the metrics surface: plain integer counters only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Metrics {
    // -- frame-time accumulator ----------------------------------------------
    /// Completed frame intervals (one per gap between consecutive frame
    /// entries), so N frames yield N-1 intervals.
    pub frames: u64,
    /// Total ns between consecutive frame entries.
    pub frame_ns_total: u64,

    // -- control-plane tick duration counters --------------------------------
    /// Readiness-poll ticks and their accumulated cost.
    pub ready_ticks: u64,
    pub ready_tick_ns_total: u64,
    /// Traffic-stats ticks and their accumulated cost.
    pub stats_ticks: u64,
    pub stats_tick_ns_total: u64,
    /// Observatory ticks and their accumulated cost.
    pub obs_ticks: u64,
    pub obs_tick_ns_total: u64,

    // -- work counters (monotonic event counts) ------------------------------
    pub ui_ctx_rebuilds: u64,
    pub plot_rebuilds: u64,
    pub raw_editor_parses: u64,
    pub geodata_searches: u64,
    pub adapter_enumerations: u64,
    pub log_filter_rebuilds: u64,
    pub routing_tag_rebuilds: u64,
    pub routing_rule_formats: u64,
    pub editor_validation_rebuilds: u64,
    pub advanced_tag_rebuilds: u64,
    pub topbar_speed_rebuilds: u64,

    // -- resource counters (current collection sizes) ------------------------
    pub raw_editor_cache_entries: u64,
    pub balancer_runtime_map_entries: u64,
    pub log_buffer_bytes: u64,
    pub server_list_rows_laid_out: u64,
}

impl Metrics {
    /// Accumulate one completed frame interval.
    pub fn record_frame_interval(&mut self, interval: Duration) {
        self.frames += 1;
        self.frame_ns_total += duration_ns(interval);
    }

    /// Accumulate one completed control-plane tick.
    pub fn record_tick(&mut self, arm: TickArm, duration: Duration) {
        let ns = duration_ns(duration);
        match arm {
            TickArm::Ready => {
                self.ready_ticks += 1;
                self.ready_tick_ns_total += ns;
            }
            TickArm::Stats => {
                self.stats_ticks += 1;
                self.stats_tick_ns_total += ns;
            }
            TickArm::Observatory => {
                self.obs_ticks += 1;
                self.obs_tick_ns_total += ns;
            }
        }
    }

    /// Bump a work counter by one. Only ever called on a real event — an idle
    /// frame must not reach here.
    pub fn bump_work(&mut self, counter: WorkCounter) {
        match counter {
            WorkCounter::UiCtxRebuilds => self.ui_ctx_rebuilds += 1,
            WorkCounter::PlotRebuilds => self.plot_rebuilds += 1,
            WorkCounter::RawEditorParses => self.raw_editor_parses += 1,
            WorkCounter::GeodataSearches => self.geodata_searches += 1,
            WorkCounter::AdapterEnumerations => self.adapter_enumerations += 1,
            WorkCounter::LogFilterRebuilds => self.log_filter_rebuilds += 1,
            WorkCounter::RoutingTagRebuilds => self.routing_tag_rebuilds += 1,
            WorkCounter::RoutingRuleFormats => self.routing_rule_formats += 1,
            WorkCounter::EditorValidationRebuilds => self.editor_validation_rebuilds += 1,
            WorkCounter::AdvancedTagRebuilds => self.advanced_tag_rebuilds += 1,
            WorkCounter::TopbarSpeedRebuilds => self.topbar_speed_rebuilds += 1,
        }
    }

    /// Store the current size of a bounded collection.
    pub fn set_resource(&mut self, counter: ResourceCounter, value: u64) {
        match counter {
            ResourceCounter::RawEditorCacheEntries => self.raw_editor_cache_entries = value,
            ResourceCounter::BalancerRuntimeMapEntries => self.balancer_runtime_map_entries = value,
            ResourceCounter::LogBufferBytes => self.log_buffer_bytes = value,
            ResourceCounter::ServerListRowsLaidOut => self.server_list_rows_laid_out = value,
        }
    }
}

/// ns conversion for per-call durations: a `u64` holds ~584 years of ns, and
/// individual values here are sub-second, so the narrowing cast cannot lose
/// anything meaningful.
fn duration_ns(duration: Duration) -> u64 {
    duration.as_nanos() as u64
}

/// Shared handle to the app-owned metrics snapshot. The app records frame
/// intervals and work/resource counters; the runtime thread records tick
/// durations through its clone.
#[derive(Clone, Default)]
pub struct MetricsHandle(Arc<Mutex<Metrics>>);

impl MetricsHandle {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Metrics> {
        // A poisoned lock (a holder that panicked) must never take down the
        // app: recover the last consistent state and keep recording.
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Cheap read path for tests and the baseline harness: one lock, one
    /// struct copy.
    pub fn snapshot(&self) -> Metrics {
        *self.lock()
    }

    /// Record one completed frame interval (measured between frame entries
    /// on the app).
    pub fn record_frame(&self, interval: Duration) {
        self.lock().record_frame_interval(interval);
    }

    /// Record one completed control-plane tick.
    pub fn record_tick(&self, arm: TickArm, duration: Duration) {
        self.lock().record_tick(arm, duration);
    }

    /// Bump a work counter by one.
    pub fn bump_work(&self, counter: WorkCounter) {
        self.lock().bump_work(counter);
    }

    /// Store the current size of a bounded collection.
    pub fn set_resource(&self, counter: ResourceCounter, value: u64) {
        self.lock().set_resource(counter, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_accumulator_counts_intervals_and_ns() {
        let mut m = Metrics::default();
        m.record_frame_interval(Duration::from_millis(16));
        m.record_frame_interval(Duration::from_millis(8));
        assert_eq!(m.frames, 2);
        assert_eq!(m.frame_ns_total, 24_000_000);
    }

    #[test]
    fn tick_counters_accumulate_per_arm() {
        let mut m = Metrics::default();
        m.record_tick(TickArm::Ready, Duration::from_millis(1));
        m.record_tick(TickArm::Ready, Duration::from_millis(2));
        m.record_tick(TickArm::Stats, Duration::from_millis(3));
        m.record_tick(TickArm::Observatory, Duration::from_millis(4));
        assert_eq!(m.ready_ticks, 2);
        assert_eq!(m.ready_tick_ns_total, 3_000_000);
        assert_eq!(m.stats_ticks, 1);
        assert_eq!(m.stats_tick_ns_total, 3_000_000);
        assert_eq!(m.obs_ticks, 1);
        assert_eq!(m.obs_tick_ns_total, 4_000_000);
    }

    #[test]
    fn work_counters_bump_independently() {
        let mut m = Metrics::default();
        m.bump_work(WorkCounter::UiCtxRebuilds);
        m.bump_work(WorkCounter::UiCtxRebuilds);
        m.bump_work(WorkCounter::RawEditorParses);
        assert_eq!(m.ui_ctx_rebuilds, 2);
        assert_eq!(m.raw_editor_parses, 1);
        assert_eq!(m.plot_rebuilds, 0);
    }

    #[test]
    fn resource_counters_store_current_sizes() {
        let mut m = Metrics::default();
        m.set_resource(ResourceCounter::LogBufferBytes, 1024);
        m.set_resource(ResourceCounter::LogBufferBytes, 512);
        m.set_resource(ResourceCounter::RawEditorCacheEntries, 7);
        assert_eq!(m.log_buffer_bytes, 512);
        assert_eq!(m.raw_editor_cache_entries, 7);
        assert_eq!(m.balancer_runtime_map_entries, 0);
    }

    #[test]
    fn handle_records_through_the_shared_cell_and_snapshots_copy() {
        let handle = MetricsHandle::new();
        handle.record_frame(Duration::from_millis(16));
        handle.record_tick(TickArm::Stats, Duration::from_millis(1));
        handle.bump_work(WorkCounter::GeodataSearches);
        handle.set_resource(ResourceCounter::BalancerRuntimeMapEntries, 3);

        let snapshot = handle.snapshot();
        assert_eq!(snapshot.frames, 1);
        assert_eq!(snapshot.frame_ns_total, 16_000_000);
        assert_eq!(snapshot.stats_ticks, 1);
        assert_eq!(snapshot.geodata_searches, 1);
        assert_eq!(snapshot.balancer_runtime_map_entries, 3);

        // The snapshot is a copy: mutating it must not touch the shared cell.
        let mut copy = handle.snapshot();
        copy.frames += 100;
        assert_eq!(copy.frames, 101);
        assert_eq!(handle.snapshot().frames, 1);
    }
}
