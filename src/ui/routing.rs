//! Routing screen: ordered first-match rules, balancers,
//! domainStrategy, observatory + burstObservatory, and the TestRoute dialog.

use crate::diag::{Diag, DiagError};
use crate::i18n::{Key, safety_message, t, t_fmt};
use crate::model::emit;
use crate::model::inbound::{
    API_INBOUND_TAG, DIRECT_OUTBOUND_TAG, DNS_INBOUND_TAG, TUN_INBOUND_TAG,
};
use crate::model::routing::{RouteTestRequest, RoutingIntegrityError};
use crate::model::safety::SafetyVerdicts;
use crate::model::settings::Language;
use crate::model::{
    Balancer, DurationMs, LeastLoadSettings, Rule, ServerProfile, ServersFile, Settings,
    StrategyCost, Webhook,
};
use crate::rt::{BalancerInfoView, CoreCmd, CorePhase, RuntimeStateView, TrialRuleAddOutcome};
use crate::sys::geodata::{GeodataCatalog, GeodataError, GeodataSnapshot};
use crate::ui::gate::{Rung, verdict};
use crate::ui::request::{Request, Terminal};
use crate::ui::status::status_colors_of;
use crate::ui::{UiCtx, widgets};
use egui::{DragValue, RichText, Ui};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;
use tokio::sync::oneshot;

/// Transient string buffers for the leastload sub-form of one balancer
/// (DurationMs fields are edited as Go duration strings, committed on parse).
#[derive(Default)]
struct LeastLoadBuf {
    baselines: Vec<String>,
    max_rtt: String,
}

/// Commit-gated edit buffers for the rule editor's PortList fields:
/// a valid list writes the model, an invalid one renders an inline
/// error and stays out of the model — the leastload `max_rtt` precedent.
#[derive(Default)]
struct RulePortBuf {
    port: String,
    source_port: String,
    local_port: String,
    vless_route: String,
}

/// One in-flight balancer control action for a single balancer tag. The
/// request's reply channel is polled per frame; pairing is structural — a
/// result can only reach the entry that requested it.
enum BalancerPending {
    /// `CoreCmd::GetBalancerInfo`; Ok carries the live ephemeral state.
    Info {
        request: Request<Result<BalancerInfoView, DiagError>>,
    },
    /// `CoreCmd::SetBalancerOverride`/`ClearBalancerOverride`; `target` is
    /// the trimmed target the UI sent (`Some` for Set, `None` for Clear) —
    /// the mutate-success path needs it to echo the applied override.
    Mutate {
        target: Option<String>,
        request: Request<Result<(), DiagError>>,
    },
}

#[derive(Default)]
struct BalancerRuntimeUi {
    pending_request: Option<BalancerPending>,
    info: Option<BalancerInfoView>,
    feedback: Option<(bool, String)>,
    known_target: String,
    use_custom_target: bool,
    custom_target: String,
    /// Bumped whenever `info` is replaced or created: the principle-targets
    /// line memo's key.
    info_generation: u64,
    /// The rendered principle-targets line and the (info generation,
    /// language) pair it was rendered for.
    principle_line: Option<PrincipleLine>,
}

/// The principle-targets line as rendered for one info reply. The reply's
/// target list only changes when the reply is consumed, so the join +
/// `t_fmt` are cached per (reply generation, language) instead of running
/// on every frame the balancer editor is open.
struct PrincipleLine {
    generation: u64,
    lang: Language,
    text: String,
}

impl BalancerRuntimeUi {
    /// Rebuild the memoized principle-targets line when the info reply or
    /// the language moved; runs before the info block's shared borrow, which
    /// then only reads the cached text.
    fn refresh_principle_line(&mut self, lang: Language) {
        let stale = self
            .principle_line
            .as_ref()
            .is_none_or(|line| line.generation != self.info_generation || line.lang != lang);
        if !stale {
            return;
        }
        let text = match self
            .info
            .as_ref()
            .and_then(|info| info.principle_targets.as_deref())
        {
            Some(targets) if !targets.is_empty() => {
                t_fmt(lang, Key::PrincipleTargets, &[&targets.join(", ")])
            }
            Some(_) => t(lang, Key::PrincipleTargetsNone).into(),
            None => t(lang, Key::PrincipleTargetsHidden).into(),
        };
        self.principle_line = Some(PrincipleLine {
            generation: self.info_generation,
            lang,
            text,
        });
    }

    /// The cached principle-targets line, refreshed this frame by
    /// [`Self::refresh_principle_line`].
    fn principle_line_text(&self) -> &str {
        self.principle_line
            .as_ref()
            .map_or("", |line| line.text.as_str())
    }
}

enum BalancerControlAction {
    Refresh,
    Set(String),
    Clear,
}

/// Snapshot of the live-core control channel taken before the balancer
/// editor runs, so the per-balancer controls can be drawn while the
/// settings tree is mutably borrowed.
struct RuntimeControl<'a> {
    cmd: &'a tokio::sync::mpsc::UnboundedSender<CoreCmd>,
    running: bool,
    /// The busy window: an exclusive job holds it.
    busy: bool,
}

#[derive(Clone, Copy)]
enum GeodataPickerKind {
    Geosite,
    Geoip,
}

impl GeodataPickerKind {
    fn button_label(self, lang: Language) -> &'static str {
        match self {
            Self::Geosite => t(lang, Key::GeodataAddGeosite),
            Self::Geoip => t(lang, Key::GeodataAddGeoip),
        }
    }

    fn file_name(self) -> &'static str {
        match self {
            Self::Geosite => "geosite.dat",
            Self::Geoip => "geoip.dat",
        }
    }

    fn prefix(self) -> &'static str {
        match self {
            Self::Geosite => "geosite:",
            Self::Geoip => "geoip:",
        }
    }

    fn catalog(self, snapshot: &GeodataSnapshot) -> &Result<GeodataCatalog, GeodataError> {
        match self {
            Self::Geosite => &snapshot.geosite,
            Self::Geoip => &snapshot.geoip,
        }
    }
}

/// Allocation-free ASCII case-insensitive substring test, shared by the
/// routing geodata filter and the logs text filter (no per-line allocations).
pub(crate) fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    let needle = needle.as_bytes();
    needle.is_empty()
        || haystack
            .as_bytes()
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
}

#[derive(Default)]
enum GeodataLoadState {
    #[default]
    Idle,
    Loading(Request<GeodataSnapshot>),
    Ready,
    Failed(String),
}

impl GeodataLoadState {
    fn is_loading(&self) -> bool {
        matches!(self, Self::Loading(_))
    }
}

/// Memoized geodata picker search result: indices into the catalog `codes`
/// that matched the query at scan time, keyed on (query, dataset revision).
/// An open menu re-renders every frame, so the scan result must outlive the
/// frame that produced it; storing indices (not `&str` references) keeps the
/// memo free of borrows into the snapshot and valid for exactly one dataset
/// revision.
#[derive(Debug)]
struct GeodataSearchMemo {
    /// The (trimmed) query the scan ran with.
    query: String,
    /// `RoutingScreen::geodata_revision` at scan time.
    dataset_revision: u64,
    /// Indices of the matching `codes` entries, in catalog order. `u32`
    /// covers the `MAX_CODES` (65,536) catalog bound in `sys::geodata`.
    matches: Vec<u32>,
}

/// Indices of `codes` entries containing `query` (ASCII case-insensitive
/// substring), in catalog order. The picker renders through these indices
/// so a cached result never holds references into the snapshot.
fn geodata_search_indices(codes: &[String], query: &str) -> Vec<u32> {
    codes
        .iter()
        .enumerate()
        .filter(|(_, code)| contains_ascii_case_insensitive(code, query))
        .map(|(index, _)| index as u32)
        .collect()
}

/// Refresh `memo` when the (query, dataset) key changed; returns the match
/// indices to render this frame. Repeated renders with an unchanged key are
/// free — the memo entry is kept whole, so its allocations survive: the
/// `matches` vector for a query that matches, the key `String` for one that
/// matches nothing. Those two allocations are what the idle-frame purity
/// test pins as un-reallocated.
fn geodata_search_matches<'a>(
    memo: &'a mut Option<GeodataSearchMemo>,
    dataset_revision: u64,
    codes: &[String],
    query: &str,
) -> &'a [u32] {
    let stale = memo
        .as_ref()
        .is_none_or(|m| m.query != query || m.dataset_revision != dataset_revision);
    if stale {
        let matches = geodata_search_indices(codes, query);
        *memo = Some(GeodataSearchMemo {
            query: query.to_owned(),
            dataset_revision,
            matches,
        });
    }
    // The stale path wrote the memo above; the only non-write path already
    // held a valid key, so the None arm is unreachable (empty slice fallback
    // renders nothing for one frame if it ever fired).
    match memo.as_ref() {
        Some(m) => m.matches.as_slice(),
        None => &[],
    }
}

/// One rule's memoized row text: the 8-char tag prefix,
/// the summary line, and the arrow-wrapped target line (empty = no target).
/// Computed once per model generation change, never per frame.
#[derive(Debug)]
struct RuleRowText {
    short_tag: String,
    summary: String,
    target_line: String,
}

/// One balancer's memoized header text: the strategy
/// caption, the optional selector summary, and the two reference-count
/// notes — every per-frame `t_fmt`/`one_plus` output of the balancer row
/// header, built once per cache generation (alongside
/// [`RoutingViewCache::reference_counts`], whose numbers they render)
/// instead of per frame.
#[derive(Debug)]
struct BalancerHeaderText {
    /// `BalancerStrategy` caption with the resolved strategy label.
    strategy: String,
    /// `BalancerSelector` summary of the selector list; absent while the
    /// balancer has no selectors (the row omits the label then).
    selector: Option<String>,
    /// `BalancerUsedBy` hover text for the delete button, shown while the
    /// button is disabled (the row has rule references).
    used_by: String,
    /// `BalancerDeleteBlocked` note under the row, shown while the row has
    /// rule references.
    delete_blocked: String,
}

/// One generation of the routing screen's derived UI data:
/// the outbound/balancer tag lists offered by the rule and balancer editors,
/// the per-rule row text, the per-balancer rule-reference counts, and the
/// TestRoute dialog's inbound options. Rebuilt only when the model generation
/// or the language advances — an edit, a cross-screen change, a locale change
/// — never on idle repaint frames.
#[derive(Debug)]
struct RoutingViewCache {
    generation: (u64, Language),
    out_tags: Vec<String>,
    /// Whether the document carries a server profile's outbound (`srv-…`): the
    /// balancer Add button and the rule editor's "select all servers" shortcut
    /// exist only then. The generator emits an outbound for every profile
    /// unconditionally, so the fact is whether the state has profiles at all —
    /// a question about the emission rule, not about the narrower `out_tags`
    /// menu.
    server_outbound_emitted: bool,
    /// Non-empty balancer tags, as offered by the rule editor's target combo.
    bal_tags: Vec<String>,
    /// Every balancer tag (empty ones included) for the rename validator.
    balancer_tags: Vec<String>,
    rule_rows: Vec<RuleRowText>,
    /// Rule-reference count per balancer, parallel to
    /// `settings.routing.balancers` — a linear rule scan per balancer, so it
    /// is computed once per generation, never per frame.
    reference_counts: Vec<usize>,
    /// Balancer row-header text (strategy caption, selector summary,
    /// delete-disabled hover and delete-blocked note), parallel to
    /// `settings.routing.balancers` — formatted once per generation next to
    /// the reference counts, never per frame.
    balancer_headers: Vec<BalancerHeaderText>,
    /// i18n'd breakage warnings from [`assess`], pre-rendered at the same
    /// generation cadence as the reference counts. Parallel to
    /// `settings.routing.balancers`; each entry renders its own row's amber
    /// warning line. The paths mirror the wire paths `assess` emits
    /// ("routing.balancers[i]").
    balancer_warnings: Vec<Option<String>>,
    /// Inbound tags offered by the TestRoute dialog's combo: the three
    /// built-in listeners plus every dokodemo tag. Rebuilt with the cache
    /// generation so an open dialog never clones the list per frame.
    known_inbounds: Vec<String>,
}

/// The refreshed live trial-rule inventory `(target tag, rule tag)` the
/// runtime returns after every List/Remove — the terminal payload both
/// share (only the add answers with [`TrialRuleAddOutcome`]).
type TrialRulesReply = Result<Vec<(String, String)>, DiagError>;

/// UI state for the trial-rule surface: the live rule list read
/// back from the core, the in-flight requests, dialog feedback, and the
/// "new rule" draft. Everything here is ephemeral — a phase change clears
/// the list, and nothing is ever persisted.
#[derive(Default)]
pub struct TrialRulesUi {
    /// Full live rule inventory `(target tag, rule tag)` read back from the
    /// core — committed config rules (which always carry UUID ruleTags in
    /// this app) and injected trials alike. Used for duplicate-tag checks;
    /// only rows whose tag is in [`Self::injected_tags`] are rendered or
    /// removable. A confirmed add whose read-back failed is added here from
    /// the submitted target, since no list could confirm it.
    rules: Vec<(String, String)>,
    /// Rule tags THIS session injected: the only rows the UI may
    /// Remove/Clear — committed rules must never be touched from here, and
    /// the banner count is the rendered rows, not the whole live list.
    injected_tags: Vec<String>,
    /// Memoized render rows = live inventory ∩ injected tags; rebuilt only
    /// when a reply result lands or invalidation clears it, never per frame.
    visible: Vec<(String, String)>,
    /// Rule tag of the in-flight Add; registered in `injected_tags` when the
    /// attempt's verdict lands — a confirmed add, or a failed one that may
    /// still have taken effect in the core.
    pending_add_tag: Option<String>,
    /// Target tag submitted with the in-flight Add (the draft's outbound or
    /// balancer tag). Kept alongside the tag so a confirmed add whose
    /// read-back failed can still show a truthful row.
    pending_add_target: Option<String>,
    /// Injected tags whose removal still waits its turn. Clear all sends one
    /// `RemoveTrialRule` at a time and starts the next only when the previous
    /// reply lands, so each reply's refreshed inventory is applied in order;
    /// a non-empty queue is part of [`RoutingScreen::trial_busy`], which keeps
    /// the section disabled until the batch finishes.
    remove_queue: VecDeque<String>,
    /// In-flight add: the reply channel the runtime answers, polled per
    /// frame. The slot itself identifies the operation, so a landed result
    /// needs no kind tag alongside it.
    pending_add: Request<Result<TrialRuleAddOutcome, DiagError>>,
    /// In-flight inventory request. List and Remove answer with the same
    /// refreshed live rule list and are applied identically, so they share
    /// this slot.
    pending_inventory: Request<TrialRulesReply>,
    /// `(ok, message)` feedback for the last completed operation.
    feedback: Option<(bool, String)>,
    /// Draft of the "new trial rule" dialog.
    draft: TrialRuleDraft,
    /// Inline validation error of the dialog draft (set on Inject, cleared
    /// on the next successful build).
    draft_error: Option<String>,
    /// Whether the dialog is open.
    open: bool,
    /// Outbound tags the running core reported, or `None` while they are
    /// unknown (never read, or the read failed). The dialog's target check
    /// rejects an outbound this set is known to lack, so an unknown set keeps
    /// the check permissive.
    live_out_tags: Option<Vec<String>>,
    /// Whether this core phase already made its one automatic live-out read
    /// attempt. The dialog renders every frame the core runs, so without this
    /// a failed read would re-issue the two-RPC read every frame until one
    /// succeeded; a phase change forgets the attempt.
    live_out_requested: bool,
    /// In-flight `CoreCmd::ListRuntimeState` that fills [`Self::live_out_tags`];
    /// one request at a time, polled per frame.
    pending_live_out: Request<Result<RuntimeStateView, DiagError>>,
}

/// Draft of one new trial rule. Text fields are committed only when the
/// dialog's "Inject" is clicked; each is validated before the request is
/// sent.
#[derive(Default)]
pub struct TrialRuleDraft {
    /// Rule tag; required and must be unique among the live rules.
    rule_tag: String,
    /// Target outbound tag (when `use_balancer` is false).
    outbound_tag: String,
    /// Target balancer tag (when `use_balancer` is true).
    balancer_tag: String,
    use_balancer: bool,
    /// One domain/geosite entry per line.
    domains: String,
    /// One IP/CIDR/geoip entry per line.
    ips: String,
    /// One process name/path per line.
    processes: String,
}

/// One trial-rule action the section can send through the runtime
/// (Add flows through the dialog's draft instead).
enum TrialAction {
    List,
    Remove(String),
}

/// Split a dialog text area into trimmed non-empty entries (one per line).
fn split_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

#[derive(Default)]
pub struct RoutingScreen {
    /// Index of the rule with the inline editor open.
    edit_rule: Option<usize>,
    /// Index of the balancer with the inline editor open.
    edit_balancer: Option<usize>,
    /// (rule_tag, rows) — kv editing buffer for `Rule.attrs` (a map, so rows
    /// with empty/duplicate keys must survive mid-edit outside the model).
    attrs_buf: Option<(String, Vec<(String, String)>)>,
    /// (rule_tag, rows) — kv editing buffer for `Webhook.headers`.
    headers_buf: Option<(String, Vec<(String, String)>)>,
    /// (rule_tag, buffers) — commit-gated edit buffers for the rule editor's
    /// PortList text fields (port, source_port, local_port, vless_route).
    /// Valid edits write the model; invalid ones stay in the buffer with an
    /// inline error, so a malformed list can never reach a saved or applied
    /// config.
    port_bufs: Option<(String, RulePortBuf)>,
    /// (balancer tag, buffers) for the expanded leastload form.
    ll_buf: Option<(String, LeastLoadBuf)>,
    /// Local edit buffer for the observatory probe interval.
    probe_interval: Option<String>,
    ping_interval: Option<String>,
    ping_timeout: Option<String>,
    test_open: bool,
    test_request: RouteTestRequest,
    test_attrs: Vec<(String, String)>,
    /// In-flight TestRoute request: the reply channel the runtime answers,
    /// polled per frame while the dialog is open. The request lives on the
    /// screen (not the dialog), so a result that lands while the dialog is
    /// closed is consumed on reopen — the run is never re-sent.
    test_pending_request: Request<Result<String, DiagError>>,
    test_result: Option<Result<String, DiagError>>,
    /// Cached `route_test_request` result (deep clone + attribute rebuild +
    /// re-validation), recomputed only when a dialog editor reports
    /// `changed()` this frame instead of on every repaint.
    prepared_route_test: Option<Result<RouteTestRequest, String>>,
    /// Draft tag for the open balancer; committed only through
    /// `RoutingCfg::rename_balancer`, which rewrites rule references.
    balancer_tag_buf: String,
    balancer_error: Option<String>,
    /// Live per-balancer runtime UI state, keyed by balancer tag; entries
    /// are evicted when their tag leaves the routing model (see
    /// [`RoutingScreen::evict_stale_balancer_runtime`]).
    balancer_runtime: BTreeMap<String, BalancerRuntimeUi>,
    /// Last completed snapshot remains visible while a Refresh worker runs.
    geodata_snapshot: Option<GeodataSnapshot>,
    geodata_load_state: GeodataLoadState,
    /// Bumped every time a new geodata snapshot lands; invalidates the search
    /// memos so an open picker rescans against the new catalog.
    geodata_revision: u64,
    /// Cached picker search results, one per kind, keyed on (query, dataset
    /// revision) — an open menu never rescans the catalog per frame.
    geosite_search_memo: Option<GeodataSearchMemo>,
    geoip_search_memo: Option<GeodataSearchMemo>,
    geosite_search: String,
    geoip_search: String,
    /// Trial-rule (ephemeral control-plane) UI state: the live rule list
    /// read back from the core, the in-flight request, and the dialog draft.
    /// Trial rules are never persisted and die with the core session
    /// — the app invalidates this state on every phase change.
    trial: TrialRulesUi,
    /// Generation-gated derived UI data: tag vectors + rule-row text, rebuilt
    /// only when the routing model changed (see [`RoutingViewCache`]).
    view_cache: Option<RoutingViewCache>,
}

impl RoutingScreen {
    pub fn show(&mut self, ui: &mut Ui, ctx: &mut UiCtx) {
        let lang = ctx.settings.language;
        self.poll_geodata_load(lang);
        let mut changed = false;

        // Derived UI data (tag vectors + rule-row text) is generation-gated:
        // rebuilt only when the routing model changed, never per frame.
        self.refresh_view_cache(*ctx.model_generation, lang, ctx.servers, ctx.settings);

        self.consume_balancer_results(lang);
        self.consume_trial_results(ctx, lang);
        self.poll_live_out_tags();

        self.rules_section(ui, ctx, lang, &mut changed);
        self.balancers_section(ui, ctx, lang, &mut changed);
        self.observability_section(ui, ctx, lang, &mut changed);
        self.trial_rules_section(ui, ctx, lang);

        if changed {
            // One edit = one generation change: the hook moves the shared
            // generation the view cache gates on, so the next frame rebuilds
            // the tag vectors and rule rows exactly once.
            ctx.mark_dirty();
        }
        self.test_route_dialog(ui, ctx);
        self.trial_rule_dialog(ui, ctx);
    }

    /// Drop the cached live rule list and this session's injected-tag
    /// registry — a phase change invalidates both: trial rules never survive
    /// a core restart or config commit, so anything the core
    /// reported earlier belongs to a dead session. The in-flight requests,
    /// the queued removals and their feedback die with it, and the live
    /// outbound set and its one-per-phase read attempt are dropped so a
    /// restarted core is read again; the dialog draft survives so the
    /// user can retry the same rule after reconnecting.
    pub fn invalidate_trial_rules(&mut self) {
        self.trial.rules.clear();
        self.trial.injected_tags.clear();
        self.trial.visible.clear();
        self.trial.pending_add_tag = None;
        self.trial.pending_add_target = None;
        self.trial.remove_queue.clear();
        self.trial.pending_add.cancel();
        self.trial.pending_inventory.cancel();
        self.trial.feedback = None;
        self.trial.live_out_tags = None;
        self.trial.live_out_requested = false;
        self.trial.pending_live_out.cancel();
    }

    /// Live trial-rule count for the topbar banner: exactly the rows the grid
    /// shows — this session's injected rules the last landed inventory
    /// reports. A tag with no row (a failed or unconfirmed add) is not
    /// counted, so the banner can never claim a rule the user cannot see or
    /// remove; committed config rules are never counted either (they are not
    /// trials and must not be removable from here).
    pub fn trial_rule_count(&self) -> usize {
        self.trial.visible.len()
    }

    /// Rebuild the memoized render rows: the full live inventory filtered
    /// to tags this session injected. Committed config rules (UUID-tagged)
    /// and untagged internal rules never appear. Called only when a reply
    /// result mutates the inventory or the registry.
    fn rebuild_visible_trial_rules(&mut self) {
        self.trial.visible = self
            .trial
            .rules
            .iter()
            .filter(|(_, rule_tag)| self.trial.injected_tags.iter().any(|t| t == rule_tag))
            .cloned()
            .collect();
    }

    /// Apply one landed inventory reply: the list is the core's own truth,
    /// so the registry keeps only the tags the core still reports — the
    /// banner count can never drift above what the core holds — and the
    /// render rows are rebuilt from the reconciled pair.
    fn apply_trial_inventory(&mut self, rules: Vec<(String, String)>) {
        self.trial
            .injected_tags
            .retain(|tag| rules.iter().any(|(_, live)| live == tag));
        self.trial.rules = rules;
        self.rebuild_visible_trial_rules();
    }

    /// Move the in-flight add's verdict into this session's registry. `Ok`
    /// means the core holds the rule; a failed add may still have landed one,
    /// so both register the tag — Remove must stay reachable for it — and
    /// only a later inventory reply can take it back out. Returns the
    /// `(target, tag)` row of a confirmed add, built from the target captured
    /// at send time (the read-back that would have named it may have failed);
    /// a verdict that is not a confirmation has no row, so its caller drops
    /// the returned value.
    fn register_pending_add_verdict(&mut self) -> Option<(String, String)> {
        let tag = self.trial.pending_add_tag.take()?;
        let target = self.trial.pending_add_target.take();
        if !self.trial.injected_tags.contains(&tag) {
            self.trial.injected_tags.push(tag.clone());
        }
        target.map(|target| (target, tag))
    }

    /// Add one row to the live inventory: a confirmed add the read-back could
    /// not list. Deduplicated by rule tag, so a landed inventory or a second
    /// verdict never doubles the row.
    fn insert_confirmed_trial_rule(&mut self, row: (String, String)) {
        if !self.trial.rules.iter().any(|(_, tag)| tag == &row.1) {
            self.trial.rules.push(row);
        }
    }

    /// Poll both in-flight trial-rule requests' reply channels, if landed.
    /// The slot a result arrives on identifies the operation, so no kind tag
    /// travels alongside it. Every landed inventory identifies exactly which
    /// rules the core holds and is applied before a queued removal's next tag
    /// goes out; a failure leaves the count untouched and surfaces the error
    /// as feedback.
    fn consume_trial_results(&mut self, ctx: &mut UiCtx, lang: Language) {
        if let Some(terminal) = self.trial.pending_add.poll() {
            match terminal {
                Terminal::Answered(Ok(outcome)) => {
                    let confirmed = self.register_pending_add_verdict();
                    match outcome.rules {
                        Some(rules) => {
                            self.apply_trial_inventory(rules);
                            self.trial.feedback = None;
                        }
                        // The core holds the rule, but the read-back after it
                        // failed: the row is added from the target the user
                        // submitted, so the grid and the banner count stay
                        // truthful, and the user learns why the rest of the
                        // list looks stale.
                        None => {
                            if let Some(row) = confirmed {
                                self.insert_confirmed_trial_rule(row);
                            }
                            self.rebuild_visible_trial_rules();
                            self.trial.feedback =
                                Some((true, t(lang, Key::TrialRuleAddedUnlisted).to_string()));
                        }
                    }
                }
                Terminal::Answered(Err(error)) => {
                    // A failed add may still have landed one: the tag stays a
                    // removable candidate, no row is invented, and the error
                    // is the feedback.
                    self.register_pending_add_verdict();
                    self.rebuild_visible_trial_rules();
                    self.trial.feedback = Some((false, error.text(lang)));
                }
                // Closed: defensive — the runtime's reply guard always sends
                // a terminal before the sender drops. The verdict never
                // arrived, so the add is treated like a failed one: the tag
                // stays a removable candidate and no row is invented. (A
                // verdict left in place would block the tag as taken forever.)
                Terminal::Exited => {
                    self.register_pending_add_verdict();
                    self.rebuild_visible_trial_rules();
                }
            }
        }
        if let Some(terminal) = self.trial.pending_inventory.poll() {
            match terminal {
                Terminal::Answered(Ok(rules)) => {
                    self.apply_trial_inventory(rules);
                    self.trial.feedback = None;
                    // A Clear-all batch is driven by its replies: the next
                    // removal goes out only now that this one's inventory
                    // landed and was applied.
                    self.start_queued_trial_removal(ctx, lang);
                }
                // The reply failed: the batch stops here — the tags that
                // still wait keep their rows and stay retryable — and the
                // keyed error is the feedback.
                Terminal::Answered(Err(error)) => {
                    self.trial.remove_queue.clear();
                    self.trial.feedback = Some((false, error.text(lang)));
                }
                // Closed: defensively the same as a failure — a batch must
                // not stay queued on a channel that can never answer.
                Terminal::Exited => self.trial.remove_queue.clear(),
            }
        }
    }

    /// Send the next queued `RemoveTrialRule`, if any. One removal is in
    /// flight at a time, so each reply's refreshed inventory is the state
    /// after that removal landed. A send failure drops the rest of the batch
    /// — the runtime channel is gone, so no later send could succeed — and
    /// surfaces the existing runtime-channel sentence instead of leaving the
    /// queue silently pending.
    fn start_queued_trial_removal(&mut self, ctx: &mut UiCtx, lang: Language) {
        let Some(rule_tag) = self.trial.remove_queue.pop_front() else {
            return;
        };
        let (reply, receiver) = oneshot::channel();
        let sent = ctx
            .cmd
            .send(CoreCmd::RemoveTrialRule { reply, rule_tag })
            .is_ok();
        if sent {
            self.trial.pending_inventory = Request::reply(receiver);
        } else {
            self.trial.remove_queue.clear();
            self.trial.feedback = Some((false, t(lang, Key::RuntimeChannelClosed).to_string()));
        }
    }

    /// True while a trial-rule request is in flight (an add or an inventory
    /// read) or a Clear-all batch still has removals queued: both gates — the
    /// section's buttons and the dialog's Inject — read this, so no operation
    /// can race another's reply and the section stays disabled until the
    /// batch finishes.
    fn trial_busy(&self) -> bool {
        self.trial.pending_add.is_pending()
            || self.trial.pending_inventory.is_pending()
            || !self.trial.remove_queue.is_empty()
    }

    /// The one gate both trial-rule surfaces read: the core must be running
    /// and no trial-rule request (an add, an inventory read, or a queued
    /// removal) may be in flight. The disabled reason is one of two static
    /// strings (`t()` returns `&'static str`), so it is never materialized
    /// into a per-frame `String`; it is attached only while a control is
    /// actually disabled (`on_disabled_hover_text` arguments evaluate
    /// eagerly).
    ///
    /// Trial-rule requests are free queries — the runtime answers them while a
    /// job holds the busy window, so nothing here refuses on the window — and
    /// the ladder is asked without one.
    fn trial_gate(&self, ctx: &UiCtx, lang: Language) -> (bool, Option<&'static str>) {
        let gate = verdict(
            matches!(ctx.phase, CorePhase::Running),
            false,
            self.trial_busy(),
        );
        let reason = match gate.rung {
            Rung::NotRunning => Some(t(lang, Key::TrialRulesNotRunning)),
            Rung::Pending => Some(t(lang, Key::TrialRulesPending)),
            // The gate states no window fact, so the busy rung cannot arise.
            Rung::Ready | Rung::Busy => None,
        };
        (gate.enabled, reason)
    }

    /// Poll the in-flight live outbound-tag read. Success stores the tags the
    /// core holds; any other terminal (a failed read, a spent channel) leaves
    /// the set unknown, so the dialog's target check stays permissive
    /// instead of rejecting a target that may well be live.
    fn poll_live_out_tags(&mut self) {
        if let Some(Terminal::Answered(Ok(view))) = self.trial.pending_live_out.poll() {
            self.trial.live_out_tags =
                Some(view.outbounds.into_iter().map(|entry| entry.tag).collect());
        }
    }

    /// Read the live outbound set once per core phase for an open dialog:
    /// exactly one request in flight, asked only while the set is still
    /// unknown and this phase has not asked yet. The reply is polled per
    /// frame; a failed read leaves the set unknown — the target check stays
    /// permissive — for the rest of the phase, so no frame re-issues the
    /// two-RPC read. [`RoutingScreen::invalidate_trial_rules`] forgets the
    /// attempt, so the next phase reads again.
    fn request_live_out_tags(&mut self, ctx: &mut UiCtx) {
        if self.trial.live_out_tags.is_some()
            || self.trial.pending_live_out.is_pending()
            || self.trial.live_out_requested
        {
            return;
        }
        // The attempt is recorded before the send: a closed channel must not
        // turn into a per-frame retry either.
        self.trial.live_out_requested = true;
        let (reply, receiver) = oneshot::channel();
        if ctx.send(CoreCmd::ListRuntimeState { reply }) {
            self.trial.pending_live_out = Request::reply(receiver);
        }
    }

    /// One trial-rule action the section can send through the runtime.
    fn send_trial_request(&mut self, action: TrialAction, ctx: &mut UiCtx, lang: Language) {
        let (reply, receiver) = oneshot::channel();
        self.trial.feedback = None;
        let sent = match action {
            TrialAction::List => ctx.send(CoreCmd::ListTrialRules { reply }),
            TrialAction::Remove(rule_tag) => ctx.send(CoreCmd::RemoveTrialRule { reply, rule_tag }),
        };
        if sent {
            self.trial.pending_inventory = Request::reply(receiver);
        } else {
            self.trial.feedback = Some((false, t(lang, Key::RuntimeChannelClosed).to_string()));
        }
    }

    fn trial_rules_section(&mut self, ui: &mut Ui, ctx: &mut UiCtx, lang: Language) {
        ui.separator();
        ui.heading(t(lang, Key::TrialRulesSection));
        ui.label(t(lang, Key::TrialRulesExplain));
        let (enabled, disabled_reason) = self.trial_gate(ctx, lang);
        let add_button = |ui: &mut egui::Ui, text: &'static str, enabled: bool| -> egui::Response {
            let button = ui.add_enabled(enabled, egui::Button::new(text));
            match disabled_reason {
                Some(reason) => button.on_disabled_hover_text(reason),
                None => button,
            }
        };
        ui.horizontal(|ui| {
            if add_button(ui, t(lang, Key::TrialRulesAdd), enabled).clicked() {
                self.trial.draft_error = None;
                self.trial.open = true;
            }
            if add_button(ui, t(lang, Key::TrialRulesRefresh), enabled).clicked() {
                self.send_trial_request(TrialAction::List, ctx, lang);
            }
            if add_button(
                ui,
                t(lang, Key::TrialRulesClearAll),
                enabled && !self.trial.injected_tags.is_empty(),
            )
            .clicked()
            {
                // One RemoveTrialRule per injected tag (never committed
                // rules), queued rather than sent at once: the kind is
                // concurrent, so a burst could adopt a read-back taken before
                // another removal landed and keep a tag the core no longer
                // holds. One removal goes out now; each reply starts the next
                // one, and `trial_busy` keeps the section disabled until the
                // queue drains.
                self.trial
                    .remove_queue
                    .extend(self.trial.injected_tags.iter().cloned());
                self.trial.feedback = None;
                self.start_queued_trial_removal(ctx, lang);
            }
        });
        if let Some((ok, message)) = &self.trial.feedback {
            let color = if *ok {
                ui.visuals().weak_text_color()
            } else {
                ui.visuals().error_fg_color
            };
            ui.colored_label(color, message);
        }
        if self.trial.injected_tags.is_empty() {
            ui.label(RichText::new(t(lang, Key::TrialRulesEmpty)).weak());
            return;
        }
        let mut remove_clicked: Option<String> = None;
        egui::Grid::new("trial-rules-grid")
            .num_columns(3)
            .striped(true)
            .show(ui, |ui| {
                ui.strong(t(lang, Key::TrialRuleTag));
                ui.strong(t(lang, Key::GridTag));
                ui.strong("");
                ui.end_row();
                for (target, rule_tag) in &self.trial.visible {
                    ui.monospace(rule_tag);
                    ui.monospace(target);
                    if ui
                        .add_enabled(enabled, egui::Button::new(t(lang, Key::TrialRulesRemove)))
                        .clicked()
                    {
                        remove_clicked = Some(rule_tag.clone());
                    }
                    ui.end_row();
                }
            });
        if let Some(rule_tag) = remove_clicked {
            self.send_trial_request(TrialAction::Remove(rule_tag), ctx, lang);
        }
    }

    /// Validate the dialog draft into a model `Rule` (target + tag +
    /// domains/ips/processes), then run the exact converter the runtime will
    /// use, so grammar errors surface before any request is sent. Each check
    /// ahead of the converter is a draft the core would only reject as a
    /// whole add: a missing, in-use condition set, a target the running core
    /// does not have, or a geodata code the loaded catalogs do not carry.
    fn build_trial_rule(&self, lang: Language) -> Result<Rule, String> {
        let draft = &self.trial.draft;
        let rule_tag = draft.rule_tag.trim();
        if rule_tag.is_empty() {
            return Err(t(lang, Key::TrialRuleTagRequired).to_string());
        }
        // The last landed read-back is not the only authority on a taken tag:
        // this session's registry holds tags the read-back may not list yet
        // (an add whose read-back failed, a removal still in flight) and a
        // request already carries its tag — a duplicate must never reach the
        // core and then look like a success.
        if self.trial.rules.iter().any(|(_, tag)| tag == rule_tag)
            || self.trial.injected_tags.iter().any(|tag| tag == rule_tag)
            || self.trial.pending_add_tag.as_deref() == Some(rule_tag)
        {
            return Err(t(lang, Key::TrialRuleTagTaken).to_string());
        }
        let domain = split_lines(&draft.domains);
        let ip = split_lines(&draft.ips);
        let process = split_lines(&draft.processes);
        if domain.is_empty() && ip.is_empty() && process.is_empty() {
            return Err(t(lang, Key::TrialRuleNeedsCondition).to_string());
        }
        let (outbound_tag, balancer_tag) = if draft.use_balancer {
            (String::new(), draft.balancer_tag.trim().to_string())
        } else {
            (draft.outbound_tag.trim().to_string(), String::new())
        };
        if outbound_tag.is_empty() && balancer_tag.is_empty() {
            return Err(t(lang, Key::TrialRuleTargetRequired).to_string());
        }
        if let Some(live) = &self.trial.live_out_tags
            && !outbound_tag.is_empty()
            && !live.iter().any(|tag| tag == &outbound_tag)
        {
            return Err(t_fmt(lang, Key::TrialRuleTargetNotLive, &[&outbound_tag]));
        }
        self.check_trial_geodata_codes(lang, &domain, &ip)?;
        let rule = Rule {
            rule_tag: rule_tag.to_string(),
            outbound_tag,
            balancer_tag,
            domain,
            ip,
            process,
            ..Default::default()
        };
        crate::rt::grpc::trial_rule_to_pb(&rule).map_err(|error| error.text(lang))?;
        Ok(rule)
    }

    /// Reject a `geosite:`/`geoip:` code the loaded catalog does not carry:
    /// the core resolves a code while it builds the rule condition, so an
    /// unknown one fails the whole add. Every other shape stays permissive —
    /// an `ext:` code names a file the dialog holds no catalog for, an
    /// unloaded or failed load leaves the code space unknown, and an empty
    /// code is left to the converter's own check. A leading `!` (the reverse
    /// prefix) is stripped first, exactly as the runtime's parser does, so a
    /// negated code is checked too. The `@attr` suffix is not part of the
    /// code, and catalog codes compare case-insensitively.
    fn check_trial_geodata_codes(
        &self,
        lang: Language,
        domain: &[String],
        ip: &[String],
    ) -> Result<(), String> {
        let Some(snapshot) = &self.geodata_snapshot else {
            return Ok(());
        };
        for (kind, entries) in [
            (GeodataPickerKind::Geosite, domain),
            (GeodataPickerKind::Geoip, ip),
        ] {
            let Ok(catalog) = kind.catalog(snapshot) else {
                continue;
            };
            for entry in entries {
                // The runtime's parsers strip every leading `!` (the reverse
                // prefix the IP hint documents) before they read a code, so
                // the check reads the same entry; an entry that is nothing
                // but the prefix leaves no code and stays unchecked.
                let entry = entry.trim_start_matches('!');
                let Some(rest) = entry.strip_prefix(kind.prefix()) else {
                    continue;
                };
                if rest.starts_with("ext:") {
                    continue;
                }
                let code = rest.split_once('@').map_or(rest, |(code, _)| code);
                if code.is_empty()
                    || catalog
                        .codes
                        .iter()
                        .any(|known| known.eq_ignore_ascii_case(code))
                {
                    continue;
                }
                return Err(t_fmt(lang, Key::TrialRuleCodeUnknown, &[&code]));
            }
        }
        Ok(())
    }

    fn trial_rule_dialog(&mut self, ui: &mut Ui, ctx: &mut UiCtx) {
        let lang = ctx.settings.language;
        if !self.trial.open {
            return;
        }
        let running = matches!(ctx.phase, CorePhase::Running);
        if running {
            // The target check needs the core's live outbound tags; ask once
            // while they are unknown (the poll runs in `show`).
            self.request_live_out_tags(ctx);
        }
        let (gate_open, disabled_reason) = self.trial_gate(ctx, lang);
        let mut close = false;
        let mut inject = false;
        egui::Window::new(t(lang, Key::TrialRulesWindow))
            .open(&mut self.trial.open)
            .collapsible(false)
            .resizable(false)
            .show(ui.ctx(), |ui| {
                let draft = &mut self.trial.draft;
                if let Some(error) = &self.trial.draft_error {
                    ui.colored_label(ui.visuals().error_fg_color, error);
                    ui.separator();
                }
                ui.label(t(lang, Key::TrialRuleTag));
                ui.add(egui::TextEdit::singleline(&mut draft.rule_tag).desired_width(220.0));
                ui.label(RichText::new(t(lang, Key::TrialRuleTagHint)).weak());
                ui.separator();
                ui.label(t(lang, Key::TrialRuleTarget));
                ui.horizontal(|ui| {
                    ui.selectable_value(
                        &mut draft.use_balancer,
                        false,
                        t(lang, Key::TrialRulesOutbound),
                    );
                    ui.selectable_value(
                        &mut draft.use_balancer,
                        true,
                        t(lang, Key::TrialRulesBalancer),
                    );
                });
                let view = self.view_cache.as_ref();
                if !draft.use_balancer {
                    egui::ComboBox::from_id_salt("trial-target-outbound")
                        .selected_text(if draft.outbound_tag.is_empty() {
                            t(lang, Key::NoneSelected)
                        } else {
                            draft.outbound_tag.as_str()
                        })
                        .show_ui(ui, |ui| {
                            if let Some(view) = view {
                                for tag in &view.out_tags {
                                    ui.selectable_value(&mut draft.outbound_tag, tag.clone(), tag);
                                }
                            }
                        });
                } else {
                    egui::ComboBox::from_id_salt("trial-target-balancer")
                        .selected_text(if draft.balancer_tag.is_empty() {
                            t(lang, Key::NoneSelected)
                        } else {
                            draft.balancer_tag.as_str()
                        })
                        .show_ui(ui, |ui| {
                            if let Some(view) = view {
                                for tag in &view.bal_tags {
                                    ui.selectable_value(&mut draft.balancer_tag, tag.clone(), tag);
                                }
                            }
                        });
                }
                ui.label(
                    RichText::new(t(lang, Key::TrialRulesOrderHint))
                        .small()
                        .weak(),
                );
                ui.separator();
                ui.label(t(lang, Key::TrialRuleDomains));
                ui.add(
                    egui::TextEdit::multiline(&mut draft.domains)
                        .desired_width(260.0)
                        .desired_rows(3),
                );
                ui.label(RichText::new(t(lang, Key::TrialRuleDomainsHint)).weak());
                ui.label(t(lang, Key::TrialRuleIps));
                ui.add(
                    egui::TextEdit::multiline(&mut draft.ips)
                        .desired_width(260.0)
                        .desired_rows(3),
                );
                ui.label(RichText::new(t(lang, Key::TrialRuleIpsHint)).weak());
                ui.label(t(lang, Key::TrialRuleProcesses));
                ui.add(
                    egui::TextEdit::multiline(&mut draft.processes)
                        .desired_width(260.0)
                        .desired_rows(2),
                );
                ui.separator();
                ui.horizontal(|ui| {
                    // The same gate as the section's buttons.
                    let inject_label = t(lang, Key::TrialRulesInject);
                    let clicked = if gate_open {
                        ui.button(inject_label).clicked()
                    } else {
                        let button = ui.add_enabled(false, egui::Button::new(inject_label));
                        let button = match disabled_reason {
                            Some(reason) => button.on_disabled_hover_text(reason),
                            None => button,
                        };
                        button.clicked()
                    };
                    if clicked {
                        inject = true;
                    }
                    if ui.button(t(lang, Key::Close)).clicked() {
                        close = true;
                    }
                });
            });
        if inject {
            match self.build_trial_rule(lang) {
                Err(error) => self.trial.draft_error = Some(error),
                Ok(rule) => {
                    self.trial.draft_error = None;
                    let (reply, receiver) = oneshot::channel();
                    self.trial.feedback = None;
                    // The tag and the submitted target travel with the
                    // request: a confirmed add whose read-back fails still
                    // produces a row and a removable tag.
                    let target_tag = if rule.balancer_tag.is_empty() {
                        rule.outbound_tag.clone()
                    } else {
                        rule.balancer_tag.clone()
                    };
                    self.trial.pending_add_tag = Some(rule.rule_tag.clone());
                    self.trial.pending_add_target = Some(target_tag);
                    if ctx
                        .cmd
                        .send(CoreCmd::AddTrialRule {
                            reply,
                            rule: Box::new(rule),
                        })
                        .is_err()
                    {
                        self.trial.pending_add_tag = None;
                        self.trial.pending_add_target = None;
                        self.trial.feedback =
                            Some((false, t(lang, Key::RuntimeChannelClosed).to_string()));
                    } else {
                        self.trial.pending_add = Request::reply(receiver);
                    }
                }
            }
        }
        if close {
            self.trial.open = false;
        }
    }

    /// Borrow (creating on demand) the live runtime UI state for one
    /// balancer tag. The per-frame editor calls this to persist UI state
    /// across frames; an insert is a real mutation, but the map's own length
    /// is the size the tests read — idle frames never insert, so they never
    /// grow it.
    fn balancer_runtime_state<'a>(
        runtime: &'a mut BTreeMap<String, BalancerRuntimeUi>,
        tag: &str,
    ) -> &'a mut BalancerRuntimeUi {
        runtime.entry(tag.to_string()).or_default()
    }

    /// Evict-absent: drop balancer-runtime entries whose
    /// tag is absent from the current routing model, mirroring the
    /// traffic-stats baseline eviction in `rt::fold_traffic`, so the map
    /// stays bounded by the live balancer set across add/remove/rename
    /// churn. Live state (pending request, info, feedback, target draft)
    /// for tags still present is untouched. Runs on model change — never
    /// per frame — so the map's own length stays bounded by the live
    /// balancer set.
    fn evict_stale_balancer_runtime(&mut self, settings: &Settings) {
        self.balancer_runtime.retain(|tag, _| {
            settings
                .routing
                .balancers
                .iter()
                .any(|balancer| balancer.tag == *tag)
        });
    }

    /// Rebuild the derived UI data (tag vectors, rule-row text, balancer
    /// reference counts, TestRoute inbound options) only when the model
    /// generation or the language changed; idle frames reuse the cached
    /// snapshot, and the cache's own generation key is what the tests pin as
    /// the rebuild decision.
    /// Also evicts balancer-runtime entries absent from the model — the
    /// generation change is the model-change signal, so
    /// the eviction pass runs once per change, never per frame.
    fn refresh_view_cache(
        &mut self,
        generation: u64,
        lang: Language,
        servers: &ServersFile,
        settings: &Settings,
    ) {
        let generation = (generation, lang);
        if matches!(&self.view_cache, Some(cache) if cache.generation == generation) {
            return;
        }

        // A balancer removed or renamed — here, or persisted from another
        // screen (config_revision) — must not leave its runtime entry
        // resident for the session.
        self.evict_stale_balancer_runtime(settings);

        // Outbound tags offered as rule targets: every profile in list order
        // (the document's first outbound is the active profile, so the menu
        // and the wire order agree) then the built-in freedom "direct" and
        // blackhole "block". Deliberately narrower than
        // `emit::outbound_tags`: that answers which tags the *document*
        // carries, and it also counts the internal `dns-out` DNS-module
        // outbound — never a traffic target, the same reason the inbound
        // lists never offer the api/in-tun/dns-in listeners.
        let out_tags: Vec<String> = servers
            .profiles
            .iter()
            .map(ServerProfile::tag)
            .chain(
                emit::BUILTIN_OUTBOUNDS
                    .iter()
                    .map(|(_, tag)| (*tag).to_string()),
            )
            .collect();
        // Whether the document carries a server outbound: every profile emits
        // an outbound unconditionally and every profile tag is `srv-…`, so the
        // fact is whether the state has profiles at all. The two prefix checks
        // below ask this — a selector only ever matches a tag that reaches the
        // wire, which the menu vector above is deliberately narrower than.
        let server_outbound_emitted = !servers.profiles.is_empty();
        let bal_tags: Vec<String> = settings
            .routing
            .balancers
            .iter()
            .filter(|balancer| !balancer.tag.is_empty())
            .map(|balancer| balancer.tag.clone())
            .collect();
        let balancer_tags: Vec<String> = settings
            .routing
            .balancers
            .iter()
            .map(|balancer| balancer.tag.clone())
            .collect();
        let rule_rows = settings
            .routing
            .rules
            .iter()
            .map(|rule| RuleRowText {
                short_tag: rule.rule_tag.chars().take(8).collect(),
                summary: rule_summary(lang, rule),
                target_line: rule_target_line(lang, rule),
            })
            .collect();
        // A linear rule scan per balancer — computed here (once per
        // generation), never per frame.
        let reference_counts: Vec<usize> = settings
            .routing
            .balancers
            .iter()
            .map(|balancer| settings.routing.balancer_reference_count(&balancer.tag))
            .collect();
        // Balancer row headers format next to the reference counts, on the
        // same generation cadence: strategy caption, optional selector
        // summary, and the two reference-count notes are per-row `t_fmt` /
        // `one_plus` output that must not run per frame.
        let balancer_headers: Vec<BalancerHeaderText> = settings
            .routing
            .balancers
            .iter()
            .zip(&reference_counts)
            .map(|(balancer, &references)| {
                let strategy_label: &str = if balancer.strategy.r#type.is_empty() {
                    "random"
                } else {
                    balancer.strategy.r#type.as_str()
                };
                BalancerHeaderText {
                    strategy: t_fmt(lang, Key::BalancerStrategy, &[&strategy_label]),
                    selector: (!balancer.selector.is_empty()).then(|| {
                        t_fmt(
                            lang,
                            Key::BalancerSelector,
                            &[&one_plus(&balancer.selector)],
                        )
                    }),
                    used_by: t_fmt(lang, Key::BalancerUsedBy, &[&references]),
                    delete_blocked: t_fmt(lang, Key::BalancerDeleteBlocked, &[&references]),
                }
            })
            .collect();
        // TestRoute dialog inbound options: every local endpoint tag (all
        // entries, list order) plus the built-in tun/dns/api listeners and
        // every dokodemo tag. A different question than `emit::inbound_tags`:
        // a trial rule may name a listener that is switched off right now —
        // the dialog offers it, and the core answers for the tags it does not
        // know — so disabled entries stay in this list on purpose.
        let known_inbounds: Vec<String> = settings
            .local_inbounds
            .iter()
            .map(|entry| entry.tag.clone())
            .chain(
                [TUN_INBOUND_TAG, DNS_INBOUND_TAG, API_INBOUND_TAG]
                    .into_iter()
                    .map(str::to_string),
            )
            .chain(settings.dokodemo.iter().map(|entry| entry.tag.clone()))
            .collect();
        // One `assess` per model generation, in the same rebuild as the
        // reference counts — never a second recomputation pattern and never
        // per frame (the inbounds ValidationCache precedent). Only the
        // balancer breakage paths are consumed here; the other screens own
        // their own paths.
        let findings = SafetyVerdicts::of(servers, settings);
        let balancer_warnings: Vec<Option<String>> = (0..settings.routing.balancers.len())
            .map(|index| {
                findings
                    .balancer_breakage(index)
                    .map(|finding| safety_message(&finding.code, lang))
            })
            .collect();

        self.view_cache = Some(RoutingViewCache {
            generation,
            out_tags,
            server_outbound_emitted,
            bal_tags,
            balancer_tags,
            rule_rows,
            reference_counts,
            balancer_headers,
            balancer_warnings,
            known_inbounds,
        });
    }

    // ---------- rules ----------

    fn rules_section(&mut self, ui: &mut Ui, ctx: &mut UiCtx, lang: Language, changed: &mut bool) {
        widgets::section(ui, t(lang, Key::RoutingRulesSection), |ui| {
            let mut delete: Option<usize> = None;
            let mut swap: Option<(usize, usize)> = None;

            {
                let rules = &mut ctx.settings.routing.rules;
                let n = rules.len();
                for (i, rule) in rules.iter_mut().enumerate() {
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            if ui
                                .add_enabled(i > 0, egui::Button::new("▲").small())
                                .on_hover_text(t(lang, Key::RoutingMoveUp))
                                .clicked()
                            {
                                swap = Some((i, i - 1));
                            }
                            if ui
                                .add_enabled(i + 1 < n, egui::Button::new("▼").small())
                                .on_hover_text(t(lang, Key::RoutingMoveDown))
                                .clicked()
                            {
                                swap = Some((i, i + 1));
                            }
                            let row = &self
                                .view_cache
                                .as_ref()
                                .expect("view cache populated above")
                                .rule_rows[i];
                            ui.monospace(&row.short_tag).on_hover_text(&rule.rule_tag);
                            ui.label(&row.summary);
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui
                                        .small_button(t(lang, Key::DeleteRow))
                                        .on_hover_text(t(lang, Key::RoutingDeleteRule))
                                        .clicked()
                                    {
                                        delete = Some(i);
                                    }
                                    let open = self.edit_rule == Some(i);
                                    if ui
                                        .small_button(if open { "▾" } else { "▸" })
                                        .on_hover_text(t(lang, Key::RoutingEditRule))
                                        .clicked()
                                    {
                                        self.edit_rule = if open { None } else { Some(i) };
                                    }
                                    let rt = if row.target_line.is_empty() {
                                        RichText::new(t(lang, Key::RoutingNoTarget))
                                            .color(ui.visuals().warn_fg_color)
                                    } else {
                                        RichText::new(&row.target_line).strong()
                                    };
                                    ui.label(rt);
                                },
                            );
                        });
                        if self.edit_rule == Some(i) {
                            *changed |= self.rule_editor(ui, lang, rule);
                        }
                    });
                }
                if n == 0 {
                    ui.label(RichText::new(t(lang, Key::RoutingNoRules)).weak());
                }
            }

            if let Some((a, b)) = swap {
                ctx.settings.routing.rules.swap(a, b);
                if self.edit_rule == Some(a) {
                    self.edit_rule = Some(b);
                } else if self.edit_rule == Some(b) {
                    self.edit_rule = Some(a);
                }
                *changed = true;
            }
            if let Some(i) = delete {
                ctx.settings.routing.rules.remove(i);
                self.edit_rule = match self.edit_rule {
                    Some(e) if e == i => None,
                    Some(e) if e > i => Some(e - 1),
                    e => e,
                };
                *changed = true;
            }
            if ui.button(t(lang, Key::RoutingAddRule)).clicked() {
                ctx.settings.routing.rules.push(Rule::new());
                self.edit_rule = Some(ctx.settings.routing.rules.len() - 1);
                *changed = true;
            }
        });
    }

    /// Inline editor covering every `Rule` model field. Returns true on change.
    fn rule_editor(&mut self, ui: &mut Ui, lang: Language, rule: &mut Rule) -> bool {
        let mut changed = false;

        // PortList fields are edited through commit-gated buffers: an
        // invalid list (bad token, out-of-range port, empty token) renders
        // an inline error and never writes the model, so it cannot reach a
        // saved or applied config. Buffers are keyed by rule
        // tag, like the attrs buffer. The tag is read off the model at
        // each id/buffer site (never cloned into a local for the frame),
        // and only a freshly seeded buffer owns a copy.
        if !matches!(&self.port_bufs, Some((t, _)) if *t == rule.rule_tag) {
            self.port_bufs = Some((
                rule.rule_tag.clone(),
                RulePortBuf {
                    port: rule.port.clone(),
                    source_port: rule.source_port.clone(),
                    local_port: rule.local_port.clone(),
                    vless_route: rule.vless_route.clone(),
                },
            ));
        }
        let port_error = |s: &str| {
            (!valid_port_list(s)).then(|| t(lang, Key::RoutingPortListInvalid).to_string())
        };

        egui::Grid::new(("rule-edit", rule.rule_tag.as_str()))
            .num_columns(2)
            .spacing([16.0, 4.0])
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(t(lang, Key::RuleTag));
                    ui.monospace(&rule.rule_tag)
                        .on_hover_text(t(lang, Key::RuleTagHint));
                });
                changed |= widgets::combo_str(
                    ui,
                    t(lang, Key::Network),
                    ("net", rule.rule_tag.as_str()),
                    &mut rule.network,
                    &["tcp", "udp", "tcp,udp"],
                    t(lang, Key::Any),
                    true,
                );
                ui.end_row();

                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(t(lang, Key::Domains));
                        changed |= self.geodata_picker_menu(
                            ui,
                            lang,
                            GeodataPickerKind::Geosite,
                            &mut rule.domain,
                        );
                    });
                    self.geodata_diagnostic(ui, lang, GeodataPickerKind::Geosite);
                    changed |= widgets::string_list(
                        ui,
                        lang,
                        "",
                        &mut rule.domain,
                        t(lang, Key::DomainsHint),
                    );
                });
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(t(lang, Key::Ips));
                        changed |= self.geodata_picker_menu(
                            ui,
                            lang,
                            GeodataPickerKind::Geoip,
                            &mut rule.ip,
                        );
                    });
                    self.geodata_diagnostic(ui, lang, GeodataPickerKind::Geoip);
                    changed |=
                        widgets::string_list(ui, lang, "", &mut rule.ip, t(lang, Key::IpsHint));
                    if let Some(message) = ip_list_error(lang, &rule.ip) {
                        ui.horizontal(|ui| {
                            ui.add_space(ui.spacing().indent);
                            ui.colored_label(
                                status_colors_of(ui).err,
                                RichText::new(message).small(),
                            );
                        });
                    }
                });
                ui.end_row();

                if let Some((_, buf)) = &mut self.port_bufs {
                    if widgets::validated_field(
                        ui,
                        t(lang, Key::Port),
                        &mut buf.port,
                        t(lang, Key::PortHint),
                        port_error,
                    ) && valid_port_list(&buf.port)
                    {
                        rule.port = buf.port.clone();
                        changed = true;
                    }
                    if widgets::validated_field(
                        ui,
                        t(lang, Key::SourcePort),
                        &mut buf.source_port,
                        t(lang, Key::SourcePortHint),
                        port_error,
                    ) && valid_port_list(&buf.source_port)
                    {
                        rule.source_port = buf.source_port.clone();
                        changed = true;
                    }
                }
                ui.end_row();

                if let Some((_, buf)) = &mut self.port_bufs
                    && widgets::validated_field(
                        ui,
                        t(lang, Key::LocalPort),
                        &mut buf.local_port,
                        t(lang, Key::LocalPortHint),
                        port_error,
                    )
                    && valid_port_list(&buf.local_port)
                {
                    rule.local_port = buf.local_port.clone();
                    changed = true;
                }
                changed |= widgets::string_list(
                    ui,
                    lang,
                    t(lang, Key::InboundTags),
                    &mut rule.inbound_tag,
                    t(lang, Key::InboundTagsHint),
                );
                ui.end_row();

                changed |= widgets::string_list(
                    ui,
                    lang,
                    t(lang, Key::SourceIps),
                    &mut rule.source,
                    t(lang, Key::SourceIpsHint),
                );
                if let Some(message) = ip_list_error(lang, &rule.source) {
                    ui.horizontal(|ui| {
                        ui.add_space(ui.spacing().indent);
                        ui.colored_label(status_colors_of(ui).err, RichText::new(message).small());
                    });
                }
                changed |= widgets::string_list(
                    ui,
                    lang,
                    t(lang, Key::LocalIps),
                    &mut rule.local_ip,
                    t(lang, Key::LocalIpsHint),
                );
                if let Some(message) = ip_list_error(lang, &rule.local_ip) {
                    ui.horizontal(|ui| {
                        ui.add_space(ui.spacing().indent);
                        ui.colored_label(status_colors_of(ui).err, RichText::new(message).small());
                    });
                }
                ui.end_row();

                changed |= widgets::string_list(
                    ui,
                    lang,
                    t(lang, Key::Protocols),
                    &mut rule.protocol,
                    t(lang, Key::ProtocolsHint),
                );
                ui.end_row();

                changed |= widgets::string_list(
                    ui,
                    lang,
                    t(lang, Key::Processes),
                    &mut rule.process,
                    t(lang, Key::ProcessesHint),
                );
                if let Some((_, buf)) = &mut self.port_bufs
                    && widgets::validated_field(
                        ui,
                        t(lang, Key::VlessRoute),
                        &mut buf.vless_route,
                        t(lang, Key::VlessRouteHint),
                        port_error,
                    )
                    && valid_port_list(&buf.vless_route)
                {
                    rule.vless_route = buf.vless_route.clone();
                    changed = true;
                }
                ui.end_row();

                changed |= widgets::string_list(
                    ui,
                    lang,
                    t(lang, Key::LocalOs),
                    &mut rule.local_os,
                    t(lang, Key::LocalOsHint),
                );
                ui.end_row();
            });

        // attrs: map key → regexp matched against HTTP sniff headers.
        ui.label(RichText::new(t(lang, Key::Attrs)).small().weak());
        if !matches!(&self.attrs_buf, Some((t, _)) if *t == rule.rule_tag) {
            self.attrs_buf = Some((rule.rule_tag.clone(), kv_from_map(&rule.attrs)));
        }
        if let Some((_, buf)) = &mut self.attrs_buf
            && widgets::kv_table(
                ui,
                lang,
                buf,
                t(lang, Key::AttrsKeyHint),
                t(lang, Key::AttrsValueHint),
            )
        {
            rule.attrs = map_from_kv(buf);
            changed = true;
        }

        // webhook sub-form
        ui.horizontal(|ui| {
            let mut on = rule.webhook.is_some();
            if ui
                .checkbox(&mut on, t(lang, Key::WebhookOnMatch))
                .on_hover_text(t(lang, Key::WebhookOnMatchHint))
                .changed()
            {
                rule.webhook = on.then(Webhook::default);
                changed = true;
            }
        });
        if let Some(wh) = rule.webhook.as_mut() {
            ui.indent(("wh", rule.rule_tag.as_str()), |ui| {
                changed |=
                    widgets::text_field(ui, t(lang, Key::Url), &mut wh.url, t(lang, Key::UrlHint));
                changed |= widgets::opt_u32(
                    ui,
                    t(lang, Key::Deduplication),
                    &mut wh.deduplication,
                    0..=86_400,
                );
                if !matches!(&self.headers_buf, Some((t, _)) if *t == rule.rule_tag) {
                    self.headers_buf = Some((rule.rule_tag.clone(), kv_from_map(&wh.headers)));
                }
                ui.label(RichText::new(t(lang, Key::Headers)).small().weak());
                if let Some((_, buf)) = &mut self.headers_buf
                    && widgets::kv_table(
                        ui,
                        lang,
                        buf,
                        t(lang, Key::HeadersKeyHint),
                        t(lang, Key::HeadersValueHint),
                    )
                {
                    wh.headers = map_from_kv(buf);
                    changed = true;
                }
            });
        }

        // target: exactly one of outbound_tag / balancer_tag (UI-enforced).
        ui.horizontal(|ui| {
            ui.label(t(lang, Key::Target));
            let is_balancer = !rule.balancer_tag.is_empty();
            if ui.radio(!is_balancer, t(lang, Key::Outbound)).clicked() {
                rule.balancer_tag.clear();
                if rule.outbound_tag.is_empty() {
                    rule.outbound_tag = self
                        .view_cache
                        .as_ref()
                        .expect("view cache populated above")
                        .out_tags
                        .iter()
                        .find(|tag| tag.as_str() == DIRECT_OUTBOUND_TAG)
                        .cloned()
                        .unwrap_or_default();
                }
                changed = true;
            }
            let balancer_response = ui
                .add_enabled(
                    !self
                        .view_cache
                        .as_ref()
                        .expect("view cache populated above")
                        .bal_tags
                        .is_empty(),
                    egui::RadioButton::new(is_balancer, t(lang, Key::Balancer)),
                )
                .on_disabled_hover_text(t(lang, Key::BalancerNeededHint));
            if balancer_response.clicked() {
                rule.outbound_tag.clear();
                rule.balancer_tag = self
                    .view_cache
                    .as_ref()
                    .expect("view cache populated above")
                    .bal_tags[0]
                    .clone();
                changed = true;
            }
        });
        ui.horizontal(|ui| {
            if rule.balancer_tag.is_empty() {
                changed |= widgets::combo_str(
                    ui,
                    t(lang, Key::Outbound),
                    ("out", rule.rule_tag.as_str()),
                    &mut rule.outbound_tag,
                    &self
                        .view_cache
                        .as_ref()
                        .expect("view cache populated above")
                        .out_tags,
                    t(lang, Key::Any),
                    false,
                );
            } else if self
                .view_cache
                .as_ref()
                .expect("view cache populated above")
                .bal_tags
                .is_empty()
            {
                ui.label(
                    RichText::new(t(lang, Key::NoBalancers)).color(ui.visuals().warn_fg_color),
                );
            } else {
                changed |= widgets::combo_str(
                    ui,
                    t(lang, Key::Balancer),
                    ("bal", rule.rule_tag.as_str()),
                    &mut rule.balancer_tag,
                    &self
                        .view_cache
                        .as_ref()
                        .expect("view cache populated above")
                        .bal_tags,
                    t(lang, Key::Any),
                    false,
                );
            }
        });
        if let Some(error) = rule.target_error() {
            ui.horizontal(|ui| {
                ui.label(RichText::new(error.text(lang)).color(ui.visuals().error_fg_color));
                if ui.small_button(t(lang, Key::UseDirect)).clicked() {
                    rule.outbound_tag = DIRECT_OUTBOUND_TAG.into();
                    rule.balancer_tag.clear();
                    changed = true;
                }
            });
        }

        changed
    }

    fn start_geodata_load(&mut self, lang: Language, repaint: egui::Context) -> bool {
        if self.geodata_load_state.is_loading() {
            return false;
        }
        match Request::worker("broccoli-geodata-loader", &repaint, |_| {
            Some(GeodataSnapshot::load_managed())
        }) {
            Ok(request) => {
                self.geodata_load_state = GeodataLoadState::Loading(request);
                true
            }
            Err(error) => {
                self.geodata_load_state =
                    GeodataLoadState::Failed(t_fmt(lang, Key::GeodataLoaderFailed, &[&error]));
                false
            }
        }
    }

    fn poll_geodata_load(&mut self, lang: Language) {
        let outcome = match &mut self.geodata_load_state {
            GeodataLoadState::Loading(request) => match request.poll() {
                Some(Terminal::Answered(snapshot)) => Some(Some(snapshot)),
                Some(Terminal::Exited) => Some(None),
                None => None,
            },
            GeodataLoadState::Idle | GeodataLoadState::Ready | GeodataLoadState::Failed(_) => None,
        };
        if let Some(snapshot) = outcome {
            match snapshot {
                Some(snapshot) => {
                    self.geodata_snapshot = Some(snapshot);
                    // A new catalog invalidates both search memos: an open
                    // picker rescans against it exactly once on its next frame.
                    self.geodata_revision += 1;
                    self.geodata_load_state = GeodataLoadState::Ready;
                }
                None => {
                    self.geodata_load_state =
                        GeodataLoadState::Failed(t(lang, Key::GeodataLoaderStopped).to_owned());
                }
            }
        }
    }

    fn geodata_picker_menu(
        &mut self,
        ui: &mut Ui,
        lang: Language,
        kind: GeodataPickerKind,
        rule_values: &mut Vec<String>,
    ) -> bool {
        let mut changed = false;
        ui.menu_button(kind.button_label(lang), |ui| {
            if matches!(self.geodata_load_state, GeodataLoadState::Idle) {
                self.start_geodata_load(lang, ui.ctx().clone());
            }

            ui.set_min_width(320.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new(kind.file_name()).strong());
                let loading = self.geodata_load_state.is_loading();
                if loading {
                    ui.spinner();
                    ui.label(RichText::new(t(lang, Key::GeodataLoading)).small().weak());
                }
                if ui
                    .add_enabled(
                        !loading,
                        egui::Button::new(t(lang, Key::GeodataRefresh)).small(),
                    )
                    .on_disabled_hover_text(t(lang, Key::GeodataRefreshBusy))
                    .clicked()
                {
                    self.start_geodata_load(lang, ui.ctx().clone());
                }
            });
            if let GeodataLoadState::Failed(error) = &self.geodata_load_state {
                ui.label(
                    RichText::new(error)
                        .small()
                        .color(ui.visuals().error_fg_color),
                );
            }

            let Some(snapshot) = self.geodata_snapshot.as_ref() else {
                ui.label(RichText::new(t(lang, Key::GeodataReading)).small().weak());
                return;
            };
            match kind.catalog(snapshot) {
                Err(error) => {
                    ui.label(
                        RichText::new(error.text(lang))
                            .small()
                            .color(ui.visuals().error_fg_color),
                    );
                }
                Ok(catalog) => {
                    let codes_bytes = ui.label(
                        RichText::new(t_fmt(
                            lang,
                            Key::GeodataCodesBytes,
                            &[&catalog.codes.len(), &catalog.metadata.byte_len],
                        ))
                        .small()
                        .weak(),
                    );
                    // The modified-time hover needs two String builds (path
                    // display + SystemTime debug) plus a `t_fmt`; egui
                    // evaluates `on_hover_text` arguments eagerly on every
                    // open-menu frame, so the tooltip is attached only on
                    // the frames the label is actually hovered.
                    // The popup renders only while open and pointer
                    // motion over the label is an interaction frame, which
                    // bounds the hover build to interaction.
                    if codes_bytes.hovered() {
                        let path = catalog.metadata.path.display().to_string();
                        let modified = catalog
                            .metadata
                            .modified
                            .as_ref()
                            .map(|modified| format!("{modified:?}"))
                            .unwrap_or_else(|| t(lang, Key::GeodataModifiedUnavailable).to_owned());
                        codes_bytes.on_hover_text(t_fmt(
                            lang,
                            Key::GeodataModified,
                            &[&path, &modified],
                        ));
                    }

                    let search = match kind {
                        GeodataPickerKind::Geosite => &mut self.geosite_search,
                        GeodataPickerKind::Geoip => &mut self.geoip_search,
                    };
                    ui.add(
                        egui::TextEdit::singleline(search)
                            .hint_text(t(lang, Key::GeodataSearch))
                            .desired_width(f32::INFINITY),
                    );
                    ui.separator();

                    let query = search.trim();
                    let row_height = ui.spacing().interact_size.y;
                    let mut selected = None;
                    if query.is_empty() {
                        egui::ScrollArea::vertical()
                            .id_salt(ui.auto_id_with(kind.file_name()))
                            .max_height(260.0)
                            .show_rows(ui, row_height, catalog.codes.len(), |ui, rows| {
                                for code in &catalog.codes[rows] {
                                    if ui.selectable_label(false, code.as_str()).clicked() {
                                        selected = Some(code.as_str());
                                    }
                                }
                            });
                    } else {
                        // Scan only when the query text or the dataset changed;
                        // identical renders reuse the memoized match indices.
                        let memo = match kind {
                            GeodataPickerKind::Geosite => &mut self.geosite_search_memo,
                            GeodataPickerKind::Geoip => &mut self.geoip_search_memo,
                        };
                        let matches = geodata_search_matches(
                            memo,
                            self.geodata_revision,
                            &catalog.codes,
                            query,
                        );
                        if matches.is_empty() {
                            ui.label(RichText::new(t(lang, Key::GeodataNoMatches)).weak());
                        } else {
                            egui::ScrollArea::vertical()
                                .id_salt(ui.auto_id_with(kind.file_name()))
                                .max_height(260.0)
                                .show_rows(ui, row_height, matches.len(), |ui, rows| {
                                    for &index in &matches[rows] {
                                        let code = catalog.codes[index as usize].as_str();
                                        if ui.selectable_label(false, code).clicked() {
                                            selected = Some(code);
                                        }
                                    }
                                });
                        }
                    }

                    if let Some(code) = selected {
                        let value = format!("{}{code}", kind.prefix());
                        if !rule_values.iter().any(|existing| existing == &value) {
                            rule_values.push(value);
                            changed = true;
                        }
                        ui.close();
                    }
                }
            }
        });
        changed
    }

    fn geodata_diagnostic(&self, ui: &mut Ui, lang: Language, kind: GeodataPickerKind) {
        let Some(snapshot) = &self.geodata_snapshot else {
            return;
        };
        let Err(error) = kind.catalog(snapshot) else {
            return;
        };
        ui.label(
            RichText::new(error.text(lang))
                .small()
                .color(ui.visuals().error_fg_color),
        );
    }

    fn consume_balancer_results(&mut self, lang: Language) {
        // Receivers live on the per-tag entries, so a result can only reach
        // the entry that requested it: polling each entry's own pending
        // receiver is structural pairing — a stale result cannot reach a
        // newer request, and an entry evicted mid-flight takes its receiver
        // down with it, discarding the result.
        for state in self.balancer_runtime.values_mut() {
            let Some(pending) = state.pending_request.take() else {
                continue;
            };
            match pending {
                BalancerPending::Info { mut request } => match request.poll() {
                    Some(terminal) => match terminal {
                        Terminal::Answered(Ok(info)) => {
                            state.info = Some(info);
                            state.info_generation = state.info_generation.wrapping_add(1);
                            state.feedback =
                                Some((true, t(lang, Key::RuntimeStateRefreshed).into()));
                        }
                        Terminal::Answered(Err(error)) => {
                            state.feedback = Some((false, error.text(lang)))
                        }
                        // Closed: defensive — the runtime's reply guard
                        // always sends a terminal before the sender drops.
                        Terminal::Exited => {}
                    },
                    // Still in flight; keep waiting.
                    None => {
                        state.pending_request = Some(BalancerPending::Info { request });
                    }
                },
                BalancerPending::Mutate {
                    target,
                    mut request,
                } => match request.poll() {
                    Some(terminal) => match terminal {
                        Terminal::Answered(Ok(())) => {
                            if state.info.is_none() {
                                // The override echo creates the snapshot: a
                                // fresh default carries no targets, so the
                                // memoized principle-targets line must be
                                // rebuilt for it.
                                state.info = Some(BalancerInfoView::default());
                                state.info_generation = state.info_generation.wrapping_add(1);
                            }
                            if let Some(info) = state.info.as_mut() {
                                info.override_target = target.clone();
                            }
                            let message = match target {
                                Some(target) => {
                                    t_fmt(lang, Key::RoutingOverrideApplied, &[&target])
                                }
                                None => t(lang, Key::RoutingOverrideCleared).to_string(),
                            };
                            state.feedback = Some((true, message));
                        }
                        Terminal::Answered(Err(error)) => {
                            state.feedback = Some((false, error.text(lang)))
                        }
                        // Closed: defensive — the runtime's reply guard
                        // always sends a terminal before the sender drops.
                        Terminal::Exited => {}
                    },
                    // Still in flight; keep waiting.
                    None => {
                        state.pending_request = Some(BalancerPending::Mutate { target, request });
                    }
                },
            }
        }
    }

    fn balancer_runtime_controls(
        &mut self,
        ui: &mut Ui,
        lang: Language,
        control: &RuntimeControl<'_>,
        tag: &str,
    ) {
        ui.separator();
        ui.label(RichText::new(t(lang, Key::RuntimeOverrideTitle)).strong());
        ui.label(
            RichText::new(t(lang, Key::RuntimeOverrideEphemeral))
                .small()
                .weak(),
        );
        // Why the core can reject a balancer tag: it only knows the balancers
        // of the configuration it is running.
        ui.label(
            RichText::new(t(lang, Key::RuntimeOverrideScopeHint))
                .small()
                .weak(),
        );

        let action = {
            let state = Self::balancer_runtime_state(&mut self.balancer_runtime, tag);
            if state.known_target.is_empty()
                || !self
                    .view_cache
                    .as_ref()
                    .expect("view cache populated above")
                    .out_tags
                    .iter()
                    .any(|candidate| candidate == &state.known_target)
            {
                state.known_target = self
                    .view_cache
                    .as_ref()
                    .expect("view cache populated above")
                    .out_tags
                    .first()
                    .cloned()
                    .unwrap_or_default();
            }

            // The principle-targets line is memoized on the info reply's
            // generation (see `PrincipleLine`), so the editor's steady
            // repaints only read the cached text.
            state.refresh_principle_line(lang);
            match &state.info {
                Some(info) => {
                    ui.label(match &info.override_target {
                        Some(target) => t_fmt(lang, Key::CurrentOverride, &[target]),
                        None => t(lang, Key::CurrentOverrideNone).into(),
                    });
                    ui.label(state.principle_line_text());
                }
                None => {
                    ui.label(RichText::new(t(lang, Key::RuntimeStateNotRefreshed)).weak());
                }
            }

            let pending = state.pending_request.is_some();
            let gate = verdict(control.running, control.busy, pending);
            // The override target is this control's own extra condition: a
            // refusal on the rungs above paints its own sentence below.
            let available = gate.enabled && !tag.trim().is_empty();
            match gate.rung {
                Rung::NotRunning => {
                    ui.label(
                        RichText::new(t(lang, Key::CoreNotRunningControls))
                            .color(ui.visuals().warn_fg_color),
                    );
                }
                Rung::Busy => {
                    ui.label(
                        RichText::new(t(lang, Key::OperationInProgress))
                            .color(ui.visuals().warn_fg_color),
                    );
                }
                Rung::Pending => {
                    ui.label(RichText::new(t(lang, Key::WaitingForXrayEllipsis)).weak());
                }
                Rung::Ready => {}
            }

            let mut action = None;
            if ui
                .add_enabled(
                    available,
                    egui::Button::new(t(lang, Key::RefreshRuntimeState)),
                )
                .clicked()
            {
                action = Some(BalancerControlAction::Refresh);
            }

            ui.horizontal(|ui| {
                ui.radio_value(
                    &mut state.use_custom_target,
                    false,
                    t(lang, Key::KnownOutbound),
                );
                ui.add_enabled_ui(!state.use_custom_target, |ui| {
                    egui::ComboBox::from_id_salt(("balancer-runtime-target", tag))
                        .selected_text(if state.known_target.is_empty() {
                            t(lang, Key::NoneSelected)
                        } else {
                            &state.known_target
                        })
                        .show_ui(ui, |ui| {
                            for target in &self
                                .view_cache
                                .as_ref()
                                .expect("view cache populated above")
                                .out_tags
                            {
                                ui.selectable_value(
                                    &mut state.known_target,
                                    target.clone(),
                                    target,
                                );
                            }
                        });
                });
            });
            ui.horizontal(|ui| {
                ui.radio_value(
                    &mut state.use_custom_target,
                    true,
                    t(lang, Key::CustomExactTag),
                );
                ui.add_enabled(
                    state.use_custom_target,
                    egui::TextEdit::singleline(&mut state.custom_target)
                        .hint_text(t(lang, Key::ExactOutboundTag))
                        .desired_width(240.0),
                );
            });
            let selected_target = if state.use_custom_target {
                state.custom_target.trim()
            } else {
                state.known_target.trim()
            };
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        available && !selected_target.is_empty(),
                        egui::Button::new(t(lang, Key::ApplyTarget)),
                    )
                    .on_disabled_hover_text(if selected_target.is_empty() {
                        t(lang, Key::ApplyTargetDisabledEmpty)
                    } else {
                        t(lang, Key::ApplyTargetDisabledBusy)
                    })
                    .clicked()
                {
                    action = Some(BalancerControlAction::Set(selected_target.to_string()));
                }
                if ui
                    .add_enabled(available, egui::Button::new(t(lang, Key::ClearOverride)))
                    .clicked()
                {
                    action = Some(BalancerControlAction::Clear);
                }
            });
            if let Some((ok, message)) = &state.feedback {
                ui.label(
                    RichText::new(message)
                        .color(if *ok {
                            ui.visuals().strong_text_color()
                        } else {
                            ui.visuals().error_fg_color
                        })
                        .small(),
                );
            }
            action
        };

        if let Some(action) = action {
            // One reply channel per action; the entry's pending holds the
            // request until the terminal lands. A synchronous send failure
            // clears exactly this request.
            let state = Self::balancer_runtime_state(&mut self.balancer_runtime, tag);
            state.feedback = None;
            match action {
                BalancerControlAction::Refresh => {
                    let (reply, rx) = oneshot::channel();
                    if control
                        .cmd
                        .send(CoreCmd::GetBalancerInfo {
                            reply,
                            balancer_tag: tag.to_string(),
                        })
                        .is_err()
                    {
                        state.feedback =
                            Some((false, t(lang, Key::RuntimeChannelClosed).to_string()));
                    } else {
                        state.pending_request = Some(BalancerPending::Info {
                            request: Request::reply(rx),
                        });
                    }
                }
                BalancerControlAction::Set(target) => {
                    let (reply, rx) = oneshot::channel();
                    if control
                        .cmd
                        .send(CoreCmd::SetBalancerOverride {
                            reply,
                            balancer_tag: tag.to_string(),
                            target: target.clone(),
                        })
                        .is_err()
                    {
                        state.feedback =
                            Some((false, t(lang, Key::RuntimeChannelClosed).to_string()));
                    } else {
                        state.pending_request = Some(BalancerPending::Mutate {
                            target: Some(target),
                            request: Request::reply(rx),
                        });
                    }
                }
                BalancerControlAction::Clear => {
                    let (reply, rx) = oneshot::channel();
                    if control
                        .cmd
                        .send(CoreCmd::ClearBalancerOverride {
                            reply,
                            balancer_tag: tag.to_string(),
                        })
                        .is_err()
                    {
                        state.feedback =
                            Some((false, t(lang, Key::RuntimeChannelClosed).to_string()));
                    } else {
                        state.pending_request = Some(BalancerPending::Mutate {
                            target: None,
                            request: Request::reply(rx),
                        });
                    }
                }
            }
        }
    }

    fn balancers_section(
        &mut self,
        ui: &mut Ui,
        ctx: &mut UiCtx,
        lang: Language,
        changed: &mut bool,
    ) {
        // Per-balancer rule-reference counts come from the view cache,
        // computed once per model generation — a linear rule scan per
        // balancer must not run on idle frames. The cache
        // borrow is per-index below (usize copy), because the section
        // closure captures `self` uniquely for `balancer_editor`.
        let control_cmd = ctx.cmd.clone();
        let control_running = matches!(ctx.phase, CorePhase::Running);
        let control_busy = ctx.busy.is_held();
        let runtime_control = RuntimeControl {
            cmd: &control_cmd,
            running: control_running,
            busy: control_busy,
        };

        widgets::section(ui, t(lang, Key::BalancersSection), |ui| {
            let mut delete: Option<usize> = None;
            let mut rename: Option<(usize, String)> = None;
            {
                let balancers = &mut ctx.settings.routing.balancers;
                for (i, bal) in balancers.iter_mut().enumerate() {
                    let references = self
                        .view_cache
                        .as_ref()
                        .expect("view cache populated above")
                        .reference_counts[i];
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(if bal.tag.is_empty() {
                                    t(lang, Key::Untagged)
                                } else {
                                    &bal.tag
                                })
                                .strong(),
                            );
                            // The header fragments are memoized with the
                            // cache generation — the strategy caption, the
                            // optional selector summary and the reference
                            // notes are per-frame `t_fmt`/`one_plus` work
                            // otherwise.
                            let header = &self
                                .view_cache
                                .as_ref()
                                .expect("view cache populated above")
                                .balancer_headers[i];
                            ui.label(&header.strategy);
                            if let Some(selector) = &header.selector {
                                ui.label(selector);
                            }
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    let delete_response = ui
                                        .add_enabled(
                                            references == 0,
                                            egui::Button::new(t(lang, Key::DeleteRow)).small(),
                                        )
                                        .on_hover_text(t(lang, Key::DeleteBalancer))
                                        .on_disabled_hover_text(&header.used_by);
                                    if delete_response.clicked() {
                                        delete = Some(i);
                                    }
                                    let open = self.edit_balancer == Some(i);
                                    if ui
                                        .small_button(if open { "▾" } else { "▸" })
                                        .on_hover_text(t(lang, Key::EditBalancer))
                                        .clicked()
                                    {
                                        if open {
                                            self.edit_balancer = None;
                                        } else {
                                            self.edit_balancer = Some(i);
                                            self.balancer_tag_buf = bal.tag.clone();
                                            self.balancer_error = None;
                                        }
                                    }
                                },
                            );
                        });
                        // The balancer breakage warning renders
                        // inline on the entry's own row, through the amber
                        // tier — a balancer whose selectors match no
                        // outbound tag cannot carry traffic.
                        if let Some(warning) = self
                            .view_cache
                            .as_ref()
                            .expect("view cache populated above")
                            .balancer_warnings[i]
                            .as_deref()
                        {
                            ui.label(
                                RichText::new(warning)
                                    .small()
                                    .color(status_colors_of(ui).warn),
                            );
                        }
                        if references != 0 {
                            let blocked = &self
                                .view_cache
                                .as_ref()
                                .expect("view cache populated above")
                                .balancer_headers[i]
                                .delete_blocked;
                            ui.label(
                                RichText::new(blocked)
                                    .small()
                                    .color(ui.visuals().warn_fg_color),
                            );
                        }
                        if self.edit_balancer == Some(i) {
                            let (row_changed, requested_tag) =
                                self.balancer_editor(ui, lang, bal, i);
                            *changed |= row_changed;
                            if let Some(tag) = requested_tag {
                                rename = Some((i, tag));
                            }
                            self.balancer_runtime_controls(ui, lang, &runtime_control, &bal.tag);
                        }
                    });
                }
            }

            if let Some((index, tag)) = rename {
                let result: Result<usize, RoutingIntegrityError> =
                    ctx.settings.routing.rename_balancer(index, &tag);
                match result {
                    Ok(_) => {
                        self.balancer_tag_buf = tag.trim().to_string();
                        self.balancer_error = None;
                        *changed = true;
                    }
                    Err(error) => self.balancer_error = Some(error.text(lang)),
                }
            }

            if let Some(index) = delete {
                match ctx.settings.routing.remove_balancer(index) {
                    Ok(_) => {
                        self.edit_balancer = match self.edit_balancer {
                            Some(open) if open == index => None,
                            Some(open) if open > index => Some(open - 1),
                            open => open,
                        };
                        self.balancer_error = None;
                        *changed = true;
                    }
                    Err(error) => self.balancer_error = Some(error.text(lang)),
                }
            }
            let selector = self
                .view_cache
                .as_ref()
                .expect("view cache populated above")
                .server_outbound_emitted
                .then_some("srv-");
            let add = ui
                .add_enabled(
                    selector.is_some(),
                    egui::Button::new(t(lang, Key::AddBalancer)),
                )
                .on_disabled_hover_text(t(lang, Key::AddBalancerDisabled));
            if add.clicked()
                && let Some(selector) = selector
            {
                let tag = unique_balancer_tag(&ctx.settings.routing.balancers);
                ctx.settings
                    .routing
                    .balancers
                    .push(Balancer::new(tag.clone(), selector.into()));
                self.edit_balancer = Some(ctx.settings.routing.balancers.len() - 1);
                self.balancer_tag_buf = tag;
                self.balancer_error = None;
                *changed = true;
            }
        });
    }

    fn balancer_editor(
        &mut self,
        ui: &mut Ui,
        lang: Language,
        bal: &mut Balancer,
        index: usize,
    ) -> (bool, Option<String>) {
        let mut changed = false;
        // Editor identity for the widget ids and edit buffers below: the
        // tag itself, borrowed — never cloned per frame. A never-saved
        // (tagless) balancer keys on its row index instead, because two
        // such balancers would otherwise share the empty tag and with it
        // the ids and buffers.
        let new_key;
        let key: &str = if bal.tag.is_empty() {
            new_key = format!("(new:{index})");
            new_key.as_str()
        } else {
            bal.tag.as_str()
        };

        let old_tag = bal.tag.as_str();
        // The duplicate verdict reads every other row's committed tag, so the
        // memoized verdict must follow that list: recompute whenever any tag
        // changes — including a sibling removed below — even though this
        // row's buffer text stays put. The row index is part of the revision
        // because the rule excludes the row's own tag.
        let tags_revision = widgets::context_revision((
            index,
            &self
                .view_cache
                .as_ref()
                .expect("view cache populated above")
                .balancer_tags,
        ));
        widgets::validated_field_with_revision(
            ui,
            t(lang, Key::Tag),
            &mut self.balancer_tag_buf,
            t(lang, Key::BalancerNameHint),
            tags_revision,
            |candidate| {
                let candidate = candidate.trim();
                if candidate.is_empty() {
                    Some(t(lang, Key::TagRequired).into())
                } else if self
                    .view_cache
                    .as_ref()
                    .expect("view cache populated above")
                    .balancer_tags
                    .iter()
                    .enumerate()
                    .any(|(other, tag)| other != index && tag == candidate)
                {
                    Some(t(lang, Key::TagDuplicate).into())
                } else {
                    None
                }
            },
        );
        let candidate = self.balancer_tag_buf.trim();
        let valid = !candidate.is_empty()
            && self
                .view_cache
                .as_ref()
                .expect("view cache populated above")
                .balancer_tags
                .iter()
                .enumerate()
                .all(|(other, tag)| other == index || tag != candidate);
        let rename = ui
            .add_enabled(
                valid && candidate != old_tag,
                egui::Button::new(if old_tag.is_empty() {
                    t(lang, Key::SetTag)
                } else {
                    t(lang, Key::RenameUpdateRules)
                }),
            )
            .on_disabled_hover_text(t(lang, Key::TagUniqueHint))
            .clicked()
            .then(|| candidate.to_string());
        if let Some(error) = &self.balancer_error {
            ui.label(
                RichText::new(error)
                    .small()
                    .color(ui.visuals().error_fg_color),
            );
        }

        changed |= widgets::string_list(
            ui,
            lang,
            t(lang, Key::Selectors),
            &mut bal.selector,
            t(lang, Key::SelectorsHint),
        );
        if bal
            .selector
            .iter()
            .all(|selector| selector.trim().is_empty())
        {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(t(lang, Key::SelectorRequired))
                        .color(ui.visuals().error_fg_color),
                );
                if self
                    .view_cache
                    .as_ref()
                    .expect("view cache populated above")
                    .server_outbound_emitted
                    && ui.small_button(t(lang, Key::SelectAllServers)).clicked()
                {
                    bal.selector = vec!["srv-".into()];
                    changed = true;
                }
            });
        }
        changed |= widgets::combo_str(
            ui,
            t(lang, Key::StrategyLabel),
            ("strat", key),
            &mut bal.strategy.r#type,
            &["random", "roundrobin", "leastping", "leastload"],
            t(lang, Key::Any),
            false,
        );
        if bal.strategy.r#type.is_empty() {
            bal.strategy.r#type = "random".into();
        }
        if bal.needs_live_health() {
            ui.label(
                RichText::new(t(lang, Key::RequiresObservatory))
                    .small()
                    .weak(),
            );
        }
        changed |= widgets::combo_str(
            ui,
            t(lang, Key::Fallback),
            ("fb", key),
            &mut bal.fallback_tag,
            &self
                .view_cache
                .as_ref()
                .expect("view cache populated above")
                .out_tags,
            t(lang, Key::Any),
            true,
        );

        if bal.strategy.r#type == "leastload" {
            let settings = bal.strategy.settings.get_or_insert_with(Default::default);
            changed |= self.leastload_form(ui, lang, settings, key);
        } else if bal.strategy.settings.take().is_some() {
            changed = true;
        }
        (changed, rename)
    }

    fn leastload_form(
        &mut self,
        ui: &mut Ui,
        lang: Language,
        s: &mut LeastLoadSettings,
        key: &str,
    ) -> bool {
        let mut changed = false;
        ui.indent(("ll", key), |ui| {
            if !matches!(&self.ll_buf, Some((t, _)) if *t == key) {
                self.ll_buf = Some((
                    key.to_string(),
                    LeastLoadBuf {
                        baselines: s.baselines.iter().map(|d| d.to_go_string()).collect(),
                        max_rtt: s.max_rtt.map(|d| d.to_go_string()).unwrap_or_default(),
                    },
                ));
            }

            // costs table
            ui.label(RichText::new(t(lang, Key::Costs)).small().weak());
            let mut del_cost: Option<usize> = None;
            egui::Grid::new(("costs", key))
                .num_columns(4)
                .show(ui, |ui| {
                    for (ci, cost) in s.costs.iter_mut().enumerate() {
                        if ui
                            .checkbox(&mut cost.regexp, "")
                            .on_hover_text(t(lang, Key::MatchRegexpHint))
                            .changed()
                        {
                            changed = true;
                        }
                        changed |= widgets::text_field(
                            ui,
                            t(lang, Key::Match),
                            &mut cost.r#match,
                            t(lang, Key::MatchHint),
                        );
                        changed |= opt_f64(
                            ui,
                            lang,
                            t(lang, Key::Weight),
                            &mut cost.value,
                            0.0..=10.0,
                            0.5,
                        );
                        if ui.small_button(t(lang, Key::DeleteRow)).clicked() {
                            del_cost = Some(ci);
                        }
                        ui.end_row();
                    }
                });
            if let Some(ci) = del_cost {
                s.costs.remove(ci);
                changed = true;
            }
            if ui.small_button(t(lang, Key::AddCost)).clicked() {
                s.costs.push(StrategyCost::default());
                changed = true;
            }

            // baselines as Go-duration strings, committed on successful parse
            if let Some((_, buf)) = &mut self.ll_buf {
                if widgets::string_list(
                    ui,
                    lang,
                    t(lang, Key::Baselines),
                    &mut buf.baselines,
                    t(lang, Key::BaselinesHint),
                ) {
                    s.baselines = buf
                        .baselines
                        .iter()
                        .filter_map(|b| DurationMs::parse(b))
                        .collect();
                    changed = true;
                }
                let max_rtt = &mut buf.max_rtt;
                if widgets::validated_field(ui, t(lang, Key::MaxRtt), max_rtt, "1s", |s| {
                    if s.trim().is_empty() || DurationMs::parse(s).is_some() {
                        None
                    } else {
                        Some(t(lang, Key::InvalidGoDurationExample).into())
                    }
                }) {
                    s.max_rtt = if max_rtt.trim().is_empty() {
                        None
                    } else {
                        DurationMs::parse(max_rtt)
                    };
                    changed = true;
                }
            }

            changed |=
                widgets::opt_i32(ui, t(lang, Key::ExpectedNodes), &mut s.expected, -1..=1024);
            ui.label(
                RichText::new(t(lang, Key::ExpectedSpeedMode))
                    .small()
                    .weak(),
            );
            changed |= opt_f64(
                ui,
                lang,
                t(lang, Key::Tolerance),
                &mut s.tolerance,
                0.0..=1.0,
                0.5,
            );
        });
        changed
    }

    // ---------- observability ----------

    fn observability_section(
        &mut self,
        ui: &mut Ui,
        ctx: &mut UiCtx,
        lang: Language,
        changed: &mut bool,
    ) {
        widgets::section(ui, t(lang, Key::ObservabilitySection), |ui| {
            {
                let rc = &mut ctx.settings.routing;
                // Go router.go: only AsIs / IpIfNonMatch / IpOnDemand exist.
                *changed |= widgets::combo_str(
                    ui,
                    t(lang, Key::DomainStrategy),
                    "domain-strategy",
                    &mut rc.domain_strategy,
                    &["AsIs", "IpIfNonMatch", "IpOnDemand"],
                    t(lang, Key::Any),
                    false,
                );
                if rc.domain_strategy.is_empty() {
                    rc.domain_strategy = "AsIs".into();
                }

                // One outbound-health engine per core: Xray registers the
                // ordinary Observatory before the burst observatory, so with
                // both configured the burst pings could never answer the
                // status read. Each toggle clears the other.
                let mut obs_enabled = rc.observatory.enabled;
                if ui
                    .checkbox(&mut obs_enabled, t(lang, Key::ObservatoryLatencyProbing))
                    .changed()
                {
                    rc.set_observatory_enabled(obs_enabled);
                    *changed = true;
                }
                ui.label(
                    RichText::new(t(lang, Key::ObservatoryEmitted))
                        .small()
                        .weak(),
                );
                // The value fields stay reachable whenever the block is
                // emitted: a dependency-forced observatory still honors the
                // probe URL, the interval and the concurrency — only its
                // subject selector is replaced by the full profile set.
                let observatory_emitted = rc.observatory_emitted();
                let observatory_chosen = rc.observatory.enabled;
                if observatory_emitted {
                    let obs = &mut rc.observatory;
                    if observatory_chosen {
                        *changed |= widgets::string_list(
                            ui,
                            lang,
                            t(lang, Key::SubjectSelectors),
                            &mut obs.subject_selector,
                            t(lang, Key::SubjectSelectorsHint),
                        );
                    } else {
                        ui.label(
                            RichText::new(t(lang, Key::ObservatoryForcedByBalancer))
                                .small()
                                .weak(),
                        );
                    }
                    ui.indent("obs", |ui| {
                        *changed |= widgets::text_field(
                            ui,
                            t(lang, Key::ProbeUrl),
                            &mut obs.probe_url,
                            "https://www.google.com/generate_204",
                        );
                        let ibuf = self
                            .probe_interval
                            .get_or_insert_with(|| obs.probe_interval.to_go_string());
                        if widgets::validated_field(
                            ui,
                            t(lang, Key::ProbeInterval),
                            ibuf,
                            "10s",
                            |value| widgets::parse_positive_probe_interval(lang, value).err(),
                        ) && let Ok(duration) =
                            widgets::parse_positive_probe_interval(lang, ibuf)
                        {
                            obs.probe_interval = duration;
                            *changed = true;
                        }
                        ui.label(
                            RichText::new(t(lang, Key::ProbeIntervalHint))
                                .small()
                                .weak(),
                        );
                        ui.label(
                            RichText::new(t(lang, Key::ProbeIntervalHint2))
                                .small()
                                .weak(),
                        );
                        if ui
                            .checkbox(&mut obs.enable_concurrency, t(lang, Key::EnableConcurrency))
                            .changed()
                        {
                            *changed = true;
                        }
                    });
                }

                // A balancer that reads live health data pins the engine: it
                // needs one whose coverage cannot be narrowed, and the app
                // fills that from the observatory.
                let balancer_gates_burst = rc.needs_live_health();
                let mut burst_enabled = rc.burst_observatory.enabled;
                let burst_toggle = ui.add_enabled(
                    !balancer_gates_burst,
                    egui::Checkbox::new(&mut burst_enabled, t(lang, Key::BurstObservatory)),
                );
                let burst_toggle = if balancer_gates_burst {
                    burst_toggle.on_disabled_hover_text(t(lang, Key::BurstObservatoryGated))
                } else {
                    burst_toggle
                };
                if burst_toggle.changed() {
                    rc.set_burst_observatory_enabled(burst_enabled);
                    *changed = true;
                }
                ui.label(
                    RichText::new(t(lang, Key::BurstObservatoryHint))
                        .small()
                        .weak(),
                );
                if rc.observatory_emitted() && rc.burst_observatory_emitted() {
                    ui.colored_label(
                        status_colors_of(ui).warn,
                        RichText::new(t(lang, Key::HealthEngineConflict)).small(),
                    );
                }
                if rc.burst_observatory.enabled {
                    let burst = &mut rc.burst_observatory;
                    *changed |= widgets::string_list(
                        ui,
                        lang,
                        t(lang, Key::SubjectSelectors),
                        &mut burst.subject_selector,
                        t(lang, Key::SubjectSelectorsHint),
                    );
                    let pc = &mut burst.ping_config;
                    ui.indent("burst", |ui| {
                        *changed |= widgets::text_field(
                            ui,
                            t(lang, Key::Destination),
                            &mut pc.destination,
                            "https://connectivitycheck.gstatic.com/generate_204",
                        );
                        *changed |= widgets::text_field(
                            ui,
                            t(lang, Key::ConnectivityCheck),
                            &mut pc.connectivity,
                            t(lang, Key::ConnectivityCheckHint),
                        );
                        let ibuf = self.ping_interval.get_or_insert_with(|| {
                            pc.interval.map(|d| d.to_go_string()).unwrap_or_default()
                        });
                        if widgets::validated_field(
                            ui,
                            t(lang, Key::Interval),
                            ibuf,
                            t(lang, Key::IntervalHint),
                            |s| {
                                if s.trim().is_empty() || DurationMs::parse(s).is_some() {
                                    None
                                } else {
                                    Some(t(lang, Key::InvalidGoDurationShort).into())
                                }
                            },
                        ) {
                            pc.interval = if ibuf.trim().is_empty() {
                                None
                            } else {
                                DurationMs::parse(ibuf)
                            };
                            *changed = true;
                        }
                        *changed |= widgets::opt_i32(
                            ui,
                            t(lang, Key::Sampling),
                            &mut pc.sampling,
                            1..=1000,
                        );
                        let tbuf = self.ping_timeout.get_or_insert_with(|| {
                            pc.timeout.map(|d| d.to_go_string()).unwrap_or_default()
                        });
                        if widgets::validated_field(
                            ui,
                            t(lang, Key::Timeout),
                            tbuf,
                            t(lang, Key::TimeoutHint),
                            |s| {
                                if s.trim().is_empty() || DurationMs::parse(s).is_some() {
                                    None
                                } else {
                                    Some(t(lang, Key::InvalidGoDurationShort).into())
                                }
                            },
                        ) {
                            pc.timeout = if tbuf.trim().is_empty() {
                                None
                            } else {
                                DurationMs::parse(tbuf)
                            };
                            *changed = true;
                        }
                        *changed |= widgets::text_field(
                            ui,
                            t(lang, Key::HttpMethod),
                            &mut pc.http_method,
                            "HEAD",
                        );
                    });
                }
            }

            ui.add_space(4.0);
            if ui.button(t(lang, Key::TestRoute)).clicked() {
                self.test_open = true;
                self.prepared_route_test = None;
            }
        });
    }

    /// Poll the in-flight TestRoute request's reply channel, if landed. The
    /// request lives on the screen (not the dialog), so a result that lands
    /// while the dialog is closed is consumed on reopen — the run is never
    /// re-sent. Called once per frame, right after the open gate.
    fn poll_test_route_result(&mut self) {
        match self.test_pending_request.poll() {
            Some(Terminal::Answered(result)) => self.test_result = Some(result),
            // Closed: defensive — the runtime's reply guard always sends a
            // terminal before the sender drops.
            Some(Terminal::Exited) | None => {}
        }
    }

    fn test_route_dialog(&mut self, ui: &mut Ui, ctx: &mut UiCtx) {
        if !self.test_open {
            return;
        }

        self.poll_test_route_result();

        let lang = ctx.settings.language;
        let mut open = self.test_open;
        let mut close = false;
        egui::Window::new(t(lang, Key::TestRouteWindow))
            .collapsible(false)
            .resizable(true)
            .default_width(540.0)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .open(&mut open)
            .show(ui.ctx(), |ui| {
                ui.label(t(lang, Key::TestRouteExplain));
                let max_height = (ui.ctx().content_rect().height() - 180.0).max(260.0);
                let mut changed = false;
                egui::ScrollArea::vertical()
                    .id_salt("test-route-fields")
                    .max_height(max_height)
                    .show(ui, |ui| {
                        ui.heading(t(lang, Key::TestTargetHeading));
                        changed |= widgets::text_field(
                            ui,
                            t(lang, Key::TestDomain),
                            &mut self.test_request.target_domain,
                            t(lang, Key::TestDomainHint),
                        );
                        changed |= widgets::string_list(
                            ui,
                            lang,
                            t(lang, Key::TestTargetIps),
                            &mut self.test_request.target_ips,
                            t(lang, Key::TestTargetIpsHint),
                        );
                        ui.horizontal(|ui| {
                            ui.label(t(lang, Key::TestTargetPort));
                            changed |= ui
                                .add(
                                    DragValue::new(&mut self.test_request.target_port)
                                        .range(1..=u16::MAX as u32),
                                )
                                .changed();
                        });

                        ui.separator();
                        ui.heading(t(lang, Key::TestSourceHeading));
                        changed |= widgets::string_list(
                            ui,
                            lang,
                            t(lang, Key::TestSourceIps),
                            &mut self.test_request.source_ips,
                            t(lang, Key::TestSourceIpsHint),
                        );
                        let mut source_port = (self.test_request.source_port != 0)
                            .then_some(self.test_request.source_port);
                        if widgets::opt_u32(
                            ui,
                            t(lang, Key::TestSourcePort),
                            &mut source_port,
                            1..=u16::MAX as u32,
                        ) {
                            self.test_request.source_port = source_port.unwrap_or(0);
                            changed = true;
                        }
                        changed |= widgets::string_list(
                            ui,
                            lang,
                            t(lang, Key::TestLocalIps),
                            &mut self.test_request.local_ips,
                            t(lang, Key::TestLocalIpsHint),
                        );
                        let mut local_port = (self.test_request.local_port != 0)
                            .then_some(self.test_request.local_port);
                        if widgets::opt_u32(
                            ui,
                            t(lang, Key::TestLocalPort),
                            &mut local_port,
                            1..=u16::MAX as u32,
                        ) {
                            self.test_request.local_port = local_port.unwrap_or(0);
                            changed = true;
                        }
                        // The inbound options (3 built-ins + dokodemo tags) are
                        // cached with the view-cache generation, so an open
                        // dialog never clones the list per frame.
                        let known_inbounds = &self
                            .view_cache
                            .as_ref()
                            .expect("view cache populated above")
                            .known_inbounds;
                        changed |= widgets::combo_str(
                            ui,
                            t(lang, Key::TestInboundTag),
                            "test-route-inbound",
                            &mut self.test_request.inbound_tag,
                            known_inbounds,
                            t(lang, Key::Any),
                            true,
                        );
                        let mut vless_route = (self.test_request.vless_route != 0)
                            .then_some(self.test_request.vless_route);
                        if widgets::opt_u32(
                            ui,
                            t(lang, Key::TestVlessRoute),
                            &mut vless_route,
                            1..=u16::MAX as u32,
                        ) {
                            self.test_request.vless_route = vless_route.unwrap_or(0);
                            changed = true;
                        }
                        ui.label(RichText::new(t(lang, Key::TestProcessNote)).small().weak());

                        ui.separator();
                        ui.heading(t(lang, Key::TestDetectedProtocol));
                        changed |= widgets::combo_str(
                            ui,
                            t(lang, Key::TestNetwork),
                            "test-route-network",
                            &mut self.test_request.network,
                            &["tcp", "udp"],
                            t(lang, Key::Any),
                            true,
                        );
                        changed |= widgets::text_field(
                            ui,
                            t(lang, Key::TestProtocol),
                            &mut self.test_request.protocol,
                            t(lang, Key::TestProtocolHint),
                        );
                        ui.label(RichText::new(t(lang, Key::TestAttributes)).small().weak());
                        changed |= widgets::kv_table(
                            ui,
                            lang,
                            &mut self.test_attrs,
                            t(lang, Key::TestAttrKeyHint),
                            t(lang, Key::TestAttrValueHint),
                        );
                    });

                // The prepared request (deep clone + attribute rebuild +
                // validation) is expensive; recompute it only when an editor
                // changed this frame.
                if changed || self.prepared_route_test.is_none() {
                    self.prepared_route_test = Some(route_test_request(
                        lang,
                        &self.test_request,
                        &self.test_attrs,
                    ));
                }
                let prepared_request = self.prepared_route_test.as_ref();
                let validation_error = prepared_request.and_then(|result| result.as_ref().err());
                let gate = verdict(
                    matches!(ctx.phase, CorePhase::Running),
                    ctx.busy.is_held(),
                    self.test_pending_request.is_pending(),
                );
                match gate.rung {
                    Rung::NotRunning => {
                        ui.label(
                            RichText::new(t(lang, Key::TestCoreNotRunning))
                                .color(ui.visuals().warn_fg_color),
                        );
                    }
                    Rung::Busy => {
                        ui.label(
                            RichText::new(t(lang, Key::OperationInProgress))
                                .color(ui.visuals().warn_fg_color),
                        );
                    }
                    Rung::Pending => {
                        ui.label(RichText::new(t(lang, Key::WaitingForXrayEllipsis)).weak());
                    }
                    Rung::Ready => {}
                }
                if let Some(error) = validation_error {
                    ui.label(RichText::new(error.as_str()).color(ui.visuals().error_fg_color));
                }

                if let Some(result) = &self.test_result {
                    ui.separator();
                    egui::ScrollArea::vertical()
                        .max_height(160.0)
                        .show(ui, |ui| match result {
                            Ok(text) => ui.label(RichText::new(text).monospace()),
                            Err(error) => ui.label(
                                RichText::new(error.text(lang))
                                    .monospace()
                                    .color(ui.visuals().error_fg_color),
                            ),
                        });
                }
                ui.horizontal(|ui| {
                    let can_run = gate.enabled && prepared_request.is_some_and(Result::is_ok);
                    let button =
                        ui.add_enabled(can_run, egui::Button::new(t(lang, Key::TestExactContext)));
                    // The disabled reason may be a static string or the
                    // validation error; build it only while the button is
                    // actually disabled (hover-text
                    // arguments evaluate eagerly every frame).
                    let button = if can_run {
                        button
                    } else {
                        let disabled_reason = match gate.rung {
                            Rung::NotRunning => t(lang, Key::TestDisabledNotRunning),
                            Rung::Busy => t(lang, Key::TestDisabledBusy),
                            Rung::Pending => t(lang, Key::TestDisabledPending),
                            // No rung refuses the control: its own request is
                            // incomplete or invalid.
                            Rung::Ready => validation_error
                                .map(String::as_str)
                                .unwrap_or(t(lang, Key::TestDisabledIncomplete)),
                        };
                        button.on_disabled_hover_text(disabled_reason)
                    };
                    if button.clicked()
                        && let Some(Ok(request)) = prepared_request.cloned()
                    {
                        // One reply channel per run; the screen's pending
                        // holds the request until the terminal lands, even
                        // across close/reopen. A synchronous send failure
                        // clears exactly this request.
                        let (reply, receiver) = oneshot::channel();
                        self.test_result = None;
                        if ctx.cmd.send(CoreCmd::TestRoute { reply, request }).is_err() {
                            let error = DiagError::from(Diag::new(Key::RuntimeChannelClosed));
                            self.test_result = Some(Err(error));
                        } else {
                            self.test_pending_request = Request::reply(receiver);
                        }
                    }
                    if ui.button(t(lang, Key::Close)).clicked() {
                        close = true;
                    }
                });
            });
        self.test_open = open && !close;
    }
}

// ---------- helpers ----------

fn unique_balancer_tag(existing: &[Balancer]) -> String {
    for suffix in 1u32.. {
        let candidate = if suffix == 1 {
            "balancer".to_string()
        } else {
            format!("balancer-{suffix}")
        };
        if existing.iter().all(|balancer| balancer.tag != candidate) {
            return candidate;
        }
    }
    unreachable!("u32 balancer tag space exhausted")
}

#[cfg(test)]
mod balancer_creation_tests {
    use super::unique_balancer_tag;
    use crate::model::Balancer;

    #[test]
    fn generated_balancer_tag_is_nonempty_and_unique() {
        let existing = vec![Balancer::new("balancer".into(), "srv-".into())];
        assert_eq!(unique_balancer_tag(&existing), "balancer-2");
    }
}

fn route_test_attributes(
    lang: Language,
    rows: &[(String, String)],
) -> Result<std::collections::BTreeMap<String, String>, String> {
    let mut attributes = std::collections::BTreeMap::new();
    for (key, value) in rows {
        let key = key.trim();
        if key.is_empty() && value.is_empty() {
            continue;
        }
        if key.is_empty() {
            return Err(t(lang, Key::AttributeKeyRequired).into());
        }
        if attributes.insert(key.to_string(), value.clone()).is_some() {
            return Err(t_fmt(lang, Key::DuplicateAttributeKey, &[&key]));
        }
    }
    Ok(attributes)
}

fn route_test_request(
    lang: Language,
    draft: &RouteTestRequest,
    rows: &[(String, String)],
) -> Result<RouteTestRequest, String> {
    let mut request = draft.clone();
    request.attributes = route_test_attributes(lang, rows)?;
    request.validate().map_err(|diag| diag.text(lang))?;
    Ok(request)
}

#[cfg(test)]
mod route_test_ui_tests {
    use super::{Language, route_test_attributes, route_test_request};
    use crate::model::routing::RouteTestRequest;

    #[test]
    fn duplicate_route_attributes_are_rejected_not_overwritten() {
        let rows = vec![
            ("host".into(), "one.example".into()),
            ("host".into(), "two.example".into()),
        ];
        assert!(route_test_attributes(Language::En, &rows).is_err());
    }

    #[test]
    fn prepared_request_never_reuses_stale_attributes() {
        let mut draft = RouteTestRequest {
            target_domain: "example.com".into(),
            ..Default::default()
        };
        draft.attributes.insert("stale".into(), "old".into());

        let request = route_test_request(
            Language::En,
            &draft,
            &[("host".into(), "current.example".into())],
        )
        .expect("current attribute rows are valid");
        assert_eq!(request.attributes.len(), 1);
        assert_eq!(
            request.attributes.get("host").map(String::as_str),
            Some("current.example")
        );
        assert!(!request.attributes.contains_key("stale"));

        let duplicate_rows = vec![
            ("host".into(), "one.example".into()),
            ("host".into(), "two.example".into()),
        ];
        assert!(route_test_request(Language::En, &draft, &duplicate_rows).is_err());
    }
}
#[cfg(test)]
mod geodata_load_state_tests {
    use super::{
        GeodataError, GeodataLoadState, GeodataSnapshot, Language, Request, RoutingScreen,
    };
    use crate::sys::geodata::GeodataOperation;
    use tokio::sync::oneshot;

    #[test]
    fn one_worker_runs_and_ready_data_survives_refresh() {
        let (_sender, receiver) = oneshot::channel();
        let screen = RoutingScreen {
            geodata_load_state: GeodataLoadState::Loading(Request::reply(receiver)),
            ..Default::default()
        };
        assert!(screen.geodata_load_state.is_loading());
        assert!(screen.geodata_snapshot.is_none());

        let snapshot = GeodataSnapshot {
            geosite: Err(test_error("geosite.dat")),
            geoip: Err(test_error("geoip.dat")),
        };
        let (_sender, receiver) = oneshot::channel();
        let refreshing = RoutingScreen {
            geodata_snapshot: Some(snapshot),
            geodata_load_state: GeodataLoadState::Loading(Request::reply(receiver)),
            ..Default::default()
        };
        assert!(refreshing.geodata_load_state.is_loading());
        assert!(refreshing.geodata_snapshot.is_some());

        let (_sender, receiver) = oneshot::channel();
        let mut duplicate = RoutingScreen {
            geodata_load_state: GeodataLoadState::Loading(Request::reply(receiver)),
            ..Default::default()
        };
        assert!(!duplicate.start_geodata_load(Language::En, egui::Context::default()));
    }

    fn test_error(file: &str) -> GeodataError {
        GeodataError::Io {
            operation: GeodataOperation::Open,
            path: file.into(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "test"),
        }
    }
}

#[cfg(test)]
mod geodata_picker_search_tests {
    use super::{
        GeodataLoadState, Request, RoutingScreen, contains_ascii_case_insensitive,
        geodata_search_indices, geodata_search_matches,
    };
    use crate::model::settings::Language;
    use crate::sys::geodata::{
        GeodataCatalog, GeodataError, GeodataFileMetadata, GeodataOperation, GeodataSnapshot,
    };
    use std::path::PathBuf;
    use tokio::sync::oneshot;

    fn fixture_catalog(codes: &[&str]) -> GeodataCatalog {
        GeodataCatalog {
            codes: codes.iter().map(|code| code.to_string()).collect(),
            metadata: GeodataFileMetadata {
                path: PathBuf::from("fixture.dat"),
                byte_len: 0,
                modified: None,
            },
        }
    }

    fn error(file: &str) -> GeodataError {
        GeodataError::Io {
            operation: GeodataOperation::Open,
            path: file.into(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "test"),
        }
    }

    /// Perf contract: the memoized result for a
    /// (query, dataset) must equal a fresh scan of the same inputs — the
    /// picker renders through the memo, so parity is a requirement.
    #[test]
    fn memoized_matches_equal_fresh_scan() {
        let catalog = fixture_catalog(&[
            "cn",
            "google",
            "github",
            "geolocation-!cn",
            "telegram",
            "netflix",
        ]);
        let mut memo = None;

        let memoized = geodata_search_matches(&mut memo, 1, &catalog.codes, "cn");
        let fresh: Vec<&str> = catalog
            .codes
            .iter()
            .map(String::as_str)
            .filter(|code| contains_ascii_case_insensitive(code, "cn"))
            .collect();
        assert_eq!(
            memoized
                .iter()
                .map(|&index| catalog.codes[index as usize].as_str())
                .collect::<Vec<_>>(),
            fresh,
            "memoized indices must resolve to exactly the fresh-scan matches"
        );
        let stored = memo.as_ref().expect("the scan must leave a memo");
        assert_eq!(stored.query, "cn", "the memo must key on the scanned query");
        assert_eq!(
            stored.dataset_revision, 1,
            "the memo must key on the scanned dataset revision"
        );
    }

    /// Idle-frame purity + generation gating: repeated renders with the same
    /// (query, dataset) reuse the memo — its `matches` allocation survives,
    /// and for a query that matches nothing its key `String` does — while a
    /// rescan would collect a fresh vector / allocate a fresh key, so the
    /// identity compare is what fails when the reuse gate is dropped. A query
    /// change or a dataset revision change rewrites the memo's key exactly
    /// once.
    #[test]
    fn rescans_only_on_query_or_dataset_change() {
        let catalog = fixture_catalog(&["cn", "google", "github", "geolocation-!cn"]);
        let mut memo = None;

        let first = geodata_search_matches(&mut memo, 1, &catalog.codes, "cn");
        assert_eq!(first, [0_u32, 3]);
        let first_matches = memo.as_ref().unwrap().matches.as_ptr();

        // Unchanged (query, dataset): reuse the memo, no scan.
        let again = geodata_search_matches(&mut memo, 1, &catalog.codes, "cn");
        assert_eq!(again, [0_u32, 3]);
        assert_eq!(
            memo.as_ref().unwrap().matches.as_ptr(),
            first_matches,
            "an unchanged (query, dataset) must reuse the memo's match vector, not rescan"
        );

        // Query change: exactly one scan, matching a fresh scan of the query.
        let changed = geodata_search_matches(&mut memo, 1, &catalog.codes, "google");
        assert_eq!(changed, [1_u32]);
        assert_eq!(memo.as_ref().unwrap().query, "google");

        // Dataset revision change with the same query: exactly one scan
        // (the picker rescans the refreshed catalog, so the memo's key
        // carries the new revision).
        let refreshed = geodata_search_matches(&mut memo, 2, &catalog.codes, "google");
        assert_eq!(refreshed, [1_u32]);
        assert_eq!(memo.as_ref().unwrap().dataset_revision, 2);

        // No-match query scans once and stays memoized as empty. Its
        // `matches` is empty and so has no allocation to identify; the idle
        // direction therefore holds the memo's *key* allocation across the
        // replay. That check fails when the reuse gate is dropped: a rescan
        // rebuilds the entry with `query.to_owned()`, and the old key is still
        // alive while the new one is allocated, so the two cannot share an
        // address.
        let none = geodata_search_matches(&mut memo, 2, &catalog.codes, "zzz");
        assert!(none.is_empty());
        assert_eq!(
            memo.as_ref().unwrap().query,
            "zzz",
            "a no-match query must still memoize its key"
        );
        let none_key = memo.as_ref().unwrap().query.as_ptr();
        let still_none = geodata_search_matches(&mut memo, 2, &catalog.codes, "zzz");
        assert!(still_none.is_empty());
        assert_eq!(
            memo.as_ref().unwrap().query.as_ptr(),
            none_key,
            "a memoized no-match query must reuse its memo key, not rescan"
        );
    }

    /// A landed snapshot bumps the dataset revision, invalidating the memos
    /// of an open picker so the next frame rescans against the new catalog.
    #[test]
    fn new_snapshot_bumps_dataset_revision() {
        let (sender, receiver) = oneshot::channel();
        let mut screen = RoutingScreen {
            geodata_load_state: GeodataLoadState::Loading(Request::reply(receiver)),
            ..Default::default()
        };
        sender
            .send(GeodataSnapshot {
                geosite: Err(error("geosite.dat")),
                geoip: Err(error("geoip.dat")),
            })
            .expect("receiver is alive");
        screen.poll_geodata_load(Language::En);

        assert_eq!(screen.geodata_revision, 1);
        assert!(screen.geodata_snapshot.is_some());
        assert!(matches!(screen.geodata_load_state, GeodataLoadState::Ready));
    }

    /// `geodata_search_indices` covers the full catalog bound documented by
    /// `sys::geodata::MAX_CODES` (65,536 codes → max index 65,535), so the
    /// `u32` storage is lossless at the documented limit.
    #[test]
    fn indices_cover_the_full_catalog_bound() {
        let codes: Vec<String> = (0..65_536u32).map(|i| format!("code-{i}")).collect();
        let indices = geodata_search_indices(&codes, "code-65535");
        assert_eq!(indices, [65_535_u32]);
    }
}

#[cfg(test)]
mod view_cache_tests {
    use super::{Language, RoutingScreen, rule_summary, rule_target_line};
    use crate::model::inbound::{DNS_INBOUND_TAG, TUN_INBOUND_TAG};
    use crate::model::{
        Balancer, DokodemoCfg, LocalInboundCfg, LocalInboundProtocol, OutboundModel, Rule,
        ServerProfile, ServersFile, Settings,
    };

    /// Memoization contract (module level): the generation key
    /// `(model generation, language)` rebuilds the tag vectors and rule rows
    /// exactly once per model change and never on idle frames. The cache's
    /// own generation key and its retained allocations are the seam — a
    /// rebuild replaces both.
    #[test]
    fn view_cache_rebuilds_only_when_the_model_generation_changes() {
        let mut screen = RoutingScreen::default();
        let servers = ServersFile::default();
        let mut settings = Settings::default();
        settings.routing.rules.push(Rule::new());

        let mut generation = 0;
        // First frame: one rebuild, one format pass, keyed on the live
        // generation.
        screen.refresh_view_cache(generation, Language::En, &servers, &settings);
        let first_rows = {
            let cache = screen.view_cache.as_ref().unwrap();
            assert_eq!(cache.generation, (generation, Language::En));
            assert_eq!(
                cache.rule_rows.len(),
                1,
                "the first build must cover every rule"
            );
            cache.rule_rows.as_ptr()
        };

        // Idle frames with the same generation rebuild nothing: the cache
        // keeps its generation key and its own allocations.
        screen.refresh_view_cache(generation, Language::En, &servers, &settings);
        screen.refresh_view_cache(generation, Language::En, &servers, &settings);
        {
            let cache = screen.view_cache.as_ref().unwrap();
            assert_eq!(cache.generation, (generation, Language::En));
            assert_eq!(
                cache.rule_rows.as_ptr(),
                first_rows,
                "idle frames must not rebuild the rule rows"
            );
        }

        // One model edit (the mutation hook's bump) → exactly one rebuild +
        // one format pass, independent of persist timing.
        settings.routing.rules[0].port = "443".into();
        generation += 1;
        screen.refresh_view_cache(generation, Language::En, &servers, &settings);
        let edited_rows = {
            let cache = screen.view_cache.as_ref().unwrap();
            assert_eq!(cache.generation, (generation, Language::En));
            cache.rule_rows.as_ptr()
        };
        screen.refresh_view_cache(generation, Language::En, &servers, &settings);
        {
            let cache = screen.view_cache.as_ref().unwrap();
            assert_eq!(cache.generation, (generation, Language::En));
            assert_eq!(cache.rule_rows.as_ptr(), edited_rows);
        }

        // The next generation rebuilds once more (a generation change is the
        // rebuild signal, whatever moved it), and the frame after it reuses
        // that build.
        generation += 1;
        screen.refresh_view_cache(generation, Language::En, &servers, &settings);
        let next_rows = {
            let cache = screen.view_cache.as_ref().unwrap();
            assert_eq!(cache.generation, (generation, Language::En));
            assert_eq!(cache.rule_rows.len(), 1, "the rebuild covers every rule");
            cache.rule_rows.as_ptr()
        };
        screen.refresh_view_cache(generation, Language::En, &servers, &settings);
        {
            let cache = screen.view_cache.as_ref().unwrap();
            assert_eq!(cache.generation, (generation, Language::En));
            assert_eq!(cache.rule_rows.as_ptr(), next_rows);
        }
    }

    /// The cached row text must equal a fresh formatting pass over the same
    /// model: the memoized summary and target lines are what the rows paint.
    #[test]
    fn cached_rule_rows_match_fresh_formatting() {
        let mut screen = RoutingScreen::default();
        let servers = ServersFile::default();
        let mut settings = Settings::default();
        settings.routing.rules.push(Rule {
            rule_tag: "rule-one".into(),
            domain: vec!["geosite:cn".into(), "example.com".into()],
            ip: vec!["geoip:private".into()],
            port: "443".into(),
            network: "tcp".into(),
            protocol: vec!["http".into()],
            outbound_tag: "direct".into(),
            ..Rule::default()
        });
        settings.routing.rules.push(Rule {
            rule_tag: "rule-two".into(),
            balancer_tag: "bal-1".into(),
            ..Rule::default()
        });

        screen.refresh_view_cache(0, Language::En, &servers, &settings);
        let rows = &screen.view_cache.as_ref().unwrap().rule_rows;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].short_tag, "rule-one");
        assert_eq!(
            rows[0].summary,
            rule_summary(Language::En, &settings.routing.rules[0])
        );
        assert_eq!(
            rows[0].target_line,
            rule_target_line(Language::En, &settings.routing.rules[0]),
            "the cached target line must match a fresh format of the same rule"
        );
        assert_eq!(
            rows[1].target_line,
            rule_target_line(Language::En, &settings.routing.rules[1]),
            "balancer targets keep their arrow-wrapped line too"
        );

        // A rule without a target renders the empty line (the row paints
        // the "no target" hint in that case).
        let mut no_target = Rule::default();
        no_target.outbound_tag.clear();
        no_target.balancer_tag.clear();
        assert_eq!(rule_target_line(Language::En, &no_target), "");
    }

    /// The cached tag vectors mirror the model: every profile tag plus the
    /// contract tags, balancer tags filtered to non-empty for the rule
    /// editor's combo, and the unfiltered list kept for the rename validator.
    #[test]
    fn cached_tag_vectors_match_the_model() {
        let mut screen = RoutingScreen::default();
        let mut servers = ServersFile::default();
        servers
            .profiles
            .push(ServerProfile::new("alpha", OutboundModel::default()));
        let mut settings = Settings::default();
        settings
            .routing
            .balancers
            .push(Balancer::new("".into(), "srv-".into()));
        settings
            .routing
            .balancers
            .push(Balancer::new("b1".into(), "srv-".into()));

        screen.refresh_view_cache(0, Language::En, &servers, &settings);
        let cache = screen.view_cache.as_ref().unwrap();

        assert_eq!(cache.out_tags.len(), 3, "one profile + direct + block");
        assert!(cache.out_tags[0].starts_with("srv-"));
        assert!(cache.out_tags.iter().any(|tag| tag == "direct"));
        assert!(cache.out_tags.iter().any(|tag| tag == "block"));
        assert_eq!(cache.bal_tags, ["b1"]);
        assert_eq!(cache.balancer_tags, ["", "b1"]);

        // A profile-list change (persisted elsewhere) rebuilds the vectors.
        servers
            .profiles
            .push(ServerProfile::new("beta", OutboundModel::default()));
        screen.refresh_view_cache(1, Language::En, &servers, &settings);
        assert_eq!(screen.view_cache.as_ref().unwrap().out_tags.len(), 4);
    }

    /// The balancer rows' "is there a server outbound" fact follows the state's
    /// profiles: the generator emits an outbound for every profile, so an empty
    /// profile list is the only state without one — exactly when the Add button
    /// and the "select all servers" shortcut stay hidden.
    #[test]
    fn cached_server_outbound_fact_follows_the_profiles() {
        let mut screen = RoutingScreen::default();
        let settings = Settings::default();
        screen.refresh_view_cache(0, Language::En, &ServersFile::default(), &settings);
        assert!(
            !screen.view_cache.as_ref().unwrap().server_outbound_emitted,
            "a model without profiles emits no server outbound"
        );

        let mut servers = ServersFile::default();
        servers
            .profiles
            .push(ServerProfile::new("alpha", OutboundModel::default()));
        screen.refresh_view_cache(1, Language::En, &servers, &settings);
        assert!(
            screen.view_cache.as_ref().unwrap().server_outbound_emitted,
            "a profile is a server outbound"
        );
    }

    /// The per-balancer reference counts are a
    /// linear rule scan per balancer — computed once per cache generation
    /// (with the tag vectors), never per frame, and refreshed exactly when
    /// the model generation advances.
    #[test]
    fn cached_reference_counts_match_the_model_and_refresh_on_generation() {
        let mut screen = RoutingScreen::default();
        let servers = ServersFile::default();
        let mut settings = Settings::default();
        settings
            .routing
            .balancers
            .push(Balancer::new("b1".into(), "srv-".into()));
        settings
            .routing
            .balancers
            .push(Balancer::new("b2".into(), "srv-".into()));
        settings.routing.rules.push(Rule {
            rule_tag: "r1".into(),
            balancer_tag: "b1".into(),
            ..Rule::default()
        });
        settings.routing.rules.push(Rule {
            rule_tag: "r2".into(),
            balancer_tag: "b1".into(),
            ..Rule::default()
        });

        screen.refresh_view_cache(0, Language::En, &servers, &settings);
        let counts = {
            let cache = screen.view_cache.as_ref().unwrap();
            assert_eq!(
                cache.reference_counts,
                [2, 0],
                "the first build must cover every balancer with the rule-scan result"
            );
            assert_eq!(
                cache.reference_counts[0],
                settings.routing.balancer_reference_count("b1"),
                "cached counts must equal a fresh scan of the same model"
            );
            cache.reference_counts.as_ptr()
        };

        // Idle frames reuse the same generation's counts: the retained
        // vector survives, so no scan ran.
        screen.refresh_view_cache(0, Language::En, &servers, &settings);
        {
            let cache = screen.view_cache.as_ref().unwrap();
            assert_eq!(cache.reference_counts, [2, 0]);
            assert_eq!(
                cache.reference_counts.as_ptr(),
                counts,
                "idle frames must not rescan the reference counts"
            );
        }

        // One rule edit (generation bump) → exactly one rebuild, one scan.
        settings.routing.rules[1].balancer_tag = "b2".into();
        screen.refresh_view_cache(1, Language::En, &servers, &settings);
        let edited = {
            let cache = screen.view_cache.as_ref().unwrap();
            assert_eq!(cache.reference_counts, [1, 1]);
            cache.reference_counts.as_ptr()
        };
        screen.refresh_view_cache(1, Language::En, &servers, &settings);
        {
            let cache = screen.view_cache.as_ref().unwrap();
            assert_eq!(cache.reference_counts, [1, 1]);
            assert_eq!(cache.reference_counts.as_ptr(), edited);
        }
    }

    /// The cached balancer header text must equal a fresh formatting pass
    /// over the same model, keep the idle-frame purity contract (same
    /// generation rebuilds nothing), and refresh exactly once when a
    /// generation bump changes the row.
    #[test]
    fn cached_balancer_headers_match_fresh_formatting_and_refresh_once() {
        let mut screen = RoutingScreen::default();
        let servers = ServersFile::default();
        let mut settings = Settings::default();
        // One rule referencing b1: the reference-count captions render that
        // count on b1's row and zero on b2's.
        let mut rule = Rule::new();
        rule.balancer_tag = "b1".into();
        settings.routing.rules.push(rule);
        // b1: single selector, default "random" strategy type.
        settings
            .routing
            .balancers
            .push(Balancer::new("b1".into(), "srv-a".into()));
        // b2: two selectors (exercises the "+N" condensation) and an empty
        // strategy type (exercises the "random" fallback label).
        settings.routing.balancers.push(Balancer {
            tag: "b2".into(),
            selector: vec!["srv-a".into(), "srv-b".into()],
            strategy: Default::default(),
            ..Default::default()
        });

        screen.refresh_view_cache(0, Language::En, &servers, &settings);
        let headers = &screen.view_cache.as_ref().unwrap().balancer_headers;
        assert_eq!(headers.len(), 2);
        assert_eq!(
            headers[0].strategy, "strategy: random",
            "the default strategy type renders through the cached caption"
        );
        assert_eq!(
            headers[0].selector.as_deref(),
            Some("selector: srv-a"),
            "a single-selector balancer condenses to the selector itself"
        );
        assert_eq!(
            headers[0].used_by,
            "1 routing rule(s) use this balancer. Retarget those rules first."
        );
        assert_eq!(
            headers[0].delete_blocked,
            "Remove blocked: 1 routing rule(s) reference this balancer."
        );
        assert_eq!(
            headers[1].strategy, "strategy: random",
            "an empty strategy type falls back to the random caption"
        );
        assert_eq!(
            headers[1].selector.as_deref(),
            Some("selector: srv-a +1"),
            "a multi-selector balancer condenses to first +N"
        );
        assert_eq!(
            headers[1].used_by,
            "0 routing rule(s) use this balancer. Retarget those rules first."
        );

        // Idle frames reuse the same generation's headers verbatim: the
        // retained vector survives, so no rebuild ran.
        let headers_ptr = screen
            .view_cache
            .as_ref()
            .unwrap()
            .balancer_headers
            .as_ptr();
        screen.refresh_view_cache(0, Language::En, &servers, &settings);
        screen.refresh_view_cache(0, Language::En, &servers, &settings);
        {
            let cache = screen.view_cache.as_ref().unwrap();
            assert_eq!(cache.balancer_headers[0].strategy, "strategy: random");
            assert_eq!(
                cache.balancer_headers.as_ptr(),
                headers_ptr,
                "idle frames must not rebuild the balancer headers"
            );
        }

        // A generation bump after a selector edit rebuilds the header text
        // exactly once, in the same pass as the tag vectors.
        settings.routing.balancers[0].selector = vec!["srv-a".into(), "srv-c".into()];
        screen.refresh_view_cache(1, Language::En, &servers, &settings);
        let rebuilt = {
            let cache = screen.view_cache.as_ref().unwrap();
            assert_eq!(
                cache.balancer_headers[0].selector.as_deref(),
                Some("selector: srv-a +1"),
                "a selector edit re-condenses the cached caption on the next generation"
            );
            cache.balancer_headers.as_ptr()
        };
        screen.refresh_view_cache(1, Language::En, &servers, &settings);
        assert_eq!(
            screen
                .view_cache
                .as_ref()
                .unwrap()
                .balancer_headers
                .as_ptr(),
            rebuilt
        );
    }

    /// The TestRoute dialog's inbound options are
    /// every local endpoint tag (list order) plus the built-in tun/dns/api
    /// tags and every dokodemo tag, rebuilt with the cache generation —
    /// never cloned per open-dialog frame.
    #[test]
    fn cached_known_inbounds_match_the_model() {
        let mut screen = RoutingScreen::default();
        let servers = ServersFile::default();
        let mut settings = Settings::default();
        settings.dokodemo.push(DokodemoCfg {
            tag: "in-doko-a".into(),
            ..DokodemoCfg::default()
        });
        settings.dokodemo.push(DokodemoCfg {
            tag: "in-doko-b".into(),
            ..DokodemoCfg::default()
        });

        screen.refresh_view_cache(0, Language::En, &servers, &settings);
        assert_eq!(
            screen.view_cache.as_ref().unwrap().known_inbounds,
            [
                "in-socks",
                "in-http",
                TUN_INBOUND_TAG,
                DNS_INBOUND_TAG,
                "api",
                "in-doko-a",
                "in-doko-b"
            ]
        );

        // A dokodemo change persisted from another screen refreshes the list.
        settings.dokodemo[1].tag = "in-doko-c".into();
        screen.refresh_view_cache(1, Language::En, &servers, &settings);
        assert_eq!(
            screen.view_cache.as_ref().unwrap().known_inbounds,
            [
                "in-socks",
                "in-http",
                TUN_INBOUND_TAG,
                DNS_INBOUND_TAG,
                "api",
                "in-doko-a",
                "in-doko-c"
            ]
        );

        // A local-endpoint change refreshes the list too: every
        // entry's tag appears in list order, enabled or not.
        settings.local_inbounds.push(LocalInboundCfg {
            tag: "in-http-1".into(),
            protocol: LocalInboundProtocol::Http,
            ..Default::default()
        });
        screen.refresh_view_cache(2, Language::En, &servers, &settings);
        assert_eq!(
            screen.view_cache.as_ref().unwrap().known_inbounds,
            [
                "in-socks",
                "in-http",
                "in-http-1",
                TUN_INBOUND_TAG,
                DNS_INBOUND_TAG,
                "api",
                "in-doko-a",
                "in-doko-c"
            ]
        );
    }
}

/// The routing editor's grammar validators mirror the wire
/// parsers Xray loads configs with (`infra/conf/common.go` PortList,
/// `common/geodata/rule_parser.go` ParseIPRules), and the balancer breakage
/// warnings follow [`assess`] through the view cache.
#[cfg(test)]
mod routing_grammar_tests {
    use super::{Language, RoutingScreen, valid_ip_rule, valid_port_list};
    use crate::i18n::{Key, t};
    use crate::model::{
        Balancer, OutboundModel, ServerProfile, ServersFile, Settings, StrategyCfg,
    };
    use crate::ui::test_rig::{UiTestRig, screen_harness_at};
    use egui_kittest::kittest::Queryable as _;

    /// A balancer that reads live health data pins the health engine: its
    /// coverage cannot be narrowed, so the burst toggle renders disabled and a
    /// click leaves the model untouched. Without such a balancer the same
    /// click enables the burst observatory — the control is gated, not inert.
    #[test]
    fn burst_toggle_is_gated_while_a_health_balancer_exists() {
        let mut rig = UiTestRig::default();
        rig.settings.routing.balancers.push(Balancer {
            tag: "health".into(),
            selector: vec!["srv-".into()],
            strategy: StrategyCfg {
                r#type: "leastping".into(),
                ..Default::default()
            },
            ..Default::default()
        });
        let mut harness =
            screen_harness_at(egui::vec2(900.0, 700.0), rig, RoutingScreen::default());
        harness.run();

        let label = t(Language::En, Key::BurstObservatory);
        harness
            .get_by_role_and_label(egui::accesskit::Role::CheckBox, label)
            .scroll_to_me();
        harness.run();
        harness
            .get_by_role_and_label(egui::accesskit::Role::CheckBox, label)
            .click();
        harness.run();
        assert!(
            !harness.state().1.settings.routing.burst_observatory.enabled,
            "a health balancer keeps the observatory, so the burst toggle must not enable"
        );

        // The dependency-forced block keeps its value fields reachable — only
        // the subject selector is replaced by the full profile set.
        assert!(
            harness
                .query_by_label(t(Language::En, Key::ProbeInterval))
                .is_some(),
            "a dependency-forced observatory must keep its interval field reachable"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::ObservatoryForcedByBalancer))
                .is_some(),
            "the forced case must say why the selector is gone"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SubjectSelectors))
                .is_none(),
            "the forced selector is the full profile set, so the field must not render"
        );

        harness.state_mut().1.settings.routing.balancers.clear();
        harness.run();
        harness
            .get_by_role_and_label(egui::accesskit::Role::CheckBox, label)
            .scroll_to_me();
        harness.run();
        harness
            .get_by_role_and_label(egui::accesskit::Role::CheckBox, label)
            .click();
        harness.run();
        assert!(
            harness.state().1.settings.routing.burst_observatory.enabled,
            "without a health balancer the burst toggle must work"
        );
    }

    #[test]
    fn port_list_grammar_matches_the_wire_parser() {
        for valid in [
            "",
            "80",
            "80,443,1000-2000",
            "0",
            "65535",
            "1-65535",
            "80, 443",
            "1000-2000,53",
            "80-80",
        ] {
            assert!(
                valid_port_list(valid),
                "{valid:?} must be a valid port list"
            );
        }
        for invalid in [
            "abc", "70,abc", "99999", "1-", "-1", "80,", ",80", "80--90", "1.5", "0x50", "80,1-",
            "65536", "90-80",
        ] {
            assert!(!valid_port_list(invalid), "{invalid:?} must be rejected");
        }
    }

    #[test]
    fn ip_rule_grammar_matches_the_wire_parser() {
        for valid in [
            "1.2.3.4",
            "::1",
            "2001:db8::68",
            "10.0.0.0/8",
            "2001:db8::/32",
            "1.2.3.0/24",
            "0.0.0.0/0",
            "::/0",
            "1.2.3.4/32",
            "::1/128",
            "geoip:cn",
            "geoip:private",
            "!1.2.3.4",
            "!!geoip:cn",
        ] {
            assert!(valid_ip_rule(valid), "{valid:?} must be a valid IP rule");
        }
        for invalid in [
            "abc",
            "example.com",
            "1.2.3.4/33",
            "::1/129",
            "1.2.3.4/abc",
            "/24",
            "geoip:",
            "999.1.2.3",
            "1.2.3.4/",
            "10.0.0.0/-1",
        ] {
            assert!(!valid_ip_rule(invalid), "{invalid:?} must be rejected");
        }
    }

    /// The cached warning vector follows the hazard projection: a selector
    /// matching no outbound tag warns, and the warning clears once a profile
    /// tag matches.
    #[test]
    fn balancer_breakage_warnings_follow_the_projection() {
        let mut screen = RoutingScreen::default();
        let mut settings = Settings::default();
        settings
            .routing
            .balancers
            .push(Balancer::new("bal-a".into(), "srv-".into()));

        // No profiles: "srv-" matches nothing among [direct, block].
        screen.refresh_view_cache(0, Language::En, &ServersFile::default(), &settings);
        let cache = screen.view_cache.as_ref().unwrap();
        assert!(
            cache.balancer_warnings[0].is_some(),
            "a selector matching no outbound tag must warn"
        );

        // An exact profile tag restores the match; the next generation
        // rebuild clears the warning.
        let mut servers = ServersFile::default();
        servers
            .profiles
            .push(ServerProfile::new("alpha", OutboundModel::default()));
        settings.routing.balancers[0].selector = vec![servers.profiles[0].tag()];
        screen.refresh_view_cache(1, Language::En, &servers, &settings);
        assert!(
            screen.view_cache.as_ref().unwrap().balancer_warnings[0].is_none(),
            "a selector matching a seeded profile must not warn"
        );
    }
}

/// Balancer runtime eviction (evict-absent): the runtime
/// map holds live per-balancer UI state and must stay bounded by the tags
/// present in the routing model. Mirrors the `prev_traffic` precedent in
/// `rt::tests`: entries for tags absent from the model are evicted in one
/// pass on model change, live state for present tags survives, and the map's
/// own length is the size the tests watch through every insert/evict cycle.
#[cfg(test)]
mod balancer_runtime_eviction_tests {
    use super::{
        Balancer, BalancerInfoView, BalancerPending, Language, Request, RoutingScreen, ServersFile,
        Settings,
    };
    use tokio::sync::oneshot;

    fn balancer(tag: &str) -> Balancer {
        Balancer::new(tag.into(), "srv-".into())
    }

    /// A live pending request with a real reply channel behind it. The
    /// sender is dropped immediately — nothing ever answers in these tests,
    /// and eviction drops the request along with its entry.
    fn pending() -> BalancerPending {
        let (_, rx) = oneshot::channel();
        BalancerPending::Info {
            request: Request::reply(rx),
        }
    }

    /// A balancer removed from the model loses only its own entry: other
    /// balancers keep their live state (pending request, info, feedback).
    #[test]
    fn balancer_removed_evicts_its_entry_and_keeps_live_state() {
        let mut screen = RoutingScreen::default();
        let servers = ServersFile::default();
        let mut settings = Settings::default();
        settings.routing.balancers.push(balancer("edge"));
        settings.routing.balancers.push(balancer("accel"));
        settings.routing.balancers.push(balancer("tunnel"));

        // Live UI state created through the real insert path, so every entry
        // the eviction pass must account for exists before it runs.
        {
            let edge = RoutingScreen::balancer_runtime_state(&mut screen.balancer_runtime, "edge");
            edge.pending_request = Some(pending());
            edge.info = Some(BalancerInfoView {
                override_target: Some("direct".into()),
                principle_targets: Some(vec!["srv-a".into(), "srv-b".into()]),
            });
        }
        {
            let accel =
                RoutingScreen::balancer_runtime_state(&mut screen.balancer_runtime, "accel");
            accel.pending_request = Some(pending());
        }
        {
            let tunnel =
                RoutingScreen::balancer_runtime_state(&mut screen.balancer_runtime, "tunnel");
            tunnel.feedback = Some((false, "no route".into()));
        }
        assert_eq!(
            screen.balancer_runtime.len(),
            3,
            "each balancer's editor must create exactly one runtime entry"
        );

        // One model change: "accel" is deleted (the edit frame's bump),
        // then the generation-gated pass evicts its entry.
        settings.routing.balancers.remove(1);
        screen.refresh_view_cache(1, Language::En, &servers, &settings);

        assert_eq!(
            screen.balancer_runtime.len(),
            2,
            "the map must shrink to the live set"
        );
        assert!(
            !screen.balancer_runtime.contains_key("accel"),
            "the removed balancer's entry must be evicted"
        );
        assert!(
            screen.balancer_runtime["edge"].pending_request.is_some(),
            "a surviving balancer's pending request must be untouched"
        );
        assert_eq!(
            screen.balancer_runtime["edge"]
                .info
                .as_ref()
                .unwrap()
                .override_target
                .as_deref(),
            Some("direct"),
            "a surviving balancer's info payload must be untouched"
        );
        assert_eq!(
            screen.balancer_runtime["tunnel"].feedback.as_ref().unwrap(),
            &(false, "no route".to_string()),
            "a surviving balancer's feedback must be untouched"
        );
    }

    /// Renaming a balancer evicts the old key; the new tag's entry is
    /// created on demand when the editor renders, never duplicated.
    #[test]
    fn tag_rename_evicts_the_old_key_without_duplicates() {
        let mut screen = RoutingScreen::default();
        let servers = ServersFile::default();
        let mut settings = Settings::default();
        settings.routing.balancers.push(balancer("edge"));
        settings.routing.balancers.push(balancer("tunnel"));

        {
            let edge = RoutingScreen::balancer_runtime_state(&mut screen.balancer_runtime, "edge");
            edge.pending_request = Some(pending());
        }
        {
            let tunnel =
                RoutingScreen::balancer_runtime_state(&mut screen.balancer_runtime, "tunnel");
            tunnel.pending_request = Some(pending());
        }
        assert_eq!(
            screen.balancer_runtime.len(),
            2,
            "each balancer's editor must create exactly one runtime entry"
        );

        // One model change: the balancer is renamed (tag rewritten in the
        // model; rule-reference rewrites are the model's concern, not the
        // map's).
        settings.routing.balancers[0].tag = "edge-2".into();
        screen.refresh_view_cache(1, Language::En, &servers, &settings);

        assert!(
            !screen.balancer_runtime.contains_key("edge"),
            "the renamed-away tag must be evicted"
        );
        assert_eq!(
            screen.balancer_runtime.len(),
            1,
            "only the renamed-away tag's entry may be evicted"
        );
        assert!(
            screen.balancer_runtime["tunnel"].pending_request.is_some(),
            "an unrelated balancer keeps its live state"
        );

        // The editor renders the new tag next frame: exactly one entry is
        // created for it alongside the survivor — no duplicates.
        {
            let renamed =
                RoutingScreen::balancer_runtime_state(&mut screen.balancer_runtime, "edge-2");
            renamed.known_target = "direct".into();
        }
        assert_eq!(
            screen.balancer_runtime.len(),
            2,
            "one entry per live tag, no duplicates"
        );
        assert_eq!(screen.balancer_runtime["edge-2"].known_target, "direct");
    }

    /// Repeated model churn keeps the map bounded by the model size: a
    /// 50-tag set shrinks to the live set in one pass, and subsequent
    /// shrink/grow cycles move the map exactly with the model.
    #[test]
    fn repeated_changes_keep_the_map_bounded_by_the_model() {
        let mut screen = RoutingScreen::default();
        let servers = ServersFile::default();
        let mut settings = Settings::default();
        for i in 0..50 {
            settings
                .routing
                .balancers
                .push(balancer(&format!("tag-{i}")));
            let state = RoutingScreen::balancer_runtime_state(
                &mut screen.balancer_runtime,
                &format!("tag-{i}"),
            );
            state.pending_request = Some(pending());
        }
        assert_eq!(
            screen.balancer_runtime.len(),
            50,
            "every balancer's editor must create exactly one runtime entry"
        );

        // The model reports only 5 of the 50 tags: one pass evicts 45.
        settings.routing.balancers.retain(|b| {
            matches!(
                b.tag.as_str(),
                "tag-0" | "tag-1" | "tag-2" | "tag-3" | "tag-4"
            )
        });
        screen.refresh_view_cache(1, Language::En, &servers, &settings);

        assert_eq!(
            screen.balancer_runtime.len(),
            5,
            "stale tags must be evicted"
        );
        assert!(!screen.balancer_runtime.contains_key("tag-5"));
        assert!(!screen.balancer_runtime.contains_key("tag-49"));
        for i in 0..5 {
            assert!(
                screen.balancer_runtime[&format!("tag-{i}")]
                    .pending_request
                    .is_some(),
                "surviving entries keep their live state"
            );
        }

        // Shrink again: 2 remain.
        settings
            .routing
            .balancers
            .retain(|b| b.tag == "tag-1" || b.tag == "tag-3");
        screen.refresh_view_cache(2, Language::En, &servers, &settings);
        assert_eq!(screen.balancer_runtime.len(), 2);

        // Grow the model: added tags have no runtime entry until their
        // editor opens, so the map never exceeds the model size.
        for i in 5..8 {
            settings
                .routing
                .balancers
                .push(balancer(&format!("tag-{i}")));
        }
        screen.refresh_view_cache(3, Language::En, &servers, &settings);
        assert_eq!(screen.balancer_runtime.len(), 2);
        assert!(screen.balancer_runtime.len() <= settings.routing.balancers.len());

        // Opening one of the new tags' editors creates exactly one entry.
        {
            let state =
                RoutingScreen::balancer_runtime_state(&mut screen.balancer_runtime, "tag-5");
            state.pending_request = Some(pending());
        }
        assert_eq!(screen.balancer_runtime.len(), 3);
    }

    /// Idle frames are pure: with no model change, the generation gate
    /// short-circuits and the runtime map (its keys and every entry's live
    /// state) stays untouched.
    #[test]
    fn idle_frames_leave_the_map_untouched() {
        let mut screen = RoutingScreen::default();
        let servers = ServersFile::default();
        let mut settings = Settings::default();
        settings.routing.balancers.push(balancer("edge"));
        settings.routing.balancers.push(balancer("tunnel"));

        {
            let edge = RoutingScreen::balancer_runtime_state(&mut screen.balancer_runtime, "edge");
            edge.pending_request = Some(pending());
        }
        {
            let tunnel =
                RoutingScreen::balancer_runtime_state(&mut screen.balancer_runtime, "tunnel");
            tunnel.pending_request = Some(pending());
        }
        screen.refresh_view_cache(0, Language::En, &servers, &settings);

        assert_eq!(
            screen.balancer_runtime.len(),
            2,
            "the two editors must have created two entries"
        );
        let before_tags: Vec<String> = screen.balancer_runtime.keys().cloned().collect();

        for _ in 0..10 {
            screen.refresh_view_cache(0, Language::En, &servers, &settings);
        }

        assert_eq!(
            screen
                .balancer_runtime
                .keys()
                .cloned()
                .collect::<Vec<String>>(),
            before_tags,
            "idle frames must not grow or shrink the map"
        );
        assert!(screen.balancer_runtime["edge"].pending_request.is_some());
        assert!(screen.balancer_runtime["tunnel"].pending_request.is_some());
    }
}

/// "first item +N" condensation of a string list for summary rows.
fn one_plus(v: &[String]) -> String {
    match v.len() {
        0 => String::new(),
        1 => v[0].clone(),
        n => format!("{} +{}", v[0], n - 1),
    }
}

fn rule_summary(lang: Language, r: &Rule) -> String {
    let mut parts = Vec::new();
    if !r.domain.is_empty() {
        parts.push(t_fmt(lang, Key::RuleSummaryDomain, &[&one_plus(&r.domain)]));
    }
    if !r.ip.is_empty() {
        parts.push(t_fmt(lang, Key::RuleSummaryIp, &[&one_plus(&r.ip)]));
    }
    if !r.port.is_empty() {
        parts.push(t_fmt(lang, Key::RuleSummaryPort, &[&r.port]));
    }
    if !r.network.is_empty() {
        parts.push(r.network.clone());
    }
    if !r.protocol.is_empty() {
        parts.push(t_fmt(
            lang,
            Key::RuleSummaryProto,
            &[&one_plus(&r.protocol)],
        ));
    }
    if !r.inbound_tag.is_empty() {
        parts.push(t_fmt(
            lang,
            Key::RuleSummaryIn,
            &[&one_plus(&r.inbound_tag)],
        ));
    }
    if !r.process.is_empty() {
        parts.push(t_fmt(lang, Key::RuleSummaryProc, &[&one_plus(&r.process)]));
    }
    if parts.is_empty() {
        t(lang, Key::RuleSummaryMatchAll).into()
    } else {
        parts.join(" · ")
    }
}

fn rule_target(lang: Language, r: &Rule) -> String {
    if !r.outbound_tag.is_empty() {
        r.outbound_tag.clone()
    } else if !r.balancer_tag.is_empty() {
        t_fmt(lang, Key::RuleTargetBalancer, &[&r.balancer_tag])
    } else {
        String::new()
    }
}

/// The painted target label of a rule row: the arrow-wrapped target, or an
/// empty string when the rule has no target (the caller renders the "no
/// target" hint). Memoized with the row so idle frames never format it.
fn rule_target_line(lang: Language, r: &Rule) -> String {
    let target = rule_target(lang, r);
    if target.is_empty() {
        String::new()
    } else {
        t_fmt(lang, Key::RoutingTargetArrow, &[&target])
    }
}

pub(crate) fn kv_from_map(m: &Map<String, Value>) -> Vec<(String, String)> {
    m.iter()
        .map(|(k, v)| {
            let s = match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            (k.clone(), s)
        })
        .collect()
}

pub(crate) fn map_from_kv(kv: &[(String, String)]) -> Map<String, Value> {
    kv.iter()
        .filter(|(k, _)| !k.trim().is_empty())
        .map(|(k, v)| (k.trim().to_string(), Value::String(v.trim().to_string())))
        .collect()
}
/// Xray routing PortList grammar (`infra/conf/common.go`): a
/// comma-separated list of port numbers or from-to ranges, every endpoint
/// 0-65535, from ≤ to (Xray's `PortRange.UnmarshalJSON` rejects reversed
/// ranges), no empty tokens. The empty string is the absent condition
/// (matches everything).
fn valid_port_list(s: &str) -> bool {
    if s.trim().is_empty() {
        return true;
    }
    s.split(',').all(|token| valid_port_token(token.trim()))
}

fn valid_port_token(token: &str) -> bool {
    match token.split_once('-') {
        Some((from, to)) => match (valid_port_number(from), valid_port_number(to)) {
            (Some(from), Some(to)) => from <= to,
            _ => false,
        },
        None => valid_port_number(token).is_some(),
    }
}

fn valid_port_number(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let port = s.parse::<u32>().ok()?;
    (port <= u16::MAX as u32).then_some(port)
}

/// Xray routing IP-rule grammar (`common/geodata/rule_parser.go`):
/// each token is an IP literal or CIDR range (v4 prefix ≤ 32, v6 prefix ≤
/// 128) or a `geoip:` tag reference; leading `!` negations are part of the
/// grammar. Tag existence is checked against the installed geoip.dat at
/// load, so any non-empty `geoip:` tag passes here.
fn valid_ip_rule(s: &str) -> bool {
    let s = s.trim_start_matches('!');
    if let Some(tag) = s.strip_prefix("geoip:") {
        return !tag.is_empty();
    }
    match s.split_once('/') {
        Some((ip, prefix)) => {
            let Ok(ip) = ip.parse::<IpAddr>() else {
                return false;
            };
            let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
            prefix.parse::<u32>().is_ok_and(|bits| bits <= max_prefix)
        }
        None => s.parse::<IpAddr>().is_ok(),
    }
}

/// Inline red-tier error for a rule IP list (`ip`, `source`, `local_ip`):
/// Xray's `ParseIPRules` hard-rejects any non-geoip token that is not an IP
/// literal or CIDR range at config load ("illegal ip rule"), so the editor
/// flags those tokens before the config is ever generated.
fn ip_list_error(lang: Language, items: &[String]) -> Option<String> {
    items
        .iter()
        .any(|item| !valid_ip_rule(item))
        .then(|| t(lang, Key::RoutingIpListInvalid).to_string())
}

/// Checkbox-gated DragValue for `Option<f64>`; enabling picks `default_on`.
fn opt_f64(
    ui: &mut Ui,
    lang: Language,
    label: &str,
    v: &mut Option<f64>,
    range: std::ops::RangeInclusive<f64>,
    default_on: f64,
) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        ui.label(label);
        let mut on = v.is_some();
        if ui.checkbox(&mut on, "").changed() {
            *v = on.then_some(default_on);
            changed = true;
        }
        if let Some(x) = v.as_mut() {
            if ui.add(DragValue::new(x).range(range).speed(0.01)).changed() {
                changed = true;
            }
        } else {
            ui.label(RichText::new(t(lang, Key::Auto)).weak());
        }
    });
    changed
}

/// Checkbox over `Option<bool>`: checked = Some(true), unchecked = None
/// (absent and false are equivalent for these core flags).
pub(crate) fn opt_bool(ui: &mut Ui, label: &str, v: &mut Option<bool>) -> bool {
    let mut on = v.unwrap_or(false);
    if ui.checkbox(&mut on, label).changed() {
        *v = if on { Some(true) } else { None };
        true
    } else {
        false
    }
}

#[cfg(test)]
mod trial_rule_validation_tests {
    use super::*;
    use crate::sys::geodata::{GeodataFileMetadata, GeodataOperation};
    use std::path::PathBuf;

    /// A draft that passes every check: tag, live target, and a condition.
    fn draft_screen() -> RoutingScreen {
        let mut screen = RoutingScreen::default();
        screen.trial.draft.rule_tag = "trial-a".into();
        screen.trial.draft.outbound_tag = "direct".into();
        screen.trial.draft.domains = "example.com".into();
        screen
    }

    fn test_error(file: &str) -> GeodataError {
        GeodataError::Io {
            operation: GeodataOperation::Open,
            path: file.into(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "test"),
        }
    }

    fn fixture_catalog(codes: &[&str]) -> GeodataCatalog {
        GeodataCatalog {
            codes: codes.iter().map(|code| code.to_string()).collect(),
            metadata: GeodataFileMetadata {
                path: PathBuf::from("fixture.dat"),
                byte_len: 0,
                modified: None,
            },
        }
    }

    fn loaded_snapshot(geosite: &[&str], geoip: &[&str]) -> GeodataSnapshot {
        GeodataSnapshot {
            geosite: Ok(fixture_catalog(geosite)),
            geoip: Ok(fixture_catalog(geoip)),
        }
    }

    /// A trial rule with no condition can never match anything, so the
    /// dialog rejects it before the request is sent.
    #[test]
    fn build_rejects_an_empty_condition_set() {
        let mut screen = draft_screen();
        screen.trial.draft.domains.clear();

        let error = screen.build_trial_rule(Language::En).unwrap_err();
        assert_eq!(error, t(Language::En, Key::TrialRuleNeedsCondition));

        // Any single condition list is enough.
        screen.trial.draft.processes = "firefox.exe".into();
        assert!(screen.build_trial_rule(Language::En).is_ok());
    }

    /// A target the running core does not have fails the add inside the
    /// core, so the dialog rejects it while the live set is known; an
    /// unknown set (never read, or the read failed) stays permissive.
    #[test]
    fn build_rejects_a_target_a_known_live_set_lacks() {
        let mut screen = draft_screen();
        screen.trial.live_out_tags = Some(vec!["proxy".into()]);

        let error = screen.build_trial_rule(Language::En).unwrap_err();
        assert_eq!(
            error,
            t_fmt(Language::En, Key::TrialRuleTargetNotLive, &[&"direct"])
        );

        screen.trial.draft.outbound_tag = "proxy".into();
        assert!(screen.build_trial_rule(Language::En).is_ok());

        screen.trial.live_out_tags = None;
        screen.trial.draft.outbound_tag = "direct".into();
        assert!(screen.build_trial_rule(Language::En).is_ok());
    }

    /// A `geosite:`/`geoip:` code the loaded catalog does not carry is
    /// rejected before the request; `ext:` forms, a catalog that failed to
    /// load, and an unloaded catalog all stay permissive.
    #[test]
    fn build_checks_geodata_codes_against_the_loaded_catalogs() {
        let mut screen = draft_screen();
        screen.geodata_snapshot = Some(loaded_snapshot(&["google", "cn"], &["cn"]));

        // The `@attr` suffix is not part of the code, and the code
        // comparison ignores case.
        screen.trial.draft.domains = "geosite:GOOGLE@cn".into();
        assert!(screen.build_trial_rule(Language::En).is_ok());

        screen.trial.draft.domains = "geosite:NOPE@cn".into();
        let error = screen.build_trial_rule(Language::En).unwrap_err();
        assert_eq!(
            error,
            t_fmt(Language::En, Key::TrialRuleCodeUnknown, &[&"NOPE"])
        );

        screen.trial.draft.domains.clear();
        screen.trial.draft.ips = "geoip:nope".into();
        let error = screen.build_trial_rule(Language::En).unwrap_err();
        assert_eq!(
            error,
            t_fmt(Language::En, Key::TrialRuleCodeUnknown, &[&"nope"])
        );

        screen.trial.draft.ips = "geoip:CN".into();
        assert!(screen.build_trial_rule(Language::En).is_ok());

        // Codes in `ext:` form name a file the dialog knows nothing about.
        screen.trial.draft.ips = "ext:other.dat:nope".into();
        assert!(screen.build_trial_rule(Language::En).is_ok());

        // A failed load leaves the catalog's coverage unknown.
        screen.geodata_snapshot = Some(GeodataSnapshot {
            geosite: Err(test_error("geosite.dat")),
            geoip: Err(test_error("geoip.dat")),
        });
        screen.trial.draft.ips = "geoip:nope".into();
        assert!(screen.build_trial_rule(Language::En).is_ok());

        screen.geodata_snapshot = None;
        assert!(screen.build_trial_rule(Language::En).is_ok());
    }

    /// A leading `!` (the reverse prefix the IP hint documents and the
    /// runtime's own parser strips before it reads the code) must not hide
    /// the code from the catalog check; an entry that is nothing but the
    /// prefix leaves no code to compare and stays the converter's check.
    #[test]
    fn build_checks_negated_geodata_codes_against_the_loaded_catalogs() {
        let mut screen = draft_screen();
        screen.geodata_snapshot = Some(loaded_snapshot(&["google", "cn"], &["cn"]));
        screen.trial.draft.domains.clear();

        screen.trial.draft.ips = "!geoip:nope".into();
        let error = screen.build_trial_rule(Language::En).unwrap_err();
        assert_eq!(
            error,
            t_fmt(Language::En, Key::TrialRuleCodeUnknown, &[&"nope"])
        );

        screen.trial.draft.ips = "!geoip:CN".into();
        assert!(screen.build_trial_rule(Language::En).is_ok());

        // The same strip applies to the domain-side prefix.
        screen.trial.draft.ips.clear();
        screen.trial.draft.domains = "!geosite:NOPE@cn".into();
        let error = screen.build_trial_rule(Language::En).unwrap_err();
        assert_eq!(
            error,
            t_fmt(Language::En, Key::TrialRuleCodeUnknown, &[&"NOPE"])
        );

        // Nothing but the prefix: the converter's own grammar check answers.
        screen.trial.draft.domains.clear();
        screen.trial.draft.ips = "!".into();
        let error = screen.build_trial_rule(Language::En).unwrap_err();
        assert_eq!(error, t(Language::En, Key::GrpcUnsupportedAddressFamily));
    }

    /// A tag this session already asked for is taken even when the last
    /// landed read-back does not list it: the registry keeps Remove
    /// reachable for those tags, and an in-flight add's tag may already be
    /// held by the core — a duplicate must never reach the core and then
    /// look like a success.
    #[test]
    fn build_rejects_a_tag_the_session_registry_or_in_flight_add_holds() {
        let mut screen = draft_screen();
        screen.trial.injected_tags = vec!["trial-a".into()];
        let error = screen.build_trial_rule(Language::En).unwrap_err();
        assert_eq!(error, t(Language::En, Key::TrialRuleTagTaken));

        let mut screen = draft_screen();
        screen.trial.pending_add_tag = Some("trial-a".into());
        let error = screen.build_trial_rule(Language::En).unwrap_err();
        assert_eq!(error, t(Language::En, Key::TrialRuleTagTaken));
    }

    #[test]
    fn build_requires_tag_target_and_unique_tag() {
        let mut screen = draft_screen();
        assert!(screen.build_trial_rule(Language::En).is_ok());

        screen.trial.draft.rule_tag.clear();
        let error = screen.build_trial_rule(Language::En).unwrap_err();
        assert_eq!(error, t(Language::En, Key::TrialRuleTagRequired));

        let mut screen = draft_screen();
        screen.trial.rules.push(("direct".into(), "trial-a".into()));
        let error = screen.build_trial_rule(Language::En).unwrap_err();
        assert_eq!(error, t(Language::En, Key::TrialRuleTagTaken));

        let mut screen = draft_screen();
        screen.trial.draft.outbound_tag.clear();
        let error = screen.build_trial_rule(Language::En).unwrap_err();
        assert_eq!(error, t(Language::En, Key::TrialRuleTargetRequired));

        // Balancer mode targets through balancer_tag instead.
        let mut screen = draft_screen();
        screen.trial.draft.outbound_tag.clear();
        screen.trial.draft.use_balancer = true;
        screen.trial.draft.balancer_tag = "accel".into();
        let rule = screen
            .build_trial_rule(Language::En)
            .expect("balancer target");
        assert_eq!(rule.balancer_tag, "accel");
        assert!(rule.outbound_tag.is_empty());
    }

    #[test]
    fn build_splits_lines_and_surfaces_grammar_errors() {
        let mut screen = draft_screen();
        {
            let draft = &mut screen.trial.draft;
            draft.domains = "example.com\n  geosite:cn  \n\n".into();
            draft.ips = "10.0.0.0/8\n".into();
            draft.processes = "firefox.exe\n".into();
        }
        let rule = screen.build_trial_rule(Language::En).expect("valid draft");
        assert_eq!(rule.domain, vec!["example.com", "geosite:cn"]);
        assert_eq!(rule.ip, vec!["10.0.0.0/8"]);
        assert_eq!(rule.process, vec!["firefox.exe"]);
        assert_eq!(rule.rule_tag, "trial-a");

        // Grammar errors come from the same converter the runtime uses.
        screen.trial.draft.ips = "999.1.2.3".into();
        let error = screen.build_trial_rule(Language::En).unwrap_err();
        assert_eq!(
            error,
            t(Language::En, Key::GrpcUnsupportedAddressFamily),
            "the converter's keyed sentence must render in the active language"
        );
    }

    #[test]
    fn invalidate_clears_list_registry_pending_and_feedback_but_keeps_draft() {
        use tokio::sync::oneshot;

        let mut screen = draft_screen();
        screen.trial.rules = vec![
            ("direct".into(), "trial-a".into()),
            ("direct".into(), "uuid-committed-rule".into()),
        ];
        screen.trial.injected_tags = vec!["trial-a".into()];
        screen.trial.visible = vec![("direct".into(), "trial-a".into())];
        screen.trial.pending_add_tag = Some("trial-a".into());
        screen.trial.pending_add_target = Some("direct".into());
        screen.trial.remove_queue.push_back("trial-a".into());
        let (_, receiver) = oneshot::channel::<Result<TrialRuleAddOutcome, DiagError>>();
        screen.trial.pending_add = Request::reply(receiver);
        let (_, receiver) = oneshot::channel::<Result<Vec<(String, String)>, DiagError>>();
        screen.trial.pending_inventory = Request::reply(receiver);
        let (_, receiver) = oneshot::channel::<Result<RuntimeStateView, DiagError>>();
        screen.trial.pending_live_out = Request::reply(receiver);
        screen.trial.live_out_tags = Some(vec!["direct".into()]);
        screen.trial.feedback = Some((false, "boom".into()));
        screen.trial.draft.domains = "kept.example".into();

        screen.invalidate_trial_rules();

        assert!(screen.trial.rules.is_empty());
        assert!(screen.trial.injected_tags.is_empty());
        assert!(screen.trial.visible.is_empty());
        assert!(screen.trial.pending_add_tag.is_none());
        assert!(screen.trial.pending_add_target.is_none());
        assert!(screen.trial.remove_queue.is_empty());
        assert!(!screen.trial.pending_add.is_pending());
        assert!(!screen.trial.pending_inventory.is_pending());
        assert!(!screen.trial_busy());
        assert!(screen.trial.feedback.is_none());
        assert!(screen.trial.live_out_tags.is_none());
        assert!(!screen.trial.pending_live_out.is_pending());
        assert_eq!(screen.trial.draft.domains, "kept.example");
        assert_eq!(screen.trial_rule_count(), 0);
    }

    /// The render rows are the live inventory intersected with the
    /// injected-tag registry: committed (UUID) and untagged internal rules
    /// never surface, and the banner counts exactly the rows the grid shows.
    #[test]
    fn visible_rows_and_count_exclude_committed_rules() {
        let mut screen = draft_screen();
        screen.trial.rules = vec![
            ("direct".into(), "trial-a".into()),
            ("direct".into(), "uuid-committed-rule".into()),
            ("direct".into(), String::new()),
        ];
        screen.trial.injected_tags = vec!["trial-a".into(), "trial-b".into()];

        screen.rebuild_visible_trial_rules();

        assert_eq!(
            screen.trial.visible,
            vec![("direct".to_string(), "trial-a".to_string())]
        );
        assert_eq!(
            screen.trial_rule_count(),
            1,
            "the count is the visible row count, never a tag with no row"
        );
    }

    /// An injected tag the core no longer lists (Remove landed) is pruned
    /// from the registry, so the banner count and Clear All follow reality.
    #[test]
    fn remove_result_prunes_tags_that_left_the_live_list() {
        let mut screen = draft_screen();
        screen.trial.injected_tags = vec!["trial-a".into(), "trial-b".into()];
        screen.trial.rules = vec![
            ("direct".into(), "trial-a".into()),
            ("direct".into(), "trial-b".into()),
        ];
        screen.rebuild_visible_trial_rules();

        // Remove of trial-b lands: the refreshed live list has only trial-a.
        screen.trial.rules = vec![("direct".into(), "trial-a".into())];
        screen
            .trial
            .injected_tags
            .retain(|tag| screen.trial.rules.iter().any(|(_, live)| live == tag));
        screen.rebuild_visible_trial_rules();

        assert_eq!(screen.trial.injected_tags, vec!["trial-a".to_string()]);
        assert_eq!(
            screen.trial.visible,
            vec![("direct".to_string(), "trial-a".to_string())]
        );
        assert_eq!(screen.trial_rule_count(), 1);
    }
}

/// Per-tag balancer reply consumption: each map
/// entry polls its own pending receiver, so a result can only reach the
/// entry that requested it. Pure unit tests — no egui, no runtime.
#[cfg(test)]
mod balancer_runtime_consume_tests {
    use super::*;
    use tokio::sync::oneshot;

    fn screen_with_entry(tag: &str) -> RoutingScreen {
        let mut screen = RoutingScreen::default();
        screen.balancer_runtime.entry(tag.to_string()).or_default();
        screen
    }

    fn entry_mut<'a>(screen: &'a mut RoutingScreen, tag: &str) -> &'a mut BalancerRuntimeUi {
        screen
            .balancer_runtime
            .get_mut(tag)
            .expect("seeded balancer entry")
    }

    /// A keyed fixture failure: production reply errors carry keys, so the
    /// tests do too, and the expected feedback text renders from the key.
    fn fixture_error() -> DiagError {
        DiagError::from(Diag::new(Key::RuntimeChannelClosed))
    }

    #[test]
    fn info_ok_applies_the_snapshot_with_refreshed_feedback() {
        let mut screen = screen_with_entry("edge");
        let (tx, rx) = oneshot::channel();
        entry_mut(&mut screen, "edge").pending_request = Some(BalancerPending::Info {
            request: Request::reply(rx),
        });
        tx.send(Ok(BalancerInfoView {
            override_target: Some("direct".into()),
            principle_targets: Some(vec!["srv-a".into()]),
        }))
        .expect("send the info verdict");

        screen.consume_balancer_results(Language::En);

        let edge = &screen.balancer_runtime["edge"];
        assert!(edge.pending_request.is_none());
        assert_eq!(
            edge.info.as_ref().unwrap().override_target.as_deref(),
            Some("direct")
        );
        assert_eq!(
            edge.feedback,
            Some((
                true,
                t(Language::En, Key::RuntimeStateRefreshed).to_string()
            ))
        );
    }

    /// The principle-targets line is memoized per info reply: consuming a
    /// reply refreshes it, idle frames reuse the cached text, and a newer
    /// reply replaces it instead of replaying the first list.
    #[test]
    fn info_reply_refreshes_the_memoized_principle_targets_line() {
        let mut screen = screen_with_entry("edge");
        let (tx, rx) = oneshot::channel();
        entry_mut(&mut screen, "edge").pending_request = Some(BalancerPending::Info {
            request: Request::reply(rx),
        });
        tx.send(Ok(BalancerInfoView {
            override_target: None,
            principle_targets: Some(vec!["srv-a".into(), "srv-b".into()]),
        }))
        .expect("send the info verdict");
        screen.consume_balancer_results(Language::En);

        let state = entry_mut(&mut screen, "edge");
        state.refresh_principle_line(Language::En);
        assert_eq!(
            state.principle_line_text(),
            t_fmt(Language::En, Key::PrincipleTargets, &[&"srv-a, srv-b"]).as_str(),
            "the line must render the consumed reply's target list"
        );
        let cached = state.principle_line_text().as_ptr();
        state.refresh_principle_line(Language::En);
        assert_eq!(
            state.principle_line_text().as_ptr(),
            cached,
            "idle frames must reuse the rendered line"
        );

        // A second reply carries a different list: the memo follows it.
        let (tx, rx) = oneshot::channel();
        state.pending_request = Some(BalancerPending::Info {
            request: Request::reply(rx),
        });
        tx.send(Ok(BalancerInfoView {
            override_target: None,
            principle_targets: None,
        }))
        .expect("send the refreshed verdict");
        screen.consume_balancer_results(Language::En);

        let state = entry_mut(&mut screen, "edge");
        state.refresh_principle_line(Language::En);
        assert_eq!(
            state.principle_line_text(),
            t(Language::En, Key::PrincipleTargetsHidden)
        );
    }

    #[test]
    fn info_error_surfaces_keyed_feedback() {
        let mut screen = screen_with_entry("edge");
        let (tx, rx) = oneshot::channel();
        entry_mut(&mut screen, "edge").pending_request = Some(BalancerPending::Info {
            request: Request::reply(rx),
        });
        tx.send(Err(fixture_error())).expect("send the failure");

        screen.consume_balancer_results(Language::En);

        let edge = &screen.balancer_runtime["edge"];
        assert!(edge.pending_request.is_none());
        assert!(edge.info.is_none());
        assert_eq!(
            edge.feedback,
            Some((
                false,
                t(Language::En, Key::RuntimeChannelClosed).to_string()
            ))
        );
    }

    #[test]
    fn mutate_set_ok_applies_the_override_with_applied_feedback() {
        let mut screen = screen_with_entry("edge");
        let (tx, rx) = oneshot::channel();
        entry_mut(&mut screen, "edge").pending_request = Some(BalancerPending::Mutate {
            target: Some("direct".into()),
            request: Request::reply(rx),
        });
        tx.send(Ok(())).expect("send the override verdict");

        screen.consume_balancer_results(Language::En);

        let edge = &screen.balancer_runtime["edge"];
        assert!(edge.pending_request.is_none());
        assert_eq!(
            edge.info.as_ref().unwrap().override_target.as_deref(),
            Some("direct"),
            "the trimmed target the UI sent must be echoed as the override"
        );
        assert_eq!(
            edge.feedback,
            Some((
                true,
                t_fmt(Language::En, Key::RoutingOverrideApplied, &[&"direct"]).to_string()
            ))
        );
    }

    #[test]
    fn mutate_clear_ok_clears_the_override_with_cleared_feedback() {
        let mut screen = screen_with_entry("edge");
        let (tx, rx) = oneshot::channel();
        entry_mut(&mut screen, "edge").pending_request = Some(BalancerPending::Mutate {
            target: None,
            request: Request::reply(rx),
        });
        tx.send(Ok(())).expect("send the clear verdict");

        screen.consume_balancer_results(Language::En);

        let edge = &screen.balancer_runtime["edge"];
        assert!(edge.pending_request.is_none());
        assert_eq!(edge.info.as_ref().unwrap().override_target, None);
        assert_eq!(
            edge.feedback,
            Some((
                true,
                t(Language::En, Key::RoutingOverrideCleared).to_string()
            ))
        );
    }

    #[test]
    fn mutate_error_surfaces_keyed_feedback() {
        let mut screen = screen_with_entry("edge");
        let (tx, rx) = oneshot::channel();
        entry_mut(&mut screen, "edge").pending_request = Some(BalancerPending::Mutate {
            target: Some("direct".into()),
            request: Request::reply(rx),
        });
        tx.send(Err(fixture_error())).expect("send the failure");

        screen.consume_balancer_results(Language::En);

        let edge = &screen.balancer_runtime["edge"];
        assert!(edge.pending_request.is_none());
        assert!(edge.info.is_none());
        assert_eq!(
            edge.feedback,
            Some((
                false,
                t(Language::En, Key::RuntimeChannelClosed).to_string()
            ))
        );
    }

    #[test]
    fn empty_pending_is_left_in_place_and_closed_is_cleared() {
        let mut screen = screen_with_entry("edge");
        // Still in flight: the receiver stays pending for the next frame.
        let (tx, rx) = oneshot::channel();
        entry_mut(&mut screen, "edge").pending_request = Some(BalancerPending::Info {
            request: Request::reply(rx),
        });
        screen.consume_balancer_results(Language::En);
        assert!(
            screen.balancer_runtime["edge"].pending_request.is_some(),
            "an unanswered request must stay pending"
        );
        drop(tx);

        // Sender gone: defensive — the reply guard always sends a terminal
        // before the sender drops, so Closed clears the slot without feedback.
        let (tx, rx) = oneshot::channel();
        entry_mut(&mut screen, "edge").pending_request = Some(BalancerPending::Mutate {
            target: None,
            request: Request::reply(rx),
        });
        drop(tx);
        screen.consume_balancer_results(Language::En);
        assert!(screen.balancer_runtime["edge"].pending_request.is_none());
        assert!(screen.balancer_runtime["edge"].feedback.is_none());
    }

    #[test]
    fn a_result_only_reaches_its_own_entry() {
        let mut screen = screen_with_entry("edge");
        screen
            .balancer_runtime
            .entry("accel".to_string())
            .or_default();
        let (tx, rx) = oneshot::channel();
        entry_mut(&mut screen, "edge").pending_request = Some(BalancerPending::Info {
            request: Request::reply(rx),
        });
        let (accel_tx, accel_rx) = oneshot::channel();
        entry_mut(&mut screen, "accel").pending_request = Some(BalancerPending::Info {
            request: Request::reply(accel_rx),
        });

        tx.send(Ok(BalancerInfoView {
            override_target: Some("direct".into()),
            principle_targets: None,
        }))
        .expect("send the edge verdict");
        screen.consume_balancer_results(Language::En);

        assert!(
            screen.balancer_runtime["edge"].pending_request.is_none(),
            "the answering entry consumes its own result"
        );
        assert!(
            screen.balancer_runtime["accel"].pending_request.is_some(),
            "an unanswered sibling entry stays pending"
        );
        drop(accel_tx);
    }
}

/// Trial-rule reply consumption: each slot polls its own pending receiver
/// and applies the operation the slot stands for. Pure unit tests over the
/// real command channel — no egui frame, no runtime.
#[cfg(test)]
mod trial_rules_consume_tests {
    use super::*;
    use crate::ui::test_rig::UiTestRig;
    use tokio::sync::oneshot;

    /// Run one consume pass over a live command channel: a queued removal's
    /// next tag (and a send failure on a closed channel) needs the channel
    /// the real frame hands over, while the runtime itself stays out of these
    /// unit tests.
    fn consume(screen: &mut RoutingScreen, lang: Language) {
        let mut rig = UiTestRig::default();
        let mut ctx = rig.ctx();
        screen.consume_trial_results(&mut ctx, lang);
    }

    fn seed_add(
        screen: &mut RoutingScreen,
    ) -> oneshot::Sender<Result<TrialRuleAddOutcome, DiagError>> {
        let (tx, rx) = oneshot::channel();
        screen.trial.pending_add = Request::reply(rx);
        tx
    }

    fn seed_inventory(
        screen: &mut RoutingScreen,
    ) -> oneshot::Sender<Result<Vec<(String, String)>, DiagError>> {
        let (tx, rx) = oneshot::channel();
        screen.trial.pending_inventory = Request::reply(rx);
        tx
    }

    /// A keyed fixture failure: production reply errors carry keys, so the
    /// tests do too, and the expected feedback text renders from the key.
    fn fixture_error() -> DiagError {
        DiagError::from(Diag::new(Key::RuntimeChannelClosed))
    }

    #[test]
    fn add_ok_commits_the_tag_and_refreshes_the_live_list() {
        let mut screen = RoutingScreen::default();
        screen.trial.pending_add_tag = Some("trial-a".into());
        let tx = seed_add(&mut screen);
        tx.send(Ok(TrialRuleAddOutcome {
            rules: Some(vec![("direct".into(), "trial-a".into())]),
        }))
        .expect("send the add verdict");

        consume(&mut screen, Language::En);

        assert!(!screen.trial_busy());
        assert!(screen.trial.pending_add_tag.is_none());
        assert_eq!(screen.trial.injected_tags, vec!["trial-a".to_string()]);
        assert_eq!(
            screen.trial.rules,
            vec![("direct".to_string(), "trial-a".to_string())]
        );
        assert_eq!(screen.trial.visible, screen.trial.rules);
        assert_eq!(screen.trial_rule_count(), 1);
        assert!(screen.trial.feedback.is_none());
    }

    /// `Ok` with no read-back: the core holds the rule, so the tag joins the
    /// registry and the row it would have listed is built from the target the
    /// user submitted — the grid and the banner count stay truthful even
    /// though the list could not be re-read.
    #[test]
    fn add_ok_without_a_readback_adds_the_submitted_row_and_says_so() {
        let mut screen = RoutingScreen::default();
        screen.trial.rules = vec![("direct".into(), "trial-a".into())];
        screen.trial.injected_tags = vec!["trial-a".into()];
        screen.rebuild_visible_trial_rules();
        screen.trial.pending_add_tag = Some("trial-b".into());
        screen.trial.pending_add_target = Some("proxy".into());
        let tx = seed_add(&mut screen);
        tx.send(Ok(TrialRuleAddOutcome { rules: None }))
            .expect("send the add verdict");

        consume(&mut screen, Language::En);

        assert!(!screen.trial_busy());
        assert!(screen.trial.pending_add_tag.is_none());
        assert!(screen.trial.pending_add_target.is_none());
        assert_eq!(
            screen.trial.rules,
            vec![
                ("direct".to_string(), "trial-a".to_string()),
                ("proxy".to_string(), "trial-b".to_string())
            ],
            "the submitted row joins the last known inventory"
        );
        assert_eq!(
            screen.trial.injected_tags,
            vec!["trial-a".to_string(), "trial-b".to_string()]
        );
        assert_eq!(screen.trial.visible, screen.trial.rules);
        assert_eq!(screen.trial_rule_count(), 2);
        assert_eq!(
            screen.trial.feedback,
            Some((
                true,
                t(Language::En, Key::TrialRuleAddedUnlisted).to_string()
            ))
        );

        // A second confirmed verdict for the same tag never doubles the row.
        screen.trial.pending_add_tag = Some("trial-b".into());
        screen.trial.pending_add_target = Some("proxy".into());
        let tx = seed_add(&mut screen);
        tx.send(Ok(TrialRuleAddOutcome { rules: None }))
            .expect("send the add verdict");
        consume(&mut screen, Language::En);
        assert_eq!(
            screen.trial.visible,
            vec![
                ("direct".to_string(), "trial-a".to_string()),
                ("proxy".to_string(), "trial-b".to_string())
            ],
            "a repeated verdict must not duplicate the row"
        );
        assert_eq!(screen.trial_rule_count(), 2);
    }

    /// A failed add may still have landed in the core: the tag stays a
    /// candidate so Remove remains reachable, and the next inventory reply —
    /// the authority on what the core holds — prunes it. Without that prune,
    /// the banner count drifts above the core's own list.
    #[test]
    fn add_error_keeps_the_tag_removable_until_an_inventory_clears_it() {
        let mut screen = RoutingScreen::default();
        screen.trial.rules = vec![("direct".into(), "trial-a".into())];
        screen.trial.pending_add_tag = Some("trial-a".into());
        let tx = seed_add(&mut screen);
        tx.send(Err(fixture_error())).expect("send the add failure");

        consume(&mut screen, Language::En);

        assert!(!screen.trial_busy());
        assert!(screen.trial.pending_add_tag.is_none());
        assert_eq!(
            screen.trial.injected_tags,
            vec!["trial-a".to_string()],
            "an unconfirmed add stays a removable candidate"
        );
        assert_eq!(
            screen.trial.feedback,
            Some((
                false,
                t(Language::En, Key::RuntimeChannelClosed).to_string()
            ))
        );

        let tx = seed_inventory(&mut screen);
        tx.send(Ok(vec![("direct".into(), "uuid-committed-rule".into())]))
            .expect("send the list verdict");
        consume(&mut screen, Language::En);

        assert!(screen.trial.injected_tags.is_empty());
        assert!(screen.trial.visible.is_empty());
        assert_eq!(screen.trial_rule_count(), 0);
    }

    /// A failed add registers the tag (it may have landed) but shows no row,
    /// and the banner counts the rows the grid shows — never a rule the user
    /// cannot see.
    #[test]
    fn a_failed_add_shows_no_row_and_leaves_the_banner_count_empty() {
        let mut screen = RoutingScreen::default();
        screen.trial.pending_add_tag = Some("trial-a".into());
        let tx = seed_add(&mut screen);
        tx.send(Err(fixture_error())).expect("send the add failure");

        consume(&mut screen, Language::En);

        assert_eq!(
            screen.trial.injected_tags,
            vec!["trial-a".to_string()],
            "an unconfirmed add stays a removable candidate"
        );
        assert!(
            screen.trial.visible.is_empty(),
            "a failed add never grows a row"
        );
        assert_eq!(
            screen.trial_rule_count(),
            0,
            "the banner counts the grid's rows, not the registry"
        );
    }

    #[test]
    fn remove_ok_prunes_tags_that_left_the_live_list() {
        let mut screen = RoutingScreen::default();
        screen.trial.injected_tags = vec!["trial-a".into(), "trial-b".into()];
        let tx = seed_inventory(&mut screen);
        tx.send(Ok(vec![("direct".into(), "trial-a".into())]))
            .expect("send the remove verdict");

        consume(&mut screen, Language::En);

        assert!(!screen.trial_busy());
        assert_eq!(screen.trial.injected_tags, vec!["trial-a".to_string()]);
        assert_eq!(
            screen.trial.rules,
            vec![("direct".to_string(), "trial-a".to_string())]
        );
        assert_eq!(screen.trial_rule_count(), 1);
    }

    /// Every landed inventory is the authority: a tag the core no longer
    /// lists leaves the registry, and a failed read leaves both untouched.
    #[test]
    fn list_ok_prunes_tags_the_core_no_longer_lists() {
        let mut screen = RoutingScreen::default();
        screen.trial.injected_tags = vec!["trial-a".into(), "trial-b".into()];
        let tx = seed_inventory(&mut screen);
        tx.send(Ok(vec![
            ("direct".into(), "trial-a".into()),
            ("direct".into(), "trial-b".into()),
        ]))
        .expect("send the list verdict");

        consume(&mut screen, Language::En);

        assert!(!screen.trial_busy());
        assert_eq!(
            screen.trial.rules,
            vec![
                ("direct".to_string(), "trial-a".to_string()),
                ("direct".to_string(), "trial-b".to_string())
            ]
        );
        assert_eq!(
            screen.trial.visible,
            vec![
                ("direct".to_string(), "trial-a".to_string()),
                ("direct".to_string(), "trial-b".to_string())
            ],
            "the refreshed list is filtered back to injected tags"
        );
        assert!(screen.trial.feedback.is_none());

        // The refreshed list omits trial-b: it left the core, so it leaves
        // the registry and the rows together.
        let tx = seed_inventory(&mut screen);
        tx.send(Ok(vec![("direct".into(), "trial-a".into())]))
            .expect("send the list verdict");
        consume(&mut screen, Language::En);

        assert_eq!(screen.trial.injected_tags, vec!["trial-a".to_string()]);
        assert_eq!(
            screen.trial.visible,
            vec![("direct".to_string(), "trial-a".to_string())]
        );
        assert_eq!(screen.trial_rule_count(), 1);

        // A list failure surfaces the keyed error and leaves the list as is.
        let tx = seed_inventory(&mut screen);
        tx.send(Err(fixture_error()))
            .expect("send the list failure");
        consume(&mut screen, Language::En);
        assert_eq!(
            screen.trial.feedback,
            Some((
                false,
                t(Language::En, Key::RuntimeChannelClosed).to_string()
            ))
        );
        assert_eq!(screen.trial.rules.len(), 1);
        assert_eq!(screen.trial_rule_count(), 1);
    }

    /// Both slots feed the same busy gate: the section's buttons and the
    /// dialog's Inject read it, so a request in flight must close them.
    #[test]
    fn trial_busy_reports_either_request_in_flight() {
        let mut screen = RoutingScreen::default();
        assert!(!screen.trial_busy());

        let tx = seed_add(&mut screen);
        assert!(
            screen.trial_busy(),
            "an in-flight add keeps the gate closed"
        );
        tx.send(Ok(TrialRuleAddOutcome::default()))
            .expect("send the add verdict");
        consume(&mut screen, Language::En);
        assert!(!screen.trial_busy());

        let tx = seed_inventory(&mut screen);
        assert!(
            screen.trial_busy(),
            "an in-flight inventory read keeps the gate closed"
        );
        tx.send(Ok(Vec::new())).expect("send the list verdict");
        consume(&mut screen, Language::En);
        assert!(!screen.trial_busy());
    }

    #[test]
    fn in_flight_requests_stay_pending_and_a_spent_channel_clears_them() {
        let mut screen = RoutingScreen::default();
        // Still in flight: nothing to consume this frame.
        let (tx, rx) = oneshot::channel();
        screen.trial.pending_inventory = Request::reply(rx);
        consume(&mut screen, Language::En);
        assert!(screen.trial.pending_inventory.is_pending());
        assert!(screen.trial_busy());
        drop(tx);

        // Sender gone: defensive — the request clears itself, and the other
        // slot is untouched by its neighbour's terminal.
        let (tx, rx) = oneshot::channel();
        screen.trial.pending_inventory = Request::reply(rx);
        let (add_tx, add_rx) = oneshot::channel();
        screen.trial.pending_add = Request::reply(add_rx);
        drop(tx);
        consume(&mut screen, Language::En);
        assert!(!screen.trial.pending_inventory.is_pending());
        assert!(screen.trial.pending_add.is_pending());
        assert!(screen.trial.feedback.is_none());
        drop(add_tx);

        consume(&mut screen, Language::En);
        assert!(!screen.trial.pending_add.is_pending());
        assert!(!screen.trial_busy());
    }
}

/// The dialog's live-outbound read behind the target check: one request in
/// flight, asked only while the set is unknown, and a failed read leaves it
/// unknown. Pure unit tests over the real command channel — no egui frame,
/// no runtime.
#[cfg(test)]
mod trial_live_out_tests {
    use super::*;
    use crate::rt::RuntimeEntryView;
    use crate::ui::test_rig::UiTestRig;

    fn running_rig() -> UiTestRig {
        UiTestRig {
            phase: CorePhase::Running,
            ..UiTestRig::default()
        }
    }

    #[test]
    fn the_live_outbound_read_is_asked_once_and_stores_the_reported_tags() {
        let mut rig = running_rig();
        let mut screen = RoutingScreen::default();
        {
            let mut ctx = rig.ctx();
            screen.request_live_out_tags(&mut ctx);
            assert!(screen.trial.pending_live_out.is_pending());
            screen.request_live_out_tags(&mut ctx);
        }
        assert!(
            !screen.trial_busy(),
            "a live-state read is not a trial-rule operation and must not close Inject"
        );

        let reply = match rig._cmd_rx.try_recv() {
            Ok(CoreCmd::ListRuntimeState { reply }) => reply,
            Ok(_) => panic!("expected a ListRuntimeState request"),
            Err(error) => panic!("the dialog must read the live state: {error}"),
        };
        assert!(
            rig._cmd_rx.try_recv().is_err(),
            "exactly one read is in flight"
        );
        reply
            .send(Ok(RuntimeStateView {
                inbounds: Vec::new(),
                outbounds: vec![RuntimeEntryView {
                    tag: "proxy".into(),
                    kind: String::new(),
                }],
            }))
            .expect("the screen holds the receiver");

        screen.poll_live_out_tags();
        assert_eq!(screen.trial.live_out_tags, Some(vec!["proxy".to_string()]));
        assert!(!screen.trial.pending_live_out.is_pending());

        // A set that is already known is never read again.
        {
            let mut ctx = rig.ctx();
            screen.request_live_out_tags(&mut ctx);
        }
        assert!(!screen.trial.pending_live_out.is_pending());
        assert!(
            rig._cmd_rx.try_recv().is_err(),
            "a known set is not re-read"
        );
    }

    #[test]
    fn a_failed_live_outbound_read_leaves_the_set_unknown_and_is_not_retried_in_the_phase() {
        let mut rig = running_rig();
        let mut screen = RoutingScreen::default();
        {
            let mut ctx = rig.ctx();
            screen.request_live_out_tags(&mut ctx);
        }
        match rig._cmd_rx.try_recv() {
            Ok(CoreCmd::ListRuntimeState { reply }) => reply
                .send(Err(DiagError::from(Diag::new(Key::RuntimeChannelClosed))))
                .expect("the screen holds the receiver"),
            Ok(_) => panic!("expected a ListRuntimeState request"),
            Err(error) => panic!("the dialog must read the live state: {error}"),
        }

        screen.poll_live_out_tags();

        assert!(screen.trial.live_out_tags.is_none());
        assert!(!screen.trial.pending_live_out.is_pending());

        // At most one automatic attempt per core phase: a failed read leaves
        // the set unknown — the check stays permissive — and the dialog asks
        // nothing more this phase, so no frame ever re-issues the two-RPC
        // read.
        {
            let mut ctx = rig.ctx();
            screen.request_live_out_tags(&mut ctx);
        }
        assert!(!screen.trial.pending_live_out.is_pending());
        assert!(
            rig._cmd_rx.try_recv().is_err(),
            "a failed read must not be re-issued within the phase"
        );

        // A new core phase is a new session: the next dialog frame asks once.
        screen.invalidate_trial_rules();
        {
            let mut ctx = rig.ctx();
            screen.request_live_out_tags(&mut ctx);
        }
        assert!(screen.trial.pending_live_out.is_pending());
    }
}

/// Render-level coverage of the trial-rule controls the state tests above
/// read through their fields — the dialog's Inject gate (the same gate as
/// the section's buttons) and the section's Clear-all batch, both driven
/// through the real command channel — plus the balancer override block's
/// scope hint, the add-rule row a "+ Add rule" click renders, and the
/// geosite picker over a loaded catalog.
#[cfg(test)]
mod routing_control_render_tests {
    use super::{Balancer, CorePhase, GeodataLoadState, Key, Language, Request, RoutingScreen, t};
    use crate::i18n::t_fmt;
    use crate::model::Rule;
    use crate::rt::{CoreCmd, TrialRuleAddOutcome};
    use crate::sys::geodata::{
        GeodataCatalog, GeodataError, GeodataFileMetadata, GeodataOperation, GeodataSnapshot,
    };
    use crate::ui::test_rig::UiTestRig;
    use egui_kittest::Harness;
    use egui_kittest::kittest::{NodeT as _, Queryable as _};
    use std::path::PathBuf;
    use tokio::sync::oneshot;

    fn harness_for(
        state: (RoutingScreen, UiTestRig),
    ) -> Harness<'static, (RoutingScreen, UiTestRig)> {
        let mut harness = Harness::builder()
            .with_size(egui::vec2(900.0, 1600.0))
            .build_ui_state(
                |ui, state: &mut (RoutingScreen, UiTestRig)| {
                    state.0.show(ui, &mut state.1.ctx());
                },
                state,
            );
        harness.run();
        harness
    }

    fn inject_disabled(harness: &Harness<'static, (RoutingScreen, UiTestRig)>) -> bool {
        harness
            .get_by_role_and_label(
                egui::accesskit::Role::Button,
                t(Language::En, Key::TrialRulesInject),
            )
            .accesskit_node()
            .is_disabled()
    }

    /// Take the next command off the rig's channel, asserting the screen has
    /// exactly one in flight: the trial-rule surface serialises its commands.
    fn take_single_command(state: &mut (RoutingScreen, UiTestRig)) -> CoreCmd {
        let command = match state.1._cmd_rx.try_recv() {
            Ok(command) => command,
            Err(error) => panic!("the screen must send a command: {error}"),
        };
        assert!(
            state.1._cmd_rx.try_recv().is_err(),
            "exactly one command may be in flight"
        );
        command
    }

    /// Clear all serialises its removals: one `RemoveTrialRule` in flight at a
    /// time, the next sent only when the previous reply lands, every reply
    /// consumed, and the section disabled until the batch finishes. A
    /// concurrent burst could adopt a read-back taken before another removal
    /// landed and keep a tag the core no longer holds.
    #[test]
    fn clear_all_sends_one_removal_at_a_time_and_consumes_every_reply() {
        let mut screen = RoutingScreen::default();
        screen.trial.rules = vec![
            ("direct".into(), "trial-a".into()),
            ("proxy".into(), "trial-b".into()),
        ];
        screen.trial.injected_tags = vec!["trial-a".into(), "trial-b".into()];
        screen.rebuild_visible_trial_rules();
        let mut harness = harness_for((
            screen,
            UiTestRig {
                phase: CorePhase::Running,
                ..UiTestRig::default()
            },
        ));
        harness
            .get_by_role_and_label(
                egui::accesskit::Role::Button,
                t(Language::En, Key::TrialRulesClearAll),
            )
            .click();
        harness.run();

        let reply = match take_single_command(harness.state_mut()) {
            CoreCmd::RemoveTrialRule { rule_tag, reply } => {
                assert_eq!(rule_tag, "trial-a", "the batch follows the registry order");
                reply
            }
            _ => panic!("expected a RemoveTrialRule request"),
        };
        assert!(
            harness.state().0.trial_busy(),
            "a queued batch keeps the section disabled"
        );

        // The first reply lands: its inventory is applied, and only then does
        // the next removal go out.
        reply
            .send(Ok(vec![("proxy".into(), "trial-b".into())]))
            .expect("the screen holds the reply channel");
        harness.run();
        assert_eq!(
            harness.state().0.trial.visible,
            vec![("proxy".to_string(), "trial-b".to_string())],
            "every landed inventory is applied"
        );

        let reply = match take_single_command(harness.state_mut()) {
            CoreCmd::RemoveTrialRule { rule_tag, reply } => {
                assert_eq!(rule_tag, "trial-b");
                reply
            }
            _ => panic!("expected a RemoveTrialRule request"),
        };
        assert!(harness.state().0.trial_busy());
        reply
            .send(Ok(Vec::new()))
            .expect("the screen holds the reply channel");
        harness.run();

        let (screen, _) = harness.state();
        assert!(!screen.trial_busy(), "the finished batch re-opens the gate");
        assert!(screen.trial.injected_tags.is_empty());
        assert!(screen.trial.visible.is_empty());
        assert_eq!(screen.trial_rule_count(), 0);
    }

    /// A confirmed add whose read-back failed still shows its row: `Ok` means
    /// the core holds the rule, so the tag and the target submitted in the
    /// dialog are the row the grid and the banner report.
    #[test]
    fn a_confirmed_add_without_a_readback_shows_the_submitted_target_and_tag() {
        let mut screen = RoutingScreen::default();
        screen.trial.open = true;
        screen.trial.draft.rule_tag = "trial-b".into();
        screen.trial.draft.outbound_tag = "proxy".into();
        screen.trial.draft.domains = "example.com".into();
        let mut harness = harness_for((
            screen,
            UiTestRig {
                phase: CorePhase::Running,
                ..UiTestRig::default()
            },
        ));
        harness
            .get_by_role_and_label(
                egui::accesskit::Role::Button,
                t(Language::En, Key::TrialRulesInject),
            )
            .click();
        harness.run();

        // The dialog's live-out read may precede the add on the channel; the
        // add is what this test drives.
        let reply = loop {
            match harness.state_mut().1._cmd_rx.try_recv() {
                Ok(CoreCmd::AddTrialRule { reply, rule }) => {
                    assert_eq!(rule.rule_tag, "trial-b");
                    assert_eq!(rule.outbound_tag, "proxy");
                    break reply;
                }
                Ok(CoreCmd::ListRuntimeState { .. }) => continue,
                Ok(_) => panic!("expected an AddTrialRule request"),
                Err(error) => panic!("the Inject click must send the add: {error}"),
            }
        };
        reply
            .send(Ok(TrialRuleAddOutcome { rules: None }))
            .expect("the screen holds the reply channel");
        harness.run();

        let (screen, _) = harness.state();
        assert_eq!(
            screen.trial.visible,
            vec![("proxy".to_string(), "trial-b".to_string())],
            "the confirmed row carries the target the user submitted"
        );
        assert_eq!(
            screen.trial.injected_tags,
            vec!["trial-b".to_string()],
            "the confirmed tag stays removable"
        );
        assert_eq!(screen.trial_rule_count(), 1);
        assert_eq!(
            screen.trial.feedback,
            Some((
                true,
                t(Language::En, Key::TrialRuleAddedUnlisted).to_string()
            ))
        );
    }

    /// The dialog's Inject follows the section's gate: a running core with no
    /// request in flight is the only enabled state.
    #[test]
    fn the_dialog_inject_gate_follows_the_phase_and_the_in_flight_requests() {
        let mut screen = RoutingScreen::default();
        screen.trial.open = true;
        let mut harness = harness_for((
            screen,
            UiTestRig {
                phase: CorePhase::Running,
                ..UiTestRig::default()
            },
        ));
        assert!(
            !inject_disabled(&harness),
            "a running core with nothing in flight must enable Inject"
        );

        // An inventory request in flight closes the gate, exactly like the
        // section's buttons.
        let (tx, rx) = oneshot::channel();
        harness.state_mut().0.trial.pending_inventory = Request::reply(rx);
        harness.run();
        assert!(
            inject_disabled(&harness),
            "a trial-rule request in flight must close Inject"
        );
        assert!(
            harness
                .get_by_role_and_label(
                    egui::accesskit::Role::Button,
                    t(Language::En, Key::TrialRulesRefresh),
                )
                .accesskit_node()
                .is_disabled(),
            "the section's buttons must read the same gate, so the two surfaces cannot drift"
        );
        drop(tx);
        harness.run();
        assert!(
            !inject_disabled(&harness),
            "the spent request must open the gate again"
        );
        assert!(
            !harness
                .get_by_role_and_label(
                    egui::accesskit::Role::Button,
                    t(Language::En, Key::TrialRulesRefresh),
                )
                .accesskit_node()
                .is_disabled(),
            "the open gate re-enables the section's buttons with Inject"
        );

        // A stopped core closes it for its own reason.
        harness.state_mut().1.phase = CorePhase::Stopped;
        harness.run();
        assert!(
            inject_disabled(&harness),
            "a stopped core must close Inject"
        );
    }

    /// The override block says why the core can reject a balancer tag: the
    /// scope hint renders directly under the ephemeral note.
    #[test]
    fn the_override_block_renders_the_scope_hint_under_the_ephemeral_note() {
        let mut rig = UiTestRig::default();
        rig.settings.routing.balancers.push(Balancer {
            tag: "edge".into(),
            selector: vec!["srv-".into()],
            ..Default::default()
        });
        let mut harness = harness_for((RoutingScreen::default(), rig));
        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "▸")
            .click();
        harness.run();

        let ephemeral = harness
            .get_by_label(t(Language::En, Key::RuntimeOverrideEphemeral))
            .rect();
        let scope = harness
            .get_by_label(t(Language::En, Key::RuntimeOverrideScopeHint))
            .rect();
        assert!(
            scope.min.y >= ephemeral.max.y,
            "the scope hint must render under the ephemeral note: {ephemeral:?} vs {scope:?}"
        );
    }

    /// A "+ Add rule" click renders the new row on the frame after the edit:
    /// the no-rules hint goes away and the row paints the memoized match-all
    /// summary — which the view cache only holds for the model generation the
    /// click advanced, since `show` refreshes the cache at the top of every
    /// frame and gates the rebuild on that generation.
    #[test]
    fn the_add_rule_click_renders_the_new_row_from_the_refreshed_view_cache() {
        let mut harness = harness_for((RoutingScreen::default(), UiTestRig::default()));
        assert!(
            harness
                .query_by_label(t(Language::En, Key::RoutingNoRules))
                .is_some(),
            "an empty rules section renders the no-rules hint"
        );

        harness
            .get_by_role_and_label(
                egui::accesskit::Role::Button,
                t(Language::En, Key::RoutingAddRule),
            )
            .click();
        // Step one processes the click (the rule is pushed and the mutation
        // hook moves the generation); step two renders the frame after the
        // edit, where the view cache rebuilds for that generation and the new
        // row can paint.
        harness.run_steps(2);
        assert!(
            harness
                .query_by_label(t(Language::En, Key::RoutingNoRules))
                .is_none(),
            "the no-rules hint must go away once the section holds a rule"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::RuleSummaryMatchAll))
                .is_some(),
            "the new row must paint the memoized match-all summary"
        );
    }

    /// The geosite picker's catalog fixture: a byte length the size label
    /// formats, and a failed geoip side so only the geosite menu has a
    /// catalog to render.
    fn fixture_catalog(codes: &[&str], bytes: u64) -> GeodataCatalog {
        GeodataCatalog {
            codes: codes.iter().map(|code| code.to_string()).collect(),
            metadata: GeodataFileMetadata {
                path: PathBuf::from("fixture.dat"),
                byte_len: bytes,
                modified: None,
            },
        }
    }

    fn fixture_error(file: &str) -> GeodataError {
        GeodataError::Io {
            operation: GeodataOperation::Open,
            path: file.into(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "test"),
        }
    }

    /// The geosite picker renders straight from the snapshot the screen
    /// already holds — the load state is Ready, so opening the picker starts
    /// no worker — and a typed query filters the rows through the memoized
    /// matches: the matching code renders, a non-matching one does not.
    #[test]
    fn the_open_geosite_picker_renders_the_loaded_catalog_and_filters_through_the_memo() {
        let codes = ["cn", "google", "github", "geolocation-!cn"];
        let bytes = 4096_u64;
        let mut rig = UiTestRig::default();
        rig.settings.routing.rules = vec![Rule {
            rule_tag: "r-1".into(),
            outbound_tag: "direct".into(),
            ..Rule::default()
        }];
        let screen = RoutingScreen {
            geodata_snapshot: Some(GeodataSnapshot {
                geosite: Ok(fixture_catalog(&codes, bytes)),
                geoip: Err(fixture_error("geoip.dat")),
            }),
            geodata_load_state: GeodataLoadState::Ready,
            ..RoutingScreen::default()
        };
        let mut harness = harness_for((screen, rig));

        // The rule row's "▸" opens the inline editor the picker lives in.
        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "▸")
            .click();
        harness.run_steps(2);
        harness
            .get_by_role_and_label(
                egui::accesskit::Role::Button,
                t(Language::En, Key::GeodataAddGeosite),
            )
            .click();
        // The popup opens on the click frame as a sizing pass; the following
        // frames lay it out at its final size before it is queried.
        harness.run_steps(3);

        let size_label = t_fmt(
            Language::En,
            Key::GeodataCodesBytes,
            &[&codes.len(), &bytes],
        );
        assert!(
            harness.query_by_label(&size_label).is_some(),
            "the loaded catalog's size label must render in the open picker: {size_label}"
        );
        assert!(
            harness
                .query_by_role_and_label(egui::accesskit::Role::Button, "cn")
                .is_some(),
            "every catalog code renders as a selectable row while the query is empty"
        );

        // The picker's search field: the text input carrying the picker's own
        // hint (the field's placeholder), focused and typed into like the
        // app-shell tests do.
        let search_hint = t(Language::En, Key::GeodataSearch);
        let field = harness
            .query_all_by_role(egui::accesskit::Role::TextInput)
            .find(|node| node.accesskit_node().placeholder() == Some(search_hint))
            .expect("the picker's search field must render with its hint");
        field.focus();
        field.type_text("geo");
        harness.run_steps(2);

        assert!(
            harness
                .query_by_role_and_label(egui::accesskit::Role::Button, "geolocation-!cn")
                .is_some(),
            "the code matching the query must render from the memoized matches"
        );
        assert!(
            harness
                .query_by_role_and_label(egui::accesskit::Role::Button, "cn")
                .is_none(),
            "a catalog code the query does not match must not render"
        );
    }
}

/// Route-test reply polling: the pending receiver
/// lives on the screen, so a landed result survives dialog close/reopen and
/// is consumed on the reopen poll without re-running. Pure unit tests — no
/// egui, no runtime.
#[cfg(test)]
mod route_test_poll_tests {
    use super::*;
    use tokio::sync::oneshot;

    #[test]
    fn landed_result_is_applied_by_the_poll() {
        let mut screen = RoutingScreen::default();
        let (tx, rx) = oneshot::channel();
        screen.test_pending_request = Request::reply(rx);
        tx.send(Ok("verdict".into())).expect("send the verdict");

        screen.poll_test_route_result();

        assert!(!screen.test_pending_request.is_pending());
        assert!(
            matches!(&screen.test_result, Some(Ok(text)) if text == "verdict"),
            "the landed verdict must be adopted: {:?}",
            screen.test_result
        );
    }

    #[test]
    fn closed_receiver_clears_the_pending_without_feedback() {
        let mut screen = RoutingScreen::default();
        let (tx, rx) = oneshot::channel();
        screen.test_pending_request = Request::reply(rx);
        drop(tx);

        screen.poll_test_route_result();

        assert!(!screen.test_pending_request.is_pending());
        assert!(screen.test_result.is_none());
    }

    #[test]
    fn pending_survives_while_the_dialog_is_closed_and_is_consumed_on_reopen() {
        let mut screen = RoutingScreen {
            test_open: false,
            ..RoutingScreen::default()
        };
        let (tx, rx) = oneshot::channel();
        screen.test_pending_request = Request::reply(rx);
        tx.send(Ok("verdict".into())).expect("send the verdict");

        // Closed dialog: no poll runs (`test_route_dialog` returns at the
        // open gate), so the landed result waits in the request untouched.
        assert!(
            screen.test_pending_request.is_pending(),
            "the pending request must survive while the dialog is closed"
        );
        assert!(screen.test_result.is_none());

        // Reopen: the per-frame poll consumes the landed result — the run is
        // never re-sent.
        screen.test_open = true;
        screen.poll_test_route_result();
        assert!(!screen.test_pending_request.is_pending());
        assert!(
            matches!(&screen.test_result, Some(Ok(text)) if text == "verdict"),
            "the landed verdict must be adopted on reopen: {:?}",
            screen.test_result
        );
    }
}

/// The rule editor's `localOS` row: the model's OS names render in their own
/// labelled field, and an edit there writes the model back.
#[cfg(test)]
mod routing_local_os_tests {
    use super::{Key, Language, RoutingScreen, Rule, t};
    use crate::ui::test_rig::{UiTestRig, screen_harness_at};
    use egui_kittest::Harness;
    use egui_kittest::kittest::Queryable as _;

    fn harness_with_local_os_rule() -> Harness<'static, (RoutingScreen, UiTestRig)> {
        let screen = RoutingScreen {
            edit_rule: Some(0),
            ..RoutingScreen::default()
        };
        let mut rig = UiTestRig::default();
        rig.settings.routing.rules = vec![Rule {
            rule_tag: "local-os".into(),
            domain: vec!["domain:example.com".into()],
            local_os: vec!["windows".into()],
            outbound_tag: "direct".into(),
            ..Rule::default()
        }];
        let mut harness = screen_harness_at(egui::vec2(900.0, 1600.0), rig, screen);
        harness.run();
        harness
    }

    #[test]
    fn the_local_os_row_renders_the_model_and_writes_it_back() {
        let mut harness = harness_with_local_os_rule();
        let label = harness.get_by_label(t(Language::En, Key::LocalOs)).rect();
        assert!(
            harness
                .get_all_by_role(egui::accesskit::Role::TextInput)
                .any(|node| node.value().as_deref() == Some("windows")),
            "the stored localOS name must render in its field"
        );

        // The row's remove button sits on the label's line, right of the
        // label cell; every other remove button is on a different line.
        harness
            .query_all_by_label(t(Language::En, Key::DeleteRow))
            .find(|node| {
                let rect = node.rect();
                rect.min.x > label.max.x && rect.min.y >= label.min.y && rect.min.y <= label.max.y
            })
            .expect("the localOS row's remove button")
            .click();
        harness.run();

        assert!(
            harness.state().1.settings.routing.rules[0]
                .local_os
                .is_empty(),
            "the row's edit must land in the rule model"
        );
    }
}
