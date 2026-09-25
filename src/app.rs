//! BroccoliApp: eframe shell — event drain, navigation, tray, dirty/apply flow,
//! first-run wizard.

use crate::diag::Diag;
use crate::r#gen::{self, keys};
use crate::i18n::{Key, t, t_fmt};
use crate::icon::{IconAssets, IconPresentation, classify};
use crate::links::excerpt;
use crate::model::inbound::API_INBOUND_TAG;
use crate::model::safety::SafetyFinding;
use crate::model::settings::{Language, Mode};
use crate::model::{ServersFile, Settings};
use crate::rt::{
    AppMessage, ApplyIntent, CoreCmd, CoreEvt, CorePhase, CoreTransport, DownloadState,
    EVT_CHANNEL_CAPACITY, JobKind, LatencyProbeResult, OutboundStatusView, RuntimeHandle,
    StatsTick, spawn_runtime, sweep_stale_scratch_configs,
};
use crate::sys::selfupd::UpdateCheckState;
use crate::sys::{self, paths};
use crate::ui::servers::{LeaveAction, ServersScreen};
use crate::ui::{self, PhaseAction, Screen, UiCtx, UiCtxParts, UiCtxSnapshot, UiCtxView};
use std::collections::{HashMap, VecDeque};
use std::ops::Deref;
use std::sync::{
    Arc, LazyLock, Mutex, OnceLock,
    atomic::{AtomicU64, Ordering},
    mpsc::{self, Receiver, Sender},
};
#[cfg(windows)]
use windows::Win32::Foundation::HWND;

/// The non-blocking tracing worker's guard, kept for the app's lifetime so a
/// clean exit flushes accepted records. The exit path takes it out
/// explicitly ([`release_log_guard`], before anything touches the app-data
/// dirs) so no log-file handle stays open when they are wiped; `Option` + mutex
/// instead of `OnceLock` because the guard must be movable out of the
/// static.
static LOG_GUARD: std::sync::Mutex<Option<tracing_appender::non_blocking::WorkerGuard>> =
    std::sync::Mutex::new(None);

const LOG_CAP: usize = 5000;
const HISTORY_CAP: usize = 120;
/// Byte cap for the in-app log ring (`LogBuffer`). Bounds worst-case
/// resident memory when every line is at the runtime's 4 KiB ceiling:
/// 1 MiB / 4 KiB = 256 lines instead of the current 5000 x 4 KiB = ~20 MiB
/// of payload. Typical GUI/core lines are
/// tens to low hundreds of bytes, so the 5000-line count cap still binds
/// first in normal use.
const LOG_BYTE_CAP: usize = 1024 * 1024;
/// A runtime producer must never monopolize egui's UI thread. Process a
/// bounded batch each frame and immediately schedule the next frame if more
/// work is queued.
const EVENT_DRAIN_LIMIT: usize = 256;
/// Size cap for `app.log`; exceeding it triggers rotation.
const APP_LOG_MAX_BYTES: u64 = 4 * 1024 * 1024;
/// Number of rotated `app.log.N` segments retained.
const APP_LOG_KEEP: usize = 3;
/// A log file untouched for this long is rotated at startup (age rotation).
const APP_LOG_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// Minimum spacing between GUI-state saves while the model stays dirty. A
/// drag or keystroke marks the model dirty on every frame, and each save is
/// two fsync'd atomic writes (`servers.save()` + `settings.save()`) plus a
/// full candidate generation, so continuous edits must not persist per frame.
/// A repaint scheduled at the flush deadline lands the final state ~interval
/// after the last change. Seconds on egui's clock (`ctx.input(|i| i.time)`),
/// which eframe drives from real time and the kittest harness from its step
/// delta, so the throttle behaves identically live and in tests.
const PERSIST_THROTTLE_SECS: f64 = 0.2;

/// Re-sample the OS dark-mode flag at most this often (seconds on egui's
/// clock). `logic` otherwise re-reads the HKCU Personalize registry key on
/// every frame; a flipped OS theme is still picked up within the interval,
/// and the `last_native_theme` gate still decides when to re-apply.
#[cfg(windows)]
const NATIVE_THEME_SAMPLE_INTERVAL_SECS: f64 = 2.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrayAction {
    Show,
    ToggleConnection,
    Quit,
}

/// In-app log ring: newest last, `(from_core, line)` entries, capped by both
/// line count (`LOG_CAP`) and resident bytes (`LOG_BYTE_CAP`) so a verbose
/// core cannot grow the buffer toward the ~20 MiB worst case of 5000 x 4 KiB
/// lines. The UI reads this as the plain
/// `VecDeque<(bool, String)>` it always was, via `Deref`; only `push`
/// mutates the ring, so the byte total cannot drift.
struct LogBuffer {
    entries: VecDeque<(bool, String)>,
    /// Sum of retained line lengths — the quantity `LOG_BYTE_CAP` bounds.
    /// Actual resident memory is this plus a fixed per-entry overhead.
    bytes: usize,
    /// Monotonic push counter: `push` is the ring's only
    /// mutation — eviction happens only inside `push` when a cap binds — so
    /// `(generation, len)` changes exactly when the ring's content changes.
    /// The Logs screen's memoized filtered view is keyed on this identity;
    /// the previous `(len, front/back String as_ptr)` fingerprint could
    /// false-equal when capacity-0 empty lines rotated through a full ring
    /// (every empty String reports the same dangling pointer).
    generation: u64,
}

impl LogBuffer {
    fn new() -> Self {
        Self {
            entries: VecDeque::with_capacity(LOG_CAP),
            bytes: 0,
            generation: 0,
        }
    }

    /// Insert one line, dropping oldest entries until both the line cap and
    /// the byte cap hold. Amortized O(1): each entry is pushed once and
    /// popped at most once, and no entry is ever re-copied. The `bytes` total
    /// it keeps is the resident accounting the tests read — this is
    /// event-driven (core events, button handlers), never per frame.
    fn push(&mut self, from_core: bool, line: String) {
        self.generation += 1;
        self.bytes += line.len();
        self.entries.push_back((from_core, line));
        while self.entries.len() > LOG_CAP || self.bytes > LOG_BYTE_CAP {
            if let Some((_, evicted)) = self.entries.pop_front() {
                self.bytes -= evicted.len();
            } else {
                // Unreachable: the just-pushed line is in the ring, so an
                // over-cap byte total implies a non-empty ring.
                break;
            }
        }
        // Invariant: `bytes` is the exact sum of resident entry lengths, so the
        // loop above always terminates within the byte cap. The assert pins it
        // against future drift in debug builds.
        debug_assert!(self.bytes <= LOG_BYTE_CAP, "log buffer over byte cap");
    }

    /// Monotonic push count: the ring-content identity the Logs screen's
    /// memoized view is keyed on.
    fn generation(&self) -> u64 {
        self.generation
    }
}

impl Deref for LogBuffer {
    type Target = VecDeque<(bool, String)>;

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

#[derive(Clone)]
struct TrayEventTarget {
    registration_id: u64,
    tray_id: Option<tray_icon::TrayIconId>,
    show_id: tray_icon::menu::MenuId,
    connect_id: tray_icon::menu::MenuId,
    quit_id: tray_icon::menu::MenuId,
    action_tx: Sender<TrayAction>,
    ctx: egui::Context,
}

static NEXT_TRAY_REGISTRATION: AtomicU64 = AtomicU64::new(1);
static TRAY_EVENT_TARGET: OnceLock<Mutex<Option<TrayEventTarget>>> = OnceLock::new();
static TRAY_EVENT_HANDLERS: OnceLock<()> = OnceLock::new();

fn event_batch_exhausted(processed: usize) -> bool {
    processed == EVENT_DRAIN_LIMIT
}

/// How the last `logic` drain ended — the drain input of the end-of-frame
/// repaint decision at the `ui` tail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DrainOutcome {
    /// No event was queued when the frame drained.
    Empty,
    /// At least one event was drained and the channel is empty again.
    Drained,
    /// [`EVENT_DRAIN_LIMIT`] events were drained — more may be queued, so
    /// the next frame must keep draining.
    Full,
}

/// What the end-of-frame repaint policy decided for this frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RepaintFollowUp {
    /// Request nothing: the next frame arrives with the runtime's next
    /// per-event poke (or another one-shot already scheduled elsewhere).
    Nothing,
    /// Ask egui for the immediate next frame — a full drain batch left
    /// queued work behind.
    NextFrame,
}

/// Decide what the `ui` tail must request after this frame.
///
/// The standing 500 ms timer that used to run while the core was
/// Running/Starting (so stats/plot animate) is gone: repainting is
/// event-driven. `phase` is accepted so tests pin the removal for each
/// former timer phase — no phase ever requests a delayed repaint here
/// anymore. While the viewport is hidden (close-to-tray) or minimized,
/// nothing is requested, even when the drain batch filled: pokes from the
/// runtime may still arrive, but the app schedules no follow-ups. Visible
/// frames request the immediate next frame only after a
/// [`DrainOutcome::Full`] drain (its continuation lives in `logic`);
/// empty and changed-event drains need no follow-up because the runtime
/// already poked for every event that produced this frame.
fn repaint_follow_up(
    _phase: &CorePhase,
    viewport_suppressed: bool,
    drain: DrainOutcome,
) -> RepaintFollowUp {
    if viewport_suppressed {
        return RepaintFollowUp::Nothing;
    }
    match drain {
        DrainOutcome::Full => RepaintFollowUp::NextFrame,
        DrainOutcome::Empty | DrainOutcome::Drained => RepaintFollowUp::Nothing,
    }
}

/// Why a save is queued. Config edits regenerate the candidate and raise
/// the Apply gate; UI-only edits (traffic unit, language, accent) never
/// affect the running core's configuration and only write the files.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PersistKind {
    Config,
    UiOnly,
}

/// The operation the shell mirrors while the runtime owns the busy window: the
/// holding job's kind together with the user-facing name the shell paints for
/// it. A mirror is built only from a kind that names itself, which is exactly
/// the set of kinds that occupy the window (`rt::seat`'s operation-name table;
/// the runtime publishes a bookend for no other kind) — so a control that
/// reports "an operation is in progress" always names it, and a query kind,
/// which never holds the window, can never become a mirror.
#[derive(Clone, Debug, PartialEq, Eq)]
struct HeldOperation {
    kind: JobKind,
    name: Diag,
}

impl HeldOperation {
    /// The shell's mirror of one kind that just took the busy window, from a
    /// bookend or from a command the shell sent: `Some` for a kind the shell
    /// can name — the kinds that occupy the window — and `None` for a query
    /// kind, which never holds it and so is nothing to mirror.
    fn mirror(kind: JobKind) -> Option<Self> {
        Some(Self {
            kind,
            name: kind.operation_name()?,
        })
    }
}

pub struct BroccoliApp {
    servers: ServersFile,
    settings: Settings,
    rt: RuntimeHandle,
    evt_rx: std::sync::mpsc::Receiver<CoreEvt>,
    /// Sender half of the runtime→app event channel, retained for kittest
    /// tests to inject synthetic events through the real drain path
    /// ([`Self::inject_event`]). The runtime
    /// owns its own clone; this one stays idle in production.
    evt_tx: std::sync::mpsc::SyncSender<CoreEvt>,
    /// Generation-gated UI-context snapshot: the owned
    /// inputs behind every frame's [`UiCtx`]. Rebuilt only when a drained
    /// event changes them (see `ui_ctx_dirty`) — never per frame.
    ui_ctx_snapshot: UiCtxSnapshot,
    /// Set when a drained event invalidates the snapshot; the next `ui()`
    /// frame rebuilds it exactly once per actual input change (the snapshot's
    /// `same_inputs` compare decides; a no-op invalidation rebuilds nothing).
    ui_ctx_dirty: bool,
    /// Monotonic per-input generations for screens' memoization keys
    /// (dashboard plot/latency-grid caches): `stats_generation` bumps once
    /// per stats tick; `latency_generation` once per observatory tick and
    /// once per consumed latency-probe result — the two writers of profile
    /// `latency_ms`, the grid's no-observatory-cell input.
    stats_generation: u64,
    latency_generation: u64,
    phase: CorePhase,
    /// Transport reported by `ActiveConfig`, held until its following start phase.
    pending_transport: Option<CoreTransport>,
    /// The operation the shell mirrors while the runtime owns the busy window:
    /// written from the runtime's own bookends and from the kind of the
    /// command the shell just sent ([`CoreCmd::job_kind`]), never from a
    /// hand-picked kind. The registry's bookends stay the authority for the
    /// release.
    operation: Option<HeldOperation>,
    /// Transport owned by the backend represented by the current live phase.
    active_transport: Option<CoreTransport>,
    stats: Option<StatsTick>,
    stats_history: VecDeque<StatsTick>,
    observatory: Vec<OutboundStatusView>,
    /// Core-output log ring, newest last, byte- and count-capped
    /// (`LogBuffer`).
    logs: LogBuffer,
    download: DownloadState,
    update_check: UpdateCheckState,
    apply_result: Option<(bool, String)>,
    /// The config-apply gate ("changes pending" chip): true while the current
    /// candidate differs from the config the running core accepted, or while
    /// the state cannot be saved/generated. Recomputed from
    /// [`Self::applied_candidate`] on every persist and settle — not a sticky
    /// latch — so an edit reverted to the applied state drops the gate again.
    config_dirty: bool,
    /// Baseline the gate compares against: the generated config the running
    /// core accepted (refreshed at each successful apply settle) or, before
    /// any apply, the startup config (what a fresh Connect would apply),
    /// normalized via [`normalize_candidate_for_compare`] so the per-launch
    /// ephemeral API port cannot mask equality. `None` only while
    /// generation fails, which keeps the gate up.
    applied_candidate: Option<serde_json::Value>,
    /// Monotonic in-memory edit generation used to prevent an older runtime
    /// result from settling newer saved edits: an apply verdict names the
    /// revision it applied, so a verdict for an older one cannot settle the
    /// configuration the app holds now.
    config_revision: u64,
    /// The model's edit generation: bumped by [`UiCtx::mark_dirty`] /
    /// [`UiCtx::mark_ui_dirty`] — the mutation hooks every edit goes through
    /// — and published on the frame context so screens' per-frame caches
    /// re-derive in the frame after any edit, including edits inside the
    /// persist throttle window that `config_revision` (bumped at persist)
    /// cannot cover.
    model_generation: u64,
    /// egui-clock seconds (`ctx.input(|i| i.time)`) of the last persist.
    /// `None` before the first save, so the first dirty frame after a quiet
    /// period persists immediately (discrete edits stay prompt) and only
    /// continuous dirty is throttled.
    last_persist: Option<f64>,
    /// An edit landed inside the persist throttle window and its save is
    /// still pending the deadline repaint. Flushed from `Drop` so quitting
    /// inside the window cannot lose the last edit. Carries the edit kind so
    /// the flush re-enters the same persist path.
    persist_pending: Option<PersistKind>,
    /// The raw-override half of the connect verdict, recorded by the boot
    /// and config-persist generations — the generations that already run for
    /// the persisted model: the excerpt-bounded generation error while
    /// `settings.raw_override` is set (`None` = no override configured, or
    /// one that generates cleanly). A frame only reads it, so no paint pass
    /// ever binds the control-plane port; an edit inside the
    /// persist-throttle window keeps the previous revision's verdict until
    /// the persist step regenerates.
    ///
    /// While the two are recorded together it mirrors `config_error`, and
    /// the connect-block verdict consults `config_error` first — it is kept
    /// as the explicit raw-override carrier so a path that clears
    /// `config_error` without a fresh generation cannot silently unblock a
    /// broken raw override.
    raw_override_verdict: Option<String>,
    /// Memoized connect-block/apply-block chip texts: the
    /// blocking reason is computed once per input change and shared by the
    /// tray sync, the top-bar Connect button, the Apply-now chip, and the
    /// screen contexts — previously re-formatted (`t_fmt`, `clone`) on
    /// every frame while any blocking state was set.
    /// Refreshed in `logic` after the event drain and re-checked at the top
    /// of `ui`; screens and the top bar borrow the text through
    /// [`cached_block_reason`].
    connect_block_cache: Option<ConnectBlockCache>,
    persistence_error: Option<String>,
    /// Hazard findings awaiting explicit acknowledgment: set
    /// when a Connect/Apply request hits the safety gate, cleared by the
    /// dialog's confirm or cancel. `Some` only while the acknowledgment
    /// modal is the response to a gated apply; the origin records which
    /// commit path the confirm button must resume.
    pending_safety_ack: Option<(PendingApplyOrigin, Vec<SafetyFinding>)>,
    /// A state file (settings.json / servers.json) held valid JSON that
    /// could not be loaded — an unknown `security`/`network` value, a field
    /// of the wrong type, etc. The file is left intact for the user to fix.
    state_error: Option<String>,
    /// One-time session log that saving is refused while `state_error` is
    /// set; prevents identical refusal lines on every edit frame.
    state_error_save_logged: bool,
    /// The top bar's own memos (captions + right-cluster measurement):
    /// opaque to the shell, which only hands the value back each frame
    /// ([`ui::topbar::show_row`]).
    topbar: ui::topbar::TopbarMemos,
    /// Generator/parsing failure for the current persisted model. Unlike a
    /// runtime verdict, this blocks sending any candidate until an edit fixes it.
    config_error: Option<String>,
    /// Outcome slot of the one single-flight latency probe: the event drain
    /// parks the drained result here and the servers screen adopts it
    /// through its `ShellParked` request — the app-owned screen-feedback
    /// slot that replaced the request/response bus. A result landing while
    /// the user is elsewhere waits here until the servers screen takes it;
    /// the single slot is exact because the probe is single-flight and the
    /// UI pending gate holds until the take.
    probe_feedback: ui::request::ParkedSlot<LatencyProbeResult>,
    core_version: Option<String>,
    /// Cached fast availability state for UI render passes. Full release-pin
    /// verification remains at every launch/validation boundary.
    core_available: bool,
    /// The installed tree's own version and its last verification failure,
    /// for the core setup surface's mounts.
    core_setup: ui::CoreSetupState,
    /// The terminal message the content area renders: the failure's keyed
    /// message plus the captured core output behind it, recorded with the
    /// phase it describes and cleared when that phase moves on or an action
    /// succeeds.
    terminal_error: Option<TerminalError>,
    /// An install this shell started has run and its transaction is still
    /// open: set by the progress event, cleared when the terminal consumes it
    /// or the runtime releases the exclusive record. Only such a terminal
    /// re-derives the core facts — a command rejected up front (stop the core
    /// first, another operation is running) never touched the tree, and a
    /// pass taken while the core runs could even misread its open files.
    install_in_flight: bool,
    is_elevated: bool,
    screen: Screen,
    dashboard: ui::dashboard::DashboardScreen,
    servers_ui: ui::servers::ServersScreen,
    routing: ui::routing::RoutingScreen,
    dns: ui::dns::DnsScreen,
    inbounds: ui::inbounds::InboundsScreen,
    tun: ui::tun::TunScreen,
    logs_ui: ui::logs::LogsScreen,
    settings_ui: ui::settings::SettingsScreen,
    profile_preview: ui::profile_preview::ProfilePreviewScreen,
    about: ui::about::AboutScreen,
    wizard: ui::wizard::WizardScreen,

    icon_assets: IconAssets,
    last_icon_presentation: Option<IconPresentation>,
    /// Kept alive for the process lifetime — dropping it removes the icon.
    tray: Option<tray_icon::TrayIcon>,
    tray_registration_id: u64,
    tray_action_rx: Receiver<TrayAction>,
    tray_menu: TrayMenu,
    quitting: bool,
    /// Close-to-tray hid the viewport (`Visible(false)`): while
    /// set, the `ui` tail requests no follow-up repaints — there is nothing
    /// to animate for an invisible window. Only [`BroccoliApp::show_window`]
    /// reopens the gate.
    viewport_hidden: bool,
    /// How the last `logic` drain ended — the drain input of the
    /// end-of-frame repaint decision at the `ui` tail. `Empty` before the
    /// first pass.
    frame_drain: DrainOutcome,
    /// Last `(label, enabled)` sent to the tray connect item (`None` before
    /// the first sync). Gates `set_text`/`set_enabled` so idle frames issue
    /// no muda calls — each `set_text` allocates and issues
    /// `SetMenuItemInfoW` per parent menu, and the label changes only on
    /// language/phase change, the enabled state only on phase/block state
    /// (mirrors `last_icon_presentation`).
    last_tray_connect: Option<TrayConnectPresentation>,
    /// Native theme (dark/light + reachable HWNDs) last applied to Windows
    /// surfaces. `None` before the first apply; drives the cheap per-frame
    /// comparison in `logic` so the tray popup is only re-themed on change.
    #[cfg(windows)]
    last_native_theme: Option<AppliedNativeTheme>,
    /// Last `(system_dark, egui-clock seconds)` sampled from the OS, so
    /// `logic` re-queries the Personalize registry key at most once per
    /// [`NATIVE_THEME_SAMPLE_INTERVAL_SECS`] instead of every frame.
    /// `last_native_theme` still gates the actual apply.
    #[cfg(windows)]
    native_theme_sample: Option<(bool, f64)>,
}

/// What the tray connect item should show this frame: the i18n `&'static
/// str` label plus the enabled flag. `Copy` so the per-frame gate in
/// [`BroccoliApp::sync_tray_action`] compares by value, mirroring
/// `last_icon_presentation`.
#[derive(Clone, Copy, PartialEq, Eq)]
struct TrayConnectPresentation {
    label: &'static str,
    enabled: bool,
}

/// Pure projection: the tray connect item's presentation depends
/// only on the phase action, the language, and whether Connect is blocked —
/// so the sync gate skips both muda calls on frames where none changed.
fn tray_connect_presentation(
    action: PhaseAction,
    language: Language,
    connect_blocked: bool,
) -> TrayConnectPresentation {
    TrayConnectPresentation {
        label: action.label(language),
        enabled: action != PhaseAction::Connect || !connect_blocked,
    }
}

struct TrayMenu {
    show: tray_icon::menu::MenuItem,
    connect: tray_icon::menu::MenuItem,
    quit: tray_icon::menu::MenuItem,
}

impl TrayEventTarget {
    fn action_for_tray_event(&self, event: &tray_icon::TrayIconEvent) -> Option<TrayAction> {
        use tray_icon::{MouseButton, MouseButtonState, TrayIconEvent};

        match event {
            TrayIconEvent::Click {
                id,
                button: MouseButton::Left,
                button_state: MouseButtonState::Down,
                ..
            } if self.tray_id.as_ref() == Some(id) => Some(TrayAction::Show),
            _ => None,
        }
    }

    fn action_for_menu_event(&self, event: &tray_icon::menu::MenuEvent) -> Option<TrayAction> {
        if event.id == self.show_id {
            Some(TrayAction::Show)
        } else if event.id == self.connect_id {
            Some(TrayAction::ToggleConnection)
        } else if event.id == self.quit_id {
            Some(TrayAction::Quit)
        } else {
            None
        }
    }
    fn dispatch_tray_event(&self, event: tray_icon::TrayIconEvent) {
        if let Some(action) = self.action_for_tray_event(&event) {
            self.send(action);
        }
    }

    fn dispatch_menu_event(&self, event: tray_icon::menu::MenuEvent) {
        if let Some(action) = self.action_for_menu_event(&event) {
            self.send(action);
        }
    }

    fn send(&self, action: TrayAction) {
        if self.action_tx.send(action).is_ok() {
            self.ctx.request_repaint();
        }
    }
}
fn tray_event_target_lock() -> &'static Mutex<Option<TrayEventTarget>> {
    TRAY_EVENT_TARGET.get_or_init(|| Mutex::new(None))
}

fn current_tray_event_target() -> Option<TrayEventTarget> {
    tray_event_target_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

fn dispatch_tray_icon_event(event: tray_icon::TrayIconEvent) {
    let Some(target) = current_tray_event_target() else {
        return;
    };
    target.dispatch_tray_event(event);
}

fn dispatch_menu_event(event: tray_icon::menu::MenuEvent) {
    let Some(target) = current_tray_event_target() else {
        return;
    };
    target.dispatch_menu_event(event);
}

fn install_tray_event_target(
    ctx: &egui::Context,
    tray_id: Option<tray_icon::TrayIconId>,
    menu: &TrayMenu,
) -> (u64, Receiver<TrayAction>) {
    let (action_tx, action_rx) = mpsc::channel();
    let registration_id = NEXT_TRAY_REGISTRATION.fetch_add(1, Ordering::Relaxed);
    let target = TrayEventTarget {
        registration_id,
        tray_id,
        show_id: menu.show.id().clone(),
        connect_id: menu.connect.id().clone(),
        quit_id: menu.quit.id().clone(),
        action_tx,
        ctx: ctx.clone(),
    };
    {
        let mut current = tray_event_target_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *current = Some(target);
    }
    let _ = TRAY_EVENT_HANDLERS.get_or_init(|| {
        tray_icon::TrayIconEvent::set_event_handler(Some(dispatch_tray_icon_event));
        tray_icon::menu::MenuEvent::set_event_handler(Some(dispatch_menu_event));
    });
    (registration_id, action_rx)
}

fn install_tray_event_handlers(
    ctx: &egui::Context,
    tray: Option<&tray_icon::TrayIcon>,
    menu: &TrayMenu,
) -> (u64, Receiver<TrayAction>) {
    install_tray_event_target(ctx, tray.map(|tray| tray.id().clone()), menu)
}

fn clear_tray_event_target(registration_id: u64) {
    let Some(lock) = TRAY_EVENT_TARGET.get() else {
        return;
    };
    let mut current = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if current
        .as_ref()
        .is_some_and(|target| target.registration_id == registration_id)
    {
        *current = None;
    }
}

fn should_hide_on_close(close_requested: bool, quitting: bool) -> bool {
    close_requested && !quitting
}

/// Quit interception for the unsaved-changes indicator: with a dirty server
/// draft the quit is deferred — the Quit leave action is staged so the
/// Save/Discard/Cancel modal resolves it on later frames, and a repaint is
/// requested so the modal appears promptly. Returns true when nothing is
/// unsaved and the app may run its normal quit path immediately.
fn quit_or_stage_leave(servers: &mut ServersScreen, ctx: &egui::Context) -> bool {
    if servers.unsaved_changes() {
        servers.stage_leave(LeaveAction::Quit);
        ctx.request_repaint();
        false
    } else {
        true
    }
}

/// Consume a resolved staged Quit: true exactly once after the leave modal
/// has cleared the action (all dirty drafts saved or discarded) and no quit
/// is already in flight. The caller then runs its normal quit path.
fn quit_resume_ready(servers: &mut ServersScreen, quitting: bool) -> bool {
    !quitting && servers.take_quit_resume()
}

impl BroccoliApp {
    /// Boot the app for a real run: window, tray icon, runtime.
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        Self::build(cc, true)
    }

    /// The headless test boot: exactly [`Self::new`] except the tray icon. The
    /// tray menu and its action channel still exist, so the tray plumbing
    /// keeps its types and stays covered, but a test run must not light up the
    /// notification area (`tests/ui_smoke.rs` and the other kittest suites
    /// boot the app through this constructor).
    pub fn new_headless(cc: &eframe::CreationContext<'_>) -> Self {
        Self::build(cc, false)
    }

    fn build(cc: &eframe::CreationContext<'_>, with_tray_icon: bool) -> Self {
        init_tracing();
        // Next-launch housekeeping: a crash or kill can strand a
        // scratch `profile-test-*.json` validation config — a full generated
        // profile with UUIDs, passwords, private keys — because the runtime
        // task that owned its removal guard died with the process. The
        // runtime's sweep removes the ones older than its age bound,
        // mirroring the crash-report cleanup discipline in main.rs; young
        // files (a concurrent second instance mid-validation) survive, and
        // the sweep never touches anything outside the scratch naming
        // contract. Best-effort — a failure must never block startup.
        if let Err(error) = sweep_stale_scratch_configs() {
            tracing::warn!("scratch config cleanup failed: {error}");
        }
        // The latency probe's temp config carries every probed profile's
        // credentials; only a crash or kill can strand one, so the same
        // best-effort sweep covers its naming contract too.
        if let Err(error) = crate::rt::sweep_stale_probe_dirs() {
            tracing::warn!("latency probe config cleanup failed: {error}");
        }
        load_cjk_fonts(&cc.egui_ctx);
        // A locked or undetectable profile directory breaks every later save
        // and download; surface the failure up front instead of letting it
        // appear later as confusing secondary errors.
        let dirs_error = paths::ensure_dirs().err();

        let (servers, servers_error) = match ServersFile::load() {
            Ok(servers) => (servers, None),
            Err(error) => {
                tracing::error!("servers.json could not be loaded (left intact): {error}");
                (ServersFile::default(), Some(error.to_string()))
            }
        };
        let (settings, settings_error) = match Settings::load() {
            Ok(settings) => (settings, None),
            Err(error) => {
                tracing::error!("settings.json could not be loaded (left intact): {error}");
                (Settings::default(), Some(error.to_string()))
            }
        };
        // Custom Visuals are not persisted by eframe (`serde(skip)`), so the
        // accent lives in broccoli settings and must be re-applied on every boot.
        crate::ui::settings::apply_accent(&cc.egui_ctx, settings.accent_color);
        let lang = settings.language;
        // A state file that cannot be read, or whose valid JSON carries
        // unknown enum values, fails the load with the file left intact (no
        // `.broken-*` quarantine, no defaults substituted). Surface it up
        // front so a typo'd `security`/`network` can never silently downgrade
        // TLS to plaintext unnoticed, and so a transient read failure cannot
        // be mistaken for a fresh install whose defaults then overwrite the
        // file.
        let state_error = match (settings_error, servers_error) {
            (None, None) => None,
            (Some(settings_err), None) => Some(t_fmt(
                lang,
                Key::StateFileLoadFailed,
                &[&"settings.json", &settings_err.as_str()],
            )),
            (None, Some(servers_err)) => Some(t_fmt(
                lang,
                Key::StateFileLoadFailed,
                &[&"servers.json", &servers_err.as_str()],
            )),
            (Some(settings_err), Some(servers_err)) => Some(format!(
                "{}\n{}",
                t_fmt(
                    lang,
                    Key::StateFileLoadFailed,
                    &[&"settings.json", &settings_err.as_str()],
                ),
                t_fmt(
                    lang,
                    Key::StateFileLoadFailed,
                    &[&"servers.json", &servers_err.as_str()],
                ),
            )),
        };
        let persistence_error = match dirs_error {
            Some(error) => {
                tracing::error!("failed to create profile directories: {error:#}");
                Some(t_fmt(
                    lang,
                    Key::CreateProfileDirsFailed,
                    &[&format!("{error:#}")],
                ))
            }
            None => None,
        };
        // Baseline for the changes-pending gate: before any apply the gate
        // compares against the config a fresh Connect would apply — the one
        // generated from the just-loaded state.
        let generated_candidate = generate_runtime_candidate(&servers, &settings, lang);
        let config_error = generated_candidate.as_ref().err().cloned();
        let applied_candidate = generated_candidate
            .ok()
            .map(normalize_candidate_for_compare);

        let (evt_tx, evt_rx) = std::sync::mpsc::sync_channel(EVT_CHANNEL_CAPACITY);
        let rt = spawn_runtime(evt_tx.clone(), cc.egui_ctx.clone());
        let log_buffer = LogBuffer::new();
        if persistence_error.is_none() {
            let want_tun = settings.mode == crate::model::Mode::Tun;
            let _ = rt.cmd.send(CoreCmd::SetTunMode(want_tun));
        }
        let icon_assets = IconAssets::new();
        #[cfg(windows)]
        let (initial_native_dark, initial_main_hwnd) = {
            let dark = native_dark_for(
                cc.egui_ctx.options(|options| options.theme_preference),
                native_theme::system_dark_mode(),
            );
            let main_hwnd = cc
                .winit_window()
                .and_then(|window| native_theme::main_window_hwnd(window));
            // Opt the process into the resolved native theme before the tray
            // menu exists, so even the very first popup renders dark/light
            // correctly. The tray window (and possibly the main window) is not
            // reachable yet; `logic` re-applies once it appears.
            let mut hwnds = [HWND::default(); 2];
            let mut count = 0;
            if let Some(hwnd) = main_hwnd {
                hwnds[count] = hwnd;
                count += 1;
            }
            native_theme::apply(dark, &hwnds[..count]);
            (dark, main_hwnd)
        };
        let (tray, tray_menu) = build_tray(&icon_assets, settings.language, with_tray_icon);
        let (tray_registration_id, tray_action_rx) =
            install_tray_event_handlers(&cc.egui_ctx, tray.as_ref(), &tray_menu);
        let (core_version, core_setup) = core_facts(sys::core_dl::cached_core_presence(
            dat_pins_suspended(&settings),
        ));
        let core_available = core_version.is_some();

        let mut app = Self {
            servers,
            settings,
            rt,
            evt_rx,
            evt_tx,
            ui_ctx_snapshot: UiCtxSnapshot {
                phase: CorePhase::Stopped,
                stats: None,
                observatory: Vec::new(),
                core_version: core_version.clone(),
                core_setup: core_setup.clone(),
                terminal_error: None,
                download: DownloadState::Idle,
                update_check: UpdateCheckState::Idle,
                stats_generation: 0,
                latency_generation: 0,
            },
            ui_ctx_dirty: false,
            stats_generation: 0,
            latency_generation: 0,
            phase: CorePhase::Stopped,
            pending_transport: None,
            active_transport: None,
            operation: None,
            stats: None,
            stats_history: VecDeque::with_capacity(HISTORY_CAP),
            observatory: Vec::new(),
            logs: log_buffer,
            download: DownloadState::Idle,
            update_check: UpdateCheckState::Idle,
            probe_feedback: ui::request::ParkedSlot::default(),
            core_version,
            core_available,
            core_setup,
            terminal_error: None,
            install_in_flight: false,
            is_elevated: sys::elevation::is_elevated(),
            screen: Screen::Dashboard,
            dashboard: Default::default(),
            servers_ui: Default::default(),
            routing: Default::default(),
            dns: Default::default(),
            inbounds: Default::default(),
            tun: Default::default(),
            apply_result: None,
            config_dirty: persistence_error.is_some() || config_error.is_some(),
            applied_candidate,
            config_revision: 0,
            model_generation: 0,
            last_persist: None,
            persist_pending: None,
            raw_override_verdict: None,
            connect_block_cache: None,
            pending_safety_ack: None,
            state_error,
            persistence_error,
            config_error,
            state_error_save_logged: false,
            topbar: ui::topbar::TopbarMemos::default(),
            logs_ui: Default::default(),
            settings_ui: Default::default(),
            profile_preview: Default::default(),
            about: Default::default(),
            wizard: Default::default(),
            icon_assets,
            last_icon_presentation: None,
            last_tray_connect: None,
            tray,
            tray_registration_id,
            tray_action_rx,
            tray_menu,
            quitting: false,
            // The viewport starts visible; close-to-tray sets the flag.
            viewport_hidden: false,
            frame_drain: DrainOutcome::Empty,
            // The tray window did not exist when the initial theme was applied
            // above (`tray_hwnd: None`), so the first `logic` frame re-applies
            // and picks it up.
            #[cfg(windows)]
            last_native_theme: Some(AppliedNativeTheme {
                dark: initial_native_dark,
                main_hwnd: initial_main_hwnd,
                tray_hwnd: None,
            }),
            // The initial OS-dark sample was consumed by the startup apply
            // above; the first `logic` frame re-samples and re-applies once
            // the tray window is reachable (same cadence as `last_native_theme`).
            #[cfg(windows)]
            native_theme_sample: None,
        };
        // The boot generation above is the raw-override verdict's first
        // source; every later label, tray item and screen context reads it —
        // no frame path runs the generator.
        app.record_raw_override_verdict();
        app
    }

    /// Append a line to the in-app log ring (rendered by the Logs screen).
    /// GUI-originated lines pass `from_core: false`, core output `true`.
    pub fn push_log(&mut self, from_core: bool, line: String) {
        // Only the disk copy is sanitized: a crafted core line must not inject
        // ANSI sequences, carriage returns, or fake log records into app.log
        // (CWE-117). The in-memory view keeps the raw line — egui
        // renders it as literal text, so the viewer is unchanged.
        if from_core {
            tracing::info!(target: "xray", "{}", escape_control_chars(&line));
        } else {
            tracing::info!(target: "broccoli", "{}", escape_control_chars(&line));
        }
        self.logs.push(from_core, line);
    }

    fn apply_observatory_statuses(servers: &mut ServersFile, statuses: &[OutboundStatusView]) {
        if statuses.is_empty() {
            return;
        }
        // Index the statuses once: `ServerProfile::tag()` allocates, so the
        // nested scan cost allocations per (status, profile) pair on every
        // observatory tick. The index keeps one `tag()` call per profile and
        // preserves the last-status-wins order of duplicate tags.
        let by_tag: HashMap<&str, &OutboundStatusView> = statuses
            .iter()
            .map(|status| (status.tag.as_str(), status))
            .collect();
        for profile in &mut servers.profiles {
            let tag = profile.tag();
            if let Some(status) = by_tag.get(tag.as_str()) {
                profile.latency_ms = Some(if status.alive { status.delay_ms } else { -1 });
            }
        }
    }

    fn replace_observatory_snapshot(
        servers: &mut ServersFile,
        current: &mut Vec<OutboundStatusView>,
        statuses: Vec<OutboundStatusView>,
    ) {
        Self::apply_observatory_statuses(servers, &statuses);
        *current = statuses;
    }
    fn drain_events(&mut self) -> DrainOutcome {
        for processed in 1..=EVENT_DRAIN_LIMIT {
            let Ok(ev) = self.evt_rx.try_recv() else {
                return if processed == 1 {
                    DrainOutcome::Empty
                } else {
                    DrainOutcome::Drained
                };
            };
            match ev {
                CoreEvt::State(phase) => {
                    self.ui_ctx_dirty = true;
                    // The terminal message reports one phase state: a failure
                    // phase records its keyed headline plus the captured core
                    // output, and any move of the live phase away from the
                    // state the message described drops the message.
                    match &phase {
                        CorePhase::Error(error) => {
                            self.terminal_error = Some(TerminalError::new(
                                error.message.clone(),
                                error.tail.clone(),
                                self.settings.language,
                            ));
                        }
                        _ if phase != self.phase => {
                            self.terminal_error = None;
                        }
                        _ => {}
                    }
                    match &phase {
                        CorePhase::Starting | CorePhase::Running => {
                            if let Some(transport) = self.pending_transport.take() {
                                self.active_transport = Some(transport);
                            }
                        }
                        CorePhase::Stopped | CorePhase::Backoff { .. } | CorePhase::Error(_) => {
                            self.pending_transport = None;
                            self.active_transport = None;
                        }
                    }
                    self.phase = phase.clone();
                    // Any phase change means a different core session (or
                    // none): trial rules never survive a restart or config
                    // commit, so the cached live list is stale by definition.
                    self.routing.invalidate_trial_rules();
                    // Same session logic for the runtime facts: rows from a
                    // previous core session would misrepresent what is bound.
                    self.profile_preview.invalidate_runtime();
                    // Stats are session facts too (rates, memory, session
                    // totals): the last tick of a dead session must not
                    // masquerade as live state. The generation bump forces
                    // the dashboard's stats caches to rebuild empty.
                    invalidate_session_stats(&mut self.stats, &mut self.stats_generation);
                    // The status read follows the configuration the core
                    // actually launched: a raw override or a rolled-back
                    // candidate can differ from what the settings describe.
                    // The runtime holds that fact (it reads it off the launch
                    // it reports) and arms the read with it; the shell owns
                    // the tags alone.
                    if matches!(phase, CorePhase::Running) {
                        let tags: Vec<String> = self
                            .servers
                            .profiles
                            .iter()
                            .map(|profile| profile.tag())
                            .collect();
                        self.rt.cmd.send(CoreCmd::SetObservatory { tags }).ok();
                    }

                    if let CorePhase::Error(error) = &phase {
                        let lang = self.settings.language;
                        self.push_log(
                            false,
                            t_fmt(lang, Key::LogCoreError, &[&error.record(lang)]),
                        );
                    }
                }
                CoreEvt::ActiveConfig {
                    snapshot,
                    transport,
                } => {
                    self.pending_transport = Some(transport);
                    self.profile_preview.record_start(snapshot);
                }
                CoreEvt::Log { line, from_core } => self.push_log(from_core, line),
                CoreEvt::AppLog(message) => {
                    // Runtime-authored text: render it in the active language
                    // and add the log prefix the runtime's raw lines carry.
                    let lang = self.settings.language;
                    self.push_log(false, format!("[broccoli] {}", message.text(lang)));
                }
                CoreEvt::Stats(tick) => {
                    self.stats_generation += 1;
                    self.ui_ctx_dirty = true;
                    if self.stats_history.len() >= HISTORY_CAP {
                        self.stats_history.pop_front();
                    }
                    self.stats_history.push_back(tick.clone());
                    self.stats = Some(tick);
                }
                CoreEvt::Observatory(list) => {
                    self.latency_generation += 1;
                    self.ui_ctx_dirty = true;
                    Self::replace_observatory_snapshot(
                        &mut self.servers,
                        &mut self.observatory,
                        list,
                    )
                }
                CoreEvt::ApplyResult {
                    ok,
                    output,
                    revision,
                } => {
                    let lang = self.settings.language;
                    if let Some(save_error) = self.persistence_error.as_deref() {
                        self.config_dirty = true;
                        self.apply_result = Some((
                            false,
                            t_fmt(
                                lang,
                                Key::ApplyResultUnsaved,
                                &[&save_error, &output.text(lang)],
                            ),
                        ));
                    } else {
                        let settles_current =
                            apply_verdict_settles_current(ok, revision, self.config_revision);
                        if settles_current {
                            // The core accepted the config generated from the
                            // current model state (revision match: no edit
                            // landed since the commit); refresh the baseline
                            // the changes-pending gate compares against.
                            self.applied_candidate =
                                generate_runtime_candidate(&self.servers, &self.settings, lang)
                                    .ok()
                                    .map(normalize_candidate_for_compare);
                        }
                        self.config_dirty = !settles_current;
                        // A success for an older revision is not a failure of
                        // what the app holds now: the top bar reports the older
                        // apply while newer saved changes stay pending.
                        self.apply_result = if ok && !settles_current {
                            Some((
                                false,
                                t_fmt(lang, Key::ApplyResultOlder, &[&output.text(lang)]),
                            ))
                        } else {
                            Some((ok, output.text(lang)))
                        };
                    }
                }
                CoreEvt::RollbackResult { ok, output } => {
                    // Even a successful rollback means the user's candidate
                    // was not retained.
                    self.config_dirty = true;
                    let lang = self.settings.language;
                    self.apply_result = Some((
                        false,
                        if ok {
                            t_fmt(lang, Key::RollbackRestored, &[&output.text(lang)])
                        } else {
                            t_fmt(lang, Key::RollbackFailed, &[&output.text(lang)])
                        },
                    ));
                }
                CoreEvt::LatencyProbe(result) => {
                    // Apply-then-park, byte-identical to the bus era: the
                    // latency_ms ingestion stays in drain order, then the
                    // outcome lands in the single probe-feedback slot for
                    // the servers screen to take.
                    if let Ok(statuses) = &result.result {
                        Self::apply_observatory_statuses(&mut self.servers, statuses);
                        // The probe just wrote profile latency_ms — an input
                        // of the dashboard grid's fallback cell — so the
                        // memoized grid rows must rebuild on this result too.
                        self.latency_generation += 1;
                        self.ui_ctx_dirty = true;
                    }
                    self.probe_feedback.park(result);
                }
                CoreEvt::Download(download) => {
                    self.ui_ctx_dirty = true;
                    match &download {
                        DownloadState::Done(version) => {
                            // The runtime verifies every compiled release pin for both the
                            // network download and local archive source before this success
                            // event, so no UI-thread rehash is needed.
                            self.core_available = true;
                            self.core_version = Some(version.clone());
                            // The tree that failed verification has been
                            // replaced and pin-verified: nothing is left for
                            // the setup surface's reason to describe, and the
                            // terminal message an install answers is cleared
                            // by the successful action (the attempt itself is
                            // never resumed automatically).
                            self.core_setup = ui::CoreSetupState::default();
                            self.terminal_error = None;
                        }
                        DownloadState::Failed(_) => {
                            // The terminal ends an install this shell started:
                            // the tree on disk is whatever the transaction
                            // left (a failed first install, the retained
                            // last-good tree restored, or a gate rollback), so
                            // the cached facts are re-derived from that tree
                            // instead of keeping the candidate's. Without it
                            // the surface can read "Installed and verified"
                            // for a tree that was replaced and the Connect
                            // gate lets an attempt through to a spawn failure.
                            // One verification pass pays for the truth; the
                            // transaction already made the memo stale.
                            if std::mem::take(&mut self.install_in_flight) {
                                self.adopt_core_presence(sys::core_dl::verify_core_presence(
                                    dat_pins_suspended(&self.settings),
                                ));
                            }
                        }
                        DownloadState::Working { .. } => self.install_in_flight = true,
                        DownloadState::Idle => {}
                    }
                    self.download = download;
                }
                CoreEvt::UpdateCheck(state) => {
                    // One terminal result per accepted click; the UI renders
                    // it from the snapshot.
                    self.update_check = state;
                    self.ui_ctx_dirty = true;
                }
                CoreEvt::Operation(operation) => {
                    if operation.is_none() {
                        // The exclusive record is released: the install
                        // transaction that set the flag is over, and a later
                        // rejection must not re-derive the tree.
                        self.install_in_flight = false;
                    }
                    self.operation = operation.and_then(HeldOperation::mirror);
                }
            }
            if event_batch_exhausted(processed) {
                // The receiver has no non-consuming queue-length probe. A
                // harmless extra repaint is preferable to consuming and
                // dropping a queued lifecycle event.
                return DrainOutcome::Full;
            }
        }
        // Unreachable: the exhausted check above fires on the last
        // iteration. Kept as a tail expression for the compiler.
        DrainOutcome::Empty
    }

    fn drain_tray(&mut self, ctx: &egui::Context) {
        while let Ok(action) = self.tray_action_rx.try_recv() {
            // A quit already in flight is final: a tray action queued behind
            // it (the user clicking the icon because the quit had not landed
            // yet) must not resurrect the window `ViewportCommand::Close` is
            // tearing down — that surfaced as the window flashing up and
            // closing again — nor start a connect during teardown.
            if self.quitting {
                continue;
            }
            match action {
                TrayAction::Show => self.show_window(ctx),
                TrayAction::ToggleConnection => match PhaseAction::for_phase(&self.phase) {
                    PhaseAction::Connect => {
                        // A connect parked on the hazard acknowledgment
                        // succeeds without starting anything, and that
                        // acknowledgment can only be answered in the window:
                        // with it hidden (close-to-tray) or minimized the
                        // tray action would look like a no-op until the user
                        // surfaced the window by hand. Same rule as the tray
                        // Quit's own deferral.
                        if self.request_connect().is_err() || self.pending_safety_ack.is_some() {
                            self.show_window(ctx);
                        }
                    }
                    PhaseAction::Disconnect | PhaseAction::CancelRetry => {
                        if self.request_stop().is_err() {
                            self.show_window(ctx);
                        }
                    }
                },
                TrayAction::Quit => self.quit(ctx),
            }
        }
    }

    /// Refresh the tray connect item only when its label or enabled state
    /// actually changed. muda's `set_text` allocates (`to_string` +
    /// `encode_wide`) and issues `SetMenuItemInfoW` per parent menu on every
    /// call, so idle frames must not call it — the presentation depends only
    /// on phase/language/block state, mirroring `sync_icons`'
    /// presentation gate.
    fn sync_tray_action(&mut self) {
        let action = PhaseAction::for_phase(&self.phase);
        let connect_blocked = self
            .connect_block_cache
            .as_ref()
            .is_some_and(|cache| cache.reason.is_some());
        let presentation =
            tray_connect_presentation(action, self.settings.language, connect_blocked);
        if self.last_tray_connect == Some(presentation) {
            return;
        }
        self.last_tray_connect = Some(presentation);
        self.tray_menu.connect.set_text(presentation.label);
        self.tray_menu.connect.set_enabled(presentation.enabled);
    }

    fn sync_icons(&mut self, frame: &eframe::Frame) {
        let presentation = classify(&self.phase, self.active_transport);
        if self.last_icon_presentation == Some(presentation) {
            return;
        }
        self.last_icon_presentation = Some(presentation);
        let tooltip = presentation.tooltip(self.settings.language);

        #[cfg(windows)]
        {
            let scale_factor = frame.winit_window().map(|window| {
                let scale_factor = window.scale_factor();
                if let Err(error) = self.icon_assets.apply_window(window, presentation.state) {
                    tracing::warn!("window/taskbar icon update failed: {error}");
                }
                scale_factor
            });

            if let Some(tray) = self.tray.as_ref() {
                match self.icon_assets.tray_icon(presentation.state, scale_factor) {
                    Ok(icon) => {
                        if let Err(error) = tray.set_icon(Some(icon)) {
                            tracing::warn!("tray icon update failed: {error}");
                        }
                    }
                    Err(error) => tracing::warn!("tray icon update failed: {error}"),
                }
                if let Err(error) = tray.set_tooltip(Some(tooltip.as_str())) {
                    tracing::warn!("tray tooltip update failed: {error}");
                }
            }
        }

        #[cfg(not(windows))]
        let _ = (frame, tooltip);
    }

    /// Keep the native Windows theme (tray popup menu, window chrome) in sync
    /// with the resolved egui theme. One small struct compare per frame; the
    /// theme is re-applied only when the resolved dark/light flips (Settings
    /// change, OS theme change while `System`, startup) or when the set of
    /// reachable HWNDs changes (the main window can be created after the first
    /// `logic` call; the tray window appears after `new`). The OS dark-mode
    /// flag itself is re-read from the registry at most once per
    /// [`NATIVE_THEME_SAMPLE_INTERVAL_SECS`] (the apply gate below still
    /// decides when to re-apply, so a flipped OS theme lands within the
    /// interval).
    #[cfg(windows)]
    fn sync_native_theme(&mut self, ctx: &egui::Context, frame: &eframe::Frame) {
        let now = ctx.input(|input| input.time);
        let system_dark = match self.native_theme_sample {
            Some((dark, sampled_at)) if now - sampled_at < NATIVE_THEME_SAMPLE_INTERVAL_SECS => {
                dark
            }
            _ => {
                let dark = native_theme::system_dark_mode();
                self.native_theme_sample = Some((dark, now));
                dark
            }
        };
        let dark = native_dark_for(ctx.options(|options| options.theme_preference), system_dark);
        let main_hwnd = frame
            .winit_window()
            .and_then(|window| native_theme::main_window_hwnd(window));
        let tray_hwnd = self.tray.as_ref().map(|tray| HWND(tray.window_handle()));
        let current = AppliedNativeTheme {
            dark,
            main_hwnd,
            tray_hwnd,
        };
        if self.last_native_theme == Some(current) {
            return;
        }

        let mut hwnds = [HWND::default(); 2];
        let mut count = 0;
        if let Some(hwnd) = main_hwnd {
            hwnds[count] = hwnd;
            count += 1;
        }
        if let Some(hwnd) = tray_hwnd {
            hwnds[count] = hwnd;
            count += 1;
        }
        native_theme::apply(dark, &hwnds[..count]);
        self.last_native_theme = Some(current);
    }

    #[cfg(not(windows))]
    fn sync_native_theme(&mut self, _ctx: &egui::Context, _frame: &eframe::Frame) {}

    fn show_window(&mut self, ctx: &egui::Context) {
        // Every path back from close-to-tray goes through here, so it is
        // the single place the visibility gate reopens.
        self.viewport_hidden = false;
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        // A minimized window stays minimized for `Visible(true)` (winit only
        // shows windows it considers hidden), and eframe then keeps taking
        // the logic-only path — the restore request must un-minimize too, or
        // "Show" (tray, connect/stop fallbacks) is a no-op.
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    fn quit(&mut self, ctx: &egui::Context) {
        // Unsaved-changes indicator: a dirty server draft defers the quit —
        // the leave action is staged, and the modal resolved on later frames
        // resumes the quit through the ui() tail. `quit_with_cleanup` /
        // `quit_with_reset` below deliberately bypass this (destructive
        // flows with their own confirms).
        if quit_or_stage_leave(&mut self.servers_ui, ctx) {
            self.quit_impl(ctx, None);
        } else if self.viewport_suppressed(ctx) {
            // The staged quit is resolved through the leave modal, which
            // cannot be seen or clicked while the viewport is hidden
            // (close-to-tray) or minimized: the tray Quit would look like a
            // no-op until the user surfaces the window by hand. Bring the
            // window up so the deferral (and its Save/Discard/Cancel) is
            // visible — the tray Quit must never be silent.
            self.show_window(ctx);
        }
    }

    /// The viewport is hidden (close-to-tray) or minimized: eframe runs
    /// logic-only passes for the latter and the window is off-screen for the
    /// former, so nothing the app renders can reach the user. The
    /// visibility gate and the staged-quit surfacing share this predicate.
    fn viewport_suppressed(&self, ctx: &egui::Context) -> bool {
        self.viewport_hidden || ctx.input(|input| input.viewport().minimized == Some(true))
    }

    /// Quit through the normal path while requesting full cleanup. The
    /// filesystem actions therefore run only after `run_native` has
    /// dropped the app — core and elevated helper stopped — and the process
    /// still exits normally.
    fn quit_with_cleanup(&mut self, ctx: &egui::Context) {
        self.quit_impl(ctx, Some(sys::cleanup::CleanupMode::Full));
    }

    /// Quit through the normal path while requesting a reset-to-default
    /// cleanup: the exit wipe deletes everything except the
    /// server list and the core, returning a fresh-install state. Runs only
    /// after `run_native` has dropped the app, like full cleanup.
    fn quit_with_reset(&mut self, ctx: &egui::Context) {
        self.quit_impl(ctx, Some(sys::cleanup::CleanupMode::ResetFiles));
    }

    fn quit_impl(&mut self, ctx: &egui::Context, mode: Option<sys::cleanup::CleanupMode>) {
        self.quitting = true;
        // The runtime owns an in-flight profile validation, and `Shutdown`
        // cancels it cooperatively: the worker observes the cancel before its
        // next profile and delivers its exactly-one terminal, never a hard
        // abort — its `xray -test` child holds the scratch config open.
        // Nothing is joined here: the wait for that terminal belongs to the
        // runtime's own teardown (and the `RuntimeHandle` drop joins it).
        // Joining here would block the GUI thread for up to one
        // `xray run -test` (`rt::apply`'s ~10 s timeout) with the quit
        // already in flight — the tray Quit that "did nothing" for seconds,
        // then let a tray Show queued behind it flash the window up and
        // close it again.
        self.rt.cmd.send(CoreCmd::Shutdown).ok();
        if let Some(mode) = mode {
            sys::cleanup::request(mode);
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
    }

    /// The reason Connect is disabled for the current state, freshly
    /// evaluated from shell-recorded state only — the frame path never calls
    /// this directly: [`Self::refresh_connect_block_cache`] recomputes it
    /// only when the keyed inputs moved, and the top bar and screen contexts
    /// then borrow the memoized text. Nothing here runs the generator, so
    /// the verdict cannot fork per surface and no paint pass binds the
    /// ephemeral control-plane port.
    fn compute_connect_blocked_reason(&self, lang: Language) -> Option<String> {
        if let Some(error) = &self.persistence_error {
            return Some(t_fmt(lang, Key::ConnectBlockedSave, &[&error]));
        }
        if self.settings.raw_override.is_some() && self.settings.mode != crate::model::Mode::Off {
            return Some(t(lang, Key::ConnectBlockedRawMode).into());
        }
        if let Some(error) = &self.config_error {
            return Some(error.clone());
        }
        // The installed-core gate is deliberately absent here: a missing,
        // stale or unverified core does not disable Connect — an attempt
        // fails visibly in the terminal error block, which points at the
        // core setup surface (see [`Self::core_gate_error`]).
        if let Some(operation) = &self.operation {
            return Some(t_fmt(
                lang,
                Key::ConnectBlockedOperation,
                &[&operation.name.text(lang)],
            ));
        }
        // The verdict the shell recorded where generation already runs
        // ([`Self::record_raw_override_verdict`]): the raw override's
        // generation error carries the same excerpt boundary as every other
        // generation-failure surface. Reading it parses nothing and
        // allocates nothing.
        if self.settings.raw_override.is_some()
            && let Some(error) = self.raw_override_verdict.as_ref()
        {
            return Some(error.clone());
        }
        None
    }

    /// Refresh the memoized connect-block texts: while any
    /// blocking state is set — persistence/config error, in-flight
    /// operation, raw-override verdict, missing core — the reason text used
    /// to be re-formatted (`t_fmt`, `clone`) on every frame the shell
    /// painted. The texts are pure functions of
    /// the keyed inputs below, so a cheap allocation-free staleness compare
    /// per pass is followed by a re-format only when an input actually
    /// moved. Runs in `logic` before the tray/icon sync reads the reason,
    /// and once more at the top of `ui` — the second call is a no-op check
    /// that keeps the borrowable texts current on every render pass (the
    /// same staleness pattern as the top bar's caption memo).
    ///
    /// The recompute reads shell-recorded state only: the raw-override
    /// verdict was recorded by the boot / config-persist generation, so this
    /// path — reached from `logic`, `ui` and the click handlers — never runs
    /// the generator.
    fn refresh_connect_block_cache(&mut self) {
        let lang = self.settings.language;
        let current = self.connect_block_cache.as_ref().is_some_and(|cache| {
            cache.lang == lang
                && cache.persistence_error == self.persistence_error
                && cache.config_error == self.config_error
                && cache.operation == self.operation
                && cache.mode == self.settings.mode
                && cache.raw_override == self.settings.raw_override
                && cache.config_revision == self.config_revision
        });
        if current {
            return;
        }
        let reason = self.compute_connect_blocked_reason(lang);
        // The Apply-now chip's "operation in progress" text (shown when
        // config_dirty and an operation blocks the apply), formatted once
        // per operation change like the reason above.
        let operation_caption = self.operation.as_ref().map(|operation| {
            t_fmt(
                lang,
                Key::AppOperationInProgress,
                &[&operation.name.text(lang)],
            )
        });
        self.connect_block_cache = Some(ConnectBlockCache {
            lang,
            persistence_error: self.persistence_error.clone(),
            config_error: self.config_error.clone(),
            // The memo owns its snapshot of the mirror: the key it compares
            // against on the next refresh.
            operation: self.operation.clone(),
            mode: self.settings.mode,
            raw_override: self.settings.raw_override.clone(),
            config_revision: self.config_revision,
            reason,
            operation_caption,
        });
    }

    /// Record the raw-override connect verdict from the generation that has
    /// just run (boot, config persist): `config_error` is that generation's
    /// result, so both move together — the verdict is kept while a raw
    /// override is configured and cleared otherwise. Only these two sites
    /// write it; the connect-block memo and every screen behind it read it.
    fn record_raw_override_verdict(&mut self) {
        self.raw_override_verdict = if self.settings.raw_override.is_some() {
            self.config_error.clone()
        } else {
            None
        };
    }

    /// Record a candidate-generation failure in every surface that echoes it
    /// (config-error chip, apply result, log). The message arrives already
    /// excerpt-bounded from `generate_runtime_candidate`,
    /// so exactly the bounded text is stored, rendered and logged.
    fn record_generation_failure(&mut self, message: String) {
        self.config_error = Some(message.clone());
        self.config_dirty = true;
        self.apply_result = Some((false, message.clone()));
        let lang = self.settings.language;
        self.push_log(false, t_fmt(lang, Key::LogBroccoliMessage, &[&message]));
    }

    /// The terminal message a Connect or Apply attempt fails with while the
    /// managed core cannot run: no tree, a stale tree (its release metadata
    /// names another build), or a tree that failed verification. The message
    /// names both versions when a tree is present; the block that carries it
    /// points at the core setup surface.
    fn core_gate_error(&self) -> Option<TerminalError> {
        if self.core_available {
            return None;
        }
        let message = match self.core_setup.installed_version.as_deref() {
            Some(installed) => Diag::new(Key::ConnectBlockedCoreUpdate)
                .arg(installed)
                .arg(sys::core_dl::pinned_core_version()),
            None => Diag::new(Key::ConnectBlockedInstallCore),
        };
        Some(TerminalError::new(
            message,
            String::new(),
            self.settings.language,
        ))
    }

    /// Record the core gate's failure in every surface that echoes it — the
    /// content-area block and the log — and return the message text for the
    /// caller's `Err`.
    fn record_core_gate_failure(&mut self, error: TerminalError) -> String {
        let lang = self.settings.language;
        let reason = error.text.clone();
        self.terminal_error = Some(error);
        // The content-area block reads the message from the UI-context
        // snapshot, which rebuilds only when an input moved.
        self.ui_ctx_dirty = true;
        self.push_log(false, t_fmt(lang, Key::LogConnectBlocked, &[&reason]));
        reason
    }

    /// Adopt one verification pass's answer as the shell's cached core facts.
    fn adopt_core_presence(&mut self, presence: sys::core_dl::CorePresence) {
        let (version, setup) = core_facts(presence);
        self.core_available = version.is_some();
        self.core_version = version;
        self.core_setup = setup;
        self.ui_ctx_dirty = true;
    }

    /// Re-verify the installed core on demand (the core setup surface's
    /// Verify action): one full pinned-payload pass, bypassing the render
    /// memo — the same work boot does once, here on an explicit click. A pass
    /// that verifies is a successful action and clears the terminal message;
    /// a pass that fails leaves its reason on the surface, where the user
    /// asked for it.
    fn verify_core(&mut self) {
        self.adopt_core_presence(sys::core_dl::verify_core_presence(dat_pins_suspended(
            &self.settings,
        )));
        if self.core_available {
            self.terminal_error = None;
        }
    }

    fn request_connect(&mut self) -> Result<(), String> {
        let lang = self.settings.language;
        // Read the memoized reason: refresh first — the click
        // path may run before this pass's `logic` refresh (tray actions
        // dispatch inside `logic`) — then clone for the event-driven error
        // and log side effects, both at click time, never per frame.
        self.refresh_connect_block_cache();
        if let Some(reason) = self
            .connect_block_cache
            .as_ref()
            .and_then(|cache| cache.reason.clone())
        {
            self.apply_result = Some((false, reason.clone()));
            self.push_log(false, t_fmt(lang, Key::LogConnectBlocked, &[&reason]));
            return Err(reason);
        }
        // The managed core cannot run yet: fail here, visibly, instead of
        // sending a doomed start. The terminal error block carries the
        // message and the way to the core setup surface, and nothing resumes
        // the attempt once an install finishes (the user retries).
        if let Some(error) = self.core_gate_error() {
            return Err(self.record_core_gate_failure(error));
        }
        // Hazardous settings must not commit until the summary
        // dialog is explicitly acknowledged. The dialog is the response —
        // not an error (no LogConnectBlocked push, no Err), so callers keep
        // their normal control flow.
        if let Some(findings) = hazard_gate_findings(&self.servers, &self.settings) {
            self.pending_safety_ack = Some((PendingApplyOrigin::Connect, findings));
            return Ok(());
        }
        self.start_apply()
    }

    /// Send one command to the runtime and mirror the busy window it opens.
    /// The kind comes from the command itself ([`CoreCmd::job_kind`]), never
    /// from the send site, so a send can neither name a kind the runtime does
    /// not occupy as nor forget the mirror; a command that opens no window —
    /// no job at all, or a query that runs alongside the occupant — leaves the
    /// mirror alone. `false` when the runtime's command channel is gone — the
    /// caller records its own failure.
    ///
    /// Mirroring the begin here is only an optimistic head start: whether the
    /// record actually began, and every release, still arrives on the runtime's
    /// own bookends, which stay the authority.
    fn send_command(&mut self, cmd: CoreCmd) -> bool {
        let kind = cmd.job_kind();
        let sent = self.rt.cmd.send(cmd).is_ok();
        if sent && let Some(held) = kind.and_then(HeldOperation::mirror) {
            self.operation = Some(held);
        }
        sent
    }

    /// The commit itself — candidate generation plus the runtime handoff.
    /// [`Self::request_connect`] and the hazard-dialog confirm both land
    /// here, so confirming applies exactly what the normal path would have
    /// started.
    fn start_apply(&mut self) -> Result<(), String> {
        let lang = self.settings.language;
        // The gate is re-checked at the commit: a hazard acknowledgment
        // resumes here long after the request that opened it, and a core that
        // cannot run must still fail visibly instead of starting a doomed
        // spawn.
        if let Some(error) = self.core_gate_error() {
            return Err(self.record_core_gate_failure(error));
        }
        if let Some(reason) = tun_outbound_interface_block_reason(
            lang,
            self.settings.mode,
            &self.settings.tun.auto_outbounds_interface,
            &sys::netif::list(),
        ) {
            self.record_generation_failure(reason.clone());
            return Err(reason);
        }
        let config = match generate_runtime_candidate(&self.servers, &self.settings, lang) {
            Ok(config) => config,
            Err(message) => {
                self.record_generation_failure(message.clone());
                return Err(message);
            }
        };
        self.config_error = None;
        let want_tun = self.settings.mode == crate::model::Mode::Tun;
        if self.send_command(CoreCmd::Apply {
            value: config,
            intent: ApplyIntent::CommitAndStart { tun_mode: want_tun },
            revision: self.config_revision,
        }) {
            Ok(())
        } else {
            let message = t(lang, Key::CoreRuntimeUnavailable).to_string();
            self.apply_result = Some((false, message.clone()));
            Err(message)
        }
    }

    /// Surface the pending hazard acknowledgment, if any, over
    /// everything else. Confirm clears the state and resumes the gated
    /// commit path; cancel clears the state and aborts. The acknowledgment
    /// is demanded on every apply while hazards remain — no persistence, no
    /// "don't ask again".
    fn show_safety_ack_modal(&mut self, ctx: &egui::Context) {
        let lang = self.settings.language;
        let Some((origin, findings)) = self.pending_safety_ack.clone() else {
            return;
        };
        show_safety_ack_modal(ctx, lang, &findings, |confirmed| {
            self.pending_safety_ack = None;
            if !confirmed {
                return;
            }
            match origin {
                PendingApplyOrigin::Connect => {
                    let _ = self.start_apply();
                }
                PendingApplyOrigin::ApplyNow => self.commit_runtime_config(lang),
            }
        });
    }

    fn request_stop(&mut self) -> Result<(), String> {
        if self
            .operation
            .as_ref()
            .is_some_and(|held| held.kind == JobKind::Stop)
        {
            return Ok(());
        }
        let lang = self.settings.language;
        if self.send_command(CoreCmd::Stop) {
            Ok(())
        } else {
            let message = t(lang, Key::CoreRuntimeUnavailable).to_string();
            self.apply_result = Some((false, message.clone()));
            Err(message)
        }
    }

    /// Persist GUI state after an edit, throttled to at most once per
    /// [`PERSIST_THROTTLE_SECS`] while the model stays dirty. A discrete edit
    /// after a quiet period persists immediately; an edit landing inside the
    /// throttle window schedules a repaint at the deadline so the final state
    /// still flushes ~`PERSIST_THROTTLE_SECS` after the last change. Runtime
    /// configuration remains unchanged until the user explicitly selects
    /// Apply now (or Connect, which must apply the current candidate before
    /// starting it).
    fn persist_if_due(&mut self, ctx: &egui::Context, kind: PersistKind) {
        let now = ctx.input(|input| input.time);
        match self.last_persist {
            Some(last) if now - last < PERSIST_THROTTLE_SECS => {
                // A config edit queued in the same window dominates a
                // UI-only one: its side effects (revision bump, Apply gate)
                // are a superset of the UI-only save.
                let kind = match (self.persist_pending, kind) {
                    (Some(PersistKind::Config), _) | (_, PersistKind::Config) => {
                        PersistKind::Config
                    }
                    _ => kind,
                };
                self.persist_pending = Some(kind);
                ctx.request_repaint_after(std::time::Duration::from_secs_f64(
                    PERSIST_THROTTLE_SECS - (now - last),
                ));
            }
            _ => self.persist_now(now, kind),
        }
    }

    /// Persist GUI state after an edit. Runtime configuration remains unchanged
    /// until the user explicitly selects Apply now (or Connect, which must
    /// apply the current candidate before starting it). A [`PersistKind::UiOnly`]
    /// save writes the files but never raises the Apply gate — display
    /// preferences cannot affect the running core.
    fn persist_now(&mut self, now: f64, kind: PersistKind) {
        // After a semantic load failure the in-memory model is
        // defaults while the intact hand-edited file stays on disk. Writing
        // now would silently overwrite that file, so saving is refused for
        // the whole session — the top-bar banner (Key::TopbarStateLoadFailed)
        // explains why. The refusal is logged once so it is findable in the
        // Logs screen without spamming identical lines per edit frame.
        if persist_blocked_by_state_error(self.state_error.as_deref()) {
            self.last_persist = Some(now);
            self.persist_pending = None;
            if !self.state_error_save_logged {
                self.state_error_save_logged = true;
                let lang = self.settings.language;
                self.push_log(
                    false,
                    t_fmt(
                        lang,
                        Key::LogBroccoliMessage,
                        &[&t(lang, Key::TopbarStateLoadFailed)],
                    ),
                );
            }
            return;
        }
        self.last_persist = Some(now);
        self.persist_pending = None;
        let lang = self.settings.language;
        let mut save_errors = Vec::new();
        if let Err(error) = self.servers.save() {
            let message = t_fmt(lang, Key::SaveServersFailed, &[&format!("{error:#}")]);
            self.push_log(false, t_fmt(lang, Key::LogBroccoliMessage, &[&message]));
            save_errors.push(message);
        }
        if let Err(error) = self.settings.save() {
            let message = t_fmt(lang, Key::SaveSettingsFailed, &[&format!("{error:#}")]);
            self.push_log(false, t_fmt(lang, Key::LogBroccoliMessage, &[&message]));
            save_errors.push(message);
        }
        self.persistence_error = if save_errors.is_empty() {
            None
        } else {
            Some(save_errors.join("\n"))
        };

        if kind == PersistKind::Config {
            self.config_revision = self.config_revision.wrapping_add(1);
            self.apply_result = None;
            match generate_runtime_candidate(&self.servers, &self.settings, lang) {
                Ok(config) => {
                    self.config_error = None;
                    // The gate is derived, not sticky: an edit reverted to the
                    // applied state (or the startup baseline) drops "changes
                    // pending" again without an Apply. Candidates are
                    // compared normalized — each generation embeds a fresh
                    // ephemeral API port.
                    self.config_dirty = config_gate_after_persist(
                        self.applied_candidate.as_ref(),
                        &normalize_candidate_for_compare(config),
                        self.persistence_error.as_deref(),
                    );
                }
                Err(message) => {
                    // Edit-time generation failures block Apply/Connect through
                    // config_error, but are not apply outcomes: recording them as
                    // apply_result (or a log line) would flash the top bar red and
                    // spam the log on every keystroke of a half-typed field.
                    self.config_error = Some(message);
                    self.config_dirty = true;
                }
            }
            // The raw-override verdict moves with the same generation, so it
            // can never describe a different persisted revision than
            // `config_error` does.
            self.record_raw_override_verdict();
        }
    }

    fn apply_runtime_config(&mut self) {
        let lang = self.settings.language;
        let blocked = self
            .persistence_error
            .as_ref()
            .map(|error| t_fmt(lang, Key::ApplyBlockedNotSaved, &[&error]))
            .or_else(|| self.config_error.clone())
            .or_else(|| {
                self.operation.as_ref().map(|operation| {
                    t_fmt(
                        lang,
                        Key::ApplyBlockedOperation,
                        &[&operation.name.text(lang)],
                    )
                })
            });
        if let Some(reason) = blocked {
            self.config_dirty = true;
            self.apply_result = Some((false, reason));
            return;
        }
        // Hazardous settings must not commit until the summary
        // dialog is explicitly acknowledged. The dialog is the response —
        // not an error (no apply_result, no log line).
        if let Some(findings) = hazard_gate_findings(&self.servers, &self.settings) {
            self.pending_safety_ack = Some((PendingApplyOrigin::ApplyNow, findings));
            return;
        }
        self.commit_runtime_config(lang);
    }

    /// The Apply-now commit after the blocked checks and the hazard gate;
    /// the hazard-dialog confirm resumes here, so confirming applies
    /// exactly what the normal path would have started.
    fn commit_runtime_config(&mut self, lang: Language) {
        if let Some(reason) = tun_outbound_interface_block_reason(
            lang,
            self.settings.mode,
            &self.settings.tun.auto_outbounds_interface,
            &sys::netif::list(),
        ) {
            self.record_generation_failure(reason);
            return;
        }
        let config = match generate_runtime_candidate(&self.servers, &self.settings, lang) {
            Ok(config) => config,
            Err(message) => {
                self.record_generation_failure(message);
                return;
            }
        };
        self.config_error = None;
        let want_tun = self.settings.mode == crate::model::Mode::Tun;
        if self.send_command(CoreCmd::Apply {
            value: config,
            intent: ApplyIntent::Commit { tun_mode: want_tun },
            revision: self.config_revision,
        }) {
            self.apply_result = None;
        } else {
            self.apply_result = Some((false, t(lang, Key::CoreRuntimeUnavailable).into()));
            self.config_dirty = true;
        }
    }
}

impl BroccoliApp {
    /// Rebuild the generation-gated UI-context snapshot.
    /// Runs only when a drained event changed its inputs — never on idle
    /// frames — so a no-op rebuild (e.g. the initial `State(Stopped)` drain)
    /// is skipped: the snapshot's own `same_inputs` compare is the gate.
    fn rebuild_ui_ctx_snapshot(&mut self) {
        let candidate = UiCtxSnapshot {
            phase: self.phase.clone(),
            stats: self.stats.clone(),
            observatory: self.observatory.clone(),
            core_version: self.core_version.clone(),
            core_setup: self.core_setup.clone(),
            terminal_error: self.terminal_error.as_ref().map(TerminalError::view),
            download: self.download.clone(),
            update_check: self.update_check.clone(),
            stats_generation: self.stats_generation,
            latency_generation: self.latency_generation,
        };
        if !self.ui_ctx_snapshot.same_inputs(&candidate) {
            self.ui_ctx_snapshot = candidate;
        }
        self.ui_ctx_dirty = false;
    }

    /// Test seam: push a synthetic runtime
    /// event through the real drain path, so kittest tests can prove the
    /// snapshot rebuilds exactly when an input generation changes. Inert in
    /// production — the runtime owns the channel's only other sender.
    pub fn inject_event(&self, ev: CoreEvt) {
        let _ = self.evt_tx.send(ev);
    }
}

impl Drop for BroccoliApp {
    fn drop(&mut self) {
        clear_tray_event_target(self.tray_registration_id);
        // The window is already gone by the time this runs, so the tray icon
        // is the last visible trace of the app: drop it now, before the
        // worker join below can hold the process open for up to one
        // `xray run -test` (rt::apply's ~10 s timeout).
        drop(self.tray.take());
        // An edit still inside the persist throttle window has its flush
        // scheduled on a repaint that never runs once the window closes —
        // write it out now so the last edit survives.
        if let Some(kind) = self.persist_pending {
            self.persist_now(0.0, kind);
        }
        let _ = self.rt.cmd.send(CoreCmd::Shutdown);
        // Exit half: the runtime keeps its select loop alive until an
        // in-flight profile validation's exactly-one terminal lands — the
        // child holds the scratch config open, so a runtime torn down
        // mid-run would strand plaintext secrets and orphan the child — and
        // the `RuntimeHandle` drop (below, with the rest of the fields) joins
        // that teardown within its bound. The window is already gone here, so
        // that bound is reached on a dead frame — the wait lives in the
        // handle drop below, never on a visible frame.
    }
}

impl eframe::App for BroccoliApp {
    fn logic(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        self.frame_drain = self.drain_events();
        if self.frame_drain == DrainOutcome::Full {
            // A full drain batch means more events are queued:
            // keep the backlog draining frame by frame.
            ctx.request_repaint();
        }
        if should_hide_on_close(
            ctx.input(|input| input.viewport().close_requested()),
            self.quitting,
        ) {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            // Close-to-tray gate: from this frame on the ui()
            // tail requests no follow-up repaints while the viewport is
            // hidden. Reopened by show_window (tray Show and the
            // connect/stop fallbacks).
            self.viewport_hidden = true;
        }
        self.drain_tray(ctx);
        // The Connect block reason is refreshed once per pass after the
        // event drain and shared by the tray sync, the top-bar Connect
        // button, and the screen contexts: the text
        // is re-formatted only when its keyed inputs moved, never on
        // repaint frames.
        self.refresh_connect_block_cache();
        self.sync_tray_action();
        self.sync_icons(frame);
        self.sync_native_theme(ctx, frame);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        // The terminal message follows the active language: the memo
        // re-renders only when the language moved (a key compare on every
        // other frame), and the snapshot below carries the fresh text.
        let language = self.settings.language;
        if let Some(error) = self.terminal_error.as_mut()
            && error.render_in(language)
        {
            self.ui_ctx_dirty = true;
        }
        // Runtime events can invalidate the generation-gated UI-context
        // snapshot; rebuild it once before this frame renders.
        if self.ui_ctx_dirty {
            self.rebuild_ui_ctx_snapshot();
        }

        // The connect-block texts were refreshed in `logic` after the event
        // drain; the re-check here (a no-op staleness compare when `logic`
        // already ran) keeps the borrowable texts current on any render
        // pass that skips `logic` — defensive, like the fallback recompute
        // the old frame slot documented.
        self.refresh_connect_block_cache();

        let mut dirty = false;
        let mut ui_dirty = false;
        let mut connect_requested = false;
        let mut stop_requested = false;
        let mut verify_core_requested = false;
        let mut open_core_folder_requested = false;
        let mut open_core_setup_requested = false;

        // Top bar: runtime phase/action, configured mode, persistence, and
        // active server. The row owns its captions, its width budget and its
        // clip (ui::topbar); the shell supplies the frame's facts and
        // dispatches the clicks.
        let lang = self.settings.language;
        let blocked = cached_block_reason(&self.connect_block_cache);
        let apply_block = apply_block_text(
            &self.persistence_error,
            &self.config_error,
            &self.connect_block_cache,
        );
        let topbar_clicks = egui::Panel::top("topbar")
            .show(ui, |ui| {
                ui::topbar::show_row(
                    ui,
                    &ui::topbar::TopbarRowState {
                        lang,
                        phase: &self.phase,
                        mode: self.settings.mode,
                        active_name: self.servers.active_profile().map(|p| p.name.as_str()),
                        core_version: self.core_version.as_deref(),
                        model_generation: self.model_generation,
                        blocked_reason: blocked.as_deref(),
                        unsaved_changes: self.servers_ui.unsaved_changes(),
                        trial_rule_count: self.routing.trial_rule_count(),
                        core_available: self.core_available,
                        config_dirty: self.config_dirty,
                        apply_block,
                        apply_result: self
                            .apply_result
                            .as_ref()
                            .map(|(ok, output)| (ok, output.as_str())),
                        terminal_error: self
                            .terminal_error
                            .as_ref()
                            .map(|error| error.text.as_str()),
                        config_error: self.config_error.as_deref(),
                        state_error: self.state_error.as_deref(),
                        persistence_error: self.persistence_error.as_deref(),
                        stats_generation: self.ui_ctx_snapshot.stats_generation,
                        unit: self.settings.traffic_unit,
                        stats: self.ui_ctx_snapshot.stats.as_ref(),
                    },
                    &mut self.topbar,
                )
            })
            .inner;
        if topbar_clicks.connect {
            let _ = self.request_connect();
        }
        if topbar_clicks.stop {
            let _ = self.request_stop();
        }
        if topbar_clicks.apply {
            self.apply_runtime_config();
        }
        if topbar_clicks.retry {
            // Explicit user action in a failure state: bypass the throttle
            // and retry immediately.
            self.persist_now(ctx.input(|input| input.time), PersistKind::Config);
        }
        if topbar_clicks.jump_to_error {
            // Jump to the message: the wrapped block with the captured core
            // output lives at the top of the dashboard content area.
            self.screen = Screen::Dashboard;
        }
        if topbar_clicks.open_folder
            && let Err(open_error) = sys::hidden_command("explorer")
                .arg(paths::state_dir())
                .spawn()
        {
            self.push_log(
                false,
                t_fmt(lang, Key::LogOpenStateFolderFailed, &[&open_error]),
            );
        }

        // Sidebar navigation. The live speed readout and the session totals
        // now live in the top bar and the dashboard table; the
        // rail carries nav only.
        egui::Panel::left("nav")
            .resizable(false)
            .default_size(140.0)
            .show(ui, |ui| {
                ui.add_space(8.0);
                let lang = self.settings.language;
                for s in Screen::ALL {
                    ui.selectable_value(&mut self.screen, s, s.label(lang));
                    ui.add_space(2.0);
                }
            });

        // Central screen dispatch. Scroll ownership: dashboard/servers/logs
        // manage their own scrolling; the rest get an outer ScrollArea.
        let operation = self.operation.as_ref().map(|held| held.kind);
        egui::CentralPanel::default().show(ui, |ui| {
            let snapshot = &self.ui_ctx_snapshot;
            let mut uictx = UiCtx::new(
                UiCtxParts {
                    servers: &mut self.servers,
                    settings: &mut self.settings,
                    cmd: &self.rt.cmd,
                    stats_history: &self.stats_history,
                    logs: &self.logs,
                    logs_generation: self.logs.generation(),
                    probe_feedback: &mut self.probe_feedback,
                    dirty: &mut dirty,
                    ui_dirty: &mut ui_dirty,
                    model_generation: &mut self.model_generation,
                    connect_requested: &mut connect_requested,
                    stop_requested: &mut stop_requested,
                    verify_core_requested: &mut verify_core_requested,
                    open_core_folder_requested: &mut open_core_folder_requested,
                    open_core_setup_requested: &mut open_core_setup_requested,
                    connect_blocked_reason: cached_block_reason(&self.connect_block_cache),
                    config_error: &self.config_error,
                    operation,
                    is_elevated: self.is_elevated,
                    config_revision: self.config_revision,
                },
                UiCtxView::Live { snapshot },
            );
            match self.screen {
                Screen::Dashboard => self.dashboard.show(ui, &mut uictx),
                Screen::Servers => self.servers_ui.show(ui, &mut uictx),
                Screen::ProfilePreview => self.profile_preview.show(ui, &mut uictx),
                Screen::Routing => scroll(ui, |ui| self.routing.show(ui, &mut uictx)),
                Screen::Dns => scroll(ui, |ui| self.dns.show(ui, &mut uictx)),
                Screen::Inbounds => scroll(ui, |ui| self.inbounds.show(ui, &mut uictx)),
                Screen::Tun => scroll(ui, |ui| self.tun.show(ui, &mut uictx)),
                Screen::Logs => self.logs_ui.show(ui, &mut uictx),
                Screen::Settings => scroll(ui, |ui| self.settings_ui.show(ui, &mut uictx)),
                Screen::About => scroll(ui, |ui| self.about.show(ui, &mut uictx)),
            }
            // The servers screen takes the probe-feedback slot each frame
            // (the probe outcome parked by the drain).
        });

        // First-run wizard over everything while the pinned core is missing
        // or does not match the compiled pins — the same two states the core
        // setup surface reports as not installed and update required. The
        // wizard shares the app's `dirty` flag (it never mutated settings;
        // its UiCtx was wired to a dropped local), so any
        // future wizard edit that calls `mark_dirty` reaches the persist
        // gate below instead of silently vanishing.
        if !self.core_available && !self.wizard.dismissed {
            // The wizard is an onboarding overlay over a core that cannot
            // run yet; the Onboarding view blanks stats/observatory while
            // the snapshot's phase, version, download
            // and update-check inputs ride along.
            let snapshot = &self.ui_ctx_snapshot;
            let mut uictx = UiCtx::new(
                UiCtxParts {
                    servers: &mut self.servers,
                    settings: &mut self.settings,
                    cmd: &self.rt.cmd,
                    stats_history: &self.stats_history,
                    logs: &self.logs,
                    logs_generation: self.logs.generation(),
                    probe_feedback: &mut self.probe_feedback,
                    dirty: &mut dirty,
                    ui_dirty: &mut ui_dirty,
                    model_generation: &mut self.model_generation,
                    connect_requested: &mut connect_requested,
                    stop_requested: &mut stop_requested,
                    verify_core_requested: &mut verify_core_requested,
                    open_core_folder_requested: &mut open_core_folder_requested,
                    open_core_setup_requested: &mut open_core_setup_requested,
                    connect_blocked_reason: cached_block_reason(&self.connect_block_cache),
                    config_error: &self.config_error,
                    operation,
                    is_elevated: self.is_elevated,
                    config_revision: self.config_revision,
                },
                UiCtxView::Onboarding { snapshot },
            );
            self.wizard.show(&ctx, &mut uictx);
        }

        // Hazard acknowledgment modal: rendered over everything
        // while a gated Connect/Apply awaits confirmation.
        if self.pending_safety_ack.is_some() {
            self.show_safety_ack_modal(&ctx);
        }

        // Unsaved-changes leave modal (server editor): rendered over
        // everything every frame while a leave action is staged (selection
        // switch, Add-dialog close, deferred quit) — same overlay role as
        // the safety-ack modal. A staged Quit resolved through the modal
        // (drafts saved or discarded) resumes the deferred quit from
        // `quit()`; the `quitting` guard keeps a quit already in flight
        // from re-entering.
        {
            let snapshot = &self.ui_ctx_snapshot;
            let mut uictx = UiCtx::new(
                UiCtxParts {
                    servers: &mut self.servers,
                    settings: &mut self.settings,
                    cmd: &self.rt.cmd,
                    stats_history: &self.stats_history,
                    logs: &self.logs,
                    logs_generation: self.logs.generation(),
                    probe_feedback: &mut self.probe_feedback,
                    dirty: &mut dirty,
                    ui_dirty: &mut ui_dirty,
                    model_generation: &mut self.model_generation,
                    connect_requested: &mut connect_requested,
                    stop_requested: &mut stop_requested,
                    verify_core_requested: &mut verify_core_requested,
                    open_core_folder_requested: &mut open_core_folder_requested,
                    open_core_setup_requested: &mut open_core_setup_requested,
                    connect_blocked_reason: cached_block_reason(&self.connect_block_cache),
                    config_error: &self.config_error,
                    operation,
                    is_elevated: self.is_elevated,
                    config_revision: self.config_revision,
                },
                UiCtxView::Live { snapshot },
            );
            self.servers_ui.show_leave_modal(&ctx, &mut uictx);
        }
        if quit_resume_ready(&mut self.servers_ui, self.quitting) {
            self.quit_impl(&ctx, None);
        }

        if dirty {
            self.persist_if_due(&ctx, PersistKind::Config);
        }
        if ui_dirty {
            self.persist_if_due(&ctx, PersistKind::UiOnly);
        }
        // The repaint `persist_if_due` arms at the throttle deadline exists to
        // land the last edit of a burst, and the frame it delivers carries no
        // widget change of its own — nothing above routes through the two
        // calls, so the pending kind is flushed here. Inside the window the
        // call only re-arms the repaint, so the write still happens at most
        // once per window.
        if let Some(kind) = self.persist_pending {
            self.persist_if_due(&ctx, kind);
        }
        if stop_requested {
            let _ = self.request_stop();
        } else if connect_requested {
            let _ = self.request_connect();
        }
        // Core setup requests from any mount (the startup dialog, the
        // Settings section, the terminal error block's button): the shell
        // owns the verification pass, the Explorer launch and the screen
        // switch these flags ask for.
        if verify_core_requested {
            self.verify_core();
        }
        if open_core_folder_requested
            && let Err(open_error) = sys::hidden_command("explorer")
                .arg(paths::core_dir())
                .spawn()
        {
            let lang = self.settings.language;
            self.push_log(
                false,
                t_fmt(lang, Key::LogOpenCoreFolderFailed, &[&open_error]),
            );
        }
        if open_core_setup_requested {
            self.screen = Screen::Settings;
        }

        // Exit-time action confirmations from the Settings modals: request
        // cleanup and quit through the normal path,
        // so the filesystem actions run only after `run_native` has dropped
        // the app (core stopped). Clean Up and Exit wipes the whole app-data
        // root; Reset to default… wipes everything except the server list
        // and the core.
        if self.settings_ui.take_cleanup_request() {
            self.quit_with_cleanup(&ctx);
        } else if self.settings_ui.take_reset_request() {
            self.quit_with_reset(&ctx);
        }

        // The standing 500 ms repaint timer is gone — repainting is
        // event-driven. The runtime pokes
        // the egui context once per queued event, full-batch drains keep
        // draining from `logic`, and one-shots (persist deadline, …) arm
        // their own frames. Visible-idle Running therefore settles at the
        // stats ticker's ~1 Hz. While the viewport is hidden (close-to-tray)
        // or minimized, request nothing — pokes may still arrive, but the
        // app schedules no follow-ups.
        let viewport_suppressed = self.viewport_suppressed(&ctx);
        if repaint_follow_up(&self.phase, viewport_suppressed, self.frame_drain)
            == RepaintFollowUp::NextFrame
        {
            ctx.request_repaint();
        }
    }
}

/// The generated candidate embeds a per-launch ephemeral API port
/// (bound from `127.0.0.1:0` at generation time) — in the root
/// `api` object and the api inbound's `listen` — so two generations of the
/// same state never compare equal. Strip both, the only per-launch volatile
/// bits, so candidates can be compared for config equality.
fn normalize_candidate_for_compare(mut config: serde_json::Value) -> serde_json::Value {
    if let Some(api) = config
        .get_mut(keys::API)
        .and_then(serde_json::Value::as_object_mut)
    {
        api.remove(keys::LISTEN);
    }
    if let Some(inbounds) = config
        .get_mut(keys::INBOUNDS)
        .and_then(serde_json::Value::as_array_mut)
    {
        for inbound in inbounds {
            let tag = inbound.get(keys::TAG).and_then(serde_json::Value::as_str);
            if tag == Some(API_INBOUND_TAG) {
                if let Some(object) = inbound.as_object_mut() {
                    object.remove(keys::LISTEN);
                }
                break;
            }
        }
    }
    config
}

/// The config-apply gate ("changes pending" chip) after an edit persisted:
/// up exactly when the current candidate differs from the config the running
/// core accepted (or, before any apply, the startup baseline), or when the
/// state cannot be saved. `applied_candidate` is `None` only while generation
/// fails, which keeps the gate up on every persist.
fn config_gate_after_persist(
    applied_candidate: Option<&serde_json::Value>,
    current_candidate: &serde_json::Value,
    persistence_error: Option<&str>,
) -> bool {
    persistence_error.is_some() || applied_candidate != Some(current_candidate)
}

/// While `state_error` is set the in-memory model is `Default` and writing
/// would silently destroy the intact hand-edited file; `persist_dirty`
/// refuses to save in that state.
fn persist_blocked_by_state_error(state_error: Option<&str>) -> bool {
    state_error.is_some()
}

/// Whether one apply verdict settles the configuration the app holds now: a
/// verdict names the revision its command was generated from, so only a
/// success for the revision the app holds may clear the changes-pending gate
/// and refresh the applied baseline. A success for an older revision is
/// reported with the older-apply wording instead, and a failure is reported
/// as its own message whichever revision it names.
fn apply_verdict_settles_current(ok: bool, verdict_revision: u64, config_revision: u64) -> bool {
    ok && verdict_revision == config_revision
}

/// A phase change ends the core session: the last stats tick (rates, memory,
/// session totals) must not masquerade as live state. When a tick exists the
/// generation bump forces the dashboard's stats caches to rebuild empty; a
/// phase change with no tick (boot, duplicate events) has nothing to
/// invalidate and leaves the generation untouched so idle purity holds.
/// Tested directly — `BroccoliApp` is not constructible in tests
/// (totals vanish on phase change).
fn invalidate_session_stats(stats: &mut Option<StatsTick>, stats_generation: &mut u64) {
    if stats.take().is_some() {
        *stats_generation = stats_generation.wrapping_add(1);
    }
}

/// TUN outbound-interface availability guard for the commit paths. With TUN
/// active and a FIXED (non-empty, non-"auto") interface name, Xray binds
/// EVERY dial — the outbound chain and the system-resolver
/// bootstrap DNS (`localdns` runs the same registered controllers) — to
/// that interface's index; a down (or vanished) adapter still binds, and
/// every socket then fails with an unreachable-host error, a total outage
/// with routing rules looking fine. `auto`/empty never bind a stale index,
/// and nothing binds while TUN is off. The name verdict itself lives in
/// [`sys::netif::fixed_name_verdict`]; this renders it with the localized
/// keys.
fn tun_outbound_interface_block_reason(
    lang: Language,
    mode: Mode,
    setting: &str,
    ifaces: &[sys::netif::NetIf],
) -> Option<String> {
    if mode != Mode::Tun {
        return None;
    }
    match sys::netif::fixed_name_verdict(setting, ifaces) {
        sys::netif::FixedNameVerdict::Unpinned | sys::netif::FixedNameVerdict::Up => None,
        sys::netif::FixedNameVerdict::Down { name } => {
            Some(t_fmt(lang, Key::TunAutoOutboundsDown, &[&name]))
        }
        sys::netif::FixedNameVerdict::Missing { name } => {
            Some(t_fmt(lang, Key::TunAutoOutboundsMissing, &[&name]))
        }
    }
}

fn generate_runtime_candidate(
    servers: &ServersFile,
    settings: &Settings,
    lang: Language,
) -> Result<serde_json::Value, String> {
    let config = r#gen::generate(servers, settings).map_err(|error| {
        // Generation errors can echo user-editable content
        // (raw-override text, model fields) into every surface that shows
        // this message — the startup baseline and edit-time config chips,
        // `record_generation_failure` (apply result + log), and the
        // raw-override verdict — so the error text is excerpted at the
        // shared 48-char bound here, before it can reach a UI label or the
        // rotating log.
        t_fmt(lang, Key::GenerationFailed, &[&excerpt(&error.text(lang))])
    })?;
    validate_raw_override_candidate(settings, &config, lang)?;
    Ok(config)
}

/// Which commit path a pending hazard acknowledgment belongs to; the
/// dialog's confirm button resumes exactly that flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingApplyOrigin {
    Connect,
    ApplyNow,
}

/// The safety-hazard gate shared by every commit path: `Some`
/// with the findings when the apply must wait for explicit acknowledgment,
/// `None` when it may proceed. The whole-config raw override stays
/// unrestricted — it never triggers the gate.
fn hazard_gate_findings(servers: &ServersFile, settings: &Settings) -> Option<Vec<SafetyFinding>> {
    if settings.raw_override.is_some() {
        return None;
    }
    let findings = crate::model::safety::assess(servers, settings);
    (!findings.is_empty()).then_some(findings)
}

/// Render the hazard-acknowledgment modal: every finding's
/// path, hazard-class label, and rendered message, with exactly two
/// actions — Apply anyway resumes the gated apply, Cancel aborts it.
/// Free-standing over callbacks so unit tests can drive it without a full
/// app (the Settings Cleanup modal's `egui::Modal` pattern).
fn show_safety_ack_modal(
    ctx: &egui::Context,
    lang: Language,
    findings: &[SafetyFinding],
    mut on_decision: impl FnMut(bool),
) {
    egui::Modal::new(egui::Id::new("broccoli-safety-ack")).show(ctx, |ui| {
        ui.set_max_width(560.0);
        ui.heading(t(lang, Key::SafetyAckTitle));
        ui.add_space(4.0);
        ui.add(
            egui::Label::new(egui::RichText::new(t(lang, Key::SafetyAckExplanation)).weak()).wrap(),
        );
        ui.add_space(10.0);
        for finding in findings {
            ui.horizontal_wrapped(|ui| {
                ui.strong(&finding.path);
                ui.label(crate::i18n::hazard_class_label(finding.class.clone(), lang));
            });
            ui.add(egui::Label::new(crate::i18n::safety_finding_message(finding, lang)).wrap());
            ui.add_space(6.0);
        }
        ui.add_space(6.0);
        ui.separator();
        if ui.button(t(lang, Key::SafetyAckApplyAnyway)).clicked() {
            on_decision(true);
        }
        ui.add_space(4.0);
        if ui.button(t(lang, Key::Cancel)).clicked() {
            on_decision(false);
        }
    });
}

/// The index of the first raw-override outbound that carries a non-null
/// retired `proxySettings` value, when one does. Xray's outbound build
/// refuses a configuration that carries it (infra/conf/xray.go:262), so the
/// override must be refused with the same finding the profile model produces
/// — it can never reach the core. Every case variant counts (Go binds the
/// name case-insensitively) and the value's shape is never inspected, but
/// JSON `null` is Go's nil pointer and stays legal; a non-array `outbounds`
/// (or a non-object entry) simply carries no outbound to check. The index is
/// 0-based: it addresses the JSON array the user pasted.
fn raw_override_retired_proxy_settings(config: &serde_json::Value) -> Option<usize> {
    config
        .get(keys::OUTBOUNDS)?
        .as_array()?
        .iter()
        .position(|outbound| {
            outbound.as_object().is_some_and(|outbound| {
                outbound.iter().any(|(key, value)| {
                    key.eq_ignore_ascii_case("proxySettings") && !value.is_null()
                })
            })
        })
}

/// One field of a JSON object, matched the way Go binds names: exactly or
/// ASCII-case-insensitively.
fn json_field<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<&'a serde_json::Value> {
    object
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
        .map(|(_, value)| value)
}

/// The path of the first raw-override outbound that carries a non-null
/// retired `finalmask.quicParams.udpHop` value, when one does. The pinned
/// core ignores the key silently (`infra/conf/transport_finalmask.go:88`),
/// so the override must be refused with the same finding the profile model
/// produces — the hop would otherwise die without a message. Every name on
/// the path counts case-insensitively (Go binds them that way), JSON `null`
/// is Go's zero value and stays legal, and a non-array `outbounds` (or a
/// non-object entry) simply carries no outbound to check. The index is
/// 0-based: it addresses the JSON array the user pasted.
fn raw_override_retired_udp_hop(config: &serde_json::Value) -> Option<String> {
    config
        .get(keys::OUTBOUNDS)?
        .as_array()?
        .iter()
        .enumerate()
        .find_map(|(index, outbound)| {
            let outbound = outbound.as_object()?;
            let stream = json_field(outbound, keys::STREAM_SETTINGS)?.as_object()?;
            let finalmask = json_field(stream, "finalmask")?.as_object()?;
            let quic_params = json_field(finalmask, "quicParams")?.as_object()?;
            quic_params
                .iter()
                .any(|(key, value)| key.eq_ignore_ascii_case("udpHop") && !value.is_null())
                .then(|| format!("outbounds[{index}].streamSettings.finalmask.quicParams.udpHop"))
        })
}

/// Raw Override bypasses every typed listener guarantee. Keep it in direct
/// child mode and prove the exact control plane the runtime will poll before
/// any candidate is sent.
fn validate_raw_override_candidate(
    settings: &Settings,
    config: &serde_json::Value,
    lang: Language,
) -> Result<(), String> {
    if settings.raw_override.is_none() {
        return Ok(());
    }
    // The retired keys are the only things the override may not carry: the
    // pinned core fails the whole config build on `proxySettings`
    // (infra/conf/xray.go:262) and ignores `finalmask.quicParams.udpHop`
    // silently, and the profile model reports the same findings under the
    // same codes, so each message is rendered once.
    if let Some(index) = raw_override_retired_proxy_settings(config) {
        let issue = crate::model::validation::ValidationIssue {
            code: crate::model::validation::ValidationCode::OutboundProxySettingsRemoved,
            path: Some(format!("outbounds[{index}]")),
            severity: crate::model::validation::Severity::Error,
        };
        return Err(crate::i18n::validation_issue_message(&issue, lang));
    }
    if let Some(path) = raw_override_retired_udp_hop(config) {
        let issue = crate::model::validation::ValidationIssue {
            code: crate::model::validation::ValidationCode::FinalmaskQuicHopMoved,
            path: Some(path),
            severity: crate::model::validation::Severity::Error,
        };
        return Err(crate::i18n::validation_issue_message(&issue, lang));
    }
    if settings.mode != crate::model::Mode::Off {
        return Err(t(lang, Key::RawOverrideOffMode).into());
    }
    // The control-plane port is ephemeral and derived from the
    // emitted config, never from Settings. The raw override must still define
    // a loopback api.listen with StatsService so the runtime can verify the
    // listener's owning PID before trusting readiness.
    let api = config
        .get(keys::API)
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| t(lang, Key::RawOverrideDefineApi))?;
    let listen = api
        .get(keys::LISTEN)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| t(lang, Key::RawOverrideDefineApi))?;
    let address: std::net::SocketAddr = listen
        .parse()
        .map_err(|_| t(lang, Key::RawOverrideDefineApi))?;
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err(t(lang, Key::RawOverrideDefineApi).into());
    }
    let has_stats = api
        .get(keys::SERVICES)
        .and_then(serde_json::Value::as_array)
        .is_some_and(|services| {
            services.iter().any(|service| {
                service
                    .as_str()
                    .is_some_and(|service| service.eq_ignore_ascii_case("StatsService"))
            })
        });
    if !has_stats {
        return Err(t(lang, Key::RawOverrideStatsService).into());
    }
    if config
        .get(keys::INBOUNDS)
        .and_then(serde_json::Value::as_array)
        .is_some_and(|inbounds| {
            inbounds.iter().any(|inbound| {
                inbound
                    .get(keys::PROTOCOL)
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|protocol| protocol.eq_ignore_ascii_case("tun"))
            })
        })
    {
        return Err(t(lang, Key::RawOverrideNoTun).into());
    }
    Ok(())
}

#[cfg(test)]
mod safety_tests {
    use super::{Language, excerpt, generate_runtime_candidate, validate_raw_override_candidate};
    use crate::i18n::{Key, t, t_fmt};
    use crate::model::{Mode, OutboundModel, Protocol, ServerProfile, ServersFile, Settings};
    use crate::rt::OutboundStatusView;
    use crate::ui::PhaseAction;
    use serde_json::json;

    #[test]
    fn event_drain_limit_preserves_following_work() {
        assert!(!super::event_batch_exhausted(super::EVENT_DRAIN_LIMIT - 1));
        assert!(super::event_batch_exhausted(super::EVENT_DRAIN_LIMIT));

        let (tx, rx) = std::sync::mpsc::channel();
        for _ in 0..=super::EVENT_DRAIN_LIMIT {
            tx.send(crate::rt::CoreEvt::Operation(None))
                .expect("queue runtime event");
        }

        let mut drained = 0;
        for _ in 0..super::EVENT_DRAIN_LIMIT {
            if rx.try_recv().is_ok() {
                drained += 1;
            }
        }
        assert_eq!(drained, super::EVENT_DRAIN_LIMIT);
        assert!(
            rx.try_recv().is_ok(),
            "the next frame must retain queued work"
        );
    }

    #[test]
    fn observatory_snapshot_updates_dashboard_and_profile_badges() {
        let mut profile = ServerProfile::new("snapshot", OutboundModel::new(Protocol::Freedom));
        profile.id = "0123456789abcdef".into();
        let tag = profile.tag();
        let mut servers = ServersFile {
            profiles: vec![profile],
            ..Default::default()
        };
        let status = OutboundStatusView {
            health_ping: None,
            tag,
            alive: true,
            delay_ms: 23,
            last_error: None,
            diagnostics: None,
        };
        let mut dashboard = vec![OutboundStatusView {
            health_ping: None,
            tag: "stale".into(),
            alive: false,
            delay_ms: 0,
            last_error: Some("stale".into()),
            diagnostics: None,
        }];

        super::BroccoliApp::replace_observatory_snapshot(
            &mut servers,
            &mut dashboard,
            vec![status.clone()],
        );

        assert_eq!(dashboard, [status]);
        assert_eq!(servers.profiles[0].latency_ms, Some(23));
    }

    #[test]
    fn observatory_statuses_update_only_their_matching_profiles() {
        let mut first = ServerProfile::new("first", OutboundModel::new(Protocol::Freedom));
        first.id = "1111111111111111".into();
        let mut second = ServerProfile::new("second", OutboundModel::new(Protocol::Freedom));
        second.id = "2222222222222222".into();
        let mut third = ServerProfile::new("third", OutboundModel::new(Protocol::Freedom));
        third.id = "3333333333333333".into();
        let mut servers = ServersFile {
            profiles: vec![first, second, third],
            ..Default::default()
        };
        let (first_tag, second_tag) = (servers.profiles[0].tag(), servers.profiles[1].tag());
        assert_ne!(first_tag, second_tag, "the fixture needs distinct tags");
        let status = |tag: &str, alive: bool, delay_ms: i64| OutboundStatusView {
            health_ping: None,
            tag: tag.to_owned(),
            alive,
            delay_ms,
            last_error: None,
            diagnostics: None,
        };

        super::BroccoliApp::apply_observatory_statuses(
            &mut servers,
            &[
                status(&first_tag, true, 12),
                status(&second_tag, false, 99),
                status("srv-abcdef12", true, 1),
            ],
        );

        assert_eq!(servers.profiles[0].latency_ms, Some(12));
        assert_eq!(
            servers.profiles[1].latency_ms,
            Some(-1),
            "a dead status records the -1 verdict, never its delay"
        );
        assert_eq!(
            servers.profiles[2].latency_ms, None,
            "a status for another tag must leave this profile untouched"
        );
    }

    #[test]
    fn tray_connect_presentation_tracks_label_and_block_state() {
        // The presentation must change exactly when the tray
        // connect item's text or enabled state would change, so
        // `sync_tray_action`'s gate skips both muda calls (`set_text`
        // allocates and issues `SetMenuItemInfoW` per parent menu) on idle
        // frames.
        let connect = super::tray_connect_presentation(PhaseAction::Connect, Language::En, false);
        assert_eq!(connect.label, t(Language::En, Key::PhaseConnect));
        assert!(connect.enabled, "an unblocked Connect must stay enabled");
        let blocked = super::tray_connect_presentation(PhaseAction::Connect, Language::En, true);
        assert_eq!(
            blocked.label, connect.label,
            "the label depends only on phase+language"
        );
        assert!(
            !blocked.enabled,
            "a blocked Connect must disable the tray item"
        );
        let disconnect =
            super::tray_connect_presentation(PhaseAction::Disconnect, Language::En, true);
        assert_eq!(disconnect.label, t(Language::En, Key::PhaseDisconnect));
        assert!(
            disconnect.enabled,
            "Disconnect/CancelRetry are never block-disabled"
        );
    }

    fn assert_tray_event(
        menu: &super::TrayMenu,
        tray_id: Option<tray_icon::TrayIconId>,
        dispatch: impl FnOnce(),
        expected: Option<super::TrayAction>,
    ) {
        use std::sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        };

        let ctx = egui::Context::default();
        let (registration_id, action_rx) = super::install_tray_event_target(&ctx, tray_id, menu);
        let action_rx = Arc::new(Mutex::new(action_rx));
        let observed = Arc::new(Mutex::new(Vec::new()));
        let wake_count = Arc::new(AtomicUsize::new(0));
        ctx.set_request_repaint_callback({
            let action_rx = Arc::clone(&action_rx);
            let observed = Arc::clone(&observed);
            let wake_count = Arc::clone(&wake_count);
            move |_| {
                wake_count.fetch_add(1, Ordering::SeqCst);
                let action_rx = action_rx.lock().expect("action receiver lock");
                let mut observed = observed.lock().expect("observed action lock");
                while let Ok(action) = action_rx.try_recv() {
                    observed.push(action);
                }
            }
        });

        dispatch();

        let should_wake = expected.is_some();
        assert_eq!(
            *observed.lock().expect("observed action lock"),
            expected.into_iter().collect::<Vec<_>>()
        );
        if should_wake {
            assert!(
                wake_count.load(Ordering::SeqCst) > 0,
                "an owned tray event must wake eframe"
            );
        } else {
            assert_eq!(
                wake_count.load(Ordering::SeqCst),
                0,
                "an unrelated tray event must not wake eframe"
            );
        }
        super::clear_tray_event_target(registration_id);
    }

    #[test]
    fn tray_event_target_routes_owned_actions_and_wakes_eframe() {
        use tray_icon::{
            MouseButton, MouseButtonState, Rect, TrayIconEvent, TrayIconId,
            dpi::PhysicalPosition,
            menu::{MenuEvent, MenuId, MenuItem},
        };

        let menu = super::TrayMenu {
            show: MenuItem::with_id("broccoli-test-show", "Show", true, None),
            connect: MenuItem::with_id("broccoli-test-connect", "Connect", true, None),
            quit: MenuItem::with_id("broccoli-test-quit", "Quit", true, None),
        };
        let tray_id = TrayIconId::new("broccoli-test-tray");
        let click = |id: TrayIconId, button: MouseButton, button_state: MouseButtonState| {
            TrayIconEvent::Click {
                id,
                position: PhysicalPosition::new(0.0, 0.0),
                rect: Rect::default(),
                button,
                button_state,
            }
        };

        assert_tray_event(
            &menu,
            Some(tray_id.clone()),
            || {
                super::dispatch_tray_icon_event(click(
                    tray_id.clone(),
                    MouseButton::Left,
                    MouseButtonState::Down,
                ))
            },
            Some(super::TrayAction::Show),
        );
        assert_tray_event(
            &menu,
            Some(tray_id.clone()),
            || {
                super::dispatch_menu_event(MenuEvent {
                    id: menu.show.id().clone(),
                })
            },
            Some(super::TrayAction::Show),
        );
        assert_tray_event(
            &menu,
            Some(tray_id.clone()),
            || {
                super::dispatch_menu_event(MenuEvent {
                    id: menu.connect.id().clone(),
                })
            },
            Some(super::TrayAction::ToggleConnection),
        );
        assert_tray_event(
            &menu,
            Some(tray_id.clone()),
            || {
                super::dispatch_menu_event(MenuEvent {
                    id: menu.quit.id().clone(),
                })
            },
            Some(super::TrayAction::Quit),
        );

        assert_tray_event(
            &menu,
            Some(tray_id.clone()),
            || {
                super::dispatch_tray_icon_event(click(
                    TrayIconId::new("foreign-tray"),
                    MouseButton::Left,
                    MouseButtonState::Down,
                ))
            },
            None,
        );
        assert_tray_event(
            &menu,
            Some(tray_id.clone()),
            || {
                super::dispatch_tray_icon_event(click(
                    tray_id.clone(),
                    MouseButton::Left,
                    MouseButtonState::Up,
                ))
            },
            None,
        );
        assert_tray_event(
            &menu,
            Some(tray_id.clone()),
            || {
                super::dispatch_tray_icon_event(click(
                    tray_id.clone(),
                    MouseButton::Right,
                    MouseButtonState::Down,
                ))
            },
            None,
        );
        assert_tray_event(
            &menu,
            Some(tray_id),
            || {
                super::dispatch_menu_event(MenuEvent {
                    id: MenuId::new("broccoli-test-unknown"),
                })
            },
            None,
        );
    }

    #[test]
    fn raw_override_requires_off_mode_and_loopback_stats_control_plane() {
        let mut settings = Settings {
            raw_override: Some("{}".into()),
            ..Default::default()
        };
        let valid = json!({
            "api": {
                "tag": "api",
                "listen": "127.0.0.1:10853",
                "services": ["ReflectionService", "StatsService"]
            }
        });
        assert!(validate_raw_override_candidate(&settings, &valid, Language::En).is_ok());

        settings.set_mode(Mode::Tun);
        assert!(
            validate_raw_override_candidate(&settings, &valid, Language::En)
                .unwrap_err()
                .contains("only in Off mode")
        );
        settings.set_mode(Mode::Off);

        let mut wrong_listen = valid.clone();
        wrong_listen["api"]["listen"] = json!("0.0.0.0:10853");
        assert!(
            validate_raw_override_candidate(&settings, &wrong_listen, Language::En)
                .unwrap_err()
                .contains("loopback")
        );

        let mut missing_stats = valid;
        missing_stats["api"]["services"] = json!(["ReflectionService"]);
        assert!(
            validate_raw_override_candidate(&settings, &missing_stats, Language::En)
                .unwrap_err()
                .contains("StatsService")
        );
    }

    #[test]
    fn raw_override_carrying_the_retired_key_never_reaches_the_core() {
        // Story: the raw override stays unrestricted for everything except
        // the retired `proxySettings` key. Any case variant and any shape is
        // refused with the same finding the profile model produces, before
        // the candidate can be written or applied.
        let settings = Settings {
            raw_override: Some("{}".into()),
            ..Default::default()
        };
        let mut config = json!({
            "api": {"tag": "api", "listen": "127.0.0.1:10853", "services": ["StatsService"]},
            "outbounds": [{"protocol": "freedom", "tag": "direct"}]
        });
        for (key, value) in [
            ("proxySettings", json!({"tag": "srv-y"})),
            ("ProxySettings", json!("srv-y")),
            ("proxysettings", json!(7)),
        ] {
            let mut outbound = serde_json::Map::new();
            outbound.insert("protocol".into(), json!("vless"));
            outbound.insert("tag".into(), json!("srv-x"));
            outbound.insert(key.into(), value.clone());
            config["outbounds"] = json!([{"protocol": "freedom", "tag": "direct"}, outbound]);

            let message =
                validate_raw_override_candidate(&settings, &config, Language::En).unwrap_err();
            assert!(
                message.contains("outbounds[1]"),
                "the finding must address the pasted array 0-based ({key} = {value}): {message}"
            );
            assert!(
                message.contains("proxySettings"),
                "{key} = {value}: {message}"
            );
            assert!(
                message.contains("streamSettings.sockopt.dialerProxy"),
                "{key} = {value}: {message}"
            );

            // The same refusal gates the whole candidate path: `generate`
            // returns an override verbatim, so this check is all that stands
            // between the text and the core.
            let mut overridden = settings.clone();
            overridden.raw_override = Some(config.to_string());
            let message =
                generate_runtime_candidate(&ServersFile::default(), &overridden, Language::En)
                    .expect_err("the retired key must gate the candidate");
            assert!(
                message.contains("streamSettings.sockopt.dialerProxy"),
                "{key} = {value}: {message}"
            );
        }

        // JSON `null` is Go's nil pointer: the pinned core accepts it, so the
        // override passes this rule, and a clean override passes too.
        for null_key in ["proxySettings", "ProxySettings", "proxysettings"] {
            let mut outbound = serde_json::Map::new();
            outbound.insert("protocol".into(), json!("vless"));
            outbound.insert("tag".into(), json!("srv-x"));
            outbound.insert(null_key.into(), json!(null));
            config["outbounds"] = json!([{"protocol": "freedom", "tag": "direct"}, outbound]);
            assert!(
                validate_raw_override_candidate(&settings, &config, Language::En).is_ok(),
                "{null_key}: null must pass"
            );
        }
        config["outbounds"] = json!([{"protocol": "freedom", "tag": "direct"}]);
        assert!(validate_raw_override_candidate(&settings, &config, Language::En).is_ok());
    }

    #[test]
    fn raw_override_carrying_the_retired_udp_hop_key_never_reaches_the_core() {
        // Story: the raw override stays unrestricted for everything except
        // the two retired keys. The hop key would be ignored by the pinned
        // core silently, so the override is refused with the same finding the
        // profile model produces, before the candidate can be written or
        // applied.
        let settings = Settings {
            raw_override: Some("{}".into()),
            ..Default::default()
        };
        let mut config = json!({
            "api": {"tag": "api", "listen": "127.0.0.1:10853", "services": ["StatsService"]},
            "outbounds": [
                {"protocol": "freedom", "tag": "direct"},
                {"protocol": "vless", "tag": "srv-x", "streamSettings": {"finalmask": {
                    "quicParams": {"congestion": "bbr", "udpHop": {"ports": "443"}}
                }}}
            ]
        });
        let message =
            validate_raw_override_candidate(&settings, &config, Language::En).unwrap_err();
        assert!(
            message.contains("outbounds[1].streamSettings.finalmask.quicParams.udpHop"),
            "the finding must address the pasted array 0-based: {message}"
        );
        assert!(message.contains("udphop UDP mask"), "{message}");
        assert!(
            message.contains("intervalLocal") && message.contains("intervalRemote"),
            "the fix-it text must state the equivalence: {message}"
        );

        // Every name on the path counts case-insensitively, and any non-null
        // shape refuses.
        for (wrapper, value) in [
            (
                "StreamSettings",
                json!({"finalmask": {"quicParams": {"UDPHOP": "hop"}}}),
            ),
            (
                "streamSettings",
                json!({"Finalmask": {"QuicParams": {"Udphop": 7}}}),
            ),
            (
                "streamSettings",
                json!({"finalmask": {"quicParams": {"udphop": true}}}),
            ),
            (
                "streamSettings",
                json!({"finalmask": {"quicParams": {"udpHop": ["hop"]}}}),
            ),
        ] {
            let mut config = config.clone();
            config["outbounds"] = json!([
                {"protocol": "freedom", "tag": "direct"},
                {"protocol": "vless", "tag": "srv-x", wrapper: value}
            ]);
            assert!(
                validate_raw_override_candidate(&settings, &config, Language::En).is_err(),
                "{wrapper}: {value} must refuse"
            );
        }

        // JSON `null` is Go's zero value: the core accepts it, so the
        // override passes this rule; a clean override passes too.
        config["outbounds"] = json!([
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "vless", "tag": "srv-x", "streamSettings": {"finalmask": {
                "quicParams": {"udpHop": null}
            }}}
        ]);
        assert!(
            validate_raw_override_candidate(&settings, &config, Language::En).is_ok(),
            "null must pass"
        );

        // The same refusal gates the whole candidate path: `generate` returns
        // an override verbatim, so this check is all that stands between the
        // text and the core.
        config["outbounds"] = json!([
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "vless", "tag": "srv-x", "streamSettings": {"finalmask": {
                "quicParams": {"udpHop": {"ports": "443", "interval": "5-10"}}
            }}}
        ]);
        let mut overridden = settings.clone();
        overridden.raw_override = Some(config.to_string());
        assert!(
            generate_runtime_candidate(&ServersFile::default(), &overridden, Language::En).is_err(),
            "the retired hop key must gate the candidate"
        );
    }

    #[test]
    fn raw_override_rejects_top_level_tun_inbound_even_in_off_mode() {
        let settings = Settings {
            raw_override: Some("{}".into()),
            ..Default::default()
        };
        let candidate = json!({
            "api": {
                "listen": "127.0.0.1:10853",
                "services": ["StatsService"]
            },
            "inbounds": [{ "protocol": "tun", "settings": {} }]
        });
        assert!(
            validate_raw_override_candidate(&settings, &candidate, Language::En)
                .unwrap_err()
                .contains("may not define a TUN inbound")
        );

        let direct_only = json!({
            "api": {
                "listen": "127.0.0.1:10853",
                "services": ["StatsService"]
            },
            "inbounds": [{ "protocol": "socks", "listen": "127.0.0.1", "port": 10808 }]
        });
        assert!(validate_raw_override_candidate(&settings, &direct_only, Language::En).is_ok());
    }

    #[test]
    fn raw_override_generation_failure_text_is_bounded_before_ui_or_log() {
        // The raw-override echo text shared by every
        // surface — the connect-block verdict, the startup/edit-time
        // config-error chips, `record_generation_failure`'s apply result and
        // log line — is built by `generate_runtime_candidate`. A hostile
        // multi-MB raw override must yield byte-bounded message text: the
        // GenerationFailed template around the shared 48-char excerpt of the
        // raw gen error (same helper, no duplicated constant), never the
        // buffer content itself.
        let hostile = "x".repeat(4 << 20);
        let settings = Settings {
            raw_override: Some(format!(r#"{{"a": "{hostile}""#)), // unterminated string
            ..Default::default()
        };
        let error = generate_runtime_candidate(&ServersFile::default(), &settings, Language::En)
            .expect_err("hostile raw override must fail generation");
        // Exact shape: template + excerpt of the raw generation error text
        // (recovered by generating without the shared boundary).
        let raw_gen_error = crate::r#gen::generate(&ServersFile::default(), &settings)
            .expect_err("the hostile raw override must fail a direct generate");
        let expected = t_fmt(
            Language::En,
            Key::GenerationFailed,
            &[&excerpt(&raw_gen_error.text(Language::En))],
        );
        assert_eq!(
            error, expected,
            "generation failure must be template + bounded excerpt"
        );
        // The template code and the cause code survive…
        assert!(
            error.starts_with(t_fmt(Language::En, Key::GenerationFailed, &[&""]).as_str()),
            "must keep the generation-failed code: {error}"
        );
        assert!(
            error.contains(&excerpt(&raw_gen_error.text(Language::En))),
            "must keep the bounded cause text: {error}"
        );
        // …the raw-override content never echoes, and the composed text is
        // byte-bounded (far below any echoed-token size).
        assert!(
            !error.contains(&"x".repeat(64)),
            "raw-override content beyond the excerpt must never echo"
        );
        assert!(
            error.len() < 1024,
            "generation failure text must stay byte-bounded, got {} bytes",
            error.len()
        );
    }

    #[test]
    fn phase_change_clears_session_stats_and_bumps_the_generation() {
        // Totals (and rates/memory) are session facts — a phase
        // change must drop the last tick and invalidate the dashboard's
        // stats caches so stale figures never masquerade as live state.
        let mut stats = Some(crate::rt::StatsTick {
            up: 100,
            down: 200,
            ..Default::default()
        });
        let mut generation = 7;
        super::invalidate_session_stats(&mut stats, &mut generation);
        assert!(stats.is_none());
        assert_eq!(generation, 8);
        // Nothing left to invalidate: a phase change without a tick (boot,
        // duplicate events) must not bump the generation — the idle-frame
        // purity contract depends on it.
        super::invalidate_session_stats(&mut stats, &mut generation);
        assert_eq!(generation, 8);
    }

    #[test]
    fn persist_is_blocked_while_state_error_is_set() {
        // While a state file failed semantic load the
        // in-memory model is defaults; persisting would silently overwrite
        // the intact hand-edited file. The guard used by `persist_dirty`
        // must refuse exactly when `state_error` is present.
        assert!(super::persist_blocked_by_state_error(Some(
            "settings.json: security: unknown value"
        )));
        assert!(super::persist_blocked_by_state_error(Some("")));
        assert!(!super::persist_blocked_by_state_error(None));
    }
}

fn scroll(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    egui::ScrollArea::vertical()
        .auto_shrink([false, true])
        .show(ui, add);
}

/// The terminal message the content area renders: the failure's keyed
/// message with the captured core output behind it. The shell records it with
/// the phase it describes and drops it when that phase moves on or an action
/// succeeds.
///
/// The message is rendered once per `(message, language)` pair — at record
/// time and again only when the active language moves — and the UI-context
/// view carries that text, so neither the content-area block nor the status
/// chip re-formats anything per frame.
struct TerminalError {
    /// The keyed message, kept for the language-change re-render.
    message: AppMessage,
    /// Captured core output (core stdout/stderr lines); empty when the
    /// failure is app-authored.
    output: String,
    /// The rendered message text and the language it was rendered in.
    text: String,
    language: Language,
}

impl TerminalError {
    /// Record one failure, rendering its message for `language` once: the
    /// rendered text and the language it was rendered in are the memo
    /// [`Self::render_in`] re-renders against.
    fn new(message: impl Into<AppMessage>, output: String, language: Language) -> Self {
        let message = message.into();
        Self {
            text: message.text(language),
            message,
            output,
            language,
        }
    }

    /// Re-render the message when the active language moved. True when the
    /// text changed, so the caller can mark the UI-context snapshot dirty;
    /// false on every other frame — and that false, with the text
    /// allocation it retains, is what the test pins.
    fn render_in(&mut self, language: Language) -> bool {
        if self.language == language {
            return false;
        }
        self.text = self.message.text(language);
        self.language = language;
        true
    }

    /// The message as the UI context carries it: rendered text, borrowed by
    /// the block and the chip.
    fn view(&self) -> ui::TerminalErrorView {
        ui::TerminalErrorView {
            text: self.text.clone(),
            output: self.output.clone(),
        }
    }
}

/// Project one verification pass into the shell's cached core facts: the
/// verified version — absent unless the tree matched the compiled pins — and
/// the core setup surface's installed-version/verification-reason pair.
fn core_facts(presence: sys::core_dl::CorePresence) -> (Option<String>, ui::CoreSetupState) {
    match presence {
        sys::core_dl::CorePresence::Verified { version } => {
            (Some(version), ui::CoreSetupState::default())
        }
        sys::core_dl::CorePresence::Unverified { installed, failure } => (
            None,
            ui::CoreSetupState {
                installed_version: installed,
                verification_error: Some(AppMessage::Error(failure)),
            },
        ),
        sys::core_dl::CorePresence::Missing => (None, ui::CoreSetupState::default()),
    }
}

/// Whether the geo data pin compare is suspended for this configuration — the
/// same predicate every verification site derives. The strict entry's drift
/// heal must not run while the managed DATs may be user-managed: the
/// committed config's geodata block is the same predicate every execution
/// path applies (a raw override can carry its own geodata block), and the
/// settings predicate covers the window before that config is first written.
fn dat_pins_suspended(settings: &Settings) -> bool {
    sys::core_dl::dat_pins_suspended_at(&crate::rt::apply::active_path())
        || settings.geodata.is_configured()
}

/// Memoized connect-block/apply-block chip texts for the shell's top bar:
/// while any blocking state is set — persistence/config
/// error, in-flight operation, raw-override verdict, missing core — the
/// reason text used to be re-formatted (`t_fmt`/`clone`) on every frame
/// the shell painted. The texts are pure functions of the keyed inputs, so
/// they are rebuilt only when an input moves, never on repaint frames (the
/// caption-memo staleness pattern; the compare below is
/// allocation-free — the `Option<String>` fields compare by value).
struct ConnectBlockCache {
    lang: Language,
    persistence_error: Option<String>,
    config_error: Option<String>,
    operation: Option<HeldOperation>,
    mode: Mode,
    raw_override: Option<String>,
    config_revision: u64,
    /// Connect-block reason for the current key (`None` = Connect enabled).
    reason: Option<String>,
    /// "operation in progress" caption for the Apply-now chip, memoized per
    /// operation change (`None` while no operation runs).
    operation_caption: Option<String>,
}

/// Borrow the Apply-now block reason for the dirty-config chip: the first of
/// the persistence error, the config error, or the memoized
/// in-flight-operation caption — all borrowed, so a painted frame with a
/// pending apply allocates nothing. Free over the fields (not a `&self`
/// method) so a frame can hold these borrows beside `&mut` shell fields.
fn apply_block_text<'a>(
    persistence_error: &'a Option<String>,
    config_error: &'a Option<String>,
    connect_block_cache: &'a Option<ConnectBlockCache>,
) -> Option<&'a str> {
    persistence_error
        .as_deref()
        .or(config_error.as_deref())
        .or_else(|| {
            connect_block_cache
                .as_ref()
                .and_then(|cache| cache.operation_caption.as_deref())
        })
}

/// `None` fallback for [`cached_block_reason`] before the first refresh.
static NO_CONNECT_BLOCK: Option<String> = None;

/// Project the memoized connect-block reason out of the cache. A free
/// function over the field (not a `&self` method): the frame's `UiCtxParts`
/// literals borrow it side by side with `&mut` model borrows, which only
/// compile while the borrow stays field-disjoint.
fn cached_block_reason(cache: &Option<ConnectBlockCache>) -> &Option<String> {
    cache
        .as_ref()
        .map(|cache| &cache.reason)
        .unwrap_or(&NO_CONNECT_BLOCK)
}

/// Resolve whether native Windows chrome/menus should render dark for the
/// given egui theme preference and OS dark-mode state. Pure and exhaustive —
/// unit-tested in [`tests`]. `System` follows the OS; `Dark`/`Light` override
/// it regardless of the OS.
fn native_dark_for(preference: egui::ThemePreference, system_dark: bool) -> bool {
    match preference {
        egui::ThemePreference::Dark => true,
        egui::ThemePreference::Light => false,
        egui::ThemePreference::System => system_dark,
    }
}

/// Native-theme state last applied to Windows surfaces, so `logic` can skip
/// re-applying while nothing observable changed (theme, main window HWND, or
/// tray window HWND).
#[cfg(windows)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct AppliedNativeTheme {
    dark: bool,
    main_hwnd: Option<HWND>,
    tray_hwnd: Option<HWND>,
}

/// Windows-native dark-mode opt-in for the tray icon popup menu.
///
/// muda 0.19.3 only themes menu *bars* (`platform_impl/windows/dark_menu_bar.rs`,
/// a port of win32-darkmode) and tray-icon 0.24.2 performs no dark-mode work
/// at all — its `TrayIcon::window_handle()` only exposes the hidden tray
/// window. The tray menu is shown with `TrackPopupMenu`
/// (`muda/src/platform_impl/windows/mod.rs::show_context_menu`), and standard
/// popup rendering follows the process-wide *preferred app mode* set through
/// the undocumented uxtheme `SetPreferredAppMode` (ordinal 135) — that is the
/// layer believed to drive popup colors. `DwmSetWindowAttribute(
/// DWMWA_USE_IMMERSIVE_DARK_MODE)` is additionally applied to the reachable
/// windows for window chrome; whether popup rendering also follows the
/// owner-window DWM flag is not guaranteed by any vendored source, so the
/// visual result must be verified manually.
#[cfg(windows)]
mod native_theme {
    use std::sync::LazyLock;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Graphics::Dwm::{DWMWA_USE_IMMERSIVE_DARK_MODE, DwmSetWindowAttribute};
    use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
    use windows::core::PCSTR;

    /// `PreferredAppMode` values (uxtheme, undocumented, build >= 18362).
    /// `AllowDark` (1) only opts in and still follows the system mode; the
    /// resolver's forced Dark/Light needs `ForceDark`/`ForceLight`.
    const PREFERRED_APP_MODE_FORCE_DARK: u32 = 2;
    const PREFERRED_APP_MODE_FORCE_LIGHT: u32 = 3;

    const UXTHEME_SHOULD_SYSTEM_USE_DARK_MODE_ORDINAL: u16 = 138;
    const UXTHEME_SET_PREFERRED_APP_MODE_ORDINAL: u16 = 135;
    const UXTHEME_FLUSH_MENU_THEMES_ORDINAL: u16 = 136;

    /// `uxtheme.dll`, loaded once and kept (leaked) for the process lifetime —
    /// the same pattern muda 0.19.3 uses for its `HUXTHEME` Lazy. Stored as
    /// `isize` because `HMODULE` is not `Sync`/`Send` and cannot live in a
    /// `static`.
    fn uxtheme() -> Option<windows::Win32::Foundation::HMODULE> {
        static UXTHEME: LazyLock<isize> = LazyLock::new(|| {
            // SAFETY: `c"uxtheme.dll"` is a static NUL-terminated ANSI string
            // that stays alive for the whole program, so the pointer is valid
            // and non-null for the duration of the call (LoadLibraryA copies
            // the module name before returning). The windows crate maps the
            // NULL-handle failure to `Err`, so `Ok(module)` is a valid HMODULE
            // of a loaded module; the handle is deliberately leaked here so it
            // stays valid for the process lifetime.
            unsafe { LoadLibraryA(PCSTR::from_raw(c"uxtheme.dll".as_ptr().cast())) }
                .map(|module| module.0 as isize)
                .unwrap_or_else(|error| {
                    tracing::warn!("uxtheme.dll unavailable — tray menu stays light: {error}");
                    0
                })
        });
        let module = windows::Win32::Foundation::HMODULE(*UXTHEME as *mut core::ffi::c_void);
        (!module.is_invalid()).then_some(module)
    }

    /// OS-level dark-mode state. Primary source is the documented
    /// `AppsUseLightTheme` registry value — it reflects the OS setting
    /// regardless of this process's `SetPreferredAppMode` call. Fallback is
    /// the undocumented uxtheme `ShouldSystemUseDarkMode` (ordinal 138,
    /// 1903+) when the registry read fails. Deliberately NOT the app-level
    /// `ShouldAppsUseDarkMode` (ordinal 132): after we force dark/light via
    /// `SetPreferredAppMode`, that function returns our own forced mode, which
    /// would self-feedback and misresolve `ThemePreference::System`.
    pub(super) fn system_dark_mode() -> bool {
        // winreg pattern matches the HKCU access in src/sys/single_instance.rs.
        let Ok(key) = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
            .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
        else {
            return should_system_use_dark_mode().unwrap_or(false);
        };
        match key.get_value::<u32, _>("AppsUseLightTheme") {
            Ok(light) => light == 0,
            Err(_) => should_system_use_dark_mode().unwrap_or(false),
        }
    }

    /// `ShouldSystemUseDarkMode` (ordinal 138) via GetProcAddress, `None`
    /// when unavailable.
    fn should_system_use_dark_mode() -> Option<bool> {
        type ShouldSystemUseDarkMode = unsafe extern "system" fn() -> bool;
        static SHOULD_SYSTEM_USE_DARK_MODE: LazyLock<Option<ShouldSystemUseDarkMode>> =
            LazyLock::new(|| {
                let module = uxtheme()?;
                // SAFETY: `module` is a valid HMODULE of the still-loaded
                // uxtheme.dll (the leaked handle above keeps it resident for
                // the process lifetime). `lpProcName` is an ordinal lookup:
                // the u16 constant cast to a pointer holds the ordinal in its
                // low 16 bits with zeros above — the MAKEINTRESOURCEA encoding
                // GetProcAddress interprets as an ordinal. The windows crate
                // maps the NULL result (export not found) to `None`.
                unsafe {
                    GetProcAddress(
                        module,
                        PCSTR::from_raw(
                            UXTHEME_SHOULD_SYSTEM_USE_DARK_MODE_ORDINAL as usize as *const u8,
                        ),
                    )
                }
                .map(|address| unsafe {
                    // SAFETY: `address` is the inner payload of
                    // `Option<FARPROC>`; the outer `Some` exists only when
                    // GetProcAddress found the export, so this is a non-null
                    // code pointer into the still-loaded uxtheme.dll. `FARPROC`
                    // is `Option<unsafe extern "system" fn() -> isize>` and the
                    // target is `unsafe extern "system" fn() -> bool`; both are
                    // one code pointer taken in `RAX` under the `system`
                    // calling convention, so the transmute is value-preserving.
                    // The export's real signature is
                    // `BOOL ShouldSystemUseDarkMode(void)` and the declared
                    // return is Rust's `bool`: MSVC returns 0 or 1 in `EAX`
                    // and a `bool` return reads the low byte of that register,
                    // which is the value the export wrote (muda declares the
                    // same shape for the same export).
                    std::mem::transmute::<_, ShouldSystemUseDarkMode>(address)
                })
            });
        (*SHOULD_SYSTEM_USE_DARK_MODE).map(|should| unsafe {
            // SAFETY: `should` is non-null (None was filtered out above) and
            // points at the ordinal-138 export of uxtheme.dll, which stays
            // loaded for the process lifetime; the declared
            // `unsafe extern "system" fn() -> bool` matches the export's
            // signature and calling convention, so calling it is sound.
            should()
        })
    }

    /// `SetPreferredAppMode` (ordinal 135) opts the whole process into dark or
    /// light native rendering; `FlushMenuThemes` (ordinal 136) drops uxTheme's
    /// cached menu themes so the already-built tray menu re-renders with the
    /// new mode on the next `TrackPopupMenu` after a runtime switch.
    fn set_preferred_app_mode(dark: bool) {
        type SetPreferredAppMode = unsafe extern "system" fn(u32) -> u32;
        type FlushMenuThemes = unsafe extern "system" fn();
        static SET_PREFERRED_APP_MODE: LazyLock<Option<SetPreferredAppMode>> = LazyLock::new(
            || {
                let module = uxtheme()?;
                // SAFETY: `module` is a valid HMODULE of the still-loaded
                // uxtheme.dll; `lpProcName` carries ordinal 135 in its low 16 bits
                // (MAKEINTRESOURCEA encoding, zeros above). The windows crate maps
                // the NULL result (export not found) to `None`.
                let address = unsafe {
                    GetProcAddress(
                        module,
                        PCSTR::from_raw(
                            UXTHEME_SET_PREFERRED_APP_MODE_ORDINAL as usize as *const u8,
                        ),
                    )
                };
                // A missing export is exactly why native menus keep the light
                // theme on pre-1903 Windows: report that once, and stay silent
                // when the export was found.
                if address.is_none() {
                    tracing::warn!(
                        "SetPreferredAppMode (uxtheme 135) unavailable — native menus stay light on \
                         pre-1903 Windows"
                    );
                }
                address.map(|address| unsafe {
                    // SAFETY: `address` is the non-null payload of a `Some`
                    // (GetProcAddress succeeded), a code pointer into the
                    // still-loaded uxtheme.dll. Its bit pattern equals
                    // `unsafe extern "system" fn(u32) -> u32`, and the ordinal-135
                    // export's real signature
                    // (`UINT SetPreferredAppMode(UINT)`) matches that declaration
                    // under the `system` calling convention, so the transmute and
                    // the later call are value- and ABI-preserving.
                    std::mem::transmute::<_, SetPreferredAppMode>(address)
                })
            },
        );
        static FLUSH_MENU_THEMES: LazyLock<Option<FlushMenuThemes>> = LazyLock::new(|| {
            let module = uxtheme()?;
            // SAFETY: `module` is a valid HMODULE of the still-loaded
            // uxtheme.dll; `lpProcName` carries ordinal 136 in its low 16 bits
            // (MAKEINTRESOURCEA encoding, zeros above). The windows crate maps
            // the NULL result (export not found) to `None`.
            let address = unsafe {
                GetProcAddress(
                    module,
                    PCSTR::from_raw(UXTHEME_FLUSH_MENU_THEMES_ORDINAL as usize as *const u8),
                )
            };
            // Only a missing export warns: with the flush absent, a runtime
            // theme switch leaves the already-built tray menu on its cached
            // theme until the next popup.
            if address.is_none() {
                tracing::warn!("FlushMenuThemes (uxtheme 136) unavailable");
            }
            address.map(|address| unsafe {
                // SAFETY: `address` is the non-null payload of a `Some`
                // (GetProcAddress succeeded), a code pointer into the
                // still-loaded uxtheme.dll. Its bit pattern equals
                // `unsafe extern "system" fn()`, and the ordinal-136 export's
                // real signature (`void FlushMenuThemes(void)`) matches that
                // declaration under the `system` calling convention, so the
                // transmute and the later call are value- and ABI-preserving.
                std::mem::transmute::<_, FlushMenuThemes>(address)
            })
        });

        if let Some(set_preferred_app_mode) = *SET_PREFERRED_APP_MODE {
            let mode = if dark {
                PREFERRED_APP_MODE_FORCE_DARK
            } else {
                PREFERRED_APP_MODE_FORCE_LIGHT
            };
            // SAFETY: non-null `Some` fn pointer to the ordinal-135 export of
            // the still-loaded uxtheme.dll; the `u32` argument and return
            // match the export's ABI.
            unsafe { set_preferred_app_mode(mode) };
        }
        if let Some(flush_menu_themes) = *FLUSH_MENU_THEMES {
            // SAFETY: non-null `Some` fn pointer to the ordinal-136 export of
            // the still-loaded uxtheme.dll; the void signature matches the
            // export's ABI.
            unsafe { flush_menu_themes() };
        }
    }

    /// Set the DWM immersive-dark flag (window chrome; on some Windows
    /// versions also the window's own menus) on one window.
    fn set_window_immersive_dark(hwnd: HWND, dark: bool) {
        let value = i32::from(dark); // BOOL-sized, as win32-darkmode passes a BOOL
        if let Err(error) = unsafe {
            // SAFETY: `hwnd` is a live top-level window handle derived from
            // the current winit window (callers filter `is_invalid`); a stale
            // handle makes the call fail with an HRESULT error, not UB.
            // `pvAttribute` points at the stack `value: i32` for the duration
            // of the call and `cbAttribute` is exactly `size_of::<i32>()` —
            // the 4-byte BOOL that `DWMWA_USE_IMMERSIVE_DARK_MODE` reads.
            DwmSetWindowAttribute(
                hwnd,
                DWMWA_USE_IMMERSIVE_DARK_MODE,
                (&value as *const i32).cast(),
                std::mem::size_of::<i32>() as u32,
            )
        } {
            tracing::warn!("failed to set immersive dark mode on window: {error}");
        }
    }

    /// Apply `dark` to native surfaces: process-wide preferred app mode (the
    /// layer believed to drive `TrackPopupMenu` rendering) plus the DWM
    /// immersive-dark window flag on each reachable HWND. Never breaks
    /// startup — every failure degrades to a `tracing::warn!` at most.
    pub(super) fn apply(dark: bool, hwnds: &[HWND]) {
        set_preferred_app_mode(dark);
        for &hwnd in hwnds {
            if !hwnd.is_invalid() {
                set_window_immersive_dark(hwnd, dark);
            }
        }
    }

    /// Win32 `HWND` of an eframe/winit window via `raw-window-handle` 0.6
    /// (winit re-exports it as `winit::raw_window_handle` with the `rwh_06`
    /// feature broccoli enables). `None` while the platform window does not
    /// exist yet or is being recreated.
    pub(super) fn main_window_hwnd(window: &winit::window::Window) -> Option<HWND> {
        use winit::raw_window_handle::{HasWindowHandle, RawWindowHandle};

        let RawWindowHandle::Win32(win32) = window.window_handle().ok()?.as_raw() else {
            return None;
        };
        Some(HWND(win32.hwnd.get() as *mut core::ffi::c_void))
    }
}

/// Build the tray menu always, and the tray icon only when `with_icon` is set:
/// the headless test boot ([`BroccoliApp::new_headless`]) keeps the menu and
/// the action channel — the tray plumbing keeps its types and stays wired —
/// but a test run must not light up the notification area.
fn build_tray(
    icon_assets: &IconAssets,
    lang: Language,
    with_icon: bool,
) -> (Option<tray_icon::TrayIcon>, TrayMenu) {
    #[cfg(windows)]
    use tray_icon::TrayIconBuilder;
    use tray_icon::menu::{Menu, MenuItem, PredefinedMenuItem};

    let show = MenuItem::new(t(lang, Key::TrayShow), true, None);
    let connect = MenuItem::new(t(lang, Key::TrayConnectDisconnect), true, None);
    let quit = MenuItem::new(t(lang, Key::TrayQuit), true, None);
    let menu = Menu::new();
    let _ = menu.append(&show);
    let _ = menu.append(&connect);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&quit);

    #[cfg(windows)]
    let tray = if with_icon {
        match icon_assets.tray_icon(crate::icon::IconState::Stopped, None) {
            Ok(icon) => TrayIconBuilder::new()
                .with_menu(Box::new(menu))
                .with_menu_on_left_click(false)
                .with_tooltip(t(lang, Key::TrayTooltipStopped))
                .with_icon(icon)
                .build()
                .map_err(|error| tracing::warn!("tray icon failed: {error}"))
                .ok(),
            Err(error) => {
                tracing::warn!("tray icon failed: {error}");
                None
            }
        }
    } else {
        None
    };
    #[cfg(not(windows))]
    let tray = {
        let _ = (icon_assets, menu);
        None
    };

    (
        tray,
        TrayMenu {
            show,
            connect,
            quit,
        },
    )
}

/// Process-lifetime bytes of the first CJK fallback font this machine ships,
/// or `None` when it ships neither.
///
/// The bytes must outlive egui: [`egui::FontData::from_static`] borrows them,
/// whereas an owned `FontData` is cloned wholesale when the fonts are built —
/// that clone kept a second copy of the ~19 MB `msyh.ttc` resident for the
/// process lifetime. CP936 Windows installs otherwise have no font covering
/// Chinese server names, log lines, or paths, which would paint as tofu.
static CJK_FONT_BYTES: LazyLock<Option<Vec<u8>>> = LazyLock::new(|| {
    [r"C:\Windows\Fonts\msyh.ttc", r"C:\Windows\Fonts\simsun.ttc"]
        .into_iter()
        .find_map(|candidate| match std::fs::read(candidate) {
            Ok(bytes) => Some(bytes),
            // A missing candidate is expected — plenty of Windows installs
            // ship neither font — but an unreadable one (lock, ACL, I/O
            // error) is worth a word: with no font loaded, CJK text paints
            // as tofu.
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                tracing::warn!("CJK fallback font {candidate} unreadable: {error}");
                None
            }
            Err(_) => None,
        })
});

fn load_cjk_fonts(ctx: &egui::Context) {
    let Some(bytes) = CJK_FONT_BYTES.as_ref() else {
        return;
    };
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "cjk".to_string(),
        std::sync::Arc::new(egui::FontData::from_static(bytes)),
    );
    for fam in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        fonts
            .families
            .entry(fam)
            .or_default()
            .push("cjk".to_string());
    }
    ctx.set_fonts(fonts);
}

/// Escape control characters in a line about to be persisted to `app.log` so
/// a crafted core line cannot inject ANSI terminal sequences, carriage
/// returns, or fake log records into the plaintext file (CWE-117).
/// Common ones get readable two-character escapes; the rest become `\xNN`.
fn escape_control_chars(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    for c in line.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                use std::fmt::Write as _;
                // fmt::Write for String is infallible.
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Append-only writer for `app.log` that rotates the file once it exceeds
/// [`APP_LOG_MAX_BYTES`] (and once by age at startup), retaining at most
/// [`APP_LOG_KEEP`] rotated segments, so a chatty core can never grow disk
/// usage without bound (CWE-400). The current file is always the
/// plain `app.log`, so anything that tails the log keeps working across
/// rotations. Fits `tracing_appender::non_blocking`'s writer bound (`Send +
/// 'static`); the inner mutex satisfies the `Sync` requirement of
/// `BoxMakeWriter` while the non-blocking worker serializes actual writes.
#[derive(Clone)]
struct RotatingLogWriter {
    state: Arc<Mutex<RotationState>>,
}

struct RotationState {
    file: std::fs::File,
    path: std::path::PathBuf,
    /// Bytes written to the current segment through this writer. Accurate
    /// because this writer is the only one appending to `app.log`.
    written: u64,
    max_bytes: u64,
    keep: usize,
}

impl RotatingLogWriter {
    fn open(path: std::path::PathBuf, max_bytes: u64, keep: usize) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        let written = match file.metadata() {
            Ok(meta) => meta.len(),
            Err(_) => 0,
        };
        let mut state = RotationState {
            file,
            path,
            written,
            max_bytes,
            keep,
        };
        // Age-based rotation: a log idle for a day starts fresh.
        let stale = match state.file.metadata().and_then(|meta| meta.modified()) {
            Ok(modified) => match modified.elapsed() {
                Ok(age) => age > APP_LOG_MAX_AGE,
                Err(_) => false,
            },
            Err(_) => false,
        };
        if stale {
            state.rotate()?;
        }
        Ok(RotatingLogWriter {
            state: Arc::new(Mutex::new(state)),
        })
    }
}

impl RotationState {
    /// Rename `app.log` -> `app.log.1`, shift older segments up, drop the one
    /// past `keep`, and open a fresh `app.log`.
    fn rotate(&mut self) -> std::io::Result<()> {
        let rotated = |n: usize| -> std::path::PathBuf {
            let name = self
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("app.log");
            self.path.with_file_name(format!("{name}.{n}"))
        };
        // Drop the oldest segment first so the shift never collides with an
        // existing destination.
        let _ = std::fs::remove_file(rotated(self.keep));
        for n in (1..self.keep).rev() {
            let from = rotated(n);
            if from.exists() {
                std::fs::rename(&from, rotated(n + 1))?;
            }
        }
        std::fs::rename(&self.path, rotated(1))?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.file = file;
        self.written = 0;
        Ok(())
    }
}

impl std::io::Write for RotatingLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| std::io::Error::other("app.log writer mutex poisoned"))?;
        if state.written + buf.len() as u64 > state.max_bytes
            && let Err(error) = state.rotate()
        {
            // Degrade rather than lose records: keep appending and retry
            // rotation on the next write past the cap.
            eprintln!("broccoli: app.log rotation failed: {error}");
        }
        let written = state.file.write(buf)?;
        state.written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| std::io::Error::other("app.log writer mutex poisoned"))?;
        state.file.flush()
    }
}

/// Drop the tracing worker guard — flushing accepted records and stopping
/// the non-blocking writer — so no log-file handle remains open. Called by
/// the exit path on every quit, before cleanup wipes the app-data dirs; after
/// this, tracing writes are no-ops for the rest of the process.
pub fn release_log_guard() {
    let guard = LOG_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    drop(guard);
}

fn init_tracing() {
    // Tracing is not initialized yet, so a failure can only reach stderr
    // here; the startup `ensure_dirs` in `BroccoliApp::new` surfaces the same
    // failure in the UI and in the log once tracing is live.
    if let Err(error) = paths::ensure_dirs() {
        eprintln!("broccoli: failed to create profile directories: {error:#}");
    }
    let writer: tracing_subscriber::fmt::writer::BoxMakeWriter = match RotatingLogWriter::open(
        paths::logs_dir().join("app.log"),
        APP_LOG_MAX_BYTES,
        APP_LOG_KEEP,
    ) {
        Ok(rotating) => {
            // Runtime events can arrive faster than disk writes. A bounded
            // worker keeps the egui thread and core output pumps independent
            // of filesystem latency; retain its guard for process lifetime so
            // a clean exit flushes accepted records. Rotation happens inside
            // the rotating writer on that worker thread, never on the pumps.
            let (writer, guard) = tracing_appender::non_blocking(rotating);
            // Keep only the first guard: a later app construction in the
            // same process (tests) must not shut the live worker down.
            let mut guard_slot = LOG_GUARD
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if guard_slot.is_none() {
                *guard_slot = Some(guard);
            }
            tracing_subscriber::fmt::writer::BoxMakeWriter::new(writer)
        }
        Err(error) => {
            eprintln!("broccoli: cannot open app.log, tracing to stdout: {error}");
            tracing_subscriber::fmt::writer::BoxMakeWriter::new(std::io::stdout)
        }
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info,wgpu=warn,naga=warn".into());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .try_init()
        .ok();
}

#[cfg(test)]
mod safety_ack_tests {
    use super::{Language, hazard_gate_findings, show_safety_ack_modal};
    use crate::i18n::{Key, t};
    use crate::model::Settings;
    use crate::model::inbound::{DokodemoCfg, LocalInboundCfg, LocalInboundProtocol};
    use crate::model::safety::{HazardClass, SafetyCode, SafetyFinding};
    use crate::model::servers::ServersFile;

    /// One finding per exposure rule: unauthenticated SOCKS + HTTP endpoints
    /// and an enabled dokodemo inbound, all bound beyond loopback.
    fn hazardous_settings() -> Settings {
        Settings {
            local_inbounds: vec![
                LocalInboundCfg {
                    protocol: LocalInboundProtocol::Socks,
                    enabled: true,
                    listen: "0.0.0.0".into(),
                    ..Default::default()
                },
                LocalInboundCfg {
                    protocol: LocalInboundProtocol::Http,
                    enabled: true,
                    listen: "0.0.0.0".into(),
                    ..Default::default()
                },
            ],
            dokodemo: vec![DokodemoCfg {
                enabled: true,
                listen: "0.0.0.0".into(),
                network: "tcp".into(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn hazardous_settings_gate_the_apply_with_every_finding() {
        let findings = hazard_gate_findings(&ServersFile::default(), &hazardous_settings())
            .expect("hazardous settings must gate the apply");
        let paths: Vec<&str> = findings
            .iter()
            .map(|finding| finding.path.as_str())
            .collect();
        for expected in [
            "localInbounds[0].listen",
            "localInbounds[1].listen",
            "dokodemo[0].listen",
        ] {
            assert!(
                paths.contains(&expected),
                "every hazard must be listed for the dialog (missing {expected})"
            );
        }
        for finding in &findings {
            assert_eq!(
                finding.class,
                HazardClass::Exposure,
                "{} must carry its hazard class",
                finding.path
            );
        }
    }

    #[test]
    fn clean_settings_never_gate() {
        assert!(
            hazard_gate_findings(&ServersFile::default(), &Settings::default()).is_none(),
            "a configuration without hazards must not gate the apply"
        );
    }

    #[test]
    fn disabled_or_loopback_inbounds_do_not_gate() {
        // Exposed listen but the endpoint is disabled.
        let disabled = Settings {
            local_inbounds: vec![LocalInboundCfg {
                protocol: LocalInboundProtocol::Socks,
                enabled: false,
                listen: "0.0.0.0".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(hazard_gate_findings(&ServersFile::default(), &disabled).is_none());
        // Enabled but loopback-only.
        let loopback = Settings {
            local_inbounds: vec![LocalInboundCfg {
                protocol: LocalInboundProtocol::Socks,
                enabled: true,
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(hazard_gate_findings(&ServersFile::default(), &loopback).is_none());
    }

    #[test]
    fn raw_override_skips_the_hazard_gate() {
        // The whole-config raw override stays unrestricted, so the
        // hazard gate must never fire while it is active.
        let settings = Settings {
            raw_override: Some(r#"{"log": {"loglevel": "debug"}}"#.into()),
            ..hazardous_settings()
        };
        assert!(
            hazard_gate_findings(&ServersFile::default(), &settings).is_none(),
            "the raw override path must bypass the hazard gate"
        );
    }

    #[test]
    fn safety_ack_modal_lists_every_finding_and_apply_anyway_confirms() {
        use egui_kittest::{Harness, kittest::Queryable};
        use std::cell::Cell;
        use std::rc::Rc;

        let findings = vec![
            SafetyFinding {
                path: "localInbounds[0].listen".into(),
                class: HazardClass::Exposure,
                code: SafetyCode::SocksListenerExposed("0.0.0.0:10808".into()),
            },
            SafetyFinding {
                path: "localInbounds[1].listen".into(),
                class: HazardClass::Exposure,
                code: SafetyCode::HttpListenerExposed("0.0.0.0:10880".into()),
            },
        ];
        let expected_messages: Vec<String> = findings
            .iter()
            .map(|finding| crate::i18n::safety_finding_message(finding, Language::En))
            .collect();
        let decision = Rc::new(Cell::new(None));
        let decision_for_ui = Rc::clone(&decision);
        let mut harness = Harness::builder().build_ui_state(
            move |ui, findings: &mut Vec<SafetyFinding>| {
                show_safety_ack_modal(ui.ctx(), Language::En, findings, |confirmed| {
                    decision_for_ui.set(Some(confirmed));
                });
            },
            findings,
        );
        harness.run();

        // Title, per-finding path + hazard-class label + rendered message.
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SafetyAckTitle))
                .is_some()
        );
        for (path, message) in [
            ("localInbounds[0].listen", &expected_messages[0]),
            ("localInbounds[1].listen", &expected_messages[1]),
        ] {
            assert!(
                harness.query_by_label(path).is_some(),
                "{path} must be listed"
            );
            assert!(
                harness.query_by_label(message).is_some(),
                "the rendered reason for {path} must be listed"
            );
        }
        assert_eq!(
            harness.query_all_by_label("Exposure").count(),
            2,
            "every finding must carry its hazard-class label"
        );

        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "Apply anyway")
            .click();
        harness.run();
        assert_eq!(
            decision.get(),
            Some(true),
            "Apply anyway must confirm the acknowledgment"
        );
    }

    #[test]
    fn safety_ack_modal_cancel_aborts_without_confirming() {
        use egui_kittest::{Harness, kittest::Queryable};
        use std::cell::Cell;
        use std::rc::Rc;

        let findings = vec![SafetyFinding {
            path: "localInbounds[0].listen".into(),
            class: HazardClass::Exposure,
            code: SafetyCode::SocksListenerExposed("0.0.0.0:10808".into()),
        }];
        let decision = Rc::new(Cell::new(None));
        let decision_for_ui = Rc::clone(&decision);
        let mut harness = Harness::builder().build_ui_state(
            move |ui, findings: &mut Vec<SafetyFinding>| {
                show_safety_ack_modal(ui.ctx(), Language::En, findings, |confirmed| {
                    decision_for_ui.set(Some(confirmed));
                });
            },
            findings,
        );
        harness.run();

        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "Cancel")
            .click();
        harness.run();
        assert_eq!(
            decision.get(),
            Some(false),
            "Cancel must abort the apply without confirming"
        );
    }
}

/// Unsaved-changes indicator wiring (contract): topbar chip, quit
/// interception, and the quit-resume tail. The app shell itself is not
/// constructible in tests (needs `eframe::CreationContext` + profile I/O),
/// so the wiring lives in small free functions and seams
/// ([`ui::topbar::topbar_status_zone`], [`quit_or_stage_leave`],
/// [`quit_resume_ready`]) that are exercised here through the real
/// ServersScreen UI (list selection, draft edits, the leave modal) and the
/// shared screen-test rig (`crate::ui::test_rig::UiTestRig`) that every
/// screen test builds through.
#[cfg(test)]
mod unsaved_changes_tests {
    use super::{quit_or_stage_leave, quit_resume_ready};
    use crate::i18n::{Key, t};
    use crate::model::settings::Language;
    use crate::model::{OutboundModel, Protocol, ServerProfile};
    use crate::ui::servers::{LeaveAction, ServersScreen};
    use crate::ui::test_rig::UiTestRig;

    /// The topbar unsaved chip renders exactly while the Servers screen
    /// reports unsaved changes (the call site passes `unsaved_changes()`
    /// straight through; the verdict itself is covered in the
    /// quit-deferral test).
    #[test]
    fn topbar_chip_renders_only_while_the_servers_screen_has_unsaved_changes() {
        use egui_kittest::{Harness, kittest::Queryable};

        let status = |unsaved: bool| crate::ui::topbar::TopbarStatus {
            lang: Language::En,
            mode_caption: "mode: TUN",
            active_caption: None,
            unsaved_changes: unsaved,
            trial_rule_count: 0,
            core_available: true,
            config_dirty: false,
            can_apply: false,
            apply_block: None,
            apply_result: None,
            terminal_error: None,
            config_error: None,
            state_error: None,
            persistence_error: None,
        };
        let mut harness = Harness::new_ui(|ui| {
            crate::ui::topbar::topbar_status_zone(ui, &status(true));
        });
        harness.run();
        assert!(
            harness
                .query_by_label(t(Language::En, Key::TopbarServerEditsUnsaved))
                .is_some(),
            "the chip must render while the servers screen reports unsaved changes"
        );

        let mut harness = Harness::new_ui(|ui| {
            crate::ui::topbar::topbar_status_zone(ui, &status(false));
        });
        harness.run();
        assert!(
            harness
                .query_by_label(t(Language::En, Key::TopbarServerEditsUnsaved))
                .is_none(),
            "the chip must not render while the servers screen is clean"
        );
    }

    /// Quit while the servers screen holds an uncommitted draft: the quit is
    /// deferred (nothing proceeds), the Quit leave action is staged, and the
    /// modal renders; Cancel keeps the draft and never resumes the quit.
    #[test]
    fn quit_is_deferred_while_the_servers_screen_has_unsaved_changes() {
        use egui_kittest::{Harness, kittest::Queryable};
        use std::cell::Cell;
        use std::rc::Rc;

        let mut rig = UiTestRig::default();
        rig.servers.profiles.push(ServerProfile::new(
            "Tokyo",
            OutboundModel::new(Protocol::Freedom),
        ));
        let deferred = Rc::new(Cell::new(None));
        let deferred_ui = Rc::clone(&deferred);
        let attempt_quit = Rc::new(Cell::new(false));
        let attempt_quit_ui = Rc::clone(&attempt_quit);
        let mut harness = Harness::builder()
            .with_size(egui::vec2(1100.0, 700.0))
            .build_ui_state(
                move |ui, state: &mut (ServersScreen, UiTestRig)| {
                    state.0.show(ui, &mut state.1.ctx());
                    // Same every-frame tail wiring as `BroccoliApp::ui`.
                    state.0.show_leave_modal(ui.ctx(), &mut state.1.ctx());
                    if attempt_quit_ui.replace(false) {
                        // Same call `BroccoliApp::quit` makes.
                        deferred_ui.set(Some(quit_or_stage_leave(&mut state.0, ui.ctx())));
                    }
                },
                (ServersScreen::default(), rig),
            );
        harness.run();

        // Select the profile through the real list; the editor draft opens.
        harness.get_by_label("Tokyo").click();
        harness.run();
        assert!(
            !harness.state().0.unsaved_changes(),
            "a fresh draft is not unsaved"
        );

        // Type into the draft's name field (the text input carrying the
        // profile name): the draft becomes unsaved.
        let name_field = harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .find(|node| node.value().as_deref() == Some("Tokyo"))
            .expect("the draft name field must render the profile name");
        name_field.focus();
        name_field.type_text("x");
        harness.run();
        assert!(
            harness.state().0.unsaved_changes(),
            "editing the draft must mark the servers screen unsaved"
        );

        // Quit while unsaved: deferred (quit_impl never runs) and staged.
        attempt_quit.set(true);
        harness.run();
        assert_eq!(
            deferred.get(),
            Some(false),
            "the quit must be deferred, not run, while the draft is unsaved"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvUnsavedChanges))
                .is_some(),
            "the deferred quit must stage the leave modal"
        );

        // Cancel keeps the draft and never resumes the quit.
        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "Cancel")
            .click();
        harness.run();
        assert!(
            harness.state().0.unsaved_changes(),
            "cancelling must keep the draft"
        );
        assert!(
            !quit_resume_ready(&mut harness.state_mut().0, false),
            "cancelling must not resume the deferred quit"
        );
    }

    /// A staged Quit resolved through the leave modal fires the quit-resume
    /// flag exactly once, and the `quitting` guard keeps a resolved quit
    /// from re-entering while a quit is already in flight.
    #[test]
    fn quit_resumes_after_the_leave_modal_resolves_and_never_reenters() {
        use egui_kittest::{Harness, kittest::Queryable};

        let mut harness = Harness::builder()
            .with_size(egui::vec2(1100.0, 700.0))
            .build_ui_state(
                |ui, state: &mut (ServersScreen, UiTestRig)| {
                    state.0.show(ui, &mut state.1.ctx());
                    // Same every-frame tail wiring as `BroccoliApp::ui`.
                    state.0.show_leave_modal(ui.ctx(), &mut state.1.ctx());
                },
                (ServersScreen::default(), UiTestRig::default()),
            );
        harness.run();

        // Stage a quit and resolve it through the modal's Discard: the
        // quit-resume flag must fire exactly once.
        harness.state_mut().0.stage_leave(LeaveAction::Quit);
        harness.run();
        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "Discard changes")
            .click();
        harness.run();
        assert!(
            quit_resume_ready(&mut harness.state_mut().0, false),
            "a resolved staged quit must resume the quit"
        );
        assert!(
            !quit_resume_ready(&mut harness.state_mut().0, false),
            "the resume flag must fire exactly once"
        );

        // A second staged quit resolved the same way must NOT resume while a
        // quit is already in flight.
        harness.state_mut().0.stage_leave(LeaveAction::Quit);
        harness.run();
        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "Discard changes")
            .click();
        harness.run();
        assert!(
            !quit_resume_ready(&mut harness.state_mut().0, true),
            "a quit already in flight must never re-enter"
        );
    }
}

/// The derived config-apply gate (contract): the chip is up exactly while the
/// current candidate differs from the config the running core accepted (or
/// the startup baseline), or while the state cannot be saved.
#[cfg(test)]
mod config_gate_tests {
    use super::{config_gate_after_persist, normalize_candidate_for_compare};
    use serde_json::json;

    #[test]
    fn gate_is_down_when_the_current_candidate_matches_the_applied_one() {
        let applied = json!({"outbounds": [{"tag": "a"}]});
        assert!(!config_gate_after_persist(Some(&applied), &applied, None));
    }

    #[test]
    fn gate_is_up_when_the_candidate_differs_from_the_applied_one() {
        let applied = json!({"outbounds": [{"tag": "a"}]});
        let current = json!({"outbounds": [{"tag": "b"}]});
        assert!(config_gate_after_persist(Some(&applied), &current, None));
    }

    #[test]
    fn gate_is_up_while_the_state_cannot_be_saved() {
        let applied = json!({"outbounds": [{"tag": "a"}]});
        assert!(config_gate_after_persist(
            Some(&applied),
            &applied,
            Some("disk full")
        ));
    }

    #[test]
    fn gate_is_up_when_no_applied_baseline_exists() {
        let current = json!({"outbounds": [{"tag": "a"}]});
        assert!(config_gate_after_persist(None, &current, None));
    }

    #[test]
    fn normalization_ignores_the_ephemeral_api_port() {
        // The api listen carries a per-launch ephemeral port
        // (root `api` object and api inbound), so two generations of the
        // same state never compare equal without this normalization.
        let a = json!({
            "api": {"listen": "127.0.0.1:12345"},
            "inbounds": [{"tag": "api", "listen": "127.0.0.1:12345"}, {"tag": "socks"}]
        });
        let b = json!({
            "api": {"listen": "127.0.0.1:54321"},
            "inbounds": [{"tag": "api", "listen": "127.0.0.1:54321"}, {"tag": "socks"}]
        });
        assert_eq!(
            normalize_candidate_for_compare(a),
            normalize_candidate_for_compare(b),
            "candidates differing only in the api port must compare equal"
        );
        assert_eq!(
            normalize_candidate_for_compare(json!({"inbounds": [{"tag": "socks"}]})),
            normalize_candidate_for_compare(json!({"inbounds": [{"tag": "socks"}]})),
            "candidates without an api listener are unchanged"
        );
    }
}

/// The apply-verdict settle (contract): the revision a verdict names decides
/// whether the app may claim it, so a success for an older revision cannot
/// settle newer saved changes (the top bar reports the older apply instead)
/// and a failure settles nothing.
#[cfg(test)]
mod apply_verdict_tests {
    use super::apply_verdict_settles_current;

    #[test]
    fn only_a_success_for_the_revision_the_app_holds_settles_it() {
        assert!(apply_verdict_settles_current(true, 7, 7));
        assert!(
            !apply_verdict_settles_current(true, 6, 7),
            "a success for an older revision must leave newer changes pending"
        );
        assert!(
            !apply_verdict_settles_current(false, 7, 7),
            "a failed apply never settles the configuration"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{LOG_BYTE_CAP, LOG_CAP, LogBuffer, TerminalError};
    use super::{Language, native_dark_for, tun_outbound_interface_block_reason};
    use crate::diag::Diag;
    use crate::i18n::{Key, t};
    use crate::model::settings::Mode;
    use crate::rt::supervisor::MAX_LINE_BYTES;

    fn iface(name: &str, up: bool) -> crate::sys::netif::NetIf {
        crate::sys::netif::NetIf {
            name: name.into(),
            ips: Vec::new(),
            up,
        }
    }

    #[test]
    fn tun_outbound_interface_guard_allows_auto_and_unset() {
        let ifaces = vec![iface("wired", false)];
        assert_eq!(
            tun_outbound_interface_block_reason(Language::En, Mode::Tun, "", &ifaces),
            None,
            "empty setting must not bind a stale index"
        );
        assert_eq!(
            tun_outbound_interface_block_reason(Language::En, Mode::Tun, "auto", &ifaces),
            None,
            "'auto' must never be blocked"
        );
        assert_eq!(
            tun_outbound_interface_block_reason(Language::En, Mode::Off, "wired", &ifaces),
            None,
            "off mode has no TUN binding to guard"
        );
    }

    #[test]
    fn tun_outbound_interface_guard_blocks_down_and_missing_fixed_names() {
        let ifaces = vec![
            iface("Ethernet", true),
            iface("wired", false),
            iface("Wi-Fi", true),
        ];
        let down = tun_outbound_interface_block_reason(Language::En, Mode::Tun, "wired", &ifaces)
            .expect("down fixed name must block the apply");
        assert!(down.contains("wired"), "{down}");
        assert!(down.contains("down"), "{down}");

        let missing =
            tun_outbound_interface_block_reason(Language::En, Mode::Tun, "ghost", &ifaces)
                .expect("missing fixed name must block the apply");
        assert!(missing.contains("ghost"), "{missing}");
    }

    #[test]
    fn tun_outbound_interface_guard_passes_up_fixed_names() {
        let ifaces = vec![iface("Ethernet", true), iface("wired", false)];
        assert_eq!(
            tun_outbound_interface_block_reason(Language::En, Mode::Tun, "Ethernet", &ifaces),
            None,
            "an up fixed name is a valid binding target"
        );
    }
    /// Control characters in a persisted line are escaped so a
    /// crafted core line cannot inject ANSI sequences or fake records into
    /// the plaintext app.log.
    #[test]
    fn control_chars_are_escaped_before_persisting() {
        use super::escape_control_chars;

        let escaped = escape_control_chars("ok\x1b[31mred\r\nfake\n\t\x7f\u{9b}");
        assert_eq!(escaped, r"ok\x1b[31mred\r\nfake\n\t\x7f\x9b");
        assert!(escaped.chars().all(|c| !c.is_control()));
    }

    /// app.log rotates at the size cap, keeps a bounded number of
    /// rotated segments, and the current file stays the write target.
    #[test]
    fn app_log_rotates_at_size_cap_and_keeps_bounded_segments() {
        use std::io::Write as _;

        use super::RotatingLogWriter;

        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("app.log");
        let mut writer = RotatingLogWriter::open(path.clone(), 100, 3).expect("open writer");
        let record = vec![b'x'; 60];

        // Six 60-byte records: the first lands, then every later write crosses
        // the 100-byte cap and rotates first. That is five rotations.
        for _ in 0..6 {
            writer.write_all(&record).expect("write record");
        }

        // Current log is still the write target and holds the newest record.
        assert_eq!(std::fs::read(&path).expect("read current log").len(), 60);
        // The two most recent rotated segments exist...
        assert_eq!(
            std::fs::read(dir.path().join("app.log.1"))
                .expect("read app.log.1")
                .len(),
            60
        );
        assert_eq!(
            std::fs::read(dir.path().join("app.log.2"))
                .expect("read app.log.2")
                .len(),
            60
        );
        // ...and the segment past `keep` was dropped, so disk usage is bounded.
        assert!(
            !dir.path().join("app.log.4").exists(),
            "rotated segments beyond keep must be removed"
        );
        // No stray files accumulate either.
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .expect("list log dir")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries.len(), 4, "app.log plus three rotated segments");
    }

    /// Exhaustive 3 x 2 preference/system matrix for the native-theme resolver.
    #[test]
    fn native_dark_covers_every_preference_system_combination() {
        use egui::ThemePreference;

        // `System` follows the OS dark-mode state.
        assert!(native_dark_for(ThemePreference::System, true));
        assert!(!native_dark_for(ThemePreference::System, false));

        // `Dark`/`Light` override the OS in both system states.
        assert!(native_dark_for(ThemePreference::Dark, true));
        assert!(native_dark_for(ThemePreference::Dark, false));
        assert!(!native_dark_for(ThemePreference::Light, true));
        assert!(!native_dark_for(ThemePreference::Light, false));
    }
    /// Lines at the runtime's 4 KiB ceiling must never leave the
    /// buffer over the byte cap — oldest lines give way instead, order is
    /// preserved, and the newest line always survives.
    #[test]
    fn max_size_lines_never_exceed_byte_cap() {
        let mut buf = LogBuffer::new();
        let max_lines = LOG_BYTE_CAP / MAX_LINE_BYTES;
        let count = 10 * LOG_CAP;
        for i in 0..count {
            // Exactly MAX_LINE_BYTES ASCII bytes per line, distinguishable
            // by the zero-padded index.
            buf.push(true, format!("{:0width$}", i, width = MAX_LINE_BYTES));
            assert!(buf.bytes <= LOG_BYTE_CAP, "push {i} left the byte cap");
        }
        // Steady state: exactly the byte cap, filled with max-size lines.
        assert_eq!(buf.len(), max_lines);
        assert_eq!(buf.bytes, max_lines * MAX_LINE_BYTES);
        // Order intact: the newest line is at the back, and the oldest
        // survivor is the first line that fits within the byte cap.
        let newest = format!("{:0width$}", count - 1, width = MAX_LINE_BYTES);
        let oldest = format!("{:0width$}", count - max_lines, width = MAX_LINE_BYTES);
        assert_eq!(buf.back().unwrap().1.as_str(), newest.as_str());
        assert_eq!(buf.front().unwrap().1.as_str(), oldest.as_str());
    }

    /// At normal line volumes the byte cap is dormant — the count
    /// cap still binds, order is preserved, and the oldest lines are dropped.
    #[test]
    fn normal_lines_keep_count_cap_ordering_and_oldest_dropped() {
        let mut buf = LogBuffer::new();
        let short = "status ok";
        let count = 3 * LOG_CAP;
        for i in 0..count {
            buf.push(i % 2 == 0, format!("{short} {i}"));
        }
        assert_eq!(buf.len(), LOG_CAP);
        // This volume never reaches the byte cap, so the count cap alone
        // shaped the buffer and the retained total is exactly the sum of
        // the surviving lines.
        let expected_bytes: usize = (2 * LOG_CAP..count)
            .map(|i| format!("{short} {i}").len())
            .sum();
        assert!(expected_bytes < LOG_BYTE_CAP);
        assert_eq!(buf.bytes, expected_bytes);
        // Oldest dropped, order and from_core flags preserved.
        let expected: Vec<(bool, String)> = (2 * LOG_CAP..count)
            .map(|i| (i % 2 == 0, format!("{short} {i}")))
            .collect();
        let actual: Vec<(bool, String)> = buf.iter().cloned().collect();
        assert_eq!(actual, expected);
    }

    /// The buffer's own byte accounting is the resident total: every push
    /// leaves it at or under the byte cap, and at max-size volumes evictions
    /// bring it down to exactly the cap.
    #[test]
    fn byte_accounting_tracks_pushes_and_evictions() {
        let mut buf = LogBuffer::new();

        buf.push(false, "hello".to_string());
        buf.push(false, "world".to_string());
        assert_eq!(buf.bytes, 10);

        // Max-size lines: the byte cap binds and stays bound on every push.
        let max_line = "y".repeat(MAX_LINE_BYTES);
        for _ in 0..(LOG_BYTE_CAP / MAX_LINE_BYTES + 2) {
            buf.push(true, max_line.clone());
            assert!(buf.bytes <= LOG_BYTE_CAP);
        }
        // The short lines were evicted; the ring holds exactly the byte cap
        // of max-size lines.
        assert_eq!(buf.len(), LOG_BYTE_CAP / MAX_LINE_BYTES);
        assert_eq!(buf.bytes, LOG_BYTE_CAP);
    }

    /// The terminal message is formatted when the failure is recorded, and
    /// every later frame reuses that text: `render_in` is the memo — it
    /// reports `false` while the message's language stands, so no idle frame
    /// re-formats (or re-allocates) the message the block and the chip
    /// render.
    #[test]
    fn terminal_error_renders_once_and_keeps_its_text() {
        let mut error = TerminalError::new(
            Diag::new(Key::RtPhaseRestartCancelled),
            String::new(),
            Language::En,
        );
        assert_eq!(error.text, t(Language::En, Key::RtPhaseRestartCancelled));
        let text_ptr = error.text.as_ptr();

        assert!(
            !error.render_in(Language::En),
            "the recorded language must keep the memoized text"
        );
        assert_eq!(
            error.text.as_ptr(),
            text_ptr,
            "an idle frame must reuse the formatted text allocation"
        );
    }
}

/// Idle repaint policy: the `ui` tail
/// no longer owns the standing 500 ms timer — repainting is event-driven
/// (the runtime pokes once per queued event) plus a next-frame request when
/// a full drain batch left queued work. The scheduling decision is pure
/// (`repaint_follow_up`); these tests pin the matrix: no standing request in
/// the former timer phases (Running/Starting), nothing while the viewport
/// is hidden or minimized, and an immediate next-frame request only for a
/// full-batch drain. Changed-event drains need no follow-up: their poke
/// already scheduled the frame that drained them.
#[cfg(test)]
mod repaint_policy_tests {
    use super::{DrainOutcome, RepaintFollowUp, repaint_follow_up};
    use crate::rt::CorePhase;

    #[test]
    fn running_visible_quiet_frame_requests_no_standing_timer() {
        // Running + visible + nothing drained used to arm
        // `request_repaint_after(500 ms)` at the `ui` tail.
        // The decision is now `Nothing`: the next frame arrives with the
        // runtime's next poke (~1 Hz stats tick while running idle).
        assert_eq!(
            repaint_follow_up(&CorePhase::Running, false, DrainOutcome::Empty),
            RepaintFollowUp::Nothing
        );
    }

    #[test]
    fn starting_visible_quiet_frame_requests_no_standing_timer() {
        // Starting was the other phase the standing timer covered; it is
        // equally poke-driven now.
        assert_eq!(
            repaint_follow_up(&CorePhase::Starting, false, DrainOutcome::Empty),
            RepaintFollowUp::Nothing
        );
    }

    #[test]
    fn hidden_or_minimized_viewport_requests_nothing_even_when_events_drained() {
        // The visibility gate overrides every drain outcome: while the
        // viewport is hidden (close-to-tray) or minimized the app adds no
        // follow-up requests at all — runtime pokes may still wake a
        // frame, but nothing is scheduled from the `ui` tail.
        assert_eq!(
            repaint_follow_up(&CorePhase::Running, true, DrainOutcome::Empty),
            RepaintFollowUp::Nothing
        );
        assert_eq!(
            repaint_follow_up(&CorePhase::Running, true, DrainOutcome::Drained),
            RepaintFollowUp::Nothing
        );
        assert_eq!(
            repaint_follow_up(&CorePhase::Running, true, DrainOutcome::Full),
            RepaintFollowUp::Nothing
        );
    }

    #[test]
    fn full_batch_drain_requests_the_immediate_next_frame() {
        // `EVENT_DRAIN_LIMIT` events were drained and more may be queued:
        // the backlog keeps moving through the immediate next frame.
        assert_eq!(
            repaint_follow_up(&CorePhase::Running, false, DrainOutcome::Full),
            RepaintFollowUp::NextFrame
        );
    }

    #[test]
    fn changed_event_drain_proceeds_via_the_runtime_poke() {
        // A changed event already poked the egui context when it was queued
        // (rt/mod.rs emit sites) — the frame that drained it exists because
        // of that poke, so a partial drain schedules nothing (and never a
        // standing 500 ms request).
        assert_eq!(
            repaint_follow_up(&CorePhase::Running, false, DrainOutcome::Drained),
            RepaintFollowUp::Nothing
        );
    }
}

#[cfg(test)]
mod font_tests {
    use super::{CJK_FONT_BYTES, load_cjk_fonts};

    #[test]
    fn cjk_text_is_renderable_exactly_when_a_fallback_font_loaded() {
        // Chinese server names, log lines, and paths must not paint as tofu,
        // so the loader has to leave a family that covers CJK codepoints.
        // egui's default families carry none, which makes the implication
        // exact in both directions: on a machine shipping neither fallback
        // font file, nothing is renderable.
        let ctx = egui::Context::default();
        load_cjk_fonts(&ctx);
        let mut renderable = false;
        let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
            renderable = ui
                .ctx()
                .fonts_mut(|fonts| fonts.has_glyphs(&egui::FontId::proportional(14.0), "服务"));
        });
        // A headless run has no renderer to apply texture deltas to; drop
        // them explicitly instead of panicking in the TexturesDelta guard.
        output.textures_delta.clear();
        assert_eq!(
            renderable,
            CJK_FONT_BYTES.is_some(),
            "CJK glyph coverage must follow the fallback font load"
        );
    }
}
