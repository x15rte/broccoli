use egui::{ScrollArea, TextEdit, TextStyle, Ui};

use crate::diag::{Diag, DiagError};
use crate::i18n::{Key, t, t_fmt};
use crate::rt::{AppMessage, CoreCmd, CorePhase, JobKind, RuntimeEntryView, RuntimeStateView};
use crate::ui::UiCtx;
use crate::ui::gate::{Rung, verdict};
use crate::ui::request::{Request, Terminal};

enum PreviewState {
    NoLaunch,
    Available(String),
    Unavailable(AppMessage),
}

/// The preview screen's two faces: the exact launched config (intent) and
/// the live runtime state read through the control plane (fact).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum PreviewTab {
    #[default]
    Config,
    Runtime,
}

pub struct ProfilePreviewScreen {
    state: PreviewState,
    tab: PreviewTab,
    /// Runtime state shown on the Runtime tab; `None` = nothing loaded yet.
    runtime: Option<Result<RuntimeStateView, DiagError>>,
    /// In-flight `ListRuntimeState` reply channel; only one request at a
    /// time (idle while none is in flight).
    pending_request: Request<Result<RuntimeStateView, DiagError>>,
}

impl Default for ProfilePreviewScreen {
    fn default() -> Self {
        Self {
            state: PreviewState::NoLaunch,
            tab: PreviewTab::Config,
            runtime: None,
            pending_request: Request::default(),
        }
    }
}

impl ProfilePreviewScreen {
    /// Adopt one launch result: the exact committed configuration, or the
    /// keyed failure the display boundary renders in the active language.
    pub(crate) fn record_start(&mut self, snapshot: Result<String, AppMessage>) {
        self.state = match snapshot {
            Ok(contents) => PreviewState::Available(contents),
            Err(error) => PreviewState::Unavailable(error),
        };
    }

    /// Drop the cached runtime view and any in-flight request — a phase
    /// change means a new core session (restart or commit), so rows from
    /// the previous session would misrepresent what is actually bound and
    /// dialing. The launched-config text (intent) survives; only the
    /// runtime facts (what `ListInbounds`/`ListOutbounds` reported) die.
    /// Clearing the pending field drops the request's receiver, so a
    /// superseded result is discarded with no re-send.
    pub(crate) fn invalidate_runtime(&mut self) {
        self.runtime = None;
        self.pending_request.cancel();
    }

    pub fn show(&mut self, ui: &mut Ui, ctx: &mut UiCtx) {
        let lang = ctx.settings.language;
        ui.heading(t(lang, Key::Preview));

        // Consume the runtime-state reply for the in-flight request, if it
        // has landed. A phase change discards the request instead
        // (`invalidate_runtime` drops the request, so a superseded result
        // can never land).
        match self.pending_request.poll() {
            Some(Terminal::Answered(result)) => self.runtime = Some(result),
            // Defensive: the runtime's reply guard always sends a terminal
            // before the sender drops.
            Some(Terminal::Exited) | None => {}
        }

        ui.horizontal(|ui| {
            ui.selectable_value(
                &mut self.tab,
                PreviewTab::Config,
                t(lang, Key::PreviewConfigTab),
            );
            ui.selectable_value(
                &mut self.tab,
                PreviewTab::Runtime,
                t(lang, Key::PreviewRuntimeTab),
            );
        });

        match self.tab {
            PreviewTab::Config => self.config_tab(ui, lang, ctx.phase),
            PreviewTab::Runtime => self.runtime_tab(ui, ctx, lang),
        }
    }

    fn config_tab(
        &mut self,
        ui: &mut Ui,
        lang: crate::model::settings::Language,
        phase: &CorePhase,
    ) {
        match &self.state {
            PreviewState::NoLaunch => {
                ui.label(t(lang, Key::PreviewNoLaunch));
            }
            PreviewState::Available(contents) => {
                ui.label(phase_label(lang, phase));
                ui.colored_label(
                    crate::ui::status::status_colors_of(ui).err,
                    t(lang, Key::PreviewCredentialsWarning),
                );
                let label = ui.label(t(lang, Key::PreviewActiveConfig));
                ScrollArea::both().show(ui, |ui| {
                    let mut text = contents.as_str();
                    ui.add(
                        TextEdit::multiline(&mut text)
                            .font(TextStyle::Monospace)
                            .desired_width(f32::INFINITY),
                    )
                    .labelled_by(label.id);
                });
            }
            PreviewState::Unavailable(error) => {
                ui.colored_label(
                    crate::ui::status::status_colors_of(ui).err,
                    t_fmt(lang, Key::PreviewLoadFailed, &[&error.text(lang)]),
                );
            }
        }
    }

    fn runtime_tab(
        &mut self,
        ui: &mut Ui,
        ctx: &mut UiCtx,
        lang: crate::model::settings::Language,
    ) {
        // The runtime-state read runs regardless of the busy window, which is
        // exactly the rule this kind declares: the ladder's window rung comes
        // from that rule instead of being stated here.
        let gate = verdict(
            matches!(ctx.phase, CorePhase::Running),
            ctx.busy.blocks(JobKind::RuntimeState),
            self.pending_request.is_pending(),
        );
        let refresh = egui::Button::new(t(lang, Key::RuntimeRefresh));
        if ui.add_enabled(gate.enabled, refresh).clicked() {
            let (reply, receiver) = tokio::sync::oneshot::channel();
            if ctx.cmd.send(CoreCmd::ListRuntimeState { reply }).is_err() {
                self.runtime = Some(Err(DiagError::from(Diag::new(Key::RuntimeChannelClosed))));
            } else {
                self.pending_request = Request::reply(receiver);
            }
        }

        if matches!(gate.rung, Rung::NotRunning) {
            ui.colored_label(
                crate::ui::status::status_colors_of(ui).warn,
                t(lang, Key::RuntimeNotRunning),
            );
            return;
        }
        match &self.runtime {
            None => {}
            Some(Err(error)) => {
                ui.colored_label(
                    ui.visuals().error_fg_color,
                    t_fmt(lang, Key::RuntimeLoadFailed, &[&error.text(lang)]),
                );
            }
            Some(Ok(view)) => {
                ui.heading(t(lang, Key::RuntimeInbounds));
                Self::entry_grid(ui, "runtime-inbounds", lang, &view.inbounds);
                ui.heading(t(lang, Key::RuntimeOutbounds));
                Self::entry_grid(ui, "runtime-outbounds", lang, &view.outbounds);
            }
        }
    }

    fn entry_grid(
        ui: &mut Ui,
        id_salt: &str,
        lang: crate::model::settings::Language,
        entries: &[RuntimeEntryView],
    ) {
        if entries.is_empty() {
            ui.label(t(lang, Key::RuntimeEmpty));
            return;
        }
        egui::Grid::new(id_salt)
            .num_columns(2)
            .striped(true)
            .show(ui, |ui| {
                ui.strong(t(lang, Key::GridTag));
                ui.strong(t(lang, Key::GridType));
                ui.end_row();
                for entry in entries {
                    ui.monospace(&entry.tag);
                    if entry.kind.is_empty() {
                        ui.label(t(lang, Key::EmDash));
                    } else {
                        ui.label(&entry.kind);
                    }
                    ui.end_row();
                }
            });
    }
}

fn phase_label(lang: crate::model::settings::Language, phase: &CorePhase) -> String {
    match phase {
        CorePhase::Running => t(lang, Key::PreviewPhaseRunning),
        _ => t(lang, Key::PreviewPhaseStopped),
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::{PreviewTab, ProfilePreviewScreen, Request, phase_label};
    use crate::diag::DiagError;
    use crate::i18n::{Key, t};
    use crate::model::settings::Language;
    use crate::rt::{CoreCmd, CorePhase, RuntimeStateView};
    use crate::ui::test_rig::UiTestRig;
    use egui_kittest::{Harness, kittest::Queryable as _};
    use tokio::sync::oneshot;

    #[test]
    fn fresh_screen_starts_on_config_tab_with_no_launch_state() {
        let screen = ProfilePreviewScreen::default();
        assert_eq!(screen.tab, PreviewTab::Config);
        assert!(matches!(screen.state, super::PreviewState::NoLaunch));
        assert!(!screen.pending_request.is_pending());
    }

    #[test]
    fn profile_preview_replaces_and_retains_latest_started_config() {
        let mut screen = ProfilePreviewScreen::default();
        screen.record_start(Ok("first config".into()));
        match &screen.state {
            super::PreviewState::Available(contents) => assert_eq!(contents, "first config"),
            _ => panic!("expected available preview"),
        }
        screen.record_start(Ok("second config".into()));
        match &screen.state {
            super::PreviewState::Available(contents) => assert_eq!(contents, "second config"),
            _ => panic!("expected available preview"),
        }
    }

    #[test]
    fn phase_change_invalidation_drops_runtime_facts_but_keeps_config_text() {
        let mut screen = ProfilePreviewScreen::default();
        screen.record_start(Ok("launched config".into()));
        screen.runtime = Some(Ok(crate::rt::RuntimeStateView {
            inbounds: vec![],
            outbounds: vec![],
        }));
        // A real in-flight reply channel: the phase change must drop it
        // (a superseded result is discarded, never landed and never
        // re-sent).
        let (_, receiver) = oneshot::channel::<Result<RuntimeStateView, DiagError>>();
        screen.pending_request = Request::reply(receiver);

        screen.invalidate_runtime();

        assert!(
            screen.runtime.is_none(),
            "runtime facts die with the session"
        );
        assert!(
            !screen.pending_request.is_pending(),
            "an in-flight request must not land into the new session"
        );
        match &screen.state {
            super::PreviewState::Available(contents) => {
                assert_eq!(contents, "launched config", "the config text survives")
            }
            _ => panic!("expected available preview"),
        }
    }

    #[test]
    fn phase_label_matches_phase() {
        assert_eq!(
            phase_label(Language::En, &CorePhase::Running),
            crate::i18n::t(Language::En, crate::i18n::Key::PreviewPhaseRunning)
        );
        assert_eq!(
            phase_label(Language::En, &CorePhase::Stopped),
            crate::i18n::t(Language::En, crate::i18n::Key::PreviewPhaseStopped)
        );
    }

    /// The Runtime-tab refresh opens a per-request reply channel.
    /// Sending an empty runtime view on the captured sender must land in
    /// the screen and render the empty-state label — no bus, no event.
    #[test]
    fn refresh_click_captures_reply_channel_and_renders_runtime_state() {
        let rig = UiTestRig {
            phase: CorePhase::Running,
            ..UiTestRig::default()
        };
        let mut harness = Harness::new_ui_state(
            |ui, state: &mut (ProfilePreviewScreen, UiTestRig)| {
                state.0.show(ui, &mut state.1.ctx());
            },
            (ProfilePreviewScreen::default(), rig),
        );
        harness.run();
        harness
            .get_by_label(t(Language::En, Key::PreviewRuntimeTab))
            .click();
        harness.run();
        harness
            .get_by_label(t(Language::En, Key::RuntimeRefresh))
            .click();
        harness.run();

        // The click must send exactly one ListRuntimeState command carrying
        // the request channel; tests hold the sender and reply as the
        // runtime would.
        let reply = {
            let cmd = harness
                .state_mut()
                .1
                ._cmd_rx
                .try_recv()
                .expect("the refresh click must send a command");
            if let CoreCmd::ListRuntimeState { reply } = cmd {
                reply
            } else {
                panic!("expected ListRuntimeState, got a different command");
            }
        };
        assert!(
            harness.state().0.pending_request.is_pending(),
            "the pending slot must hold the request"
        );

        let empty_view = RuntimeStateView {
            inbounds: vec![],
            outbounds: vec![],
        };
        reply
            .send(Ok(empty_view.clone()))
            .expect("the screen must listen for the reply");
        harness.run();

        assert!(
            !harness.state().0.pending_request.is_pending(),
            "a landed reply must clear the pending slot"
        );
        assert!(
            matches!(&harness.state().0.runtime, Some(Ok(view)) if *view == empty_view),
            "the landed runtime view must be adopted as the rendered state"
        );
        let empty = t(Language::En, Key::RuntimeEmpty);
        assert!(
            harness
                .query_all_by(|n| n.value().is_some_and(|v| v.contains(empty)))
                .next()
                .is_some(),
            "the empty-state label must render for an empty view"
        );
    }
}
