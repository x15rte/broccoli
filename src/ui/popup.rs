//! The app's pop-up windows, one window each.
//!
//! A window opened through [`show`] is an egui *immediate viewport*: the
//! platform gives it an OS window, so the user can drag it outside the main
//! window and onto another monitor, while its content is still drawn from the
//! frame that owns the state behind it. A backend with no viewports to give
//! (the headless UI harness) folds the call back into its parent instead, and
//! the same body renders in a floating window inside the main one — which is
//! what the tests drive, so one body serves both.
//!
//! [`show`] owns the window's presentation only: the caller keeps the title,
//! the body, and the state that decides whether the window exists, so one place
//! still owns each fact. [`modal`] is the other half of the app's dialogs: a
//! confirmation stays in the window it asks about, dimming it and blocking it,
//! instead of opening a window of its own.

use egui::{Context, Id, Ui, ViewportBuilder, ViewportId};

/// Render the pop-up window `key` (titled `title`) for one frame, drawing
/// `body` inside it.
///
/// `key` identifies the window across frames; two windows shown in the same
/// frame need different keys, and the same window keeps its key for the whole
/// session — that key is what preserves its placement and size while it stays
/// open.
///
/// `size` is the initial inner size in points and `resizable` the window's
/// resize affordance, both applied when the window is created: from then on the
/// platform owns the geometry, so a window the user moved or resized keeps what
/// they gave it, and a window that closed starts from `size` again when it is
/// opened next.
///
/// Returns whether the platform asked for the window to close — its title-bar
/// close button or Alt+F4. That request is the pop-up's counterpart of the
/// in-window close button, so the caller decides what closing means for its own
/// state, and the window exists exactly while the caller renders it. A caller
/// that cannot close yet (one waiting on a validation it started) ignores the
/// request, and the window comes back next frame.
///
/// The window's client area is painted like a screen of the app — its
/// background, its margins — because nothing else paints it: a window of its
/// own has the platform's background behind the app wherever the body is
/// shorter than the window.
pub(crate) fn show(
    ctx: &Context,
    key: impl egui::AsIdSalt,
    title: &str,
    size: [f32; 2],
    resizable: bool,
    mut body: impl FnMut(&mut Ui),
) -> bool {
    let viewport_id = ViewportId::from_hash_of(key);
    let mut close_requested = false;
    ctx.show_viewport_immediate(
        viewport_id,
        ViewportBuilder::default()
            .with_title(title)
            .with_inner_size(size)
            .with_resizable(resizable),
        |ui, _class| {
            // A close request is not echoed back at the window: the caller
            // dropped it from this frame on, and the next frame's render is
            // what the request removes.
            if ui.input(|input| input.viewport().close_requested()) {
                close_requested = true;
            } else {
                // The window's size is the platform's and fixed by the caller's
                // `size`, while a body can outgrow it — a taller translation, a
                // transcript, a validation report — so the body scrolls here.
                // That is the reachability the in-window panel got for free by
                // growing with its content, in one place instead of in every
                // body.
                let mut scroll = |ui: &mut Ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("popup-body")
                        .show(ui, |ui| body(ui));
                };
                if ui.ctx().embed_viewports() {
                    // An embedded call renders inside an in-window
                    // `egui::Window`, whose own frame already paints the
                    // background a central panel would.
                    scroll(ui);
                } else {
                    // A window of its own is a client area nothing has painted:
                    // the platform's background would show through the app
                    // wherever the body is shorter than the window — eframe's
                    // default is a near-black gray — and the window would read
                    // as a hole in the app. A central panel is what a screen of
                    // this app looks like, so the window is filled and inset
                    // like one.
                    egui::CentralPanel::default().show(ui, |ui| scroll(ui));
                }
            }
        },
    );
    close_requested
}

/// Render the confirmation `key` (titled `title`) in `ctx`'s window for one
/// frame, drawing `body` inside it.
///
/// A confirmation belongs to the window it asks about, so it renders in that
/// window's own pass as an in-window modal: the window dims behind it and
/// nothing in it can be clicked, which is the modality an OS window cannot
/// give it — the platform knows no modal relationship between windows, and a
/// second window is one more thing for the user to find and close. Pass the
/// context of the window the confirmation belongs to: the app's own context
/// for a question about the main window, a pop-up's `ui.ctx()` for one about
/// that pop-up.
///
/// `width` is the modal's minimum width in points, so the content does not
/// collapse on a short title.
///
/// Returns whether the confirmation was declined — a click on the dimmed
/// window behind it, Escape, or a body that closed itself through
/// `Ui::close` — which the caller answers the same way as its Cancel button.
pub(crate) fn modal(
    ctx: &Context,
    key: impl egui::AsIdSalt,
    title: &str,
    width: f32,
    mut body: impl FnMut(&mut Ui),
) -> bool {
    // The key names the confirmation: two of them in one frame need different
    // keys, and the same one keeps its key across frames.
    let id = Id::unique(("popup-modal", key));
    egui::Modal::new(id)
        .show(ctx, |ui| {
            // The modal carries no chrome of its own, so the helper draws the
            // title the window it replaces would have carried.
            ui.set_min_width(width);
            ui.heading(title);
            ui.add_space(4.0);
            body(ui);
        })
        .should_close()
}

/// Dim and block `ctx`'s window for one frame, with no question of its own.
///
/// A confirmation that renders in a sibling window — the add-server editor's
/// question about the draft it holds — cannot reach the window that must also
/// stay modal behind it from inside its own pass: the app draws this backdrop
/// in that window instead, and the question renders in the sibling.
///
/// Returns whether the backdrop was clicked, which the caller answers the same
/// way as its Cancel button.
pub(crate) fn backdrop(ctx: &Context, key: impl egui::AsIdSalt) -> bool {
    // The backdrop is the dim and the modality and nothing else: `egui::Modal`'s
    // own popup frame around an empty body would leave a stray box in the middle
    // of the dimmed window, and a dead spot for the click that declines.
    egui::Modal::new(Id::unique(("popup-modal-backdrop", key)))
        .frame(egui::Frame::NONE)
        .show(ctx, |_| {})
        .should_close()
}

#[cfg(test)]
mod tests {
    use super::{backdrop, modal, show};
    use egui::{
        Context, Event, ImmediateViewport, Key, Modifiers, Pos2, RawInput, Rect, Shape,
        ViewportEvent, ViewportInfo,
    };
    use std::cell::RefCell;
    use std::rc::Rc;

    /// A press of `key`, the way the platform hands one to the window that has
    /// the keyboard.
    fn key_press(key: Key) -> Event {
        Event::Key {
            key,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: Modifiers::NONE,
        }
    }

    /// The screen the stand-in platform reports for a window, big enough to
    /// hold the windows the tests open.
    const SCREEN: Rect = Rect {
        min: Pos2::ZERO,
        max: Pos2 { x: 400.0, y: 300.0 },
    };

    /// Stand in for the platform: render one child viewport, with an input that
    /// carries the viewport's close request when `close_requested` and `events`
    /// as the keys and pointer the window received, and hand back the shapes the
    /// window drew.
    ///
    /// A backend that owns viewports calls back this way (the harness has none
    /// and folds the call into its parent instead), so this is the cheapest
    /// frame in which a platform close can be seen reaching the caller,
    /// in which a key the window has the keyboard for can be seen, and the only
    /// frame in which what a window of its own paints is visible.
    fn render(
        ctx: &Context,
        viewport: ImmediateViewport<'_>,
        events: Vec<Event>,
        close_requested: bool,
    ) -> Vec<Shape> {
        let id = viewport.ids.this;
        let mut info = ViewportInfo::default();
        if close_requested {
            info.events.push(ViewportEvent::Close);
        }
        let input = RawInput {
            viewport_id: id,
            viewports: core::iter::once((id, info)).collect(),
            system_theme: Some(egui::Theme::Light),
            screen_rect: Some(SCREEN),
            events,
            ..Default::default()
        };
        let mut callback = viewport.viewport_ui_cb;
        // The child's own output has no integration behind it here: its
        // texture deltas are dropped deliberately, the way a backend that
        // painted them would consume them.
        let mut output = ctx.run_ui(input, |ui| callback(ui));
        output.textures_delta.clear();
        output.shapes.into_iter().map(|shape| shape.shape).collect()
    }

    /// One frame of a window under test, against a backend that owns
    /// viewports: returns whether the close request reached the caller, and
    /// how many times the body ran.
    fn one_frame(close_requested: bool) -> (bool, usize) {
        let ctx = Context::default();
        ctx.set_embed_viewports(false);
        Context::set_immediate_viewport_renderer(move |ctx, viewport| {
            render(ctx, viewport, Vec::new(), close_requested);
        });

        let mut bodies = 0;
        let mut reported = false;
        let mut output = ctx.run_ui(RawInput::default(), |ui| {
            reported = show(
                ui.ctx(),
                "test.popup",
                "Pop-up",
                [200.0, 100.0],
                true,
                |ui| {
                    bodies += 1;
                    ui.label("body");
                },
            );
        });
        output.textures_delta.clear();
        (reported, bodies)
    }

    /// The platform's close request is the in-content Close button's twin: the
    /// caller is told, and a window that is going away draws no body.
    #[test]
    fn a_close_request_reaches_the_caller_without_drawing_the_body() {
        let (reported, bodies) = one_frame(true);

        assert!(reported, "the platform's close must reach the caller");
        assert_eq!(bodies, 0, "a window being closed draws no body");
    }

    /// The other half of the contract: without a close request nothing is
    /// reported and the body renders — a window that never reports is a window
    /// the user cannot close.
    #[test]
    fn a_frame_without_a_close_request_draws_the_body_and_reports_nothing() {
        let (reported, bodies) = one_frame(false);

        assert!(!reported, "an untouched frame reports nothing");
        assert_eq!(bodies, 1, "an open window draws its body once");
    }

    /// The window the confirmation renders in is the window the keyboard
    /// reaches, so Escape gets to it: a dismissal means the same as the
    /// dialog's own Cancel.
    #[test]
    fn escape_declines_the_confirmation() {
        let ctx = Context::default();
        let pass = |escape: bool| {
            let mut declined = None;
            let mut output = ctx.run_ui(
                RawInput {
                    screen_rect: Some(SCREEN),
                    events: if escape {
                        vec![key_press(Key::Escape)]
                    } else {
                        Vec::new()
                    },
                    ..Default::default()
                },
                |ui| {
                    declined = Some(modal(ui.ctx(), "test.confirm", "Confirm", 200.0, |ui| {
                        ui.label("body");
                    }));
                },
            );
            output.textures_delta.clear();
            declined
        };

        // The first pass is where the modal claims the topmost layer, and the
        // layer it claimed is published at that pass's end: from then on the
        // key reaches it, which is every frame a user could press Escape in.
        assert_eq!(
            pass(false),
            Some(false),
            "the confirmation is up before the key is pressed"
        );
        assert_eq!(
            pass(true),
            Some(true),
            "Escape in the confirmation's window must decline it"
        );
    }

    /// The app's own backdrop — what keeps a window modal behind a question
    /// that renders in a sibling window — is a dismissal like any other: the
    /// key that lands on the dimmed window reaches the caller, which answers it
    /// the way the question's own Cancel would.
    #[test]
    fn escape_in_the_backdrop_window_declines_it() {
        let ctx = Context::default();
        let pass = |escape: bool| {
            let mut dismissed = None;
            let mut output = ctx.run_ui(
                RawInput {
                    screen_rect: Some(SCREEN),
                    events: if escape {
                        vec![key_press(Key::Escape)]
                    } else {
                        Vec::new()
                    },
                    ..Default::default()
                },
                |ui| {
                    dismissed = Some(backdrop(ui.ctx(), "test.confirm"));
                },
            );
            output.textures_delta.clear();
            dismissed
        };

        assert_eq!(
            pass(false),
            Some(false),
            "the backdrop is up before the key is pressed"
        );
        assert_eq!(
            pass(true),
            Some(true),
            "Escape in the backdrop's window must decline it"
        );
    }

    /// A confirmation belongs to the window it asks about, so it opens no
    /// window of its own: it renders in the pass of the context it is handed,
    /// and a backend that owns viewports is never asked for one.
    #[test]
    fn a_confirmation_opens_no_window_of_its_own() {
        let ctx = Context::default();
        ctx.set_embed_viewports(false);
        let child_passes = Rc::new(RefCell::new(0usize));
        let counted = Rc::clone(&child_passes);
        Context::set_immediate_viewport_renderer(move |ctx, viewport| {
            *counted.borrow_mut() += 1;
            render(ctx, viewport, Vec::new(), false);
        });

        let mut bodies = 0;
        let mut declined = None;
        let mut output = ctx.run_ui(
            RawInput {
                screen_rect: Some(SCREEN),
                ..Default::default()
            },
            |ui| {
                declined = Some(modal(ui.ctx(), "test.confirm", "Confirm", 200.0, |ui| {
                    bodies += 1;
                    ui.label("body");
                }));
            },
        );
        output.textures_delta.clear();

        assert_eq!(
            *child_passes.borrow(),
            0,
            "a confirmation must open no window of its own"
        );
        assert_eq!(
            bodies, 1,
            "the confirmation's body renders in the pass it was handed"
        );
        assert_eq!(
            declined,
            Some(false),
            "an untouched confirmation declines nothing"
        );
    }

    /// A window of its own has a client area nothing else paints, so the helper
    /// paints it like a screen of the app: without that, the platform's
    /// background shows through wherever the body is shorter than the window,
    /// and the window reads as a hole in the app.
    #[test]
    fn the_windows_client_area_is_painted_like_a_screen_of_the_app() {
        let ctx = Context::default();
        ctx.set_embed_viewports(false);
        let shapes = Rc::new(RefCell::new(Vec::new()));
        let captured = Rc::clone(&shapes);
        Context::set_immediate_viewport_renderer(move |ctx, viewport| {
            *captured.borrow_mut() = render(ctx, viewport, Vec::new(), false);
        });

        let mut output = ctx.run_ui(
            RawInput {
                screen_rect: Some(SCREEN),
                ..Default::default()
            },
            |ui| {
                show(
                    ui.ctx(),
                    "test.popup",
                    "Pop-up",
                    [200.0, 100.0],
                    true,
                    |ui| {
                        ui.label("body");
                    },
                );
            },
        );
        output.textures_delta.clear();

        let fill = ctx.global_style().visuals.panel_fill;
        let painted = shapes.borrow().iter().any(|shape| match shape {
            Shape::Rect(rect) => rect.fill == fill && rect.rect.contains_rect(SCREEN),
            _ => false,
        });
        assert!(
            painted,
            "the window's client area must be filled with the app's background: {:?}",
            shapes.borrow().len()
        );
    }
}
