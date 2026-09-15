//! Dashboard: core state, mode switching, throughput plot, latency table.

use crate::i18n::{Key, t, t_fmt};
use crate::metrics::WorkCounter;
use crate::model::Mode;
use crate::model::settings::{Language, TrafficUnit};
use crate::rt::{CorePhase, DownloadState, OutboundStatusView};
use crate::ui::inbounds::protocol_label;
use crate::ui::status::{StatusColors, status_colors_of};
use crate::ui::{PhaseAction, UiCtx};

/// Throughput-plot series, rebuilt only when the stats generation advances
/// (a 1 Hz stats tick — the only way the history ring changes).
struct PlotCache {
    stats_generation: u64,
    up: Vec<egui_plot::PlotPoint>,
    down: Vec<egui_plot::PlotPoint>,
}

/// The memoized latency grid: one pass over profiles + observatory per
/// generation change, zero per-row lookups or formatting on idle frames.
/// The language is part of the key because the cached captions are
/// localized.
struct GridCache {
    key: (u64, bool, u64, Language),
    rows: Vec<LatencyRow>,
}

/// The memoized listener-traffic table, session totals line, sys-stats
/// memory line and the stats-block captions: formatted once per stats tick,
/// traffic-unit or language change, zero per-frame formatting on idle
/// frames — the same generation contract as the plot and latency caches.
struct InboundCache {
    key: (u64, TrafficUnit, Language),
    /// `(tag, up label, down label, up total label, down total label)` —
    /// per-tag rates and cumulative totals are formatted once per rebuild.
    rows: Vec<(String, String, String, String, String)>,
    /// The full memory line text (Alloc · Sys · live objects · GC).
    memory: Option<String>,
    /// The uptime caption (`h:mm:ss` under the `DashboardUptime` template)
    /// and the goroutines caption — inherently per-tick text, formatted in
    /// the same rebuild as the rows.
    uptime: Option<String>,
    goroutines: Option<String>,
}

/// One latency-grid row's memoized lookups and formatted text.
struct LatencyRow {
    name: String,
    tag: String,
    cell: LatencyCell,
    /// Row detail shortened to ≤ 60 chars, plus the full text for the hover
    /// and whether the label was truncated. The detail is the observatory's
    /// last error — with the probe child's diagnostics wall when one was
    /// captured — or the burst engine's window statistics.
    detail_short: String,
    detail_full: String,
    detail_truncated: bool,
}

/// The latency display resolution for one profile row.
enum LatencyCell {
    /// Observatory entry alive: show its live delay.
    Alive { delay_ms: i64, text: String },
    /// Observatory entry present but dead.
    DeadObservatory,
    /// No observatory entry; the profile carries a non-negative stale delay.
    Stale { ms: i64, text: String },
    /// No observatory entry; the profile's last probe was dead.
    DeadStale,
    /// No observatory entry and no recorded delay.
    Unknown,
}

#[derive(Default)]
pub struct DashboardScreen {
    /// Throughput-plot series, rebuilt only when the stats generation
    /// advances.
    plot_cache: Option<PlotCache>,
    /// Latency-grid rows, rebuilt only when `(config_revision, dirty,
    /// latency_generation, language)` advances.
    grid_cache: Option<GridCache>,
    /// Listener-traffic rows, the session totals and the memory line,
    /// rebuilt only when the stats generation, the traffic unit or the
    /// language changes.
    inbound_cache: Option<InboundCache>,
    /// Header-row labels (phase badge, endpoint rows, API-port line),
    /// rebuilt only when a phase/endpoint/persist/language/core-start
    /// change moved them.
    header_cache: Option<HeaderCache>,
}

impl DashboardScreen {
    /// The throughput series for this frame: cached, rebuilt only when the
    /// stats generation advanced — a stats tick is the only way the history
    /// ring changes. Bumps [`WorkCounter::PlotRebuilds`] once per rebuild,
    /// never per frame. The initial cache fill (a screen's first render) is
    /// a one-time seed, not a rebuild, so the counter stays at absolute zero
    /// on a fresh harness (the idle-frame purity contract).
    fn plot_series(&mut self, ctx: &UiCtx<'_>) -> &PlotCache {
        let generation = ctx.stats_generation;
        if !self
            .plot_cache
            .as_ref()
            .is_some_and(|cache| cache.stats_generation == generation)
        {
            let rebuild = self.plot_cache.is_some();
            let n = ctx.stats_history.len();
            let up = ctx
                .stats_history
                .iter()
                .enumerate()
                .map(|(i, s)| egui_plot::PlotPoint::new(i as f64 - n as f64, s.up as f64))
                .collect();
            let down = ctx
                .stats_history
                .iter()
                .enumerate()
                .map(|(i, s)| egui_plot::PlotPoint::new(i as f64 - n as f64, s.down as f64))
                .collect();
            self.plot_cache = Some(PlotCache {
                stats_generation: generation,
                up,
                down,
            });
            if rebuild {
                ctx.metrics.bump_work(WorkCounter::PlotRebuilds);
            }
        }
        self.plot_cache
            .as_ref()
            .expect("plot cache populated above")
    }

    /// The latency grid's memoized rows for this frame: one pass per
    /// `(config_revision, dirty, latency_generation, language)` change,
    /// zero per-row lookups or formatting on idle frames.
    fn latency_rows(&mut self, ctx: &UiCtx<'_>) -> &GridCache {
        let key = (
            ctx.config_revision,
            *ctx.dirty,
            ctx.latency_generation,
            ctx.settings.language,
        );
        if !self
            .grid_cache
            .as_ref()
            .is_some_and(|cache| cache.key == key)
        {
            self.grid_cache = Some(GridCache {
                key,
                rows: build_latency_rows(ctx),
            });
        }
        self.grid_cache
            .as_ref()
            .expect("grid cache populated above")
    }

    /// The listener-traffic rows, session totals line and sys-stats memory
    /// line for this frame: formatted once per stats tick or traffic-unit
    /// change, zero per-frame formatting on idle frames (the same
    /// generation contract as the plot and latency caches). The rows are
    /// the dynamic tag set from the core's `inbound>>>` counters — no
    /// coupling to the generated config.
    fn inbound_cache(&mut self, ctx: &UiCtx<'_>) -> &InboundCache {
        let key = (
            ctx.stats_generation,
            ctx.settings.traffic_unit,
            ctx.settings.language,
        );
        if !self
            .inbound_cache
            .as_ref()
            .is_some_and(|cache| cache.key == key)
        {
            let lang = ctx.settings.language;
            let unit = ctx.settings.traffic_unit;
            // t_fmt takes &[&dyn Display]; a bare `&str` element does not
            // coerce (str: Display is absent), so pass a double reference —
            // same shape as the other t_fmt call sites.
            let (rows, memory, uptime, goroutines) = match &ctx.stats {
                Some(s) => {
                    // The stats contract keeps both vectors sorted by tag
                    // with the same tag set, so a single zip walk pairs
                    // totals to rows; a divergence is caught in debug
                    // builds instead of surfacing as silently-zero totals.
                    let mut totals_iter = s.per_inbound_totals.iter();
                    let rows = s
                        .per_inbound
                        .iter()
                        .map(|(tag, up, down)| {
                            let (total_up, total_down) = match totals_iter.next() {
                                Some((t, total_up, total_down)) if t == tag => {
                                    (*total_up, *total_down)
                                }
                                other => {
                                    debug_assert!(
                                        false,
                                        "per_inbound and per_inbound_totals diverged at tag \
                                             {tag:?}, next totals row {other:?}"
                                    );
                                    (0, 0)
                                }
                            };
                            (
                                tag.clone(),
                                t_fmt(lang, Key::DashboardRateUp, &[&format_bytes(*up, unit)]),
                                t_fmt(lang, Key::DashboardRateDown, &[&format_bytes(*down, unit)]),
                                format!("↑ {}", format_bytes(total_up, unit)),
                                format!("↓ {}", format_bytes(total_down, unit)),
                            )
                        })
                        .collect();
                    debug_assert!(
                        totals_iter.next().is_none(),
                        "per_inbound_totals carries tags per_inbound lacks"
                    );
                    (
                        rows,
                        Some(t_fmt(
                            lang,
                            Key::DashboardMemory,
                            &[
                                &format_bytes(s.alloc_bytes, unit),
                                &format_bytes(s.sys_bytes, unit),
                                &s.live_objects,
                                &s.num_gc,
                            ],
                        )),
                        Some(t_fmt(
                            lang,
                            Key::DashboardUptime,
                            &[&human_uptime(s.uptime_secs)],
                        )),
                        Some(t_fmt(lang, Key::DashboardGoroutines, &[&s.goroutines])),
                    )
                }
                None => (Vec::new(), None, None, None),
            };
            self.inbound_cache = Some(InboundCache {
                key,
                rows,
                memory,
                uptime,
                goroutines,
            });
        }
        self.inbound_cache
            .as_ref()
            .expect("inbound cache populated above")
    }

    /// The header-row labels for this frame (phase badge, per-endpoint
    /// status rows, API-port line): formatted only when a phase transition,
    /// an endpoint-list change, a persist, a language change or a core
    /// start moved them — never on repaint frames. The
    /// status word inside each endpoint caption is phase-derived, so the
    /// phase is part of the key (variant + payload, compared explicitly).
    fn header_cache(&mut self, ctx: &UiCtx<'_>) -> &HeaderCache {
        let lang = ctx.settings.language;
        let dirty = *ctx.dirty;
        let stale = match &self.header_cache {
            Some(cache) => {
                cache.lang != lang
                    || cache.config_revision != ctx.config_revision
                    || cache.dirty != dirty
                    || !same_phase(&cache.phase, ctx.phase)
            }
            None => true,
        };
        if stale {
            let phase = ctx.phase.clone();
            let badge = phase_badge_text(ctx.phase, lang);
            let endpoints = ctx
                .settings
                .local_inbounds
                .iter()
                .map(|entry| {
                    let status = listener_status(ctx.phase, entry.enabled);
                    let word = match status {
                        ListenerStatus::Up => t(lang, Key::LocalStatusUp),
                        ListenerStatus::Starting => t(lang, Key::LocalStatusStarting),
                        ListenerStatus::Down => t(lang, Key::LocalStatusDown),
                        ListenerStatus::Disabled => t(lang, Key::LocalStatusDisabled),
                    };
                    (
                        t_fmt(
                            lang,
                            Key::EndpointRow,
                            &[
                                &protocol_label(lang, entry.protocol),
                                &format!("{}:{}", entry.listen, entry.port),
                                &word,
                            ],
                        ),
                        status,
                    )
                })
                .collect();
            self.header_cache = Some(HeaderCache {
                phase,
                config_revision: ctx.config_revision,
                dirty,
                lang,
                badge,
                endpoints,
            });
        }
        self.header_cache
            .as_ref()
            .expect("header cache populated above")
    }

    pub fn show(&mut self, ui: &mut egui::Ui, ctx: &mut UiCtx) {
        egui::ScrollArea::vertical()
            .id_salt("dashboard-scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add_space(6.0);

                // State + connect row.
                ui.horizontal(|ui| {
                    let lang = ctx.settings.language;
                    // The badge caption is memoized with the other
                    // header-row labels; the dot color is a
                    // cheap per-phase lookup.
                    ui.colored_label(phase_badge_color(ctx.phase, status_colors_of(ui)), "●");
                    ui.heading(&self.header_cache(ctx).badge);
                    let action = PhaseAction::for_phase(ctx.phase);
                    match action {
                        PhaseAction::Disconnect | PhaseAction::CancelRetry => {
                            if ui.button(action.label(lang)).clicked() {
                                ctx.request_stop();
                            }
                        }
                        PhaseAction::Connect => {
                            // One verdict owner: the shell's per-revision
                            // generation. Its reason enables the button and
                            // supplies the hover text, and its stored
                            // generation error is the inline label. The
                            // screen never generates — that binds an
                            // ephemeral control-plane port, so it stays on
                            // the shell's boot and persist paths.
                            let blocked = ctx.connect_blocked_reason.as_deref();
                            if ui
                                .add_enabled(
                                    blocked.is_none(),
                                    egui::Button::new(action.label(lang)),
                                )
                                .on_disabled_hover_text(
                                    blocked.unwrap_or(t(lang, Key::ConnectUnavailable)),
                                )
                                .clicked()
                            {
                                ctx.request_connect();
                            }
                            if let Some(error) = ctx.config_error.as_deref() {
                                ui.colored_label(status_colors_of(ui).err, error);
                            }
                        }
                    }
                    if let DownloadState::Working { stage, done, total } = &ctx.download {
                        ui.separator();
                        let stage_text = stage.text(lang);
                        let bar = if *total > 0 {
                            egui::ProgressBar::new(*done as f32 / *total as f32).text(t_fmt(
                                lang,
                                Key::DashboardDownloadProgress,
                                &[&stage_text, &done, &total],
                            ))
                        } else {
                            egui::ProgressBar::new(0.0).text(stage_text)
                        };
                        ui.add(bar);
                    } else if let DownloadState::Failed(error) = &ctx.download {
                        ui.colored_label(
                            status_colors_of(ui).err,
                            t_fmt(lang, Key::DashboardDownloadFailed, &[&error.text(lang)]),
                        );
                    }
                });
                ui.add_space(8.0);

                // Mode radio.
                ui.horizontal(|ui| {
                    let lang = ctx.settings.language;
                    ui.label(t(lang, Key::DashboardNetworkMode));
                    let mode = ctx.settings.mode;
                    if ui
                        .selectable_label(mode == Mode::Off, t(lang, Key::Off))
                        .clicked()
                        && ctx.settings.set_mode(Mode::Off)
                    {
                        ctx.mark_dirty();
                    }
                    let tun = ui
                        .selectable_label(mode == Mode::Tun, t(lang, Key::Tun))
                        .on_hover_text(if ctx.is_elevated {
                            t(lang, Key::DashboardTunHoverElevated)
                        } else {
                            t(lang, Key::DashboardTunHoverNotElevated)
                        });
                    if tun.clicked() && ctx.settings.set_mode(Mode::Tun) {
                        ctx.mark_dirty();
                    }
                });
                ui.add_space(4.0);

                // Local-endpoint status row: the managed
                // SOCKS/HTTP inbounds remain loopback endpoints other
                // applications can point at. Status is derived from the
                // core phase and settings only — never probed.
                ui.label(
                    egui::RichText::new(t(ctx.settings.language, Key::DashboardLocalEndpoints))
                        .weak()
                        .small(),
                );
                // The status chips must wrap onto new lines when the window
                // is narrow — a plain horizontal row overflows and widens the
                // whole scroll content, which also clips the stats row below
                // (user report: the uptime/goroutines/mem info vanished on a
                // narrow window).
                ui.horizontal_wrapped(|ui| {
                    let lang = ctx.settings.language;
                    let colors = status_colors_of(ui);
                    let tun = tun_status(ctx.phase, (ctx.settings.mode, ctx.is_elevated));
                    let tun_word = match tun {
                        TunStatus::Active => t(lang, Key::TunStatusActive),
                        TunStatus::Elevation => t(lang, Key::TunStatusElevation),
                        TunStatus::Off => t(lang, Key::TunStatusOff),
                        TunStatus::Starting => t(lang, Key::LocalStatusStarting),
                        TunStatus::Down => t(lang, Key::LocalStatusDown),
                    };
                    let tun_color = match tun {
                        TunStatus::Active => colors.ok,
                        TunStatus::Elevation | TunStatus::Starting => colors.warn,
                        TunStatus::Off => ui.visuals().weak_text_color(),
                        TunStatus::Down => colors.err,
                    };
                    // Elevation is the one status whose label needs its
                    // reason explained; every other item carries the row
                    // hint.
                    let tun_hint = match tun {
                        TunStatus::Elevation => t(lang, Key::DashboardTunHoverNotElevated),
                        _ => t(lang, Key::DashboardEndpointHint),
                    };
                    ui.colored_label(tun_color, t_fmt(lang, Key::TunStatus, &[&tun_word]))
                        .on_hover_text(tun_hint);
                    // One status row per local endpoint, in list order.
                    // The captions are pre-rendered with the
                    // header cache on the same key (phase + endpoint list),
                    // so idle frames only re-derive the cheap status color.
                    let endpoints = &self.header_cache(ctx).endpoints;
                    for (label, status) in endpoints {
                        let color = match status {
                            ListenerStatus::Up => colors.ok,
                            ListenerStatus::Starting => colors.warn,
                            ListenerStatus::Down => colors.err,
                            ListenerStatus::Disabled => ui.visuals().weak_text_color(),
                        };
                        ui.colored_label(color, label)
                            .on_hover_text(t(lang, Key::DashboardEndpointHint));
                    }
                });
                ui.add_space(4.0);

                // Active server. The selected caption is the active
                // profile's name — an O(n) borrow (no allocation) with the
                // same fallback as the label always had.
                ui.horizontal(|ui| {
                    let lang = ctx.settings.language;
                    ui.label(t(lang, Key::DashboardActiveServer));
                    let cur = match ctx.servers.active.as_deref() {
                        Some(id) => ctx
                            .servers
                            .profiles
                            .iter()
                            .find(|p| p.id == id)
                            .map_or(t(lang, Key::NoneSelected), |p| p.name.as_str()),
                        None => t(lang, Key::NoneSelected),
                    };
                    egui::ComboBox::from_id_salt("active-server")
                        .selected_text(cur)
                        .show_ui(ui, |ui| {
                            // The popup reads the profile list and writes
                            // the selection slot — two disjoint fields of
                            // the same model borrow — by deferring the
                            // click to a row index. Only the chosen id is
                            // cloned, on the click, instead of an
                            // (id, name) pair per profile per open-popup
                            // frame.
                            let mut picked = None;
                            for (index, profile) in ctx.servers.profiles.iter().enumerate() {
                                let selected =
                                    ctx.servers.active.as_deref() == Some(profile.id.as_str());
                                if ui
                                    .selectable_label(selected, profile.name.as_str())
                                    .clicked()
                                {
                                    picked = Some(index);
                                }
                            }
                            if let Some(index) = picked {
                                // The active profile is the list's first row
                                // (the config's default route), so picking it
                                // moves it there.
                                let id = ctx.servers.profiles[index].id.clone();
                                ctx.servers.activate(&id);
                                ctx.mark_dirty();
                            }
                        });
                });
                ui.separator();

                // Live stats + plot. The stats captions must wrap onto new
                // lines when the window is too narrow — a plain horizontal
                // row clips them at the right edge (user report: the
                // uptime/goroutines/mem info vanished on a narrow window).
                ui.horizontal_wrapped(|ui| {
                    let lang = ctx.settings.language;
                    // Traffic-unit selector: the memoized rows, session
                    // totals and plot axis re-render on change (their cache
                    // keys include the unit).
                    ui.label(t(lang, Key::DashboardTrafficUnits));
                    let unit = ctx.settings.traffic_unit;
                    egui::ComboBox::from_id_salt("traffic-unit")
                        .selected_text(t(lang, traffic_unit_label_key(unit)))
                        .show_ui(ui, |ui| {
                            for value in TRAFFIC_UNITS {
                                if ui
                                    .selectable_label(
                                        unit == value,
                                        t(lang, traffic_unit_label_key(value)),
                                    )
                                    .clicked()
                                {
                                    ctx.settings.traffic_unit = value;
                                    // Display preference: persisted, but
                                    // never raises the Apply gate.
                                    ctx.mark_ui_dirty();
                                }
                            }
                        });
                    ui.separator();
                    // The cache reads the current unit internally, so a
                    // same-frame unit change applies immediately.
                    let inbound_cache = self.inbound_cache(ctx);
                    if ctx.stats.is_some() {
                        // Uptime/goroutines/memory captions ride the inbound
                        // cache's stats-tick rebuild. The
                        // aggregate rates live in the top bar now
                        // (ui::topbar); the sys-stats surface costs no
                        // extra RPCs — the 1 Hz tick already fetches the
                        // whole struct.
                        if let Some(uptime) = &inbound_cache.uptime {
                            ui.label(uptime);
                        }
                        if let Some(goroutines) = &inbound_cache.goroutines {
                            ui.label(goroutines);
                        }
                        if let Some(memory) = &inbound_cache.memory {
                            ui.label(memory);
                        }
                    } else {
                        let copy = match &ctx.phase {
                            CorePhase::Starting => t(lang, Key::DashboardNoStatsStarting),
                            CorePhase::Running => t(lang, Key::DashboardNoStatsRunning),
                            CorePhase::Stopped => t(lang, Key::DashboardNoStatsStopped),
                            CorePhase::NoConfig => t(lang, Key::DashboardNoStatsNoConfig),
                            CorePhase::Backoff { .. } => t(lang, Key::DashboardNoStatsBackoff),
                            CorePhase::Error(_) => t(lang, Key::DashboardNoStatsError),
                        };
                        ui.label(copy);
                    }
                });
                // The session totals live in the dashboard's inbound table
                // total columns now; the top bar carries the aggregate
                // rates (ui::topbar). The stats row only carries
                // uptime/goroutines/memory.
                let lang = ctx.settings.language;
                let unit = ctx.settings.traffic_unit;
                let plot_cache = self.plot_series(ctx);
                // Explicit global id: `PlotMemory` is keyed by it, so the
                // chart's bounds are observable from tests (and the id no
                // longer shifts when the surrounding layout changes).
                // Pan/zoom/scroll interactions are disabled: egui_plot's
                // automatic bounds are sticky — any translate, zoom or
                // wheel-scroll flips `PlotMemory.auto_bounds` to false
                // permanently (only a double-click restores it), freezing
                // the Y zoom at the peak scale once a spike passes. A live
                // throughput chart must always auto-fit its window instead.
                egui_plot::Plot::new("throughput")
                    .id(egui::Id::new("throughput-chart"))
                    .height(160.0)
                    .include_y(0.0)
                    .allow_drag(false)
                    .allow_zoom(false)
                    .allow_scroll(false)
                    .allow_boxed_zoom(false)
                    .allow_axis_zoom_drag(false)
                    .legend(egui_plot::Legend::default())
                    .x_axis_label(t(lang, Key::DashboardPlotSecondsAgo))
                    .y_axis_label(y_axis_label_for(unit, lang))
                    .y_axis_formatter(move |mark, _range| format_axis(mark.value, unit))
                    .coordinates_formatter(
                        egui_plot::Corner::LeftBottom,
                        egui_plot::CoordinatesFormatter::new(move |coord, _bounds| {
                            let x = coord.x;
                            format!("{x:.0}s · {}", format_rate(coord.y as u64, unit))
                        }),
                    )
                    .show(ui, |plot| {
                        plot.line(egui_plot::Line::new(
                            t(lang, Key::PlotUp),
                            egui_plot::PlotPoints::Borrowed(&plot_cache.up),
                        ));
                        plot.line(egui_plot::Line::new(
                            t(lang, Key::PlotDown),
                            egui_plot::PlotPoints::Borrowed(&plot_cache.down),
                        ));
                    });
                ui.separator();

                // Latency table.
                let lang = ctx.settings.language;
                ui.heading(t(lang, Key::Servers));
                if ctx.servers.profiles.is_empty() {
                    ui.label(t(lang, Key::DashboardNoServers));
                } else {
                    let grid = self.latency_rows(ctx);
                    egui::Grid::new("latency-grid")
                        .num_columns(4)
                        .striped(true)
                        .show(ui, |ui| {
                            ui.strong(t(lang, Key::GridName));
                            ui.strong(t(lang, Key::GridTag));
                            ui.strong(t(lang, Key::GridLatency));
                            ui.strong(t(lang, Key::GridDetail));
                            ui.end_row();
                            let colors = status_colors_of(ui);
                            for row in &grid.rows {
                                ui.label(&row.name);
                                ui.monospace(&row.tag);
                                match &row.cell {
                                    LatencyCell::Alive { delay_ms, text } => {
                                        ui.colored_label(latency_color(*delay_ms, colors), text);
                                    }
                                    LatencyCell::DeadObservatory | LatencyCell::DeadStale => {
                                        ui.colored_label(colors.err, t(lang, Key::Dead));
                                    }
                                    LatencyCell::Stale { ms, text } => {
                                        ui.colored_label(latency_color(*ms, colors), text);
                                    }
                                    LatencyCell::Unknown => {
                                        ui.label(t(lang, Key::EmDash));
                                    }
                                }
                                let response = ui.label(&row.detail_short);
                                if row.detail_truncated {
                                    response.on_hover_text(&row.detail_full);
                                }
                                ui.end_row();
                            }
                        });
                }

                // Listener traffic (per-inbound rates and cumulative
                // totals), rendered from the memoized per-tick rows.
                let inbound_rows = &self.inbound_cache(ctx).rows;
                if !inbound_rows.is_empty() {
                    ui.separator();
                    let lang = ctx.settings.language;
                    ui.heading(t(lang, Key::DashboardInboundTraffic));
                    egui::Grid::new("inbound-traffic-grid")
                        .num_columns(5)
                        .striped(true)
                        .show(ui, |ui| {
                            ui.strong(t(lang, Key::GridTag));
                            ui.strong(t(lang, Key::GridUp));
                            ui.strong(t(lang, Key::GridDown));
                            ui.strong(t(lang, Key::GridUpTotal));
                            ui.strong(t(lang, Key::GridDownTotal));
                            ui.end_row();
                            for (tag, up, down, up_total, down_total) in inbound_rows {
                                ui.monospace(tag);
                                ui.label(up);
                                ui.label(down);
                                ui.label(up_total);
                                ui.label(down_total);
                                ui.end_row();
                            }
                        });
                }
            });
    }
}

fn truncate_chars(value: &str, max_chars: usize) -> (String, bool) {
    let mut chars = value.chars();
    let short = chars.by_ref().take(max_chars).collect();
    (short, chars.next().is_some())
}
/// One pass over profiles + observatory: per-row lookup, latency formatting,
/// and detail truncation for the latency grid. Run only when the grid's
/// generation key changes, never per frame.
fn build_latency_rows(ctx: &UiCtx<'_>) -> Vec<LatencyRow> {
    let lang = ctx.settings.language;
    ctx.servers
        .profiles
        .iter()
        .map(|p| {
            let tag = p.tag();
            let status = ctx.observatory.iter().find(|o| o.tag == tag);
            let cell = match status {
                Some(o) if o.alive => LatencyCell::Alive {
                    delay_ms: o.delay_ms,
                    text: t_fmt(lang, Key::LatencyMs, &[&o.delay_ms]),
                },
                Some(_) => LatencyCell::DeadObservatory,
                None => match p.latency_ms {
                    Some(ms) if ms >= 0 => LatencyCell::Stale {
                        ms,
                        text: t_fmt(lang, Key::LatencyMs, &[&ms]),
                    },
                    Some(_) => LatencyCell::DeadStale,
                    None => LatencyCell::Unknown,
                },
            };
            let detail = row_detail(lang, status);
            let (detail_short, detail_truncated) = truncate_chars(&detail, 60);
            LatencyRow {
                name: p.name.clone(),
                tag,
                cell,
                detail_short,
                detail_full: detail,
                detail_truncated,
            }
        })
        .collect()
}

/// The detail column of one row: the burst engine's window statistics when it
/// reported them, else the Observatory's last error — a dead row whose status
/// carries probe-child diagnostics surfaces that wall in the hover-full text,
/// while the visible label stays a 60-char truncation of the combined text.
/// A dead row the Observatory could not explain reads the keyed fallback; a
/// live row needs no detail and keeps the column empty.
fn row_detail(lang: Language, status: Option<&OutboundStatusView>) -> String {
    let Some(status) = status else {
        return String::new();
    };
    if let Some(health) = status.health_ping {
        // The engine keeps no error text; the sample window is the whole
        // story of a dead row.
        return t_fmt(
            lang,
            Key::HealthPingSummary,
            &[
                &health.average_ms,
                &health.min_ms,
                &health.max_ms,
                &health.deviation_ms,
                &health.fail,
                &health.all,
            ],
        );
    }
    let mut detail = match status.last_error.as_deref() {
        Some(text) => text.to_owned(),
        None if status.alive => String::new(),
        None => t(lang, Key::DashboardLatencyNoObservation).to_owned(),
    };
    if let Some(tail) = status.diagnostics.as_deref() {
        detail = crate::probe_verdict::with_diagnostics_wall(lang, detail, tail);
    }
    detail
}

fn latency_color(ms: i64, colors: StatusColors) -> egui::Color32 {
    if ms < 300 {
        colors.ok
    } else if ms < 1000 {
        colors.warn
    } else {
        colors.err
    }
}

/// The IEC ladder step for a byte count under [`TrafficUnit::Auto`]:
/// B/KiB/MiB/GiB, 1024-based, one decimal, capped at GiB (the pre-unit
/// `human_rate` behavior, kept verbatim).
fn iec_scale(v: f64) -> (f64, &'static str) {
    const U: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut x = v;
    let mut i = 0;
    while x >= 1024.0 && i < 3 {
        x /= 1024.0;
        i += 1;
    }
    (x, U[i])
}

/// A byte count rendered in the selected unit: the IEC ladder under
/// [`TrafficUnit::Auto`], or an unconditional division by the unit's base
/// under a fixed unit. One decimal, always. Also used by the top-bar speed
/// readout (ui::topbar), which must show the same numbers the dashboard
/// does under the same global unit.
pub(crate) fn format_bytes(v: u64, unit: TrafficUnit) -> String {
    match unit {
        TrafficUnit::Auto => {
            let (x, u) = iec_scale(v as f64);
            format!("{x:.1} {u}")
        }
        TrafficUnit::Bps => format!("{:.1} B", v as f64),
        TrafficUnit::KiBps => format!("{:.1} KiB", v as f64 / 1024.0),
        TrafficUnit::MiBps => format!("{:.1} MiB", v as f64 / (1024.0 * 1024.0)),
        TrafficUnit::GiBps => format!("{:.1} GiB", v as f64 / (1024.0 * 1024.0 * 1024.0)),
    }
}

/// A byte rate in the selected unit: [`format_bytes`] plus the `/s` suffix.
fn format_rate(v: u64, unit: TrafficUnit) -> String {
    format!("{}/s", format_bytes(v, unit))
}

/// Axis-mark label for the throughput plot: [`format_bytes`] on an `f64`
/// byte value, without the `/s` suffix (the axis label carries it).
fn format_axis(v: f64, unit: TrafficUnit) -> String {
    match unit {
        TrafficUnit::Auto => {
            let (x, u) = iec_scale(v);
            format!("{x:.1} {u}")
        }
        TrafficUnit::Bps => format!("{v:.1} B"),
        TrafficUnit::KiBps => format!("{:.1} KiB", v / 1024.0),
        TrafficUnit::MiBps => format!("{:.1} MiB", v / (1024.0 * 1024.0)),
        TrafficUnit::GiBps => format!("{:.1} GiB", v / (1024.0 * 1024.0 * 1024.0)),
    }
}

/// The throughput plot's y-axis title for the selected traffic unit. Fixed
/// units name their unit (`KiB/s`, `MiB/s`, `GiB/s`) so the title matches
/// the tick labels; `Auto` and `Bps` keep the raw-byte `B/s` title. The
/// axis tick formatter already renders values in the selected unit without
/// a `/s` suffix (the title carries it).
fn y_axis_label_for(unit: TrafficUnit, lang: Language) -> &'static str {
    match unit {
        TrafficUnit::Auto | TrafficUnit::Bps => t(lang, Key::DashboardPlotBytesPerSec),
        TrafficUnit::KiBps => t(lang, Key::TrafficUnitKiBps),
        TrafficUnit::MiBps => t(lang, Key::TrafficUnitMiBps),
        TrafficUnit::GiBps => t(lang, Key::TrafficUnitGiBps),
    }
}

/// The i18n label key for one traffic-unit dropdown option.
fn traffic_unit_label_key(unit: TrafficUnit) -> Key {
    match unit {
        TrafficUnit::Auto => Key::TrafficUnitAuto,
        TrafficUnit::Bps => Key::TrafficUnitBps,
        TrafficUnit::KiBps => Key::TrafficUnitKiBps,
        TrafficUnit::MiBps => Key::TrafficUnitMiBps,
        TrafficUnit::GiBps => Key::TrafficUnitGiBps,
    }
}

/// The five selectable traffic units, in dropdown order.
const TRAFFIC_UNITS: [TrafficUnit; 5] = [
    TrafficUnit::Auto,
    TrafficUnit::Bps,
    TrafficUnit::KiBps,
    TrafficUnit::MiBps,
    TrafficUnit::GiBps,
];

fn human_uptime(secs: u64) -> String {
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

/// Derived state of one managed loopback inbound, from the core phase and
/// the inbound's enabled flag only — never probed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ListenerStatus {
    Up,
    Starting,
    Down,
    Disabled,
}

/// The dashboard header-row labels: the phase-badge
/// caption, the per-endpoint status rows (label + the derived status they
/// were formatted for) and the API-port line — rebuilt only when a phase
/// transition, an endpoint-list change, a persist, a language change or a
/// core start moved them, never on repaint frames. The phase is keyed by
/// clone-at-rebuild plus an explicit variant comparison ([`same_phase`] —
/// `CorePhase` carries no `PartialEq`), so the per-frame staleness check
/// never allocates.
struct HeaderCache {
    phase: CorePhase,
    config_revision: u64,
    dirty: bool,
    lang: Language,
    badge: String,
    endpoints: Vec<(String, ListenerStatus)>,
}

/// Explicit `CorePhase` equality for the header-cache key — the enum
/// carries no `PartialEq` derive (it lives in rt), and the payloads are
/// part of the rendered captions.
fn same_phase(a: &CorePhase, b: &CorePhase) -> bool {
    match (a, b) {
        (CorePhase::Stopped, CorePhase::Stopped)
        | (CorePhase::NoConfig, CorePhase::NoConfig)
        | (CorePhase::Starting, CorePhase::Starting)
        | (CorePhase::Running, CorePhase::Running) => true,
        (CorePhase::Backoff { attempt: x }, CorePhase::Backoff { attempt: y }) => x == y,
        (CorePhase::Error(x), CorePhase::Error(y)) => x == y,
        _ => false,
    }
}

/// Pure phase → badge caption: static phases render their `t()` string,
/// parameterized phases format their payload. Runs inside the header-cache
/// rebuild only — never per frame.
fn phase_badge_text(p: &CorePhase, lang: Language) -> String {
    match p {
        CorePhase::Stopped => t(lang, Key::DashboardPhaseStopped).into(),
        CorePhase::NoConfig => t(lang, Key::DashboardPhaseNoConfig).into(),
        CorePhase::Starting => t(lang, Key::DashboardPhaseStarting).into(),
        CorePhase::Running => t(lang, Key::DashboardPhaseRunning).into(),
        CorePhase::Backoff { attempt } => t_fmt(lang, Key::DashboardPhaseRetry, &[&attempt]),
        CorePhase::Error(error) => {
            t_fmt(lang, Key::DashboardPhaseError, &[&error.message.text(lang)])
        }
    }
}

/// Pure phase → badge dot color.
fn phase_badge_color(p: &CorePhase, colors: StatusColors) -> egui::Color32 {
    match p {
        CorePhase::Stopped => egui::Color32::GRAY,
        CorePhase::NoConfig => egui::Color32::GRAY,
        CorePhase::Starting => colors.warn,
        CorePhase::Running => colors.ok,
        CorePhase::Backoff { .. } => colors.warn,
        CorePhase::Error(_) => colors.err,
    }
}

/// Pure phase/settings → status derivation for one local endpoint.
fn listener_status(phase: &CorePhase, enabled: bool) -> ListenerStatus {
    if !enabled {
        return ListenerStatus::Disabled;
    }
    match phase {
        CorePhase::Running => ListenerStatus::Up,
        CorePhase::Starting => ListenerStatus::Starting,
        _ => ListenerStatus::Down,
    }
}

/// Derived dashboard status of the TUN item (precedence order).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TunStatus {
    Active,
    Elevation,
    Off,
    Starting,
    Down,
}

/// Pure settings/phase → status derivation for the TUN row item. The tuple
/// is `(mode, is_elevated)`.
fn tun_status(phase: &CorePhase, (mode, is_elevated): (Mode, bool)) -> TunStatus {
    if mode == Mode::Tun && matches!(phase, CorePhase::Running) {
        return TunStatus::Active;
    }
    if mode == Mode::Tun && !is_elevated {
        return TunStatus::Elevation;
    }
    if mode != Mode::Tun {
        return TunStatus::Off;
    }
    if mode == Mode::Tun && matches!(phase, CorePhase::Starting) {
        return TunStatus::Starting;
    }
    TunStatus::Down
}

#[cfg(test)]
mod tests {
    use super::{
        DashboardScreen, LatencyCell, ListenerStatus, TunStatus, build_latency_rows, format_axis,
        format_bytes, listener_status, phase_badge_color, phase_badge_text, truncate_chars,
        tun_status, y_axis_label_for,
    };
    use crate::diag::Diag;
    use crate::i18n::{Key, t, t_fmt};
    use crate::links::excerpt;
    use crate::model::settings::{Language, TrafficUnit};
    use crate::model::{
        LocalInboundCfg, LocalInboundProtocol, Mode, OutboundModel, Protocol, ServerProfile,
        ServersFile, Settings,
    };
    use crate::rt::{CorePhase, HealthPingView, OutboundStatusView, PhaseError, StatsTick};
    use crate::ui::test_rig::UiTestRig;
    use egui_kittest::{Harness, kittest::NodeT, kittest::Queryable as _};
    use std::cell::RefCell;
    use std::rc::Rc;

    /// A terminal phase for the listener-status matrix: production payloads
    /// are keyed, so the fixture uses a key too.
    fn error_phase() -> CorePhase {
        CorePhase::Error(PhaseError::new(Diag::new(Key::RtPhaseRestartCancelled)))
    }

    #[test]
    fn no_config_badge_is_distinct_and_not_an_error() {
        let color = phase_badge_color(&CorePhase::NoConfig, crate::ui::status::status_colors(true));
        assert_eq!(
            phase_badge_text(&CorePhase::NoConfig, Language::En),
            "No config yet"
        );
        assert_ne!(color, egui::Color32::RED);
    }

    #[test]
    fn error_truncation_never_slices_utf8_bytes() {
        let input = "错误🙂".repeat(30);
        let (short, truncated) = truncate_chars(&input, 60);
        assert!(truncated);
        assert_eq!(short.chars().count(), 60);
        assert!(input.starts_with(&short));
    }

    fn profile(name: &str, latency: Option<i64>) -> ServerProfile {
        let mut p = ServerProfile::new(name, OutboundModel::new(Protocol::Trojan));
        p.latency_ms = latency;
        p
    }

    /// The listener-traffic table renders one row per inbound tag from the
    /// stats tick, with the per-tag rates, and stays hidden with no data.
    #[test]
    fn inbound_traffic_table_renders_per_tag_rows() {
        let rig = Rc::new(RefCell::new(UiTestRig::default()));
        rig.borrow_mut().stats = Some(StatsTick {
            per_inbound: vec![
                ("socks".to_string(), 0, 2_097_152),
                ("tun".to_string(), 1_048_576, 0),
            ],
            per_inbound_totals: vec![
                ("socks".to_string(), 3_000_000, 4_000_000),
                ("tun".to_string(), 5_000_000, 6_000_000),
            ],
            ..Default::default()
        });
        let rig_handle = rig.clone();
        let mut harness = Harness::builder().build_ui_state(
            move |ui, screen: &mut DashboardScreen| {
                let mut rig = rig_handle.borrow_mut();
                screen.show(ui, &mut rig.ctx())
            },
            DashboardScreen::default(),
        );
        harness.run();

        harness
            .get_all_by_label(t(Language::En, Key::DashboardInboundTraffic))
            .next()
            .expect("inbound traffic heading must render");
        harness
            .get_all_by_label("tun")
            .next()
            .expect("tun row tag must render");
        harness
            .get_all_by_label("socks")
            .next()
            .expect("socks row tag must render");
        // 1 MiB/s up / 2 MiB/s down through the same IEC ladder under Auto.
        harness
            .get_all_by_label("↑ 1.0 MiB/s")
            .next()
            .expect("tun up rate must render");
        harness
            .get_all_by_label("↓ 2.0 MiB/s")
            .next()
            .expect("socks down rate must render");
    }

    /// The sys-stats line renders the memory/GC figures from the tick.
    #[test]
    fn sys_stats_memory_line_renders() {
        let rig = Rc::new(RefCell::new(UiTestRig::default()));
        rig.borrow_mut().stats = Some(StatsTick {
            uptime_secs: 90,
            goroutines: 12,
            alloc_bytes: 3_145_728,
            sys_bytes: 6_291_456,
            live_objects: 12_345,
            num_gc: 7,
            ..Default::default()
        });
        let rig_handle = rig.clone();
        let mut harness = Harness::builder().build_ui_state(
            move |ui, screen: &mut DashboardScreen| {
                let mut rig = rig_handle.borrow_mut();
                screen.show(ui, &mut rig.ctx())
            },
            DashboardScreen::default(),
        );
        harness.run();

        // "mem 3.0 MiB · sys 6.0 MiB · 12345 live objs · GC 7"
        harness
            .get_all_by_label("mem 3.0 MiB · sys 6.0 MiB · 12345 live objs · GC 7")
            .next()
            .expect("memory line must render the sys-stats fields");
    }

    /// User report: on a narrow window the stats row (uptime · goroutines ·
    /// mem · …) is cut off at the window edge instead of wrapping to a new
    /// line. The row is laid out in a single non-wrapping `ui.horizontal`,
    /// so overflow content extends past the clip rect. The memory line is
    /// the longest caption; at a narrow width it must stay fully inside the
    /// window.
    #[test]
    fn stats_row_stays_inside_the_window_when_narrow() {
        let rig = Rc::new(RefCell::new(UiTestRig::default()));
        rig.borrow_mut().stats = Some(StatsTick {
            uptime_secs: 90,
            goroutines: 184,
            alloc_bytes: 10_800_000,
            sys_bytes: 154_300_000,
            live_objects: 62_494,
            num_gc: 91,
            ..Default::default()
        });
        let rig_handle = rig.clone();
        let width = 340.0;
        let height = 700.0;
        let mut harness = Harness::builder()
            .with_size(egui::vec2(width, height))
            .build_ui_state(
                move |ui, screen: &mut DashboardScreen| {
                    let mut rig = rig_handle.borrow_mut();
                    screen.show(ui, &mut rig.ctx())
                },
                DashboardScreen::default(),
            );
        harness.run();

        let node = harness
            .get_all_by_label("mem 10.3 MiB · sys 147.2 MiB · 62494 live objs · GC 91")
            .next()
            .expect("memory line must render");
        let rect = node.rect();
        assert!(
            rect.left() >= 0.0 - 0.5 && rect.right() <= width + 0.5,
            "stats row must wrap inside the window at {width}px; memory line rect {rect:?}"
        );
    }

    /// The Connect verdict has one owner: the shell's per-revision
    /// generation. The row takes enablement from `ctx.connect_blocked_reason`
    /// alone and renders `ctx.config_error` — the shell's stored,
    /// excerpt-bounded generation error — inline. It never generates the
    /// candidate itself: generating binds the ephemeral control-plane port
    /// (a paint pass must not open a socket) and would render a text the
    /// shell's echo boundary never produced.
    #[test]
    fn connect_row_renders_the_shell_verdict_and_never_generates() {
        let rig = Rc::new(RefCell::new(UiTestRig::default()));
        // A model the generator rejects. Were the screen to generate (as it
        // used to), it would render this unbounded message and disable
        // Connect on its own verdict.
        let broken = Settings {
            raw_override: Some("{".into()),
            ..Default::default()
        };
        let own_error = crate::r#gen::generate(&ServersFile::default(), &broken)
            .expect_err("the truncated override must not parse")
            .to_string();
        // The shell's stored text for that same failure: the
        // `GenerationFailed` template around the 48-char excerpt.
        let shell_error = t_fmt(Language::En, Key::GenerationFailed, &[&excerpt(&own_error)]);
        rig.borrow_mut().settings = broken;

        let rig_handle = rig.clone();
        let mut harness = Harness::builder().build_ui_state(
            move |ui, screen: &mut DashboardScreen| {
                let mut rig = rig_handle.borrow_mut();
                screen.show(ui, &mut rig.ctx())
            },
            DashboardScreen::default(),
        );
        harness.run();

        // A clear shell verdict leaves Connect enabled even though this
        // model cannot generate, and the screen's own generation result
        // never renders.
        let connect_label = t(Language::En, Key::PhaseConnect);
        let connect = harness
            .query_all_by_role_and_label(egui::accesskit::Role::Button, connect_label)
            .next()
            .expect("the dashboard must render its Connect button");
        assert!(
            !connect.accesskit_node().is_disabled(),
            "the shell verdict, not a screen-local generation, enables Connect"
        );
        assert!(
            harness
                .query_all_by_label(own_error.as_str())
                .next()
                .is_none(),
            "the screen must not render a generation error it produced itself: {own_error:?}"
        );

        // The shell's verdict and stored error arrive: the button follows
        // the verdict and the inline label carries the stored text.
        rig.borrow_mut().connect_blocked_reason = Some("blocked by the shell".into());
        rig.borrow_mut().config_error = Some(shell_error.clone());
        harness.run();

        let connect = harness
            .query_all_by_role_and_label(egui::accesskit::Role::Button, connect_label)
            .next()
            .expect("the dashboard must render its Connect button");
        assert!(
            connect.accesskit_node().is_disabled(),
            "the shell's block reason must disable Connect"
        );
        assert!(
            harness
                .query_all_by_label(shell_error.as_str())
                .next()
                .is_some(),
            "the inline label must render the shell's stored generation error: {shell_error:?}"
        );
    }

    /// The unit-aware byte formatter: the IEC ladder under Auto (capped at
    /// GiB, one decimal) and an unconditional division by the unit's base
    /// under a fixed unit.
    #[test]
    fn format_bytes_adapts_ladder_and_honors_fixed_override() {
        assert_eq!(format_bytes(0, TrafficUnit::Auto), "0.0 B");
        assert_eq!(format_bytes(1536, TrafficUnit::Auto), "1.5 KiB");
        // The ladder caps at GiB under Auto: multi-TiB counts stay in GiB.
        assert_eq!(
            format_bytes(5_000_000_000_000, TrafficUnit::Auto),
            "4656.6 GiB"
        );
        assert_eq!(format_bytes(1_048_576, TrafficUnit::KiBps), "1024.0 KiB");
        assert_eq!(format_bytes(500_000, TrafficUnit::MiBps), "0.5 MiB");
        assert_eq!(format_bytes(1_610_612_736, TrafficUnit::GiBps), "1.5 GiB");
        assert_eq!(format_bytes(1234, TrafficUnit::Bps), "1234.0 B");
    }

    /// The plot axis formatter: the same ladder on f64 input without the
    /// `/s` suffix (the axis label carries it), fixed units dividing by
    /// their base unconditionally.
    #[test]
    fn format_axis_adaptive_ticks() {
        assert_eq!(format_axis(2_000_000.0, TrafficUnit::Auto), "1.9 MiB");
        assert_eq!(format_axis(500.0, TrafficUnit::Auto), "500.0 B");
        assert_eq!(format_axis(0.0, TrafficUnit::Auto), "0.0 B");
        assert_eq!(format_axis(2048.0, TrafficUnit::KiBps), "2.0 KiB");
        assert_eq!(format_axis(1_048_576.0, TrafficUnit::MiBps), "1.0 MiB");
    }

    /// The throughput plot's y-axis title follows the selected unit: fixed
    /// units name their unit (`KiB/s`, `MiB/s`, `GiB/s`); Auto and Bps stay
    /// `B/s` (the raw axis unit). Regression: the title was hardcoded to
    /// `B/s` for every unit.
    #[test]
    fn plot_y_axis_label_follows_traffic_unit() {
        for (unit, expected) in [
            (TrafficUnit::Auto, "B/s"),
            (TrafficUnit::Bps, "B/s"),
            (TrafficUnit::KiBps, "KiB/s"),
            (TrafficUnit::MiBps, "MiB/s"),
            (TrafficUnit::GiBps, "GiB/s"),
        ] {
            assert_eq!(y_axis_label_for(unit, Language::En), expected);
        }
    }

    /// Picking a fixed unit from the traffic-unit dropdown re-renders the
    /// inbound table, the session totals line and the memory line in that
    /// unit, writes the setting and marks the model dirty.
    #[test]
    fn unit_override_rerenders_table_and_memory() {
        let rig = Rc::new(RefCell::new(UiTestRig::default()));
        rig.borrow_mut().stats = Some(StatsTick {
            per_inbound: vec![("tun".to_string(), 1000, 2000)],
            per_inbound_totals: vec![("tun".to_string(), 1_500_000, 2_500_000)],
            total_up: 1_500_000,
            total_down: 2_500_000,
            ..Default::default()
        });
        let rig_handle = rig.clone();
        let mut harness = Harness::builder().build_ui_state(
            move |ui, screen: &mut DashboardScreen| {
                let mut rig = rig_handle.borrow_mut();
                screen.show(ui, &mut rig.ctx())
            },
            DashboardScreen::default(),
        );
        harness.run();

        // Auto (the default): sub-KiB rates in bytes, totals on the IEC
        // ladder. The down rate climbs the ladder: 2000/1024 = 1.953
        // -> "2.0 KiB".
        harness
            .get_all_by_label("↑ 1000.0 B/s")
            .next()
            .expect("the up rate renders in bytes below 1 KiB under auto");
        harness
            .get_all_by_label("↓ 2.0 KiB/s")
            .next()
            .expect("the down rate climbs the ladder under auto");

        // Pick "MiB/s" from the unit dropdown: the combo button carries the
        // current unit's label as its value.
        harness
            .get_all_by_role(egui::accesskit::Role::ComboBox)
            .find(|node| node.value().as_deref() == Some("Auto"))
            .expect("the traffic-unit combo must show the current unit")
            .click();
        harness.run();
        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "MiB/s")
            .click();
        harness.run();

        assert_eq!(
            rig.borrow().settings.traffic_unit,
            TrafficUnit::MiBps,
            "the dropdown writes the selected unit into settings"
        );
        assert!(
            rig.borrow().ui_dirty,
            "the unit change marks the UI-only persist flag"
        );
        assert!(
            !rig.borrow().dirty,
            "a display preference must never enter the config-apply gate"
        );

        // Fixed unit: every figure divides by the MiB base unconditionally
        // (1000 B -> "0.0 MiB"), and the memory line follows the unit.
        harness
            .get_all_by_label("↑ 0.0 MiB/s")
            .next()
            .expect("the up rate renders in the fixed unit");
        harness
            .get_all_by_label("↓ 0.0 MiB/s")
            .next()
            .expect("the down rate renders in the fixed unit");
        harness
            .get_all_by_label("mem 0.0 MiB · sys 0.0 MiB · 0 live objs · GC 0")
            .next()
            .expect("the memory line re-renders in the fixed unit");
    }

    /// The inbound cache rebuilds exactly once per input change: idle
    /// frames rebuild nothing, and a traffic-unit flip rebuilds once (no
    /// work counter exists for the inbound cache; its memoization is
    /// structural — the labels only ever change on the rebuild frame, so
    /// the `(stats_generation, unit, language)` key is observable through
    /// them).
    #[test]
    fn unit_change_rebuilds_inbound_cache_once() {
        let rig = Rc::new(RefCell::new(UiTestRig::default()));
        rig.borrow_mut().stats = Some(StatsTick {
            per_inbound: vec![("tun".to_string(), 1_048_576, 2_097_152)],
            per_inbound_totals: vec![("tun".to_string(), 3_145_728, 4_194_304)],
            total_up: 3_145_728,
            total_down: 4_194_304,
            ..Default::default()
        });
        let rig_handle = rig.clone();
        let mut harness = Harness::builder().build_ui_state(
            move |ui, screen: &mut DashboardScreen| {
                let mut rig = rig_handle.borrow_mut();
                screen.show(ui, &mut rig.ctx())
            },
            DashboardScreen::default(),
        );

        // The seed frame renders the Auto labels; idle frames keep them.
        harness.run();
        harness
            .get_all_by_label("↑ 1.0 MiB/s")
            .next()
            .expect("the seed frame renders the auto rate");
        harness.run_steps(10);
        harness
            .get_all_by_label("↑ 1.0 MiB/s")
            .next()
            .expect("idle frames keep the memoized auto labels");

        // A unit flip without a stats tick rebuilds exactly once: the flip
        // frame shows the new unit and drops the old labels, idle frames
        // change nothing more.
        rig.borrow_mut().settings.traffic_unit = TrafficUnit::KiBps;
        harness.run();
        harness
            .get_all_by_label("↑ 1024.0 KiB/s")
            .next()
            .expect("the flip frame re-renders the rate in the new unit");
        assert!(
            harness.query_all_by_label("↑ 1.0 MiB/s").next().is_none(),
            "the old-unit label disappears on the flip frame"
        );
        harness.run_steps(10);
        harness
            .get_all_by_label("↑ 1024.0 KiB/s")
            .next()
            .expect("idle frames keep the new-unit labels");
        assert!(
            harness.query_all_by_label("↑ 1.0 MiB/s").next().is_none(),
            "idle frames must not rebuild back to the old labels"
        );

        // Flipping back restores the original labels, again in one frame.
        rig.borrow_mut().settings.traffic_unit = TrafficUnit::Auto;
        harness.run();
        harness
            .get_all_by_label("↑ 1.0 MiB/s")
            .next()
            .expect("flipping back restores the auto labels");
        assert!(
            harness
                .query_all_by_label("↑ 1024.0 KiB/s")
                .next()
                .is_none(),
            "the new-unit label disappears on the flip-back frame"
        );
        harness.run_steps(10);
        harness
            .get_all_by_label("↑ 1.0 MiB/s")
            .next()
            .expect("idle frames keep the restored labels");
    }

    /// The dashboard memoizes its plot series and latency grid on generation
    /// keys: idle frames rebuild nothing, and exactly one rebuild follows
    /// each real input change (stats tick, observatory tick, model change).
    #[test]
    fn plot_and_grid_rebuild_only_when_their_generation_advances() {
        // The harness closure borrows the rig for its whole lifetime, so the
        // rig lives behind a RefCell: the test mutates inputs between frames
        // and the closure re-borrows per frame.
        let rig = Rc::new(RefCell::new(UiTestRig::default()));
        rig.borrow_mut().servers.profiles = vec![
            profile("alpha", Some(42)),
            profile("beta", Some(-1)),
            profile("gamma", None),
        ];
        let rig_handle = rig.clone();
        let mut harness = Harness::builder().build_ui_state(
            move |ui, screen: &mut DashboardScreen| {
                let mut rig = rig_handle.borrow_mut();
                screen.show(ui, &mut rig.ctx())
            },
            DashboardScreen::default(),
        );

        // First render: the initial cache fill is a one-time seed, not a
        // rebuild (the purity contract keeps counters at absolute
        // zero on a fresh harness), and the seeded grid rows render their
        // stale-latency cells.
        harness.run();
        assert_eq!(
            rig.borrow().metrics.snapshot().plot_rebuilds,
            0,
            "the first render seeds the plot cache without counting a rebuild"
        );
        harness
            .get_all_by_label("42 ms")
            .next()
            .expect("stale profile latency renders as its label");
        harness
            .get_all_by_label("dead")
            .next()
            .expect("dead-profile latency renders as the dead label");
        harness
            .get_all_by_label("—")
            .next()
            .expect("unmeasured profile latency renders as the em dash");

        // Idle frames: no stats tick, no observatory tick, no model change
        // -> no rebuild, no grid work (no counter exists for the grid; its
        // memoization is structural — the values below stay stable).
        let expected = rig.borrow().metrics.snapshot().plot_rebuilds;
        harness.run_steps(30);
        assert_eq!(
            rig.borrow().metrics.snapshot().plot_rebuilds,
            expected,
            "idle frames must not rebuild the plot series"
        );
        harness
            .get_all_by_label("42 ms")
            .next()
            .expect("idle frames keep the memoized grid values");

        rig.borrow_mut().stats_history.push_back(StatsTick {
            up: 100,
            down: 200,
            ..Default::default()
        });
        rig.borrow_mut().stats_generation += 1;
        harness.run();
        assert_eq!(
            rig.borrow().metrics.snapshot().plot_rebuilds,
            expected + 1,
            "one stats tick must rebuild the plot series exactly once"
        );
        harness.run_steps(10);
        assert_eq!(
            rig.borrow().metrics.snapshot().plot_rebuilds,
            expected + 1,
            "frames after the tick must not rebuild again"
        );

        let tag = rig.borrow().servers.profiles[0].tag();
        rig.borrow_mut().observatory = vec![OutboundStatusView {
            health_ping: None,
            tag,
            alive: true,
            delay_ms: 123,
            last_error: None,
            diagnostics: None,
        }];
        rig.borrow_mut().latency_generation += 1;
        harness.run();
        harness
            .get_all_by_label("123 ms")
            .next()
            .expect("a live observatory status replaces the stale latency");
        assert!(
            harness.query_all_by_label("42 ms").next().is_none(),
            "the stale latency label must disappear with the observatory row"
        );
        harness.run_steps(10);
        assert_eq!(
            rig.borrow().metrics.snapshot().plot_rebuilds,
            expected + 1,
            "an observatory tick must not rebuild the plot series"
        );

        rig.borrow_mut().servers.profiles[1].name = "beta-renamed".into();
        rig.borrow_mut().config_revision += 1;
        harness.run();
        harness
            .get_all_by_label("beta-renamed")
            .next()
            .expect("a persist-generation bump rebuilds the grid rows");
        assert_eq!(
            rig.borrow().metrics.snapshot().plot_rebuilds,
            expected + 1,
            "a model change must not rebuild the plot series"
        );
    }

    /// Long observatory last-error text is truncated to 60 chars in the
    /// memoized row, and the full text is kept for the hover.
    #[test]
    fn grid_rows_truncate_long_errors_once_per_rebuild() {
        let long_error = "e".repeat(100);
        let rig = Rc::new(RefCell::new(UiTestRig::default()));
        {
            let mut rig = rig.borrow_mut();
            // The rig ships no profiles; a grid row only exists for a
            // profile, so the test seeds one (UiTestRig::default leaves
            // ServersFile::default — empty).
            rig.servers.profiles = vec![profile("Tokyo edge", None)];
            let tag = rig.servers.profiles[0].tag();
            rig.observatory = vec![OutboundStatusView {
                health_ping: None,
                tag,
                alive: false,
                delay_ms: 0,
                last_error: Some(long_error.clone()),
                diagnostics: None,
            }];
            rig.latency_generation += 1;
        }
        let rig_handle = rig.clone();
        let mut harness = Harness::builder().build_ui_state(
            move |ui, screen: &mut DashboardScreen| {
                let mut rig = rig_handle.borrow_mut();
                screen.show(ui, &mut rig.ctx())
            },
            DashboardScreen::default(),
        );
        harness.run();

        harness
            .get_all_by_label(&long_error[..60])
            .next()
            .expect("the grid row shows the 60-char truncation of the error");
        harness.run_steps(10);
        harness
            .get_all_by_label(&long_error[..60])
            .next()
            .expect("idle frames keep the memoized truncation");

        let rows = build_latency_rows(&rig.borrow_mut().ctx());
        assert_eq!(rows.len(), 1);
        assert!(matches!(rows[0].cell, LatencyCell::DeadObservatory));
        assert_eq!(rows[0].detail_short, long_error[..60]);
        assert_eq!(rows[0].detail_full, long_error);
        assert!(rows[0].detail_truncated);
    }

    /// A dead row whose status carries the probe run's
    /// diagnostics tail shows the wall in the hover-full text while the
    /// visible label stays the 60-char truncation of the combined text.
    #[test]
    fn grid_rows_include_probe_diagnostics_in_the_hover_full_text() {
        let rig = Rc::new(RefCell::new(UiTestRig::default()));
        {
            let mut rig = rig.borrow_mut();
            rig.servers.profiles = vec![profile("Tokyo edge", None)];
            let tag = rig.servers.profiles[0].tag();
            rig.observatory = vec![OutboundStatusView {
                health_ping: None,
                tag,
                alive: false,
                delay_ms: 0,
                last_error: Some("connection refused".into()),
                diagnostics: Some("[stderr] rejected: unknown SNI".into()),
            }];
            rig.latency_generation += 1;
        }

        let rows = build_latency_rows(&rig.borrow_mut().ctx());
        assert_eq!(rows.len(), 1);
        assert!(matches!(rows[0].cell, LatencyCell::DeadObservatory));
        let combined = format!(
            "connection refused\n{}\n[stderr] rejected: unknown SNI",
            t(Language::En, Key::ProbeDiagnosticsWall)
        );
        assert_eq!(rows[0].detail_short, &combined[..60]);
        assert_eq!(rows[0].detail_full, combined);
        assert!(rows[0].detail_truncated);
    }

    /// Rows whose dead status carries no diagnostics are
    /// byte-identical to the previous text.
    #[test]
    fn grid_rows_without_diagnostics_keep_the_plain_error_text() {
        let rig = Rc::new(RefCell::new(UiTestRig::default()));
        {
            let mut rig = rig.borrow_mut();
            rig.servers.profiles = vec![profile("Tokyo edge", None)];
            let tag = rig.servers.profiles[0].tag();
            rig.observatory = vec![OutboundStatusView {
                health_ping: None,
                tag,
                alive: false,
                delay_ms: 0,
                last_error: Some("connection refused".into()),
                diagnostics: None,
            }];
            rig.latency_generation += 1;
        }

        let rows = build_latency_rows(&rig.borrow_mut().ctx());
        assert_eq!(rows[0].detail_short, "connection refused");
        assert_eq!(rows[0].detail_full, "connection refused");
        assert!(!rows[0].detail_truncated);
    }

    /// A status without error text renders the keyed fallback in the detail
    /// column of a dead row; a live row needs no detail and stays empty.
    #[test]
    fn grid_rows_without_error_text_use_the_keyed_fallback() {
        let rig = Rc::new(RefCell::new(UiTestRig::default()));
        {
            let mut rig = rig.borrow_mut();
            rig.servers.profiles = vec![profile("Tokyo edge", None), profile("Osaka", None)];
            let dead_tag = rig.servers.profiles[0].tag();
            let alive_tag = rig.servers.profiles[1].tag();
            rig.observatory = vec![
                OutboundStatusView {
                    health_ping: None,
                    tag: dead_tag,
                    alive: false,
                    delay_ms: 0,
                    last_error: None,
                    diagnostics: None,
                },
                OutboundStatusView {
                    health_ping: None,
                    tag: alive_tag,
                    alive: true,
                    delay_ms: 23,
                    last_error: None,
                    diagnostics: None,
                },
            ];
            rig.latency_generation += 1;
        }

        let rows = build_latency_rows(&rig.borrow_mut().ctx());
        assert_eq!(rows.len(), 2);
        assert!(matches!(rows[0].cell, LatencyCell::DeadObservatory));
        assert_eq!(
            rows[0].detail_full,
            t(Language::En, Key::DashboardLatencyNoObservation)
        );
        assert_eq!(rows[1].detail_full, "");
    }

    /// A row reported by the burst engine carries its window statistics in
    /// the detail column: that engine keeps no error text, so a dead row
    /// explains itself through its sample window.
    #[test]
    fn grid_rows_show_burst_window_statistics() {
        let rig = Rc::new(RefCell::new(UiTestRig::default()));
        {
            let mut rig = rig.borrow_mut();
            rig.servers.profiles = vec![profile("Tokyo edge", None)];
            let tag = rig.servers.profiles[0].tag();
            rig.observatory = vec![OutboundStatusView {
                health_ping: Some(HealthPingView {
                    all: 10,
                    fail: 1,
                    average_ms: 123,
                    deviation_ms: 40,
                    max_ms: 210,
                    min_ms: 90,
                }),
                tag,
                alive: true,
                delay_ms: 123,
                last_error: None,
                diagnostics: None,
            }];
            rig.latency_generation += 1;
        }

        let rows = build_latency_rows(&rig.borrow_mut().ctx());
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].detail_full,
            t_fmt(
                Language::En,
                Key::HealthPingSummary,
                &[&123, &90, &210, &40, &1, &10]
            )
        );
        assert!(
            !rows[0].detail_short.is_empty(),
            "the statistics must be visible without hovering"
        );
    }

    /// The local-endpoint derivation: a disabled inbound always wins
    /// (it is never listening), then Running/Starting map to up/starting and
    /// every other phase to down.
    #[test]
    fn listener_status_covers_all_four_states() {
        assert_eq!(
            listener_status(&CorePhase::Running, true),
            ListenerStatus::Up
        );
        assert_eq!(
            listener_status(&CorePhase::Starting, true),
            ListenerStatus::Starting
        );
        for phase in [
            CorePhase::Stopped,
            CorePhase::NoConfig,
            CorePhase::Backoff { attempt: 2 },
            error_phase(),
        ] {
            assert_eq!(listener_status(&phase, true), ListenerStatus::Down);
        }
        // Disabled wins regardless of phase, even while the core runs.
        assert_eq!(
            listener_status(&CorePhase::Running, false),
            ListenerStatus::Disabled
        );
        assert_eq!(
            listener_status(&CorePhase::Stopped, false),
            ListenerStatus::Disabled
        );
    }

    /// The TUN item derivation in precedence order: running TUN
    /// mode is active (elevation is moot), a non-elevated TUN mode explains
    /// itself as elevation needed, other modes are off, a starting (elevated)
    /// TUN is starting, and anything else is down.
    #[test]
    fn tun_status_covers_all_five_states() {
        let running = CorePhase::Running;
        let starting = CorePhase::Starting;
        let stopped = CorePhase::Stopped;

        // Active: mode==Tun && Running — with or without the (moot, since it
        // is already running) elevation flag.
        assert_eq!(tun_status(&running, (Mode::Tun, true)), TunStatus::Active);
        assert_eq!(tun_status(&running, (Mode::Tun, false)), TunStatus::Active);
        // Elevation: mode==Tun && !is_elevated, before the starting clause.
        assert_eq!(
            tun_status(&stopped, (Mode::Tun, false)),
            TunStatus::Elevation
        );
        assert_eq!(
            tun_status(&starting, (Mode::Tun, false)),
            TunStatus::Elevation
        );
        // Off: any non-TUN mode, whatever the phase.
        assert_eq!(tun_status(&running, (Mode::Off, true)), TunStatus::Off);
        assert_eq!(tun_status(&starting, (Mode::Off, false)), TunStatus::Off);
        // Starting: mode==Tun && Starting, when elevated.
        assert_eq!(
            tun_status(&starting, (Mode::Tun, true)),
            TunStatus::Starting
        );
        // Down: everything left — elevated TUN mode not running/starting.
        assert_eq!(tun_status(&stopped, (Mode::Tun, true)), TunStatus::Down);
    }

    /// The dashboard renders one status row per local endpoint, in list
    /// order, labeled by protocol and listen:port. Disabled
    /// entries still render — as disabled.
    #[test]
    fn endpoint_rows_render_one_row_per_local_entry_in_list_order() {
        let rig = Rc::new(RefCell::new(UiTestRig::default()));
        {
            let mut rig = rig.borrow_mut();
            rig.settings.local_inbounds.push(LocalInboundCfg {
                tag: "in-socks-1".into(),
                protocol: LocalInboundProtocol::Socks,
                port: 10810,
                ..Default::default()
            });
            rig.settings.local_inbounds[1].enabled = false;
        }
        let rig_handle = rig.clone();
        let mut harness = Harness::builder().build_ui_state(
            move |ui, screen: &mut DashboardScreen| {
                let mut rig = rig_handle.borrow_mut();
                screen.show(ui, &mut rig.ctx())
            },
            DashboardScreen::default(),
        );
        harness.run();

        let rows: Vec<_> = harness
            .get_all_by_label("SOCKS 127.0.0.1:10808 down")
            .collect();
        assert_eq!(
            rows.len(),
            1,
            "the first list entry renders its own SOCKS row"
        );
        harness
            .get_all_by_label("HTTP 127.0.0.1:10809 disabled")
            .next()
            .expect("a disabled entry renders a disabled row, not an omitted one");
        harness
            .get_all_by_label("SOCKS 127.0.0.1:10810 down")
            .next()
            .expect("the third entry renders after the first two, in list order");
    }

    /// The header-row labels (phase badge, endpoint status
    /// captions) are memoized on their inputs — idle frames repaint the
    /// cached captions and a phase transition rebuilds exactly once, on the
    /// transition frame.
    #[test]
    fn header_labels_follow_phase_transitions_once_per_change() {
        let rig = Rc::new(RefCell::new(UiTestRig::default()));
        rig.borrow_mut().phase = CorePhase::Running;
        let rig_handle = rig.clone();
        let mut harness = Harness::builder().build_ui_state(
            move |ui, screen: &mut DashboardScreen| {
                let mut rig = rig_handle.borrow_mut();
                screen.show(ui, &mut rig.ctx())
            },
            DashboardScreen::default(),
        );

        harness.run();
        harness
            .get_all_by_label("Running")
            .next()
            .expect("the running phase caption renders");
        harness
            .get_all_by_label("SOCKS 127.0.0.1:10808 up")
            .next()
            .expect("a live endpoint renders its up caption");
        harness.run_steps(10);
        harness
            .get_all_by_label("SOCKS 127.0.0.1:10808 up")
            .next()
            .expect("idle frames keep the memoized endpoint captions");

        // A phase transition flips the captions on the transition frame;
        // idle frames then stay flat on the new text.
        rig.borrow_mut().phase = CorePhase::Stopped;
        harness.run();
        harness
            .get_all_by_label("SOCKS 127.0.0.1:10808 down")
            .next()
            .expect("the transition frame re-renders the endpoint as down");
        harness
            .get_all_by_label("Stopped")
            .next()
            .expect("the transition frame re-renders the phase caption");
        assert!(
            harness.query_all_by_label("Running").next().is_none(),
            "the old phase caption disappears with the transition"
        );
        harness.run_steps(10);
        harness
            .get_all_by_label("SOCKS 127.0.0.1:10808 down")
            .next()
            .expect("idle frames keep the down caption");
    }
}
