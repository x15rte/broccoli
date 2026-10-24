//! Inbounds screen: the user-managed local SOCKS/HTTP endpoint list,
//! dokodemo-door forwards, sniffing. IP listeners bind a user-configurable
//! listen address (default 127.0.0.1, any IP literal allowed); dokodemo also
//! supports UNIX sockets.

use crate::i18n::{Key, safety_message, t, t_fmt, validation_issue_message, validation_message};
use crate::model::emit;
use crate::model::inbound::{
    API_INBOUND_TAG, DokodemoNetwork, is_wildcard_listen, listen_endpoints_conflict,
    new_dokodemo_tag, next_local_tag,
};
use crate::model::settings::Language;
use crate::model::validation::{
    FindingTarget, ValidationCode, Verdict, normalize_windows_socket_path, validate_finalmask,
    validate_listen_address,
};
use crate::model::{
    Account, DokodemoCfg, FinalmaskModel, FinalmaskTcpMask, FinalmaskUdpMask, LocalInboundCfg,
    LocalInboundProtocol, Settings, Sniffing,
};
use crate::ui::InboundsCtx;
use crate::ui::servers::finalmask_editors::filter_settings_editor;
use crate::ui::widgets;
use serde_json::Map;

#[derive(Default)]
pub struct InboundsScreen {
    /// Transient port_map rows per dokodemo entry (synced on edit).
    port_map_rows: Vec<Vec<(String, String)>>,
    /// Cross-listener validation references, rebuilt whenever the model
    /// generation moves — never on idle repaint frames. `None` until the
    /// first frame.
    validation: Option<ValidationCache>,
    /// The reveal control's state: `true` while the user asked to see the
    /// account credentials this screen hides. Transient — leaving the screen
    /// hides them again.
    revealed: bool,
}

/// One generation of the inbounds validation references: the listener
/// snapshot plus every derived verdict the model pass does not publish per
/// row (draft-level collisions, routing reference counts, the row-label tag
/// errors, LAN-exposure posture, the row-local mask findings). Rows borrow
/// these while their editors are open — no per-frame rebuilds or clones. The
/// rules the settings walk reports are *not* cached here: the row asks
/// `ctx.verdict.for_target(..)` for those.
struct ValidationCache {
    /// The model generation these verdicts were derived from.
    generation: u64,
    non_loopback: bool,
    /// One collision verdict per local endpoint list entry, in list order.
    local_collisions: Vec<Option<String>>,
    /// Every listener-mask finding per local endpoint list entry, in list
    /// order — the same `validate_finalmask` pass the settings gate runs,
    /// rendered with the row-local mask path rather than the document path
    /// the walk prefixes, so a malformed `filter` rule reads as its own field
    /// in the row and identically to the gate's message at apply.
    local_filter_errors: Vec<Vec<String>>,
    doko_collisions: Vec<Option<String>>,
    doko_references: Vec<usize>,
    /// One row-label verdict per dokodemo entry, in list order: the empty tag,
    /// a tag a builtin/reserved listener took, and a duplicate among the
    /// dokodemo list — including disabled entries, which the walk skips.
    doko_tag_errors: Vec<Option<String>>,
    /// i18n'd exposure warnings from the shell's verdict, pre-rendered at
    /// the same generation cadence as the collisions. Each listen field
    /// renders its own entry as the amber warning channel; the paths mirror
    /// the wire paths the assessment emits ("localInbounds[i].listen",
    /// "dokodemo[i].listen").
    local_warnings: Vec<Option<String>>,
    doko_warnings: Vec<Option<String>>,
}

impl ValidationCache {
    /// Whether these verdicts still describe `settings` at `generation`.
    ///
    /// Two conditions, both the cache's own: it was derived from the current
    /// model generation (the mutation hook moves it, so an edit inside the
    /// persist throttle window is covered), and it holds exactly one entry
    /// per rendered row — the render indexes these vectors by the live list
    /// index, so a row count that outgrew them would be an out-of-bounds
    /// read, and the cache states that precondition itself rather than
    /// trusting every caller to fold the counts into a key.
    fn is_current(&self, generation: u64, settings: &Settings) -> bool {
        self.generation == generation
            && self.local_collisions.len() == settings.local_inbounds.len()
            && self.doko_collisions.len() == settings.dokodemo.len()
    }
}

impl InboundsScreen {
    /// Hide the account credentials again. The shell calls this when the user
    /// leaves the screen, so a reveal never outlives the visit.
    pub(crate) fn mask_secrets(&mut self) {
        self.revealed = false;
    }

    pub fn show(&mut self, ui: &mut egui::Ui, ctx: &mut InboundsCtx) {
        let lang = ctx.settings.language;
        // The published generation verdict: the model rules the rows render
        // are asked here, by structural target, instead of re-derived per
        // row. The reference is copied out before the model is borrowed
        // mutably below.
        let verdict = ctx.verdict;
        // The validation references are rebuilt when the model generation
        // moves — the frame after any edit — and never on idle repaint
        // frames; the cache validates its own row correspondence.
        let generation = ctx.hooks.model_generation();
        if !matches!(&self.validation, Some(cache) if cache.is_current(generation, ctx.settings)) {
            let snapshot = listeners(ctx.settings, lang);
            // The shell's verdict for this generation: the exposure warnings
            // below are the one slice of it this screen renders, and the
            // assessment itself runs once per generation in the shell.
            let findings = ctx.safety;
            self.validation = Some(ValidationCache {
                generation,
                non_loopback: any_non_loopback_listen(ctx.settings),
                local_collisions: (0..ctx.settings.local_inbounds.len())
                    .map(|index| listener_collision(&snapshot, lang, ListenerKey::Local(index)))
                    .collect(),
                // A disabled listener reaches neither the wire nor the
                // settings walk, so its mask verdict must stay off the row
                // for the same reason the walk judges no row it drops.
                local_filter_errors: (0..ctx.settings.local_inbounds.len())
                    .map(|index| {
                        let entry = &ctx.settings.local_inbounds[index];
                        if !emit::local_inbound_emitted(entry) {
                            return Vec::new();
                        }
                        entry
                            .finalmask
                            .as_ref()
                            .map(|finalmask| {
                                validate_finalmask(finalmask)
                                    .iter()
                                    .map(|issue| validation_issue_message(issue, lang))
                                    .collect()
                            })
                            .unwrap_or_default()
                    })
                    .collect(),
                doko_collisions: (0..ctx.settings.dokodemo.len())
                    .map(|index| listener_collision(&snapshot, lang, ListenerKey::Dokodemo(index)))
                    .collect(),
                doko_references: ctx
                    .settings
                    .dokodemo
                    .iter()
                    .map(|entry| ctx.settings.routing.inbound_reference_count(&entry.tag))
                    .collect(),
                doko_tag_errors: (0..ctx.settings.dokodemo.len())
                    .map(|index| dokodemo_tag_error(ctx.settings, lang, index))
                    .collect(),
                local_warnings: (0..ctx.settings.local_inbounds.len())
                    .map(|index| {
                        findings
                            .local_inbound_exposure(index)
                            .map(|finding| safety_message(&finding.code, lang))
                    })
                    .collect(),
                doko_warnings: (0..ctx.settings.dokodemo.len())
                    .map(|index| {
                        findings
                            .dokodemo_exposure(index)
                            .map(|finding| safety_message(&finding.code, lang))
                    })
                    .collect(),
            });
        }
        let validation = match &self.validation {
            Some(cache) => cache,
            None => unreachable!("validation is built when absent, above"),
        };
        ui.add_space(4.0);
        // The scope is pushed unconditionally so its auto-id slot is always
        // consumed: the sections below (CollapsingHeader internals wrap each
        // section in a saltless `ui.vertical`, whose id embeds the parent's
        // auto-id counter) would otherwise shift their widget ids when the
        // warning appears/disappears, dropping egui focus from an edited field
        // (e.g. the listen address while a half-typed IP stops being
        // non-loopback).
        ui.push_id("posture-banner", |ui| {
            if validation.non_loopback {
                ui.label(egui::RichText::new(t(lang, Key::InboundsPostureWarn)).weak());
            }
        });
        ui.add_space(4.0);

        // ---- Local listeners: one row per user-managed
        // SOCKS/HTTP endpoint, in list order. Tags are GUI-owned and hidden;
        // the allocator assigns them once and they persist with the entry. The
        // section header carries the reveal control its account credentials
        // answer to, so the screen spends no row on a control of its own; the
        // local listen addresses stay visible — they are loopback literals, not
        // server information.
        let fakedns_on = ctx.settings.dns.fakedns.enabled;
        let mut remove: Option<usize> = None;
        let mut changed = false;
        widgets::section_with_reveal(
            ui,
            t(lang, Key::LocalListeners),
            lang,
            &mut self.revealed,
            |ui, masked| {
                if ctx.settings.local_inbounds.is_empty() {
                    ui.label(
                        egui::RichText::new(t(lang, Key::EmptyLocalListeners))
                            .small()
                            .weak(),
                    );
                }
                for (i, entry) in ctx.settings.local_inbounds.iter_mut().enumerate() {
                    // Hash the tag to an owned salt first: the row editor
                    // borrows the whole entry, which conflicts with a live
                    // reference into it.
                    let row_salt = egui::IdSalt::new(&entry.tag);
                    ui.push_id(row_salt, |ui| {
                        ui.horizontal(|ui| {
                            ui.monospace(protocol_label(lang, entry.protocol));
                            changed |= ui
                                .checkbox(&mut entry.enabled, t(lang, Key::Enabled))
                                .changed();
                            if ui.button(t(lang, Key::RemoveEndpoint)).clicked() {
                                remove = Some(i);
                            }
                        });
                        changed |=
                            widgets::port_field(ui, t(lang, Key::PortLower), &mut entry.port);
                        changed |= widgets::validated_field_with_warning(
                            ui,
                            t(lang, Key::InboundsListenAddress),
                            &mut entry.listen,
                            "127.0.0.1",
                            |listen| {
                                validate_listen_address(listen)
                                    .err()
                                    .map(|code| validation_message(&code, lang))
                            },
                            validation.local_warnings[i].as_deref(),
                        );
                        match entry.protocol {
                            LocalInboundProtocol::Socks => {
                                changed |= ui
                                    .checkbox(&mut entry.udp, t(lang, Key::InboundsUdpSupport))
                                    .changed();
                                if entry.udp {
                                    changed |= widgets::text_field(
                                        ui,
                                        t(lang, Key::InboundsUdpRelayIp),
                                        &mut entry.ip,
                                        t(lang, Key::InboundsUdpRelayIpHint),
                                    );
                                    if is_wildcard_listen(&entry.listen) {
                                        ui.label(
                                            egui::RichText::new(t(
                                                lang,
                                                Key::InboundsUdpWildcardHint,
                                            ))
                                            .small()
                                            .weak(),
                                        );
                                    }
                                }
                            }
                            // allowTransparent is intentionally not editable:
                            // values still round-trip through import/saved settings.
                            LocalInboundProtocol::Http => {}
                        }
                        let mut user_level = (entry.user_level != 0).then_some(entry.user_level);
                        if widgets::opt_u32(
                            ui,
                            t(lang, Key::UserLevel),
                            &mut user_level,
                            0..=u32::MAX,
                        ) {
                            entry.user_level = user_level.unwrap_or(0);
                            changed = true;
                        }
                        let mut auth_pw = entry.auth == "password";
                        if ui
                            .checkbox(&mut auth_pw, t(lang, Key::InboundsRequireAuth))
                            .changed()
                        {
                            entry.auth = if auth_pw {
                                "password".into()
                            } else {
                                "noauth".into()
                            };
                            changed = true;
                        }
                        if auth_pw {
                            changed |= accounts_editor(ui, lang, &mut entry.accounts, masked);
                        }
                        // The model's own row finding, rendered under the
                        // accounts editor it qualifies: password-mode HTTP with
                        // zero accounts authenticates nobody on the wire, so
                        // the row cannot apply at any bind.
                        inline_error(
                            ui,
                            row_finding(
                                verdict,
                                lang,
                                FindingTarget::LocalInbound(i),
                                &ValidationCode::LocalInboundAuthRequiresAccounts,
                            )
                            .as_deref(),
                        );
                        changed |= sniffing_editor(ui, lang, &mut entry.sniffing, fakedns_on);
                        inline_error(
                            ui,
                            row_finding(
                                verdict,
                                lang,
                                FindingTarget::LocalInbound(i),
                                &ValidationCode::SniffingDestOverrideInvalid,
                            )
                            .as_deref(),
                        );
                        changed |= local_filter_editor(ui, lang, entry);
                        for message in &validation.local_filter_errors[i] {
                            inline_error(ui, Some(message));
                        }
                        inline_error(ui, validation.local_collisions[i].as_deref());
                    });
                    ui.separator();
                }
                ui.horizontal(|ui| {
                    if ui.button(t(lang, Key::AddSocks)).clicked() {
                        let tag = next_local_tag(
                            &ctx.settings.local_inbounds,
                            LocalInboundProtocol::Socks,
                            &mut ctx.settings.socks_tag_seq,
                        );
                        ctx.settings
                            .local_inbounds
                            .push(LocalInboundCfg::socks_default(&tag));
                        changed = true;
                    }
                    if ui.button(t(lang, Key::AddHttp)).clicked() {
                        let tag = next_local_tag(
                            &ctx.settings.local_inbounds,
                            LocalInboundProtocol::Http,
                            &mut ctx.settings.http_tag_seq,
                        );
                        ctx.settings
                            .local_inbounds
                            .push(LocalInboundCfg::http_default(&tag));
                        changed = true;
                    }
                });
            },
        );
        if let Some(i) = remove {
            ctx.settings.local_inbounds.remove(i);
            changed = true;
        }
        if changed {
            ctx.hooks.mark_dirty();
        }

        // ---- Dokodemo-door ----
        let doko_len = ctx.settings.dokodemo.len();
        self.port_map_rows.resize_with(doko_len, Vec::new);
        let mut remove: Option<usize> = None;
        let mut changed = false;
        widgets::section(ui, t(lang, Key::InboundsSectionDokodemo), |ui| {
            for (i, d) in ctx.settings.dokodemo.iter_mut().enumerate() {
                let reference_count = validation.doko_references[i];
                // Hash the tag to an owned salt first: the closure captures
                // `d` mutably as a whole (the network editor takes &mut d),
                // which borrowck rejects while `&d.tag` is live as the salt.
                // References hash as their pointee, so child ids are exactly
                // what `push_id(&d.tag, ..)` would have produced.
                let row_salt = egui::IdSalt::new(&d.tag);
                ui.push_id(row_salt, |ui| {
                    ui.horizontal(|ui| {
                        ui.monospace(&d.tag)
                            .on_hover_text(t(lang, Key::InboundsStableTagHint));
                        changed |= ui.checkbox(&mut d.enabled, "").changed();
                        let delete = ui
                            .add_enabled(
                                reference_count == 0,
                                egui::Button::new(t(lang, Key::DeleteRow)),
                            )
                            .on_hover_text(t(lang, Key::InboundsDeleteDokodemo))
                            .on_disabled_hover_text(t_fmt(
                                lang,
                                Key::InboundsUsedByRules,
                                &[&reference_count],
                            ));
                        if delete.clicked() {
                            remove = Some(i);
                        }
                    });
                    inline_error(ui, validation.doko_tag_errors[i].as_deref());
                    inline_error(ui, validation.doko_collisions[i].as_deref());
                    if reference_count != 0 {
                        ui.label(
                            egui::RichText::new(t_fmt(
                                lang,
                                Key::InboundsDeleteBlocked,
                                &[&reference_count],
                            ))
                            .small()
                            .color(ui.visuals().warn_fg_color),
                        );
                    }

                    changed |= dokodemo_network_editor(ui, lang, d);
                    match d.network_mode() {
                        Ok(DokodemoNetwork::Unix) => {
                            changed |= widgets::text_field(
                                ui,
                                t(lang, Key::InboundsUnixPath),
                                &mut d.unix_socket_path,
                                r"C:\path\to\xray.sock",
                            );
                            ui.label(
                                egui::RichText::new(t(lang, Key::InboundsUnixNote))
                                    .small()
                                    .weak(),
                            );
                        }
                        Ok(_) => {
                            changed |= widgets::port_field(
                                ui,
                                t(lang, Key::InboundsListenPort),
                                &mut d.listen_port,
                            );
                            changed |= widgets::validated_field_with_warning(
                                ui,
                                t(lang, Key::InboundsListenAddress),
                                &mut d.listen,
                                "127.0.0.1",
                                |listen| {
                                    validate_listen_address(listen)
                                        .err()
                                        .map(|code| validation_message(&code, lang))
                                },
                                validation.doko_warnings[i].as_deref(),
                            );
                        }
                        Err(_) => {
                            ui.label(
                                egui::RichText::new(t(lang, Key::InboundsImportedNote))
                                    .small()
                                    .weak(),
                            );
                            changed |= widgets::port_field(
                                ui,
                                t(lang, Key::InboundsListenPort),
                                &mut d.listen_port,
                            );
                            changed |= widgets::text_field(
                                ui,
                                t(lang, Key::InboundsUnixPath),
                                &mut d.unix_socket_path,
                                r"C:\path\to\xray.sock",
                            );
                        }
                    }
                    ui.horizontal(|ui| {
                        ui.label("→");
                        changed |= widgets::text_field(
                            ui,
                            t(lang, Key::InboundsTargetAddress),
                            &mut d.address,
                            t(lang, Key::InboundsTargetAddressHint),
                        );
                        changed |=
                            widgets::port_field(ui, t(lang, Key::InboundsTargetPort), &mut d.port);
                    });
                    ui.horizontal(|ui| {
                        let mut ul = (d.user_level != 0).then_some(d.user_level);
                        if widgets::opt_u32(ui, t(lang, Key::UserLevel), &mut ul, 0..=u32::MAX) {
                            d.user_level = ul.unwrap_or(0);
                            changed = true;
                        }
                    });
                    // port_map: two-column editor over transient rows
                    ui.label(t(lang, Key::InboundsPortMap));
                    let rows = &mut self.port_map_rows[i];
                    if rows.is_empty() && !d.port_map.is_empty() {
                        *rows = d
                            .port_map
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect();
                    }
                    // The model sync below must gate on THIS row's port-map
                    // editors only: the section-wide `changed` flag is set by
                    // any row's any field (a keystroke in row 0 would
                    // otherwise rebuild every seeded row's map every frame).
                    let mut map_changed = false;
                    let mut del: Option<usize> = None;
                    for (j, (k, v)) in rows.iter_mut().enumerate() {
                        ui.horizontal(|ui| {
                            if ui
                                .add(
                                    egui::TextEdit::singleline(k)
                                        .desired_width(70.0)
                                        .hint_text("53"),
                                )
                                .changed()
                                || ui
                                    .add(
                                        egui::TextEdit::singleline(v)
                                            .desired_width(170.0)
                                            .hint_text("8.8.8.8:53"),
                                    )
                                    .changed()
                            {
                                map_changed = true;
                            }
                            if ui.button(t(lang, Key::DeleteRow)).clicked() {
                                del = Some(j);
                            }
                        });
                    }
                    if let Some(j) = del {
                        rows.remove(j);
                        map_changed = true;
                    }
                    if ui.button(t(lang, Key::InboundsAddPortMapping)).clicked() {
                        rows.push((String::new(), String::new()));
                        map_changed = true;
                    }
                    if map_changed {
                        changed = true;
                        d.port_map = rows
                            .iter()
                            .filter(|(k, _)| !k.trim().is_empty())
                            .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                            .collect();
                    }
                    changed |= sniffing_editor(ui, lang, &mut d.sniffing, fakedns_on);
                    inline_error(
                        ui,
                        row_finding(
                            verdict,
                            lang,
                            FindingTarget::Dokodemo(i),
                            &ValidationCode::SniffingDestOverrideInvalid,
                        )
                        .as_deref(),
                    );
                });
                ui.separator();
            }
            if ui.button(t(lang, Key::InboundsAddDokodemo)).clicked() {
                let tag = new_dokodemo_tag(&ctx.settings.dokodemo);
                ctx.settings.dokodemo.push(DokodemoCfg {
                    tag,
                    ..Default::default()
                });
                changed = true;
            }
        });
        if let Some(i) = remove {
            ctx.settings.dokodemo.remove(i);
            self.port_map_rows.remove(i);
            changed = true;
        }
        if changed {
            ctx.hooks.mark_dirty();
        }
    }
}

/// Which mask list a listener's filter section edits.
#[derive(Clone, Copy)]
enum FilterList {
    Tcp,
    Udp,
}

/// The listener's source-IP `filter` mask, one toggle per mask list the
/// listener runs (TCP always; UDP when the SOCKS relay is on). Enabling seeds
/// an empty mask: the core builds no matcher from empty lists, so the mask
/// changes nothing until a rule is added. `None` keeps the block out of the
/// generated document.
fn local_filter_editor(ui: &mut egui::Ui, lang: Language, entry: &mut LocalInboundCfg) -> bool {
    let had_finalmask = entry.finalmask.is_some();
    let mut finalmask = entry.finalmask.take().unwrap_or_default();
    let udp_listener = entry.protocol == LocalInboundProtocol::Socks && entry.udp;
    let mut changed = false;
    widgets::section(ui, t(lang, Key::InboundsFilterMask), |ui| {
        ui.label(
            egui::RichText::new(t(lang, Key::InboundsFilterMaskHint))
                .small()
                .weak(),
        );
        changed |= filter_list_editor(ui, lang, FilterList::Tcp, &mut finalmask);
        if udp_listener {
            changed |= filter_list_editor(ui, lang, FilterList::Udp, &mut finalmask);
        }
    });
    if had_finalmask || !finalmask.is_empty() {
        entry.finalmask = Some(finalmask);
    }
    changed
}

fn filter_list_editor(
    ui: &mut egui::Ui,
    lang: Language,
    list: FilterList,
    finalmask: &mut FinalmaskModel,
) -> bool {
    let mut enabled = match list {
        FilterList::Tcp => finalmask
            .tcp
            .iter()
            .any(|mask| matches!(mask, FinalmaskTcpMask::Filter { .. })),
        FilterList::Udp => finalmask
            .udp
            .iter()
            .any(|mask| matches!(mask, FinalmaskUdpMask::Filter { .. })),
    };
    let mut changed = false;
    let label = match list {
        FilterList::Tcp => "TCP",
        FilterList::Udp => "UDP",
    };
    if ui.checkbox(&mut enabled, label).changed() {
        changed = true;
        match list {
            FilterList::Tcp => finalmask
                .tcp
                .retain(|mask| !matches!(mask, FinalmaskTcpMask::Filter { .. })),
            FilterList::Udp => finalmask
                .udp
                .retain(|mask| !matches!(mask, FinalmaskUdpMask::Filter { .. })),
        }
        if enabled {
            match list {
                FilterList::Tcp => finalmask.tcp.push(FinalmaskTcpMask::Filter {
                    settings: Default::default(),
                    extra: Map::new(),
                }),
                FilterList::Udp => finalmask.udp.push(FinalmaskUdpMask::Filter {
                    settings: Default::default(),
                    extra: Map::new(),
                }),
            }
        }
    }
    let settings = match list {
        FilterList::Tcp => finalmask.tcp.iter_mut().find_map(|mask| match mask {
            FinalmaskTcpMask::Filter { settings, .. } => Some(settings),
            _ => None,
        }),
        FilterList::Udp => finalmask.udp.iter_mut().find_map(|mask| match mask {
            FinalmaskUdpMask::Filter { settings, .. } => Some(settings),
            _ => None,
        }),
    };
    if let Some(settings) = settings {
        changed |= filter_settings_editor(ui, lang, settings);
    }
    changed
}

fn dokodemo_network_editor(ui: &mut egui::Ui, lang: Language, config: &mut DokodemoCfg) -> bool {
    const MODES: [(DokodemoNetwork, Key); 3] = [
        (DokodemoNetwork::Tcp, Key::InboundsModeTcp),
        (DokodemoNetwork::Udp, Key::InboundsModeUdp),
        (DokodemoNetwork::TcpUdp, Key::InboundsModeTcpUdp),
    ];

    let parsed = config.network_mode();
    let selected = parsed.as_ref().ok().copied();
    let imported_error = parsed.err();
    let mut chosen = None;
    ui.horizontal_wrapped(|ui| {
        ui.label(t(lang, Key::InboundsListener));
        for (mode, key) in MODES {
            if ui
                .selectable_label(selected == Some(mode), t(lang, key))
                .clicked()
                && selected != Some(mode)
            {
                chosen = Some(mode);
            }
        }
        if imported_error.is_some() {
            ui.selectable_label(
                true,
                t_fmt(
                    lang,
                    Key::InboundsPreserveImported,
                    &[&format!("{:?}", config.network)],
                ),
            )
            .on_hover_text(t(lang, Key::InboundsPreserveImportedHint));
        }
    });

    if let Some(mode) = chosen {
        config.network = mode.canonical().into();
        return true;
    }
    if let Some(error) = imported_error {
        inline_error(
            ui,
            Some(&t_fmt(
                lang,
                Key::InboundsImportedUnsupported,
                &[&format!("{:?}", config.network), &error],
            )),
        );
    }
    false
}

/// Locale label for one local-endpoint protocol — the row's protocol chip
/// on the inbounds screen and the dashboard status row prefix.
pub(crate) fn protocol_label(lang: Language, protocol: LocalInboundProtocol) -> &'static str {
    match protocol {
        LocalInboundProtocol::Socks => t(lang, Key::EndpointProtocolSocks),
        LocalInboundProtocol::Http => t(lang, Key::EndpointProtocolHttp),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ListenerKey {
    Local(usize),
    Dokodemo(usize),
}

enum ListenerEndpoint {
    IpPort {
        listen: String,
        port: u16,
        protocols: u8,
    },
    Unix {
        path: String,
    },
    Invalid(String),
}

struct ListenerView {
    key: ListenerKey,
    label: String,
    enabled: bool,
    endpoint: ListenerEndpoint,
}

const TCP: u8 = 1;
const UDP: u8 = 2;

/// True when some ENABLED IP listener binds a non-loopback address. An
/// unparseable listen is treated as loopback — validation reports it as an
/// error, so it should never warn as a LAN exposure.
fn any_non_loopback_listen(settings: &Settings) -> bool {
    // The address is classified in its socket form, as the model's exposure
    // rule does: an IPv4-mapped loopback literal binds loopback.
    let non_loopback = |listen: &str| -> bool {
        listen
            .parse::<std::net::IpAddr>()
            .map(|address| !crate::model::inbound::socket_address(address).is_loopback())
            .unwrap_or(false)
    };
    settings
        .local_inbounds
        .iter()
        .any(|entry| entry.enabled && non_loopback(&entry.listen))
        || settings.dokodemo.iter().any(|entry| {
            entry.enabled
                && matches!(
                    entry.network_mode(),
                    Ok(DokodemoNetwork::Tcp | DokodemoNetwork::Udp | DokodemoNetwork::TcpUdp)
                )
                && non_loopback(&entry.listen)
        })
}

fn listeners(settings: &Settings, lang: Language) -> Vec<ListenerView> {
    // The control-plane API listener is loopback-only on an ephemeral port:
    // it is chosen at generation time, so the UI cannot list or
    // collide it against user-editable listeners here.
    let mut result = Vec::with_capacity(settings.local_inbounds.len() + settings.dokodemo.len());
    result.extend(
        settings
            .local_inbounds
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                let protocols = match entry.protocol {
                    LocalInboundProtocol::Socks => TCP | if entry.udp { UDP } else { 0 },
                    LocalInboundProtocol::Http => TCP,
                };
                ListenerView {
                    key: ListenerKey::Local(index),
                    label: protocol_label(lang, entry.protocol).into(),
                    enabled: entry.enabled,
                    endpoint: ListenerEndpoint::IpPort {
                        listen: entry.listen.clone(),
                        port: entry.port,
                        protocols,
                    },
                }
            }),
    );
    result.extend(settings.dokodemo.iter().enumerate().map(|(index, entry)| {
        let endpoint = match entry.network_mode() {
            Ok(DokodemoNetwork::Tcp) => ListenerEndpoint::IpPort {
                listen: entry.listen.clone(),
                port: entry.listen_port,
                protocols: TCP,
            },
            Ok(DokodemoNetwork::Udp) => ListenerEndpoint::IpPort {
                listen: entry.listen.clone(),
                port: entry.listen_port,
                protocols: UDP,
            },
            Ok(DokodemoNetwork::TcpUdp) => ListenerEndpoint::IpPort {
                listen: entry.listen.clone(),
                port: entry.listen_port,
                protocols: TCP | UDP,
            },
            Ok(DokodemoNetwork::Unix) => ListenerEndpoint::Unix {
                path: entry.unix_socket_path.clone(),
            },
            Err(error) => ListenerEndpoint::Invalid(error),
        };
        ListenerView {
            key: ListenerKey::Dokodemo(index),
            label: t_fmt(lang, Key::ListenerLabelDokodemo, &[&entry.tag]),
            enabled: entry.enabled,
            endpoint,
        }
    }));
    result
}

/// The row's collision verdict, or `None` when the row is appliable. The
/// conjunction itself is one definition
/// (`crate::model::inbound::listen_endpoints_conflict`); this walk keeps the
/// draft-level concerns — invalid endpoints, the zero port, the empty UNIX
/// path, disabled listeners, path normalization, labels, and the
/// `Collision*` keys the model pass cannot render.
fn listener_collision(
    listeners: &[ListenerView],
    lang: Language,
    key: ListenerKey,
) -> Option<String> {
    let current = listeners.iter().find(|listener| listener.key == key)?;
    if let ListenerEndpoint::Invalid(error) = &current.endpoint {
        return Some(t_fmt(
            lang,
            Key::CollisionInvalidNetwork,
            &[&current.label, error],
        ));
    }
    if !current.enabled {
        return None;
    }

    let (conflicts, endpoint) = match &current.endpoint {
        ListenerEndpoint::IpPort {
            listen,
            port,
            protocols,
        } => {
            if *port == 0 {
                return Some(t_fmt(lang, Key::CollisionNeedsPort, &[&current.label]));
            }
            let current_endpoint = (*port, *protocols, listen.as_str());
            let conflicts = listeners
                .iter()
                .filter(|other| other.key != key && other.enabled)
                .filter(|other| match &other.endpoint {
                    ListenerEndpoint::IpPort {
                        listen: other_listen,
                        port: other_port,
                        protocols: other_protocols,
                    } => listen_endpoints_conflict(
                        current_endpoint,
                        (*other_port, *other_protocols, other_listen.as_str()),
                    ),
                    ListenerEndpoint::Unix { .. } | ListenerEndpoint::Invalid(_) => false,
                })
                .map(|other| other.label.as_str())
                .collect::<Vec<_>>();
            (conflicts, format!("{listen}:{port}"))
        }
        ListenerEndpoint::Unix { path } => {
            if path.trim().is_empty() {
                return Some(t_fmt(lang, Key::CollisionNeedsUnix, &[&current.label]));
            }
            let normalized = normalize_windows_socket_path(path);
            let conflicts = listeners
                .iter()
                .filter(|other| other.key != key && other.enabled)
                .filter(|other| {
                    matches!(
                        &other.endpoint,
                        ListenerEndpoint::Unix { path: other_path }
                            if normalize_windows_socket_path(other_path) == normalized
                    )
                })
                .map(|other| other.label.as_str())
                .collect::<Vec<_>>();
            (
                conflicts,
                t_fmt(lang, Key::CollisionEndpoint, &[&format!("{path:?}")]),
            )
        }
        ListenerEndpoint::Invalid(_) => unreachable!(),
    };

    if conflicts.is_empty() {
        None
    } else {
        Some(t_fmt(
            lang,
            Key::CollisionConflict,
            &[&current.label, &conflicts.join(", "), &endpoint],
        ))
    }
}

/// The row-label tag verdict for one dokodemo entry. This is the screen's own
/// check, not a re-derivation of a walk rule: it names the tag problem in the
/// row's vocabulary (`DokodemoTagMissing`/`Builtin`/`Duplicate`), judges
/// entries the walk drops (a disabled row still shows its label fault), and
/// answers "which label is wrong" rather than "is this document appliable".
fn dokodemo_tag_error(settings: &Settings, lang: Language, index: usize) -> Option<String> {
    let tag = settings.dokodemo.get(index)?.tag.trim();
    if tag.is_empty() {
        return Some(t(lang, Key::DokodemoTagMissing).into());
    }
    // Reserved-tag collisions: every local endpoint tag — the user-managed
    // list replaced the fixed in-socks/in-http builtins, so its tags are
    // builtins now — plus the listeners the app appends behind them (tun and
    // the in-tun DNS pair, gated exactly as the emitter gates them) and the
    // api control plane. The in-tun DNS listeners are added to the running
    // core rather than emitted, but their tags are taken all the same.
    if emit::appended_inbound_tags(settings)
        .chain(std::iter::once(API_INBOUND_TAG))
        .any(|reserved| reserved == tag)
        || settings.local_inbounds.iter().any(|entry| entry.tag == tag)
    {
        return Some(t_fmt(lang, Key::DokodemoTagBuiltin, &[&format!("{tag:?}")]));
    }
    if settings
        .dokodemo
        .iter()
        .enumerate()
        .any(|(other, entry)| other != index && entry.tag == tag)
    {
        return Some(t_fmt(
            lang,
            Key::DokodemoTagDuplicate,
            &[&format!("{tag:?}")],
        ));
    }
    None
}

/// One row's finding of `code` from the published generation verdict,
/// rendered as the code's own message. The model reported it for this
/// structural target, so the row only asks and renders: the finding's path is
/// the document's location text, which the row itself already is.
fn row_finding(
    verdict: &Verdict,
    lang: Language,
    target: FindingTarget,
    code: &ValidationCode,
) -> Option<String> {
    verdict
        .for_target(target)
        .find(|issue| &issue.code == code)
        .map(|issue| validation_message(&issue.code, lang))
}

fn inline_error(ui: &mut egui::Ui, error: Option<&str>) {
    if let Some(error) = error {
        ui.label(
            egui::RichText::new(error)
                .small()
                .color(crate::ui::status::status_colors_of(ui).err),
        );
    }
}

fn accounts_editor(
    ui: &mut egui::Ui,
    lang: Language,
    accounts: &mut Vec<Account>,
    // Whether the account credentials render masked (the reveal control).
    masked: bool,
) -> bool {
    let mut changed = false;
    ui.label(t(lang, Key::Accounts));
    let mut del: Option<usize> = None;
    for (i, a) in accounts.iter_mut().enumerate() {
        ui.horizontal(|ui| {
            if masked {
                // The stand-in carries the field's own hint, so a row with no
                // credential looks the same masked and revealed.
                widgets::masked_stand_in(ui, !a.user.is_empty(), t(lang, Key::AccountUserHint));
                widgets::masked_stand_in(ui, !a.pass.is_empty(), t(lang, Key::AccountPasswordHint));
            } else if ui
                .add(
                    egui::TextEdit::singleline(&mut a.user)
                        .desired_width(110.0)
                        .hint_text(t(lang, Key::AccountUserHint)),
                )
                .changed()
                || ui
                    .add(
                        egui::TextEdit::singleline(&mut a.pass)
                            .desired_width(110.0)
                            .hint_text(t(lang, Key::AccountPasswordHint)),
                    )
                    .changed()
            {
                changed = true;
            }
            if ui.button(t(lang, Key::DeleteRow)).clicked() {
                del = Some(i);
            }
        });
    }
    if let Some(i) = del {
        accounts.remove(i);
        changed = true;
    }
    if ui.button(t(lang, Key::AddAccount)).clicked() {
        accounts.push(Account::default());
        changed = true;
    }
    changed
}

pub(crate) fn sniffing_editor(
    ui: &mut egui::Ui,
    lang: Language,
    s: &mut Sniffing,
    fakedns_on: bool,
) -> bool {
    let mut changed = false;
    widgets::section(ui, t(lang, Key::SniffingSection), |ui| {
        changed |= ui.checkbox(&mut s.enabled, t(lang, Key::Enabled)).changed();
        ui.horizontal(|ui| {
            ui.label(t(lang, Key::SniffingDestOverride));
            for proto in ["http", "tls", "quic"] {
                let mut on = s.dest_override.iter().any(|d| d == proto);
                if ui.checkbox(&mut on, proto).changed() {
                    if on {
                        s.dest_override.push(proto.into());
                    } else {
                        s.dest_override.retain(|d| d != proto);
                    }
                    changed = true;
                }
            }
            if fakedns_on {
                ui.add_enabled_ui(false, |ui| {
                    let mut checked = true;
                    ui.checkbox(&mut checked, "fakedns")
                        .on_hover_text(t(lang, Key::SniffingFakednsHint));
                });
            }
        });
        changed |= widgets::string_list(
            ui,
            lang,
            t(lang, Key::SniffingDomainsExcluded),
            &mut s.domains_excluded,
            "example.com",
        );
        changed |= widgets::string_list(
            ui,
            lang,
            t(lang, Key::SniffingIpsExcluded),
            &mut s.ips_excluded,
            "1.2.3.0/24",
        );
        changed |= crate::ui::routing::opt_bool(
            ui,
            t(lang, Key::SniffingMetadataOnly),
            &mut s.metadata_only,
        );
        changed |= ui
            .checkbox(&mut s.route_only, t(lang, Key::SniffingRouteOnly))
            .changed();
    });
    changed
}

#[cfg(test)]
mod listener_validation_tests {
    use super::{
        InboundsScreen, ListenerKey, dokodemo_tag_error, listener_collision, listeners,
        normalize_windows_socket_path,
    };
    use crate::i18n::validation_message;
    use crate::model::settings::Language;
    use crate::model::validation::ValidationCode;
    use crate::model::{DokodemoCfg, LocalInboundCfg, LocalInboundProtocol, Settings};
    use crate::ui::test_rig::UiTestRig;
    use egui_kittest::{Harness, kittest::Queryable as _};
    use std::cell::RefCell;
    use std::rc::Rc;

    /// The shared row-error text, rendered through the model code the
    /// verdict pass emits (one rule, one message).
    fn auth_requires_accounts_error() -> String {
        validation_message(
            &ValidationCode::LocalInboundAuthRequiresAccounts,
            Language::En,
        )
    }

    /// The sniffing vocabulary's own message, rendered through the code the
    /// walk publishes.
    fn sniffing_override_error() -> String {
        validation_message(&ValidationCode::SniffingDestOverrideInvalid, Language::En)
    }

    /// The row asks the published verdict for its sniffing finding: an
    /// emitted row carrying an unknown `destOverride` item renders the model's
    /// message, and clearing the item clears it on the next frame.
    #[test]
    fn emitted_row_renders_the_verdicts_sniffing_finding() {
        let rig = Rc::new(RefCell::new(UiTestRig::default()));
        {
            let mut rig = rig.borrow_mut();
            rig.settings.local_inbounds[0].sniffing.enabled = true;
            rig.settings.local_inbounds[0].sniffing.dest_override = vec!["nope".into()];
        }
        let mut harness = harness_for(rig.clone());
        harness.run();
        assert!(
            harness
                .query_by_label(sniffing_override_error().as_str())
                .is_some(),
            "the row must render the finding the settings walk published"
        );

        {
            let mut rig = rig.borrow_mut();
            rig.settings.local_inbounds[0]
                .sniffing
                .dest_override
                .clear();
            rig.edit();
        }
        harness.run();
        harness.run();
        assert!(
            harness
                .query_by_label(sniffing_override_error().as_str())
                .is_none(),
            "clearing the refused item must clear the row finding"
        );
    }

    #[test]
    fn enabled_overlapping_listener_protocols_collide() {
        let lang = Language::En;
        let mut settings = Settings::default();
        settings.local_inbounds[1].port = settings.local_inbounds[0].port;
        assert!(
            listener_collision(&listeners(&settings, lang), lang, ListenerKey::Local(0)).is_some()
        );

        settings.local_inbounds[1].enabled = false;
        settings.local_inbounds[0].udp = false;
        settings.dokodemo.push(DokodemoCfg {
            tag: "in-doko-udp".into(),
            enabled: true,
            listen_port: settings.local_inbounds[0].port,
            network: "udp".into(),
            ..Default::default()
        });
        assert!(
            listener_collision(&listeners(&settings, lang), lang, ListenerKey::Local(0)).is_none()
        );
    }

    #[test]
    fn wildcard_listen_collides_with_specific_listen_on_shared_port() {
        let lang = Language::En;
        let mut settings = Settings::default();
        settings.local_inbounds[1].port = settings.local_inbounds[0].port;
        settings.local_inbounds[0].listen = "0.0.0.0".into();
        settings.local_inbounds[1].listen = "127.0.0.1".into();

        let error = listener_collision(&listeners(&settings, lang), lang, ListenerKey::Local(0))
            .expect("wildcard SOCKS listen must collide with HTTP");
        assert!(error.contains("conflicts with HTTP"), "{error}");
        assert!(
            error.contains("0.0.0.0:"),
            "endpoint must be the wildcard listen: {error}"
        );
    }

    #[test]
    fn distinct_listen_addresses_do_not_collide_on_shared_port() {
        let lang = Language::En;
        let mut settings = Settings::default();
        settings.local_inbounds[1].port = settings.local_inbounds[0].port;
        settings.local_inbounds[0].listen = "127.0.0.1".into();
        settings.local_inbounds[1].listen = "192.168.1.5".into();
        assert!(
            listener_collision(&listeners(&settings, lang), lang, ListenerKey::Local(0)).is_none()
        );
        assert!(
            listener_collision(&listeners(&settings, lang), lang, ListenerKey::Local(1)).is_none()
        );

        // ...but equal concrete addresses still collide
        settings.local_inbounds[1].listen = settings.local_inbounds[0].listen.clone();
        assert!(
            listener_collision(&listeners(&settings, lang), lang, ListenerKey::Local(0)).is_some()
        );
    }

    #[test]
    fn unix_collisions_use_case_insensitive_lexically_normalized_windows_paths() {
        let mut settings = Settings::default();
        settings.local_inbounds[0].enabled = false;
        settings.local_inbounds[1].enabled = false;
        settings.dokodemo = vec![
            DokodemoCfg {
                tag: "in-doko-unix-a".into(),
                enabled: true,
                network: "unix".into(),
                unix_socket_path: r"C:\broccoli\sockets\.\xray.sock".into(),
                ..Default::default()
            },
            DokodemoCfg {
                tag: "in-doko-unix-b".into(),
                enabled: true,
                network: "UNIX".into(),
                unix_socket_path: "c:/broccoli/sockets/xray.sock".into(),
                ..Default::default()
            },
        ];

        let lang = Language::En;
        let error = listener_collision(&listeners(&settings, lang), lang, ListenerKey::Dokodemo(0))
            .expect("normalized UNIX socket paths must collide");
        assert!(error.contains("UNIX socket"));
        assert_eq!(
            normalize_windows_socket_path(r"C:\broccoli\socket\..\xray.sock"),
            normalize_windows_socket_path("c:/broccoli/xray.sock")
        );

        settings.dokodemo[1].unix_socket_path = r"C:\broccoli\other.sock".into();
        assert!(
            listener_collision(&listeners(&settings, lang), lang, ListenerKey::Dokodemo(0))
                .is_none()
        );
    }

    #[test]
    fn unix_listener_never_collides_with_ip_port_listener() {
        let mut settings = Settings::default();
        settings.local_inbounds[1].enabled = false;
        settings.local_inbounds[0].udp = false;
        settings.dokodemo.push(DokodemoCfg {
            tag: "in-doko-unix".into(),
            enabled: true,
            listen_port: settings.local_inbounds[0].port,
            network: "unix".into(),
            unix_socket_path: r"C:\broccoli\xray.sock".into(),
            ..Default::default()
        });

        let lang = Language::En;
        assert!(
            listener_collision(&listeners(&settings, lang), lang, ListenerKey::Local(0)).is_none()
        );
        assert!(
            listener_collision(&listeners(&settings, lang), lang, ListenerKey::Dokodemo(0))
                .is_none()
        );
    }

    #[test]
    fn malformed_networks_are_errors_not_tcp_udp_collisions() {
        let lang = Language::En;
        for network in ["unix,tcp", "quic"] {
            let mut settings = Settings::default();
            settings.local_inbounds[1].enabled = false;
            settings.local_inbounds[0].udp = false;
            settings.dokodemo.push(DokodemoCfg {
                tag: "in-doko-imported".into(),
                enabled: true,
                listen_port: settings.local_inbounds[0].port,
                network: network.into(),
                ..Default::default()
            });

            let error =
                listener_collision(&listeners(&settings, lang), lang, ListenerKey::Dokodemo(0))
                    .expect("malformed network must be reported");
            assert!(error.contains("invalid listener network"));
            assert!(!error.contains("conflicts"));
            assert!(
                listener_collision(&listeners(&settings, lang), lang, ListenerKey::Local(0))
                    .is_none()
            );
        }
    }

    #[test]
    fn duplicate_stable_inbound_tags_are_reported() {
        let lang = Language::En;
        let settings = Settings {
            dokodemo: vec![
                DokodemoCfg {
                    tag: "same".into(),
                    ..Default::default()
                },
                DokodemoCfg {
                    tag: "same".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        assert!(dokodemo_tag_error(&settings, lang, 0).is_some());
    }

    #[test]
    fn dokodemo_tag_colliding_with_a_local_endpoint_tag_is_reported() {
        let lang = Language::En;
        // Default list carries tags in-socks/in-http; a dokodemo tag reusing
        // one collides with an emitted local endpoint.
        let settings = Settings {
            dokodemo: vec![DokodemoCfg {
                tag: "in-socks".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(dokodemo_tag_error(&settings, lang, 0).is_some());
        assert!(
            dokodemo_tag_error(&settings, lang, 0)
                .unwrap()
                .contains("built-in")
        );
    }

    #[test]
    fn duplicate_port_across_list_entries_is_flagged() {
        let lang = Language::En;
        let mut settings = Settings::default();
        // A third entry sharing the first entry's listen:port collides with
        // it, in both directions, whatever its protocol.
        settings
            .local_inbounds
            .push(LocalInboundCfg::socks_default("in-socks-1"));
        assert!(
            listener_collision(&listeners(&settings, lang), lang, ListenerKey::Local(0)).is_some()
        );
        assert!(
            listener_collision(&listeners(&settings, lang), lang, ListenerKey::Local(2)).is_some()
        );

        // A distinct port clears the collision for both rows.
        settings.local_inbounds[2].port = 10999;
        assert!(
            listener_collision(&listeners(&settings, lang), lang, ListenerKey::Local(0)).is_none()
        );
        assert!(
            listener_collision(&listeners(&settings, lang), lang, ListenerKey::Local(2)).is_none()
        );
    }

    /// A tall harness so every list row and the add buttons render into the
    /// AccessKit tree without scrolling (the screen has no ScrollArea of its
    /// own in this unit-harness context).
    fn harness_for(rig: Rc<RefCell<UiTestRig>>) -> Harness<'static, InboundsScreen> {
        Harness::builder()
            .with_size(egui::vec2(900.0, 2400.0))
            .build_ui_state(
                move |ui, screen: &mut InboundsScreen| {
                    let mut rig = rig.borrow_mut();
                    screen.show(ui, &mut rig.ctx().inbounds())
                },
                InboundsScreen::default(),
            )
    }

    /// The add buttons allocate the next free `in-<proto>-<n>` tag for the
    /// clicked protocol and push a protocol-defaulted entry.
    #[test]
    fn add_socks_button_allocates_in_socks_1() {
        let rig = Rc::new(RefCell::new(UiTestRig::default()));
        let mut harness = harness_for(rig.clone());
        harness.run();

        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "Add SOCKS")
            .click();
        harness.run();

        let settings = &rig.borrow().settings;
        assert_eq!(settings.local_inbounds.len(), 3);
        let added = &settings.local_inbounds[2];
        assert_eq!(added.tag, "in-socks-1");
        assert_eq!(added.protocol, LocalInboundProtocol::Socks);
        assert!(added.enabled);
        assert_eq!(added.port, 10808);
        assert_eq!(added.listen, "127.0.0.1");
    }

    #[test]
    fn add_http_button_allocates_in_http_1() {
        let rig = Rc::new(RefCell::new(UiTestRig::default()));
        let mut harness = harness_for(rig.clone());
        harness.run();

        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "Add HTTP")
            .click();
        harness.run();

        let settings = &rig.borrow().settings;
        assert_eq!(settings.local_inbounds.len(), 3);
        let added = &settings.local_inbounds[2];
        assert_eq!(added.tag, "in-http-1");
        assert_eq!(added.protocol, LocalInboundProtocol::Http);
        assert!(added.enabled);
        assert_eq!(added.port, 10809);
    }

    /// The remove button deletes exactly its own row; the surviving entries
    /// keep their tags and order.
    #[test]
    fn remove_button_deletes_the_row() {
        let rig = Rc::new(RefCell::new(UiTestRig::default()));
        {
            let mut rig = rig.borrow_mut();
            rig.settings
                .local_inbounds
                .push(LocalInboundCfg::socks_default("in-socks-1"));
        }
        let mut harness = harness_for(rig.clone());
        harness.run();

        // One Remove button per row, in list order; delete the row the test
        // added (the third row).
        let removes: Vec<_> = harness
            .get_all_by_role_and_label(egui::accesskit::Role::Button, "Remove")
            .collect();
        assert_eq!(removes.len(), 3, "every local row must offer Remove");
        removes[2].click();
        harness.run();

        let settings = &rig.borrow().settings;
        assert_eq!(settings.local_inbounds.len(), 2);
        assert_eq!(settings.local_inbounds[0].tag, "in-socks");
        assert_eq!(settings.local_inbounds[1].tag, "in-http");
        assert!(
            settings
                .local_inbounds
                .iter()
                .all(|entry| entry.tag != "in-socks-1"),
            "removing a row must drop its entry from the list"
        );
    }

    /// The empty-list hint renders when every entry is removed.
    #[test]
    fn removing_every_entry_renders_the_empty_hint() {
        let rig = Rc::new(RefCell::new(UiTestRig::default()));
        let mut harness = harness_for(rig.clone());
        harness.run();

        for _ in 0..2 {
            let removes: Vec<_> = harness
                .get_all_by_role_and_label(egui::accesskit::Role::Button, "Remove")
                .collect();
            removes[0].click();
            harness.run();
        }
        assert_eq!(rig.borrow().settings.local_inbounds.len(), 0);
        // Removal applies at the end of its frame; the hint renders once the
        // following frame rebuilds for the empty list.
        harness.run();
        assert!(
            harness
                .query_by_label("No local listeners configured")
                .is_some(),
            "an empty list must render the empty-state hint"
        );
    }

    /// The password-mode HTTP row with zero accounts renders the shared
    /// gate error inline, and adding the first account clears it.
    #[test]
    fn password_mode_http_row_error_clears_when_the_first_account_is_added() {
        let rig = Rc::new(RefCell::new(UiTestRig::default()));
        {
            let mut rig = rig.borrow_mut();
            // The seeded HTTP row (index 1): Require auth ticked, no
            // accounts, loopback bind — the trap holds at any bind.
            rig.settings.local_inbounds[1].auth = "password".into();
        }
        let mut harness = harness_for(rig.clone());
        harness.run();
        assert!(
            harness
                .query_by_label(auth_requires_accounts_error().as_str())
                .is_some(),
            "the trapped row must render the shared inline error"
        );

        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "+ account")
            .click();
        harness.run();
        // The model mutation lands at the end of the click frame; the rig's
        // published verdict is rebuilt from the model on the next frame.
        harness.run();
        assert!(
            harness
                .query_by_label(auth_requires_accounts_error().as_str())
                .is_none(),
            "adding the first account must clear the row error"
        );
        assert_eq!(rig.borrow().settings.local_inbounds[1].accounts.len(), 1);
    }

    /// The validation references are generation-gated: an idle frame
    /// re-renders the cached verdicts (the same allocation — nothing is
    /// recomputed), and an edit — recorded through the shell's mutation hook,
    /// as a screen records one — rebuilds them once. An app boot plus a frame
    /// window is not needed to see that: the gate, its key and its cached
    /// vectors are all reachable from the screen itself.
    #[test]
    fn validation_cache_is_generation_gated() {
        let rig = Rc::new(RefCell::new(UiTestRig::default()));
        {
            let mut rig = rig.borrow_mut();
            // The seeded SOCKS/HTTP pair on one loopback port: the SOCKS row
            // carries a collision verdict.
            rig.settings.local_inbounds[1].port = rig.settings.local_inbounds[0].port;
        }
        let mut harness = harness_for(rig.clone());
        harness.run();
        assert!(
            harness
                .query_by_label_contains("conflicts with HTTP")
                .is_some(),
            "the cached SOCKS collision verdict must render on its row"
        );
        assert!(
            harness
                .query_by_label_contains("conflicts with SOCKS")
                .is_some(),
            "the cached HTTP collision verdict must render on its row"
        );

        let (generation, verdicts) = {
            let cache = harness
                .state()
                .validation
                .as_ref()
                .expect("the first frame builds the cache");
            assert!(
                cache.local_collisions.iter().any(Option::is_some),
                "the seeded port collision must be in the cached verdicts"
            );
            (cache.generation, cache.local_collisions.as_ptr())
        };

        // An idle frame keeps the key and the verdict allocation.
        harness.run();
        {
            let cache = harness.state().validation.as_ref().unwrap();
            assert_eq!(cache.generation, generation);
            assert_eq!(
                cache.local_collisions.as_ptr(),
                verdicts,
                "an unchanged generation must re-render the cached verdicts"
            );
        }

        // One edit, recorded through the mutation hook: the cache rebuilds
        // once and the cleared collision is gone.
        {
            let mut rig = rig.borrow_mut();
            rig.settings.local_inbounds[1].port = 10899;
            rig.edit();
        }
        harness.run();
        {
            let cache = harness.state().validation.as_ref().unwrap();
            assert_ne!(cache.generation, generation, "an edit must move the key");
            assert!(
                cache.local_collisions.iter().all(Option::is_none),
                "the cleared collision must be gone from the rebuilt cache"
            );
        }
    }

    /// Unticking Require auth on the trapped row clears the error the same
    /// way adding an account does.
    #[test]
    fn unticking_require_auth_clears_the_row_error() {
        let rig = Rc::new(RefCell::new(UiTestRig::default()));
        {
            let mut rig = rig.borrow_mut();
            rig.settings.local_inbounds[1].auth = "password".into();
        }
        let mut harness = harness_for(rig.clone());
        harness.run();
        assert!(
            harness
                .query_by_label(auth_requires_accounts_error().as_str())
                .is_some(),
            "the trapped row must render the shared inline error"
        );

        // One require-authentication checkbox per row, in list order; the
        // HTTP row is second (SOCKS is seeded first).
        let checkboxes: Vec<_> = harness
            .query_all_by_label("require authentication")
            .collect();
        assert_eq!(checkboxes.len(), 2);
        checkboxes[1].click();
        harness.run();
        harness.run();
        assert!(
            harness
                .query_by_label(auth_requires_accounts_error().as_str())
                .is_none(),
            "unticking Require auth must clear the row error"
        );
        assert_eq!(rig.borrow().settings.local_inbounds[1].auth, "noauth");
    }
}
