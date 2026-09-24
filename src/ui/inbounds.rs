//! Inbounds screen: the user-managed local SOCKS/HTTP endpoint list,
//! dokodemo-door forwards, sniffing. IP listeners bind a user-configurable
//! listen address (default 127.0.0.1, any IP literal allowed); dokodemo also
//! supports UNIX sockets.

use crate::i18n::{Key, safety_message_for_path, t, t_fmt, validation_message};
use crate::model::inbound::{
    API_INBOUND_TAG, DNS_INBOUND_TAG, DokodemoNetwork, TUN_INBOUND_TAG, is_wildcard_listen,
    listen_endpoints_conflict, new_dokodemo_tag, next_local_tag,
};
use crate::model::safety::assess;
use crate::model::settings::Language;
use crate::model::validation::{
    ValidationCode, inbound_auth_trap, normalize_windows_socket_path, validate_listen_address,
    validate_sniffing,
};
use crate::model::{
    Account, DokodemoCfg, LocalInboundCfg, LocalInboundProtocol, Settings, Sniffing,
};
use crate::ui::UiCtx;
use crate::ui::widgets;

#[derive(Default)]
pub struct InboundsScreen {
    /// Transient port_map rows per dokodemo entry (synced on edit).
    port_map_rows: Vec<Vec<(String, String)>>,
    /// Cross-listener validation references, rebuilt only when the model
    /// generation `(config_revision, dirty)` changes — never on idle
    /// repaint frames. `None` until the first frame.
    validation: Option<ValidationCache>,
}

/// One generation of the inbounds validation references: the listener
/// snapshot plus every derived verdict (collisions, routing reference counts,
/// tag errors, LAN-exposure posture, auth traps). Rows borrow these while
/// their editors are open — no per-frame rebuilds or clones.
struct ValidationCache {
    generation: (u64, bool, usize, usize),
    non_loopback: bool,
    /// One collision verdict per local endpoint list entry, in list order.
    local_collisions: Vec<Option<String>>,
    /// One auth-trap verdict per local endpoint list entry, in list order:
    /// password-mode HTTP with zero accounts is un-appliable at any bind.
    /// The model verdict pass enforces the same rule, and the row renders
    /// the same code's message.
    local_auth_errors: Vec<Option<&'static str>>,
    /// One sniffing-vocabulary verdict per local endpoint list entry, in
    /// list order. The model verdict pass enforces the same rule; the row
    /// renders the shared model message (same code), so the row and the
    /// gate never disagree.
    local_sniffing_errors: Vec<Option<String>>,
    doko_collisions: Vec<Option<String>>,
    doko_references: Vec<usize>,
    doko_tag_errors: Vec<Option<String>>,
    /// One sniffing-vocabulary verdict per dokodemo entry, in list order
    /// (same shared gate/message as `local_sniffing_errors`).
    doko_sniffing_errors: Vec<Option<String>>,
    /// i18n'd exposure warnings from [`assess`], pre-rendered at the same
    /// generation cadence as the collisions. Each listen field renders its
    /// own entry as the amber warning channel; the paths mirror the wire
    /// paths `assess` emits ("localInbounds[i].listen",
    /// "dokodemo[i].listen").
    local_warnings: Vec<Option<String>>,
    doko_warnings: Vec<Option<String>>,
}

impl InboundsScreen {
    pub fn show(&mut self, ui: &mut egui::Ui, ctx: &mut UiCtx) {
        let lang = ctx.settings.language;
        // The validation references are rebuilt only when the model
        // generation changes — an edit frame, a persist, or a row-count
        // change — never on idle repaint frames. The row
        // counts are part of the key because `dirty` is frame-local (reset
        // at the top of every frame) and `config_revision` bumps only on
        // persist (throttled): two Adds inside the throttle window would
        // otherwise render the grown list against the stale per-row arrays
        // and index out of bounds. The rendered verdicts lag an edit by at
        // most one frame, exactly like the old per-frame build (which also
        // ran before the editors mutated the model).
        let generation = (
            ctx.config_revision,
            *ctx.dirty,
            ctx.settings.local_inbounds.len(),
            ctx.settings.dokodemo.len(),
        );
        if !matches!(&self.validation, Some(cache) if cache.generation == generation) {
            let snapshot = listeners(ctx.settings, lang);
            // One `assess` per model generation, in the same rebuild as the
            // collision references — never a second recomputation pattern
            // and never per-frame.
            let findings = assess(ctx.servers, ctx.settings);
            self.validation = Some(ValidationCache {
                generation,
                non_loopback: any_non_loopback_listen(ctx.settings),
                local_collisions: (0..ctx.settings.local_inbounds.len())
                    .map(|index| listener_collision(&snapshot, lang, ListenerKey::Local(index)))
                    .collect(),
                local_auth_errors: (0..ctx.settings.local_inbounds.len())
                    .map(|index| {
                        local_inbound_auth_error(lang, &ctx.settings.local_inbounds[index])
                    })
                    .collect(),
                local_sniffing_errors: (0..ctx.settings.local_inbounds.len())
                    .map(|index| {
                        sniffing_row_error(
                            lang,
                            ctx.settings.local_inbounds[index].enabled,
                            &ctx.settings.local_inbounds[index].sniffing,
                            &format!("localInbounds[{index}].sniffing"),
                        )
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
                doko_sniffing_errors: (0..ctx.settings.dokodemo.len())
                    .map(|index| {
                        sniffing_row_error(
                            lang,
                            ctx.settings.dokodemo[index].enabled,
                            &ctx.settings.dokodemo[index].sniffing,
                            &format!("dokodemo[{index}].sniffing"),
                        )
                    })
                    .collect(),
                local_warnings: (0..ctx.settings.local_inbounds.len())
                    .map(|index| {
                        safety_message_for_path(
                            &findings,
                            &format!("localInbounds[{index}].listen"),
                            lang,
                        )
                    })
                    .collect(),
                doko_warnings: (0..ctx.settings.dokodemo.len())
                    .map(|index| {
                        safety_message_for_path(
                            &findings,
                            &format!("dokodemo[{index}].listen"),
                            lang,
                        )
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
        // the allocator assigns them once and they persist with the entry.
        let fakedns_on = ctx.settings.dns.fakedns.enabled;
        let mut remove: Option<usize> = None;
        let mut changed = false;
        widgets::section(ui, t(lang, Key::LocalListeners), |ui| {
            if ctx.settings.local_inbounds.is_empty() {
                ui.label(
                    egui::RichText::new(t(lang, Key::EmptyLocalListeners))
                        .small()
                        .weak(),
                );
            }
            for (i, entry) in ctx.settings.local_inbounds.iter_mut().enumerate() {
                ui.push_id(&entry.tag, |ui| {
                    ui.horizontal(|ui| {
                        ui.monospace(protocol_label(lang, entry.protocol));
                        changed |= ui
                            .checkbox(&mut entry.enabled, t(lang, Key::Enabled))
                            .changed();
                        if ui.button(t(lang, Key::RemoveEndpoint)).clicked() {
                            remove = Some(i);
                        }
                    });
                    changed |= widgets::port_field(ui, t(lang, Key::PortLower), &mut entry.port);
                    changed |= widgets::validated_field_with_warning(
                        ui,
                        t(lang, Key::InboundsListenAddress),
                        &mut entry.listen,
                        "127.0.0.1",
                        |listen| {
                            validate_listen_address(listen)
                                .err()
                                .map(|code| validation_message(&code, lang).to_string())
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
                                        egui::RichText::new(t(lang, Key::InboundsUdpWildcardHint))
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
                    if widgets::opt_u32(ui, t(lang, Key::UserLevel), &mut user_level, 0..=u32::MAX)
                    {
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
                        changed |= accounts_editor(ui, lang, &mut entry.accounts);
                    }
                    // The shared gate verdict, rendered under the accounts
                    // editor it qualifies: password-mode HTTP with zero
                    // accounts authenticates nobody on the wire, so the row
                    // cannot apply at any bind (the model auth-trap rule).
                    inline_error(ui, validation.local_auth_errors[i]);
                    changed |= sniffing_editor(ui, lang, &mut entry.sniffing, fakedns_on);
                    inline_error(ui, validation.local_sniffing_errors[i].as_deref());
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
        });
        if let Some(i) = remove {
            ctx.settings.local_inbounds.remove(i);
            changed = true;
        }
        if changed {
            ctx.mark_dirty();
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
                            .on_disabled_hover_text(
                                t(lang, Key::InboundsUsedByRules)
                                    .replace("{reference_count}", &reference_count.to_string()),
                            );
                        if delete.clicked() {
                            remove = Some(i);
                        }
                    });
                    inline_error(ui, validation.doko_tag_errors[i].as_deref());
                    inline_error(ui, validation.doko_collisions[i].as_deref());
                    if reference_count != 0 {
                        ui.label(
                            egui::RichText::new(
                                t(lang, Key::InboundsDeleteBlocked)
                                    .replace("{reference_count}", &reference_count.to_string()),
                            )
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
                                egui::RichText::new(t(lang, Key::InboundsUnixHint))
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
                                        .map(|code| validation_message(&code, lang).to_string())
                                },
                                validation.doko_warnings[i].as_deref(),
                            );
                        }
                        Err(_) => {
                            ui.label(
                                egui::RichText::new(t(lang, Key::InboundsImportedHint))
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
                    inline_error(ui, validation.doko_sniffing_errors[i].as_deref());
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
            ctx.mark_dirty();
        }
    }
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
    let non_loopback = |listen: &str| -> bool {
        listen
            .parse::<std::net::IpAddr>()
            .map(|address| !address.is_loopback())
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
                t(lang, Key::CollisionEndpoint).replace("{path:?}", &format!("{path:?}")),
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

fn dokodemo_tag_error(settings: &Settings, lang: Language, index: usize) -> Option<String> {
    let tag = settings.dokodemo.get(index)?.tag.trim();
    if tag.is_empty() {
        return Some(t(lang, Key::DokodemoTagMissing).into());
    }
    // Reserved-tag collisions: the tun/dns/api listeners plus every
    // local endpoint tag — the user-managed list replaced the fixed
    // in-socks/in-http builtins, so its tags are builtins now. The DNS
    // listener is added to the running core rather than emitted, but its
    // tag is taken all the same.
    if matches!(tag, API_INBOUND_TAG | DNS_INBOUND_TAG | TUN_INBOUND_TAG)
        || settings.local_inbounds.iter().any(|entry| entry.tag == tag)
    {
        return Some(t(lang, Key::DokodemoTagBuiltin).replace("{tag:?}", &format!("{tag:?}")));
    }
    if settings
        .dokodemo
        .iter()
        .enumerate()
        .any(|(other, entry)| other != index && entry.tag == tag)
    {
        return Some(t(lang, Key::DokodemoTagDuplicate).replace("{tag:?}", &format!("{tag:?}")));
    }
    None
}

/// The inline validation error for one local endpoint row, or `None` when
/// the row is appliable. The rule and its text are the model pass's
/// (`validate_settings` emits the same code — Apply/Connect are blocked
/// through `config_error`); this screen only renders that code's message
/// under the accounts editor.
fn local_inbound_auth_error(lang: Language, entry: &LocalInboundCfg) -> Option<&'static str> {
    if entry.enabled && inbound_auth_trap(entry) {
        Some(validation_message(
            &ValidationCode::LocalInboundAuthRequiresAccounts,
            lang,
        ))
    } else {
        None
    }
}

/// The inline validation error for one row's sniffing block, or `None` when
/// the row is appliable. Mirrors the model pass's `validate_sniffing`
/// verdict exactly (the same codes through the same i18n key); disabled
/// rows never block, so nothing renders for them (they are not emitted to
/// the wire and Xray never sees their state).
fn sniffing_row_error(
    lang: Language,
    enabled: bool,
    sniffing: &Sniffing,
    prefix: &str,
) -> Option<String> {
    if !enabled {
        return None;
    }
    validate_sniffing(sniffing, prefix)
        .into_iter()
        .next()
        .map(|issue| validation_message(&issue.code, lang).to_string())
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

fn accounts_editor(ui: &mut egui::Ui, lang: Language, accounts: &mut Vec<Account>) -> bool {
    let mut changed = false;
    ui.label(t(lang, Key::Accounts));
    let mut del: Option<usize> = None;
    for (i, a) in accounts.iter_mut().enumerate() {
        ui.horizontal(|ui| {
            if ui
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
        local_inbound_auth_error, normalize_windows_socket_path,
    };
    use crate::i18n::validation_message;
    use crate::model::settings::Language;
    use crate::model::validation::ValidationCode;
    use crate::model::{Account, DokodemoCfg, LocalInboundCfg, LocalInboundProtocol, Settings};
    use crate::ui::test_rig::UiTestRig;
    use egui_kittest::{Harness, kittest::Queryable as _};
    use std::cell::RefCell;
    use std::rc::Rc;

    /// The shared row-error text, rendered through the model code the
    /// verdict pass emits (one rule, one message).
    fn auth_requires_accounts_error() -> &'static str {
        validation_message(
            &ValidationCode::LocalInboundAuthRequiresAccounts,
            Language::En,
        )
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
        let rig_handle = rig.clone();
        Harness::builder()
            .with_size(egui::vec2(900.0, 2400.0))
            .build_ui_state(
                move |ui, screen: &mut InboundsScreen| {
                    let mut rig = rig_handle.borrow_mut();
                    screen.show(ui, &mut rig.ctx())
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

    /// The row verdict mirrors the generator gate: an enabled password-mode
    /// HTTP inbound with zero accounts errors at any bind; a disabled row
    /// (never emitted, never gated), noauth HTTP, HTTP with accounts, and
    /// SOCKS password mode with an empty list (deny-all on the wire — a
    /// separate non-security behavior) all stay clean. The English text is
    /// the generator's shared const by contract, so the inline row and the
    /// Apply/Connect gate can never disagree.
    #[test]
    fn local_auth_error_matches_the_generator_gate_message() {
        let lang = Language::En;
        let http = |enabled: bool, auth: &str, accounts: usize| LocalInboundCfg {
            protocol: LocalInboundProtocol::Http,
            tag: "in-http".into(),
            enabled,
            listen: "127.0.0.1".into(),
            auth: auth.into(),
            accounts: vec![Account::default(); accounts],
            ..Default::default()
        };
        for listen in ["127.0.0.1", "0.0.0.0"] {
            let trapped = LocalInboundCfg {
                listen: listen.into(),
                ..http(true, "password", 0)
            };
            let error = local_inbound_auth_error(lang, &trapped)
                .expect("password-mode HTTP with zero accounts must error");
            assert_eq!(
                error,
                auth_requires_accounts_error(),
                "the row error must be the generator gate's message (bind {listen})"
            );
        }
        assert!(
            local_inbound_auth_error(lang, &http(false, "password", 0)).is_none(),
            "a disabled row never reaches the wire, so it must not error"
        );
        for (auth, accounts) in [("password", 1), ("noauth", 0)] {
            assert!(
                local_inbound_auth_error(lang, &http(true, auth, accounts)).is_none(),
                "{auth:?} with {accounts} account(s) must stay appliable"
            );
        }
        // SOCKS password mode with an empty list denies every connection on
        // the wire — genuinely safe, never the auth trap.
        let socks = LocalInboundCfg {
            tag: "in-socks".into(),
            enabled: true,
            auth: "password".into(),
            ..Default::default()
        };
        assert!(local_inbound_auth_error(lang, &socks).is_none());
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
                .query_by_label(auth_requires_accounts_error())
                .is_some(),
            "the trapped row must render the shared inline error"
        );

        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "+ account")
            .click();
        harness.run();
        // The model mutation lands at the end of the click frame; the
        // verdict cache rebuilds one frame later (the dirty flag is part of
        // its generation key).
        harness.run();
        assert!(
            harness
                .query_by_label(auth_requires_accounts_error())
                .is_none(),
            "adding the first account must clear the row error"
        );
        assert_eq!(rig.borrow().settings.local_inbounds[1].accounts.len(), 1);
    }

    /// The validation references are generation-gated: a frame whose
    /// `(config_revision, dirty, row counts)` key is unchanged re-renders the
    /// cached verdicts (the same allocation — nothing is recomputed), and a
    /// key move rebuilds them once. An app boot plus a frame window is not
    /// needed to see that: the gate, its key and its cached vectors are all
    /// reachable from the screen itself.
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

        // One edit: the frame's dirty flag is part of the key, so the cache
        // rebuilds once and the cleared collision is gone.
        {
            let mut rig = rig.borrow_mut();
            rig.settings.local_inbounds[1].port = 10899;
            rig.dirty = true;
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
                .query_by_label(auth_requires_accounts_error())
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
                .query_by_label(auth_requires_accounts_error())
                .is_none(),
            "unticking Require auth must clear the row error"
        );
        assert_eq!(rig.borrow().settings.local_inbounds[1].auth, "noauth");
    }
}
