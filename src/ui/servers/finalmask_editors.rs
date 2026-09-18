//! Typed editors for the finalmask envelope of the servers screen: the
//! render-editor-returning-changed family over the finalmask model
//! (range/sequence/list rows, transforms, TCP/UDP masks, realm TLS, QUIC
//! hops), entered from the screen's advanced-tab editor plus intra-family
//! recursion. Raw-JSON and PEM fields edit through the screen's seeded
//! buffer machinery (`super::raw_editor`). Private to the screen.

use crate::i18n::{Key, t, t_fmt};
use crate::metrics::MetricsHandle;
use crate::model::settings::Language;
use crate::model::validation::{ValidationCode, pinned_peer_cert_sha256_valid};
use crate::model::{
    FinalmaskNoiseItem, FinalmaskPortList, FinalmaskQuicParams, FinalmaskRawValue,
    FinalmaskRealmPortMapping, FinalmaskRealmTls, FinalmaskSudoku, FinalmaskTcpItem,
    FinalmaskTcpMask, FinalmaskTransform, FinalmaskTransformArg, FinalmaskUdpHop, FinalmaskUdpItem,
    FinalmaskUdpMask, FinalmaskXmc, FinalmaskXmcProfile, Int32Range, TlsCert,
};
use crate::ui::status::status_colors_of;
use crate::ui::widgets;

use super::raw_editor::{
    FieldKey, JsonBuf, JsonEditorSpec, PemBuf, RawField, pem_lines_editor, raw_buffer_edit,
};
use super::{
    TLS_VERSIONS, ech_sockopt_editor, fingerprint_editor, mask_sockopt_editor, path_field,
};

// ---------- finalmask typed editor ----------

fn range_editor(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut Int32Range,
    range: std::ops::RangeInclusive<i32>,
) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        ui.label(label);
        changed |= ui
            .add(egui::DragValue::new(&mut value.from).range(range.clone()))
            .changed();
        ui.label("–");
        changed |= ui
            .add(egui::DragValue::new(&mut value.to).range(range))
            .changed();
    });
    changed
}

fn ranges_editor(
    ui: &mut egui::Ui,
    lang: Language,
    label: &str,
    values: &mut Vec<Int32Range>,
    range: std::ops::RangeInclusive<i32>,
) -> bool {
    let mut changed = false;
    ui.label(label);
    let mut remove = None;
    for (index, value) in values.iter_mut().enumerate() {
        ui.push_id((label, index), |ui| {
            ui.horizontal(|ui| {
                changed |= ui
                    .add(egui::DragValue::new(&mut value.from).range(range.clone()))
                    .changed();
                ui.label("–");
                changed |= ui
                    .add(egui::DragValue::new(&mut value.to).range(range.clone()))
                    .changed();
                if ui.small_button(t(lang, Key::SrvRemove)).clicked() {
                    remove = Some(index);
                }
            });
        });
    }
    if let Some(index) = remove {
        values.remove(index);
        changed = true;
    }
    if ui.small_button(t(lang, Key::SrvAddRange)).clicked() {
        values.push(Int32Range::single(*range.start()));
        changed = true;
    }
    changed
}

pub(super) fn finalmask_move_buttons(
    ui: &mut egui::Ui,
    lang: Language,
    index: usize,
    len: usize,
    move_to: &mut Option<(usize, usize)>,
    remove: &mut Option<usize>,
) {
    if ui
        .add_enabled(index > 0, egui::Button::new(t(lang, Key::SrvUp)))
        .clicked()
    {
        *move_to = Some((index, index - 1));
    }
    if ui
        .add_enabled(index + 1 < len, egui::Button::new(t(lang, Key::SrvDown)))
        .clicked()
    {
        *move_to = Some((index, index + 1));
    }
    if ui.small_button(t(lang, Key::SrvRemove)).clicked() {
        *remove = Some(index);
    }
}

fn finalmask_unknown_editor(
    ui: &mut egui::Ui,
    lang: Language,
    raw: &mut serde_json::Value,
    key: egui::Id,
    profile: &str,
    raw_buffers: &mut std::collections::HashMap<egui::Id, JsonBuf>,
    metrics: &MetricsHandle,
) -> bool {
    ui.colored_label(
        status_colors_of(ui).warn,
        t_fmt(
            lang,
            Key::SrvUnknownFutureFinalmask,
            &[&raw
                .get("type")
                .unwrap_or(&serde_json::Value::Null)
                .to_string()],
        ),
    );
    raw_buffer_edit(
        ui,
        lang,
        t(lang, Key::SrvPreservedRawValue),
        RawField {
            id: FieldKey { key, profile },
            buffers: raw_buffers,
        },
        raw,
        &JsonEditorSpec {
            hint: "{}",
            rows: 5,
        },
        metrics,
    )
}

fn finalmask_raw_value_editor(
    ui: &mut egui::Ui,
    lang: Language,
    label: &str,
    encoding: &mut String,
    raw: &mut FinalmaskRawValue,
    field: RawField<'_>,
    metrics: &MetricsHandle,
) -> bool {
    let mut changed = widgets::combo_str_labeled(
        ui,
        &t_fmt(lang, Key::SrvLabelSyntax, &[&label]),
        encoding,
        &["", "array", "str", "hex", "base64"],
        t(lang, Key::SrvDefault),
        false,
    );
    let mut present = !raw.is_absent();
    if ui
        .checkbox(&mut present, t_fmt(lang, Key::SrvSetLabel, &[&label]))
        .changed()
    {
        *raw = if present {
            FinalmaskRawValue::Present(match encoding.as_str() {
                "str" | "hex" | "base64" => serde_json::Value::String(String::new()),
                _ => serde_json::json!([]),
            })
        } else {
            FinalmaskRawValue::Absent
        };
        changed = true;
    }
    let Some(value) = raw.value_mut() else {
        return changed;
    };
    if matches!(encoding.as_str(), "str" | "hex" | "base64")
        && let serde_json::Value::String(text) = value
    {
        // The string case edits the model's own text in place — the widget
        // writes it only on a real edit, so a repaint copies nothing.
        changed |= widgets::text_field(ui, label, text, "");
    } else {
        changed |= raw_buffer_edit(
            ui,
            lang,
            label,
            RawField {
                id: field.id,
                buffers: &mut *field.buffers,
            },
            value,
            &JsonEditorSpec {
                hint: "[0, 255]",
                rows: 2,
            },
            metrics,
        );
    }
    changed
}

fn finalmask_transform_editor(
    ui: &mut egui::Ui,
    lang: Language,
    transform: &mut FinalmaskTransform,
    key: egui::Id,
    profile: &str,
    raw_buffers: &mut std::collections::HashMap<egui::Id, JsonBuf>,
    metrics: &MetricsHandle,
) -> bool {
    let mut changed = widgets::text_field(ui, "op", &mut transform.op, "operation");
    let mut remove = None;
    for (index, arg) in transform.args.iter_mut().enumerate() {
        ui.push_id(("transform-arg", key, index), |ui| {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(t_fmt(lang, Key::SrvArgumentN, &[&(index + 1)]));
                    if ui.small_button(t(lang, Key::SrvRemove)).clicked() {
                        remove = Some(index);
                    }
                });
                // The pre-selection kind stays a `&'static str` so the row
                // does not clone it; only the combo's own buffer is owned
                // (its API writes a `String`).
                let old_kind = if !arg.bytes.is_absent() {
                    "bytes"
                } else if arg.u64.is_some() {
                    "u64"
                } else if !arg.reuse.is_empty() {
                    "reuse"
                } else if !arg.metadata.is_empty() {
                    "metadata"
                } else if arg.transform.is_some() {
                    "transform"
                } else {
                    "none"
                };
                let mut kind = old_kind.to_string();
                changed |= widgets::combo_str_labeled(
                    ui,
                    "value",
                    &mut kind,
                    &["none", "bytes", "u64", "reuse", "metadata", "transform"],
                    t(lang, Key::SrvDefault),
                    false,
                );
                if kind != old_kind {
                    arg.bytes = FinalmaskRawValue::Absent;
                    arg.u64 = None;
                    arg.reuse.clear();
                    arg.metadata.clear();
                    arg.transform = None;
                    match kind.as_str() {
                        "bytes" => arg.bytes = FinalmaskRawValue::Present(serde_json::json!([])),
                        "u64" => arg.u64 = Some(0),
                        "reuse" => arg.reuse = "_var".into(),
                        "metadata" => arg.metadata = "metadata".into(),
                        "transform" => arg.transform = Some(Box::default()),
                        _ => {}
                    }
                    changed = true;
                }
                match kind.as_str() {
                    "bytes" => {
                        changed |= finalmask_raw_value_editor(
                            ui,
                            lang,
                            "bytes",
                            &mut arg.encoding,
                            &mut arg.bytes,
                            RawField {
                                id: FieldKey {
                                    key: key.with(("arg", index, "bytes")),
                                    profile,
                                },
                                buffers: raw_buffers,
                            },
                            metrics,
                        );
                    }
                    "u64" => {
                        changed |= widgets::opt_num(ui, "u64", &mut arg.u64, 0..=u64::MAX);
                    }
                    "reuse" => {
                        changed |= widgets::text_field(ui, "reuse", &mut arg.reuse, "_var");
                    }
                    "metadata" => {
                        changed |= widgets::text_field(
                            ui,
                            "metadata",
                            &mut arg.metadata,
                            "metadata selector",
                        );
                    }
                    "transform" => {
                        if let Some(nested) = arg.transform.as_mut() {
                            changed |= finalmask_transform_editor(
                                ui,
                                lang,
                                nested,
                                key.with(("arg", index, "nested")),
                                profile,
                                raw_buffers,
                                metrics,
                            );
                        }
                    }
                    _ => {}
                }
            });
        });
    }
    if let Some(index) = remove {
        transform.args.remove(index);
        changed = true;
    }
    if ui
        .small_button(t(lang, Key::SrvAddTransformArgument))
        .clicked()
    {
        transform.args.push(FinalmaskTransformArg::default());
        changed = true;
    }
    changed
}

fn finalmask_tcp_item_editor(
    ui: &mut egui::Ui,
    lang: Language,
    item: &mut FinalmaskTcpItem,
    key: egui::Id,
    profile: &str,
    raw_buffers: &mut std::collections::HashMap<egui::Id, JsonBuf>,
    metrics: &MetricsHandle,
) -> bool {
    let mut changed = range_editor(ui, "delay", &mut item.delay, i32::MIN..=i32::MAX);
    changed |= ui
        .horizontal(|ui| {
            ui.label(t(lang, Key::SrvRandLength));
            ui.add(egui::DragValue::new(&mut item.rand).range(0..=i32::MAX))
                .changed()
        })
        .inner;
    changed |= widgets::opt_range(ui, "randRange", &mut item.rand_range, 0..=255);
    changed |= widgets::text_field(ui, "capture", &mut item.capture, "_saved");
    changed |= widgets::text_field(ui, "reuse", &mut item.reuse, "_saved");
    changed |= finalmask_raw_value_editor(
        ui,
        lang,
        "packet",
        &mut item.encoding,
        &mut item.packet,
        RawField {
            id: FieldKey {
                key: key.with("packet"),
                profile,
            },
            buffers: raw_buffers,
        },
        metrics,
    );
    let mut has_transform = item.transform.is_some();
    if ui.checkbox(&mut has_transform, "transform").changed() {
        item.transform = has_transform.then(FinalmaskTransform::default);
        changed = true;
    }
    if let Some(transform) = item.transform.as_mut() {
        changed |= finalmask_transform_editor(
            ui,
            lang,
            transform,
            key.with("transform"),
            profile,
            raw_buffers,
            metrics,
        );
    }
    changed
}

fn finalmask_udp_item_editor(
    ui: &mut egui::Ui,
    lang: Language,
    item: &mut FinalmaskUdpItem,
    key: egui::Id,
    profile: &str,
    raw_buffers: &mut std::collections::HashMap<egui::Id, JsonBuf>,
    metrics: &MetricsHandle,
) -> bool {
    let mut changed = ui
        .horizontal(|ui| {
            ui.label(t(lang, Key::SrvRandLength));
            ui.add(egui::DragValue::new(&mut item.rand).range(0..=i32::MAX))
                .changed()
        })
        .inner;
    changed |= widgets::opt_range(ui, "randRange", &mut item.rand_range, 0..=255);
    changed |= widgets::text_field(ui, "capture", &mut item.capture, "_saved");
    changed |= widgets::text_field(ui, "reuse", &mut item.reuse, "_saved");
    changed |= finalmask_raw_value_editor(
        ui,
        lang,
        "packet",
        &mut item.encoding,
        &mut item.packet,
        RawField {
            id: FieldKey {
                key: key.with("packet"),
                profile,
            },
            buffers: raw_buffers,
        },
        metrics,
    );
    let mut has_transform = item.transform.is_some();
    if ui.checkbox(&mut has_transform, "transform").changed() {
        item.transform = has_transform.then(FinalmaskTransform::default);
        changed = true;
    }
    if let Some(transform) = item.transform.as_mut() {
        changed |= finalmask_transform_editor(
            ui,
            lang,
            transform,
            key.with("transform"),
            profile,
            raw_buffers,
            metrics,
        );
    }
    changed
}

fn finalmask_tcp_sequences_editor(
    ui: &mut egui::Ui,
    lang: Language,
    label: &str,
    sequences: &mut Vec<Vec<FinalmaskTcpItem>>,
    field: RawField<'_>,
    metrics: &MetricsHandle,
) -> bool {
    let mut changed = false;
    ui.label(label);
    let mut remove_sequence = None;
    for (sequence_index, sequence) in sequences.iter_mut().enumerate() {
        ui.push_id((field.id.key, "sequence", sequence_index), |ui| {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(t_fmt(lang, Key::SrvSequenceN, &[&(sequence_index + 1)]));
                    if ui.small_button(t(lang, Key::SrvRemoveSequence)).clicked() {
                        remove_sequence = Some(sequence_index);
                    }
                });
                let mut remove_item = None;
                for (item_index, item) in sequence.iter_mut().enumerate() {
                    ui.push_id(("item", item_index), |ui| {
                        egui::CollapsingHeader::new(t_fmt(
                            lang,
                            Key::SrvItemN,
                            &[&(item_index + 1)],
                        ))
                        .default_open(true)
                        .show(ui, |ui| {
                            if ui.small_button(t(lang, Key::SrvRemoveItem)).clicked() {
                                remove_item = Some(item_index);
                            }
                            changed |= finalmask_tcp_item_editor(
                                ui,
                                lang,
                                item,
                                field.id.key.with((sequence_index, item_index)),
                                field.id.profile,
                                &mut *field.buffers,
                                metrics,
                            );
                        });
                    });
                }
                if let Some(index) = remove_item {
                    sequence.remove(index);
                    changed = true;
                }
                if ui.small_button(t(lang, Key::SrvAddItem)).clicked() {
                    sequence.push(FinalmaskTcpItem::default());
                    changed = true;
                }
            });
        });
    }
    if let Some(index) = remove_sequence {
        sequences.remove(index);
        changed = true;
    }
    if ui.small_button(t(lang, Key::SrvAddSequence)).clicked() {
        sequences.push(vec![FinalmaskTcpItem::default()]);
        changed = true;
    }
    changed
}

fn finalmask_udp_items_editor(
    ui: &mut egui::Ui,
    lang: Language,
    label: &str,
    items: &mut Vec<FinalmaskUdpItem>,
    field: RawField<'_>,
    metrics: &MetricsHandle,
) -> bool {
    let mut changed = false;
    ui.label(label);
    let mut remove = None;
    for (index, item) in items.iter_mut().enumerate() {
        ui.push_id((field.id.key, index), |ui| {
            egui::CollapsingHeader::new(t_fmt(lang, Key::SrvItemN, &[&(index + 1)]))
                .default_open(true)
                .show(ui, |ui| {
                    if ui.small_button(t(lang, Key::SrvRemoveItem)).clicked() {
                        remove = Some(index);
                    }
                    changed |= finalmask_udp_item_editor(
                        ui,
                        lang,
                        item,
                        field.id.key.with(index),
                        field.id.profile,
                        &mut *field.buffers,
                        metrics,
                    );
                });
        });
    }
    if let Some(index) = remove {
        items.remove(index);
        changed = true;
    }
    if ui.small_button(t(lang, Key::SrvAddItem)).clicked() {
        items.push(FinalmaskUdpItem::default());
        changed = true;
    }
    changed
}

/// The `udphop` mask editor: the mode set (three combinable tokens), the
/// seconds interval, the remote port list, the remote address/prefix list,
/// and the mask's own socket options.
fn finalmask_udphop_editor(
    ui: &mut egui::Ui,
    lang: Language,
    settings: &mut FinalmaskUdpHop,
) -> bool {
    // The three names the mask build accepts, case-insensitively, in the
    // canonical order. A stored mode that carries anything else keeps those
    // tokens: the checkboxes rewrite the known set, and the unknown tokens
    // stay put so the validation finding keeps naming them instead of a
    // checkbox edit dropping the user's text.
    const MODES: [&str; 3] = ["intervalLocal", "intervalRemote", "perConnRemote"];
    let tokens: Vec<&str> = settings
        .mode
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .collect();
    let mut modes = MODES.map(|name| tokens.iter().any(|token| name.eq_ignore_ascii_case(token)));
    let mut mode_changed = false;
    ui.label("mode");
    ui.horizontal(|ui| {
        for (index, name) in MODES.iter().enumerate() {
            mode_changed |= ui.checkbox(&mut modes[index], *name).changed();
        }
    });
    if mode_changed {
        let mut parts: Vec<&str> = MODES
            .iter()
            .zip(modes.iter())
            .filter(|(_, on)| **on)
            .map(|(name, _)| *name)
            .collect();
        parts.extend(
            tokens
                .iter()
                .copied()
                .filter(|token| !MODES.iter().any(|name| name.eq_ignore_ascii_case(token))),
        );
        settings.mode = parts.join(",");
    }
    let mut changed = mode_changed;
    changed |= range_editor(
        ui,
        t(lang, Key::SrvIntervalS),
        &mut settings.interval,
        0..=i32::MAX,
    );
    // The text arm edits the model's own port list in place (the widget
    // writes only on a real edit); only the numeric arm needs a buffer,
    // built from the number for the widget to edit.
    match &mut settings.remote_ports {
        FinalmaskPortList::Number(number) => {
            let mut text = number.to_string();
            if widgets::text_field(ui, "remotePorts", &mut text, "443,10000-20000,env:PORT") {
                settings.remote_ports = text
                    .parse::<u32>()
                    .map(FinalmaskPortList::Number)
                    .unwrap_or(FinalmaskPortList::Text(text));
                changed = true;
            }
        }
        FinalmaskPortList::Text(text) => {
            let edited = widgets::text_field(ui, "remotePorts", text, "443,10000-20000,env:PORT");
            changed |= edited;
            if edited && let Ok(number) = text.parse::<u32>() {
                settings.remote_ports = FinalmaskPortList::Number(number);
            }
        }
    }
    changed |= widgets::string_list(
        ui,
        lang,
        "remoteIPs",
        &mut settings.remote_ips,
        "198.51.100.0/24 or 2001:db8::1",
    );
    changed |= mask_sockopt_editor(ui, lang, &mut settings.sockopt);
    changed
}

fn finalmask_sudoku_editor(
    ui: &mut egui::Ui,
    lang: Language,
    settings: &mut FinalmaskSudoku,
) -> bool {
    let mut changed = widgets::text_field(ui, "password", &mut settings.password, "");
    changed |= widgets::text_field(ui, "ascii", &mut settings.ascii, "");
    changed |= widgets::text_field(ui, "customTable", &mut settings.custom_table, "");
    changed |= widgets::text_field(
        ui,
        t(lang, Key::SrvCustomTableLegacy),
        &mut settings.legacy_custom_table,
        "",
    );
    changed |= widgets::string_list(ui, lang, "customTables", &mut settings.custom_tables, "");
    changed |= widgets::string_list(
        ui,
        lang,
        t(lang, Key::SrvCustomTablesLegacy),
        &mut settings.legacy_custom_sets,
        "",
    );
    changed |= ui
        .horizontal(|ui| {
            ui.label("paddingMin");
            ui.add(egui::DragValue::new(&mut settings.padding_min).range(0..=u32::MAX))
                .changed()
        })
        .inner;
    changed |= ui
        .horizontal(|ui| {
            ui.label("paddingMax");
            ui.add(egui::DragValue::new(&mut settings.padding_max).range(0..=u32::MAX))
                .changed()
        })
        .inner;
    changed |= ui
        .horizontal(|ui| {
            ui.label(t(lang, Key::SrvPaddingMinLegacy));
            ui.add(egui::DragValue::new(&mut settings.legacy_padding_min).range(0..=u32::MAX))
                .changed()
        })
        .inner;
    changed |= ui
        .horizontal(|ui| {
            ui.label(t(lang, Key::SrvPaddingMaxLegacy));
            ui.add(egui::DragValue::new(&mut settings.legacy_padding_max).range(0..=u32::MAX))
                .changed()
        })
        .inner;
    changed
}

fn finalmask_xmc_editor(ui: &mut egui::Ui, lang: Language, settings: &mut FinalmaskXmc) -> bool {
    let mut changed =
        widgets::text_field(ui, "hostname", &mut settings.hostname, "play.example.com");
    changed |= widgets::text_field(
        ui,
        "password",
        &mut settings.password,
        "RSA derivation password",
    );
    let mut remove = None;
    for (index, profile) in settings.profiles.iter_mut().enumerate() {
        ui.push_id(("xmc-profile", index), |ui| {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(t_fmt(lang, Key::SrvMinecraftProfileN, &[&(index + 1)]));
                    if ui.small_button(t(lang, Key::SrvRemove)).clicked() {
                        remove = Some(index);
                    }
                });
                changed |= widgets::text_field(ui, "username", &mut profile.username, "Player_1");
                changed |= widgets::text_field(
                    ui,
                    "uuid",
                    &mut profile.uuid,
                    "00000000-0000-0000-0000-000000000000",
                );
                changed |= widgets::text_field(
                    ui,
                    "texturesValue",
                    &mut profile.textures_value,
                    "signed Mojang textures value",
                );
                changed |= widgets::text_field(
                    ui,
                    "texturesSignature",
                    &mut profile.textures_signature,
                    "signed Mojang textures signature",
                );
            });
        });
    }
    if let Some(index) = remove {
        settings.profiles.remove(index);
        changed = true;
    }
    if ui
        .small_button(t(lang, Key::SrvAddMinecraftProfile))
        .clicked()
    {
        settings.profiles.push(FinalmaskXmcProfile::default());
        changed = true;
    }
    changed
}

pub(super) fn finalmask_tcp_settings_editor(
    ui: &mut egui::Ui,
    lang: Language,
    mask: &mut FinalmaskTcpMask,
    key: egui::Id,
    profile: &str,
    raw_buffers: &mut std::collections::HashMap<egui::Id, JsonBuf>,
    metrics: &MetricsHandle,
) -> bool {
    match mask {
        FinalmaskTcpMask::HeaderCustom { settings, .. } => {
            let mut changed = finalmask_tcp_sequences_editor(
                ui,
                lang,
                "clients",
                &mut settings.clients,
                RawField {
                    id: FieldKey {
                        key: key.with("clients"),
                        profile,
                    },
                    buffers: raw_buffers,
                },
                metrics,
            );
            changed |= finalmask_tcp_sequences_editor(
                ui,
                lang,
                "servers",
                &mut settings.servers,
                RawField {
                    id: FieldKey {
                        key: key.with("servers"),
                        profile,
                    },
                    buffers: raw_buffers,
                },
                metrics,
            );
            changed |= finalmask_tcp_sequences_editor(
                ui,
                lang,
                "errors",
                &mut settings.errors,
                RawField {
                    id: FieldKey {
                        key: key.with("errors"),
                        profile,
                    },
                    buffers: raw_buffers,
                },
                metrics,
            );
            changed
        }
        FinalmaskTcpMask::Fragment { settings, .. } => {
            let mut changed = widgets::text_field(
                ui,
                "packets",
                &mut settings.packets,
                "tlshello, N, or from-to",
            );
            changed |= range_editor(ui, "length", &mut settings.length, i32::MIN..=i32::MAX);
            changed |= range_editor(ui, "delay", &mut settings.delay, i32::MIN..=i32::MAX);
            changed |= ranges_editor(
                ui,
                lang,
                t(lang, Key::SrvLengthsPrecedence),
                &mut settings.lengths,
                i32::MIN..=i32::MAX,
            );
            changed |= ranges_editor(
                ui,
                lang,
                t(lang, Key::SrvDelaysPrecedence),
                &mut settings.delays,
                i32::MIN..=i32::MAX,
            );
            changed |= range_editor(ui, "maxSplit", &mut settings.max_split, i32::MIN..=i32::MAX);
            changed
        }
        FinalmaskTcpMask::Sudoku { settings, .. } => finalmask_sudoku_editor(ui, lang, settings),
        FinalmaskTcpMask::Xmc { settings, .. } => finalmask_xmc_editor(ui, lang, settings),
        FinalmaskTcpMask::Unknown(raw) => finalmask_unknown_editor(
            ui,
            lang,
            raw,
            key.with("unknown"),
            profile,
            raw_buffers,
            metrics,
        ),
    }
}

fn finalmask_realm_tls_editor(
    ui: &mut egui::Ui,
    lang: Language,
    profile: &str,
    tls: &mut FinalmaskRealmTls,
    pem_buffers: &mut std::collections::HashMap<egui::Id, PemBuf>,
) -> bool {
    let mut changed = widgets::opt_bool(
        ui,
        t(lang, Key::SrvAllowInsecureRemovedLabel),
        &mut tls.allow_insecure,
        t(lang, Key::SrvUnset),
    );
    if tls.allow_insecure == Some(true) {
        ui.colored_label(
            status_colors_of(ui).err,
            t(lang, Key::SrvAllowInsecureRemoved),
        );
    }
    changed |= widgets::text_field(ui, "serverName", &mut tls.server_name, "example.com");
    changed |= widgets::string_list(ui, lang, t(lang, Key::SrvAlpn), &mut tls.alpn, "h2");
    changed |= widgets::opt_bool(
        ui,
        "enableSessionResumption",
        &mut tls.enable_session_resumption,
        t(lang, Key::SrvUnset),
    );
    changed |= widgets::opt_bool(
        ui,
        "disableSystemRoot",
        &mut tls.disable_system_root,
        t(lang, Key::SrvUnset),
    );
    changed |= widgets::combo_str_labeled(
        ui,
        "minVersion",
        &mut tls.min_version,
        TLS_VERSIONS,
        t(lang, Key::SrvDefault),
        false,
    );
    changed |= widgets::combo_str_labeled(
        ui,
        "maxVersion",
        &mut tls.max_version,
        TLS_VERSIONS,
        t(lang, Key::SrvDefault),
        false,
    );
    changed |= widgets::text_field(ui, "cipherSuites", &mut tls.cipher_suites, "");
    changed |= fingerprint_editor(
        ui,
        lang,
        &mut tls.fingerprint,
        ValidationCode::FinalmaskRealmFingerprintUnknown,
    );
    changed |= widgets::opt_bool(
        ui,
        "rejectUnknownSni",
        &mut tls.reject_unknown_sni,
        t(lang, Key::SrvUnset),
    );
    changed |= widgets::string_list(
        ui,
        lang,
        "curvePreferences",
        &mut tls.curve_preferences,
        "X25519MLKEM768",
    );
    changed |= path_field(ui, lang, "masterKeyLog", &mut tls.master_key_log, true);
    changed |= widgets::validated_field(
        ui,
        "pinnedPeerCertSha256",
        &mut tls.pinned_peer_cert_sha256,
        "comma-separated SHA-256 hex",
        |v| (!pinned_peer_cert_sha256_valid(v)).then(|| t(lang, Key::SrvCertPinHex).to_string()),
    );
    changed |= widgets::text_field(
        ui,
        "verifyPeerCertByName",
        &mut tls.verify_peer_cert_by_name,
        "comma-separated names",
    );
    changed |= widgets::text_field(
        ui,
        "echServerKeys",
        &mut tls.ech_server_keys,
        "standard base64 ECH server keys",
    );
    changed |= widgets::text_field(
        ui,
        "echConfigList",
        &mut tls.ech_config_list,
        "ECH config list",
    );
    // The realm TLS ECH sockopt's findings already ride the memoized
    // finalmask sweep (`validate_finalmask` validates this exact field under
    // its mask-scoped path), so the inline re-check here would be a second
    // message channel for the same value; the memoized finalmask verdict
    // list below the mask list is the one that renders it.
    changed |= ech_sockopt_editor(ui, lang, &mut tls.ech_sockopt, &[]);
    ui.weak(t(lang, Key::SrvRealmTlsWireNote));
    let mut remove = None;
    for (index, certificate) in tls.certificates.iter_mut().enumerate() {
        ui.push_id(("realm-cert", index), |ui| {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(t_fmt(lang, Key::SrvCertificateN, &[&(index + 1)]));
                    if ui.small_button(t(lang, Key::SrvRemove)).clicked() {
                        remove = Some(index);
                    }
                });
                changed |= path_field(
                    ui,
                    lang,
                    t(lang, Key::SrvCertificateFile),
                    &mut certificate.certificate_file,
                    false,
                );
                changed |= path_field(
                    ui,
                    lang,
                    t(lang, Key::SrvKeyFile),
                    &mut certificate.key_file,
                    false,
                );
                changed |= pem_lines_editor(
                    ui,
                    t(lang, Key::SrvCertificatePem),
                    profile,
                    &mut certificate.certificate,
                    "-----BEGIN CERTIFICATE-----",
                    pem_buffers,
                );
                changed |= pem_lines_editor(
                    ui,
                    t(lang, Key::SrvKeyPem),
                    profile,
                    &mut certificate.key,
                    "-----BEGIN PRIVATE KEY-----",
                    pem_buffers,
                );
                changed |= widgets::combo_str_labeled(
                    ui,
                    "usage",
                    &mut certificate.usage,
                    &["", "encipherment", "verify", "issue"],
                    t(lang, Key::SrvDefault),
                    false,
                );
                changed |= widgets::opt_num(
                    ui,
                    t(lang, Key::SrvOcspStaplingS),
                    &mut certificate.ocsp_stapling,
                    0..=u64::MAX,
                );
                changed |= widgets::opt_bool(
                    ui,
                    "oneTimeLoading",
                    &mut certificate.one_time_loading,
                    t(lang, Key::SrvUnset),
                );
                changed |= widgets::opt_bool(
                    ui,
                    "buildChain",
                    &mut certificate.build_chain,
                    t(lang, Key::SrvUnset),
                );
            });
        });
    }
    if let Some(index) = remove {
        tls.certificates.remove(index);
        changed = true;
    }
    if ui
        .small_button(t(lang, Key::SrvAddRealmTlsCertificate))
        .clicked()
    {
        tls.certificates.push(TlsCert::default());
        changed = true;
    }
    changed
}

pub(super) fn finalmask_udp_settings_editor(
    ui: &mut egui::Ui,
    lang: Language,
    mask: &mut FinalmaskUdpMask,
    field: RawField<'_>,
    pem_buffers: &mut std::collections::HashMap<egui::Id, PemBuf>,
    metrics: &MetricsHandle,
) -> bool {
    match mask {
        FinalmaskUdpMask::HeaderCustom { settings, .. } => {
            let mut changed = widgets::combo_str_labeled(
                ui,
                "mode",
                &mut settings.mode,
                &["", "prefix", "standalone"],
                t(lang, Key::SrvDefault),
                false,
            );
            changed |= finalmask_udp_items_editor(
                ui,
                lang,
                "client",
                &mut settings.client,
                RawField {
                    id: FieldKey {
                        key: field.id.key.with("client"),
                        profile: field.id.profile,
                    },
                    buffers: &mut *field.buffers,
                },
                metrics,
            );
            changed |= finalmask_udp_items_editor(
                ui,
                lang,
                "server",
                &mut settings.server,
                RawField {
                    id: FieldKey {
                        key: field.id.key.with("server"),
                        profile: field.id.profile,
                    },
                    buffers: &mut *field.buffers,
                },
                metrics,
            );
            changed
        }
        FinalmaskUdpMask::MkcpLegacy { settings, .. } => {
            let mut changed = widgets::combo_str_labeled(
                ui,
                "header",
                &mut settings.header,
                &["", "dns", "dtls", "srtp", "utp", "wechat", "wireguard"],
                t(lang, Key::SrvDefault),
                false,
            );
            changed |= widgets::text_field(
                ui,
                "value",
                &mut settings.value,
                "DNS domain or AES-128-GCM password",
            );
            changed
        }
        FinalmaskUdpMask::Noise { settings, .. } => {
            let mut changed = range_editor(ui, "reset", &mut settings.reset, i32::MIN..=i32::MAX);
            let mut remove = None;
            for (index, item) in settings.noise.iter_mut().enumerate() {
                ui.push_id(("noise", index), |ui| {
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(t_fmt(lang, Key::SrvNoiseN, &[&(index + 1)]));
                            if ui.small_button(t(lang, Key::SrvRemove)).clicked() {
                                remove = Some(index);
                            }
                        });
                        changed |= range_editor(ui, "rand", &mut item.rand, 0..=i32::MAX);
                        changed |=
                            widgets::opt_range(ui, "randRange", &mut item.rand_range, 0..=255);
                        changed |= range_editor(ui, "delay", &mut item.delay, i32::MIN..=i32::MAX);
                        changed |= finalmask_raw_value_editor(
                            ui,
                            lang,
                            "packet",
                            &mut item.encoding,
                            &mut item.packet,
                            RawField {
                                id: FieldKey {
                                    key: field.id.key.with(("noise", index)),
                                    profile: field.id.profile,
                                },
                                buffers: &mut *field.buffers,
                            },
                            metrics,
                        );
                    });
                });
            }
            if let Some(index) = remove {
                settings.noise.remove(index);
                changed = true;
            }
            if ui.small_button(t(lang, Key::SrvAddNoise)).clicked() {
                settings.noise.push(FinalmaskNoiseItem::default());
                changed = true;
            }
            changed
        }
        FinalmaskUdpMask::Salamander { settings, .. } => {
            let mut changed = widgets::text_field(ui, "password", &mut settings.password, "");
            changed |= range_editor(ui, "packetSize", &mut settings.packet_size, 0..=2048);
            changed
        }
        FinalmaskUdpMask::Sudoku { settings, .. } => finalmask_sudoku_editor(ui, lang, settings),
        FinalmaskUdpMask::Xdns { settings, .. } => {
            let mut changed = widgets::string_list(
                ui,
                lang,
                t(lang, Key::SrvDomainsServer),
                &mut settings.domains,
                "example.com",
            );
            changed |= widgets::string_list(
                ui,
                lang,
                t(lang, Key::SrvResolversClient),
                &mut settings.resolvers,
                "example.com+udp://1.1.1.1:53",
            );
            if !settings.domain.is_absent() {
                ui.colored_label(
                    status_colors_of(ui).err,
                    t(lang, Key::SrvImportedDomainRemoved),
                );
                if ui
                    .small_button(t(lang, Key::SrvRemoveObsoleteDomain))
                    .clicked()
                {
                    settings.domain = FinalmaskRawValue::Absent;
                    changed = true;
                }
            }
            changed
        }
        FinalmaskUdpMask::Xicmp { settings, .. } => {
            let mut changed = ui.checkbox(&mut settings.dgram, "dgram").changed();
            changed |= widgets::string_list(
                ui,
                lang,
                t(lang, Key::Ips),
                &mut settings.ips,
                "198.51.100.1",
            );
            changed
        }
        FinalmaskUdpMask::Realm { settings, .. } => {
            let mut changed =
                widgets::text_field(ui, "url", &mut settings.url, "realm://token@host/id");
            changed |= widgets::string_list(
                ui,
                lang,
                "stunServers",
                &mut settings.stun_servers,
                "stun.example.com:3478",
            );
            changed |= widgets::combo_str_labeled(
                ui,
                "ipMode",
                &mut settings.ip_mode,
                &["dual", "v4", "v6"],
                t(lang, Key::SrvDefault),
                true,
            );
            ui.weak(t(lang, Key::SrvRealmIpModeNote));
            let mut has_mapping = settings.port_mapping.is_some();
            if ui.checkbox(&mut has_mapping, "portMapping").changed() {
                settings.port_mapping = has_mapping.then(FinalmaskRealmPortMapping::default);
                changed = true;
            }
            if let Some(mapping) = settings.port_mapping.as_mut() {
                changed |= ui.checkbox(&mut mapping.enabled, "enabled").changed();
                changed |= widgets::opt_num(
                    ui,
                    t(lang, Key::SrvTimeoutS),
                    &mut mapping.timeout,
                    0..=i64::MAX,
                );
                changed |= widgets::opt_num(
                    ui,
                    t(lang, Key::SrvLifetimeS),
                    &mut mapping.lifetime,
                    0..=i64::MAX,
                );
                ui.weak(t(lang, Key::SrvRealmPortMappingNote));
            }
            let mut has_tls = settings.tls_config.is_some();
            if ui.checkbox(&mut has_tls, "tlsConfig").changed() {
                settings.tls_config = has_tls.then(FinalmaskRealmTls::default);
                changed = true;
            }
            if let Some(tls) = settings.tls_config.as_mut() {
                changed |= finalmask_realm_tls_editor(ui, lang, field.id.profile, tls, pem_buffers);
            }
            changed
        }
        FinalmaskUdpMask::Udphop { settings, .. } => finalmask_udphop_editor(ui, lang, settings),
        FinalmaskUdpMask::Unknown(raw) => finalmask_unknown_editor(
            ui,
            lang,
            raw,
            field.id.key.with("unknown"),
            field.id.profile,
            &mut *field.buffers,
            metrics,
        ),
    }
}

pub(super) fn finalmask_quic_editor(
    ui: &mut egui::Ui,
    lang: Language,
    quic: &mut Option<FinalmaskQuicParams>,
) -> bool {
    let mut changed = false;
    let mut enabled = quic.is_some();
    if ui.checkbox(&mut enabled, "quicParams").changed() {
        *quic = enabled.then(FinalmaskQuicParams::default);
        changed = true;
    }
    let Some(quic) = quic.as_mut() else {
        return changed;
    };
    changed |= widgets::combo_str_labeled(
        ui,
        "congestion",
        &mut quic.congestion,
        &["", "reno", "bbr", "brutal", "force-brutal"],
        t(lang, Key::SrvDefault),
        false,
    );
    changed |= widgets::opt_bool(ui, "debug", &mut quic.debug, t(lang, Key::SrvUnset));
    changed |= widgets::combo_str_labeled(
        ui,
        "bbrProfile",
        &mut quic.bbr_profile,
        &["", "conservative", "standard", "aggressive"],
        t(lang, Key::SrvDefault),
        false,
    );
    changed |= widgets::text_field(ui, "brutalUp", &mut quic.brutal_up, "50 mbps");
    changed |= widgets::text_field(ui, "brutalDown", &mut quic.brutal_down, "100 mbps");
    changed |= widgets::opt_bool(
        ui,
        "brutalDisableLossCompensation",
        &mut quic.brutal_disable_loss_compensation,
        t(lang, Key::SrvUnset),
    );
    changed |= widgets::opt_num(
        ui,
        "initStreamReceiveWindow",
        &mut quic.init_stream_receive_window,
        0..=u64::MAX,
    );
    changed |= widgets::opt_num(
        ui,
        "maxStreamReceiveWindow",
        &mut quic.max_stream_receive_window,
        0..=u64::MAX,
    );
    changed |= widgets::opt_num(
        ui,
        "initConnectionReceiveWindow",
        &mut quic.init_connection_receive_window,
        0..=u64::MAX,
    );
    changed |= widgets::opt_num(
        ui,
        "maxConnectionReceiveWindow",
        &mut quic.max_connection_receive_window,
        0..=u64::MAX,
    );
    changed |= widgets::opt_num(
        ui,
        t(lang, Key::SrvMaxIdleTimeoutS),
        &mut quic.max_idle_timeout,
        0..=120,
    );
    changed |= widgets::opt_num(
        ui,
        t(lang, Key::SrvKeepAlivePeriodS),
        &mut quic.keep_alive_period,
        0..=60,
    );
    changed |= widgets::opt_bool(
        ui,
        "disablePathMTUDiscovery",
        &mut quic.disable_path_mtu_discovery,
        t(lang, Key::SrvUnset),
    );
    changed |= widgets::opt_bool(
        ui,
        "disableChromeParrot",
        &mut quic.disable_chrome_parrot,
        t(lang, Key::SrvUnset),
    );
    changed |= widgets::opt_bool(
        ui,
        "disableGSO",
        &mut quic.disable_gso,
        t(lang, Key::SrvUnset),
    );
    changed |= widgets::opt_num(
        ui,
        "maxIncomingStreams",
        &mut quic.max_incoming_streams,
        0..=i64::MAX,
    );
    changed |= widgets::opt_bool(
        ui,
        "disableStatelessReset",
        &mut quic.disable_stateless_reset,
        t(lang, Key::SrvUnset),
    );
    changed
}
