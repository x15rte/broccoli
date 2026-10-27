//! Typed editors for the finalmask envelope of the servers screen: the
//! render-editor-returning-changed family over the finalmask model
//! (range/sequence/list rows, transforms, TCP/UDP masks, realm TLS, QUIC
//! hops), entered from the screen's advanced-tab editor plus intra-family
//! recursion. Raw-JSON and PEM fields edit through the screen's seeded
//! buffer machinery (`super::raw_editor`). The `filter` list editor is shared
//! with the inbound screen, which mounts the same mask on a listener.

use crate::i18n::{Key, t, t_fmt, validation_message};
use crate::model::settings::Language;
use crate::model::validation::{
    ValidationCode, noise_exp_finding, noise_exp_packet_finding, noise_script_issues,
    pinned_peer_cert_sha256_valid,
};
use crate::model::{
    FINALMASK_XDNS_DEFAULT_TYPES, FinalmaskFilter, FinalmaskNoiseItem, FinalmaskPortList,
    FinalmaskQuicParams, FinalmaskRawValue, FinalmaskRealmPortMapping, FinalmaskRealmTls,
    FinalmaskSudoku, FinalmaskTcpItem, FinalmaskTcpMask, FinalmaskTransform, FinalmaskTransformArg,
    FinalmaskUdpHop, FinalmaskUdpItem, FinalmaskUdpMask, FinalmaskXdns, FinalmaskXdnsDomain,
    FinalmaskXdnsResolver, FinalmaskXmc, FinalmaskXmcProfile, Int32Range, TlsCert, TlsModel,
    fold_eq,
};
use crate::ui::status::status_colors_of;
use crate::ui::widgets;

use super::raw_editor::{
    JsonEditorSpec, RawField, SeededBuffers, pem_lines_editor, raw_buffer_edit,
};
use super::tls_editor::{tls_connection_editor, tls_fields_editor, use_system_ca_row};
use super::{TLS_VERSIONS, ech_sockopt_editor, fingerprint_editor, path_field};

// ---------- finalmask typed editor ----------

/// One list's pre-rendered ordinal captions: the `t_fmt` outputs a row
/// header used to rebuild per row per frame.
///
/// The caption text is stored with the list length and language it was
/// rendered for — the DNS screen's `row_captions` cadence, which is all the
/// ordinal and its localized template depend on. It lives in egui temp data
/// (never persisted) under the list's own id, so an idle frame indexes the
/// cached strings and only a length or language change rebuilds them. The
/// returned `Arc` makes the per-frame handoff a refcount bump: a borrowed
/// cache could not outlive the `data_mut` closure while the row loop still
/// renders.
#[derive(Clone)]
struct ListCaptions {
    key: Key,
    lang: Language,
    len: usize,
    text: std::sync::Arc<[String]>,
}

fn list_captions(
    ui: &egui::Ui,
    id: egui::Id,
    len: usize,
    lang: Language,
    key: Key,
) -> std::sync::Arc<[String]> {
    if let Some(cached) = ui.ctx().data(|data| data.get_temp::<ListCaptions>(id))
        && cached.key == key
        && cached.lang == lang
        && cached.len == len
    {
        return cached.text;
    }
    let text: std::sync::Arc<[String]> = (0..len)
        .map(|index| t_fmt(lang, key, &[&(index + 1)]))
        .collect::<Vec<String>>()
        .into();
    ui.ctx().data_mut(|data| {
        data.insert_temp(
            id,
            ListCaptions {
                key,
                lang,
                len,
                text: std::sync::Arc::clone(&text),
            },
        );
    });
    text
}

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
    crate::ui::widgets::move_buttons(
        ui,
        index,
        len,
        crate::ui::widgets::MoveLabels::words(t(lang, Key::SrvUp), t(lang, Key::SrvDown)),
        move_to,
    );
    if ui.small_button(t(lang, Key::SrvRemove)).clicked() {
        *remove = Some(index);
    }
}

fn finalmask_unknown_editor(
    ui: &mut egui::Ui,
    lang: Language,
    raw: &mut serde_json::Value,
    field: RawField<'_>,
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
        field,
        raw,
        &JsonEditorSpec {
            hint: "{}",
            rows: 5,
        },
    )
}

fn finalmask_raw_value_editor(
    ui: &mut egui::Ui,
    lang: Language,
    label: &str,
    encoding: &mut String,
    raw: &mut FinalmaskRawValue,
    field: RawField<'_>,
) -> bool {
    let mut changed = widgets::combo_str_labeled(
        ui,
        &t_fmt(lang, Key::SrvLabelSyntax, &[&label]),
        encoding,
        &["", "array", "str", "hex", "base64"],
        t(lang, Key::SrvDefault),
        false,
    );
    changed |= finalmask_raw_value_body(ui, lang, label, encoding, raw, field);
    changed
}

/// The part of a raw-value field below its `type` combo: the present
/// checkbox and the value widget. Split out so a field whose type set is
/// wider than the byte-encoding kinds — the `noise` item's `exp` — can
/// render its own combo over the same body.
fn finalmask_raw_value_body(
    ui: &mut egui::Ui,
    lang: Language,
    label: &str,
    encoding: &str,
    raw: &mut FinalmaskRawValue,
    field: RawField<'_>,
) -> bool {
    let mut changed = false;
    let mut present = !raw.is_absent();
    if ui
        .checkbox(&mut present, t_fmt(lang, Key::SrvSetLabel, &[&label]))
        .changed()
    {
        *raw = if present {
            FinalmaskRawValue::Present(match encoding {
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
    if matches!(encoding, "str" | "hex" | "base64")
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
        );
    }
    changed
}

/// The `noise` item's `packet`. The byte-encoding kinds edit through
/// [`finalmask_raw_value_editor`]; `exp` reads a JSON string and parses it as
/// the token mini-language (`infra/conf/transport_finalmask.go:318-326`), so
/// its type edits the expression as plain text and never as a raw JSON
/// buffer.
fn finalmask_noise_packet_editor(
    ui: &mut egui::Ui,
    lang: Language,
    item: &mut FinalmaskNoiseItem,
    field: RawField<'_>,
) -> bool {
    let mut changed = widgets::combo_str_labeled(
        ui,
        &t_fmt(lang, Key::SrvLabelSyntax, &[&"packet"]),
        &mut item.encoding,
        &["", "array", "str", "hex", "base64", "exp"],
        t(lang, Key::SrvDefault),
        false,
    );
    if fold_eq(&item.encoding, "exp") {
        changed |= finalmask_noise_exp_field(ui, lang, &mut item.packet);
    } else {
        changed |=
            finalmask_raw_value_body(ui, lang, "packet", &item.encoding, &mut item.packet, field);
    }
    changed
}

/// The `noise` item's `exp` packet: the token expression in a plain text
/// field, with the model's own finding under it. A loaded packet that is not
/// a string cannot be read as an expression, so its finding renders and the
/// present checkbox replaces the value with the string the field edits.
fn finalmask_noise_exp_field(
    ui: &mut egui::Ui,
    lang: Language,
    raw: &mut FinalmaskRawValue,
) -> bool {
    let mut changed = false;
    let mut present = !raw.is_absent();
    if ui
        .checkbox(&mut present, t_fmt(lang, Key::SrvSetLabel, &[&"packet"]))
        .changed()
    {
        *raw = if present {
            FinalmaskRawValue::Present(serde_json::Value::String(String::new()))
        } else {
            FinalmaskRawValue::Absent
        };
        changed = true;
    }
    match raw.value_mut() {
        Some(serde_json::Value::String(expression)) => {
            changed |= widgets::validated_field(
                ui,
                "packet",
                expression,
                t(lang, Key::SrvNoiseExpHint),
                |text| noise_exp_finding(text).map(|code| validation_message(&code, lang)),
            );
        }
        _ => {
            if let Some(code) = noise_exp_packet_finding(raw) {
                ui.colored_label(status_colors_of(ui).err, validation_message(&code, lang));
            }
        }
    }
    changed
}

fn finalmask_transform_editor(
    ui: &mut egui::Ui,
    lang: Language,
    transform: &mut FinalmaskTransform,
    mut field: RawField<'_>,
) -> bool {
    let mut changed = widgets::text_field(ui, "op", &mut transform.op, "operation");
    let mut remove = None;
    let arg_captions = list_captions(
        ui,
        field.id.key.with("transform-arg-captions"),
        transform.args.len(),
        lang,
        Key::SrvArgumentN,
    );
    for (index, arg) in transform.args.iter_mut().enumerate() {
        ui.push_id(("transform-arg", field.id.key, index), |ui| {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(arg_captions[index].as_str());
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
                            field.with(("arg", index, "bytes")),
                        );
                    }
                    "u64" => {
                        changed |= widgets::opt_num(ui, "u64", &mut arg.u64, 0..=u64::MAX);
                    }
                    "reuse" => {
                        changed |= widgets::text_field(ui, "reuse", &mut arg.reuse, "_var");
                    }
                    "metadata" => {
                        changed |= widgets::text_field(ui, "metadata", &mut arg.metadata, "");
                    }
                    "transform" => {
                        if let Some(nested) = arg.transform.as_mut() {
                            changed |= finalmask_transform_editor(
                                ui,
                                lang,
                                nested,
                                field.with(("arg", index, "nested")),
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
    mut field: RawField<'_>,
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
        field.with("packet"),
    );
    let mut has_transform = item.transform.is_some();
    if ui.checkbox(&mut has_transform, "transform").changed() {
        item.transform = has_transform.then(FinalmaskTransform::default);
        changed = true;
    }
    if let Some(transform) = item.transform.as_mut() {
        changed |= finalmask_transform_editor(ui, lang, transform, field.with("transform"));
    }
    changed
}

fn finalmask_udp_item_editor(
    ui: &mut egui::Ui,
    lang: Language,
    item: &mut FinalmaskUdpItem,
    mut field: RawField<'_>,
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
        field.with("packet"),
    );
    let mut has_transform = item.transform.is_some();
    if ui.checkbox(&mut has_transform, "transform").changed() {
        item.transform = has_transform.then(FinalmaskTransform::default);
        changed = true;
    }
    if let Some(transform) = item.transform.as_mut() {
        changed |= finalmask_transform_editor(ui, lang, transform, field.with("transform"));
    }
    changed
}

fn finalmask_tcp_sequences_editor(
    ui: &mut egui::Ui,
    lang: Language,
    label: &str,
    sequences: &mut Vec<Vec<FinalmaskTcpItem>>,
    mut field: RawField<'_>,
) -> bool {
    let mut changed = false;
    ui.label(label);
    let mut remove_sequence = None;
    let sequence_captions = list_captions(
        ui,
        field.id.key.with("sequence-captions"),
        sequences.len(),
        lang,
        Key::SrvSequenceN,
    );
    for (sequence_index, sequence) in sequences.iter_mut().enumerate() {
        ui.push_id((field.id.key, "sequence", sequence_index), |ui| {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(sequence_captions[sequence_index].as_str());
                    if ui.small_button(t(lang, Key::SrvRemoveSequence)).clicked() {
                        remove_sequence = Some(sequence_index);
                    }
                });
                let mut remove_item = None;
                let item_captions = list_captions(
                    ui,
                    field
                        .id
                        .key
                        .with(("sequence-item-captions", sequence_index)),
                    sequence.len(),
                    lang,
                    Key::SrvItemN,
                );
                for (item_index, item) in sequence.iter_mut().enumerate() {
                    ui.push_id(("item", item_index), |ui| {
                        egui::CollapsingHeader::new(item_captions[item_index].as_str())
                            .default_open(true)
                            .show(ui, |ui| {
                                if ui.small_button(t(lang, Key::SrvRemoveItem)).clicked() {
                                    remove_item = Some(item_index);
                                }
                                changed |= finalmask_tcp_item_editor(
                                    ui,
                                    lang,
                                    item,
                                    field.with((sequence_index, item_index)),
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
    mut field: RawField<'_>,
) -> bool {
    let mut changed = false;
    ui.label(label);
    let mut remove = None;
    let item_captions = list_captions(
        ui,
        field.id.key.with("udp-item-captions"),
        items.len(),
        lang,
        Key::SrvItemN,
    );
    for (index, item) in items.iter_mut().enumerate() {
        ui.push_id((field.id.key, index), |ui| {
            egui::CollapsingHeader::new(item_captions[index].as_str())
                .default_open(true)
                .show(ui, |ui| {
                    if ui.small_button(t(lang, Key::SrvRemoveItem)).clicked() {
                        remove = Some(index);
                    }
                    changed |= finalmask_udp_item_editor(ui, lang, item, field.with(index));
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
/// seconds interval, the remote port list, and the remote address/prefix
/// list. The retired `sockopt` key renders its advisory and a removal
/// control instead of a sub-editor.
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
    // The retired `sockopt` key has no authoring control: the pinned core
    // removed the field, so a stored block draws the advisory here and a
    // control that drops it on the next commit. The advisory names the
    // replacement (the transport sockopt).
    if settings.sockopt.is_some() {
        ui.colored_label(
            status_colors_of(ui).warn,
            validation_message(&ValidationCode::FinalmaskUdpHopSockoptRetired, lang),
        );
        if ui.button(t(lang, Key::SrvRemoveUdpHopSockoptKey)).clicked() {
            settings.sockopt = None;
            changed = true;
        }
    }
    changed
}

fn finalmask_sudoku_editor(
    ui: &mut egui::Ui,
    lang: Language,
    settings: &mut FinalmaskSudoku,
    // Whether the mask's password renders masked (the reveal control).
    masked: bool,
) -> bool {
    let mut changed =
        widgets::masked_text_field(ui, "password", &mut settings.password, "", masked);
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

fn finalmask_xmc_editor(
    ui: &mut egui::Ui,
    lang: Language,
    settings: &mut FinalmaskXmc,
    // Whether the mask's password renders masked (the reveal control). The
    // login username is masked with it: a leaked username and a leaked
    // password together are worse than either alone.
    masked: bool,
    // The list's layout-caption identity (its `RawField` key).
    captions_id: egui::Id,
) -> bool {
    let mut changed =
        widgets::text_field(ui, "hostname", &mut settings.hostname, "play.example.com");
    changed |= widgets::masked_text_field(
        ui,
        "password",
        &mut settings.password,
        t(lang, Key::SrvXmcPasswordHint),
        masked,
    );
    let mut remove = None;
    let profile_captions = list_captions(
        ui,
        captions_id,
        settings.profiles.len(),
        lang,
        Key::SrvMinecraftProfileN,
    );
    for (index, profile) in settings.profiles.iter_mut().enumerate() {
        ui.push_id(("xmc-profile", index), |ui| {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(profile_captions[index].as_str());
                    if ui.small_button(t(lang, Key::SrvRemove)).clicked() {
                        remove = Some(index);
                    }
                });
                changed |= widgets::masked_text_field(
                    ui,
                    "username",
                    &mut profile.username,
                    "Player_1",
                    masked,
                );
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
                    t(lang, Key::SrvXmcTexturesValueHint),
                );
                changed |= widgets::text_field(
                    ui,
                    "texturesSignature",
                    &mut profile.textures_signature,
                    t(lang, Key::SrvXmcTexturesSignatureHint),
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

/// One removable text row of the `xdns` lists: the label and field, then the
/// remove action. Returns whether the text changed and whether the row asked
/// to be removed.
fn xdns_text_row(
    ui: &mut egui::Ui,
    lang: Language,
    label: &str,
    value: &mut String,
    hint: &str,
) -> (bool, bool) {
    let mut changed = false;
    let mut remove = false;
    ui.horizontal(|ui| {
        let label = ui.label(label);
        // Right-to-left: the remove button pins to the row's right edge and
        // the field fills exactly the remaining width. An unbounded field
        // laid out first would claim the whole row and push the button past
        // the clip rect (invisible, unclickable).
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.small_button(t(lang, Key::SrvRemove)).clicked() {
                remove = true;
            }
            changed = ui
                .add(
                    egui::TextEdit::singleline(value)
                        .hint_text(hint)
                        .desired_width(f32::INFINITY),
                )
                .labelled_by(label.id)
                .changed();
        });
    });
    (changed, remove)
}

/// Editor for the `xdns` settings: the server domains (each with its names,
/// limits, record types, and edns0), the client resolvers (each with its
/// addresses and worker count), and the `extraPoll` counter. A stored mask
/// written against a removed shape reaches this editor already migrated, so
/// only the current shape renders.
fn finalmask_xdns_editor(
    ui: &mut egui::Ui,
    lang: Language,
    settings: &mut FinalmaskXdns,
    field: &mut RawField<'_>,
) -> bool {
    // The record types the core's `NewDomain` accepts, as the body's numbers.
    const RECORD_TYPES: [(i32, &str); 4] = [(1, "A"), (5, "CNAME"), (16, "TXT"), (28, "AAAA")];
    let mut changed = false;

    ui.label(t(lang, Key::SrvDomainsServer));
    let mut remove_domain = None;
    let domain_captions = list_captions(
        ui,
        field.id.key.with("xdns-domain-captions"),
        settings.domains.len(),
        lang,
        Key::SrvXdnsDomainN,
    );
    for (index, domain) in settings.domains.iter_mut().enumerate() {
        ui.push_id(("xdns-domain", index), |ui| {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(domain_captions[index].as_str());
                    if ui.small_button(t(lang, Key::SrvRemove)).clicked() {
                        remove_domain = Some(index);
                    }
                });
                let mut remove_name = None;
                for (name_index, name) in domain.names.iter_mut().enumerate() {
                    ui.push_id(("xdns-domain-name", name_index), |ui| {
                        let (name_changed, remove) =
                            xdns_text_row(ui, lang, "name", name, "example.com");
                        changed |= name_changed;
                        if remove {
                            remove_name = Some(name_index);
                        }
                    });
                }
                if let Some(name_index) = remove_name {
                    domain.names.remove(name_index);
                    changed = true;
                }
                if ui.small_button(t(lang, Key::SrvAddXdnsName)).clicked() {
                    domain.names.push(String::new());
                    changed = true;
                }
                // The limits stay the core's own ranges. Whether a pair
                // leaves room for the encoded payload depends on the names
                // edited in this row, so the row cannot offer a tighter
                // bound; the validation pass reports a pair that does not.
                ui.horizontal(|ui| {
                    ui.label("lenLimit");
                    changed |= ui
                        .add(egui::DragValue::new(&mut domain.len_limit).range(0..=255))
                        .changed();
                    ui.label("labelLimit");
                    changed |= ui
                        .add(egui::DragValue::new(&mut domain.label_limit).range(0..=63))
                        .changed();
                });
                ui.horizontal(|ui| {
                    ui.label("types");
                    for (record_type, label) in RECORD_TYPES {
                        let mut on = domain.types.contains(&record_type);
                        if ui.checkbox(&mut on, label).changed() {
                            if on {
                                domain.types.push(record_type);
                            } else {
                                domain.types.retain(|value| *value != record_type);
                            }
                            changed = true;
                        }
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("edns0");
                    changed |= ui
                        .add(egui::DragValue::new(&mut domain.edns0).range(0..=4096))
                        .changed();
                });
            });
        });
    }
    if let Some(index) = remove_domain {
        settings.domains.remove(index);
        changed = true;
    }
    if ui.small_button(t(lang, Key::SrvAddXdnsDomain)).clicked() {
        settings.domains.push(FinalmaskXdnsDomain {
            // The core's 255/63 defaults, written out so the row shows the
            // limits it runs with; the types keep the row answering the
            // address records instead of the core's TXT-only default.
            len_limit: 255,
            label_limit: 63,
            types: FINALMASK_XDNS_DEFAULT_TYPES.to_vec(),
            ..Default::default()
        });
        changed = true;
    }

    ui.label(t(lang, Key::SrvResolversClient));
    let mut remove_resolver = None;
    let resolver_captions = list_captions(
        ui,
        field.id.key.with("xdns-resolver-captions"),
        settings.resolvers.len(),
        lang,
        Key::SrvXdnsResolverN,
    );
    for (index, resolver) in settings.resolvers.iter_mut().enumerate() {
        ui.push_id(("xdns-resolver", index), |ui| {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(resolver_captions[index].as_str());
                    if ui.small_button(t(lang, Key::SrvRemove)).clicked() {
                        remove_resolver = Some(index);
                    }
                });
                let mut remove_addr = None;
                for (addr_index, addr) in resolver.addrs.iter_mut().enumerate() {
                    ui.push_id(("xdns-resolver-addr", addr_index), |ui| {
                        let (addr_changed, remove) =
                            xdns_text_row(ui, lang, "addr", addr, "1.1.1.1:53");
                        changed |= addr_changed;
                        if remove {
                            remove_addr = Some(addr_index);
                        }
                    });
                }
                if let Some(addr_index) = remove_addr {
                    resolver.addrs.remove(addr_index);
                    changed = true;
                }
                if ui.small_button(t(lang, Key::SrvAddXdnsAddr)).clicked() {
                    resolver.addrs.push(String::new());
                    changed = true;
                }
                // Zero is the core's own 32-worker default, so the row
                // offers it as the unset shape; a negative count is what the
                // DoH resolver refuses, and the validation pass names it.
                ui.horizontal(|ui| {
                    ui.label("worker");
                    changed |= ui
                        .add(egui::DragValue::new(&mut resolver.worker).range(0..=i32::MAX))
                        .changed();
                });
                // A DoH resolver needs its own TLS block to run, and its h3
                // form is the ALPN list holding exactly `h3`. Both blocks use
                // the editors the outbound TLS settings and the mask-level
                // QUIC parameters already use, so the field names and rules
                // stay identical across the surfaces.
                let mut has_tls = resolver.tls_config.is_some();
                if ui
                    .checkbox(&mut has_tls, "tlsConfig")
                    .on_hover_text(t(lang, Key::SrvXdnsResolverTlsNote))
                    .changed()
                {
                    resolver.tls_config = has_tls.then(TlsModel::default);
                    changed = true;
                }
                if let Some(tls) = resolver.tls_config.as_mut() {
                    changed |= tls_fields_editor(
                        ui,
                        lang,
                        tls,
                        ValidationCode::TlsFingerprintUnsupported,
                        None,
                    );
                    changed |= tls_connection_editor(
                        ui,
                        lang,
                        tls,
                        field.id.profile,
                        &mut *field.buffers,
                        // The finalmask sweep already validates this nested
                        // block under its mask path, so the inline pass has
                        // no separate memoized list to render.
                        &[],
                    );
                }
                changed |= finalmask_quic_editor(ui, lang, "quicConfig", &mut resolver.quic_config);
            });
        });
    }
    if let Some(index) = remove_resolver {
        settings.resolvers.remove(index);
        changed = true;
    }
    if ui.small_button(t(lang, Key::SrvAddXdnsResolver)).clicked() {
        settings.resolvers.push(FinalmaskXdnsResolver::default());
        changed = true;
    }

    ui.horizontal(|ui| {
        ui.label("extraPoll");
        changed |= ui
            .add(egui::DragValue::new(&mut settings.extra_poll).range(0..=3))
            .changed();
    });

    changed
}

pub(super) fn finalmask_tcp_settings_editor(
    ui: &mut egui::Ui,
    lang: Language,
    mask: &mut FinalmaskTcpMask,
    mut field: RawField<'_>,
    // Whether the mask's credentials render masked (the reveal control).
    masked: bool,
) -> bool {
    match mask {
        FinalmaskTcpMask::HeaderCustom { settings, .. } => {
            let mut changed = finalmask_tcp_sequences_editor(
                ui,
                lang,
                "clients",
                &mut settings.clients,
                field.with("clients"),
            );
            changed |= finalmask_tcp_sequences_editor(
                ui,
                lang,
                "servers",
                &mut settings.servers,
                field.with("servers"),
            );
            changed |= finalmask_tcp_sequences_editor(
                ui,
                lang,
                "errors",
                &mut settings.errors,
                field.with("errors"),
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
        FinalmaskTcpMask::Sudoku { settings, .. } => {
            finalmask_sudoku_editor(ui, lang, settings, masked)
        }
        FinalmaskTcpMask::Xmc { settings, .. } => finalmask_xmc_editor(
            ui,
            lang,
            settings,
            masked,
            field.id.key.with("xmc-profile-captions"),
        ),
        FinalmaskTcpMask::Filter { settings, .. } => filter_settings_editor(ui, lang, settings),
        FinalmaskTcpMask::Unknown(raw) => {
            finalmask_unknown_editor(ui, lang, raw, field.with("unknown"))
        }
    }
}

/// The two source-IP rule lists of a `filter` mask
/// (`infra/conf/transport_finalmask.go:100-115`). Both accept the routing
/// IP-rule grammar; the core refuses the configuration on a malformed entry.
/// Shared by the listener editor and the finalmask editor, so the caption,
/// hint, and row shape cannot drift.
pub(crate) fn filter_settings_editor(
    ui: &mut egui::Ui,
    lang: Language,
    settings: &mut FinalmaskFilter,
) -> bool {
    const HINT: &str = "IP, CIDR, geoip:TAG, or ext:FILE:CODE";
    let mut changed = widgets::string_list(
        ui,
        lang,
        t(lang, Key::InboundsBlockedSourceIps),
        &mut settings.blocked_source_ips,
        HINT,
    );
    changed |= widgets::string_list(
        ui,
        lang,
        t(lang, Key::InboundsAllowedSourceIps),
        &mut settings.allowed_source_ips,
        HINT,
    );
    changed
}

fn finalmask_realm_tls_editor(
    ui: &mut egui::Ui,
    lang: Language,
    profile: &str,
    tls: &mut FinalmaskRealmTls,
    buffers: &mut SeededBuffers,
    // The certificate list's layout-caption identity (its `RawField` key).
    captions_id: egui::Id,
) -> bool {
    // The removed `allowInsecure` key has no authoring control: Xray's TLS
    // build refuses any non-zero value (infra/conf/transport_security.go), so
    // a stored value draws the model's own message here and a control that
    // drops it on the next commit.
    let mut changed = false;
    if tls.allow_insecure.is_some() {
        ui.colored_label(
            status_colors_of(ui).warn,
            validation_message(&ValidationCode::FinalmaskRealmAllowInsecureRemoved, lang),
        );
        if ui.button(t(lang, Key::SrvRemoveAllowInsecureKey)).clicked() {
            tls.allow_insecure = None;
            changed = true;
        }
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
    changed |= use_system_ca_row(ui, lang, &mut tls.use_system_ca);
    changed |= widgets::combo_str_labeled(
        ui,
        "minVersion",
        &mut tls.min_version,
        &TLS_VERSIONS,
        t(lang, Key::SrvDefault),
        false,
    );
    changed |= widgets::combo_str_labeled(
        ui,
        "maxVersion",
        &mut tls.max_version,
        &TLS_VERSIONS,
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
        t(lang, Key::SrvRealmTlsPinnedPeerCertSha256Hint),
        |v| (!pinned_peer_cert_sha256_valid(v)).then(|| t(lang, Key::SrvCertPinHex).to_string()),
    );
    changed |= widgets::text_field(
        ui,
        "verifyPeerCertByName",
        &mut tls.verify_peer_cert_by_name,
        t(lang, Key::SrvRealmTlsVerifyPeerCertByNameHint),
    );
    changed |= widgets::text_field(
        ui,
        "echServerKeys",
        &mut tls.ech_server_keys,
        t(lang, Key::SrvRealmTlsEchServerKeysHint),
    );
    changed |= widgets::text_field(ui, "echConfigList", &mut tls.ech_config_list, "");
    // The realm TLS ECH sockopt's findings already ride the memoized
    // finalmask sweep (`validate_finalmask` validates this exact field under
    // its mask-scoped path), so the inline re-check here would be a second
    // message channel for the same value; the memoized finalmask verdict
    // list below the mask list is the one that renders it.
    changed |= ech_sockopt_editor(ui, lang, &mut tls.ech_sockopt, &[]);
    let mut remove = None;
    let certificate_captions = list_captions(
        ui,
        captions_id,
        tls.certificates.len(),
        lang,
        Key::SrvCertificateN,
    );
    for (index, certificate) in tls.certificates.iter_mut().enumerate() {
        ui.push_id(("realm-cert", index), |ui| {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(certificate_captions[index].as_str());
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
                    buffers,
                );
                changed |= pem_lines_editor(
                    ui,
                    t(lang, Key::SrvKeyPem),
                    profile,
                    &mut certificate.key,
                    "-----BEGIN PRIVATE KEY-----",
                    buffers,
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
    mut field: RawField<'_>,
    // Whether the mask's credentials render masked (the reveal control).
    masked: bool,
    // The draft generation the script row's conflict verdict memoizes on.
    revision: u64,
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
                field.with("client"),
            );
            changed |= finalmask_udp_items_editor(
                ui,
                lang,
                "server",
                &mut settings.server,
                field.with("server"),
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
                t(lang, Key::SrvMkcpHeaderValueHint),
            );
            changed
        }
        FinalmaskUdpMask::Noise { settings, .. } => {
            // The script owns the mask's packets, so the row reports the
            // core's own exclusivity rule beside the shared path rule: a
            // script and the item list never reach the core together.
            let items = settings.noise.len();
            let conflict =
                |script: &str| noise_script_issues(Some(script), items).into_iter().next();
            let mut changed = widgets::lua_script_field(
                ui,
                lang,
                widgets::LuaScriptLabels {
                    toggle: t(lang, Key::SrvNoiseScriptToggle),
                    path: t(lang, Key::SrvNoiseScriptPath),
                    hint: t(lang, Key::SrvNoiseScriptHint),
                },
                &mut settings.script,
                widgets::context_revision((revision, items)),
                conflict,
            );
            changed |= range_editor(ui, "reset", &mut settings.reset, i32::MIN..=i32::MAX);
            let mut remove = None;
            let noise_captions = list_captions(
                ui,
                field.id.key.with("noise-captions"),
                settings.noise.len(),
                lang,
                Key::SrvNoiseN,
            );
            for (index, item) in settings.noise.iter_mut().enumerate() {
                ui.push_id(("noise", index), |ui| {
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(noise_captions[index].as_str());
                            if ui.small_button(t(lang, Key::SrvRemove)).clicked() {
                                remove = Some(index);
                            }
                        });
                        changed |= range_editor(ui, "rand", &mut item.rand, 0..=i32::MAX);
                        changed |=
                            widgets::opt_range(ui, "randRange", &mut item.rand_range, 0..=255);
                        changed |= range_editor(ui, "delay", &mut item.delay, i32::MIN..=i32::MAX);
                        changed |= finalmask_noise_packet_editor(
                            ui,
                            lang,
                            item,
                            field.with(("noise", index)),
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
            let mut changed =
                widgets::masked_text_field(ui, "password", &mut settings.password, "", masked);
            changed |= range_editor(ui, "packetSize", &mut settings.packet_size, 0..=2048);
            changed
        }
        FinalmaskUdpMask::Sudoku { settings, .. } => {
            finalmask_sudoku_editor(ui, lang, settings, masked)
        }
        FinalmaskUdpMask::Xdns { settings, .. } => {
            finalmask_xdns_editor(ui, lang, settings, &mut field)
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
            changed |= widgets::noted(ui, t(lang, Key::SrvRealmIpModeNote), |ui| {
                widgets::combo_str_labeled(
                    ui,
                    "ipMode",
                    &mut settings.ip_mode,
                    &["dual", "v4", "v6"],
                    t(lang, Key::SrvDefault),
                    true,
                )
            });
            let mut has_mapping = settings.port_mapping.is_some();
            if ui
                .checkbox(&mut has_mapping, "portMapping")
                .on_hover_text(t(lang, Key::SrvRealmPortMappingNote))
                .changed()
            {
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
            }
            let mut has_tls = settings.tls_config.is_some();
            if ui
                .checkbox(&mut has_tls, "tlsConfig")
                .on_hover_text(t(lang, Key::SrvRealmTlsWireNote))
                .changed()
            {
                settings.tls_config = has_tls.then(FinalmaskRealmTls::default);
                changed = true;
            }
            if let Some(tls) = settings.tls_config.as_mut() {
                changed |= finalmask_realm_tls_editor(
                    ui,
                    lang,
                    field.id.profile,
                    tls,
                    &mut *field.buffers,
                    field.id.key.with("realm-certificate-captions"),
                );
            }
            changed
        }
        FinalmaskUdpMask::Udphop { settings, .. } => finalmask_udphop_editor(ui, lang, settings),
        FinalmaskUdpMask::Filter { settings, .. } => filter_settings_editor(ui, lang, settings),
        FinalmaskUdpMask::Unknown(raw) => {
            finalmask_unknown_editor(ui, lang, raw, field.with("unknown"))
        }
    }
}

pub(super) fn finalmask_quic_editor(
    ui: &mut egui::Ui,
    lang: Language,
    // The key the block hangs under in this context: `quicParams` at the
    // mask level, `quicConfig` inside an xdns resolver.
    label: &str,
    quic: &mut Option<FinalmaskQuicParams>,
) -> bool {
    let mut changed = false;
    let mut enabled = quic.is_some();
    if ui.checkbox(&mut enabled, label).changed() {
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
    changed
}
