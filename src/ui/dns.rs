//! DNS screen: DNS server list, hosts map, global toggles, and
//! the fakeDNS switch (whose trio — pool + server entry + sniffing
//! destOverride — is injected by the generator).

use crate::i18n::{Key, t, t_fmt};
use crate::model::dns::{
    DEFAULT_FAKEDNS_POOL_CIDR, DEFAULT_QUERY_STRATEGY, MAX_SERVE_EXPIRED_TTL,
    SECOND_FAKEDNS_POOL_CIDR, SECOND_FAKEDNS_POOL_SIZE, is_valid_cidr,
};
use crate::model::settings::Language;
use crate::model::{DnsServer, FakeDnsPool};
use crate::ui::{UiCtx, widgets};
use egui::{DragValue, RichText, Ui};
use serde_json::{Map, Value};

#[derive(Default)]
pub struct DnsScreen {
    /// Index of the DNS server with the inline editor open.
    edit_server: Option<usize>,
    /// Editing buffer for the hosts map (rows with empty keys must survive
    /// mid-edit, so they can't live in the model directly).
    hosts_buf: Option<Vec<(String, String)>>,
    /// Per-server `domains` hover text, pre-joined when a row is edited or
    /// the list is restructured — the row loop renders these instead of
    /// re-joining on every frame. Always aligned with `dns.servers`.
    hover_domains: Vec<String>,
    /// Per-server row caption fragments (`#N` ordinal, `:port` suffix,
    /// domains-count caption), pre-rendered at the same cadence as
    /// `hover_domains` — the row loop paints them instead of formatting on
    /// every frame. Always aligned with `dns.servers`.
    row_captions: Vec<ServerRowCaption>,
    /// The language the current `row_captions` were rendered in — the
    /// domains-count caption is localized, so a language switch rebuilds
    /// the captions (cheap `Copy` compare; `hover_domains` is
    /// language-independent and does not need the key).
    row_caption_lang: Language,
}

/// One DNS-server row's memoized caption fragments: the
/// `format!`/`t_fmt` outputs the row header used to rebuild per row per
/// frame. `port`/`domains_count` mirror their render gates — absent while
/// the server has no port / no domains.
struct ServerRowCaption {
    /// "#N" ordinal prefix (list position).
    ordinal: String,
    /// ":port" suffix.
    port: Option<String>,
    /// Domains-count caption.
    domains_count: Option<String>,
}

/// Pre-render one row's caption fragments from the model — called only on
/// list restructures and row edits, never on idle repaint frames.
fn row_caption(i: usize, srv: &DnsServer, lang: Language) -> ServerRowCaption {
    ServerRowCaption {
        ordinal: format!("#{}", i + 1),
        port: srv.port.map(|port| format!(":{port}")),
        domains_count: (!srv.domains.is_empty())
            .then(|| t_fmt(lang, Key::DnsDomainsCount, &[&srv.domains.len()])),
    }
}

impl DnsScreen {
    pub fn show(&mut self, ui: &mut Ui, ctx: &mut UiCtx) {
        let mut changed = false;
        self.servers_section(ui, ctx, &mut changed);
        self.hosts_section(ui, ctx, &mut changed);
        self.global_section(ui, ctx, &mut changed);
        self.fakedns_section(ui, ctx, &mut changed);
        if changed {
            ctx.mark_dirty();
        }
    }

    // ---------- servers ----------

    fn servers_section(&mut self, ui: &mut Ui, ctx: &mut UiCtx, changed: &mut bool) {
        let lang = ctx.settings.language;
        widgets::section(ui, t(lang, Key::DnsSectionServers), |ui| {
            let mut delete: Option<usize> = None;
            let mut swap: Option<(usize, usize)> = None;
            {
                let servers = &mut ctx.settings.dns.servers;
                let server_count = servers.len();
                // Domains change only through the inline editor (which marks
                // the row dirty below) or the list operations after the loop,
                // so the joined hover text is cached per row and rebuilt only
                // when the list is restructured. The row captions (`#N`,
                // `:port`, domains count) ride the same resync cadence, plus
                // a language switch — the count caption is localized.
                if self.hover_domains.len() != servers.len() || self.row_caption_lang != lang {
                    self.hover_domains = servers.iter().map(|s| s.domains.join("\n")).collect();
                    self.row_captions = servers
                        .iter()
                        .enumerate()
                        .map(|(i, srv)| row_caption(i, srv, lang))
                        .collect();
                    self.row_caption_lang = lang;
                }
                for (i, srv) in servers.iter_mut().enumerate() {
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            // Caption fragments come from the pre-rendered
                            // row cache; only the tag label
                            // stays live (it is the row's own String).
                            ui.monospace(&self.row_captions[i].ordinal)
                                .on_hover_text(t(lang, Key::DnsPriorityHint));
                            if ui
                                .add_enabled(i > 0, egui::Button::new("▲").small())
                                .on_hover_text(t(lang, Key::DnsMoveUp))
                                .clicked()
                            {
                                swap = Some((i, i - 1));
                            }
                            if ui
                                .add_enabled(i + 1 < server_count, egui::Button::new("▼").small())
                                .on_hover_text(t(lang, Key::DnsMoveDown))
                                .clicked()
                            {
                                swap = Some((i, i + 1));
                            }
                            ui.label(
                                RichText::new(if srv.address.is_empty() {
                                    t(lang, Key::DnsNoAddress)
                                } else {
                                    &srv.address
                                })
                                .strong(),
                            );
                            if let Some(port) = &self.row_captions[i].port {
                                ui.label(port);
                            }
                            if let Some(count) = &self.row_captions[i].domains_count {
                                ui.label(count).on_hover_text(&self.hover_domains[i]);
                            }
                            if !srv.tag.is_empty() {
                                ui.monospace(&srv.tag);
                            }
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui
                                        .small_button(t(lang, Key::DeleteRow))
                                        .on_hover_text(t(lang, Key::DeleteServer))
                                        .clicked()
                                    {
                                        delete = Some(i);
                                    }
                                    let open = self.edit_server == Some(i);
                                    if ui
                                        .small_button(if open { "▾" } else { "▸" })
                                        .on_hover_text(t(lang, Key::DnsEditServer))
                                        .clicked()
                                    {
                                        self.edit_server = if open { None } else { Some(i) };
                                    }
                                },
                            );
                        });
                        if self.edit_server == Some(i) {
                            let edited = server_editor(ui, lang, srv, i);
                            if edited {
                                self.hover_domains[i] = srv.domains.join("\n");
                                self.row_captions[i] = row_caption(i, srv, lang);
                            }
                            *changed |= edited;
                        }
                    });
                }
            }
            if delete.is_none()
                && let Some((from, to)) = swap
            {
                ctx.settings.dns.servers.swap(from, to);
                self.hover_domains.swap(from, to);
                // Captions can't follow the swap wholesale: the ordinal is
                // index-bound. Rebuild the two affected rows from their new
                // contents (a swap is an interaction frame, never idle).
                self.row_captions[from] = row_caption(from, &ctx.settings.dns.servers[from], lang);
                self.row_captions[to] = row_caption(to, &ctx.settings.dns.servers[to], lang);
                self.edit_server = remap_swapped_index(self.edit_server, from, to);
                *changed = true;
            }
            if let Some(i) = delete {
                ctx.settings.dns.servers.remove(i);
                self.edit_server = match self.edit_server {
                    Some(e) if e == i => None,
                    Some(e) if e > i => Some(e - 1),
                    e => e,
                };
                *changed = true;
            }
            if ui.button(t(lang, Key::DnsAddServer)).clicked() {
                ctx.settings.dns.servers.push(new_dns_server());
                self.edit_server = Some(ctx.settings.dns.servers.len() - 1);
                *changed = true;
            }
        });
    }

    // ---------- hosts ----------

    fn hosts_section(&mut self, ui: &mut Ui, ctx: &mut UiCtx, changed: &mut bool) {
        let lang = ctx.settings.language;
        widgets::section(ui, t(lang, Key::DnsSectionHosts), |ui| {
            let buf = self
                .hosts_buf
                .get_or_insert_with(|| hosts_to_rows(&ctx.settings.dns.hosts));
            if widgets::kv_table(
                ui,
                lang,
                buf,
                t(lang, Key::DnsHostsKeyHint),
                t(lang, Key::DnsHostsValueHint),
            ) {
                ctx.settings.dns.hosts = rows_to_hosts(buf);
                *changed = true;
            }
        });
    }

    // ---------- global ----------

    fn global_section(&mut self, ui: &mut Ui, ctx: &mut UiCtx, changed: &mut bool) {
        let lang = ctx.settings.language;
        widgets::section(ui, t(lang, Key::DnsSectionGlobal), |ui| {
            let dns = &mut ctx.settings.dns;
            *changed |= widgets::text_field(
                ui,
                t(lang, Key::DnsClientIp),
                &mut dns.client_ip,
                t(lang, Key::DnsClientIpHint),
            );
            *changed |= widgets::text_field(
                ui,
                t(lang, Key::DnsBootstrapLabel),
                &mut dns.bootstrap,
                t(lang, Key::DnsBootstrapHint),
            );
            *changed |= widgets::combo_str(
                ui,
                t(lang, Key::DnsQueryStrategy),
                "dns-qs",
                &mut dns.query_strategy,
                &["useip", "useip4", "useip6", "usesys"],
                t(lang, Key::Any),
                false,
            );
            if dns.query_strategy.is_empty() {
                dns.query_strategy = DEFAULT_QUERY_STRATEGY.into();
            }
            ui.horizontal(|ui| {
                if ui
                    .checkbox(&mut dns.disable_cache, t(lang, Key::DnsDisableCache))
                    .changed()
                {
                    *changed = true;
                }
                if ui
                    .checkbox(&mut dns.disable_fallback, t(lang, Key::DnsDisableFallback))
                    .changed()
                {
                    *changed = true;
                }
                if ui
                    .checkbox(
                        &mut dns.disable_fallback_if_match,
                        t(lang, Key::DnsDisableFallbackIfMatched),
                    )
                    .on_hover_text(t(lang, Key::DnsSkipFallbackHint))
                    .changed()
                {
                    *changed = true;
                }
            });
            ui.horizontal(|ui| {
                if ui
                    .checkbox(&mut dns.serve_stale, t(lang, Key::DnsServeStale))
                    .on_hover_text(t(lang, Key::DnsServeStaleHint))
                    .changed()
                {
                    *changed = true;
                }
                if ui
                    .checkbox(
                        &mut dns.enable_parallel_query,
                        t(lang, Key::DnsParallelQueries),
                    )
                    .changed()
                {
                    *changed = true;
                }
                if ui
                    .checkbox(&mut dns.use_system_hosts, t(lang, Key::DnsUseSystemHosts))
                    .changed()
                {
                    *changed = true;
                }
            });
            // The range cap is the shared model const: a raised
            // default must never fall outside the editor's reach.
            *changed |= widgets::opt_u32(
                ui,
                t(lang, Key::DnsServeExpiredTtl),
                &mut dns.serve_expired_ttl,
                0..=MAX_SERVE_EXPIRED_TTL,
            );
        });
    }

    // ---------- fakeDNS ----------

    fn fakedns_section(&mut self, ui: &mut Ui, ctx: &mut UiCtx, changed: &mut bool) {
        let lang = ctx.settings.language;
        widgets::section(ui, t(lang, Key::DnsSectionFakedns), |ui| {
            let fd = &mut ctx.settings.dns.fakedns;
            if ui
                .checkbox(&mut fd.enabled, t(lang, Key::DnsEnableFakedns))
                .changed()
            {
                if fd.enabled && fd.pools.is_empty() {
                    fd.pools.push(FakeDnsPool::default());
                }
                *changed = true;
            }
            ui.label(
                RichText::new(t(lang, Key::DnsFakednsExplain))
                    .small()
                    .weak(),
            );
            if fd.enabled {
                let mut delete = None;
                for (index, pool) in fd.pools.iter_mut().enumerate() {
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.strong(t_fmt(lang, Key::DnsPoolTitle, &[&(index + 1)]));
                            if ui.small_button(t(lang, Key::Remove)).clicked() {
                                delete = Some(index);
                            }
                        });
                        *changed |= widgets::validated_field(
                            ui,
                            t(lang, Key::DnsIpPool),
                            &mut pool.ip_pool,
                            if index == 0 {
                                DEFAULT_FAKEDNS_POOL_CIDR
                            } else {
                                SECOND_FAKEDNS_POOL_CIDR
                            },
                            |value| {
                                let value = value.trim();
                                if value.is_empty() {
                                    Some(t(lang, Key::DnsPoolCidrRequired).into())
                                } else if !is_valid_cidr(value) {
                                    Some(t(lang, Key::DnsPoolCidrInvalid).into())
                                } else {
                                    None
                                }
                            },
                        );
                        ui.horizontal(|ui| {
                            ui.label(t(lang, Key::DnsPoolSize));
                            *changed |= ui
                                .add(DragValue::new(&mut pool.pool_size).range(1..=i64::MAX))
                                .changed();
                        });
                    });
                }
                if let Some(index) = delete {
                    fd.pools.remove(index);
                    if fd.pools.is_empty() {
                        fd.pools.push(FakeDnsPool::default());
                    }
                    *changed = true;
                }
                if ui.button(t(lang, Key::DnsAddPool)).clicked() {
                    let mut pool = FakeDnsPool::default();
                    if !fd.pools.is_empty() {
                        pool = new_pool_suggestion();
                    }
                    fd.pools.push(pool);
                    *changed = true;
                }
            }
        });
    }
}

/// Per-server editor; covers every `DnsServer` model field.
fn server_editor(ui: &mut Ui, lang: Language, srv: &mut DnsServer, idx: usize) -> bool {
    let mut changed = false;
    // Id salts are index tuples, not `format!` strings — the editor renders
    // only while open, but its per-frame ids stay allocation-free.
    egui::Grid::new(("dns-srv", idx))
        .num_columns(2)
        .spacing([16.0, 4.0])
        .show(ui, |ui| {
            changed |= widgets::validated_field(
                ui,
                t(lang, Key::DnsAddress),
                &mut srv.address,
                t(lang, Key::DnsAddressHint),
                |address| {
                    address
                        .trim()
                        .is_empty()
                        .then(|| t(lang, Key::DnsAddressRequired).into())
                },
            );
            changed |= opt_u16(ui, lang, t(lang, Key::DnsPort), &mut srv.port);
            ui.end_row();

            // `string_list` emits its label, item rows, and "+ Add" button as
            // separate widgets into the caller's layout. Inside a Grid each
            // would occupy its own cell, corrupting the column bookkeeping
            // (cells land past the viewport; the overflow grows the section's
            // max_rect and pushes later rows' buttons out of the clip rect).
            // A single-cell group keeps each list in exactly one grid cell.
            changed |= ui
                .vertical(|ui| {
                    widgets::string_list(
                        ui,
                        lang,
                        t(lang, Key::DnsDomains),
                        &mut srv.domains,
                        t(lang, Key::DnsDomainsHint),
                    )
                })
                .inner;
            changed |= ui
                .vertical(|ui| {
                    widgets::string_list(
                        ui,
                        lang,
                        t(lang, Key::DnsExpectedIps),
                        &mut srv.expected_ips,
                        t(lang, Key::DnsExpectedIpsHint),
                    )
                })
                .inner;
            ui.end_row();

            changed |= ui
                .vertical(|ui| {
                    widgets::string_list(
                        ui,
                        lang,
                        t(lang, Key::DnsUnexpectedIps),
                        &mut srv.unexpected_ips,
                        t(lang, Key::DnsUnexpectedIpsHint),
                    )
                })
                .inner;
            changed |= widgets::text_field(
                ui,
                t(lang, Key::DnsClientIp),
                &mut srv.client_ip,
                t(lang, Key::DnsClientIpOverride),
            );
            ui.end_row();

            changed |= widgets::combo_str(
                ui,
                t(lang, Key::DnsQueryStrategy),
                ("dns-srv-qs", idx),
                &mut srv.query_strategy,
                &["useip", "useip4", "useip6", "usesys"],
                t(lang, Key::Any),
                true,
            );
            changed |= widgets::text_field(
                ui,
                t(lang, Key::DnsTag),
                &mut srv.tag,
                t(lang, Key::DnsTagOutbound),
            );
            ui.end_row();

            changed |= widgets::opt_bool_tri(
                ui,
                lang,
                t(lang, Key::DnsSkipFallback),
                &mut srv.skip_fallback,
            );
            changed |=
                widgets::opt_bool_tri(ui, lang, t(lang, Key::DnsFinalQuery), &mut srv.final_query);
            ui.end_row();

            changed |= widgets::opt_bool_tri(
                ui,
                lang,
                t(lang, Key::DnsDisableCache),
                &mut srv.disable_cache,
            );
            changed |=
                widgets::opt_bool_tri(ui, lang, t(lang, Key::DnsServeStale), &mut srv.serve_stale);
            ui.end_row();

            changed |= widgets::opt_u32(
                ui,
                t(lang, Key::DnsServeExpiredTtl),
                &mut srv.serve_expired_ttl,
                0..=u32::MAX,
            );
            ui.end_row();
        });
    changed |= timeout_editor(ui, lang, &mut srv.timeout_ms);
    changed
}

// ---------- helpers ----------
fn parse_timeout_ms(lang: Language, input: &str) -> Result<u64, String> {
    if input.is_empty() {
        return Err(t(lang, Key::DnsTimeoutRequired).into());
    }
    if !input.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(t(lang, Key::DnsTimeoutInteger).into());
    }
    input
        .parse()
        .map_err(|_| t(lang, Key::DnsTimeoutRange).into())
}

fn timeout_editor(ui: &mut Ui, lang: Language, timeout_ms: &mut u64) -> bool {
    let id = ui.next_auto_id().with("dns-timeout-ms");
    let mut text = ui
        .data(|data| data.get_temp::<String>(id))
        .unwrap_or_else(|| timeout_ms.to_string());
    let mut error = None;
    let mut changed = false;

    ui.horizontal(|ui| {
        let label = ui.label(t(lang, Key::DnsTimeoutMs));
        let response = ui
            .add(
                egui::TextEdit::singleline(&mut text)
                    .desired_width(180.0)
                    .hint_text("8000"),
            )
            .labelled_by(label.id);
        // One parse per frame (the verdict feeds both the hover/error
        // display and the commit gate below), replacing the pre-existing
        // double parse on every changed frame.
        let parsed = parse_timeout_ms(lang, &text);
        error = parsed.as_ref().err().cloned();
        let response =
            response.on_hover_text(error.as_deref().unwrap_or(t(lang, Key::DnsTimeoutHint)));
        if response.changed() {
            if let Ok(value) = parsed
                && *timeout_ms != value
            {
                *timeout_ms = value;
                changed = true;
            }
            ui.data_mut(|data| data.insert_temp(id, text.clone()));
        }
        ui.label(
            RichText::new(t(lang, Key::DnsTimeoutDefault))
                .small()
                .weak(),
        );
    });
    if let Some(message) = error {
        ui.horizontal(|ui| {
            ui.add_space(ui.spacing().indent);
            ui.colored_label(ui.visuals().error_fg_color, RichText::new(message).small());
        });
    }
    changed
}

/// dns.hosts values: a single IP/domain string, or a JSON array when the
/// edited value contains commas.
fn hosts_to_rows(hosts: &Map<String, Value>) -> Vec<(String, String)> {
    hosts
        .iter()
        .map(|(k, v)| {
            let s = match v {
                Value::String(s) => s.clone(),
                Value::Array(a) => a
                    .iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect::<Vec<_>>()
                    .join(", "),
                other => other.to_string(),
            };
            (k.clone(), s)
        })
        .collect()
}

fn rows_to_hosts(rows: &[(String, String)]) -> Map<String, Value> {
    rows.iter()
        .filter(|(k, _)| !k.trim().is_empty())
        .map(|(k, v)| {
            let parts: Vec<String> = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let val = if parts.len() > 1 {
                Value::Array(parts.into_iter().map(Value::String).collect())
            } else {
                Value::String(parts.into_iter().next().unwrap_or_default())
            };
            (k.trim().to_string(), val)
        })
        .collect()
}

fn new_dns_server() -> DnsServer {
    DnsServer {
        address: "1.1.1.1".into(),
        ..Default::default()
    }
}
/// The pool the DNS screen commits when the user adds a pool after the
/// first: exactly the fresh-install seed's second pool (the UI
/// suggestion and the seed share one canonical definition).
fn new_pool_suggestion() -> FakeDnsPool {
    FakeDnsPool {
        ip_pool: SECOND_FAKEDNS_POOL_CIDR.into(),
        pool_size: SECOND_FAKEDNS_POOL_SIZE,
        ..Default::default()
    }
}
fn remap_swapped_index(selected: Option<usize>, a: usize, b: usize) -> Option<usize> {
    match selected {
        Some(index) if index == a => Some(b),
        Some(index) if index == b => Some(a),
        other => other,
    }
}

/// Checkbox-gated DragValue for `Option<u16>` ports.
fn opt_u16(ui: &mut Ui, lang: Language, label: &str, v: &mut Option<u16>) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        ui.label(label);
        let mut on = v.is_some();
        if ui.checkbox(&mut on, "").changed() {
            *v = on.then_some(53);
            changed = true;
        }
        if let Some(x) = v.as_mut() {
            if ui.add(DragValue::new(x).range(1..=65535)).changed() {
                changed = true;
            }
        } else {
            ui.label(RichText::new(t(lang, Key::DnsSchemeDefault)).weak());
        }
    });
    changed
}

#[cfg(test)]
mod tests {
    use super::{
        DnsScreen, Language, new_dns_server, new_pool_suggestion, parse_timeout_ms,
        remap_swapped_index, row_caption, timeout_editor,
    };
    use crate::model::FakeDnsCfg;
    use crate::ui::test_rig::UiTestRig;
    use egui_kittest::{Harness, kittest::Queryable as _};

    #[test]
    fn add_pool_suggestion_matches_seeded_second_pool() {
        let suggested = new_pool_suggestion();
        let seed = &FakeDnsCfg::default().pools[1];
        assert_eq!(suggested.ip_pool, seed.ip_pool);
        assert_eq!(suggested.pool_size, seed.pool_size);
    }

    /// The row caption fragments are pre-rendered once per
    /// model change — the cache entries must equal what the row header used
    /// to format live, including the empty-fragment gates.
    #[test]
    fn row_captions_match_fresh_formatting() {
        let mut srv = new_dns_server();
        let caption = row_caption(0, &srv, Language::En);
        assert_eq!(caption.ordinal, "#1");
        assert_eq!(caption.port, None, "no port renders no suffix fragment");
        assert_eq!(
            caption.domains_count, None,
            "no domains renders no count fragment"
        );

        srv.port = Some(53);
        srv.domains = vec!["example.com".into(), "test.org".into()];
        let caption = row_caption(2, &srv, Language::En);
        assert_eq!(caption.ordinal, "#3", "the ordinal follows the list index");
        assert_eq!(caption.port.as_deref(), Some(":53"));
        assert_eq!(caption.domains_count.as_deref(), Some("domains: 2 +"));
    }

    #[test]
    fn open_editor_follows_reordered_dns_server() {
        assert_eq!(remap_swapped_index(Some(1), 1, 0), Some(0));
        assert_eq!(remap_swapped_index(Some(0), 1, 0), Some(1));
        assert_eq!(remap_swapped_index(Some(2), 1, 0), Some(2));
    }

    #[test]
    fn added_dns_server_has_a_core_valid_address() {
        assert_eq!(new_dns_server().address, "1.1.1.1");
    }

    #[test]
    fn timeout_decimal_parser_covers_full_u64_domain() {
        let lang = Language::En;
        assert_eq!(parse_timeout_ms(lang, "0"), Ok(0));
        assert_eq!(parse_timeout_ms(lang, "4000"), Ok(4000));
        assert_eq!(parse_timeout_ms(lang, "18446744073709551615"), Ok(u64::MAX));
        assert!(parse_timeout_ms(lang, "18446744073709551616").is_err());
        assert!(parse_timeout_ms(lang, "").is_err());
        assert!(parse_timeout_ms(lang, "-1").is_err());
        assert!(parse_timeout_ms(lang, "4s").is_err());
    }

    #[test]
    fn timeout_editor_accepts_u64_max_from_keyboard() {
        let mut harness = Harness::new_ui_state(
            |ui, timeout| {
                let _ = timeout_editor(ui, Language::En, timeout);
            },
            4000_u64,
        );
        harness.get_by_label("Timeout (ms)").focus();
        harness.run();
        harness.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::A);
        harness
            .get_by_label("Timeout (ms)")
            .type_text("18446744073709551615");
        harness.run();

        assert_eq!(*harness.state(), u64::MAX);
    }

    #[test]
    fn expanding_first_server_keeps_second_rows_buttons_in_view() {
        // Regression: opening the inline editor of the first DNS server
        // (1.1.1.1) used to push the second row's (8.8.8.8) edit/delete
        // buttons out of the visible area — invisible, unclickable.
        let mut rig = UiTestRig::default();
        assert_eq!(
            rig.settings.dns.servers.len(),
            2,
            "seeded default pair 1.1.1.1 + 8.8.8.8"
        );
        let mut screen = DnsScreen::default();
        let mut harness = Harness::builder()
            .with_size(egui::vec2(980.0, 720.0))
            .build_ui_state(
                move |ui, _state: &mut ()| {
                    // Same outer scroll wrapper as app.rs's screen dispatch.
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, true])
                        .show(ui, |ui| screen.show(ui, &mut rig.ctx()));
                },
                (),
            );
        harness.run();

        let toggles: Vec<_> = harness.query_all_by_label("▸").collect();
        assert_eq!(toggles.len(), 2, "both rows start collapsed");
        // The first row is the topmost toggle.
        let first = if toggles[0].rect().top() <= toggles[1].rect().top() {
            toggles[0]
        } else {
            toggles[1]
        };
        first.click();
        harness.run();
        harness.run();
        harness.run();
        harness.run();

        let collapsed: Vec<_> = harness.query_all_by_label("▸").collect();
        assert_eq!(
            collapsed.len(),
            1,
            "first row expanded, second stays collapsed"
        );
        let deletes: Vec<_> = harness.query_all_by_label("🗑").collect();
        assert_eq!(deletes.len(), 2, "both rows keep their delete buttons");

        let viewport = egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(980.0, 720.0));
        assert!(
            collapsed[0].rect().intersects(viewport),
            "second row's edit toggle must stay visible; got {:?}",
            collapsed[0].rect()
        );
        assert!(
            deletes.iter().all(|n| n.rect().intersects(viewport)),
            "every delete button must stay visible"
        );
    }
}
