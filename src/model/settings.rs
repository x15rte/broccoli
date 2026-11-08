//! Application settings (GUI state: %APPDATA%\broccoli\state\settings.json).

use super::dns::DnsCfg;
use super::inbound::{DokodemoCfg, LocalInboundCfg, TunCfg, default_local_inbounds};
use super::routing::RoutingCfg;
use super::{
    StateLoadError, load_state, save_state, skip_blank_str, skip_empty_str, skip_empty_vec,
    skip_false, skip_true, skip_zero_u32,
};
use crate::i18n::{Key, t};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Network mode switch. Serializes camelCase: "off" | "tun".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Mode {
    #[default]
    Off,
    Tun,
}

/// The latency probe's outbound path. `BindNic` binds the TUN screen's
/// outbound interface (the same selection and resolver the tunnel uses), so
/// the probe's dials bypass the capture; `Native` follows the OS stack, so the
/// tunnel captures them and the probe measures through it. This is the OS
/// stack, not Xray's direct route.
///
/// Serializes camelCase ("bindNic" | "native"). The retired
/// `latencyTestBindInterface` boolean also loads here (true → BindNic,
/// false → Native), so an older settings.json keeps its effective behavior.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProbePath {
    #[default]
    BindNic,
    Native,
}

impl<'de> Deserialize<'de> for ProbePath {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ProbePathVisitor;

        impl serde::de::Visitor<'_> for ProbePathVisitor {
            type Value = ProbePath;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("\"bindNic\", \"native\", or a legacy boolean")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                match value {
                    "bindNic" => Ok(ProbePath::BindNic),
                    "native" => Ok(ProbePath::Native),
                    other => Err(E::unknown_variant(other, &["bindNic", "native"])),
                }
            }

            // The retired `latencyTestBindInterface` boolean: true bound the
            // physical uplink, which is Bind NIC here.
            fn visit_bool<E: serde::de::Error>(self, bind: bool) -> Result<Self::Value, E> {
                Ok(if bind {
                    ProbePath::BindNic
                } else {
                    ProbePath::Native
                })
            }
        }

        deserializer.deserialize_any(ProbePathVisitor)
    }
}

/// A subscription refresh's outbound path. `BindNic` and `Native` mean what
/// they mean for the probe; `Socks5` dials through the configured SOCKS5
/// proxy and adds no bind of its own, so the user's routing owns the
/// connection to that proxy.
///
/// Serializes camelCase ("bindNic" | "native" | "socks5"). The retired
/// `subscriptionDirectFetch` boolean also loads here (true → BindNic,
/// false → Native).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RefreshPath {
    #[default]
    BindNic,
    Native,
    Socks5,
}

impl<'de> Deserialize<'de> for RefreshPath {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RefreshPathVisitor;

        impl serde::de::Visitor<'_> for RefreshPathVisitor {
            type Value = RefreshPath;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("\"bindNic\", \"native\", \"socks5\", or a legacy boolean")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                match value {
                    "bindNic" => Ok(RefreshPath::BindNic),
                    "native" => Ok(RefreshPath::Native),
                    "socks5" => Ok(RefreshPath::Socks5),
                    other => Err(E::unknown_variant(other, &["bindNic", "native", "socks5"])),
                }
            }

            // The retired `subscriptionDirectFetch` boolean: true bound the
            // physical uplink, which is Bind NIC here. SOCKS5 did not exist.
            fn visit_bool<E: serde::de::Error>(self, bind: bool) -> Result<Self::Value, E> {
                Ok(if bind {
                    RefreshPath::BindNic
                } else {
                    RefreshPath::Native
                })
            }
        }

        deserializer.deserialize_any(RefreshPathVisitor)
    }
}

/// The SOCKS5 carrier a subscription refresh can dial through. `port` 0 means
/// the field is unset; a blank host or a zero port fails the fetch loudly
/// rather than falling back to the OS stack. Credentials are optional and a
/// blank username is treated as absent.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Socks5Cfg {
    pub host: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// UI locale. Serializes camelCase ("en"). Unknown or absent tags resolve to
/// English (the fallback locale) so a foreign or hand-edited value in
/// settings.json can never corrupt the state file.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Language {
    #[default]
    En,
}

impl<'de> Deserialize<'de> for Language {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct LanguageVisitor;

        impl<'de> serde::de::Visitor<'de> for LanguageVisitor {
            type Value = Language;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a language tag (\"en\", \"zhHans\", …)")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(match value {
                    "en" => Language::En,
                    // English fallback: a future pack's tag (or a hand-edited
                    // file) must degrade to English, never fail to load.
                    _ => Language::En,
                })
            }

            // Graceful degradation for hand-edited non-string values: a null,
            // number, or bool `language` field must not fail `Settings`
            // deserialization (which would rename settings.json to
            // `.broken-<ts>` and discard every setting). Any such value
            // resolves to the English fallback locale.
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(Language::En)
            }

            fn visit_bool<E: serde::de::Error>(self, _v: bool) -> Result<Self::Value, E> {
                Ok(Language::En)
            }

            fn visit_i64<E: serde::de::Error>(self, _v: i64) -> Result<Self::Value, E> {
                Ok(Language::En)
            }

            fn visit_u64<E: serde::de::Error>(self, _v: u64) -> Result<Self::Value, E> {
                Ok(Language::En)
            }

            fn visit_f64<E: serde::de::Error>(self, _v: f64) -> Result<Self::Value, E> {
                Ok(Language::En)
            }
        }

        // `deserialize_any`, not `deserialize_str`: both serde_json
        // deserializers dispatch only string tokens to `visit_str`; null,
        // number, and bool tokens would otherwise be rejected outright
        // instead of degrading through the fallbacks above.
        deserializer.deserialize_any(LanguageVisitor)
    }
}

/// Dashboard traffic-unit ladder. Serializes camelCase:
/// "auto" | "bps" | "kiBps" | "miBps" | "giBps". Unknown wire values fail
/// the load like every state enum.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TrafficUnit {
    #[default]
    Auto,
    Bps,
    KiBps,
    MiBps,
    GiBps,
}

/// True is the default for app-owned opt-out switches, so an absent key keeps
/// the established behavior and a saved true stays out of the file.
fn default_true() -> bool {
    true
}

/// Skip the `trafficUnit` key when the dashboard uses the adaptive default.
fn skip_default_traffic_unit(unit: &TrafficUnit) -> bool {
    *unit == TrafficUnit::Auto
}

/// One `policy.levels["<userLevel>"]` entry (policy.go:7-18).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PolicyLevelCfg {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handshake: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conn_idle: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uplink_only: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub downlink_only: Option<u32>,
    /// KB; -1 = unlimited.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buffer_size: Option<i32>,
    #[serde(skip_serializing_if = "skip_false")]
    pub stats_user_uplink: bool,
    #[serde(skip_serializing_if = "skip_false")]
    pub stats_user_downlink: bool,
    #[serde(skip_serializing_if = "skip_false")]
    pub stats_user_online: bool,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl PolicyLevelCfg {
    pub fn is_empty(&self) -> bool {
        self.handshake.is_none()
            && self.conn_idle.is_none()
            && self.uplink_only.is_none()
            && self.downlink_only.is_none()
            && self.buffer_size.is_none()
            && !self.stats_user_uplink
            && !self.stats_user_downlink
            && !self.stats_user_online
            && self.extra.is_empty()
    }
}

/// GUI policy model. Keys are Xray user levels (for example `"0"` or `"1"`).
/// Root keys outside `levels` (unknown future fields or the old flat
/// level-0 spellings) deserialize into `extra` and round-trip losslessly.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PolicyCfg {
    pub levels: BTreeMap<String, PolicyLevelCfg>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl PolicyCfg {
    pub fn is_empty(&self) -> bool {
        self.levels.values().all(PolicyLevelCfg::is_empty) && self.extra.is_empty()
    }
}

fn default_version() -> u32 {
    1
}

/// Default geodata auto-update schedule (5-field cron, core's `geodata.cron`).
pub const DEFAULT_GEODATA_CRON: &str = "0 4 * * *";

/// Environment names that re-point the core's asset, configuration, and
/// certificate directories. Xray applies `settings.env` with `os.Setenv`
/// before it resolves assets, and checks the dotted `xray.location.*` keys
/// before the uppercase spellings, so both forms are refused in the settings
/// model and scrubbed from a launched core.
pub const CORE_LOCATION_ENV_NAMES: [&str; 8] = [
    "xray.location.asset",
    "xray.location.confdir",
    "xray.location.config",
    "xray.location.cert",
    "XRAY_LOCATION_ASSET",
    "XRAY_LOCATION_CONFDIR",
    "XRAY_LOCATION_CONFIG",
    "XRAY_LOCATION_CERT",
];

/// Geodata auto-update configuration (core-native `geodata` key).
/// All fields optional: empty = built-in dat files from the pinned core payload.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GeodataCfg {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geoip_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geosite_url: Option<String>,
    /// 5-field cron; None or empty = DEFAULT_GEODATA_CRON at emission.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cron: Option<String>,
}

impl GeodataCfg {
    /// True when at least one dat URL is configured. No URL → the generated
    /// config carries no `geodata` key and the bundled dats are used.
    pub fn is_configured(&self) -> bool {
        self.geoip_url.as_deref().is_some_and(|url| !url.is_empty())
            || self
                .geosite_url
                .as_deref()
                .is_some_and(|url| !url.is_empty())
    }
}

/// True when a geodata URL is unset (empty) or a valid HTTPS URL with a
/// host pass. Mirrors the core's `validateHTTPS` (`infra/conf/geodata.go`)
/// — broccoli validates shape only, the `-test` gate owns the full grammar.
pub fn geodata_url_valid(url: &str) -> bool {
    url.is_empty()
        || url::Url::parse(url)
            .is_ok_and(|parsed| parsed.scheme() == "https" && parsed.host_str().is_some())
}

/// Validate one geodata URL: empty (unconfigured) or a valid HTTPS URL with a
/// host pass; anything else is an error. Mirrors the core's `validateHTTPS`
/// (`infra/conf/geodata.go`) — broccoli validates shape only, the `-test` gate
/// owns the full grammar.
pub fn geodata_url_error(url: &str, lang: Language) -> Option<String> {
    (!geodata_url_valid(url)).then(|| t(lang, Key::GeodataUrlNotHttps).into())
}

/// True when a geodata cron is unset (empty → default at emission) or
/// exactly 5 whitespace-separated fields. The core's full cron grammar
/// (incl. `@descriptors`) is the `-test` gate's job — broccoli rejects only
/// the shape.
pub fn geodata_cron_valid(cron: &str) -> bool {
    cron.is_empty() || cron.split_whitespace().count() == 5
}

/// Validate the geodata cron: empty (unset → default at emission) or exactly
/// 5 whitespace-separated fields. The core's full cron grammar (incl.
/// `@descriptors`) is the `-test` gate's job — broccoli rejects only the shape.
pub fn geodata_cron_error(cron: &str, lang: Language) -> Option<String> {
    (!geodata_cron_valid(cron)).then(|| t(lang, Key::GeodataCronNotFiveFields).into())
}

/// `localInbounds` reads an absent key and a JSON `null` the same way: both
/// load the fresh-install seed list. Every other key of [`Settings`] keeps
/// its field default, and unknown keys land in `extra` and round-trip
/// losslessly.
fn deserialize_local_inbounds<'de, D>(deserializer: D) -> Result<Vec<LocalInboundCfg>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<Vec<LocalInboundCfg>>::deserialize(deserializer)?
        .unwrap_or_else(default_local_inbounds))
}

/// Read the Servers table's view sort, degrading any unknown or malformed
/// stored value to no sort. A hand-edited preference must never fail the
/// settings load — that would rename the file `.broken-<ts>` and discard every
/// other setting with it.
fn deserialize_view_sort<'de, D>(deserializer: D) -> Result<Option<ViewSort>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<Value>::deserialize(deserializer)?;
    Ok(raw.and_then(|value| serde_json::from_value(value).ok()))
}

/// The Servers table's column widths, in points, after the user dragged one
/// of its dividers. The name column is stored too: a drag freezes every width
/// it touches, and the adaptive fit is what the table returns to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ColumnWidths {
    pub order: f32,
    pub switch: f32,
    pub name: f32,
    pub protocol: f32,
    pub address: f32,
    pub latency: f32,
    pub group: f32,
}

/// A column the Servers table can order its rows by. The sort is a view
/// only: it never reorders the stored rows, and `Emitted` ignores it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SortColumn {
    Name,
    Protocol,
    Latency,
}

/// The Servers table's view sort: one column and its direction. It belongs
/// to the screen, survives a tab switch and a restart, and never reaches the
/// generated configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ViewSort {
    pub column: SortColumn,
    pub ascending: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    /// An absent key loads as 0 (unset) — the version records what the file
    /// itself carries, not the fresh-install default.
    #[serde(default)]
    pub version: u32,
    /// User-managed local endpoints: zero or more SOCKS/HTTP
    /// entries; serialized as `localInbounds`. An absent key — and the null a
    /// hand-edited file may carry — loads the fresh-install seed list.
    #[serde(
        default = "default_local_inbounds",
        deserialize_with = "deserialize_local_inbounds"
    )]
    pub local_inbounds: Vec<LocalInboundCfg>,
    /// GUI-owned tag-allocator high-water marks: one per
    /// protocol, bumped on every allocation, never decremented, so a tag
    /// number is never reissued after its entry is removed.
    #[serde(skip_serializing_if = "skip_zero_u32")]
    pub socks_tag_seq: u32,
    #[serde(skip_serializing_if = "skip_zero_u32")]
    pub http_tag_seq: u32,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub dokodemo: Vec<DokodemoCfg>,
    pub routing: RoutingCfg,
    pub dns: DnsCfg,
    pub tun: TunCfg,
    pub mode: Mode,
    /// An absent key loads as the empty level — the value the generator emits
    /// as `loglevel` — never as the fresh-install `warning`.
    #[serde(default, skip_serializing_if = "skip_empty_str")]
    pub log_level: String,
    /// xray per-connection access log lines ("from … accepted …"); on =
    /// the generator omits `access` (xray defaults that to console), off =
    /// it emits `"access": "none"`. Kept separate from `log_level`,
    /// which only gates xray's error-log channel.
    #[serde(skip_serializing_if = "skip_false")]
    pub access_log: bool,
    /// Broccoli-owned: whether the elevated helper points the outbound
    /// adapter's DNS at the tunnel while TUN runs. Off keeps Xray's native TUN
    /// DNS — the TUN adapter still points at the gateway — and leaves every
    /// other adapter's DNS alone. Never emitted into the Xray config. Unlike
    /// the core fields, the app-owned true default is omitted: absence means
    /// on, and only the off override is persisted.
    #[serde(default = "default_true", skip_serializing_if = "skip_true")]
    pub dns_takeover: bool,
    /// UI locale; English is the fallback and the only pack that ships today.
    pub language: Language,
    /// Dashboard traffic-unit ladder: Auto scales adaptively, the
    /// fixed units pin one IEC step. Skipped when Auto.
    #[serde(skip_serializing_if = "skip_default_traffic_unit")]
    pub traffic_unit: TrafficUnit,
    /// Custom UI accent as packed u32 RGBA (r<<24 | g<<16 | b<<8 | a).
    /// `None` = stock egui accent. Lives in broccoli settings because eframe does
    /// not persist custom `Visuals` (`Options::dark_style`/`light_style` are
    /// `serde(skip)`); it is re-applied at startup and on picker change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accent_color: Option<u32>,
    /// Masks a profile's server information — its address, port, and a
    /// WireGuard peer endpoint — behind the servers editor's reveal control.
    /// A display preference: the value never reaches the generated
    /// configuration, so an edit neither regenerates the candidate nor
    /// raises the Apply gate.
    #[serde(skip_serializing_if = "skip_false")]
    pub hide_server_info: bool,
    /// The Servers table's column widths after a divider drag; absent fits
    /// each column to its content and header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_table_columns: Option<ColumnWidths>,
    /// The Servers table's view sort, the column and the direction. Absent
    /// keeps each tab's stored order; an unknown or malformed stored value
    /// loads as absent instead of failing the settings load.
    #[serde(
        default,
        deserialize_with = "deserialize_view_sort",
        skip_serializing_if = "Option::is_none"
    )]
    pub server_table_sort: Option<ViewSort>,
    pub policy: PolicyCfg,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub env: Vec<(String, String)>,
    /// Core-native `geodata` auto-update block; always serialized
    /// (like `dns`/`tun`), empty = built-in dats from the pinned core payload.
    pub geodata: GeodataCfg,
    /// Custom probe URL for the on-demand ping test ("Test latency" toolbar
    /// button and per-row ⚡): the isolated one-shot probe fetches this URL.
    /// Empty falls back to the observatory probe URL, then the built-in
    /// default (https://www.google.com/generate_204).
    #[serde(skip_serializing_if = "skip_blank_str")]
    pub probe_url: String,
    /// The global User-Agent subscription fetches send; a group without a
    /// custom one uses it verbatim, and an empty value omits the header. It is
    /// written even when empty: the default belongs to a setting the file
    /// never had, not to one the user cleared.
    pub subscription_user_agent: String,
    /// The global outbound path subscription fetches take. Always written:
    /// the new form replaced the retired `subscriptionDirectFetch` boolean,
    /// which still loads here (true → Bind NIC, false → Native).
    #[serde(default, alias = "subscriptionDirectFetch")]
    pub subscription_path: RefreshPath,
    /// The global SOCKS5 fields a `Socks5` refresh path dials through; a
    /// group's override replaces them together with the path.
    pub subscription_socks5: Socks5Cfg,
    /// The latency test's outbound path. Always written: the new form replaced
    /// the retired `latencyTestBindInterface` boolean, which still loads here
    /// (true → Bind NIC, false → Native).
    #[serde(default, alias = "latencyTestBindInterface")]
    pub latency_test_path: ProbePath,
    /// when Some, the generator returns the parsed text VERBATIM
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_override: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            version: default_version(),
            local_inbounds: default_local_inbounds(),
            socks_tag_seq: 0,
            http_tag_seq: 0,
            dokodemo: Vec::new(),
            routing: RoutingCfg::default(),
            dns: DnsCfg::default(),
            tun: TunCfg::default(),
            mode: Mode::default(),
            log_level: "warning".into(),
            access_log: false,
            dns_takeover: true,
            language: Language::default(),
            traffic_unit: TrafficUnit::default(),
            accent_color: None,
            hide_server_info: false,
            server_table_columns: None,
            server_table_sort: None,
            policy: PolicyCfg::default(),
            env: Vec::new(),
            geodata: GeodataCfg::default(),
            probe_url: String::new(),
            subscription_user_agent: default_subscription_user_agent(),
            subscription_path: RefreshPath::BindNic,
            subscription_socks5: Socks5Cfg::default(),
            latency_test_path: ProbePath::BindNic,
            raw_override: None,
            extra: Map::new(),
        }
    }
}

/// The shipped User-Agent: the app name and version, so a provider can tell
/// the client apart without a per-subscription setting.
pub fn default_subscription_user_agent() -> String {
    format!("broccoli/{}", env!("CARGO_PKG_VERSION"))
}

impl Settings {
    /// Load settings.json. Missing or structurally corrupt files fall back to
    /// `Default` (the corrupt file is quarantined); a
    /// semantically invalid file (valid JSON, bad content) returns an error
    /// naming the offending field and is left intact for the user to fix.
    pub fn load() -> Result<Self, StateLoadError> {
        load_state("settings.json")
    }
    pub fn save(&self) -> anyhow::Result<()> {
        save_state("settings.json", self)
    }

    /// Set the network mode. The mode is the single persisted TUN switch —
    /// every other site derives TUN state from `mode == Mode::Tun`. Returns
    /// whether the mode actually changed.
    pub fn set_mode(&mut self, mode: Mode) -> bool {
        let previous = self.mode;
        self.mode = mode;
        previous != mode
    }

    /// Probe URL for the on-demand ping test ("Test latency" toolbar button
    /// and per-row ⚡): the isolated one-shot probe fetches this URL. Empty
    /// or whitespace-only falls back to the observatory probe URL; the
    /// generator substitutes the built-in default
    /// (https://www.google.com/generate_204) when both are empty.
    pub fn ping_test_probe_url(&self) -> &str {
        if self.probe_url.trim().is_empty() {
            &self.routing.observatory.probe_url
        } else {
            &self.probe_url
        }
    }

    /// Rewrite every exact outbound-tag reference named in `renames`
    /// (old tag → new tag): routing rule targets, balancer selectors and
    /// fallback tags, and both observatory subject selectors. Prefixes the
    /// user wrote are left alone — only a stored spelling that names the old
    /// tag is rewritten. Returns whether anything changed.
    pub fn rewrite_outbound_tags(&mut self, renames: &[(String, String)]) -> bool {
        if renames.is_empty() {
            return false;
        }
        let mut changed = false;
        let mut rewrite = |value: &mut String| {
            if let Some((_, new)) = renames.iter().find(|(old, _)| old == value) {
                *value = new.clone();
                changed = true;
            }
        };
        for rule in &mut self.routing.rules {
            rewrite(&mut rule.outbound_tag);
        }
        for balancer in &mut self.routing.balancers {
            rewrite_selector(&mut balancer.selector, renames);
            rewrite(&mut balancer.fallback_tag);
        }
        rewrite_selector(&mut self.routing.observatory.subject_selector, renames);
        rewrite_selector(
            &mut self.routing.burst_observatory.subject_selector,
            renames,
        );
        changed
    }
}

/// Rewrite one selector list: an exact old tag becomes its new tag, and a
/// legacy `srv-` prefix expands into every new tag whose old tag it prefixed
/// (a prefix over ids has no equivalent prefix over `[Group] Name` tags).
fn rewrite_selector(selector: &mut Vec<String>, renames: &[(String, String)]) {
    let mut rewritten = Vec::with_capacity(selector.len());
    for pattern in selector.drain(..) {
        if let Some((_, new)) = renames.iter().find(|(old, _)| *old == pattern) {
            rewritten.push(new.clone());
            continue;
        }
        if pattern.starts_with("srv-") {
            let mut expanded: Vec<String> = renames
                .iter()
                .filter(|(old, _)| old.starts_with(&pattern) && old != "srv-")
                .map(|(_, new)| new.clone())
                .collect();
            if expanded.is_empty() {
                rewritten.push(pattern);
            } else {
                rewritten.append(&mut expanded);
            }
            continue;
        }
        rewritten.push(pattern);
    }
    *selector = rewritten;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::appdata::with_appdata;
    use serde_json::json;

    #[test]
    fn legacy_prefix_selectors_expand_to_the_new_tags() {
        let mut settings = Settings::default();
        settings.routing.balancers.push(crate::model::Balancer {
            tag: "bal".into(),
            selector: vec!["srv-ab".into(), "srv-".into()],
            ..Default::default()
        });
        let renames = vec![
            ("srv-abaaaaaa".to_owned(), "[Manual] A".to_owned()),
            ("srv-abbbbbbb".to_owned(), "[Manual] B".to_owned()),
            ("srv-c".to_owned(), "[Manual] C".to_owned()),
            ("srv-".to_owned(), "[".to_owned()),
        ];
        settings.rewrite_outbound_tags(&renames);
        assert_eq!(
            settings.routing.balancers[0].selector,
            ["[Manual] A", "[Manual] B", "["]
        );
    }

    #[test]
    fn legacy_persisted_api_port_is_ignored_not_an_error() {
        // The control-plane port is ephemeral per launch and the
        // user-editable `apiPort` setting is gone. A settings.json written by
        // an older build still carries the key; it must load without error and
        // the stale value must never resurface as the active API port.
        let settings: Settings = serde_json::from_value(json!({
            "version": 1,
            "socks": {},
            "http": {},
            "routing": {},
            "dns": {},
            "tun": {},
            "mode": "off",
            "apiPort": 10853,
            "policy": {},
            "geodata": {}
        }))
        .unwrap();
        // `Settings` has no api_port field anymore, so nothing can read the
        // stale value; the unknown key is preserved losslessly in `extra` like
        // any future key (lossless round-trip contract).
        assert_eq!(settings.extra["apiPort"], json!(10853));
    }

    #[test]
    fn default_settings_never_serialize_an_api_port() {
        let value = serde_json::to_value(Settings::default()).unwrap();
        assert!(
            value.get("apiPort").is_none(),
            "Settings must not carry an apiPort key: {value}"
        );
    }

    #[test]
    fn unknown_policy_root_keys_round_trip_losslessly_in_extra() {
        // Root keys outside `levels` — unknown future fields or the old flat
        // level-0 spellings — must never be promoted into a level: they land
        // in `extra` and round-trip losslessly (flatten-extra contract).
        let policy: PolicyCfg = serde_json::from_value(json!({
            "futureRoot": true,
            "futureBlock": { "nested": [1, 2, 3] }
        }))
        .unwrap();

        assert!(
            policy.levels.is_empty(),
            "unknown root keys must not be relocated into levels"
        );
        assert_eq!(policy.extra["futureRoot"], json!(true));
        assert_eq!(policy.extra["futureBlock"], json!({ "nested": [1, 2, 3] }));

        let flat: PolicyCfg = serde_json::from_value(json!({
            "handshake": 9,
            "statsUserOnline": true
        }))
        .unwrap();
        assert!(
            flat.levels.is_empty(),
            "flat level-0 keys must not be relocated into levels"
        );
        assert_eq!(flat.extra["handshake"], json!(9));
        assert_eq!(flat.extra["statsUserOnline"], json!(true));

        // Serializing must reproduce the exact original shapes — no
        // synthesized `levels["0"]` entry.
        let value = serde_json::to_value(&policy).unwrap();
        assert_eq!(value["levels"], json!({}));
        assert_eq!(value["futureRoot"], json!(true));
        assert_eq!(value["futureBlock"], json!({ "nested": [1, 2, 3] }));
        assert!(
            value.get("levels").and_then(|l| l.get("0")).is_none(),
            "no levels['0'] entry may be synthesized"
        );
    }

    #[test]
    fn policy_levels_round_trip_without_losing_root_extensions() {
        let mut policy = PolicyCfg::default();
        policy.levels.insert(
            "3".into(),
            PolicyLevelCfg {
                stats_user_uplink: true,
                ..Default::default()
            },
        );
        policy.extra.insert("futureRoot".into(), json!(true));

        let value = serde_json::to_value(&policy).unwrap();
        let restored: PolicyCfg = serde_json::from_value(value).unwrap();
        assert!(restored.levels["3"].stats_user_uplink);
        assert_eq!(restored.extra["futureRoot"], json!(true));
    }

    #[test]
    fn the_view_sort_round_trips_and_a_malformed_value_loads_as_no_sort() {
        let mut settings = Settings::default();
        assert_eq!(settings.server_table_sort, None);
        settings.server_table_sort = Some(ViewSort {
            column: SortColumn::Latency,
            ascending: false,
        });
        let value = serde_json::to_value(&settings).unwrap();
        assert_eq!(
            value["serverTableSort"],
            json!({ "column": "latency", "ascending": false })
        );
        let restored: Settings = serde_json::from_value(value).unwrap();
        assert_eq!(restored.server_table_sort, settings.server_table_sort);

        // An unknown column, a missing direction, a wrong shape, and null
        // each degrade to no sort instead of failing the load.
        for raw in [
            json!({ "column": "address", "ascending": true }),
            json!({ "column": "name" }),
            json!({ "ascending": true }),
            json!("name"),
            json!(7),
            json!([]),
            json!(null),
        ] {
            let loaded: Settings =
                serde_json::from_value(json!({ "serverTableSort": raw, "mode": "tun" })).unwrap();
            assert_eq!(loaded.server_table_sort, None, "{raw} must load as no sort");
            assert_eq!(loaded.mode, Mode::Tun, "{raw} must not lose the rest");
        }
    }

    #[test]
    fn language_and_accent_round_trip_through_the_settings_json_path() {
        let mut settings = Settings::default();
        assert_eq!(settings.language, Language::En);
        assert_eq!(settings.accent_color, None);

        settings.accent_color = Some(0x4f_af_4f_ff);
        let value = serde_json::to_value(&settings).unwrap();
        assert_eq!(value["language"], json!("en"));
        assert_eq!(value["accentColor"], json!(0x4f_af_4f_ff));

        let restored: Settings = serde_json::from_value(value).unwrap();
        assert_eq!(restored.language, Language::En);
        assert_eq!(restored.accent_color, Some(0x4f_af_4f_ff));
    }

    #[test]
    fn absent_or_unknown_language_field_resolves_to_english() {
        let absent: Settings = serde_json::from_value(json!({})).unwrap();
        assert_eq!(absent.language, Language::En);
        assert_eq!(absent.accent_color, None);
        let unknown: Settings = serde_json::from_value(json!({ "language": "fr" })).unwrap();
        assert_eq!(unknown.language, Language::En);
    }

    #[test]
    fn non_string_language_values_degrade_to_english_without_losing_settings() {
        // A hand-edited `language` of null, number, or bool must deserialize
        // to the English fallback — never fail `Settings` deserialization
        // (which would rename settings.json to `.broken-<ts>` and discard
        // every other setting).
        for raw in [json!(null), json!(3), json!(true), json!(3.5)] {
            let restored: Settings = serde_json::from_value(json!({
                "language": raw,
                "mode": "tun",
                "proxyBypass": "custom.example;<local>",
                "accentColor": 0x4f_af_4f_ff,
            }))
            .unwrap();
            assert_eq!(
                restored.language,
                Language::En,
                "language {raw} must degrade to En"
            );
            assert_eq!(
                restored.mode,
                Mode::Tun,
                "mode must survive a non-string language"
            );
            assert_eq!(restored.accent_color, Some(0x4f_af_4f_ff));
        }

        // The real load path (`load_state` → `serde_json::from_slice`) must
        // degrade the same way.
        let bytes = br#"{"language": null, "mode": "tun"}"#;
        let parsed: Settings = serde_json::from_slice(bytes).unwrap();
        assert_eq!(parsed.language, Language::En);
        assert_eq!(parsed.mode, Mode::Tun);
    }

    #[test]
    fn traffic_unit_defaults_to_auto() {
        let settings = Settings::default();
        assert_eq!(settings.traffic_unit, TrafficUnit::Auto);
    }

    #[test]
    fn traffic_unit_round_trips_through_the_settings_json_path() {
        let settings = Settings {
            traffic_unit: TrafficUnit::MiBps,
            ..Default::default()
        };

        let value = serde_json::to_value(&settings).unwrap();
        assert_eq!(value["trafficUnit"], json!("miBps"));

        let restored: Settings = serde_json::from_value(value).unwrap();
        assert_eq!(restored.traffic_unit, TrafficUnit::MiBps);
    }

    #[test]
    fn auto_traffic_unit_omits_the_key_when_serializing() {
        let value = serde_json::to_value(Settings::default()).unwrap();
        assert!(
            value.get("trafficUnit").is_none(),
            "Settings must not carry a trafficUnit key: {value}"
        );
    }

    #[test]
    fn absent_traffic_unit_field_resolves_to_auto() {
        // An older settings.json has no `trafficUnit` key;
        // it must load as the adaptive Auto default.
        let absent: Settings = serde_json::from_value(json!({})).unwrap();
        assert_eq!(absent.traffic_unit, TrafficUnit::Auto);
    }

    #[test]
    fn unknown_traffic_unit_value_in_settings_errors_with_file_intact() {
        // An unknown enum value must fail the load naming the
        // field and the value, leaving the file intact for the user to fix
        // (mirrors the `mode` strict-load test in model/tests.rs).
        // Redirect %APPDATA% to a scratch dir so the user's real
        // settings.json is never touched.
        with_appdata(|| {
            crate::sys::paths::ensure_dirs().expect("create dirs");
            let path = crate::model::state_file("settings.json");
            // Valid JSON, but a typo'd unit. Any serde data error on valid JSON
            // must fail the load without touching the file.
            let bad = br#"{"trafficUnit":"kibps"}"#;
            std::fs::write(&path, bad).expect("write settings with unknown traffic unit");
            let original = std::fs::read(&path).expect("read back settings");

            let error = load_state::<Settings>("settings.json")
                .expect_err("unknown traffic unit value must fail the load");
            let message = format!("{error}");
            assert!(
                message.contains("trafficUnit"),
                "names the field: {message}"
            );
            assert!(message.contains("kibps"), "names the value: {message}");

            assert_eq!(
                std::fs::read(&path).expect("read back settings"),
                original,
                "settings.json must not be touched by a semantic failure"
            );
        });
    }

    #[test]
    fn geodata_defaults_to_unconfigured_and_round_trips_as_empty_object() {
        let settings = Settings::default();
        assert!(!settings.geodata.is_configured());

        let value = serde_json::to_value(&settings).unwrap();
        assert_eq!(value["geodata"], json!({}));

        let restored: Settings = serde_json::from_value(value).unwrap();
        assert!(!restored.geodata.is_configured());
        let absent: Settings = serde_json::from_value(json!({})).unwrap();
        assert!(!absent.geodata.is_configured());
    }

    #[test]
    fn geodata_is_configured_when_either_url_is_nonempty() {
        let mut settings = Settings::default();
        assert!(!settings.geodata.is_configured());
        settings.geodata.geoip_url = Some("https://example.com/geoip.dat".into());
        assert!(settings.geodata.is_configured());
        settings.geodata.geoip_url = None;
        assert!(!settings.geodata.is_configured());
        settings.geodata.geosite_url = Some("https://example.com/geosite.dat".into());
        assert!(settings.geodata.is_configured());
    }

    #[test]
    fn geodata_url_validation_accepts_https_with_host_and_rejects_the_rest() {
        let lang = Language::En;
        for url in ["", "https://example.com/geoip.dat", "https://example.com"] {
            assert_eq!(geodata_url_error(url, lang), None, "{url:?} must pass");
        }
        for url in [
            "http://example.com/geoip.dat",
            "ftp://example.com/geoip.dat",
            "https://",
            "not a url",
            "example.com/geoip.dat",
        ] {
            assert!(geodata_url_error(url, lang).is_some(), "{url:?} must fail");
        }
    }

    #[test]
    fn geodata_cron_validation_accepts_empty_and_five_fields_only() {
        let lang = Language::En;
        for cron in ["", "0 4 * * *", "17 3 * * 1", "*/15 * * * *"] {
            assert_eq!(geodata_cron_error(cron, lang), None, "{cron:?} must pass");
        }
        for cron in ["0 4 *", "0 4 * * * *", "1 2 3 4 5 6 7", "   "] {
            assert!(
                geodata_cron_error(cron, lang).is_some(),
                "{cron:?} must fail"
            );
        }
    }

    #[test]
    fn unchecked_local_inbounds_survive_settings_save_load_round_trip() {
        // Redirect %APPDATA% to a scratch dir so the user's real
        // settings.json is never touched.
        with_appdata(|| {
            // User unchecks both seed endpoints in the UI (ui/inbounds.rs)…
            let mut settings = Settings::default();
            settings.local_inbounds[0].enabled = false;
            settings.local_inbounds[1].enabled = false;
            // …plus the per-endpoint sniffing toggle (a default-true bool that
            // must persist its off state across the save/load seam).
            settings.local_inbounds[0].sniffing.enabled = false;
            settings.local_inbounds[1].sniffing.enabled = false;

            // …then the app saves settings.json (Settings::save) and reloads it
            // on next launch (Settings::load) — the exact persistence seam.
            settings.save().expect("save settings.json");
            let restored = Settings::load().expect("reload settings.json");

            assert_eq!(
                restored.local_inbounds.len(),
                2,
                "seed list keeps both entries"
            );
            assert!(
                !restored.local_inbounds[0].enabled,
                "SOCKS endpoint unchecked state did not survive save/load: \
                 localInbounds[0].enabled == {} after round-trip (expected false)",
                restored.local_inbounds[0].enabled
            );
            assert!(
                !restored.local_inbounds[1].enabled,
                "HTTP endpoint unchecked state did not survive save/load: \
                 localInbounds[1].enabled == {} after round-trip (expected false)",
                restored.local_inbounds[1].enabled
            );
            assert!(
                !restored.local_inbounds[0].sniffing.enabled,
                "SOCKS sniffing unchecked state did not survive save/load: \
                 localInbounds[0].sniffing.enabled == {} after round-trip (expected false)",
                restored.local_inbounds[0].sniffing.enabled
            );
            assert!(
                !restored.local_inbounds[1].sniffing.enabled,
                "HTTP sniffing unchecked state did not survive save/load: \
                 localInbounds[1].sniffing.enabled == {} after round-trip (expected false)",
                restored.local_inbounds[1].sniffing.enabled
            );
        });
    }

    #[test]
    fn null_local_inbounds_loads_the_seed_list_like_an_absent_key() {
        // A hand-edited `null` is the absent-key reading — the fresh-install
        // seed list — never an error and never an empty list.
        let seed = serde_json::to_value(default_local_inbounds()).unwrap();
        let null: Settings = serde_json::from_value(json!({"localInbounds": null})).unwrap();
        assert_eq!(
            serde_json::to_value(&null.local_inbounds).unwrap(),
            seed,
            "a null localInbounds must load the seed list"
        );
        // A present list wins, the empty one included: clearing every endpoint
        // in the UI must not resurrect the seed entries on the next launch.
        let empty: Settings = serde_json::from_value(json!({"localInbounds": []})).unwrap();
        assert!(
            empty.local_inbounds.is_empty(),
            "an empty localInbounds list must stay empty"
        );
    }

    /// Clearing the global User-Agent means "send none", so the empty string
    /// must survive the file: the default is a property of an absent setting,
    /// not of one the user emptied.
    #[test]
    fn an_empty_global_user_agent_survives_the_settings_json_path() {
        let settings = Settings {
            subscription_user_agent: String::new(),
            ..Default::default()
        };
        let wire = serde_json::to_value(&settings).expect("settings serialize");
        assert_eq!(wire["subscriptionUserAgent"], "");
        let loaded: Settings = serde_json::from_value(wire).expect("settings load");
        assert_eq!(loaded.subscription_user_agent, "");

        // A file that never carried the field still gets the client default.
        let absent: Settings = serde_json::from_value(json!({})).expect("settings load");
        assert_eq!(
            absent.subscription_user_agent,
            default_subscription_user_agent()
        );
    }

    #[test]
    fn probe_url_round_trips_through_the_settings_json_path() {
        let settings = Settings {
            probe_url: "https://example.com/generate_204".into(),
            ..Default::default()
        };

        let value = serde_json::to_value(&settings).unwrap();
        assert_eq!(value["probeUrl"], json!("https://example.com/generate_204"));

        let restored: Settings = serde_json::from_value(value).unwrap();
        assert_eq!(restored.probe_url, "https://example.com/generate_204");
    }

    #[test]
    fn empty_probe_url_omits_the_key_when_serializing() {
        let value = serde_json::to_value(Settings::default()).unwrap();
        assert!(
            value.get("probeUrl").is_none(),
            "Settings must not carry an empty probeUrl key: {value}"
        );
    }

    #[test]
    fn whitespace_only_probe_url_omits_the_key_when_serializing() {
        let value = serde_json::to_value(Settings {
            probe_url: "   ".into(),
            ..Default::default()
        })
        .unwrap();
        assert!(
            value.get("probeUrl").is_none(),
            "a blank probeUrl must not be persisted: {value}"
        );
    }

    #[test]
    fn probe_url_folds_from_raw_and_defaults_to_empty() {
        let with_url: Settings = serde_json::from_value(json!({
            "probeUrl": "https://example.com/generate_204",
            "routing": {}
        }))
        .unwrap();
        assert_eq!(with_url.probe_url, "https://example.com/generate_204");

        let absent: Settings = serde_json::from_value(json!({})).unwrap();
        assert_eq!(absent.probe_url, "");
    }

    #[test]
    fn default_settings_have_no_ping_test_probe_url() {
        assert_eq!(Settings::default().probe_url, "");
    }

    #[test]
    fn ping_test_probe_url_prefers_own_value() {
        let mut settings = Settings {
            probe_url: "https://example.com/generate_204".into(),
            ..Default::default()
        };
        settings.routing.observatory.probe_url = "https://observatory.example/generate_204".into();
        assert_eq!(
            settings.ping_test_probe_url(),
            "https://example.com/generate_204"
        );
    }

    #[test]
    fn ping_test_probe_url_treats_whitespace_as_empty() {
        let mut settings = Settings {
            probe_url: "   ".into(),
            ..Default::default()
        };
        settings.routing.observatory.probe_url = "https://observatory.example/generate_204".into();
        assert_eq!(
            settings.ping_test_probe_url(),
            "https://observatory.example/generate_204"
        );
    }

    #[test]
    fn ping_test_probe_url_falls_back_to_the_observatory_probe_url() {
        let mut settings = Settings::default();
        settings.routing.observatory.probe_url = "https://observatory.example/generate_204".into();
        assert_eq!(
            settings.ping_test_probe_url(),
            "https://observatory.example/generate_204"
        );
    }

    #[test]
    fn dns_takeover_defaults_on_and_off_round_trips() {
        let default = Settings::default();
        assert!(default.dns_takeover, "the established behavior is on");
        let wire = serde_json::to_value(&default).expect("settings serialize");
        assert!(
            wire.get("dnsTakeover").is_none(),
            "the default stays out of the file"
        );

        let off = Settings {
            dns_takeover: false,
            ..default
        };
        let wire = serde_json::to_value(&off).expect("settings serialize");
        assert_eq!(wire["dnsTakeover"], false);
        let loaded: Settings = serde_json::from_value(wire).expect("settings load");
        assert!(!loaded.dns_takeover);
    }

    #[test]
    fn ping_test_probe_url_returns_empty_when_nothing_is_configured() {
        let mut settings = Settings::default();
        settings.probe_url.clear();
        settings.routing.observatory.probe_url.clear();
        assert_eq!(settings.ping_test_probe_url(), "");
    }

    #[test]
    fn both_outbound_paths_default_to_bind_nic() {
        let settings = Settings::default();
        assert_eq!(settings.latency_test_path, ProbePath::BindNic);
        assert_eq!(settings.subscription_path, RefreshPath::BindNic);
        assert_eq!(settings.subscription_socks5, Socks5Cfg::default());

        let absent: Settings = serde_json::from_value(json!({ "mode": "off" })).expect("settings");
        assert_eq!(absent.latency_test_path, ProbePath::BindNic);
        assert_eq!(absent.subscription_path, RefreshPath::BindNic);
    }

    #[test]
    fn retired_latency_bind_boolean_loads_as_the_probe_path() {
        for (legacy, expected) in [(true, ProbePath::BindNic), (false, ProbePath::Native)] {
            let settings: Settings = serde_json::from_value(json!({
                "latencyTestBindInterface": legacy,
            }))
            .expect("the retired boolean must still load");
            assert_eq!(settings.latency_test_path, expected);
            assert!(
                settings.extra.is_empty(),
                "the retired key is consumed, not preserved in extra"
            );

            // Saving writes the new form and drops the retired key.
            let wire = serde_json::to_value(&settings).expect("settings serialize");
            assert_eq!(wire["latencyTestPath"], json!(expected));
            assert!(wire.get("latencyTestBindInterface").is_none());
        }
    }

    #[test]
    fn retired_subscription_direct_boolean_loads_as_the_refresh_path() {
        for (legacy, expected) in [(true, RefreshPath::BindNic), (false, RefreshPath::Native)] {
            let settings: Settings = serde_json::from_value(json!({
                "subscriptionDirectFetch": legacy,
            }))
            .expect("the retired boolean must still load");
            assert_eq!(settings.subscription_path, expected);
            assert!(
                settings.extra.is_empty(),
                "the retired key is consumed, not preserved in extra"
            );

            let wire = serde_json::to_value(&settings).expect("settings serialize");
            assert_eq!(wire["subscriptionPath"], json!(expected));
            assert!(wire.get("subscriptionDirectFetch").is_none());
        }
    }

    #[test]
    fn outbound_paths_round_trip_as_names() {
        let settings = Settings {
            latency_test_path: ProbePath::Native,
            subscription_path: RefreshPath::Socks5,
            ..Default::default()
        };
        let wire = serde_json::to_value(&settings).expect("settings serialize");
        assert_eq!(wire["latencyTestPath"], json!("native"));
        assert_eq!(wire["subscriptionPath"], json!("socks5"));

        let loaded: Settings = serde_json::from_value(wire).expect("settings load");
        assert_eq!(loaded.latency_test_path, ProbePath::Native);
        assert_eq!(loaded.subscription_path, RefreshPath::Socks5);
    }

    #[test]
    fn unknown_outbound_path_names_fail_the_load() {
        let probe = serde_json::from_value::<Settings>(json!({
            "latencyTestPath": "direct",
        }));
        let refresh = serde_json::from_value::<Settings>(json!({
            "subscriptionPath": "direct",
        }));
        assert!(probe.is_err(), "an unknown path must not load silently");
        assert!(refresh.is_err(), "an unknown path must not load silently");
    }

    #[test]
    fn socks5_settings_round_trip_and_omit_absent_credentials() {
        let settings = Settings {
            subscription_path: RefreshPath::Socks5,
            subscription_socks5: Socks5Cfg {
                host: "proxy.example".into(),
                port: 1080,
                username: Some("alice".into()),
                password: Some("s3cr3t".into()),
            },
            ..Default::default()
        };
        let wire = serde_json::to_value(&settings).expect("settings serialize");
        assert_eq!(
            wire["subscriptionSocks5"],
            json!({
                "host": "proxy.example",
                "port": 1080,
                "username": "alice",
                "password": "s3cr3t",
            })
        );
        let loaded: Settings = serde_json::from_value(wire).expect("settings load");
        assert_eq!(loaded.subscription_socks5, settings.subscription_socks5);

        let wire = serde_json::to_value(Socks5Cfg::default()).expect("socks serialize");
        assert_eq!(wire, json!({ "host": "", "port": 0 }));
    }
}
