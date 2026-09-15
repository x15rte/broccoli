//! DNS + fakedns model (dns.go, fakedns.go).
//! `fakedns` is stored inside [`DnsCfg`] for GUI grouping but generates the
//! three coordinated pieces (top-level fakeDns + {"address":"fakedns"}
//! server + "fakedns" sniffing destOverride) in the generator.

use super::{skip_empty_map, skip_empty_str, skip_empty_vec, skip_false};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value, json};

pub fn default_timeout_ms() -> u64 {
    8000
}
fn skip_default_timeout(v: &u64) -> bool {
    *v == 8000
}
fn skip_default_query_strategy(s: &str) -> bool {
    s == DEFAULT_QUERY_STRATEGY
}

/// One entry of `dns.servers[]` (dns.go:20-34).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsServer {
    /// plain IP/domain | localhost | https:// | h2c:// | https+local:// |
    /// quic+local:// | tcp:// | tcp+local:// | fakedns
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub domains: Vec<String>,
    #[serde(skip_serializing_if = "skip_empty_vec", rename = "expectedIPs")]
    pub expected_ips: Vec<String>,
    #[serde(skip_serializing_if = "skip_empty_vec", rename = "unexpectedIPs")]
    pub unexpected_ips: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_fallback: Option<bool>,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub client_ip: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub query_strategy: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub tag: String,
    #[serde(skip_serializing_if = "skip_default_timeout")]
    pub timeout_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_cache: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serve_stale: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "serveExpiredTTL")]
    pub serve_expired_ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_query: Option<bool>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for DnsServer {
    fn default() -> Self {
        Self {
            address: String::new(),
            port: None,
            domains: Vec::new(),
            expected_ips: Vec::new(),
            unexpected_ips: Vec::new(),
            skip_fallback: None,
            client_ip: String::new(),
            query_strategy: String::new(),
            tag: String::new(),
            timeout_ms: default_timeout_ms(),
            disable_cache: None,
            serve_stale: None,
            serve_expired_ttl: None,
            final_query: None,
            extra: Map::new(),
        }
    }
}

impl<'de> Deserialize<'de> for DnsServer {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Default, Deserialize)]
        #[serde(rename_all = "camelCase", default)]
        struct Object {
            address: String,
            port: Option<u16>,
            domains: Vec<String>,
            #[serde(rename = "expectedIPs")]
            expected_ips: Option<Vec<String>>,
            #[serde(rename = "expectIPs")]
            legacy_expect_ips: Option<Vec<String>>,
            #[serde(rename = "unexpectedIPs")]
            unexpected_ips: Vec<String>,
            skip_fallback: Option<bool>,
            client_ip: String,
            query_strategy: String,
            tag: String,
            timeout_ms: Option<u64>,
            disable_cache: Option<bool>,
            serve_stale: Option<bool>,
            #[serde(rename = "serveExpiredTTL")]
            serve_expired_ttl: Option<u32>,
            final_query: Option<bool>,
            #[serde(flatten)]
            extra: Map<String, Value>,
        }

        /// One entry: the plain address shorthand or the configuration
        /// object. A hand-written visitor instead of
        /// `#[serde(untagged)] enum`: an untagged enum swallows the inner
        /// error, so a mistyped modeled field (`"timeoutMs": "abc"`) reports
        /// only "did not match any variant" and the caller cannot name the
        /// field the user must repair.
        struct Wire;

        impl<'de> serde::de::Visitor<'de> for Wire {
            type Value = DnsServer;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a DNS server address string or configuration object")
            }

            fn visit_str<E: serde::de::Error>(self, address: &str) -> Result<DnsServer, E> {
                Ok(DnsServer {
                    address: address.to_owned(),
                    ..DnsServer::default()
                })
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                map: A,
            ) -> Result<DnsServer, A::Error> {
                let wire = serde::de::value::MapAccessDeserializer::new(map);
                let object = Object::deserialize(wire)?;
                Ok(DnsServer {
                    address: object.address,
                    port: object.port,
                    domains: object.domains,
                    expected_ips: object
                        .expected_ips
                        .or(object.legacy_expect_ips)
                        .unwrap_or_default(),
                    unexpected_ips: object.unexpected_ips,
                    skip_fallback: object.skip_fallback,
                    client_ip: object.client_ip,
                    query_strategy: object.query_strategy,
                    tag: object.tag,
                    timeout_ms: object.timeout_ms.unwrap_or_else(default_timeout_ms),
                    disable_cache: object.disable_cache,
                    serve_stale: object.serve_stale,
                    serve_expired_ttl: object.serve_expired_ttl,
                    final_query: object.final_query,
                    extra: object.extra,
                })
            }
        }

        deserializer.deserialize_any(Wire)
    }
}

/// Fresh-install default fakeDNS pool (IPv4); also `FakeDnsPool::default`
/// and the DNS screen's hint for the first pool.
pub const DEFAULT_FAKEDNS_POOL_CIDR: &str = "198.18.0.0/15";
/// Fresh-install default fakeDNS pool size.
pub const DEFAULT_FAKEDNS_POOL_SIZE: i64 = 65_535;
/// Fresh-install second fakeDNS pool (IPv6) — also the pool the DNS screen
/// offers when adding a pool after the first (one canonical
/// definition drives the seed, the UI placeholder, and the Add-pool button).
pub const SECOND_FAKEDNS_POOL_CIDR: &str = "fc00::/18";
/// Fresh-install second fakeDNS pool size.
pub const SECOND_FAKEDNS_POOL_SIZE: i64 = 32_768;

/// Fresh-install default plaintext DNS resolver pair — the seeded
/// `dns.servers`, the TUN adapter's fallback adapter DNS, and the
/// generator's plaintext fallback share this one definition (changing it
/// once changes every site; agreement tests pin the linkage).
pub const DEFAULT_PLAINTEXT_RESOLVERS: [&str; 2] = ["1.1.1.1", "8.8.8.8"];

/// Fresh-install default DNS query strategy (`useip` — every query resolves
/// through the DNS module). One definition drives the model seed, the
/// wire-omission predicate, and the UI normalization, so a re-default
/// cannot silently change the wire shape.
pub const DEFAULT_QUERY_STRATEGY: &str = "useip";

/// Fresh-install default `serveExpiredTTL` (seconds): one day of stale
/// answers. One definition drives the model seed and the editor-cap guard —
/// a raised default must never become un-editable.
pub const DEFAULT_SERVE_EXPIRED_TTL: u32 = 86_400;

/// Editor ceiling for `serveExpiredTTL` (seconds): the DNS screen's range
/// cap. Guarded by test to stay >= [`DEFAULT_SERVE_EXPIRED_TTL`].
pub const MAX_SERVE_EXPIRED_TTL: u32 = 86_400;

/// One fakeDNS address pool (fakedns.go:13-16).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FakeDnsPool {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub ip_pool: String,
    pub pool_size: i64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for FakeDnsPool {
    fn default() -> Self {
        Self {
            ip_pool: DEFAULT_FAKEDNS_POOL_CIDR.into(),
            pool_size: DEFAULT_FAKEDNS_POOL_SIZE,
            extra: Map::new(),
        }
    }
}

/// GUI-only fakeDNS settings. `pools` emits an object for one pool and the
/// official array form for multiple IPv4/IPv6 pools.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FakeDnsCfg {
    #[serde(skip_serializing_if = "skip_false")]
    pub enabled: bool,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub pools: Vec<FakeDnsPool>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for FakeDnsCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            pools: vec![
                FakeDnsPool {
                    ip_pool: DEFAULT_FAKEDNS_POOL_CIDR.into(),
                    pool_size: DEFAULT_FAKEDNS_POOL_SIZE,
                    ..Default::default()
                },
                FakeDnsPool {
                    ip_pool: SECOND_FAKEDNS_POOL_CIDR.into(),
                    pool_size: SECOND_FAKEDNS_POOL_SIZE,
                    ..Default::default()
                },
            ],
            extra: Map::new(),
        }
    }
}

impl FakeDnsCfg {
    /// Top-level `fakeDns` wire form: a single pool collapses to an object,
    /// multiple pools emit the official array form, and an empty pool list
    /// falls back to the runnable default pool.
    pub fn to_wire(&self) -> Option<Value> {
        let mut pools: Vec<Value> = self
            .pools
            .iter()
            .map(|pool| {
                serde_json::to_value(pool).expect(
                    "model serialization is infallible: FakeDnsPool fields are a string, \
                     an i64, and a string-keyed Value map only",
                )
            })
            .collect();
        if pools.is_empty() {
            pools.push(serde_json::to_value(FakeDnsPool::default()).expect(
                "model serialization is infallible: FakeDnsPool fields are a string, \
                     an i64, and a string-keyed Value map only",
            ));
        }
        Some(if pools.len() == 1 {
            pools.pop().unwrap()
        } else {
            Value::Array(pools)
        })
    }
}

/// Top-level `dns` object (dns.go:161-172) + GUI-only fakedns group.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DnsCfg {
    /// Always serialized (storage): an explicit empty list must survive the
    /// load round-trip — with the seeded non-empty default, a missing key
    /// would resurrect 1.1.1.1 after the user cleared DNS. `to_wire` strips
    /// the empty list so the wire form stays clean.
    #[serde(default)]
    pub servers: Vec<DnsServer>,
    /// domain → IP string | array | another domain (HostAddress)
    #[serde(skip_serializing_if = "skip_empty_map")]
    pub hosts: Map<String, Value>,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub client_ip: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub tag: String,
    /// GUI-only proxy-server resolver override: an endpoint (same grammar
    /// as a `DnsServer` address — scheme://host[:port][/path] or bare
    /// host[:port]) that the generator uses for the scoped `+local`
    /// bootstrap server resolving proxy-server domains, instead of deriving
    /// it from the first configured server. Must be an IP literal or the
    /// literal "localhost" (the OS resolver) — a domain host would need the
    /// very resolution it provides. Stripped from the wire like `fakedns`;
    /// empty = auto-derive. Always serialized (storage): cleared must survive
    /// the round-trip against the seeded "localhost" default.
    #[serde(default)]
    pub bootstrap: String,
    /// useip | useip4 | useip6 | usesys
    #[serde(skip_serializing_if = "skip_default_query_strategy")]
    pub query_strategy: String,
    #[serde(skip_serializing_if = "skip_false")]
    pub disable_cache: bool,
    /// Always serialized (storage): off must survive the round-trip against
    /// the seeded true default; `to_wire` strips the false value.
    #[serde(default)]
    pub serve_stale: bool,
    /// Always serialized (storage): a cleared value (None → null) must
    /// survive the round-trip against the seeded `DEFAULT_SERVE_EXPIRED_TTL`
    /// default; `to_wire` strips the null value.
    #[serde(rename = "serveExpiredTTL")]
    pub serve_expired_ttl: Option<u32>,
    #[serde(skip_serializing_if = "skip_false")]
    pub disable_fallback: bool,
    #[serde(skip_serializing_if = "skip_false")]
    pub disable_fallback_if_match: bool,
    /// Always serialized (storage): off must survive the round-trip against
    /// the seeded true default; `to_wire` strips the false value.
    #[serde(default)]
    pub enable_parallel_query: bool,
    #[serde(skip_serializing_if = "skip_false")]
    pub use_system_hosts: bool,
    /// GUI-only group; stripped from the dns object by the generator.
    pub fakedns: FakeDnsCfg,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for DnsCfg {
    fn default() -> Self {
        Self {
            servers: DEFAULT_PLAINTEXT_RESOLVERS
                .iter()
                .map(|address| DnsServer {
                    address: (*address).into(),
                    ..Default::default()
                })
                .collect(),
            hosts: Map::new(),
            client_ip: String::new(),
            tag: String::new(),
            bootstrap: "localhost".into(),
            query_strategy: DEFAULT_QUERY_STRATEGY.into(),
            disable_cache: false,
            serve_stale: true,
            serve_expired_ttl: Some(DEFAULT_SERVE_EXPIRED_TTL),
            disable_fallback: false,
            disable_fallback_if_match: false,
            enable_parallel_query: true,
            use_system_hosts: false,
            fakedns: FakeDnsCfg::default(),
            extra: Map::new(),
        }
    }
}

impl DnsCfg {
    /// Wire form of the top-level `dns` object, or None when effectively
    /// empty. Strips the GUI-only `fakedns` group; fakeDns trio (2/3):
    /// appends {"address":"fakedns"} (deduped) when enabled.
    pub fn to_wire(&self, fakedns: bool) -> Option<Value> {
        let mut v = serde_json::to_value(self).expect(
            "model serialization is infallible: DnsCfg/DnsServer/FakeDnsCfg fields are \
             ints, bools, strings, and string-keyed Value maps only",
        );
        let obj = v.as_object_mut()?;
        obj.remove("fakedns");
        obj.remove("bootstrap");
        if fakedns {
            let has = obj
                .get("servers")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .any(|s| s.get("address").and_then(Value::as_str) == Some("fakedns"))
                })
                .unwrap_or(false);
            if !has {
                let servers = obj
                    .entry(String::from("servers"))
                    .or_insert_with(|| json!([]));
                if let Some(a) = servers.as_array_mut() {
                    a.push(json!({ "address": "fakedns" }));
                }
            }
        }
        // Storage-explicit fields stripped for the wire: an empty servers
        // list or a false parallel flag would otherwise make an effectively
        // empty config look configured (and an empty servers array is not
        // meaningful to the core). The fakedns append above runs first so a
        // fakedns-only config keeps its server entry.
        if obj
            .get("servers")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
        {
            obj.remove("servers");
        }
        if obj.get("enableParallelQuery") == Some(&Value::Bool(false)) {
            obj.remove("enableParallelQuery");
        }
        // serveStale/serveExpiredTTL only modify server behaviour: without a
        // servers list (cleared DNS) they would keep the object from
        // collapsing to nothing; false/null values are also stripped so the
        // wire stays minimal (core defaults: serveStale false, TTL unset).
        if !obj.contains_key("servers") {
            obj.remove("serveStale");
            obj.remove("serveExpiredTTL");
        }
        if obj.get("serveStale") == Some(&Value::Bool(false)) {
            obj.remove("serveStale");
        }
        if obj.get("serveExpiredTTL").is_none_or(Value::is_null) {
            obj.remove("serveExpiredTTL");
        }
        if obj.is_empty() { None } else { Some(v) }
    }

    /// True when the top-level `dns` object would be omitted from the wire
    /// config — no servers, hosts, or other settings, and fakeDNS disabled.
    /// Mirrors the generator's emission decision exactly.
    pub fn is_effectively_empty(&self) -> bool {
        self.to_wire(self.fakedns.enabled).is_none()
    }
}

/// Parse a fakeDNS pool range exactly as Xray's fakeip holder does (Go
/// `net.ParseCIDR`, app/dns/fakedns/fake.go:82-90): an IP CIDR with a
/// prefix (a bare IP is rejected), v4 prefix ≤ 32, v6 prefix ≤ 128.
/// Returns `(bits, host_bits)`; `host_bits` may exceed 63 — then any i64
/// pool size fits the subnet.
pub(crate) fn parse_pool_cidr(s: &str) -> Option<(u32, u32)> {
    let (ip, prefix) = s.split_once('/')?;
    let ip: std::net::IpAddr = ip.parse().ok()?;
    let (bits, max_prefix) = if ip.is_ipv4() { (32, 32) } else { (128, 128) };
    let prefix: u32 = prefix.parse().ok()?;
    (prefix <= max_prefix).then(|| (bits, bits - prefix))
}

/// True when `s` is a valid fakeDNS pool CIDR (see [`parse_pool_cidr`]).
pub(crate) fn is_valid_cidr(s: &str) -> bool {
    parse_pool_cidr(s).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pool_cidr_grammar_matches_xray_fakeip() {
        for valid in [
            "198.18.0.0/15",
            "fc00::/18",
            "0.0.0.0/0",
            "::/0",
            "127.0.0.1/32",
            "::1/128",
        ] {
            assert!(is_valid_cidr(valid), "{valid:?} must parse as a pool CIDR");
        }
        for invalid in [
            "198.18.0.0",
            "fc00::1",
            "300.1.1.1/8",
            "10.0.0.0/33",
            "::/129",
            "10.0.0.0/",
            "foo",
            "",
        ] {
            assert!(!is_valid_cidr(invalid), "{invalid:?} must be rejected");
        }
        assert_eq!(parse_pool_cidr("198.18.0.0/15"), Some((32, 17)));
    }

    #[test]
    fn fresh_install_default_pool_set_covers_ipv4_and_ipv6() {
        let config = FakeDnsCfg::default();
        assert_eq!(config.pools.len(), 2);
        assert_eq!(config.pools[0].ip_pool, DEFAULT_FAKEDNS_POOL_CIDR);
        assert_eq!(config.pools[0].pool_size, DEFAULT_FAKEDNS_POOL_SIZE);
        assert_eq!(config.pools[1].ip_pool, SECOND_FAKEDNS_POOL_CIDR);
        assert_eq!(config.pools[1].pool_size, SECOND_FAKEDNS_POOL_SIZE);
    }

    #[test]
    fn default_fakedns_wire_emits_two_pool_array() {
        let config = FakeDnsCfg::default();
        assert_eq!(
            config.to_wire(),
            Some(json!([
                {"ipPool": DEFAULT_FAKEDNS_POOL_CIDR, "poolSize": DEFAULT_FAKEDNS_POOL_SIZE},
                {"ipPool": SECOND_FAKEDNS_POOL_CIDR, "poolSize": SECOND_FAKEDNS_POOL_SIZE}
            ]))
        );
    }
    #[test]
    fn timeout_above_u32_round_trips_as_exact_integer() {
        let input = json!({
            "version": 1,
            "dns": {
                "servers": [{
                    "address": "1.1.1.1",
                    "timeoutMs": 4_294_967_296_u64
                }]
            }
        });
        let settings: crate::model::Settings = serde_json::from_value(input).unwrap();
        let persisted = serde_json::to_value(&settings).unwrap();
        let restored: crate::model::Settings = serde_json::from_value(persisted).unwrap();

        assert_eq!(restored.dns.servers[0].timeout_ms, 4_294_967_296_u64);
        assert_eq!(
            serde_json::to_value(restored).unwrap()["dns"]["servers"][0]["timeoutMs"],
            json!(4_294_967_296_u64)
        );
    }

    #[test]
    fn timeout_boundaries_and_default_omission_are_stable() {
        for value in [0, default_timeout_ms(), u64::MAX] {
            let server: DnsServer = serde_json::from_value(json!({
                "address": "1.1.1.1",
                "timeoutMs": value
            }))
            .unwrap();
            assert_eq!(server.timeout_ms, value);

            let output = serde_json::to_value(server).unwrap();
            if value == default_timeout_ms() {
                assert!(output.get("timeoutMs").is_none());
            } else {
                assert_eq!(output["timeoutMs"], json!(value));
            }
        }
    }

    #[test]
    fn bootstrap_resolver_persists_but_is_stripped_from_wire() {
        let mut cfg = DnsCfg::default();
        cfg.servers.push(DnsServer {
            address: "https://1.1.1.1/dns-query".into(),
            ..Default::default()
        });
        cfg.bootstrap = "https://223.5.5.5/dns-query".into();

        let wire = cfg.to_wire(false).unwrap();
        assert_eq!(
            wire.get("bootstrap"),
            None,
            "GUI-only field must not reach the wire"
        );

        let persisted = serde_json::to_value(&cfg).unwrap();
        assert_eq!(persisted["bootstrap"], json!("https://223.5.5.5/dns-query"));
        let restored: DnsCfg = serde_json::from_value(persisted).unwrap();
        assert_eq!(restored.bootstrap, "https://223.5.5.5/dns-query");
    }

    #[test]
    fn expected_ips_migrate_to_one_canonical_key() {
        let canonical: DnsServer = serde_json::from_value(json!({
            "address": "1.1.1.1",
            "expectedIPs": ["geoip:canonical"]
        }))
        .unwrap();
        assert_eq!(canonical.expected_ips, ["geoip:canonical"]);
        assert_eq!(
            serde_json::to_value(canonical).unwrap()["expectedIPs"],
            json!(["geoip:canonical"])
        );

        let legacy: DnsServer = serde_json::from_value(json!({
            "address": "1.1.1.1",
            "expectIPs": ["geoip:legacy"]
        }))
        .unwrap();
        let legacy_output = serde_json::to_value(legacy).unwrap();
        assert_eq!(legacy_output["expectedIPs"], json!(["geoip:legacy"]));
        assert!(legacy_output.get("expectIPs").is_none());

        let dual: DnsServer = serde_json::from_value(json!({
            "address": "1.1.1.1",
            "expectedIPs": ["geoip:canonical"],
            "expectIPs": ["geoip:legacy"]
        }))
        .unwrap();
        let dual_output = serde_json::to_value(dual).unwrap();
        assert_eq!(dual_output["expectedIPs"], json!(["geoip:canonical"]));
        assert!(dual_output.get("expectIPs").is_none());
    }

    #[test]
    fn per_server_bool_overrides_round_trip_explicit_false() {
        let server: DnsServer = serde_json::from_value(json!({
            "address": "1.1.1.1",
            "skipFallback": false,
            "disableCache": false,
            "serveStale": false,
            "finalQuery": false
        }))
        .unwrap();

        assert_eq!(server.skip_fallback, Some(false));
        assert_eq!(server.disable_cache, Some(false));
        assert_eq!(server.serve_stale, Some(false));
        assert_eq!(server.final_query, Some(false));
        let output = serde_json::to_value(server).unwrap();
        assert_eq!(output["skipFallback"], json!(false));
        assert_eq!(output["disableCache"], json!(false));
        assert_eq!(output["serveStale"], json!(false));
        assert_eq!(output["finalQuery"], json!(false));
    }

    #[test]
    fn nameserver_address_shorthand_migrates_to_stable_object() {
        let server: DnsServer = serde_json::from_value(json!("1.1.1.1")).unwrap();
        assert_eq!(server.address, "1.1.1.1");
        assert_eq!(server.timeout_ms, default_timeout_ms());
        assert_eq!(
            serde_json::to_value(server).unwrap(),
            json!({"address": "1.1.1.1"})
        );

        let error = serde_json::from_value::<DnsServer>(json!(["1.1.1.1"]))
            .unwrap_err()
            .to_string();
        assert!(error.contains("DNS server address string or configuration object"));
    }

    #[test]
    fn mistyped_object_field_errors_name_the_field_and_keep_the_inner_error() {
        // The entry shape is a hand-written visitor rather than a
        // `#[serde(untagged)]` enum: an untagged enum replaces the inner
        // error with its own "did not match any variant" text, hiding the
        // field the user must repair. `load_state` renders this path and
        // text, so both halves are asserted here.
        let value = json!({"address": "1.1.1.1", "timeoutMs": "abc"});
        let bytes = serde_json::to_vec(&value).unwrap();
        let mut de = serde_json::Deserializer::from_slice(&bytes);
        let error = serde_path_to_error::deserialize::<_, DnsServer>(&mut de)
            .expect_err("a mistyped modeled field must fail the entry");
        let message = format!("{}: {}", error.path(), error.inner());
        assert!(message.contains("timeoutMs"), "names the field: {message}");
        assert!(
            message.contains("invalid type"),
            "keeps the inner type error: {message}"
        );
        assert!(
            !message.contains("untagged"),
            "must not degrade to the untagged-enum text: {message}"
        );
    }
}
