//! Section and field names of the generated core configuration document.
//!
//! One home for the keys that cross the generator→reader seam: the emitted
//! document's top-level sections and the nested keys another module reads
//! back out of a config. The spelling is the contract — Xray binds these
//! names in its own `infra/conf` structs (each const cites its binding), so
//! a re-spelling has to land here and in every reader at once instead of
//! drifting silently between the generator and the code that inspects a
//! config the core is running.
//!
//! A key with one emitting site inside the generator stays a literal at that
//! site: a nested `json!` key in a block nothing reads back needs no name of
//! its own. Two spellings are deliberately shared: the top-level `dns`
//! module and the TUN protocol settings' own resolver list are one word in
//! two upstream structs, and `domainStrategy` names both the sockopt field
//! the generator patches into an outbound and the routing section's own key,
//! which has one emitting site and stays a literal there.

// ---------- top-level sections ----------

/// The top-level `log` section (`Config.LogConfig`, infra/conf/xray.go:394).
pub const LOG: &str = "log";

/// The top-level `stats` section (`Config.Stats`, infra/conf/xray.go:402).
/// Emitted as an empty object: the system stats policy keys are what enable
/// the counters.
pub const STATS: &str = "stats";

/// The top-level `api` section (`Config.API`, infra/conf/xray.go:400): the
/// control-plane listener. The runtime reads its `listen` back to learn the
/// ephemeral port to poll (`rt::apply`), and the candidate comparison strips
/// that port from it.
pub const API: &str = "api";

/// The top-level `policy` section (`Config.Policy`, infra/conf/xray.go:399).
pub const POLICY: &str = "policy";

/// The top-level `inbounds` section (`Config.InboundConfigs`,
/// infra/conf/xray.go:397) — the array every inbound reader walks: the TUN
/// adapter lookup, the DNS-module gate, the in-tun listener derivation, and
/// the raw-override checks.
pub const INBOUNDS: &str = "inbounds";

/// The top-level `outbounds` section (`Config.OutboundConfigs`,
/// infra/conf/xray.go:398) — read back by the raw-override checks for the
/// retired `proxySettings` and `finalmask.quicParams.udpHop` keys.
pub const OUTBOUNDS: &str = "outbounds";

/// The top-level `routing` section (`Config.RouterConfig`,
/// infra/conf/xray.go:395).
pub const ROUTING: &str = "routing";

/// The top-level `dns` section (`Config.DNSConfig`, infra/conf/xray.go:396),
/// and the same word for the TUN protocol settings' resolver list
/// (`TunConfig.DNS`, infra/conf/tun.go:19, where the generator pins the
/// in-tun address the runtime's listener must bind).
pub const DNS: &str = "dns";

/// The top-level `observatory` section (`Config.Observatory`,
/// infra/conf/xray.go:405): one of the two outbound-health extensions whose
/// presence decides whether the app reads a health status at all.
pub const OBSERVATORY: &str = "observatory";

/// The top-level `burstObservatory` section (`Config.BurstObservatory`,
/// infra/conf/xray.go:406): the windowed health extension, the other half of
/// the pair above.
pub const BURST_OBSERVATORY: &str = "burstObservatory";

/// The top-level `fakeDns` section (`Config.FakeDNS`,
/// infra/conf/xray.go:404): the fake-DNS pool.
pub const FAKE_DNS: &str = "fakeDns";

/// The top-level `env` section (`Config.Env`, infra/conf/xray.go:393):
/// environment variables the core exposes to its own outbound configs.
pub const ENV: &str = "env";

/// The top-level `geodata` section (`Config.Geodata`,
/// infra/conf/xray.go:408): the core's own DAT updater. Its presence — see
/// [`ASSETS`] and [`URL`] — is what suspends the release pins on the geo
/// data files (`sys::core_dl`).
pub const GEODATA: &str = "geodata";

// ---------- nested keys another module reads back ----------

/// The `listen` field (`APIConfig.Listen`, infra/conf/api.go:18; the inbound
/// detour carries its own, infra/conf/xray.go:130): the address a listener
/// binds. Read back from the `api` section to derive the control-plane port,
/// and stripped — from the section and from the api inbound — when two
/// generated candidates are compared for equality.
pub const LISTEN: &str = "listen";

/// The `services` array of the `api` section (`APIConfig.Services`,
/// infra/conf/api.go:19). The app requires `StatsService` among them before
/// it trusts a candidate's control plane.
pub const SERVICES: &str = "services";

/// The `tag` field of an inbound or outbound detour
/// (`InboundDetourConfig.Tag`, infra/conf/xray.go:132;
/// `OutboundDetourConfig.Tag`, infra/conf/xray.go:217): the identity routing
/// rules, runtime teardown, and the app's own scans address a listener or
/// outbound by. Its values are the wire tags of `model::inbound`.
pub const TAG: &str = "tag";

/// The `protocol` field of an inbound or outbound detour
/// (`InboundDetourConfig.Protocol`, infra/conf/xray.go:128;
/// `OutboundDetourConfig.Protocol`, infra/conf/xray.go:215) — read back to
/// find a detour by kind rather than by tag.
pub const PROTOCOL: &str = "protocol";

/// The `settings` field of an inbound or outbound detour
/// (`InboundDetourConfig.Settings`, infra/conf/xray.go:131;
/// `OutboundDetourConfig.Settings`, infra/conf/xray.go:218): the
/// protocol-specific settings object. The generator patches the TUN
/// inbound's adapter DNS into it, and the TUN adapter lookup and the in-tun
/// listener derivation read it back.
pub const SETTINGS: &str = "settings";

/// The outbound detour's `streamSettings` block
/// (`OutboundDetourConfig.StreamSetting`, infra/conf/xray.go:219), whose
/// `sockopt` the generator patches caller-side dial policy into.
pub const STREAM_SETTINGS: &str = "streamSettings";

/// The stream block's `sockopt` object (`StreamConfig.SocketSettings`,
/// infra/conf/transport_internet.go:62): the per-dial socket options.
pub const SOCKOPT: &str = "sockopt";

/// The sockopt `dialerProxy` field (`SocketConfig.DialerProxy`,
/// infra/conf/transport_sockopt.go:51): the outbound tag a dial-through
/// profile hands its connection to — the one chain spelling the pinned core
/// still reads (its retired predecessor is refused,
/// infra/conf/xray.go:262).
pub const DIALER_PROXY: &str = "dialerProxy";

/// The sockopt `interface` field (`SocketConfig.Interface`,
/// infra/conf/transport_sockopt.go:60): the network interface a dial binds
/// to — the latency probe pins it so its measurement bypasses the TUN.
pub const INTERFACE: &str = "interface";

/// The sockopt `domainStrategy` field (`SocketConfig.DomainStrategy`,
/// infra/conf/transport_sockopt.go:50): `useip` routes a domain-addressed
/// server dial through the DNS module. The routing section has a
/// `domainStrategy` of its own (`RouterConfig.DomainStrategy`,
/// infra/conf/router.go:73); that one has a single emitting site and stays a
/// literal there, not this field.
pub const DOMAIN_STRATEGY: &str = "domainStrategy";

/// The `geodata` block's `assets` array (`GeodataConfig.Assets`,
/// infra/conf/geodata.go:45): one entry per DAT file the core refreshes.
pub const ASSETS: &str = "assets";

/// An asset entry's `url` (`GeodataAssetConfig.URL`,
/// infra/conf/geodata.go:14): its presence is what makes the geo data files
/// updater-managed and suspends their release pins.
pub const URL: &str = "url";
