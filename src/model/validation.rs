//! Model validation pass — the single seam shared by the share-link importer/
//! exporter, the config generator, and the editor.
//!
//! Pure model checks: no i18n here. Every issue carries a [`ValidationCode`],
//! an optional wire path, and its [`Severity`] tier (`Error` findings block
//! save/import/apply; `Warning` findings are advisory); callers
//! render codes through `crate::i18n::validation_message` /
//! `validation_issue_message`. One pass per model, no short-circuit — a
//! single `validate_outbound` call surfaces every protocol, stream, and
//! transport-security problem.
//!
//! `Network::supports_reality` stays in `stream.rs` as the shared fact; this
//! module only consumes it.

use super::Int32Range;
use super::dns::parse_pool_cidr;
use super::inbound::{
    API_INBOUND_TAG, BLOCK_OUTBOUND_TAG, DIRECT_OUTBOUND_TAG, DokodemoNetwork, LocalInboundCfg,
    LocalInboundProtocol, Sniffing, listen_endpoints_conflict,
};
use super::outbound::{
    MuxModel, OutboundModel, ProtocolSettings, blackhole_custom_response_data_decodes,
    blackhole_response_is_custom, blackhole_response_type_supported,
    endpoint_requires_transport_security, vless_encryption_supported,
    wireguard_remote_dns_supported,
};
use super::stream::{
    FinalmaskModel, FinalmaskPortList, FinalmaskQuicParams, FinalmaskRawValue, FinalmaskSudoku,
    FinalmaskTcpMask, FinalmaskTransform, FinalmaskUdpMask, FinalmaskXmc, MAX_XHTTP_DOWNLOAD_DEPTH,
    Network, Security, SockoptModel, StreamModel, XmuxConfig,
};
use super::{ServerProfile, ServersFile, Settings, TunCfg, emit};
use crate::links::{excerpt, excerpt_debug};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Every rejection the model layer knows, keyed by rule rather than by
/// rendered message. Order-independent; parameterized rules carry the value
/// that the message interpolates — always the bounded form from
/// `crate::links::excerpt` (at most `crate::links::MAX_ERROR_EXCERPT_CHARS`
/// characters of the source value, plus an optional trailing `…`). Bounding
/// happens at construction, so a hostile import input can never inflate a
/// rendered message and no render site needs its own truncation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationCode {
    // ---- stream / transport invariants (validate_stream) ----
    XhttpDepthExceeded,
    TransportSettingsMissing(Network),
    /// A transport's `headers` map carries a value that is not a string. Xray
    /// types `wsSettings.headers`, `httpupgradeSettings.headers` and the XHTTP
    /// settings' own `headers` as `map[string]string`, so a non-string value
    /// makes the whole document unloadable; the share-link grammar refuses the
    /// same value on import.
    HeaderValuesNotStrings(Network),
    HysteriaTransportRequiresTls,
    /// Both the outbound `settings.version` and the transport
    /// `hysteriaSettings.version` collapse into this one rule; the issue's
    /// path disambiguates which one failed.
    HysteriaTransportVersion,
    RealityRequiresTransport,
    RealitySettingsMissing,
    TlsSettingsMissing,
    /// xHTTP `mode == "stream-one"` carrying a `downloadSettings` subtree:
    /// Xray's SplitHTTPConfig.Build refuses the pair
    /// (infra/conf/transport_method.go:500-501). The loaded model keeps the
    /// subtree — a saved or imported profile is not silently rewritten — and
    /// this Error blocks generation/apply until the user removes it.
    StreamOneNoDownload,
    /// TLS/REALITY `masterKeyLog` would make Xray open an attacker-chosen file
    /// and log session keys to it — refused on import.
    MasterKeyLogNotSupported,
    /// `tlsSettings.allowInsecure` was removed by Xray (use
    /// `pinnedPeerCertSha256` / `verifyPeerCertByName`); any carried value
    /// other than the JSON `false` zero value either hard-fails
    /// TLSConfig.Build or breaks Xray's `bool` unmarshal — refused.
    TlsAllowInsecureRemoved,
    // ---- protocol-level invariants (validate_outbound) ----
    ShadowsocksLevelRange,
    /// `settings.response.type` outside the vocabulary Xray's blackhole
    /// conf matches after lowercasing it (infra/conf/blackhole.go:24-26):
    /// the empty spelling and `none` (no response), `http`, `custom`. Any
    /// case of those spellings is accepted; the stored text is untouched.
    BlackholeResponseInvalid,
    /// `settings.response.customResponseData` that Xray's conf load cannot
    /// decode as standard base64 while `response.type` is `custom`
    /// (infra/conf/blackhole.go:31-34 returns the decode error, so the whole
    /// config fails to build). The payload is kept verbatim — the gate is the
    /// user's fix-it prompt, not a rewrite.
    BlackholeCustomResponseDataInvalid,
    // ---- protocol-settings vocabulary / required values (validate_outbound) ----
    /// VLESS `settings.flow` outside {``, `xtls-rprx-vision`,
    /// `xtls-rprx-vision-udp443`}: Xray's conf load rejects unknown flows
    /// (conf/vless.go), mirroring the share-link import grammar.
    VlessFlowUnsupported,
    /// VLESS `settings.encryption` other than `` / `none` / a canonical
    /// `mlkem768x25519plus.<native|xorpub|random>.<1rtt|0rtt>.<parts…>` with
    /// at least one full key part: parts shorter than 20 characters are
    /// padding tokens, every other part must be a 32- or 1184-byte url-safe
    /// base64 key, and the padding tokens must satisfy the core's padding
    /// grammar (proxy/vless/encryption/common.go:223-257). Xray's conf load
    /// panics on an all-padding value and rejects every other malformed
    /// encryption (conf/vless.go). `` stays accepted — the state seam's
    /// default, which emit normalization renders `none` on the wire.
    VlessEncryptionUnsupported,
    /// Shadowsocks `settings.method` outside Xray's AEAD + 2022 + legacy
    /// alias vocabulary (conf/shadowsocks.go `cipherFromString` /
    /// `shadowaead_2022.List`; legacy stream ciphers hit the same unknown-
    /// cipher load error). Vocabulary mirrors the import whitelist.
    ShadowsocksMethodUnsupported,
    /// Shadowsocks-2022 `settings.password` is not base64 of the method's
    /// key length (16 B for `2022-blake3-aes-128-gcm`, 32 B for the other
    /// 2022 methods; the ChaCha20 2022 method also rejects multi-psk
    /// colon-separated keys). Xray accepts the config (`run -test` passes —
    /// live repro 2026-09-05, Xray 26.7.28) and the session only fails at
    /// dial/auth time, so this is advisory (Severity::Warning).
    Shadowsocks2022KeyInvalid,
    /// Trojan `settings` missing essentials — empty `address` / `password`,
    /// port 0 — that Xray's conf build rejects (conf/trojan.go). One rule,
    /// path-disambiguated.
    TrojanSettingsIncomplete,
    /// Shadowsocks `settings` missing essentials — empty `address` /
    /// `password`, port 0 — that Xray's conf build rejects
    /// (conf/shadowsocks.go). One rule, path-disambiguated.
    ShadowsocksSettingsIncomplete,
    /// VLESS/VMess `settings.port` of 0: Xray accepts it (`run -test`
    /// passes — live repro 2026-09-05, Xray 26.7.28) but dial :0 can never
    /// connect (class A), so the model refuses it like the import grammar.
    SettingsPortZero,
    /// VLESS/VMess `settings.id` that is non-empty and not a canonical
    /// UUID: Xray silently sha1-maps short strings to a deterministic v5
    /// UUID (common/uuid/uuid.go) — dialing a *different* account. Broccoli
    /// deliberately diverges with a UUID-only policy (the one definition is
    /// `is_canonical_uuid`, which the import `check_uuid`, the finalmask
    /// validator, and the UI UUID field validator all call). Empty ids stay
    /// out of scope (draft state; the editor requires them).
    SettingsIdNotUuid,
    // ---- transport-security formats (validate_stream) ----
    /// REALITY client `publicKey` (stored in the profile's `password`
    /// field, the upstream alias) is not an unpadded base64url string
    /// decoding to 32 bytes — Xray's conf build refuses it, empty included
    /// (conf/transport_security.go, client branch).
    RealityPublicKeyInvalid,
    /// REALITY `shortId` is not an even-length hex value of at most 16
    /// characters — Xray hex-decodes it into 8 bytes and Go rejects
    /// odd-length or non-hex input (conf/transport_security.go). Empty is
    /// the model default and stays valid.
    RealityShortIdInvalid,
    /// REALITY `spiderX` is not a URL path beginning with `/` — Xray's conf
    /// build rejects the missing slash, and unparseable paths break its
    /// query rewriter (conf/transport_security.go). Empty stays valid —
    /// Xray defaults it to `/`.
    RealitySpiderXInvalid,
    /// REALITY `mldsa65Verify` is not an unpadded base64url string decoding
    /// to the 1952-byte ML-DSA-65 public key
    /// (conf/transport_security.go). Empty stays valid (no post-quantum
    /// verification key).
    RealityMldsa65Invalid,
    /// TLS `fingerprint` outside the wire-valid uTLS vocabulary
    /// (conf/transport_security.go TLSConfig.Build; the vocabulary table is
    /// `crate::model::fingerprint`). `unsafe` and `hellogolang` stay legal
    /// on the TLS block — they resolve to native Go TLS there.
    TlsFingerprintUnsupported,
    /// REALITY `fingerprint` = `unsafe`/`hellogolang` or outside the
    /// wire-valid uTLS vocabulary — the conf build rejects both classes
    /// explicitly (conf/transport_security.go, client branch).
    RealityFingerprintUnsupported,
    /// REALITY `fingerprint` wire-valid but outside the known-good set the
    /// editor offers (empty — the uTLS Chrome_Auto default — plus `chrome`,
    /// `firefox`, `safari`): Xray still accepts the value, but upstream's
    /// REALITY scenario suite exercises only those three
    /// (testing/scenarios/vless_test.go TestVlessRealityFingerprints, the
    /// private `REALITY_EDITOR_OPTIONS` table is the single source) — the
    /// stored value is never rewritten, so the advisory tells the user
    /// instead of leaving them to diagnose a handshake failure
    /// (Severity::Warning). The code carries the stored name for the
    /// message.
    RealityFingerprintUntested(String),
    /// TLS `pinnedPeerCertSha256` holds an entry that is not a 32-byte
    /// SHA-256 fingerprint written as hex (colons optional, entries
    /// comma-separated) — Xray's conf build errors on non-hex or
    /// wrong-length entries (conf/transport_security.go).
    PinnedPeerCertSha256Invalid,
    /// TLS `alpn` carries `fromMitm` alongside other names: Xray's conf build
    /// refuses the list (`infra/conf/transport_security.go`: only one element
    /// is allowed in "alpn" when using "fromMitm" in it). The finalmask realm
    /// TLS mount has its own code ([`Self::FinalmaskRealmAlpnFromMitm`]).
    TlsFromMitmAlpnShort,
    /// An outbound TLS certificate row names no non-blank `certificateFile`
    /// and holds no non-blank inline `certificate` line — both values are
    /// trimmed before the emptiness test, so a whitespace-only value counts as
    /// absent: Xray's conf build refuses such an entry (infra/conf: both file
    /// and bytes are empty). The finding's path names the offending row. The
    /// finalmask realm TLS mount has its own code
    /// ([`Self::FinalmaskRealmCertRequired`]).
    TlsCertificateRequired,
    // ---- transport security (validate_outbound) ----
    VisionRequiresTlsOrReality,
    PublicVlessRequiresTlsOrEncryption,
    PublicTrojanRequiresTlsOrReality,
    // ---- listen address ----
    ListenAddressInvalid,
    // ---- sockopt ----
    SockoptDomainStrategyInvalid,
    SockoptAddressPortStrategyInvalid,
    SockoptTcpFastOpenType,
    SockoptKeepaliveSigns,
    SockoptCustomOptRequired,
    SockoptCustomTypeInvalid,
    // ---- finalmask ----
    FinalmaskQuicCongestionInvalid,
    FinalmaskQuicBbrProfileInvalid,
    FinalmaskQuicBandwidthTooSmall,
    FinalmaskQuicBandwidthSyntax,
    FinalmaskQuicBandwidthNonFinite,
    FinalmaskQuicBandwidthTooLarge,
    FinalmaskQuicBandwidthUnitInvalid(String),
    FinalmaskQuicForceBrutalNeedsUp,
    /// A profile's `quicParams` carried the retired `udpHop` key: the hop
    /// moved to the `udphop` UDP mask (`infra/conf/transport_finalmask.go:88`
    /// at v26.9.9) and the core ignores the old key silently, so the config
    /// applies without the hop until the user rebuilds it as a mask. The key
    /// is kept for the settings file (JSON `null` is the Go zero shape and
    /// counts as absent), never serialized to the wire, and never migrated.
    FinalmaskQuicHopMoved,
    /// The `udphop` mask `mode` is not a comma-separated set of
    /// `intervalLocal` / `intervalRemote` / `perConnRemote` — the mask build
    /// refuses every other component at config load
    /// (`infra/conf/transport_finalmask.go:930-940`).
    FinalmaskUdpHopModeInvalid,
    /// The `udphop` mask `interval` states an endpoint below the core's
    /// 5-second floor — including an unset zero: the wrap refuses anything
    /// less (`transport/internet/finalmask/udphop/conn.go:71-73`).
    FinalmaskUdpHopIntervalTooSmall,
    /// A `udphop` mask `remoteIPs` entry is neither an address nor a CIDR
    /// prefix — the mask build refuses the entry at config load
    /// (`infra/conf/transport_finalmask.go:950-960`).
    FinalmaskUdpHopIpInvalid,
    /// A mask that wraps the outbound's own packet connection (`udphop`,
    /// `realm`, or `xicmp`) and a dial-through chain on the same outbound:
    /// each of those client wraps refuses a proxied packet connection — an
    /// `internet.FakePacketConn`, which is what `sockopt.dialerProxy` yields
    /// (`transport/internet/finalmask/{udphop,realm,xicmp}/config.go:11-13`).
    /// The core starts and every dial fails, so this is a configuration
    /// warning, never a gate.
    FinalmaskDialerProxyConflict,
    /// A `udphop` / `realm` / `xicmp` UDP mask sits anywhere but the last
    /// list entry: the UDP mask manager reverses the list at construction
    /// and wraps forward, so the JSON list's last entry is wrapped first
    /// (`transport/internet/finalmask/finalmask.go:21-25,28-31`), and those
    /// wraps demand that first slot — level 0
    /// (`.../udphop/config.go:11-13`, `.../realm/config.go:11-20`,
    /// `.../xicmp/config.go:11-20`). The core starts and every dial fails,
    /// so this gates. Carries the mask type name.
    FinalmaskUdpMaskNotLast(String),
    /// A `sudoku` UDP mask sits anywhere but the first list entry: its wrap
    /// demands the last-wrapped slot — level `levelCount`
    /// (`transport/internet/finalmask/sudoku/config.go:39-49`), which the
    /// reversed-and-forward manager maps to the JSON list's first entry. The
    /// core starts and every dial fails, so this gates. Carries the mask
    /// type name.
    FinalmaskUdpMaskNotFirst(String),
    /// A `udphop` mask carries an interval mode on a transport that cannot
    /// run a hop: `intervalLocal` dials a fresh local socket per hop and
    /// `intervalRemote` re-rolls the remote address
    /// (`transport/internet/finalmask/udphop/conn.go:96-135`), so only a
    /// transport that moves a live connection survives — hysteria2, the
    /// splithttp HTTP/3 mode (TLS ALPN exactly `["h3"]`), or the WireGuard
    /// outbound, whose client applies the same mask manager to its own
    /// packet conn (`proxy/wireguard/client.go:309-310`). On every other
    /// transport the mask list is either never wrapped or cannot carry the
    /// connection across a hop. The core starts either way, so this is a
    /// configuration warning, never a gate.
    FinalmaskUdpHopIntervalTransportConflict,
    FinalmaskQuicReceiveWindowTooSmall,
    FinalmaskQuicMaxIdleTimeoutInvalid,
    FinalmaskQuicKeepAlivePeriodInvalid,
    FinalmaskQuicMaxIncomingStreamsInvalid,
    FinalmaskPortNumberRange,
    FinalmaskPortEnvNameRequired,
    FinalmaskPortListInvalid(String),
    FinalmaskBytesValueRequired(String),
    FinalmaskArrayByteSyntax,
    FinalmaskStrByteSyntax,
    FinalmaskHexByteSyntax,
    FinalmaskBase64ByteSyntax,
    FinalmaskUnknownByteSyntax(String),
    FinalmaskTransformOpRequired,
    FinalmaskTransformArgRequired,
    FinalmaskTransformArgExclusive,
    FinalmaskVarNameInvalid,
    FinalmaskCustomItemExclusive,
    FinalmaskRandRangeInvalid,
    FinalmaskXmcProfilesRequired,
    FinalmaskXmcPasswordRequired,
    FinalmaskXmcUsernameInvalid,
    FinalmaskXmcUuidInvalid,
    FinalmaskXmcTexturesRequired,
    FinalmaskPacketsFirstNotZero,
    FinalmaskPacketsSyntax,
    FinalmaskLengthsStartAboveZero,
    FinalmaskUnknownTcpMask(Option<String>),
    FinalmaskUdpHeaderModeInvalid,
    FinalmaskMkcpHeaderInvalid,
    FinalmaskNoisePacketExclusive,
    FinalmaskSalamanderPacketSize,
    FinalmaskXdnsDomainRemoved,
    FinalmaskXdnsEmpty,
    FinalmaskXdnsResolverUdp,
    FinalmaskXicmpIpInvalid,
    FinalmaskRealmScheme,
    FinalmaskRealmHostRequired,
    FinalmaskRealmTokenBeforeAt,
    FinalmaskRealmIdInPath,
    FinalmaskRealmUrlSyntax(String),
    FinalmaskRealmStunRequired,
    FinalmaskRealmStunFormat,
    FinalmaskRealmAllowInsecureRemoved,
    FinalmaskRealmFingerprintUnknown,
    FinalmaskRealmAlpnFromMitm,
    FinalmaskRealmCertRequired,
    FinalmaskRealmEchKeysBase64,
    FinalmaskUnknownUdpMask(Option<String>),
    // ---- editor rules that decide configuration validity
    //      (validate_outbound / validate_settings) ----
    //
    // These three rules used to live only in the servers editor's error
    // list; they decide whether the configuration is valid (a profile that
    // fails them cannot be applied), so the model pass owns them now and the
    // editor, generation and the importer all consume the same codes. The
    // messages are the editor's existing error-list texts.
    /// Outbound `sendThrough` is neither `origin`/`srcip` nor an IP address
    /// or CIDR — Xray's dialer accepts nothing else there.
    SendThroughInvalid,
    /// A freedom `settings.finalRules[]` entry whose action is neither
    /// `allow` nor `block` (case-insensitive) — Xray's freedom build rejects
    /// the outbound at load.
    FreedomFinalRuleInvalid,
    /// A DNS inbound/outbound `settings.rules[]` entry whose action is not
    /// one of {direct, drop, return, hijack} — Xray's DNS build rejects
    /// unknown actions.
    DnsRuleActionInvalid,
    /// A WireGuard `settings.remoteDNS` list holds an entry that is neither
    /// an IP literal nor the `local` sentinel as the list's only entry. The
    /// pinned core builds the in-network resolver set with
    /// `netip.MustParseAddr` while it creates the outbound
    /// (proxy/wireguard/client.go:117-124), so any other entry panics the
    /// whole process during config load — the config can never start. Error
    /// tier: the profile gates until the list is fixed.
    WireguardRemoteDnsInvalid,
    // ---- settings-wide verdict rules (validate_settings /
    //      validate_profiles) ----
    //
    // The generator's former free-form settings checks, one code per rule.
    // Parameterized codes carry exactly the values the pre-pass strings
    // interpolated; `validation_issue_message` reproduces the same bytes.
    // Findings whose message already names its offender carry no path;
    // findings scoped to one model instance (a profile, an inbound) carry
    // the human-readable location as their path.
    /// `servers.active` names no profile.
    ActiveProfileMissing(String),
    /// `servers.active` matches more than one profile (duplicate IDs).
    ActiveProfileAmbiguous(String, usize),
    /// The latency probe was asked to run with no server profiles.
    ProfilesRequired,
    /// A server profile's ID is empty or whitespace-only (1-based index).
    ProfileIdEmpty(usize),
    /// Two server profiles share an ID (1-based indices, then the ID).
    ProfileIdDuplicated(usize, usize, String),
    /// A server profile's generated outbound tag is empty (index, profile ID).
    ProfileTagEmpty(usize, String),
    /// A server profile's generated outbound tag carries whitespace or
    /// control characters (index, profile ID, tag).
    ProfileTagInvalid(usize, String, String),
    /// A server profile's generated outbound tag collides with the reserved
    /// `direct`/`block` built-ins (index, profile ID, tag).
    ProfileTagReserved(usize, String, String),
    /// Two server profiles generate the same outbound tag (indices, IDs,
    /// tag).
    ProfileTagDuplicated(usize, String, usize, String, String),
    /// A profile's stored outbound carries a non-null retired
    /// `proxySettings` value: Xray's outbound build refuses a configuration
    /// that carries it (infra/conf/xray.go:262, `outbound "proxySettings"` →
    /// `"streamSettings.sockopt.dialerProxy"`), so the config cannot apply
    /// until the user resolves it. The raw value stays in the model and in
    /// `servers.json` — nothing is migrated, and an unrelated save keeps it —
    /// while generated configurations never carry it; JSON `null` is the Go
    /// zero shape and stays silent.
    OutboundProxySettingsRemoved,
    /// A profile's chained outbound reference names no known outbound
    /// (source tag, missing target).
    OutboundChainMissing(String, String),
    /// The chained-outbound graph contains a cycle (the joined path).
    OutboundChainCycle(String),
    /// A routing balancer without a tag (1-based index).
    BalancerTagMissing(usize),
    /// A routing balancer whose selector list is empty or all-blank (tag).
    BalancerSelectorMissing(String),
    /// Two routing balancers share a tag.
    BalancerTagDuplicated(String),
    /// A routing balancer's `fallbackTag` names no outbound (balancer tag,
    /// fallback tag).
    BalancerFallbackMissing(String, String),
    /// Password-mode HTTP local inbound with an empty account list — the
    /// ticked "require authentication" intent never reaches the wire and
    /// Xray's HTTP inbound then serves everyone.
    LocalInboundAuthRequiresAccounts,
    /// An enabled local inbound with port 0 (tag).
    LocalInboundPortZero(String),
    /// Two inbound tags collide (tag).
    InboundTagDuplicated(String),
    /// A dokodemo entry without a stable tag (1-based index).
    DokodemoTagMissing(usize),
    /// A dokodemo entry whose `network` does not name a legal mode (tag,
    /// the mode parser's error text).
    DokodemoNetworkInvalid(String, String),
    /// A dokodemo UNIX listener without a socket path (tag).
    DokodemoUnixSocketRequired(String),
    /// Two dokodemo UNIX listeners normalize to the same socket path
    /// (tag, other tag, path).
    DokodemoUnixSocketConflict(String, String, String),
    /// A dokodemo IP listener with listen port 0 (tag).
    DokodemoPortZero(String),
    /// TUN mode without an IPv4 gateway: the adapter would carry no address
    /// while the in-tun DNS listener pins an address no adapter owns.
    TunIpv4GatewayRequired,
    /// Two listeners share an endpoint (current label, other label, address,
    /// port).
    ListenerConflict(String, String, String, u16),
    /// A routing rule names neither or both of an outbound and a balancer
    /// (1-based index, the target rule's error text).
    RoutingRuleTarget(usize, String),
    /// A routing rule references a missing outbound (index, tag).
    RoutingRuleOutboundMissing(usize, String),
    /// A routing rule references a missing balancer (index, tag).
    RoutingRuleBalancerMissing(usize, String),
    /// A routing rule references a missing inbound (index, tag).
    RoutingRuleInboundMissing(usize, String),
    /// A configured DNS server without an address (1-based index).
    DnsServerAddressMissing(usize),
    /// A fakeDNS pool whose `ipPool` is not an IP CIDR range (1-based index).
    FakeDnsPoolCidrInvalid(usize),
    /// A fakeDNS pool with a non-positive `poolSize` (1-based index).
    FakeDnsPoolSizeInvalid(usize),
    /// A fakeDNS pool whose `poolSize` does not fit its subnet (1-based
    /// index, size, pool CIDR).
    FakeDnsPoolCapacityExceeded(usize, i64, String),
    /// A geodata URL that is not an HTTPS URL with a host (the dat file it
    /// feeds).
    GeodataUrlInvalid(String),
    /// A geodata cron that is not the five-field shape.
    GeodataCronInvalid,
    // ---- advisory warnings (Severity::Warning, never gate) ----
    /// VLESS vision flow over enabled TCP mux: the server tears the whole
    /// mux connection down on the first TCP frame — deterministic breakage
    /// that stays xray-legal, so it warns instead of blocking.
    MuxWithVisionFlow,
    /// TLS/REALITY `serverName` that cannot be a real DNS name or IP
    /// literal (UUID-shaped, or carrying impossible characters) — the SNI
    /// can never match, but Xray accepts the config, so it warns.
    ServerNameImplausible,
    /// TLS `minVersion`/`maxVersion` outside {1.0, 1.1, 1.2, 1.3}: Xray
    /// accepts the string but silently leaves the version zeroed, so Go's
    /// defaults apply (tls/config.go version switches) — advisory, never
    /// blocking. The in-range min > max inversion is a separate rule.
    TlsVersionRangeInvalid,
    /// TLS `minVersion`/`maxVersion` both in {1.0, 1.1, 1.2, 1.3} with the
    /// minimum ranked above the maximum (inverted range). Live repro
    /// 2026-09-06 on Xray 26.7.28: `run -test` accepts
    /// the pair, and a wire probe shows the client's version pins are never
    /// applied — minVersion 1.3 / maxVersion 1.2 negotiates TLS 1.3 and the
    /// relay runs (a maxVersion-only "1.2" pin also negotiates 1.3). The
    /// config silently never behaves as written on either side of the
    /// contradiction, so it warns (Severity::Warning), never blocks.
    TlsMinExceedsMax,
    // ---- stream/sockopt/strategy enum surfaces (validate_stream /
    //      validate_sockopt / validate_outbound / validate_sniffing) ----
    //
    // The XHTTP refusals below mirror Xray's SplitHTTPConfig.Build
    // (infra/conf/transport_method.go:317-459) — Error tier because Xray
    // refuses the config at load — and share their predicates with the
    // share-link xhttp grammar, so the import seam and the model seam
    // cannot drift. KCP / sockopt tproxy / gRPC are class-E silent
    // behaviors and the kcp range is docs-only, so those are
    // configuration warnings (Severity::Warning).
    /// XHTTP `mode` outside {``, `auto`, `packet-up`, `stream-up`,
    /// `stream-one`} (empty = the wire default `auto`); Xray's conf build
    /// rejects every other string.
    XhttpModeUnsupported,
    /// XHTTP `xPaddingBytes` range present with a non-positive bound (the
    /// zero range — padding off — is the one legal `≤ 0` shape). Xray's
    /// conf build rejects the rest.
    XhttpPaddingBytesInvalid,
    /// XHTTP `xPaddingPlacement` outside {``, `cookie`, `header`, `query`,
    /// `queryInHeader`} (empty = Xray's `queryInHeader` default).
    XhttpPaddingPlacementInvalid,
    /// XHTTP `xPaddingMethod` outside {``, `repeat-x`, `tokenish`} (empty =
    /// Xray's `repeat-x` default).
    XhttpPaddingMethodInvalid,
    /// XHTTP `uplinkDataPlacement` outside {``, `auto`, `body`, `cookie`,
    /// `header`} (empty = `auto`).
    XhttpUplinkDataPlacementInvalid,
    /// XHTTP `uplinkDataPlacement` = `cookie`/`header` outside `packet-up`
    /// mode: Xray only supports cookie/header upload in packet-up.
    XhttpUplinkDataPlacementRequiresPacketUp,
    /// XHTTP `uplinkHTTPMethod` = `GET` outside `packet-up` mode: Xray
    /// only allows the GET upload method in packet-up (empty = `POST`).
    XhttpUplinkHttpMethodRequiresPacketUp,
    /// XHTTP `sessionIDPlacement` outside {``, `path`, `cookie`, `header`,
    /// `query`} (empty = Xray's `path` default).
    XhttpSessionIdPlacementInvalid,
    /// XHTTP `seqPlacement` outside {``, `path`, `cookie`, `header`,
    /// `query`} (empty = Xray's `path` default).
    XhttpSeqPlacementInvalid,
    /// XHTTP `sessionIDTable` set without `sessionIDLength`: Xray refuses
    /// the pair unless a length range is present.
    XhttpSessionIdLengthRequired,
    /// XHTTP `sessionIDTable`/`sessionIDLength` cannot open Xray's required
    /// 2^31 key space: a non-ASCII table, a `length.from` ≤ 0 (or reversed
    /// range), or simply too few combinations for the table alphabet.
    XhttpSessionIdTableInvalid,
    /// XHTTP xmux `maxConnections` and `maxConcurrency` both in use
    /// (`to > 0` each): Xray refuses them together.
    XhttpXmuxLimitsExclusive,
    /// Inbound sniffing `destOverride` item outside {http, tls/https/ssl,
    /// quic, fakedns, fakedns+others} (case-insensitive): Xray's
    /// SniffingConfig build rejects unknown protocols (infra/conf/xray.go).
    /// Fires from `validate_sniffing` for the local-inbound and dokodemo
    /// rows (Error tier — it gates generate/apply exactly like Xray's load
    /// refusal).
    SniffingDestOverrideInvalid,
    /// Outbound `targetStrategy` non-empty and outside Xray's strategy
    /// vocabulary {asis, useip, useipv4, useipv6, useipv4v6, useipv6v4,
    /// forceip, forceipv4, forceipv6, forceipv4v6, forceipv6v4}
    /// (case-insensitive — Xray lowercases, infra/conf/xray.go
    /// OutboundDetectorConfig.Build): the conf load rejects the outbound.
    /// Empty stays legal (the wire default `asis`).
    OutboundTargetStrategyInvalid,
    /// Sockopt `tproxy` outside {off, tproxy, redirect}: Xray lowercases
    /// the value and silently maps every other string to Off
    /// (infra/conf/transport_sockopt.go) — a typo runs without
    /// transparency, but the config loads and the wire works, so this is a
    /// configuration warning (Severity::Warning).
    SockoptTproxySilentOff,
    /// mKCP `mtu` outside the documented [576, 1460] or `tti` outside the
    /// documented [10, 100] (docs mkcp.md; values outside Xray's hard load
    /// bounds — mtu ≥ 21, tti 10..=1000 — are refused separately as
    /// [`KcpRangeInvalid`]). The wire works — this is docs-soft advisory
    /// only (Severity::Warning); the value is legal, just
    /// outside the band Xray's documentation recommends.
    KcpRangeSoft,
    /// mKCP `mtu` below 21 or `tti` outside [10, 1000]: Xray's
    /// KCPConfig.Build refuses the config at load ("Mtu must be at least
    /// 21", "invalid mKCP TTI" — infra/conf/transport_method.go); the
    /// import grammar refuses the same band. Severity::Error (the
    /// docs-soft [`KcpRangeSoft`] warning stays exclusive to values Xray
    /// accepts).
    KcpRangeInvalid,
    /// XHTTP `serverMaxHeaderBytes` negative: Xray's SplitHTTPConfig.Build
    /// refuses it at load (infra/conf/transport_method.go) and the
    /// share-link grammar refuses it on import — the model closes the
    /// state path. Severity::Error.
    XhttpServerMaxHeaderBytesInvalid,
    /// gRPC `idle_timeout`/`health_check_timeout`/`initial_windows_size`
    /// negative: Xray silently clamps negatives to zero
    /// (infra/conf/transport_method.go GRPCConfig.Build). Zero is
    /// intentional on all three (dial.go attaches keepalive only for
    /// `> 0`, and the window option only for `> 0` — clamped 0 = Xray's
    /// default), so only negatives warn (Severity::Warning).
    GrpcNegativeClamp,
    // ---- mux-block semantics (validate_outbound) ----
    //
    // Mux is a local-only model block — the share-link grammar never sees
    // it and the editor combo/slider are keystroke constraints that cannot
    // see deserialized values — so this model pass is the single
    // validation seam. Error tier where Xray refuses the config at load,
    // Warning tier where Xray silently reinterprets or ignores the value.
    /// Mux `xudpProxyUDP443` outside {`reject`, `allow`, `skip`}: Xray's
    /// mux Build refuses unknown values at conf load (infra/conf/xray.go
    /// MuxConfig.Build — an exact, case-sensitive switch). Empty is legal
    /// and defaults to `reject` on the wire, so only non-empty
    /// out-of-vocabulary values fire.
    MuxXudpProxyUdp443Unsupported,
    /// Mux `concurrency`, while `mux.enabled`, naming a value Xray
    /// silently reinterprets: `0` runs as 8, values above 128 clamp to
    /// 128, and any negative other than the documented `-1` TCP-direct
    /// escape disables mux entirely (proxy outbound handler; docs
    /// outbound.md MuxObject bounds [1, 128]). The config loads and the
    /// wire works — advisory (Severity::Warning); the message
    /// names the effective behavior.
    MuxConcurrencyReinterpreted,
    /// Mux XUDP knobs (`xudpConcurrency` / `xudpProxyUDP443`) set while
    /// `mux.enabled` is false: Xray reads the knobs only inside the
    /// `Enabled` block, so the whole XUDP side is silently ignored (proxy
    /// outbound handler) — dead-knob class E, advisory
    /// (Severity::Warning).
    MuxXudpKnobsInert,
    // ---- extra-passthrough scans (validate_outbound per-settings extras +
    //      validate_stream transport extras) ----
    //
    // serde binds only the exact-case modeled fields; any other key lands in
    // a settings `extra` flatten map and ships verbatim into the generated
    // config. Go's JSON unmarshal matches struct fields case-insensitively,
    // so these scans look the extra maps over case-insensitively for the
    // known removed/inert keys. Disposition: removed-feature keys are Error
    // (Xray refuses the config at load — the MasterKeyLogNotSupported
    // precedent), accepted-then-ignored keys are Warning (advisory, never
    // gates).
    /// Trojan `settings.flow` (removed-feature load error): Xray's
    /// TrojanClientConfig.Build refuses a non-empty flow with
    /// PrintRemovedFeatureError (conf/trojan.go), and its deprecation note
    /// points to VLESS with a vision flow.
    TrojanFlowRemoved,
    /// mKCP `stream.kcpSettings.seed` / `.header` (removed-feature load
    /// error): KCPConfig.Build refuses a set seed or header object with
    /// PrintRemovedFeatureError naming the finalmask UDP masks as the
    /// migration (conf/transport_method.go). JSON `null` is the Go zero
    /// shape and stays silent.
    KcpSeedHeaderRemoved,
    /// mKCP `stream.kcpSettings.headerType`: never an Xray JSON key (the
    /// old camouflage object is `header`, `headerType` exists only in
    /// share links), so Xray's unmarshal silently ignores it — advisory
    /// (Severity::Warning).
    KcpHeaderTypeIgnored,
    /// VMess `settings.alterId` / `settings.aid` (inert): the legacy
    /// alterId field is gone from Xray's conf struct (conf/vmess.go has no
    /// such field — VMess is AEAD-only) and any carried value is silently
    /// ignored — advisory (Severity::Warning).
    VmessAlterIdIgnored,
    /// VLESS `settings.seed` (inert): VLessOutboundConfig still parses the
    /// key but the Build assignment is commented out upstream
    /// (conf/vless.go), so the carried value is silently dropped — advisory
    /// (Severity::Warning).
    VlessSeedIgnored,
    /// Freedom `settings.noise` (removed-feature load error): Xray's
    /// FreedomConfig.Build refuses a non-null singular `noise` object with
    /// PrintRemovedFeatureError naming the `noises` array as the migration
    /// (conf/freedom.go). JSON `null` is the Go zero shape and stays
    /// silent. The modeled `noises` field is never affected.
    FreedomNoiseRemoved,
    /// Freedom `settings.domainStrategy` outside Xray's strategy
    /// vocabulary (conf/freedom.go Build switch — the same ten
    /// case-insensitive values as the outbound `targetStrategy` rule):
    /// freedom reads `domainStrategy` whenever `targetStrategy` is empty,
    /// so in-vocabulary values work on the wire and stay silent; every
    /// other non-null value (non-string JSON shapes included — Go's
    /// `string` unmarshal fails) refuses the outbound at load. The field
    /// is unmodeled, so this extra scan is its only seam.
    FreedomDomainStrategyUnsupported,
    /// REALITY server-form keys (`dest`, `target`, `privateKey`,
    /// `serverNames`, `shortIds`, `mldsa65Seed`) carried on a client
    /// profile: a client REALITY build never reads them, and a set
    /// dest/target flips REALITYConfig.Build onto the server branch
    /// (conf/transport_security.go), so an outbound carrying them cannot
    /// behave as a client. They are carried verbatim and Xray accepts the
    /// config — advisory (Severity::Warning; refusal could
    /// false-positive on tooling that deliberately carries server-form
    /// material).
    RealityServerFormKeysInert,
    /// Hysteria2 `stream.hysteriaSettings.congestion` / `.up` / `.down` /
    /// `.udphop` (accepted then dropped): HysteriaConfig still parses the
    /// legacy QUIC knobs, logs an upstream warning and discards them — the
    /// values moved to `finalmask.quicParams` (`congestion`, `brutalUp` /
    /// `brutalDown`, `udpHop`) — so the config loads and runs without the
    /// knobs — advisory (Severity::Warning). JSON `null` is the
    /// Go zero shape and stays silent.
    HysteriaQuicKnobsMoved,
    /// XHTTP `xhttpSettings.extra` holds a key that names a modeled xhttp
    /// setting: the extra value overrides it.
    /// serde flatten emits the extra value over the typed field on export,
    /// and Xray's SplitHTTPConfig.Build additionally replaces the whole
    /// outer object with the nested `extra` object except host/path/mode
    /// (infra/conf/transport_method.go). Live repro 2026-09-06 on Xray
    /// 26.7.28: outer `xPaddingMethod: "tokenish"` + extra
    /// `xPaddingMethod: "bogus"` refuses with "unsupported padding method:
    /// bogus" (the edited value never reaches Xray; the refusal cites the
    /// extra's), while an extra `mode` key is ignored (host/path/mode are
    /// protected on the nested path — but NOT through broccoli's flatten).
    /// Configuration warning (class E, Severity::Warning): the
    /// code carries the offending key.
    XhttpExtraShadowsSettings(String),

    // ---- draft requirements ----
    //
    // The rules below judge a *server draft*: the empty field a fresh draft
    // starts from, the value a widget can only judge while the user types it.
    // Every one of them is a value the wire accepts — Xray builds a config
    // with an empty id or an empty WireGuard peer list as readily as it
    // builds an empty string — so no model sweep emits them and no stored
    // profile is refused for carrying them. The editor's own sweep emits them
    // so a draft rule has an identity (code + tier) instead of a rendered
    // sentence. Their messages name the field the user is looking at, so none
    // carries a wire path.
    /// The profile's protocol tag and its `settings` block name different
    /// protocols: serde binds the two independently, so a hand-edited state
    /// file can disagree, and every model rule reads one of them.
    ProtocolSettingsMismatch,
    /// A server address field is empty (`settings.address`). An outbound
    /// dialing the empty host fails every connection.
    ServerAddressRequired,
    /// A server port field is zero (`settings.port`).
    ServerPortRequired,
    /// VLESS `settings.id` is empty. Xray builds the config and the handler
    /// rejects every connection for lack of a user id.
    VlessIdRequired,
    /// VLESS `settings.encryption` is empty — the handler's encryption
    /// factory refuses it (`proxy/vless/outbound/outbound.go`: "failed to use
    /// encryption"). The *value* grammar is [`Self::VlessEncryptionUnsupported`];
    /// this code is the missing-value state.
    VlessEncryptionRequired,
    /// VLESS `settings.reverse.tag` is set but empty: the reverse tag is the
    /// outbound's own tag on the wire, and an empty one cannot be routed to.
    VlessReverseTagRequired,
    /// VMess `settings.id` is empty — the same missing-user state as
    /// [`Self::VlessIdRequired`].
    VmessIdRequired,
    /// VMess `settings.security` is outside the vocabulary Xray's
    /// `proxy/vmess/outbound` reads, so the core refuses connection attempts
    /// with an unknown cipher instead of falling back to `auto`.
    VmessSecurityUnsupported,
    /// WireGuard `settings.secretKey` is not the base64 of 32 bytes the
    /// Noise handshake needs (`proxy/wireguard/device` key parsing).
    WireguardSecretKeyInvalid,
    /// WireGuard `settings.reserved` is set but not exactly three bytes: the
    /// value is spliced into the header ahead of the handshake
    /// (`proxy/wireguard/client.go`), so any other length corrupts it.
    WireguardReservedKeyBytes,
    /// WireGuard `settings.peers` is empty: a peer-less tunnel has nothing to
    /// hand a packet to.
    WireguardPeersRequired,
    /// A WireGuard peer's `publicKey` is not the base64 of 32 bytes.
    WireguardPeerPublicKeyRequired,
    /// A WireGuard peer's `endpoint` is empty: the dial has no target.
    WireguardPeerEndpointRequired,
    /// A set WireGuard peer `preSharedKey` is not the base64 of 32 bytes the
    /// handshake mixes in.
    WireguardPresharedKeyInvalid,
    /// Freedom `settings.fragment` cannot run: Xray's fragment manager
    /// requires a positive length range and a non-decreasing interval range.
    FreedomFragmentInvalid,
    /// A Freedom `settings.noises` entry cannot run: its `type`, `packet`
    /// payload and `applyTo` value must each match the shape Xray's noise
    /// manager reads.
    FreedomNoiseInvalid,
    /// Loopback `settings.inboundTag` is empty: the outbound hands the
    /// connection back to the inbound it names, and no inbound carries the
    /// empty tag.
    LoopbackTagRequired,
}

/// Advisory tier of a [`ValidationIssue`]. `Error` findings block
/// save/import/generation/apply; `Warning` findings never gate
/// anything — they render amber and advisory wherever issues render.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

/// One validation finding: a rule, the wire path that failed (absent for
/// whole-model findings), and its advisory tier. Every non-warning rule is
/// [`Severity::Error`]; only the new configuration-warning rules are
/// [`Severity::Warning`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationIssue {
    pub code: ValidationCode,
    pub path: Option<String>,
    pub severity: Severity,
}

impl ValidationIssue {
    /// An error-tier finding with no wire path: the rule is about the profile
    /// as a whole, or its message names the field the user is looking at, so
    /// no path is prefixed.
    pub fn error(code: ValidationCode) -> Self {
        ValidationIssue {
            code,
            path: None,
            severity: Severity::Error,
        }
    }
}

fn issue(code: ValidationCode, path: Option<String>) -> ValidationIssue {
    ValidationIssue {
        code,
        path,
        severity: Severity::Error,
    }
}

fn warning(code: ValidationCode, path: Option<String>) -> ValidationIssue {
    ValidationIssue {
        code,
        path,
        severity: Severity::Warning,
    }
}

/// True when an `extra` map carries `key` (ASCII-case-insensitively — Go's
/// JSON unmarshal binds struct fields case-insensitively, so every case
/// variant reaches the same wire field). Presence is the test: the broker
/// never emits these keys itself, so any carried spelling is foreign
/// material worth flagging.
fn extra_has_key(extra: &Map<String, Value>, key: &str) -> bool {
    extra
        .keys()
        .any(|candidate| candidate.eq_ignore_ascii_case(key))
}

/// True when an `extra` map carries `key` with a value Go treats as "set":
/// anything but JSON `null`, which unmarshals to the Go zero value and
/// leaves pointer fields nil / strings empty.
fn extra_key_set(extra: &Map<String, Value>, key: &str) -> bool {
    extra
        .iter()
        .any(|(candidate, value)| candidate.eq_ignore_ascii_case(key) && !value.is_null())
}

/// The vision (XRV) flow spellings Xray's XRV servers accept, in display
/// order — the set [`is_vision_flow`] judges. Spelled once: the
/// transport-security rule, the mux+vision warning, the share-link grammar
/// and the VLESS flow combo all reach it through these two items.
pub const VISION_FLOW_OPTIONS: &[&str] = &["xtls-rprx-vision", "xtls-rprx-vision-udp443"];

/// True when a VLESS `flow` is one of the two vision (XRV) variants.
pub fn is_vision_flow(flow: &str) -> bool {
    VISION_FLOW_OPTIONS.contains(&flow)
}

/// Mux/vision predicate (shared with the editor's targeted-inline hints, so
/// the model and the UI can never disagree): true when a VLESS profile
/// combines a vision flow with TCP-carrying mux:
/// Xray's XRV servers reject TCP frames over mux (breaking the whole mux
/// connection on the first one), so such a profile cannot work. `concurrency
/// = -1` is the TCP-direct escape hatch — XUDP stays available, so it never
/// warns; the XUDP knobs (`xudpConcurrency`/`xudpProxyUDP443`) do NOT
/// suppress the warning, because TCP rides smux whenever mux is enabled with
/// a non-negative concurrency.
pub fn mux_conflicts_with_vision_flow(
    flow: &str,
    mux_enabled: bool,
    mux_concurrency: Option<i16>,
) -> bool {
    is_vision_flow(flow) && mux_enabled && mux_concurrency != Some(-1)
}

/// The `xudpProxyUDP443` vocabulary: the three modes Xray's mux Build
/// accepts verbatim (infra/conf/xray.go MuxConfig.Build — an exact,
/// case-sensitive switch; empty is separately legal and defaults to
/// `reject` on the wire). Shared with the editor combo, so the offered
/// choices and this refusal predicate can never disagree.
pub const XUDP_PROXY_UDP443_MODES: &[&str] = &["reject", "allow", "skip"];

/// True when a `xudpProxyUDP443` is legal on the wire —
/// empty (Xray defaults it to `reject`) or one of {reject, allow, skip}.
/// Xray's conf build refuses every other value (infra/conf/xray.go:
/// 110-117), including case variants — the switch never lowercases.
fn xudp_proxy_udp443_supported(value: &str) -> bool {
    value.is_empty() || XUDP_PROXY_UDP443_MODES.contains(&value)
}

/// Concurrency reinterpretation: true when mux is
/// enabled with a `concurrency` value Xray silently changes the meaning
/// of — `0` runs as 8, values above 128 clamp to 128, and any negative
/// other than the documented `-1` TCP-direct escape disables mux entirely
/// (proxy outbound handler; docs outbound.md MuxObject bounds [1, 128]).
/// Disabled blocks never fire: Xray reads `concurrency` only inside the
/// `Enabled` branch, so an out-of-band value there is a dead knob, not a
/// reinterpretation. `-1` and 1..=128 never fire.
fn mux_concurrency_reinterpreted(mux_enabled: bool, concurrency: Option<i16>) -> bool {
    mux_enabled && concurrency.is_some_and(|c| c == 0 || !(-1..=128).contains(&c))
}

/// Dead XUDP knobs: true when an XUDP knob is set
/// while `mux.enabled` is off — Xray reads `xudpConcurrency` /
/// `xudpProxyUDP443` only inside the `Enabled` block (proxy outbound
/// handler), so the whole XUDP side is silently ignored.
fn mux_xudp_knobs_inert(m: &MuxModel) -> bool {
    !m.enabled && (m.xudp_concurrency.is_some() || m.xudp_proxy_udp443.is_some())
}

/// Predicate shared with the editor's targeted-inline hints: true when a
/// TLS/REALITY `serverName` cannot plausibly be a hostname or IP
/// literal — canonical UUID (8-4-4-4-12 hex, case-insensitive), exactly 32
/// hex characters, or any character that can never appear in a DNS name or
/// IP literal (anything outside ASCII alphanumerics, `-._:`, and Unicode
/// alphanumerics). IP literals (v4/v6), punycode and raw-unicode IDN forms,
/// single labels, and underscore labels never warn; empty is out of scope
/// (no editor-side rule covers it — the xray `run -test` report does).
pub fn server_name_implausible(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    // Canonical 8-4-4-4-12 UUID (hex is case-insensitive). Byte positions
    // 8/13/18/23 must hold the dashes; non-ASCII bytes fail hexdigit, so a
    // multibyte string of the same byte length cannot slip through.
    let uuid_shaped = value.len() == 36
        && value.as_bytes().iter().enumerate().all(|(i, &byte)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        });
    // Bare 32-hex value.
    let bare_32_hex = value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit());
    uuid_shaped
        || bare_32_hex
        || value
            .chars()
            .any(|c| !(c.is_alphanumeric() || matches!(c, '-' | '.' | '_' | ':')))
}

// ---------- protocol-settings vocabulary ----------
//
// Every predicate here mirrors the share-link import grammar (the
// `validate_profile` whitelists in `crate::links`) and the Xray conf
// builders they cite, so the model seam, the import grammar, and the
// editor never disagree about a value's acceptability. Keep the two
// mirrors in lockstep: same literals, same comparisons. The VLESS
// encryption rule is not mirrored but shared: `vless_encryption_supported`
// lives in `super::outbound`, and the model pass, the import grammar, and
// the editor validator all call it. The UUID rule is shared the same way:
// `is_canonical_uuid` below is its one definition, and the import grammar,
// the finalmask validator, and the editor validator call it.

/// True when a VLESS `flow` is acceptable on the wire —
/// empty (the default) or one of the two vision (XRV) variants. Xray's conf
/// build rejects every other flow (conf/vless.go).
fn vless_flow_supported(flow: &str) -> bool {
    flow.is_empty() || is_vision_flow(flow)
}

/// The VMess `settings.security` vocabulary: the ciphers Xray's
/// `proxy/vmess/outbound` reads, matched exactly (the core's cipher list is
/// a map lookup, so a case variant is an unknown cipher). The editor combo
/// and the share-link grammar both read this list.
pub const VMESS_SECURITY_OPTIONS: &[&str] = &["auto", "aes-128-gcm", "chacha20-poly1305"];

/// True when a VMess `settings.security` names one of
/// [`VMESS_SECURITY_OPTIONS`].
pub fn vmess_security_supported(security: &str) -> bool {
    VMESS_SECURITY_OPTIONS.contains(&security)
}

/// The AEAD method vocabulary: the canonical spellings, then the legacy
/// aliases Xray's `cipherFromString` folds onto them (each alias sits beside
/// the canonical name it names). Compared case-insensitively.
const SS_AEAD_METHODS: &[&str] = &[
    "aes-128-gcm",
    "aead_aes_128_gcm",
    "aes-256-gcm",
    "aead_aes_256_gcm",
    "chacha20-poly1305",
    "aead_chacha20_poly1305",
    "chacha20-ietf-poly1305",
    "xchacha20-poly1305",
    "aead_xchacha20_poly1305",
    "xchacha20-ietf-poly1305",
];

/// The Shadowsocks-2022 method names, matched exactly by Xray's
/// `shadowaead_2022.List` (a map lookup: a case variant is not a method).
const SS_METHODS_2022: &[&str] = &[
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
];

/// The Shadowsocks method vocabulary the editors offer and the share links
/// spell, in display order: the four canonical AEAD methods, then the 2022
/// methods. Spelled element-wise from the two accepted lists, so the offered
/// set can never hold a method the rule refuses (the legacy alias spellings
/// are accepted but never offered).
pub const SS_METHOD_OPTIONS: &[&str] = &[
    SS_AEAD_METHODS[0],
    SS_AEAD_METHODS[2],
    SS_AEAD_METHODS[6],
    SS_AEAD_METHODS[9],
    SS_METHODS_2022[0],
    SS_METHODS_2022[1],
    SS_METHODS_2022[2],
];

/// True when a Shadowsocks `method` is in Xray's
/// accepted vocabulary — the AEAD methods and their legacy alias spellings
/// (case-insensitive, `cipherFromString`) plus the exact 2022 method names
/// (`shadowaead_2022.List`). Legacy *stream* ciphers (e.g. `aes-256-cfb`)
/// and anything else fall through to the unknown-cipher load error and are
/// unsupported. The share-link grammar calls this predicate instead of
/// re-listing the methods.
pub fn shadowsocks_method_supported(method: &str) -> bool {
    SS_AEAD_METHODS
        .iter()
        .any(|accepted| method.eq_ignore_ascii_case(accepted))
        || SS_METHODS_2022.contains(&method)
}

/// True when a Shadowsocks-2022 `password` is usable key
/// material for `method` — base64 (padded or raw) decoding to exactly the
/// method's key length (16 B for `2022-blake3-aes-128-gcm`, 32 B for
/// `2022-blake3-aes-256-gcm` / `2022-blake3-chacha20-poly1305`), with the
/// ChaCha20 2022 method rejecting the multi-psk colon-separated form. Any
/// other method treats the password as opaque. Mirrors `links`'
/// `validate_2022_key`. Empty passwords pass here — the required-value rule
/// (`ShadowsocksSettingsIncomplete`, Error) owns them, and Xray's conf build
/// rejects them outright.
fn shadowsocks_2022_key_supported(method: &str, password: &str) -> bool {
    let key_len = match method {
        "2022-blake3-aes-128-gcm" => 16,
        "2022-blake3-aes-256-gcm" | "2022-blake3-chacha20-poly1305" => 32,
        _ => return true,
    };
    if password.is_empty() {
        return true;
    }
    if method == "2022-blake3-chacha20-poly1305" && password.contains(':') {
        return false;
    }
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
    password.split(':').all(|key| {
        base64::Engine::decode(&STANDARD, key)
            .or_else(|_| base64::Engine::decode(&STANDARD_NO_PAD, key))
            .is_ok_and(|decoded| decoded.len() == key_len)
    })
}

/// The UUID format policy, one definition: true when an id is a canonical
/// UUID under `uuid::Uuid::parse_str`. Xray itself sha1-maps 1-30-char
/// strings to a deterministic v5 UUID (common/uuid/uuid.go) and accepts
/// 32-36-char hex forms, so only a true UUID dials the configured account.
/// The import grammar's `check_uuid`, the finalmask XMC validator, and the
/// editor's UUID field validator all call this predicate, each keeping only
/// its own message channel.
pub(crate) fn is_canonical_uuid(id: &str) -> bool {
    uuid::Uuid::parse_str(id).is_ok()
}

// ---------- transport-security formats ----------
//
// Single-source predicates for the TLS/REALITY security-format rules. The
// share-link import grammar
// (`validate_reality` / `validate_tls` in `crate::links`) delegates its
// shape checks to these predicates and the editor's keygen guards call
// them, so import, model, and editor can never disagree about a value's
// acceptability. Fingerprint vocabulary lives in `crate::model::fingerprint`
// (the canonical tables); this module only consumes its predicates.

/// Predicate shared with the share-link grammar's pbk check and the editor's
/// derive guard: true when the REALITY client `publicKey` (stored in the
/// profile's `password` field, the upstream alias) is an unpadded base64url
/// string decoding to exactly 32 bytes. Empty is invalid
/// — Xray's conf build refuses an empty key (`empty "password"`) and the
/// import grammar requires it.
pub fn reality_public_key_valid(value: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|decoded| decoded.len() == 32)
}

/// mKCP hard load bound (shared with the share-link grammar's kcp check):
/// true when `mtu` satisfies Xray's KCPConfig.Build floor of 21
/// (infra/conf/transport_method.go: "Mtu must be at least 21").
pub fn kcp_mtu_hard_ok(mtu: u32) -> bool {
    mtu >= 21
}

/// mKCP hard load bound (shared with the share-link grammar's kcp check):
/// true when `tti` lies within Xray's KCPConfig.Build window [10, 1000]
/// (infra/conf/transport_method.go: "invalid mKCP TTI").
pub fn kcp_tti_hard_ok(tti: u32) -> bool {
    (10..=1000).contains(&tti)
}

/// XHTTP load bound (shared with the share-link grammar's xhttp check):
/// true when `serverMaxHeaderBytes` is non-negative —
/// SplitHTTPConfig.Build refuses negatives (infra/conf/transport_method.go).
pub fn server_max_header_bytes_ok(value: i32) -> bool {
    value >= 0
}

/// Predicate shared with the share-link grammar's sid check:
/// true when the REALITY `shortId` is empty (the default) or an even-length
/// hex value of at most 16 characters — the exact set Xray hex-decodes into
/// its 8-byte short id without error (conf/transport_security.go; Go's
/// hex.Decode rejects odd-length and non-hex input).
pub fn reality_short_id_valid(value: &str) -> bool {
    value.is_empty()
        || (value.len() <= 16
            && value.len().is_multiple_of(2)
            && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

/// Predicate shared with the share-link grammar's spx check:
/// true when the REALITY `spiderX` is empty (Xray defaults it to `/`) or a
/// URL path beginning with `/` with no control characters — the shape Xray's
/// conf build accepts and its query rewriter can parse
/// (conf/transport_security.go client branch).
pub fn reality_spider_x_valid(value: &str) -> bool {
    value.is_empty()
        || (value.starts_with('/')
            && !value.bytes().any(|byte| byte.is_ascii_control())
            && url::Url::parse(&format!("https://reality.invalid{value}")).is_ok())
}

/// Predicate shared with the share-link grammar's pqv check and the editor's
/// keygen guard: true when the REALITY `mldsa65Verify` is
/// empty (no post-quantum verification key) or an unpadded base64url string
/// decoding to the 1952-byte ML-DSA-65 public key
/// (conf/transport_security.go client branch).
pub fn reality_mldsa65_verify_valid(value: &str) -> bool {
    value.is_empty()
        || URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|decoded| decoded.len() == 1952)
}

/// Predicate shared with the share-link grammar's pcs check:
/// true when `pinnedPeerCertSha256` is empty or every comma-separated entry
/// (whitespace-trimmed, colons stripped) is exactly 64 hex digits — 32
/// bytes of SHA-256 fingerprint, the shape Xray's conf build decodes
/// (conf/transport_security.go).
pub fn pinned_peer_cert_sha256_valid(value: &str) -> bool {
    value
        .split(',')
        .map(str::trim)
        .filter(|pin| !pin.is_empty())
        .all(|pin| {
            let compact = pin.replace(':', "");
            compact.len() == 64 && compact.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

/// The TLS version vocabulary Xray's transport layer maps onto a concrete
/// TLS version (transport/internet/tls/config.go switches); every other
/// string is accepted by the conf loader but silently dropped, leaving the
/// Go defaults in place. Empty is the field's wire default rather than a
/// version — the rules that judge a version check emptiness themselves — so
/// it is not an entry here; the version combos add their own empty display
/// entry.
pub const TLS_VERSION_OPTIONS: &[&str] = &["1.0", "1.1", "1.2", "1.3"];

/// True when `version` names one of [`TLS_VERSION_OPTIONS`].
pub fn tls_version_supported(version: &str) -> bool {
    TLS_VERSION_OPTIONS.contains(&version)
}

/// Monotonic rank of one wire TLS version in {1.0, 1.1, 1.2, 1.3} — the
/// shared ordering predicate for the in-range min > max rule. Out-of-range
/// strings rank None (they are `TlsVersionRangeInvalid`'s business).
pub fn tls_version_rank(version: &str) -> Option<u8> {
    match version {
        "1.0" => Some(10),
        "1.1" => Some(11),
        "1.2" => Some(12),
        "1.3" => Some(13),
        _ => None,
    }
}

// ---------- stream/sockopt/strategy enum surfaces ----------
//
// The XHTTP predicates below are the single definition of each vocabulary /
// cross-field rule, shared with the share-link xhttp grammar
// (`crate::links::validate_xhttp`) so the import seam and the model seam
// cannot drift (the `is_vision_flow` pattern). The upstream
// mirror is Xray's SplitHTTPConfig.Build (infra/conf/transport_method.go:
// 317-459): every non-`""` value outside the sets below is refused at Xray
// conf load, and `""` is always the wire default of the field it feeds.

/// The XHTTP `mode` vocabulary: empty (wire default `auto`) or one of the
/// four modes. Xray's conf build rejects every other string ("unsupported
/// mode"). The editor's mode combo aliases this list.
pub const XHTTP_MODE_OPTIONS: &[&str] = &["", "auto", "packet-up", "stream-up", "stream-one"];

/// True when an XHTTP `mode` is one Xray accepts — empty (wire default
/// `auto`) or one of the four modes.
pub fn xhttp_mode_supported(mode: &str) -> bool {
    XHTTP_MODE_OPTIONS.contains(&mode)
}

/// The `xPaddingPlacement` vocabulary: empty (wire default `queryInHeader`)
/// or one of the four placements Xray accepts.
pub const X_PADDING_PLACEMENT_OPTIONS: &[&str] =
    &["", "cookie", "header", "query", "queryInHeader"];

/// True when an `xPaddingPlacement` is one of
/// [`X_PADDING_PLACEMENT_OPTIONS`].
pub fn xpadding_placement_supported(placement: &str) -> bool {
    X_PADDING_PLACEMENT_OPTIONS.contains(&placement)
}

/// The `xPaddingMethod` vocabulary: empty (wire default `repeat-x`) or one
/// of the two methods Xray accepts.
pub const XPADDING_METHOD_OPTIONS: &[&str] = &["", "repeat-x", "tokenish"];

/// True when an `xPaddingMethod` is one of [`XPADDING_METHOD_OPTIONS`].
pub fn xpadding_method_supported(method: &str) -> bool {
    XPADDING_METHOD_OPTIONS.contains(&method)
}

/// The `uplinkDataPlacement` vocabulary: empty (wire default `auto`) or one
/// of the four placements Xray accepts.
pub const UPLINK_DATA_PLACEMENT_OPTIONS: &[&str] = &["", "auto", "body", "cookie", "header"];

/// True when an `uplinkDataPlacement` is one of
/// [`UPLINK_DATA_PLACEMENT_OPTIONS`].
pub fn uplink_data_placement_supported(placement: &str) -> bool {
    UPLINK_DATA_PLACEMENT_OPTIONS.contains(&placement)
}

/// The `sessionIDPlacement` vocabulary: empty (wire default `path`) plus the
/// four placements Xray accepts.
pub const SESSION_ID_PLACEMENT_OPTIONS: &[&str] = &["", "path", "cookie", "header", "query"];

/// True when a `sessionIDPlacement` is one of
/// [`SESSION_ID_PLACEMENT_OPTIONS`].
pub fn session_id_placement_supported(placement: &str) -> bool {
    SESSION_ID_PLACEMENT_OPTIONS.contains(&placement)
}

/// `seqPlacement` uses exactly the sessionID placement vocabulary upstream;
/// one list and one predicate.
pub const SEQ_PLACEMENT_OPTIONS: &[&str] = SESSION_ID_PLACEMENT_OPTIONS;

/// True when a `seqPlacement` is one of [`SEQ_PLACEMENT_OPTIONS`].
pub fn seq_placement_supported(placement: &str) -> bool {
    SEQ_PLACEMENT_OPTIONS.contains(&placement)
}

/// True when an `xPaddingBytes` range is acceptable —
/// absent or zero (padding off) or a range with both bounds positive. Xray
/// refuses any other shape ("xPaddingBytes cannot be disabled").
pub fn xpadding_bytes_supported(range: Option<Int32Range>) -> bool {
    !range.is_some_and(|range| {
        (range.from != 0 || range.to != 0) && (range.from <= 0 || range.to <= 0)
    })
}

/// Cross-field predicates: Xray supports cookie/header upload
/// placement and the GET upload method only in `packet-up` mode. Empty mode
/// means `auto` on the wire, so `mode != "packet-up"` is the exact refusal
/// condition in both seams (compare the raw string exactly like upstream's
/// build does).
pub fn uplink_placement_mode_supported(placement: &str, mode: &str) -> bool {
    !matches!(placement, "cookie" | "header") || mode == "packet-up"
}

/// Cross-field predicate: `uplinkHTTPMethod` GET only in
/// `packet-up` mode (empty method = the wire default `POST`; Xray compares
/// the uppercased method, hence the case-insensitive GET test).
pub fn uplink_http_method_mode_supported(method: &str, mode: &str) -> bool {
    !method.eq_ignore_ascii_case("GET") || mode == "packet-up"
}

/// XHTTP xmux `maxConnections` and `maxConcurrency` are
/// mutually exclusive while both are in use. Xray compares the ranges'
/// upper bounds (`To > 0`), so a range whose `to` is 0 is the "not in use"
/// wire shape in both seams.
pub fn xmux_limits_conflict(xmux: Option<&XmuxConfig>) -> bool {
    xmux.is_some_and(|xmux| {
        xmux.max_connections.is_some_and(|range| range.to > 0)
            && xmux.max_concurrency.is_some_and(|range| range.to > 0)
    })
}

/// Predicate shared with the xhttp grammar: true when an ASCII
/// `sessionIDTable` of `table.len()` characters with a `sessionIDLength`
/// range from `range.from` to `range.to` can open Xray's required 2^31 key
/// combinations (the key space is the count of table strings of every
/// length in the range). Mirrors Xray's `roomSize` comparison in
/// SplitHTTPConfig.Build — reversed ranges, `from ≤ 0`, and non-ASCII
/// tables all fail here exactly like upstream.
pub(crate) fn range_has_session_room(table: &str, range: crate::model::Int32Range) -> bool {
    if range.from <= 0 || range.to < range.from || !table.is_ascii() {
        return false;
    }
    let table_len = match table {
        "ALPHABET" | "alphabet" => 26,
        "Alphabet" => 52,
        "BASE36" | "base36" => 36,
        "Base62" => 62,
        "HEX" | "hex" => 16,
        "number" => 10,
        custom => custom.len(),
    };
    if table_len < 2 {
        return false;
    }
    // The smallest possible base is two, so any term with exponent 31 or
    // greater already reaches Xray's required 2^31 key space.
    if range.from >= 31 {
        return true;
    }
    let base = table_len.min(u64::MAX as usize) as u64;
    let required = 2_u64 << 30;
    let mut power = 1_u64;
    let mut total = 0_u64;
    for exponent in 1..=range.to.min(64) {
        power = power.saturating_mul(base);
        if exponent >= range.from {
            total = total.saturating_add(power);
            if total >= required {
                return true;
            }
        }
    }
    false
}

/// Sockopt `tproxy` vocabulary — the three values Xray accepts, shared with
/// the warning predicate below so the accepted set and the check can never
/// disagree. `off` is the explicit spelling of Xray's default
/// (SocketConfig_Off) and is honored as-is; `tproxy` and `redirect` are the
/// two active modes (infra/conf/transport_sockopt.go). The structured editor
/// renders no widget for this field (its Linux-only readers are the only
/// consumers), so the vocabulary is reachable only through a hand-edited
/// profile or the raw config override.
pub const TPROXY_MODES: &[&str] = &["off", "redirect", "tproxy"];

/// The target-domain-strategy vocabulary: every value Xray's outbound
/// `targetStrategy` switch and freedom `domainStrategy` switch accept
/// (infra/conf/xray.go OutboundDetectorConfig.Build and conf/freedom.go read
/// the same word list). Comparison folds case — Xray lowercases the value
/// before switching — and empty is the wire default (`asis`), which the
/// rules that judge a strategy check themselves. The strategy combos alias
/// this list.
pub const TARGET_STRATEGY_OPTIONS: &[&str] = &[
    "AsIs",
    "UseIP",
    "UseIPv4",
    "UseIPv6",
    "UseIPv4v6",
    "UseIPv6v4",
    "ForceIP",
    "ForceIPv4",
    "ForceIPv6",
    "ForceIPv6v4",
    "ForceIPv4v6",
];

/// True when `target_strategy` names one of Xray's
/// outbound target domain strategies, case-insensitively — Xray lowercases
/// the value before its switch (infra/conf/xray.go OutboundDetectorConfig
/// Build). Empty stays legal (the wire default `asis`).
fn target_strategy_supported(strategy: &str) -> bool {
    TARGET_STRATEGY_OPTIONS
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(strategy))
}

/// True when a freedom `domainStrategy`
/// value names one of the strategies Xray's FreedomConfig.Build switch
/// accepts — the very same word list as the outbound `targetStrategy`
/// rule, compared the same case-insensitive way (Xray lowercases before
/// switching, conf/freedom.go). Empty is separately legal (the wire
/// default `asis`).
fn freedom_domain_strategy_supported(strategy: &str) -> bool {
    target_strategy_supported(strategy)
}

/// The `settings.domainStrategy` vocabulary the WireGuard editor offers —
/// the resolution strategies the core's WireGuard endpoint dial runs a peer
/// host through, plus the empty zero value that leaves the core's own
/// `forceip` default in place. The combo offers the list verbatim, and the
/// dial keeps its own default for an unknown value, so no rule judges one.
pub const WG_TARGET_STRATEGY_OPTIONS: &[&str] = &[
    "",
    "ForceIP",
    "ForceIPv4",
    "ForceIPv6",
    "ForceIPv4v6",
    "ForceIPv6v4",
];

// ---------- outbound envelope / DNS-rule vocabularies ----------
//
// These three rules used to live only in the servers editor's error list.
// They decide whether the configuration is valid, so the model pass owns
// them now: [`validate_outbound`] reports the codes, and the editor's
// inline hints and combos call these same predicates instead of carrying
// private copies.

/// True when a freedom `finalRules[].action` is one Xray's freedom build
/// accepts — `allow` or `block`, compared case-insensitively (the editor
/// combo offers exactly these spellings).
pub fn freedom_final_rule_supported(action: &str) -> bool {
    matches!(action.to_ascii_lowercase().as_str(), "allow" | "block")
}

/// The DNS-out `rules[].action` vocabulary — the four actions Xray's DNS
/// config build accepts. The editor combo additionally offers the empty
/// "(default)" display entry; an empty action is not an action.
pub const DNS_OUT_ACTIONS: &[&str] = &["direct", "drop", "return", "hijack"];

/// True when a DNS-out `rules[].action` names one of [`DNS_OUT_ACTIONS`].
pub fn dns_out_action_supported(action: &str) -> bool {
    DNS_OUT_ACTIONS.contains(&action)
}

/// True when a `sendThrough` value is one Xray's dialer accepts —
/// `origin`/`srcip` or an IP address / CIDR literal.
pub fn send_through_supported(value: &str) -> bool {
    matches!(value, "origin" | "srcip")
        || value.parse::<std::net::IpAddr>().is_ok()
        || value.parse::<cidr_shim::Cidr>().is_ok()
}

/// Minimal CIDR parse shim so the sendThrough rule needs no extra dep.
mod cidr_shim {
    pub struct Cidr;
    impl std::str::FromStr for Cidr {
        type Err = ();
        fn from_str(s: &str) -> Result<Self, ()> {
            let (ip, len) = s.split_once('/').ok_or(())?;
            ip.parse::<std::net::IpAddr>().map_err(|_| ())?;
            let n: u8 = len.parse().map_err(|_| ())?;
            let max = if ip.contains(':') { 128 } else { 32 };
            if n > max {
                return Err(());
            }
            Ok(Cidr)
        }
    }
}

/// True when a sniffing `destOverride` item names one
/// of the protocols Xray's SniffingConfig build accepts, case-insensitively
/// (infra/conf/xray.go: http, tls with the https/ssl spellings folded in,
/// quic, and fakedns with the `fakedns+others` spelling folded in). The
/// "fakedns" item the generator appends itself at wire time is part of this
/// vocabulary, so the rule can never false-positive on it.
pub fn sniffing_dest_override_supported(protocol: &str) -> bool {
    [
        "http",
        "tls",
        "https",
        "ssl",
        "quic",
        "fakedns",
        "fakedns+others",
    ]
    .iter()
    .any(|candidate| protocol.eq_ignore_ascii_case(candidate))
}

/// Validate one inbound sniffing block. `prefix`
/// is the state-file path of the sniffing block (e.g.
/// `"localInbounds[0].sniffing"`); each finding names the offending field
/// as `{prefix}.destOverride`. Error tier: Xray refuses the whole config at
/// load on an unknown protocol, and this verdict gates generation exactly
/// like that load refusal. Emits one issue per offending item — never on
/// `fakedns`/`fakedns+others`, which Xray accepts and the generator
/// appends at wire time.
pub fn validate_sniffing(sniffing: &Sniffing, prefix: &str) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    for item in &sniffing.dest_override {
        if !sniffing_dest_override_supported(item) {
            issues.push(issue(
                ValidationCode::SniffingDestOverrideInvalid,
                Some(format!("{prefix}.destOverride")),
            ));
        }
    }
    issues
}

/// Validate one outbound: protocol-level rules, transport security, and the
/// whole stream (recursively over XHTTP downloads) — one pass, no
/// short-circuit; every violation is reported.
pub fn validate_outbound(o: &OutboundModel) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();

    // The retired `proxySettings` key left this mark behind: the pinned core
    // refuses to build the outbound while the stored profile carries it
    // (infra/conf/xray.go:262), so the profile gates until the user resolves
    // it — the key is kept verbatim for the settings file and is never
    // migrated. Carries no path: the key is not a field of the model, and
    // the servers-level pass scopes the finding with the profile's location.
    if o.retired_proxy_settings.is_some() {
        issues.push(issue(ValidationCode::OutboundProxySettingsRemoved, None));
    }
    if let ProtocolSettings::Shadowsocks(settings) = &o.settings
        && settings.level.is_some_and(|level| level > u8::MAX.into())
    {
        issues.push(issue(
            ValidationCode::ShadowsocksLevelRange,
            Some("settings.level".into()),
        ));
    }
    if let ProtocolSettings::Blackhole(settings) = &o.settings
        && let Some(response) = settings.response.as_ref()
    {
        if !blackhole_response_type_supported(&response.r#type) {
            issues.push(issue(
                ValidationCode::BlackholeResponseInvalid,
                Some("settings.response.type".into()),
            ));
        }
        if blackhole_response_is_custom(&response.r#type)
            && !blackhole_custom_response_data_decodes(&response.custom_response_data)
        {
            issues.push(issue(
                ValidationCode::BlackholeCustomResponseDataInvalid,
                Some("settings.response.customResponseData".into()),
            ));
        }
    }
    if let ProtocolSettings::Hysteria(settings) = &o.settings
        && settings.version != 2
    {
        issues.push(issue(
            ValidationCode::HysteriaTransportVersion,
            Some("settings.version".into()),
        ));
    }
    // WireGuard's in-network resolver list: the pinned core parses each entry
    // with `netip.MustParseAddr` while it creates the outbound client and
    // reads `local` as the sentinel only when the list length is one, so a
    // non-address entry or a mixed list panics the whole process during
    // config load (proxy/wireguard/client.go:117-124; verified against the
    // pinned binary, which exits with that panic under `run -test`). Error
    // tier, like every other WireGuard value the core cannot build.
    if let ProtocolSettings::Wireguard(settings) = &o.settings
        && !wireguard_remote_dns_supported(&settings.remote_dns)
    {
        issues.push(issue(
            ValidationCode::WireguardRemoteDnsInvalid,
            Some("settings.remoteDNS".into()),
        ));
    }

    // Protocol-`settings` vocabulary / required values: the out-of-vocab
    // VLESS flow/encryption, unsupported SS method, missing Trojan/SS
    // essentials, and VLESS/VMess port-0 / non-UUID id rows the editor combos
    // and the share-link grammar already refuse. These gate save/apply exactly
    // like an import refusal, whatever the source of the profile (state file,
    // deserialization, draft). The SS-2022 key-length rule is the exception:
    // Xray accepts the config (`run -test` passes) and the session only fails
    // at dial/auth time — advisory.
    // Paths are the wire paths of the offending fields.
    match &o.settings {
        ProtocolSettings::Vless(settings) => {
            if !vless_flow_supported(&settings.flow) {
                issues.push(issue(
                    ValidationCode::VlessFlowUnsupported,
                    Some("settings.flow".into()),
                ));
            }
            if !vless_encryption_supported(&settings.encryption) {
                issues.push(issue(
                    ValidationCode::VlessEncryptionUnsupported,
                    Some("settings.encryption".into()),
                ));
            }
            if settings.port == 0 {
                issues.push(issue(
                    ValidationCode::SettingsPortZero,
                    Some("settings.port".into()),
                ));
            }
            if !settings.id.is_empty() && !is_canonical_uuid(&settings.id) {
                issues.push(issue(
                    ValidationCode::SettingsIdNotUuid,
                    Some("settings.id".into()),
                ));
            }
        }
        ProtocolSettings::Vmess(settings) => {
            if settings.port == 0 {
                issues.push(issue(
                    ValidationCode::SettingsPortZero,
                    Some("settings.port".into()),
                ));
            }
            if !settings.id.is_empty() && !is_canonical_uuid(&settings.id) {
                issues.push(issue(
                    ValidationCode::SettingsIdNotUuid,
                    Some("settings.id".into()),
                ));
            }
        }
        ProtocolSettings::Trojan(settings) => {
            if settings.address.is_empty() {
                issues.push(issue(
                    ValidationCode::TrojanSettingsIncomplete,
                    Some("settings.address".into()),
                ));
            }
            if settings.password.is_empty() {
                issues.push(issue(
                    ValidationCode::TrojanSettingsIncomplete,
                    Some("settings.password".into()),
                ));
            }
            if settings.port == 0 {
                issues.push(issue(
                    ValidationCode::TrojanSettingsIncomplete,
                    Some("settings.port".into()),
                ));
            }
        }
        ProtocolSettings::Shadowsocks(settings) => {
            if settings.address.is_empty() {
                issues.push(issue(
                    ValidationCode::ShadowsocksSettingsIncomplete,
                    Some("settings.address".into()),
                ));
            }
            if settings.password.is_empty() {
                issues.push(issue(
                    ValidationCode::ShadowsocksSettingsIncomplete,
                    Some("settings.password".into()),
                ));
            }
            if settings.port == 0 {
                issues.push(issue(
                    ValidationCode::ShadowsocksSettingsIncomplete,
                    Some("settings.port".into()),
                ));
            }
            if !shadowsocks_method_supported(&settings.method) {
                issues.push(issue(
                    ValidationCode::ShadowsocksMethodUnsupported,
                    Some("settings.method".into()),
                ));
            }
            if !shadowsocks_2022_key_supported(&settings.method, &settings.password) {
                issues.push(warning(
                    ValidationCode::Shadowsocks2022KeyInvalid,
                    Some("settings.password".into()),
                ));
            }
        }
        _ => {}
    }

    // Extra-passthrough scans — per-settings extras: serde binds only the
    // exact-case modeled fields, so a removed/inert key lands in the
    // flattened `extra` map and is still flattened verbatim into the
    // generated `settings` object. Removed-feature keys are Error (Xray
    // refuses the outbound at load); accepted-then-ignored keys are Warning
    // (Severity::Warning).
    // Value tests mirror Go's unmarshal: JSON `null` is the zero value that
    // leaves the field nil/empty and stays silent.
    match &o.settings {
        ProtocolSettings::Trojan(settings) => {
            // Trojan `flow` — conf/trojan.go refuses a non-empty flow
            // (PrintRemovedFeatureError); the empty string is the zero
            // value and stays silent. Xray's own deprecation note moves
            // Trojan users to VLESS with a vision flow.
            if settings.extra.iter().any(|(key, value)| {
                key.eq_ignore_ascii_case("flow")
                    && !value.is_null()
                    && !matches!(value, Value::String(flow) if flow.is_empty())
            }) {
                issues.push(issue(
                    ValidationCode::TrojanFlowRemoved,
                    Some("settings.flow".into()),
                ));
            }
        }
        ProtocolSettings::Vmess(settings) => {
            // VMess `alterId`/`aid` — the legacy alterId field is gone
            // from conf/vmess.go (VMess is AEAD-only), so Xray silently
            // ignores any carried value.
            for wire_key in ["alterId", "aid"] {
                if extra_has_key(&settings.extra, wire_key) {
                    issues.push(warning(
                        ValidationCode::VmessAlterIdIgnored,
                        Some(format!("settings.{wire_key}")),
                    ));
                }
            }
        }
        ProtocolSettings::Vless(settings) => {
            // VLESS `seed` — parsed-but-inert upstream: the conf struct
            // keeps the field but Build never assigns it (the assignment is
            // commented out, conf/vless.go), so Xray silently drops the
            // carried value.
            if extra_has_key(&settings.extra, "seed") {
                issues.push(warning(
                    ValidationCode::VlessSeedIgnored,
                    Some("settings.seed".into()),
                ));
            }
        }
        ProtocolSettings::Freedom(settings) => {
            // Freedom singular `noise` — conf/freedom.go refuses a
            // non-nil NoiseConfig with PrintRemovedFeatureError naming the
            // `noises` array as the migration. The modeled `noises` field
            // is never affected.
            if extra_key_set(&settings.extra, "noise") {
                issues.push(issue(
                    ValidationCode::FreedomNoiseRemoved,
                    Some("settings.noise".into()),
                ));
            }
            // Freedom `domainStrategy` is unmodeled (only
            // `targetStrategy` is), so any carried value lives in `extra` —
            // yet Xray reads it whenever targetStrategy is empty. Only
            // out-of-vocabulary values fail: conf/freedom.go lowercases and
            // switches over the ten strategies, refusing everything else at
            // load; non-string values fail Go's `string` unmarshal the same
            // way. In-vocabulary values work on the wire and stay silent.
            if settings.extra.iter().any(|(key, value)| {
                key.eq_ignore_ascii_case("domainStrategy")
                    && !value.is_null()
                    && !matches!(
                        value,
                        Value::String(strategy)
                            if strategy.is_empty() || freedom_domain_strategy_supported(strategy)
                    )
            }) {
                issues.push(issue(
                    ValidationCode::FreedomDomainStrategyUnsupported,
                    Some("settings.domainStrategy".into()),
                ));
            }
        }
        _ => {}
    }

    // Transport security: Xray rejects Vision flow without TLS/REALITY, and
    // rejects plaintext VLESS/Trojan connections to public endpoints. Vision
    // wins over the plaintext-public rule when both apply (matches the old
    // single-error precedence).
    if o.stream.security == Security::None {
        match &o.settings {
            ProtocolSettings::Vless(settings) if is_vision_flow(&settings.flow) => {
                issues.push(issue(
                    ValidationCode::VisionRequiresTlsOrReality,
                    Some("settings.flow".into()),
                ));
            }
            ProtocolSettings::Vless(settings)
                if matches!(settings.encryption.as_str(), "" | "none")
                    && endpoint_requires_transport_security(&settings.address) =>
            {
                issues.push(issue(
                    ValidationCode::PublicVlessRequiresTlsOrEncryption,
                    None,
                ));
            }
            ProtocolSettings::Trojan(settings)
                if endpoint_requires_transport_security(&settings.address) =>
            {
                issues.push(issue(
                    ValidationCode::PublicTrojanRequiresTlsOrReality,
                    None,
                ));
            }
            _ => {}
        }
    }

    // Advisory: vision flow over enabled TCP mux. The
    // profile is xray-legal but deterministically broken — the server tears
    // the whole mux connection down on the first TCP frame — so this warns
    // (Severity::Warning) and never gates; the message names the fix.
    if let ProtocolSettings::Vless(settings) = &o.settings
        && mux_conflicts_with_vision_flow(&settings.flow, o.mux.enabled, o.mux.concurrency)
    {
        issues.push(warning(
            ValidationCode::MuxWithVisionFlow,
            Some("mux".into()),
        ));
    }

    // Mux-block semantics: the
    // local-only mux block has no share-link seam, so the model pass is its
    // single validation surface besides the editor combo/slider keystroke
    // constraints (which cannot see deserialized values). These rules are
    // purely additive on the same block — nothing below suppresses or dedups
    // the MuxWithVisionFlow warning above when both apply.
    if o.mux
        .xudp_proxy_udp443
        .as_deref()
        .is_some_and(|value| !xudp_proxy_udp443_supported(value))
    {
        issues.push(issue(
            ValidationCode::MuxXudpProxyUdp443Unsupported,
            Some("mux.xudpProxyUDP443".into()),
        ));
    }
    if mux_concurrency_reinterpreted(o.mux.enabled, o.mux.concurrency) {
        issues.push(warning(
            ValidationCode::MuxConcurrencyReinterpreted,
            Some("mux.concurrency".into()),
        ));
    }
    if mux_xudp_knobs_inert(&o.mux) {
        issues.push(warning(
            ValidationCode::MuxXudpKnobsInert,
            Some("mux.enabled".into()),
        ));
    }

    // Outbound `targetStrategy` vocabulary:
    // Xray lowercases the value and refuses every non-empty strategy
    // outside its set at conf load (infra/conf/xray.go
    // OutboundDetectorConfig.Build), so this is Error-tier and gates
    // save/apply/import like any other model refusal. Empty stays legal —
    // the wire default is `asis`.
    if o.target_strategy
        .as_deref()
        .is_some_and(|strategy| !strategy.is_empty() && !target_strategy_supported(strategy))
    {
        issues.push(issue(
            ValidationCode::OutboundTargetStrategyInvalid,
            Some("targetStrategy".into()),
        ));
    }

    // Inbound-style sniffing that rides outbound settings: Xray
    // builds a loopback outbound's sniffing block through the very same
    // SniffingConfig.Build (infra/conf/loopback.go) and refuses unknown
    // destOverride protocols at load, so the same code + predicate gate
    // here with the settings-level wire path.
    if let ProtocolSettings::Loopback(settings) = &o.settings
        && let Some(sniffing) = settings.sniffing.as_ref()
    {
        issues.extend(validate_sniffing(sniffing, "settings.sniffing"));
    }

    // Editor rules that decide configuration validity — moved into the
    // per-model pass so the editor, generation and the importer all consume
    // one verdict. Each rule keeps the editor's old error shape: one finding
    // per rule, whole-model (the message names no field), so the rendered
    // text is byte-identical wherever the editor lists it.
    if o.send_through
        .as_deref()
        .is_some_and(|value| !send_through_supported(value))
    {
        issues.push(issue(ValidationCode::SendThroughInvalid, None));
    }
    if let ProtocolSettings::Freedom(settings) = &o.settings
        && settings
            .final_rules
            .iter()
            .any(|rule| !freedom_final_rule_supported(&rule.action))
    {
        issues.push(issue(ValidationCode::FreedomFinalRuleInvalid, None));
    }
    if let ProtocolSettings::Dns(settings) = &o.settings
        && settings
            .rules
            .iter()
            .any(|rule| !dns_out_action_supported(&rule.action))
    {
        issues.push(issue(ValidationCode::DnsRuleActionInvalid, None));
    }

    // Advisory: a `udphop` interval mode moves the outbound's socket, and
    // only a transport that can move a live connection runs it: hysteria2
    // (quic-go in `transport/internet/hysteria/dialer.go`), the splithttp
    // HTTP/3 mode — TLS ALPN exactly `["h3"]`, which is the branch that
    // applies the mask manager (`transport/internet/splithttp/dialer.go:216`)
    // — and the WireGuard outbound, which applies the mask to its own packet
    // conn and follows endpoint changes (`proxy/wireguard/client.go:309-310`).
    // Every other transport either never wraps the mask list or cannot carry
    // the connection across a hop, so the hop cannot run. The core starts
    // either way, so this is a configuration warning, never a gate.
    if finalmask_udp_hop_interval_mode(&o.stream) && !hop_transport_migrates_connections(o) {
        issues.push(warning(
            ValidationCode::FinalmaskUdpHopIntervalTransportConflict,
            None,
        ));
    }

    issues.extend(validate_stream(&o.stream));
    issues
}

/// Validate a stream model, recursing over every modeled XHTTP download
/// stream. Mirrors the old `StreamModel::validation_errors` visit logic.
pub fn validate_stream(s: &StreamModel) -> Vec<ValidationIssue> {
    fn visit(stream: &StreamModel, depth: usize, issues: &mut Vec<ValidationIssue>) {
        if depth > MAX_XHTTP_DOWNLOAD_DEPTH {
            issues.push(issue(ValidationCode::XhttpDepthExceeded, None));
            return;
        }
        match stream.network {
            Network::Raw => {}
            Network::Xhttp if stream.xhttp_settings.is_none() => issues.push(issue(
                ValidationCode::TransportSettingsMissing(Network::Xhttp),
                Some("stream.xhttpSettings".into()),
            )),
            Network::Kcp if stream.kcp_settings.is_none() => issues.push(issue(
                ValidationCode::TransportSettingsMissing(Network::Kcp),
                Some("stream.kcpSettings".into()),
            )),
            Network::Grpc if stream.grpc_settings.is_none() => issues.push(issue(
                ValidationCode::TransportSettingsMissing(Network::Grpc),
                Some("stream.grpcSettings".into()),
            )),
            Network::Ws if stream.ws_settings.is_none() => issues.push(issue(
                ValidationCode::TransportSettingsMissing(Network::Ws),
                Some("stream.wsSettings".into()),
            )),
            Network::Httpupgrade if stream.httpupgrade_settings.is_none() => issues.push(issue(
                ValidationCode::TransportSettingsMissing(Network::Httpupgrade),
                Some("stream.httpupgradeSettings".into()),
            )),
            Network::Hysteria if stream.hysteria_settings.is_none() => issues.push(issue(
                ValidationCode::TransportSettingsMissing(Network::Hysteria),
                Some("stream.hysteriaSettings".into()),
            )),
            _ => {}
        }
        // Every headers map reaches Xray's `map[string]string` fields, and a
        // non-string value (a hand-edited state file, or an extra-map key kept
        // verbatim from one) makes the generated document unloadable. The
        // share-link grammar refuses the same value on import, so the state
        // load is the only way in — and generation must refuse it with a
        // message that names the rule instead of spending a core start on it.
        let headers = match stream.network {
            Network::Xhttp => stream
                .xhttp_settings
                .as_ref()
                .map(|settings| (&settings.headers, "stream.xhttpSettings.headers")),
            Network::Ws => stream
                .ws_settings
                .as_ref()
                .map(|settings| (&settings.headers, "stream.wsSettings.headers")),
            Network::Httpupgrade => stream
                .httpupgrade_settings
                .as_ref()
                .map(|settings| (&settings.headers, "stream.httpupgradeSettings.headers")),
            _ => None,
        };
        if let Some((headers, path)) = headers
            && headers.values().any(|value| !value.is_string())
        {
            issues.push(issue(
                ValidationCode::HeaderValuesNotStrings(stream.network),
                Some(path.into()),
            ));
        }
        if stream.network == Network::Hysteria {
            if stream.security != Security::Tls {
                issues.push(issue(
                    ValidationCode::HysteriaTransportRequiresTls,
                    Some("stream.security".into()),
                ));
            }
            if stream
                .hysteria_settings
                .as_ref()
                .is_some_and(|settings| settings.version != 2)
            {
                issues.push(issue(
                    ValidationCode::HysteriaTransportVersion,
                    Some("stream.hysteriaSettings.version".into()),
                ));
            }
        }
        if stream.security == Security::Reality && !stream.network.supports_reality() {
            issues.push(issue(
                ValidationCode::RealityRequiresTransport,
                Some("stream.security".into()),
            ));
        }
        if stream.security == Security::Reality && stream.reality_settings.is_none() {
            issues.push(issue(
                ValidationCode::RealitySettingsMissing,
                Some("stream.realitySettings".into()),
            ));
        }
        if stream.security == Security::Tls && stream.tls_settings.is_none() {
            issues.push(issue(
                ValidationCode::TlsSettingsMissing,
                Some("stream.tlsSettings".into()),
            ));
        }
        // Advisory: a TLS/REALITY serverName that can
        // never be a real SNI (UUID-shaped or impossible characters) always
        // fails the handshake, yet Xray accepts the config — warn, never
        // gate. Mirrors the masterKeyLog convention below: the check rides
        // the settings block whenever one is present, and empty is out of
        // scope.
        if let Some(tls) = stream.tls_settings.as_ref()
            && server_name_implausible(&tls.server_name)
        {
            issues.push(warning(
                ValidationCode::ServerNameImplausible,
                Some("stream.tlsSettings.serverName".into()),
            ));
        }
        if let Some(reality) = stream.reality_settings.as_ref()
            && server_name_implausible(&reality.server_name)
        {
            issues.push(warning(
                ValidationCode::ServerNameImplausible,
                Some("stream.realitySettings.serverName".into()),
            ));
        }
        // `masterKeyLog` makes Xray create/append an attacker-chosen file and
        // log TLS session keys to it — refused on import (the share-link
        // export already rejects it as outside #716). serde binds only the
        // exact-case `masterKeyLog` to the model field; a case variant lands
        // in the flattened `extra` map, is still flattened verbatim into the
        // generated config, and Go's case-insensitive JSON unmarshal sets
        // MasterKeyLog regardless — so the extra map is scanned
        // case-insensitively too.
        if let Some(tls) = stream.tls_settings.as_ref()
            && (!tls.master_key_log.is_empty()
                || tls
                    .extra
                    .keys()
                    .any(|key| key.eq_ignore_ascii_case("masterKeyLog")))
        {
            issues.push(issue(
                ValidationCode::MasterKeyLogNotSupported,
                Some("stream.tlsSettings.masterKeyLog".into()),
            ));
        }
        if let Some(reality) = stream.reality_settings.as_ref()
            && (!reality.master_key_log.is_empty()
                || reality
                    .extra
                    .keys()
                    .any(|key| key.eq_ignore_ascii_case("masterKeyLog")))
        {
            issues.push(issue(
                ValidationCode::MasterKeyLogNotSupported,
                Some("stream.realitySettings.masterKeyLog".into()),
            ));
        }
        // `allowInsecure` is a removed Xray TLS field (not modeled), so a
        // carried value lands in the flattened `extra` map and must be
        // refused. `false` is the Go zero value — Xray runs it fine; any
        // other value (`true`, strings, numbers) either hard-fails
        // TLSConfig.Build (PrintRemovedFeatureError) or Xray's JSON
        // unmarshal into `AllowInsecure bool`. Go's unmarshal matches field
        // names case-insensitively, so every key case must be scanned.
        if let Some(tls) = stream.tls_settings.as_ref()
            && tls.extra.iter().any(|(key, value)| {
                key.eq_ignore_ascii_case("allowInsecure")
                    && !matches!(value, Value::Bool(false) | Value::Null)
            })
        {
            issues.push(issue(
                ValidationCode::TlsAllowInsecureRemoved,
                Some("stream.tlsSettings.allowInsecure".into()),
            ));
        }
        // Extra-passthrough scans — transport-level extras: the same
        // flatten-map mechanics as the masterKeyLog/allowInsecure scans above,
        // over the kcp/hysteria/reality settings blocks. Removed-feature keys
        // are Error; accepted-then-ignored keys are Warning
        // (Severity::Warning). JSON `null` is the Go zero shape and stays
        // silent on the keys whose upstream check tests a non-nil pointer.
        if let Some(kcp) = stream.kcp_settings.as_ref() {
            // mKCP `seed`/`header` — KCPConfig.Build refuses a set
            // seed or header object with PrintRemovedFeatureError naming
            // the finalmask UDP masks as the migration
            // (conf/transport_method.go).
            for (wire_key, path) in [
                ("seed", "stream.kcpSettings.seed"),
                ("header", "stream.kcpSettings.header"),
            ] {
                if extra_key_set(&kcp.extra, wire_key) {
                    issues.push(issue(
                        ValidationCode::KcpSeedHeaderRemoved,
                        Some(path.into()),
                    ));
                }
            }
            // `headerType` never was an Xray JSON key (the old camouflage
            // object is `header`; `headerType` exists only in share links),
            // so Xray's unmarshal silently ignores it — advisory only.
            if extra_has_key(&kcp.extra, "headerType") {
                issues.push(warning(
                    ValidationCode::KcpHeaderTypeIgnored,
                    Some("stream.kcpSettings.headerType".into()),
                ));
            }
        }
        if let Some(hysteria) = stream.hysteria_settings.as_ref() {
            // Hysteria `congestion`/`up`/`down`/`udphop` — HysteriaConfig
            // still parses the legacy QUIC knobs, logs an upstream warning
            // ("congestion & up & down & udphop move to finalmask/quicParams")
            // and discards them (conf/transport_method.go); the config
            // loads and runs without the knobs — advisory.
            for (wire_key, path) in [
                ("congestion", "stream.hysteriaSettings.congestion"),
                ("up", "stream.hysteriaSettings.up"),
                ("down", "stream.hysteriaSettings.down"),
                ("udphop", "stream.hysteriaSettings.udphop"),
            ] {
                if extra_key_set(&hysteria.extra, wire_key) {
                    issues.push(warning(
                        ValidationCode::HysteriaQuicKnobsMoved,
                        Some(path.into()),
                    ));
                }
            }
        }
        if let Some(reality) = stream.reality_settings.as_ref() {
            // REALITY server-form keys (dest, target, privateKey,
            // serverNames, shortIds, mldsa65Seed) carried on a client
            // profile: a client REALITY build never reads them, and a set
            // dest/target flips REALITYConfig.Build onto the server branch
            // (conf/transport_security.go), so an outbound carrying them
            // cannot behave as a client. They are carried verbatim and the
            // config loads — advisory (a profile may deliberately hold
            // server-form material for tooling).
            for wire_key in [
                "dest",
                "target",
                "privateKey",
                "serverNames",
                "shortIds",
                "mldsa65Seed",
            ] {
                // JSON null is the Go zero value — nothing is carried and
                // the dest/target server-branch flip never triggers, so
                // only non-null presence warns (extra_key_set, matching
                // the other removed-feature rows' Go-zero semantics).
                if extra_key_set(&reality.extra, wire_key) {
                    issues.push(warning(
                        ValidationCode::RealityServerFormKeysInert,
                        Some(format!("stream.realitySettings.{wire_key}")),
                    ));
                }
            }
        }
        // Transport-security formats: REALITY client formats, fingerprint
        // wire vocabulary on both blocks, cert pins, and the silently-dropped
        // TLS version strings.
        // All Error findings mirror Xray conf-load rejections
        // (conf/transport_security.go), so they gate save/apply exactly like
        // an import refusal; the version drop is class-E silent, so it warns
        // instead (tls/config.go). The security refusals above (masterKeyLog,
        // allowInsecure) report first when several findings share one block;
        // like those conventions, the format checks ride the settings block
        // whenever one is present. Fingerprint vocabulary is the canonical
        // table in `crate::model::fingerprint` — TLS accepts the full wire
        // vocabulary (`unsafe`/`hellogolang` included), REALITY additionally
        // excludes `unsafe` and `hellogolang`.
        if let Some(tls) = stream.tls_settings.as_ref() {
            if !crate::model::fingerprint::wire_validation_supported(&tls.fingerprint) {
                issues.push(issue(
                    ValidationCode::TlsFingerprintUnsupported,
                    Some("stream.tlsSettings.fingerprint".into()),
                ));
            }
            if !pinned_peer_cert_sha256_valid(&tls.pinned_peer_cert_sha256) {
                issues.push(issue(
                    ValidationCode::PinnedPeerCertSha256Invalid,
                    Some("stream.tlsSettings.pinnedPeerCertSha256".into()),
                ));
            }
            // Configuration warning: Xray accepts any string here
            // but the version switches in tls/config.go leave unrecognized
            // values at the Go default — the configured cap/floor silently
            // never applies. The in-range min > max inversion is a separate
            // runtime-class rule and is NOT coded here.
            for (version, path) in [
                (&tls.min_version, "stream.tlsSettings.minVersion"),
                (&tls.max_version, "stream.tlsSettings.maxVersion"),
            ] {
                if !version.is_empty() && !tls_version_supported(version) {
                    issues.push(warning(
                        ValidationCode::TlsVersionRangeInvalid,
                        Some(path.into()),
                    ));
                }
            }
            // In-range min > max inversion:
            // both versions are valid {1.0..1.3} but the range is inverted.
            // Live repro 2026-09-06 on Xray 26.7.28: `run -test` accepts the
            // pair and the wire negotiates TLS 1.3 — the client version
            // pins never apply (a maxVersion-only "1.2" probe also
            // negotiates 1.3, and a minVersion-only "1.3" probe accepts
            // 1.2), so the config silently never behaves as written —
            // configuration warning (Severity::Warning).
            if let (Some(min), Some(max)) = (
                tls_version_rank(&tls.min_version),
                tls_version_rank(&tls.max_version),
            ) && min > max
            {
                issues.push(warning(
                    ValidationCode::TlsMinExceedsMax,
                    Some("stream.tlsSettings".into()),
                ));
            }
        }
        // Xray consults `tlsSettings` only when `security` selects TLS (the
        // wire pass drops the block otherwise), so the certificate and ALPN
        // rules ride that selection, exactly like the ECH sockopt check below.
        if stream.security == Security::Tls
            && let Some(tls) = stream.tls_settings.as_ref()
        {
            // `fromMitm` beside another ALPN name: Xray's conf build refuses
            // the list (infra/conf/transport_security.go: only one element is
            // allowed in "alpn" when using "fromMitm" in it).
            if tls.alpn.len() > 1 && tls.alpn.iter().any(|value| value == "fromMitm") {
                issues.push(issue(
                    ValidationCode::TlsFromMitmAlpnShort,
                    Some("stream.tlsSettings.alpn".into()),
                ));
            }
            // A certificate row with neither a file nor inline PEM lines has
            // no key material to load (infra/conf: both file and bytes are
            // empty). Both tests are trimmed: a whitespace-only path names no
            // readable file and a blank-only line list parses no certificate,
            // so the row has nothing to load. The path names the row so the
            // finding points at the entry the user has to fill in.
            for (index, certificate) in tls.certificates.iter().enumerate() {
                if certificate.certificate_file.trim().is_empty()
                    && certificate
                        .certificate
                        .iter()
                        .all(|line| line.trim().is_empty())
                {
                    issues.push(issue(
                        ValidationCode::TlsCertificateRequired,
                        Some(format!("stream.tlsSettings.certificates[{index}]")),
                    ));
                }
            }
        }
        if let Some(reality) = stream.reality_settings.as_ref() {
            if !crate::model::fingerprint::reality_wire_supported(&reality.fingerprint) {
                issues.push(issue(
                    ValidationCode::RealityFingerprintUnsupported,
                    Some("stream.realitySettings.fingerprint".into()),
                ));
            } else if crate::model::fingerprint::reality_fingerprint_outside_known_good(
                &reality.fingerprint,
            ) {
                // The wire accepts the name and Xray runs it, but upstream's
                // REALITY scenarios exercise only the known-good three, so
                // the stored value is an untested shape rather than a broken
                // one — advisory (Severity::Warning), never a gate.
                issues.push(warning(
                    ValidationCode::RealityFingerprintUntested(excerpt(&reality.fingerprint)),
                    Some("stream.realitySettings.fingerprint".into()),
                ));
            }
            if !reality_public_key_valid(&reality.password) {
                issues.push(issue(
                    ValidationCode::RealityPublicKeyInvalid,
                    Some("stream.realitySettings.publicKey".into()),
                ));
            }
            if !reality_short_id_valid(&reality.short_id) {
                issues.push(issue(
                    ValidationCode::RealityShortIdInvalid,
                    Some("stream.realitySettings.shortId".into()),
                ));
            }
            if !reality_spider_x_valid(&reality.spider_x) {
                issues.push(issue(
                    ValidationCode::RealitySpiderXInvalid,
                    Some("stream.realitySettings.spiderX".into()),
                ));
            }
            if !reality_mldsa65_verify_valid(&reality.mldsa65_verify) {
                issues.push(issue(
                    ValidationCode::RealityMldsa65Invalid,
                    Some("stream.realitySettings.mldsa65Verify".into()),
                ));
            }
        }
        if let Some(sockopt) = &stream.sockopt {
            issues.extend(validate_sockopt(sockopt, "stream.sockopt"));
        }
        if stream.security == Security::Tls
            && let Some(ech_sockopt) = stream
                .tls_settings
                .as_ref()
                .and_then(|tls| tls.ech_sockopt.as_ref())
        {
            issues.extend(validate_sockopt(
                ech_sockopt,
                "stream.tlsSettings.echSockopt",
            ));
        }
        if let Some(finalmask) = &stream.finalmask {
            issues.extend(validate_finalmask(finalmask));
            // The outermost masks wrap the outbound's own packet connection,
            // and their client wraps refuse a proxied packet connection
            // (`transport/internet/finalmask/{udphop,realm,xicmp}/config.go:
            // 11-13` reject an `internet.FakePacketConn`, which is what a
            // dialerProxy dial yields). The core starts, and every dial
            // fails, so this is a configuration warning, never a gate.
            let wraps_the_dialed_connection = finalmask.udp.iter().any(|mask| {
                matches!(
                    mask,
                    FinalmaskUdpMask::Udphop { .. }
                        | FinalmaskUdpMask::Realm { .. }
                        | FinalmaskUdpMask::Xicmp { .. }
                )
            });
            if wraps_the_dialed_connection
                && stream
                    .sockopt
                    .as_ref()
                    .is_some_and(|sockopt| !sockopt.dialer_proxy.is_empty())
            {
                issues.push(warning(ValidationCode::FinalmaskDialerProxyConflict, None));
            }
        }
        // XHTTP enum vocabularies and cross-field rules: every value below is
        // refused by Xray's SplitHTTPConfig Build at config load
        // (infra/conf/transport_method.go:317-459) and
        // by the share-link xhttp grammar on import — the predicates are the
        // single source shared with `crate::links::validate_xhttp`, so the
        // import seam and this pass decide identically on every value.
        // Findings ride the settings block whenever one is present (the TLS
        // block convention); the recursion below re-visits nested XHTTP
        // download blocks with the same checks.
        if let Some(xhttp) = stream.xhttp_settings.as_ref() {
            if !xhttp_mode_supported(&xhttp.mode) {
                issues.push(issue(
                    ValidationCode::XhttpModeUnsupported,
                    Some("stream.xhttpSettings.mode".into()),
                ));
            }
            if !xpadding_bytes_supported(xhttp.x_padding_bytes) {
                issues.push(issue(
                    ValidationCode::XhttpPaddingBytesInvalid,
                    Some("stream.xhttpSettings.xPaddingBytes".into()),
                ));
            }
            if !xpadding_placement_supported(&xhttp.x_padding_placement) {
                issues.push(issue(
                    ValidationCode::XhttpPaddingPlacementInvalid,
                    Some("stream.xhttpSettings.xPaddingPlacement".into()),
                ));
            }
            if !xpadding_method_supported(&xhttp.x_padding_method) {
                issues.push(issue(
                    ValidationCode::XhttpPaddingMethodInvalid,
                    Some("stream.xhttpSettings.xPaddingMethod".into()),
                ));
            }
            if !uplink_data_placement_supported(&xhttp.uplink_data_placement) {
                issues.push(issue(
                    ValidationCode::XhttpUplinkDataPlacementInvalid,
                    Some("stream.xhttpSettings.uplinkDataPlacement".into()),
                ));
            }
            if !uplink_placement_mode_supported(&xhttp.uplink_data_placement, &xhttp.mode) {
                issues.push(issue(
                    ValidationCode::XhttpUplinkDataPlacementRequiresPacketUp,
                    Some("stream.xhttpSettings.uplinkDataPlacement".into()),
                ));
            }
            if !uplink_http_method_mode_supported(&xhttp.uplink_http_method, &xhttp.mode) {
                issues.push(issue(
                    ValidationCode::XhttpUplinkHttpMethodRequiresPacketUp,
                    Some("stream.xhttpSettings.uplinkHTTPMethod".into()),
                ));
            }
            if !session_id_placement_supported(&xhttp.session_id_placement) {
                issues.push(issue(
                    ValidationCode::XhttpSessionIdPlacementInvalid,
                    Some("stream.xhttpSettings.sessionIDPlacement".into()),
                ));
            }
            if !seq_placement_supported(&xhttp.seq_placement) {
                issues.push(issue(
                    ValidationCode::XhttpSeqPlacementInvalid,
                    Some("stream.xhttpSettings.seqPlacement".into()),
                ));
            }
            if !xhttp.session_id_table.is_empty() {
                match xhttp.session_id_length {
                    None => issues.push(issue(
                        ValidationCode::XhttpSessionIdLengthRequired,
                        Some("stream.xhttpSettings.sessionIDLength".into()),
                    )),
                    Some(range) if !range_has_session_room(&xhttp.session_id_table, range) => {
                        issues.push(issue(
                            ValidationCode::XhttpSessionIdTableInvalid,
                            Some("stream.xhttpSettings.sessionIDTable".into()),
                        ));
                    }
                    _ => {}
                }
            }
            if xmux_limits_conflict(xhttp.xmux.as_ref()) {
                issues.push(issue(
                    ValidationCode::XhttpXmuxLimitsExclusive,
                    Some("stream.xhttpSettings.xmux".into()),
                ));
            }
            // Negative serverMaxHeaderBytes is refused by
            // SplitHTTPConfig.Build at load (infra/conf/transport_method.go)
            // and by the import grammar — the model closes the state path
            // (Error tier, shared server_max_header_bytes_ok predicate).
            if xhttp
                .server_max_header_bytes
                .is_some_and(|value| !server_max_header_bytes_ok(value))
            {
                issues.push(issue(
                    ValidationCode::XhttpServerMaxHeaderBytesInvalid,
                    Some("stream.xhttpSettings.serverMaxHeaderBytes".into()),
                ));
            }
            // Extra-passthrough shadowing:
            // an `xhttpSettings.extra` key naming a modeled xhttp setting
            // overrides it — serde flatten emits the extra value over the
            // typed field on export, and Xray's SplitHTTPConfig.Build
            // (infra/conf/transport_method.go) replaces the whole outer
            // object with the nested `extra` object except host/path/mode.
            // Live repro 2026-09-06 on Xray 26.7.28: outer
            // `xPaddingMethod: "tokenish"` + extra
            // `xPaddingMethod: "bogus"` refuses at load ("unsupported
            // padding method: bogus") while the same config without the
            // extra key loads — the edited value never reaches Xray.
            // Configuration warning (class E, Severity::Warning); the carried
            // key names the offender. The list is
            // the camelCase serde surface of `XhttpSettings`.
            for wire_key in [
                "host",
                "path",
                "mode",
                "headers",
                "uplinkHTTPMethod",
                "uplinkDataPlacement",
                "uplinkDataKey",
                "uplinkChunkSize",
                "xPaddingBytes",
                "xPaddingObfsMode",
                "xPaddingKey",
                "xPaddingHeader",
                "xPaddingPlacement",
                "xPaddingMethod",
                "sessionIDPlacement",
                "sessionIDKey",
                "sessionIDTable",
                "sessionIDLength",
                "seqPlacement",
                "seqKey",
                "noGRPCHeader",
                "noSSEHeader",
                "scMaxEachPostBytes",
                "scMinPostsIntervalMs",
                "scMaxBufferedPosts",
                "scStreamUpServerSecs",
                "serverMaxHeaderBytes",
                "xmux",
                "downloadSettings",
            ] {
                if extra_has_key(&xhttp.extra, wire_key) {
                    issues.push(warning(
                        ValidationCode::XhttpExtraShadowsSettings(wire_key.to_string()),
                        Some(format!("stream.xhttpSettings.{wire_key}")),
                    ));
                }
            }
            if xhttp.mode == "stream-one" && xhttp.download_settings.is_some() {
                issues.push(issue(
                    ValidationCode::StreamOneNoDownload,
                    Some("stream.xhttpSettings.downloadSettings".into()),
                ));
            }
            if let Some(download) = xhttp.download_settings.as_deref() {
                visit(download, depth + 1, issues);
            }
        }
        // mKCP configuration ranges: Xray's
        // KCPConfig.Build load-refuses mtu < 21 and tti outside [10, 1000]
        // (infra/conf/transport_method.go) — Error tier below, sharing the
        // import grammar's hard bounds (kcp_mtu_hard_ok /
        // kcp_tti_hard_ok). The docs (mkcp.md) merely recommend
        // mtu 576-1460 / tti 10-100, so values Xray accepts outside that
        // band stay a docs-soft Warning.
        if let Some(kcp) = stream.kcp_settings.as_ref() {
            if kcp.mtu.is_some_and(|mtu| !kcp_mtu_hard_ok(mtu)) {
                issues.push(issue(
                    ValidationCode::KcpRangeInvalid,
                    Some("stream.kcpSettings.mtu".into()),
                ));
            } else if kcp.mtu.is_some_and(|mtu| !(576..=1460).contains(&mtu)) {
                issues.push(warning(
                    ValidationCode::KcpRangeSoft,
                    Some("stream.kcpSettings.mtu".into()),
                ));
            }
            if kcp.tti.is_some_and(|tti| !kcp_tti_hard_ok(tti)) {
                issues.push(issue(
                    ValidationCode::KcpRangeInvalid,
                    Some("stream.kcpSettings.tti".into()),
                ));
            } else if kcp.tti.is_some_and(|tti| !(10..=100).contains(&tti)) {
                issues.push(warning(
                    ValidationCode::KcpRangeSoft,
                    Some("stream.kcpSettings.tti".into()),
                ));
            }
        }
        // gRPC negative-clamp configuration warnings (Severity::Warning):
        // Xray clamps negative
        // idle_timeout / health_check_timeout / initial_windows_size to zero
        // at conf build (infra/conf/transport_method.go GRPCConfig.Build).
        // Zero itself is intentional on every knob — the keepalive params
        // and the initial-window option are attached only for `> 0` values
        // (grpc dial.go), so 0 means "disabled / Xray's default window" —
        // only negatives are a silent reinterpretation of the user's value.
        if let Some(grpc) = stream.grpc_settings.as_ref() {
            for (knob, path) in [
                (&grpc.idle_timeout, "stream.grpcSettings.idle_timeout"),
                (
                    &grpc.health_check_timeout,
                    "stream.grpcSettings.health_check_timeout",
                ),
                (
                    &grpc.initial_windows_size,
                    "stream.grpcSettings.initial_windows_size",
                ),
            ] {
                if knob.is_some_and(|seconds| seconds < 0) {
                    issues.push(warning(
                        ValidationCode::GrpcNegativeClamp,
                        Some(path.into()),
                    ));
                }
            }
        }
    }

    let mut issues = Vec::new();
    visit(s, 0, &mut issues);
    issues
}

/// The sockopt `domainStrategy` vocabulary: the empty wire default plus the
/// same word list the outbound `targetStrategy` rule reads
/// (infra/conf/transport_sockopt.go hands the value to the dial's resolver).
/// The sockopt combo aliases this list.
pub const SOCKOPT_DOMAIN_STRATEGY_OPTIONS: &[&str] = &[
    "",
    "AsIs",
    "UseIP",
    "UseIPv4",
    "UseIPv6",
    "UseIPv4v6",
    "UseIPv6v4",
    "ForceIP",
    "ForceIPv4",
    "ForceIPv6",
    "ForceIPv4v6",
    "ForceIPv6v4",
];

/// True when a sockopt `domainStrategy` is one of
/// [`SOCKOPT_DOMAIN_STRATEGY_OPTIONS`], case-insensitively.
pub fn sockopt_domain_strategy_supported(strategy: &str) -> bool {
    SOCKOPT_DOMAIN_STRATEGY_OPTIONS
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(strategy))
}

/// The sockopt `addressPortStrategy` vocabulary: the empty wire default plus
/// the SRV/TXT lookup orders Xray's dialer reads
/// (infra/conf/transport_sockopt.go). The sockopt combo aliases this list.
pub const SOCKOPT_ADDRESS_PORT_STRATEGY_OPTIONS: &[&str] = &[
    "",
    "none",
    "srvportonly",
    "srvaddressonly",
    "srvportandaddress",
    "txtportonly",
    "txtaddressonly",
    "txtportandaddress",
];

/// True when a sockopt `addressPortStrategy` is one of
/// [`SOCKOPT_ADDRESS_PORT_STRATEGY_OPTIONS`], case-insensitively.
pub fn sockopt_address_port_strategy_supported(strategy: &str) -> bool {
    SOCKOPT_ADDRESS_PORT_STRATEGY_OPTIONS
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(strategy))
}

/// Validate one sockopt block. `prefix` is the wire path prefix that scopes
/// every field finding (e.g. `"stream.sockopt"`).
pub fn validate_sockopt(s: &SockoptModel, prefix: &str) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    if !sockopt_domain_strategy_supported(&s.domain_strategy) {
        issues.push(issue(
            ValidationCode::SockoptDomainStrategyInvalid,
            Some(format!("{prefix}.domainStrategy")),
        ));
    }
    if !sockopt_address_port_strategy_supported(&s.address_port_strategy) {
        issues.push(issue(
            ValidationCode::SockoptAddressPortStrategyInvalid,
            Some(format!("{prefix}.addressPortStrategy")),
        ));
    }
    if s.tcp_fast_open
        .as_ref()
        .is_some_and(|value| !value.is_boolean() && !value.is_number())
    {
        issues.push(issue(
            ValidationCode::SockoptTcpFastOpenType,
            Some(format!("{prefix}.tcpFastOpen")),
        ));
    }
    let idle = s.tcp_keep_alive_idle.unwrap_or_default();
    let interval = s.tcp_keep_alive_interval.unwrap_or_default();
    // Direct sign comparison, not `idle.wrapping_mul(interval) < 0`: the
    // product overflows for large magnitudes, so 86400 * 86400 wrapped
    // negative and rejected valid same-sign keepalives while large
    // opposite-sign pairs wrapped positive and slipped through. A `0`
    // default (missing field) must keep pairing with any value as
    // same-sign, matching the old `0 * x == 0` behavior, so both values
    // must be strictly nonzero for their signs to conflict.
    if (idle < 0 && interval > 0) || (idle > 0 && interval < 0) {
        issues.push(issue(
            ValidationCode::SockoptKeepaliveSigns,
            Some(format!("{prefix}.tcpKeepAliveIdle")),
        ));
    }
    if s.custom_sockopt
        .iter()
        .any(|custom| custom.opt.trim().is_empty())
    {
        issues.push(issue(
            ValidationCode::SockoptCustomOptRequired,
            Some(format!("{prefix}.customSockopt")),
        ));
    }
    if s.custom_sockopt
        .iter()
        .any(|custom| !matches!(custom.r#type.as_str(), "int" | "str"))
    {
        issues.push(issue(
            ValidationCode::SockoptCustomTypeInvalid,
            Some(format!("{prefix}.customSockopt")),
        ));
    }
    // Tproxy configuration warning (Severity::Warning): Xray
    // lowercases `tproxy` and maps everything outside {tproxy, redirect} —
    // a typo included, `off` being the explicit spelling of the Off default
    // that is honored as-is — onto SocketConfig_Off without a word
    // (infra/conf/transport_sockopt.go), so a misspelled mode runs without
    // transparency. Advisory: the config loads and the wire works, the
    // value silently never applies. The vocabulary is the shared
    // [`TPROXY_MODES`] list; the field has no widget any more, so a value
    // this flags came from a hand-edited profile or the raw config override.
    if s.tproxy.as_deref().is_some_and(|value| {
        !value.is_empty()
            && !TPROXY_MODES
                .iter()
                .any(|mode| mode.eq_ignore_ascii_case(value))
    }) {
        issues.push(warning(
            ValidationCode::SockoptTproxySilentOff,
            Some(format!("{prefix}.tproxy")),
        ));
    }
    issues
}

/// Validate a listen address: always a concrete IP literal.
pub fn validate_listen_address(s: &str) -> Result<(), ValidationCode> {
    match s.parse::<std::net::IpAddr>() {
        Ok(_) => Ok(()),
        Err(_) => Err(ValidationCode::ListenAddressInvalid),
    }
}

// ---------- finalmask ----------

fn finalmask_range_bounds(value: Int32Range) -> (i32, i32) {
    if value.from <= value.to {
        (value.from, value.to)
    } else {
        (value.to, value.from)
    }
}

/// Validate one finalmask block. Paths are wire paths suitable for inline UI
/// and share-link diagnostics; they mirror the rejections of the current Xray
/// finalmask loader and QUIC parameter builder.
pub fn validate_finalmask(fm: &FinalmaskModel) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    for (index, mask) in fm.tcp.iter().enumerate() {
        finalmask_validate_tcp_mask(index, mask, &mut issues);
    }
    finalmask_validate_udp_order(&fm.udp, &mut issues);
    for (index, mask) in fm.udp.iter().enumerate() {
        finalmask_validate_udp_mask(index, mask, &mut issues);
    }
    if let Some(quic) = &fm.quic_params {
        finalmask_validate_quic_params("finalmask.quicParams", quic, &mut issues);
    }
    issues
}

/// Gate the UDP mask positions the wrap refuses. The manager reverses the
/// list at construction and wraps forward
/// (`transport/internet/finalmask/finalmask.go:21-25,28-31` at v26.9.9), so
/// the JSON list's last entry wraps first and the first entry wraps last.
/// `udphop`, `realm`, and `xicmp` demand the first-wrapped slot — level 0
/// (`.../udphop/config.go:11-13`, `.../realm/config.go:11-20`,
/// `.../xicmp/config.go:11-20`) — so they belong at the end of the list, and
/// `sudoku` demands the last-wrapped slot — level `levelCount`
/// (`.../sudoku/config.go:39-49`) — so it belongs at the start. A
/// single-entry list fills both slots, and no TCP mask type is pinned. The
/// core enforces this only while it wraps a connection, so the config build
/// accepts a misordered chain and every dial fails; the app gates it instead.
fn finalmask_validate_udp_order(masks: &[FinalmaskUdpMask], issues: &mut Vec<ValidationIssue>) {
    let Some(last) = masks.len().checked_sub(1) else {
        return;
    };
    for (index, mask) in masks.iter().enumerate() {
        match mask {
            FinalmaskUdpMask::Sudoku { .. } if index != 0 => issues.push(issue(
                ValidationCode::FinalmaskUdpMaskNotFirst("sudoku".into()),
                Some(format!("finalmask.udp[{index}]")),
            )),
            FinalmaskUdpMask::Realm { .. }
            | FinalmaskUdpMask::Xicmp { .. }
            | FinalmaskUdpMask::Udphop { .. }
                if index != last =>
            {
                issues.push(issue(
                    ValidationCode::FinalmaskUdpMaskNotLast(
                        mask.known_type()
                            .expect("the match arm only admits known mask types")
                            .into(),
                    ),
                    Some(format!("finalmask.udp[{index}]")),
                ));
            }
            _ => {}
        }
    }
}

/// True when a `udphop` UDP mask selects an interval mode
/// (`intervalLocal` or `intervalRemote`, comma-combinable and
/// case-insensitive) over a well-formed `mode` set. Each hop moves or
/// re-rolls the outbound's socket, unlike the per-connection `perConnRemote`
/// roll.
fn finalmask_udp_hop_interval_mode(stream: &StreamModel) -> bool {
    stream
        .finalmask
        .as_ref()
        .is_some_and(|finalmask| finalmask.udp.iter().any(finalmask_udphop_selects_interval))
}

/// True when the transport can run an interval hop: hysteria2 and the
/// splithttp HTTP/3 mode carry a QUIC connection that migrates, and the
/// WireGuard outbound reads the mask from its stream settings and wraps its
/// own packet conn, which follows endpoint changes
/// (`proxy/wireguard/client.go:309-310`).
///
/// Splithttp dials HTTP/3 — and only that branch applies the mask manager
/// (`transport/internet/splithttp/dialer.go:216`) — when its TLS ALPN is
/// exactly `["h3"]`: REALITY forces HTTP/2 and a stream without TLS falls
/// back to HTTP/1.1 (`.../splithttp/dialer.go:82-99`). Other transports
/// either never wrap the mask list or cannot move a live connection, so an
/// interval hop cannot run there.
fn hop_transport_migrates_connections(outbound: &OutboundModel) -> bool {
    if matches!(&outbound.settings, ProtocolSettings::Wireguard(_)) {
        return true;
    }
    match outbound.stream.network {
        Network::Hysteria => true,
        Network::Xhttp => {
            outbound.stream.security == Security::Tls
                && outbound
                    .stream
                    .tls_settings
                    .as_ref()
                    .is_some_and(|tls| tls.alpn.len() == 1 && tls.alpn[0] == "h3")
        }
        _ => false,
    }
}

fn finalmask_valid_var_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return true;
    };
    (first == b'_' || first.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn finalmask_validate_bytes(
    path: &str,
    encoding: &str,
    raw: &FinalmaskRawValue,
    issues: &mut Vec<ValidationIssue>,
) {
    let kind = encoding.to_ascii_lowercase();
    let Some(value) = raw.value() else {
        if !matches!(kind.as_str(), "" | "array") {
            issues.push(issue(
                ValidationCode::FinalmaskBytesValueRequired(excerpt(&kind)),
                Some(path.to_string()),
            ));
        }
        return;
    };
    if value.is_null() {
        return;
    }
    match kind.as_str() {
        "" | "array" => {
            let valid = value.as_array().is_some_and(|values| {
                values
                    .iter()
                    .all(|value| value.as_u64().is_some_and(|byte| byte <= u8::MAX as u64))
            });
            if !valid {
                issues.push(issue(
                    ValidationCode::FinalmaskArrayByteSyntax,
                    Some(path.to_string()),
                ));
            }
        }
        "str" => {
            if !value.is_string() {
                issues.push(issue(
                    ValidationCode::FinalmaskStrByteSyntax,
                    Some(path.to_string()),
                ));
            }
        }
        "hex" => match value.as_str() {
            Some(text)
                if text.len() % 2 == 0 && text.bytes().all(|byte| byte.is_ascii_hexdigit()) => {}
            _ => issues.push(issue(
                ValidationCode::FinalmaskHexByteSyntax,
                Some(path.to_string()),
            )),
        },
        "base64" => match value.as_str() {
            Some(text)
                if base64::Engine::decode(&base64::engine::general_purpose::STANDARD, text)
                    .is_ok() => {}
            _ => issues.push(issue(
                ValidationCode::FinalmaskBase64ByteSyntax,
                Some(path.to_string()),
            )),
        },
        _ => issues.push(issue(
            ValidationCode::FinalmaskUnknownByteSyntax(excerpt_debug(encoding)),
            Some(path.to_string()),
        )),
    }
}

fn finalmask_validate_transform(
    path: &str,
    transform: &FinalmaskTransform,
    issues: &mut Vec<ValidationIssue>,
) {
    if transform.op.is_empty() {
        issues.push(issue(
            ValidationCode::FinalmaskTransformOpRequired,
            Some(format!("{path}.op")),
        ));
    }
    if transform.args.is_empty() {
        issues.push(issue(
            ValidationCode::FinalmaskTransformArgRequired,
            Some(format!("{path}.args")),
        ));
    }
    for (index, arg) in transform.args.iter().enumerate() {
        let arg_path = format!("{path}.args[{index}]");
        let count = usize::from(!arg.bytes.is_absent())
            + usize::from(arg.u64.is_some())
            + usize::from(!arg.reuse.is_empty())
            + usize::from(!arg.metadata.is_empty())
            + usize::from(arg.transform.is_some());
        if count != 1 {
            issues.push(issue(
                ValidationCode::FinalmaskTransformArgExclusive,
                Some(arg_path.clone()),
            ));
        }
        if !arg.bytes.is_absent() {
            finalmask_validate_bytes(
                &format!("{arg_path}.bytes"),
                &arg.encoding,
                &arg.bytes,
                issues,
            );
        }
        if !finalmask_valid_var_name(&arg.reuse) {
            issues.push(issue(
                ValidationCode::FinalmaskVarNameInvalid,
                Some(format!("{arg_path}.reuse")),
            ));
        }
        if let Some(nested) = &arg.transform {
            finalmask_validate_transform(&format!("{arg_path}.transform"), nested, issues);
        }
    }
}

/// Read-only view of the finalmask header-custom item fields shared by the
/// TCP and UDP item structs, so validation can accept either.
trait FinalmaskCustomItem {
    fn capture(&self) -> &str;
    fn packet(&self) -> &FinalmaskRawValue;
    fn rand(&self) -> i32;
    fn rand_range(&self) -> Option<Int32Range>;
    fn encoding(&self) -> &str;
    fn reuse(&self) -> &str;
    fn transform(&self) -> Option<&FinalmaskTransform>;
}

impl FinalmaskCustomItem for super::stream::FinalmaskTcpItem {
    fn capture(&self) -> &str {
        &self.capture
    }
    fn packet(&self) -> &FinalmaskRawValue {
        &self.packet
    }
    fn rand(&self) -> i32 {
        self.rand
    }
    fn rand_range(&self) -> Option<Int32Range> {
        self.rand_range
    }
    fn encoding(&self) -> &str {
        &self.encoding
    }
    fn reuse(&self) -> &str {
        &self.reuse
    }
    fn transform(&self) -> Option<&FinalmaskTransform> {
        self.transform.as_ref()
    }
}

impl FinalmaskCustomItem for super::stream::FinalmaskUdpItem {
    fn capture(&self) -> &str {
        &self.capture
    }
    fn packet(&self) -> &FinalmaskRawValue {
        &self.packet
    }
    fn rand(&self) -> i32 {
        self.rand
    }
    fn rand_range(&self) -> Option<Int32Range> {
        self.rand_range
    }
    fn encoding(&self) -> &str {
        &self.encoding
    }
    fn reuse(&self) -> &str {
        &self.reuse
    }
    fn transform(&self) -> Option<&FinalmaskTransform> {
        self.transform.as_ref()
    }
}

fn finalmask_validate_custom_item(
    path: &str,
    item: &impl FinalmaskCustomItem,
    issues: &mut Vec<ValidationIssue>,
) {
    let capture = item.capture();
    let packet = item.packet();
    let rand = item.rand();
    let rand_range = item.rand_range();
    let encoding = item.encoding();
    let reuse = item.reuse();
    let transform = item.transform();
    if !finalmask_valid_var_name(capture) {
        issues.push(issue(
            ValidationCode::FinalmaskVarNameInvalid,
            Some(format!("{path}.capture")),
        ));
    }
    if !finalmask_valid_var_name(reuse) {
        issues.push(issue(
            ValidationCode::FinalmaskVarNameInvalid,
            Some(format!("{path}.reuse")),
        ));
    }
    let count = usize::from(!packet.is_absent())
        + usize::from(rand > 0)
        + usize::from(!reuse.is_empty())
        + usize::from(transform.is_some());
    if count > 1 || (count == 0 && !capture.is_empty()) {
        issues.push(issue(
            ValidationCode::FinalmaskCustomItemExclusive,
            Some(path.to_string()),
        ));
    }
    if let Some(range) = rand_range {
        let (from, to) = finalmask_range_bounds(range);
        if from < 0 || to > 255 {
            issues.push(issue(
                ValidationCode::FinalmaskRandRangeInvalid,
                Some(format!("{path}.randRange")),
            ));
        }
    }
    finalmask_validate_bytes(&format!("{path}.packet"), encoding, packet, issues);
    if let Some(transform) = transform {
        finalmask_validate_transform(&format!("{path}.transform"), transform, issues);
    }
}

fn finalmask_validate_sudoku(_path: &str, _settings: &FinalmaskSudoku) {
    // Xray deliberately accepts every value and applies current-field-over-
    // legacy-field precedence during Build.
}

fn finalmask_validate_xmc(path: &str, settings: &FinalmaskXmc, issues: &mut Vec<ValidationIssue>) {
    if settings.profiles.is_empty() {
        issues.push(issue(
            ValidationCode::FinalmaskXmcProfilesRequired,
            Some(format!("{path}.profiles")),
        ));
    }
    if settings.password.is_empty() {
        issues.push(issue(
            ValidationCode::FinalmaskXmcPasswordRequired,
            Some(format!("{path}.password")),
        ));
    }
    for (index, profile) in settings.profiles.iter().enumerate() {
        let profile_path = format!("{path}.profiles[{index}]");
        let username = profile.username.as_bytes();
        if !(3..=16).contains(&username.len())
            || !username
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            issues.push(issue(
                ValidationCode::FinalmaskXmcUsernameInvalid,
                Some(format!("{profile_path}.username")),
            ));
        }
        if !is_canonical_uuid(&profile.uuid) {
            issues.push(issue(
                ValidationCode::FinalmaskXmcUuidInvalid,
                Some(format!("{profile_path}.uuid")),
            ));
        }
        if profile.textures_value.is_empty() || profile.textures_signature.is_empty() {
            issues.push(issue(
                ValidationCode::FinalmaskXmcTexturesRequired,
                Some(profile_path),
            ));
        }
    }
}

/// QUIC `brutalUp`/`brutalDown` bandwidth → bytes per second.
///
/// `Ok(None)` is Xray's unset shape: blank input or an explicit zero (the
/// too-small rule's own message names `0/empty` as legal), which leaves the
/// QUIC parameter at its default. `Ok(Some(bytes))` is a positive bit rate
/// truncated to whole bytes, so a sub-byte rate (`"5bps"`, a bare `"1"`)
/// yields `Some(0)` — a value that can never work, reported by the caller as
/// too small instead of being read as unset.
fn finalmask_parse_bandwidth_bps(value: &str) -> Result<Option<u64>, ValidationCode> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Ok(None);
    }
    let index = normalized
        .char_indices()
        .find_map(|(index, ch)| (!(ch.is_ascii_digit() || ch == '.')).then_some(index))
        .unwrap_or(normalized.len());
    let number: f64 = normalized[..index]
        .parse()
        .map_err(|_| ValidationCode::FinalmaskQuicBandwidthSyntax)?;
    if !number.is_finite() || number < 0.0 {
        return Err(ValidationCode::FinalmaskQuicBandwidthNonFinite);
    }
    let unit = normalized[index..].trim();
    let multiplier = match unit {
        "" | "b" | "bps" => 1_u64,
        "k" | "kb" | "kbps" => 1024,
        "m" | "mb" | "mbps" => 1024 * 1024,
        "g" | "gb" | "gbps" => 1024 * 1024 * 1024,
        "t" | "tb" | "tbps" => 1024_u64 * 1024 * 1024 * 1024,
        _ => {
            return Err(ValidationCode::FinalmaskQuicBandwidthUnitInvalid(excerpt(
                unit,
            )));
        }
    };
    let bits = number * multiplier as f64;
    if bits > u64::MAX as f64 {
        return Err(ValidationCode::FinalmaskQuicBandwidthTooLarge);
    }
    if bits == 0.0 {
        return Ok(None);
    }
    Ok(Some(bits as u64 / 8))
}

fn finalmask_validate_port_list(
    path: &str,
    ports: &FinalmaskPortList,
    issues: &mut Vec<ValidationIssue>,
) {
    match ports {
        FinalmaskPortList::Number(port) => {
            if *port > u16::MAX as u32 {
                issues.push(issue(
                    ValidationCode::FinalmaskPortNumberRange,
                    Some(path.to_string()),
                ));
            }
        }
        FinalmaskPortList::Text(text) => {
            for item in text
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
            {
                if let Some(environment) = item.strip_prefix("env:") {
                    if environment.is_empty() {
                        issues.push(issue(
                            ValidationCode::FinalmaskPortEnvNameRequired,
                            Some(path.to_string()),
                        ));
                    }
                    continue;
                }
                let valid_port = |part: &str| {
                    part.parse::<u32>()
                        .is_ok_and(|port| port <= u16::MAX as u32)
                };
                let valid = match item.split_once('-') {
                    Some((from, to)) => valid_port(from) && valid_port(to) && !to.contains('-'),
                    None => valid_port(item),
                };
                if !valid {
                    issues.push(issue(
                        ValidationCode::FinalmaskPortListInvalid(excerpt_debug(item)),
                        Some(path.to_string()),
                    ));
                }
            }
        }
    }
}

fn finalmask_validate_quic_params(
    path: &str,
    quic: &FinalmaskQuicParams,
    issues: &mut Vec<ValidationIssue>,
) {
    let congestion = quic.congestion.to_ascii_lowercase();
    if !matches!(
        congestion.as_str(),
        "" | "brutal" | "reno" | "bbr" | "force-brutal"
    ) {
        issues.push(issue(
            ValidationCode::FinalmaskQuicCongestionInvalid,
            Some(format!("{path}.congestion")),
        ));
    }
    let profile = quic.bbr_profile.to_ascii_lowercase();
    if !matches!(
        profile.as_str(),
        "" | "conservative" | "standard" | "aggressive"
    ) {
        issues.push(issue(
            ValidationCode::FinalmaskQuicBbrProfileInvalid,
            Some(format!("{path}.bbrProfile")),
        ));
    }
    // An unset (blank/explicit-zero) bandwidth reports nothing; a positive
    // rate below the 64 KiB/s floor — including one that truncates below a
    // single byte per second — reports the too-small rule. `force-brutal`
    // additionally needs an upload rate at all, but only when the value
    // itself parsed: a syntax/unit finding already names the field, so the
    // derived rule must not double-report the same path.
    let mut up_parse_failed = false;
    let up = match finalmask_parse_bandwidth_bps(&quic.brutal_up) {
        Ok(Some(value)) => {
            if value < 65_536 {
                issues.push(issue(
                    ValidationCode::FinalmaskQuicBandwidthTooSmall,
                    Some(format!("{path}.brutalUp")),
                ));
            }
            Some(value)
        }
        Ok(None) => None,
        Err(code) => {
            issues.push(issue(code, Some(format!("{path}.brutalUp"))));
            up_parse_failed = true;
            None
        }
    };
    match finalmask_parse_bandwidth_bps(&quic.brutal_down) {
        Ok(Some(value)) if value < 65_536 => issues.push(issue(
            ValidationCode::FinalmaskQuicBandwidthTooSmall,
            Some(format!("{path}.brutalDown")),
        )),
        Err(code) => issues.push(issue(code, Some(format!("{path}.brutalDown")))),
        _ => {}
    }
    if congestion == "force-brutal" && up.is_none() && !up_parse_failed {
        issues.push(issue(
            ValidationCode::FinalmaskQuicForceBrutalNeedsUp,
            Some(format!("{path}.brutalUp")),
        ));
    }
    if quic.retired_udp_hop.is_some() {
        // The retired `quicParams.udpHop` key left this mark behind: the
        // core now ignores the key and the hop would die silently, so the
        // profile gates until the user rebuilds it as a `udphop` UDP mask.
        // Nothing is migrated — the raw value stays for the settings file.
        // Carries no path: the key is a settings-file fact, not a field of
        // the generated document.
        issues.push(issue(ValidationCode::FinalmaskQuicHopMoved, None));
    }
    for (name, value) in [
        ("initStreamReceiveWindow", quic.init_stream_receive_window),
        ("maxStreamReceiveWindow", quic.max_stream_receive_window),
        (
            "initConnectionReceiveWindow",
            quic.init_connection_receive_window,
        ),
        (
            "maxConnectionReceiveWindow",
            quic.max_connection_receive_window,
        ),
    ] {
        if value.is_some_and(|value| value > 0 && value < 16_384) {
            issues.push(issue(
                ValidationCode::FinalmaskQuicReceiveWindowTooSmall,
                Some(format!("{path}.{name}")),
            ));
        }
    }
    if quic
        .max_idle_timeout
        .is_some_and(|value| value != 0 && !(4..=120).contains(&value))
    {
        issues.push(issue(
            ValidationCode::FinalmaskQuicMaxIdleTimeoutInvalid,
            Some(format!("{path}.maxIdleTimeout")),
        ));
    }
    if quic
        .keep_alive_period
        .is_some_and(|value| value != 0 && !(2..=60).contains(&value))
    {
        issues.push(issue(
            ValidationCode::FinalmaskQuicKeepAlivePeriodInvalid,
            Some(format!("{path}.keepAlivePeriod")),
        ));
    }
    if quic
        .max_incoming_streams
        .is_some_and(|value| value != 0 && value < 8)
    {
        issues.push(issue(
            ValidationCode::FinalmaskQuicMaxIncomingStreamsInvalid,
            Some(format!("{path}.maxIncomingStreams")),
        ));
    }
}

fn finalmask_validate_tcp_mask(
    index: usize,
    mask: &FinalmaskTcpMask,
    issues: &mut Vec<ValidationIssue>,
) {
    let path = format!("finalmask.tcp[{index}]");
    match mask {
        FinalmaskTcpMask::HeaderCustom { settings, .. } => {
            for (group_name, groups) in [
                ("clients", &settings.clients),
                ("servers", &settings.servers),
                ("errors", &settings.errors),
            ] {
                for (sequence_index, sequence) in groups.iter().enumerate() {
                    for (item_index, item) in sequence.iter().enumerate() {
                        finalmask_validate_custom_item(
                            &format!(
                                "{path}.settings.{group_name}[{sequence_index}][{item_index}]"
                            ),
                            item,
                            issues,
                        );
                    }
                }
            }
        }
        FinalmaskTcpMask::Fragment { settings, .. } => {
            if !settings.packets.is_empty() && !settings.packets.eq_ignore_ascii_case("tlshello") {
                match Int32Range::parse(&settings.packets) {
                    Some(range) if range.from != 0 => {}
                    Some(_) => issues.push(issue(
                        ValidationCode::FinalmaskPacketsFirstNotZero,
                        Some(format!("{path}.settings.packets")),
                    )),
                    None => issues.push(issue(
                        ValidationCode::FinalmaskPacketsSyntax,
                        Some(format!("{path}.settings.packets")),
                    )),
                }
            }
            let last = settings.lengths.last().copied().unwrap_or(settings.length);
            if finalmask_range_bounds(last).0 == 0 {
                issues.push(issue(
                    ValidationCode::FinalmaskLengthsStartAboveZero,
                    Some(format!("{path}.settings.lengths")),
                ));
            }
        }
        FinalmaskTcpMask::Sudoku { settings, .. } => {
            finalmask_validate_sudoku(&format!("{path}.settings"), settings);
        }
        FinalmaskTcpMask::Xmc { settings, .. } => {
            finalmask_validate_xmc(&format!("{path}.settings"), settings, issues);
        }
        FinalmaskTcpMask::Unknown(raw) => issues.push(issue(
            ValidationCode::FinalmaskUnknownTcpMask(
                raw.get("type").and_then(Value::as_str).map(excerpt),
            ),
            Some(path),
        )),
    }
}

fn finalmask_valid_split_host_port(value: &str) -> bool {
    if let Some(rest) = value.strip_prefix('[') {
        return rest.find(']').is_some_and(|close| {
            rest.get(close + 1..)
                .is_some_and(|suffix| suffix.starts_with(':'))
        });
    }
    value.matches(':').count() == 1
}

fn finalmask_validate_udp_mask(
    index: usize,
    mask: &FinalmaskUdpMask,
    issues: &mut Vec<ValidationIssue>,
) {
    let path = format!("finalmask.udp[{index}]");
    match mask {
        FinalmaskUdpMask::HeaderCustom { settings, .. } => {
            if !matches!(settings.mode.as_str(), "" | "prefix" | "standalone") {
                issues.push(issue(
                    ValidationCode::FinalmaskUdpHeaderModeInvalid,
                    Some(format!("{path}.settings.mode")),
                ));
            }
            for (group_name, items) in [("client", &settings.client), ("server", &settings.server)]
            {
                for (item_index, item) in items.iter().enumerate() {
                    finalmask_validate_custom_item(
                        &format!("{path}.settings.{group_name}[{item_index}]"),
                        item,
                        issues,
                    );
                }
            }
        }
        FinalmaskUdpMask::MkcpLegacy { settings, .. } => {
            let header = settings.header.to_ascii_lowercase();
            if !matches!(
                header.as_str(),
                "" | "dns" | "dtls" | "srtp" | "utp" | "wechat" | "wireguard"
            ) {
                issues.push(issue(
                    ValidationCode::FinalmaskMkcpHeaderInvalid,
                    Some(format!("{path}.settings.header")),
                ));
            }
        }
        FinalmaskUdpMask::Noise { settings, .. } => {
            for (item_index, item) in settings.noise.iter().enumerate() {
                let item_path = format!("{path}.settings.noise[{item_index}]");
                if !item.packet.is_absent() && finalmask_range_bounds(item.rand).1 > 0 {
                    issues.push(issue(
                        ValidationCode::FinalmaskNoisePacketExclusive,
                        Some(item_path.clone()),
                    ));
                }
                if let Some(range) = item.rand_range {
                    let (from, to) = finalmask_range_bounds(range);
                    if from < 0 || to > 255 {
                        issues.push(issue(
                            ValidationCode::FinalmaskRandRangeInvalid,
                            Some(format!("{item_path}.randRange")),
                        ));
                    }
                }
                finalmask_validate_bytes(
                    &format!("{item_path}.packet"),
                    &item.encoding,
                    &item.packet,
                    issues,
                );
            }
        }
        FinalmaskUdpMask::Salamander { settings, .. } => {
            let (from, to) = finalmask_range_bounds(settings.packet_size);
            if to > 0 && (from <= 0 || to > 2048) {
                issues.push(issue(
                    ValidationCode::FinalmaskSalamanderPacketSize,
                    Some(format!("{path}.settings.packetSize")),
                ));
            }
        }
        FinalmaskUdpMask::Sudoku { settings, .. } => {
            finalmask_validate_sudoku(&format!("{path}.settings"), settings);
        }
        FinalmaskUdpMask::Xdns { settings, .. } => {
            if !settings.domain.is_absent() {
                issues.push(issue(
                    ValidationCode::FinalmaskXdnsDomainRemoved,
                    Some(format!("{path}.settings.domain")),
                ));
            }
            if settings.domains.is_empty() && settings.resolvers.is_empty() {
                issues.push(issue(
                    ValidationCode::FinalmaskXdnsEmpty,
                    Some(format!("{path}.settings")),
                ));
            }
            for (resolver_index, resolver) in settings.resolvers.iter().enumerate() {
                if !resolver.contains("+udp://") {
                    issues.push(issue(
                        ValidationCode::FinalmaskXdnsResolverUdp,
                        Some(format!("{path}.settings.resolvers[{resolver_index}]")),
                    ));
                }
            }
        }
        FinalmaskUdpMask::Xicmp { settings, .. } => {
            for (ip_index, ip) in settings.ips.iter().enumerate() {
                if ip.parse::<std::net::IpAddr>().is_err() {
                    issues.push(issue(
                        ValidationCode::FinalmaskXicmpIpInvalid,
                        Some(format!("{path}.settings.ips[{ip_index}]")),
                    ));
                }
            }
        }
        FinalmaskUdpMask::Realm { settings, .. } => {
            match url::Url::parse(&settings.url) {
                Ok(url) => {
                    if !matches!(url.scheme(), "realm" | "realm+http") {
                        issues.push(issue(
                            ValidationCode::FinalmaskRealmScheme,
                            Some(format!("{path}.settings.url")),
                        ));
                    }
                    if url.host_str().is_none_or(str::is_empty) {
                        issues.push(issue(
                            ValidationCode::FinalmaskRealmHostRequired,
                            Some(format!("{path}.settings.url")),
                        ));
                    }
                    if url.username().is_empty() {
                        issues.push(issue(
                            ValidationCode::FinalmaskRealmTokenBeforeAt,
                            Some(format!("{path}.settings.url")),
                        ));
                    }
                    if url.path().trim_start_matches('/').is_empty() {
                        issues.push(issue(
                            ValidationCode::FinalmaskRealmIdInPath,
                            Some(format!("{path}.settings.url")),
                        ));
                    }
                }
                Err(error) => issues.push(issue(
                    ValidationCode::FinalmaskRealmUrlSyntax(excerpt(&error.to_string())),
                    Some(format!("{path}.settings.url")),
                )),
            }
            if settings.stun_servers.is_empty() {
                issues.push(issue(
                    ValidationCode::FinalmaskRealmStunRequired,
                    Some(format!("{path}.settings.stunServers")),
                ));
            }
            for (server_index, server) in settings.stun_servers.iter().enumerate() {
                if !finalmask_valid_split_host_port(server) {
                    issues.push(issue(
                        ValidationCode::FinalmaskRealmStunFormat,
                        Some(format!("{path}.settings.stunServers[{server_index}]")),
                    ));
                }
            }
            if let Some(tls) = &settings.tls_config {
                finalmask_validate_realm_tls(&format!("{path}.settings.tlsConfig"), tls, issues);
            }
        }
        FinalmaskUdpMask::Udphop { settings, .. } => {
            finalmask_validate_udphop(&format!("{path}.settings"), settings, issues);
        }
        FinalmaskUdpMask::Unknown(raw) => issues.push(issue(
            ValidationCode::FinalmaskUnknownUdpMask(
                raw.get("type").and_then(Value::as_str).map(excerpt),
            ),
            Some(path),
        )),
    }
}

/// One `udphop` `mode` name, matched the way the mask build matches it:
/// split on `,`, lowercased, never trimmed
/// (`infra/conf/transport_finalmask.go:925-940`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum FinalmaskUdpHopMode {
    IntervalLocal,
    IntervalRemote,
    PerConnRemote,
}

/// Classify one component of a `udphop` mask's `mode` value. `None` when the
/// component is outside the three names — the mask build refuses that shape
/// at config load, so the mode gate reports it and the interval-hop advisory
/// stays silent for it rather than adding a second message for one value.
fn finalmask_udphop_mode(component: &str) -> Option<FinalmaskUdpHopMode> {
    match component.to_ascii_lowercase().as_str() {
        "intervallocal" => Some(FinalmaskUdpHopMode::IntervalLocal),
        "intervalremote" => Some(FinalmaskUdpHopMode::IntervalRemote),
        "perconnremote" => Some(FinalmaskUdpHopMode::PerConnRemote),
        _ => None,
    }
}

/// True when one `udphop` mask selects an interval mode over a well-formed
/// `mode` set. Each interval hop moves or re-rolls the outbound's socket,
/// unlike the per-connection `perConnRemote` roll, so only a transport that
/// moves a live connection runs it.
fn finalmask_udphop_selects_interval(mask: &FinalmaskUdpMask) -> bool {
    let FinalmaskUdpMask::Udphop { settings, .. } = mask else {
        return false;
    };
    let mut interval = false;
    for component in settings.mode.split(',') {
        match finalmask_udphop_mode(component) {
            // An invalid component is the mode gate's load error; the
            // advisory never speaks for a mode set the profile cannot use.
            None => return false,
            Some(FinalmaskUdpHopMode::IntervalLocal | FinalmaskUdpHopMode::IntervalRemote) => {
                interval = true;
            }
            Some(FinalmaskUdpHopMode::PerConnRemote) => {}
        }
    }
    interval
}

/// Validate one `udphop` UDP mask's settings against the mask build and the
/// wrap-time checks (`infra/conf/transport_finalmask.go:911-965` and
/// `transport/internet/finalmask/udphop/conn.go:71-73`).
fn finalmask_validate_udphop(
    path: &str,
    settings: &super::stream::FinalmaskUdpHop,
    issues: &mut Vec<ValidationIssue>,
) {
    // The build splits on ',' and refuses every component outside the three
    // names, case-insensitively and without trimming each split part
    // (`strings.Split` + `strings.ToLower`,
    // `infra/conf/transport_finalmask.go:925-940`), so a whitespace-carrying
    // component is refused too — the pinned core exits with `invalid mode
    // intervalRemote` for `"intervalLocal, intervalRemote"`. An empty mode
    // splits to one empty component and is refused as well.
    if settings
        .mode
        .split(',')
        .any(|component| finalmask_udphop_mode(component).is_none())
    {
        issues.push(issue(
            ValidationCode::FinalmaskUdpHopModeInvalid,
            Some(format!("{path}.mode")),
        ));
    }
    // The wrap refuses either endpoint below 5 seconds, so an unset zero is
    // refused alongside 1 through 4.
    let (from, to) = finalmask_range_bounds(settings.interval);
    if from < 5 || to < 5 {
        issues.push(issue(
            ValidationCode::FinalmaskUdpHopIntervalTooSmall,
            Some(format!("{path}.interval")),
        ));
    }
    finalmask_validate_port_list(
        &format!("{path}.remotePorts"),
        &settings.remote_ports,
        issues,
    );
    for (index, entry) in settings.remote_ips.iter().enumerate() {
        if crate::model::stream::finalmask_udphop_remote_ip(entry).is_none() {
            issues.push(issue(
                ValidationCode::FinalmaskUdpHopIpInvalid,
                Some(format!("{path}.remoteIPs[{index}]")),
            ));
        }
    }
    if let Some(sockopt) = &settings.sockopt {
        issues.extend(validate_sockopt(sockopt, &format!("{path}.sockopt")));
    }
}

fn finalmask_validate_realm_tls(
    path: &str,
    tls: &super::stream::FinalmaskRealmTls,
    issues: &mut Vec<ValidationIssue>,
) {
    if tls.allow_insecure == Some(true) {
        issues.push(issue(
            ValidationCode::FinalmaskRealmAllowInsecureRemoved,
            Some(format!("{path}.allowInsecure")),
        ));
    }
    // Canonical fingerprint vocabulary (src/model/fingerprint.rs): the full
    // table. The historical inline allow-list lowercased the value before
    // matching; `wire_validation_supported` keeps that ASCII-case tolerance.
    if !crate::model::fingerprint::wire_validation_supported(&tls.fingerprint) {
        issues.push(issue(
            ValidationCode::FinalmaskRealmFingerprintUnknown,
            Some(format!("{path}.fingerprint")),
        ));
    }
    if tls.alpn.len() > 1 && tls.alpn.iter().any(|alpn| alpn == "fromMitm") {
        issues.push(issue(
            ValidationCode::FinalmaskRealmAlpnFromMitm,
            Some(format!("{path}.alpn")),
        ));
    }
    for (certificate_index, certificate) in tls.certificates.iter().enumerate() {
        if certificate.certificate_file.is_empty()
            && certificate.certificate.iter().all(String::is_empty)
        {
            issues.push(issue(
                ValidationCode::FinalmaskRealmCertRequired,
                Some(format!("{path}.certificates[{certificate_index}]")),
            ));
        }
    }
    if !tls.ech_server_keys.is_empty()
        && base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &tls.ech_server_keys,
        )
        .is_err()
    {
        issues.push(issue(
            ValidationCode::FinalmaskRealmEchKeysBase64,
            Some(format!("{path}.echServerKeys")),
        ));
    }
    if let Some(sockopt) = &tls.ech_sockopt {
        issues.extend(validate_sockopt(sockopt, &format!("{path}.echSockopt")));
    }
}

// ---------- settings-level verdict ----------
//
// The generator's former private pass, now the model's single answer to
// "is this configuration valid". It runs the profile set, then every
// settings-wide rule, in the exact order the generator walked them, and
// never short-circuits — every finding is reported with its severity.
// Callers gate on the first [`Severity::Error`] (generation's single-error
// surface) or render the whole list (editors, tests).
//
// Findings scoped to one model instance carry the human-readable location
// (a profile's display name, an inbound label) as their path; findings
// whose message already names the offender carry none. Generation renders
// a path-carrying finding as `"{location}: {rule message}"` — the same
// bytes the pre-pass generator emitted.

/// True when a local inbound's "require authentication" intent never
/// reaches the wire: password mode with an empty account list. SOCKS
/// carries an `auth` key, so its password mode with zero accounts denies
/// every connection — genuinely safe and never trapped; HTTP carries no
/// auth key, so `accounts` is its only authentication and the empty list
/// leaves the listener open. Derived from [`LocalInboundCfg::authenticates`]
/// — the exposure rule and this gate share that one model truth, never
/// re-implemented.
pub fn inbound_auth_trap(entry: &LocalInboundCfg) -> bool {
    entry.auth == "password" && !entry.authenticates()
}

/// The gateway list's IPv4 address: the first entry whose CIDR prefix is an
/// IPv4 literal. `None` for an empty or IPv6-only list — TUN then has no
/// adapter address and no in-subnet address for the in-tun DNS listener
/// ([`ValidationCode::TunIpv4GatewayRequired`]); the generator derives the
/// DNS listener address from the same value.
pub fn tun_ipv4_gateway(tun: &TunCfg) -> Option<&str> {
    tun.gateway
        .iter()
        .find_map(|entry| entry.split('/').next().filter(|ip| ip.contains('.')))
}

/// Canonical form of a Windows socket path (case-folded, `/` → `\`,
/// `.`/`..` resolved, separators collapsed) — the comparison key for the
/// dokodemo UNIX-listener conflict rule and the inbounds screen's row
/// highlight. One implementation, shared by both.
pub(crate) fn normalize_windows_socket_path(path: &str) -> String {
    let path: String = path
        .trim()
        .chars()
        .flat_map(|character| (if character == '/' { '\\' } else { character }).to_lowercase())
        .collect();
    let bytes = path.as_bytes();
    let unc = path.starts_with(r"\\");
    let has_drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';

    let (prefix, remainder, rooted, protected_components) = if unc {
        (r"\\", path.trim_start_matches('\\'), true, 2)
    } else if has_drive {
        let remainder = &path[2..];
        (
            &path[..2],
            remainder.trim_start_matches('\\'),
            remainder.starts_with('\\'),
            0,
        )
    } else if path.starts_with('\\') {
        ("", path.trim_start_matches('\\'), true, 0)
    } else {
        ("", path.as_str(), false, 0)
    };

    let mut components = Vec::new();
    for component in remainder
        .split('\\')
        .filter(|component| !component.is_empty())
    {
        let protected_unc_component = unc && components.len() < protected_components;
        if component == "." && !protected_unc_component {
            continue;
        }
        if component == ".." && !protected_unc_component {
            if components.len() > protected_components && components.last().copied() != Some("..") {
                components.pop();
            } else if !rooted {
                components.push(component);
            }
            continue;
        }
        components.push(component);
    }

    let mut normalized = String::with_capacity(path.len());
    normalized.push_str(prefix);
    if rooted && !normalized.ends_with('\\') {
        normalized.push('\\');
    }
    for (index, component) in components.into_iter().enumerate() {
        if index != 0 {
            normalized.push('\\');
        }
        normalized.push_str(component);
    }
    normalized
}

/// Protocol mask for dokodemo IP modes (TCP=1, UDP=2, TCP+UDP=3); UNIX
/// listeners are not IP listeners and have no mask.
fn dokodemo_ip_protocols(mode: DokodemoNetwork) -> Option<u8> {
    Some(match mode {
        DokodemoNetwork::Tcp => 1,
        DokodemoNetwork::Udp => 2,
        DokodemoNetwork::TcpUdp => 3,
        DokodemoNetwork::Unix => return None,
    })
}

/// A profile's human-readable location: its name when set, else its
/// generated tag — the same choice the pre-pass generator made when
/// prefixing a profile's first invalid-model finding. Bounded with [`excerpt`]
/// because both halves are user-authored and only the share-link importer
/// caps them: the value becomes the path of every finding scoped to that
/// profile (and the generator's invalid-model message).
fn profile_display_name(profile: &ServerProfile) -> String {
    if profile.name.is_empty() {
        excerpt(&profile.tag())
    } else {
        excerpt(&profile.name)
    }
}

/// Validate the server-profile set: identity and generated-tag rules, every
/// profile's outbound model (findings scoped to the profile's display name,
/// warnings included), and the chained-outbound graph. `require_nonempty`
/// is the latency probe's at-least-one-profile gate.
pub fn validate_profiles(
    profiles: &[ServerProfile],
    active_id: Option<&str>,
    require_nonempty: bool,
) -> Vec<ValidationIssue> {
    let outbound_tags = emit::profile_outbound_tags(profiles);
    profile_set_verdict(profiles, active_id, require_nonempty, &outbound_tags)
}

/// [`validate_profiles`]'s body: the profile-level findings, judged against
/// the outbound tags the given configuration carries (`outbound_tags`, so
/// every target check below reads the emission universe rather than a copy of
/// it).
fn profile_set_verdict(
    profiles: &[ServerProfile],
    active_id: Option<&str>,
    require_nonempty: bool,
    outbound_tags: &BTreeSet<String>,
) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    if require_nonempty && profiles.is_empty() {
        issues.push(issue(ValidationCode::ProfilesRequired, None));
    }
    if let Some(active_id) = active_id {
        let active_matches = profiles
            .iter()
            .filter(|profile| profile.id == active_id)
            .count();
        match active_matches {
            1 => {}
            0 => issues.push(issue(
                ValidationCode::ActiveProfileMissing(excerpt(active_id)),
                None,
            )),
            count => issues.push(issue(
                ValidationCode::ActiveProfileAmbiguous(excerpt(active_id), count),
                None,
            )),
        }
    }

    let mut profile_ids = BTreeMap::<&str, usize>::new();
    let mut profile_tags = BTreeMap::<String, (&str, usize)>::new();
    for (index, profile) in profiles.iter().enumerate() {
        let profile_number = index + 1;
        if profile.id.trim().is_empty() {
            issues.push(issue(ValidationCode::ProfileIdEmpty(profile_number), None));
        }
        if let Some(first_number) = profile_ids.insert(profile.id.as_str(), profile_number) {
            issues.push(issue(
                ValidationCode::ProfileIdDuplicated(
                    first_number,
                    profile_number,
                    excerpt(&profile.id),
                ),
                None,
            ));
        }

        let tag = profile.tag();
        let tag_usable = if tag.trim().is_empty() {
            issues.push(issue(
                ValidationCode::ProfileTagEmpty(profile_number, excerpt(&profile.id)),
                None,
            ));
            false
        } else if tag
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        {
            issues.push(issue(
                ValidationCode::ProfileTagInvalid(
                    profile_number,
                    excerpt(&profile.id),
                    excerpt(&tag),
                ),
                None,
            ));
            false
        } else if matches!(tag.as_str(), DIRECT_OUTBOUND_TAG | BLOCK_OUTBOUND_TAG) {
            issues.push(issue(
                ValidationCode::ProfileTagReserved(
                    profile_number,
                    excerpt(&profile.id),
                    excerpt(&tag),
                ),
                None,
            ));
            false
        } else {
            true
        };
        if tag_usable {
            if let Some(&(first_id, first_number)) = profile_tags.get(&tag) {
                issues.push(issue(
                    ValidationCode::ProfileTagDuplicated(
                        first_number,
                        excerpt(first_id),
                        profile_number,
                        excerpt(&profile.id),
                        excerpt(&tag),
                    ),
                    None,
                ));
            } else {
                profile_tags.insert(tag, (profile.id.as_str(), profile_number));
            }
        }
    }

    for profile in profiles {
        let location = profile_display_name(profile);
        for finding in validate_outbound(&profile.outbound) {
            issues.push(ValidationIssue {
                code: finding.code,
                path: Some(location.clone()),
                severity: finding.severity,
            });
        }
    }

    // The chain rules (dangling hop, cycle) belong to the dial graph, which
    // every other profile-set question reads (the generator's bootstrap
    // scope, the probe's staged child, the delete dialog's references).
    issues.extend(super::dial::DialGraph::new(profiles, outbound_tags).chain_findings());

    issues
}

/// One settings-level verdict for the whole configuration: the server
/// profiles the settings reference, then every settings-wide rule —
/// balancers, local inbounds, dokodemo listeners, TUN, listener collisions,
/// routing rules, DNS servers, fakeDNS pools, geodata — in the generator's
/// order. `api_port` is the loopback control-plane port generation will
/// bind; the API listener participates in the collision rule like every
/// other listener. `settings.mode` selects the TUN rules.
pub fn validate_settings(
    settings: &Settings,
    servers: &ServersFile,
    api_port: u16,
) -> Vec<ValidationIssue> {
    // The emitted outbound universe first: every check below — the profile
    // verdict's chain targets, the balancer fallbacks, the rules — judges the
    // tags the generated document carries.
    let outbound_tags = emit::outbound_tags(servers, settings);
    let mut issues = profile_set_verdict(
        &servers.profiles,
        servers.active.as_deref(),
        false,
        &outbound_tags,
    );
    let tun_on = emit::tun_inbound_emitted(settings);

    let mut balancer_tags = BTreeSet::new();
    for (index, balancer) in settings.routing.balancers.iter().enumerate() {
        if balancer.tag.trim().is_empty() {
            issues.push(issue(ValidationCode::BalancerTagMissing(index + 1), None));
            // The remaining checks would name a tag that does not exist.
            continue;
        }
        if balancer
            .selector
            .iter()
            .all(|selector| selector.trim().is_empty())
        {
            issues.push(issue(
                ValidationCode::BalancerSelectorMissing(excerpt(&balancer.tag)),
                None,
            ));
        }
        if !balancer_tags.insert(balancer.tag.clone()) {
            issues.push(issue(
                ValidationCode::BalancerTagDuplicated(excerpt(&balancer.tag)),
                None,
            ));
        }
        if !balancer.fallback_tag.is_empty() && !outbound_tags.contains(&balancer.fallback_tag) {
            issues.push(issue(
                ValidationCode::BalancerFallbackMissing(
                    excerpt(&balancer.tag),
                    excerpt(&balancer.fallback_tag),
                ),
                None,
            ));
        }
    }

    let mut ip_listeners = vec![("API".to_string(), "127.0.0.1".to_string(), api_port, 1_u8)];
    // The set this walk grows is the emitted inbound universe
    // (`emit::inbound_tags`: API, TUN, dns-in, the emitted local endpoints,
    // the emitted dokodemo listeners). It is built by insertion because the
    // insert that fails IS the duplicate rule — the arm that inserts second
    // reports the collision, in emission order, so the findings below stay in
    // the order their refusal reads. Which entries are emitted and which tags
    // the emitter adds itself are `emit`'s answers (`local_inbound_emitted`,
    // `dokodemo_emitted`, `appended_inbound_tags`), so the two readers of the
    // universe can never drift apart.
    let mut inbound_tags = BTreeSet::from([API_INBOUND_TAG.to_string()]);
    // Local endpoints: every emitted entry must bind a valid listen address
    // on a non-zero port, and its tag must be unique among all emitted
    // inbound tags (local endpoints, TUN, dns-in, API, dokodemo).
    for (index, entry) in settings.local_inbounds.iter().enumerate() {
        if !emit::local_inbound_emitted(entry) {
            continue;
        }
        // "Require authentication" ticked with zero accounts is a lie at
        // any bind: the wire projection drops the empty list and Xray's
        // HTTP inbound then serves everyone. SOCKS password mode with an
        // empty list denies all and never traps.
        if inbound_auth_trap(entry) {
            issues.push(issue(
                ValidationCode::LocalInboundAuthRequiresAccounts,
                None,
            ));
        }
        if entry.port == 0 {
            issues.push(issue(
                ValidationCode::LocalInboundPortZero(excerpt(&entry.tag)),
                None,
            ));
        }
        let listen_valid = validate_listen_address(&entry.listen).is_ok();
        if !listen_valid {
            issues.push(issue(
                ValidationCode::ListenAddressInvalid,
                Some(format!("local inbound {:?}", excerpt(&entry.tag))),
            ));
        }
        // Inbound sniffing vocabulary: Xray refuses the whole config at
        // load on an unknown destOverride protocol, so this gates
        // generate/apply exactly like the load refusal. The "fakedns" item
        // the generator appends at wire time is part of the accepted
        // vocabulary, so it can never false-positive here.
        for finding in
            validate_sniffing(&entry.sniffing, &format!("localInbounds[{index}].sniffing"))
        {
            issues.push(ValidationIssue {
                code: finding.code,
                path: Some(format!("local inbound {:?}", excerpt(&entry.tag))),
                severity: finding.severity,
            });
        }
        if listen_valid && entry.port != 0 {
            let protocols = match entry.protocol {
                LocalInboundProtocol::Socks => 1 | if entry.udp { 2 } else { 0 },
                LocalInboundProtocol::Http => 1,
            };
            ip_listeners.push((
                format!("local inbound {:?}", excerpt(&entry.tag)),
                entry.listen.clone(),
                entry.port,
                protocols,
            ));
        }
        if !inbound_tags.insert(entry.tag.clone()) {
            issues.push(issue(
                ValidationCode::InboundTagDuplicated(excerpt(&entry.tag)),
                None,
            ));
        }
    }

    let mut unix_listeners = BTreeMap::<String, String>::new();
    for (index, inbound) in settings.dokodemo.iter().enumerate() {
        if !emit::dokodemo_emitted(inbound) {
            continue;
        }
        if inbound.tag.is_empty() {
            issues.push(issue(ValidationCode::DokodemoTagMissing(index + 1), None));
        }
        let tag = inbound.tag.clone();
        let mode = inbound.network_mode();
        if let Err(error) = &mode {
            issues.push(issue(
                ValidationCode::DokodemoNetworkInvalid(excerpt(&tag), excerpt(error)),
                None,
            ));
        }
        // Same sniffing gate as the local endpoints above.
        for finding in validate_sniffing(&inbound.sniffing, &format!("dokodemo[{index}].sniffing"))
        {
            issues.push(ValidationIssue {
                code: finding.code,
                path: Some(format!("dokodemo inbound {:?}", excerpt(&tag))),
                severity: finding.severity,
            });
        }
        match mode {
            Ok(DokodemoNetwork::Unix) => {
                let path = inbound.unix_socket_path.trim();
                if path.is_empty() {
                    issues.push(issue(
                        ValidationCode::DokodemoUnixSocketRequired(excerpt(&tag)),
                        None,
                    ));
                } else {
                    let normalized = normalize_windows_socket_path(path);
                    match unix_listeners.get(&normalized) {
                        Some(other) => issues.push(issue(
                            ValidationCode::DokodemoUnixSocketConflict(
                                excerpt(&tag),
                                excerpt(other),
                                excerpt(path),
                            ),
                            None,
                        )),
                        None => {
                            unix_listeners.insert(normalized, tag.clone());
                        }
                    }
                }
            }
            Ok(DokodemoNetwork::Tcp | DokodemoNetwork::Udp | DokodemoNetwork::TcpUdp) => {
                if inbound.listen_port == 0 {
                    issues.push(issue(ValidationCode::DokodemoPortZero(excerpt(&tag)), None));
                }
                let listen_valid = validate_listen_address(&inbound.listen).is_ok();
                if !listen_valid {
                    issues.push(issue(
                        ValidationCode::ListenAddressInvalid,
                        Some(format!("dokodemo inbound {:?}", excerpt(&tag))),
                    ));
                }
                if listen_valid && inbound.listen_port != 0 {
                    let protocols =
                        dokodemo_ip_protocols(mode.expect("matched IP mode")).expect("IP mask");
                    ip_listeners.push((
                        format!("dokodemo inbound {:?}", excerpt(&tag)),
                        inbound.listen.clone(),
                        inbound.listen_port,
                        protocols,
                    ));
                }
            }
            Err(_) => {}
        }
        if !inbound_tags.insert(tag.clone()) {
            issues.push(issue(
                ValidationCode::InboundTagDuplicated(excerpt(&tag)),
                None,
            ));
        }
    }

    // The TUN gateway entries become the adapter's addresses, and the
    // in-tun DNS listener anchors on the gateway's IPv4 (the WFP DNS shield
    // permits port-53 only inside the TUN subnet). The IPv4 gateway is a
    // virtual address that needs no IPv4 from the network — an IPv6-only
    // uplink still works with it — so an IPv6-only gateway list is refused
    // by design, not for want of an address. An empty list is refused with
    // it: nothing would own the address the adapter DNS pins.
    let tun_gateway = tun_ipv4_gateway(&settings.tun);
    if tun_on && tun_gateway.is_none() {
        issues.push(issue(ValidationCode::TunIpv4GatewayRequired, None));
    }
    // The tags the emitter appends behind the configured entries reserve their
    // slots here, in the emitter's own order: the insert that fails reports
    // the collision for the arm walked second, so a configured entry reusing
    // one of these tags is reported on the reserved arm exactly as the
    // document carries it.
    for tag in emit::appended_inbound_tags(settings) {
        if !inbound_tags.insert(tag.to_string()) {
            issues.push(issue(
                ValidationCode::InboundTagDuplicated(tag.into()),
                None,
            ));
        }
    }
    // The in-tun DNS listener (TUN gateway:53, TCP+UDP) is added to the
    // running TUN core while a DNS module exists; a user listener on the
    // same endpoint must be rejected like any other collision.
    if emit::dns_inbound_emitted(settings)
        && let Some(address) = tun_gateway
    {
        ip_listeners.push(("DNS-in".into(), address.to_string(), 53, 3));
    }
    // The conjunction itself is one definition
    // (`crate::model::inbound::listen_endpoints_conflict`); this walk keeps
    // the model-level concerns — each entry's label, the pairing against
    // earlier listeners, and the `ListenerConflict` code. Disabled entries,
    // invalid listen addresses, and zero ports never reach `ip_listeners`.
    for current in 0..ip_listeners.len() {
        let (label, address, port, protocols) = &ip_listeners[current];
        let endpoint = (*port, *protocols, address.as_str());
        if let Some(other) = ip_listeners[..current].iter().find(|other| {
            let (_, other_address, other_port, other_protocols) = other;
            listen_endpoints_conflict(
                endpoint,
                (*other_port, *other_protocols, other_address.as_str()),
            )
        }) {
            issues.push(issue(
                ValidationCode::ListenerConflict(
                    label.clone(),
                    other.0.clone(),
                    address.clone(),
                    *port,
                ),
                None,
            ));
        }
    }

    for (index, rule) in settings.routing.rules.iter().enumerate() {
        if let Some(error) = rule.target_error() {
            issues.push(issue(
                ValidationCode::RoutingRuleTarget(index + 1, error.to_string()),
                None,
            ));
            // The reference checks below would name an unresolved target.
            continue;
        }
        if !rule.outbound_tag.is_empty() && !outbound_tags.contains(&rule.outbound_tag) {
            issues.push(issue(
                ValidationCode::RoutingRuleOutboundMissing(index + 1, excerpt(&rule.outbound_tag)),
                None,
            ));
        }
        if !rule.balancer_tag.is_empty() && !balancer_tags.contains(&rule.balancer_tag) {
            issues.push(issue(
                ValidationCode::RoutingRuleBalancerMissing(index + 1, excerpt(&rule.balancer_tag)),
                None,
            ));
        }
        if let Some(tag) = rule
            .inbound_tag
            .iter()
            .find(|tag| !inbound_tags.contains(*tag))
        {
            issues.push(issue(
                ValidationCode::RoutingRuleInboundMissing(index + 1, excerpt(tag)),
                None,
            ));
        }
    }

    for (index, server) in settings.dns.servers.iter().enumerate() {
        if server.address.trim().is_empty() {
            issues.push(issue(
                ValidationCode::DnsServerAddressMissing(index + 1),
                None,
            ));
        }
    }
    // fakeDNS pools must be CIDRs Xray's fakeip holder can build: a bad
    // range, a non-positive size, or an LRU size not smaller than the
    // subnet fails the core at start (app/dns/fakedns/fake.go:82-90) — such
    // a config must never be applied.
    for (index, pool) in settings.dns.fakedns.pools.iter().enumerate() {
        let parsed = parse_pool_cidr(&pool.ip_pool);
        if parsed.is_none() {
            issues.push(issue(
                ValidationCode::FakeDnsPoolCidrInvalid(index + 1),
                None,
            ));
        }
        if pool.pool_size < 1 {
            issues.push(issue(
                ValidationCode::FakeDnsPoolSizeInvalid(index + 1),
                None,
            ));
        }
        if let Some((_, host_bits)) = parsed
            && pool.pool_size >= 1
            && host_bits < 63
            && (pool.pool_size as u64) >= (1u64 << host_bits)
        {
            issues.push(issue(
                ValidationCode::FakeDnsPoolCapacityExceeded(
                    index + 1,
                    pool.pool_size,
                    excerpt(&pool.ip_pool),
                ),
                None,
            ));
        }
    }

    // Geodata block: when configured, every URL must be HTTPS-with-host and
    // the cron (when set) must be the 5-field shape. Empty = unconfigured.
    if settings.geodata.is_configured() {
        for (url, file) in [
            (settings.geodata.geoip_url.as_deref(), "geoip.dat"),
            (settings.geodata.geosite_url.as_deref(), "geosite.dat"),
        ] {
            if let Some(url) = url
                && !crate::model::settings::geodata_url_valid(url)
            {
                issues.push(issue(
                    ValidationCode::GeodataUrlInvalid(file.to_string()),
                    None,
                ));
            }
        }
        if let Some(cron) = settings.geodata.cron.as_deref()
            && !crate::model::settings::geodata_cron_valid(cron)
        {
            issues.push(issue(ValidationCode::GeodataCronInvalid, None));
        }
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::outbound::{OutboundModel, Protocol, ProtocolSettings};
    use crate::model::stream::{
        CustomSockopt, GrpcSettings, HttpupgradeSettings, HysteriaTransport, KcpSettings, Security,
        SockoptModel, WsSettings, XhttpSettings,
    };
    use serde_json::json;

    fn codes(issues: &[ValidationIssue]) -> Vec<ValidationCode> {
        issues.iter().map(|issue| issue.code.clone()).collect()
    }

    /// Every published field vocabulary and the predicate that judges it
    /// agree: the predicate accepts each entry of the list, and refuses the
    /// near-misses the list does not hold (a case variant of a case-sensitive
    /// vocabulary, a spelling with stray whitespace, a value one step past
    /// the set). A combo that offers a value its own rule refuses, or a rule
    /// that drifts off its list, reds here. `WG_TARGET_STRATEGY_OPTIONS` is
    /// the one published list without a pair: the dial keeps its own default
    /// for an unknown value, so nothing judges it.
    #[test]
    fn field_vocabularies_and_their_predicates_agree() {
        fn couples(options: &[&str], accepts: impl Fn(&str) -> bool, refused: &[&str]) {
            assert!(
                !options.is_empty(),
                "a published vocabulary must hold the values it offers"
            );
            for entry in options {
                assert!(
                    accepts(entry),
                    "{entry:?} is in its vocabulary and refused by its predicate"
                );
            }
            for neighbour in refused {
                assert!(
                    !accepts(neighbour),
                    "{neighbour:?} is outside the vocabulary and must be refused"
                );
            }
        }

        couples(
            TARGET_STRATEGY_OPTIONS,
            target_strategy_supported,
            &["ForceIPv6v4 ", "asis+", "bogus"],
        );
        couples(
            SOCKOPT_DOMAIN_STRATEGY_OPTIONS,
            sockopt_domain_strategy_supported,
            &["asis+", "bogus"],
        );
        couples(
            SOCKOPT_ADDRESS_PORT_STRATEGY_OPTIONS,
            sockopt_address_port_strategy_supported,
            &["srvportonly ", "txtportandaddress!", "bogus"],
        );
        couples(
            SS_METHOD_OPTIONS,
            shadowsocks_method_supported,
            &["", "aes-128-gcm ", "2022-BLAKE3-AES-128-GCM", "bogus"],
        );
        couples(
            XHTTP_MODE_OPTIONS,
            xhttp_mode_supported,
            &["packet_up", "stream-one-plus", "bogus"],
        );
        couples(
            X_PADDING_PLACEMENT_OPTIONS,
            xpadding_placement_supported,
            &["queryinheader", "body", "bogus"],
        );
        couples(
            XPADDING_METHOD_OPTIONS,
            xpadding_method_supported,
            &["repeatx", "cookie", "bogus"],
        );
        couples(
            UPLINK_DATA_PLACEMENT_OPTIONS,
            uplink_data_placement_supported,
            &["path", "body ", "bogus"],
        );
        couples(
            SESSION_ID_PLACEMENT_OPTIONS,
            session_id_placement_supported,
            &["body", "query ", "bogus"],
        );
        couples(
            SEQ_PLACEMENT_OPTIONS,
            seq_placement_supported,
            &["body", "query ", "bogus"],
        );
        couples(
            TLS_VERSION_OPTIONS,
            tls_version_supported,
            &["", "1.4", "TLSv1.3", "bogus"],
        );
        couples(
            VMESS_SECURITY_OPTIONS,
            vmess_security_supported,
            &["", "AES-128-GCM", "auto ", "bogus"],
        );
        couples(
            VISION_FLOW_OPTIONS,
            is_vision_flow,
            &["", "xtls-rprx-vision-udp444", "bogus"],
        );
    }

    #[test]
    fn single_pass_reports_protocol_stream_and_transport_security_issues() {
        let mut outbound = OutboundModel::new(Protocol::Vless);
        let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.address = "example.com".into();
        settings.flow = "xtls-rprx-vision".into();
        settings.encryption = "none".into();
        // Ws without settings + Reality on Ws + sockopt violation: stream,
        // transport-security, and sockopt classes surface in one call.
        // VisionRequiresTlsOrReality deliberately does NOT fire here: REALITY
        // satisfies the Vision security requirement (the gate is
        // security == None), so this fixture only exercises the reality/ws
        // conflict, missing-settings, and sockopt rules.
        outbound.stream.network = crate::model::stream::Network::Ws;
        outbound.stream.security = Security::Reality;
        outbound.stream.reality_settings = Some(Default::default());
        outbound.stream.sockopt = Some(SockoptModel {
            domain_strategy: "future-strategy".into(),
            ..Default::default()
        });

        let issues = validate_outbound(&outbound);
        let found = codes(&issues);
        for code in [
            ValidationCode::RealityRequiresTransport,
            ValidationCode::TransportSettingsMissing(crate::model::stream::Network::Ws),
            ValidationCode::SockoptDomainStrategyInvalid,
        ] {
            assert!(found.contains(&code), "missing {code:?} in {found:#?}");
        }
    }

    /// Xray types `wsSettings.headers`, `httpupgradeSettings.headers` and the
    /// XHTTP settings' `headers` as `map[string]string`. A non-string value
    /// cannot be built into the document (and cannot be migrated out of the
    /// legacy `Host` form), and only a hand-edited state file can carry one —
    /// the share-link grammar refuses it on import — so the model must gate it
    /// with a field-scoped finding instead of spending a core start on the
    /// failure.
    #[test]
    fn non_string_transport_header_values_gate_the_profile() {
        for (network, path) in [
            (Network::Xhttp, "stream.xhttpSettings.headers"),
            (Network::Ws, "stream.wsSettings.headers"),
            (Network::Httpupgrade, "stream.httpupgradeSettings.headers"),
        ] {
            let headers = |value: Value| {
                let mut headers = serde_json::Map::new();
                headers.insert("Host".to_string(), value);
                headers
            };

            let mut outbound = vless_canonical();
            outbound.stream.network = network;
            match network {
                Network::Xhttp => {
                    outbound.stream.xhttp_settings = Some(XhttpSettings {
                        headers: headers(json!(123)),
                        ..Default::default()
                    })
                }
                Network::Ws => {
                    outbound.stream.ws_settings = Some(WsSettings {
                        headers: headers(json!(123)),
                        ..Default::default()
                    })
                }
                Network::Httpupgrade => {
                    outbound.stream.httpupgrade_settings = Some(HttpupgradeSettings {
                        headers: headers(json!(123)),
                        ..Default::default()
                    })
                }
                _ => unreachable!(),
            }
            let issues = validate_outbound(&outbound);
            let finding = issues
                .iter()
                .find(|issue| issue.code == ValidationCode::HeaderValuesNotStrings(network))
                .unwrap_or_else(|| {
                    panic!("{network:?} must gate a non-string header value: {issues:#?}")
                });
            assert_eq!(finding.path.as_deref(), Some(path));
            assert_eq!(finding.severity, Severity::Error);

            // A string-valued map — including the legacy `Host` form the wire
            // pass canonicalizes — still validates.
            let mut outbound = vless_canonical();
            outbound.stream.network = network;
            let string_headers = headers(json!("example.com"));
            match network {
                Network::Xhttp => {
                    outbound.stream.xhttp_settings = Some(XhttpSettings {
                        headers: string_headers,
                        ..Default::default()
                    })
                }
                Network::Ws => {
                    outbound.stream.ws_settings = Some(WsSettings {
                        headers: string_headers,
                        ..Default::default()
                    })
                }
                Network::Httpupgrade => {
                    outbound.stream.httpupgrade_settings = Some(HttpupgradeSettings {
                        headers: string_headers,
                        ..Default::default()
                    })
                }
                _ => unreachable!(),
            }
            let issues = validate_outbound(&outbound);
            assert!(
                !issues
                    .iter()
                    .any(|issue| matches!(issue.code, ValidationCode::HeaderValuesNotStrings(_))),
                "{network:?} must accept string header values: {issues:#?}"
            );
        }
    }

    #[test]
    fn hysteria_version_rule_covers_outbound_and_transport_with_distinct_paths() {
        let mut outbound = OutboundModel::new(Protocol::Hysteria);
        let ProtocolSettings::Hysteria(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.version = 1;
        outbound.stream.network = crate::model::stream::Network::Hysteria;
        outbound.stream.hysteria_settings = Some(HysteriaTransport {
            version: 1,
            ..Default::default()
        });
        outbound.stream.security = Security::Tls;
        outbound.stream.tls_settings = Some(Default::default());

        let issues = validate_outbound(&outbound);
        let version_issues: Vec<&ValidationIssue> = issues
            .iter()
            .filter(|issue| issue.code == ValidationCode::HysteriaTransportVersion)
            .collect();
        assert_eq!(version_issues.len(), 2, "{issues:#?}");
        assert_eq!(version_issues[0].path.as_deref(), Some("settings.version"));
        assert_eq!(
            version_issues[1].path.as_deref(),
            Some("stream.hysteriaSettings.version")
        );
    }

    #[test]
    fn finalmask_issues_carry_wire_paths_and_parameters() {
        let fm: FinalmaskModel = serde_json::from_value(json!({
            "tcp": [
                {"type": "fragment", "settings": {"packets": "0", "length": 0}},
                {"type": "xmc", "settings": {
                    "password": "", "profiles": [{
                        "username": "x", "uuid": "bad",
                        "texturesValue": "", "texturesSignature": ""
                    }]
                }}
            ],
            "udp": [
                {"type": "noise", "settings": {
                    "noise": [{"rand": 1, "type": "hex", "packet": "00"}]
                }},
                {"type": "salamander", "settings": {"packetSize": "0-2049"}},
                {"type": "xdns", "settings": {"resolvers": ["https://dns.example"]}},
                {"type": "xicmp", "settings": {"ips": ["not-an-ip"]}},
                {"type": "realm", "settings": {"url": "https://example", "stunServers": []}},
                {"type": "udphop", "settings": {
                    "mode": "intervalLocal,banana", "interval": 4,
                    "remotePorts": 70000, "remoteIPs": ["nope"]
                }}
            ],
            "quicParams": {
                "congestion": "force-brutal", "brutalUp": "1 kbps",
                "bbrProfile": "turbo",
                "initStreamReceiveWindow": 1, "maxIdleTimeout": 3,
                "keepAlivePeriod": 61, "maxIncomingStreams": 7
            }
        }))
        .unwrap();
        let issues = validate_finalmask(&fm);
        for (code, path) in [
            (
                ValidationCode::FinalmaskPacketsFirstNotZero,
                "finalmask.tcp[0].settings.packets",
            ),
            (
                ValidationCode::FinalmaskXmcUsernameInvalid,
                "finalmask.tcp[1].settings.profiles[0].username",
            ),
            (
                ValidationCode::FinalmaskNoisePacketExclusive,
                "finalmask.udp[0].settings.noise[0]",
            ),
            (
                ValidationCode::FinalmaskSalamanderPacketSize,
                "finalmask.udp[1].settings.packetSize",
            ),
            (
                ValidationCode::FinalmaskXdnsResolverUdp,
                "finalmask.udp[2].settings.resolvers[0]",
            ),
            (
                ValidationCode::FinalmaskXicmpIpInvalid,
                "finalmask.udp[3].settings.ips[0]",
            ),
            (
                ValidationCode::FinalmaskRealmScheme,
                "finalmask.udp[4].settings.url",
            ),
            (
                ValidationCode::FinalmaskUdpHopModeInvalid,
                "finalmask.udp[5].settings.mode",
            ),
            (
                ValidationCode::FinalmaskUdpHopIntervalTooSmall,
                "finalmask.udp[5].settings.interval",
            ),
            (
                ValidationCode::FinalmaskPortNumberRange,
                "finalmask.udp[5].settings.remotePorts",
            ),
            (
                ValidationCode::FinalmaskUdpHopIpInvalid,
                "finalmask.udp[5].settings.remoteIPs[0]",
            ),
            (
                ValidationCode::FinalmaskQuicBandwidthTooSmall,
                "finalmask.quicParams.brutalUp",
            ),
            (
                ValidationCode::FinalmaskQuicBbrProfileInvalid,
                "finalmask.quicParams.bbrProfile",
            ),
            (
                ValidationCode::FinalmaskQuicReceiveWindowTooSmall,
                "finalmask.quicParams.initStreamReceiveWindow",
            ),
            (
                ValidationCode::FinalmaskQuicMaxIdleTimeoutInvalid,
                "finalmask.quicParams.maxIdleTimeout",
            ),
            (
                ValidationCode::FinalmaskQuicKeepAlivePeriodInvalid,
                "finalmask.quicParams.keepAlivePeriod",
            ),
            (
                ValidationCode::FinalmaskQuicMaxIncomingStreamsInvalid,
                "finalmask.quicParams.maxIncomingStreams",
            ),
        ] {
            assert!(
                issues
                    .iter()
                    .any(|issue| issue.code == code && issue.path.as_deref() == Some(path)),
                "missing {code:?} at {path:?} in {issues:#?}"
            );
        }
    }

    /// Sub-byte bandwidths are values, not unset: a positive bit rate that
    /// truncates below one byte per second reports the too-small rule (blank
    /// input and an explicit zero stay the unset shape the rule's own message
    /// names), and an unparsable `brutalUp` reports only its own rule instead
    /// of doubling with the derived force-brutal requirement.
    #[test]
    fn quic_bandwidth_rounding_reports_sub_byte_values() {
        let issues_for = |congestion: &str, brutal_up: &str| {
            let fm: FinalmaskModel = serde_json::from_value(json!({
                "quicParams": {"congestion": congestion, "brutalUp": brutal_up}
            }))
            .expect("fixture is valid finalmask JSON");
            validate_finalmask(&fm)
        };

        for value in ["5bps", "1", "7 b"] {
            let issues = issues_for("brutal", value);
            assert_eq!(
                codes(&issues),
                vec![ValidationCode::FinalmaskQuicBandwidthTooSmall],
                "brutalUp {value:?} must report the too-small rule: {issues:#?}"
            );
            assert_eq!(
                issues[0].path.as_deref(),
                Some("finalmask.quicParams.brutalUp")
            );
        }
        for value in ["", "  ", "0", "0bps", "0.0 kbps"] {
            let issues = issues_for("brutal", value);
            assert!(
                codes(&issues).is_empty(),
                "brutalUp {value:?} is the unset shape: {issues:#?}"
            );
        }

        assert_eq!(
            codes(&issues_for("force-brutal", "")),
            vec![ValidationCode::FinalmaskQuicForceBrutalNeedsUp],
            "force-brutal still requires an upload rate"
        );
        let refused = issues_for("force-brutal", "1 zap");
        assert_eq!(
            codes(&refused),
            vec![ValidationCode::FinalmaskQuicBandwidthUnitInvalid(
                "zap".into()
            )],
            "one unparsable value must not double-report: {refused:#?}"
        );
    }

    /// The `udphop` mask gates what the mask build and the wrap refuse: a
    /// mode outside the three names (empty included) and an interval
    /// endpoint below 5 seconds (unset included). The editor's fresh mask
    /// and every accepted spelling stay clean.
    #[test]
    fn udphop_mask_gates_the_mode_set_and_the_five_second_floor() {
        let codes_for = |settings: &str| {
            let fm: FinalmaskModel = serde_json::from_str(&format!(
                r#"{{"udp":[{{"type":"udphop","settings":{settings}}}]}}"#
            ))
            .expect("fixture is valid finalmask JSON");
            codes(&validate_finalmask(&fm))
        };

        for settings in [
            r#"{"mode":"perConnRemote","interval":"5-10"}"#,
            r#"{"mode":"intervalLocal,intervalRemote","interval":"5-5"}"#,
            r#"{"mode":"INTERVALREMOTE,INTERVALLOCAL","interval":"5-30"}"#,
            r#"{"mode":"perConnRemote","interval":"30-60"}"#,
        ] {
            assert!(
                codes_for(settings).is_empty(),
                "{settings} must be legal: {:#?}",
                codes_for(settings)
            );
        }

        // The core lowercases but never trims, so a space around a component
        // is a load error, exactly like an unknown name.
        for mode in [
            "",
            "banana",
            "intervalLocal,banana",
            "perConnLocal",
            "intervalLocal, intervalRemote",
            " intervalLocal",
            "intervalLocal ",
        ] {
            let found = codes_for(&format!(r#"{{"mode":"{mode}","interval":"5-10"}}"#));
            assert_eq!(
                found,
                vec![ValidationCode::FinalmaskUdpHopModeInvalid],
                "mode {mode:?}"
            );
        }

        for interval in [json!(0), json!(4), json!("2-10"), json!("5-4")] {
            let found = codes_for(&format!(
                r#"{{"mode":"perConnRemote","interval":{interval}}}"#
            ));
            assert_eq!(
                found,
                vec![ValidationCode::FinalmaskUdpHopIntervalTooSmall],
                "interval {interval}"
            );
        }

        // A `remoteIPs` entry that parses as neither an address nor a prefix
        // is refused at build time, one finding per entry. An IPv6 zone is
        // legal in both forms — Go's ParseAddr keeps it and both
        // ParsePrefix and PrefixFrom strip it again, and a form that fails
        // the prefix parse falls through to the address parse (verified
        // against the pinned core: `fe80::1%eth0`, `2001:db8::1%en0`,
        // `fe80::1%eth0/64`, `fe80::1%eth0%more`, and
        // `fe80::1%eth0/64%x` all load) — while an empty zone, a zone on
        // IPv4, an out-of-range bit count, and a padded entry do not.
        assert_eq!(
            codes_for(
                r#"{"mode":"perConnRemote","interval":"5-10","remoteIPs":["203.0.113.10","nope","2001:db8::/129","fe80::1%","1.2.3.4%eth0"," fe80::1","fe80::1/ 64"]}"#
            ),
            vec![
                ValidationCode::FinalmaskUdpHopIpInvalid,
                ValidationCode::FinalmaskUdpHopIpInvalid,
                ValidationCode::FinalmaskUdpHopIpInvalid,
                ValidationCode::FinalmaskUdpHopIpInvalid,
                ValidationCode::FinalmaskUdpHopIpInvalid,
                ValidationCode::FinalmaskUdpHopIpInvalid,
            ]
        );
        assert!(
            codes_for(
                r#"{"mode":"perConnRemote","interval":"5-10","remoteIPs":["203.0.113.10","2001:db8::/48","::1","fe80::1%eth0","2001:db8::1%en0","fe80::1%eth0/64","fe80::1%eth0%more","fe80::1%eth0/64%x"]}"#
            )
            .is_empty()
        );
    }

    /// The outermost UDP masks wrap the outbound's own packet connection, so
    /// a dial-through chain cannot run with `udphop`, `realm`, or `xicmp`:
    /// each of those client wraps refuses the proxied packet connection, and
    /// the advisory names the pair while every other combination stays quiet.
    #[test]
    fn proxied_chains_warn_for_every_outermost_mask_without_gating() {
        let mask = |envelope: serde_json::Value| FinalmaskModel {
            udp: vec![serde_json::from_value(envelope).expect("the mask envelope loads")],
            ..Default::default()
        };
        let conflicts = |outbound: &OutboundModel| -> usize {
            validate_outbound(outbound)
                .iter()
                .filter(|issue| issue.code == ValidationCode::FinalmaskDialerProxyConflict)
                .count()
        };

        for (envelope, label) in [
            (
                json!({"type": "udphop", "settings": {"mode": "perConnRemote", "interval": "5-10"}}),
                "udphop",
            ),
            (json!({"type": "realm", "settings": {}}), "realm"),
            (json!({"type": "xicmp", "settings": {}}), "xicmp"),
        ] {
            let mut outbound = OutboundModel::new(Protocol::Vless);
            outbound.stream.finalmask = Some(mask(envelope.clone()));
            assert_eq!(
                conflicts(&outbound),
                0,
                "{label} without a chain must stay quiet"
            );
            outbound.chain_via("srv-exit");
            let issues = validate_outbound(&outbound);
            let found: Vec<_> = issues
                .iter()
                .filter(|issue| issue.code == ValidationCode::FinalmaskDialerProxyConflict)
                .collect();
            assert_eq!(found.len(), 1, "{label}: {issues:#?}");
            assert_eq!(found[0].severity, Severity::Warning, "{label}");
            assert_eq!(found[0].path, None, "{label}");
        }

        // A chain with a mask that never wraps the packet connection stays
        // quiet.
        let mut outbound = OutboundModel::new(Protocol::Vless);
        outbound.stream.finalmask = Some(mask(
            json!({"type": "salamander", "settings": {"password": "pw"}}),
        ));
        outbound.chain_via("srv-exit");
        assert_eq!(
            conflicts(&outbound),
            0,
            "{:#?}",
            validate_outbound(&outbound)
        );
    }

    /// The UDP mask manager reverses the list at construction and wraps
    /// forward (`transport/internet/finalmask/finalmask.go:21-25,28-31` at
    /// v26.9.9), so the wrap pins `udphop`/`realm`/`xicmp` to the last list
    /// entry and `sudoku` to the first. A misplaced entry gates with its
    /// path and the required end; the previously valid `[realm, sudoku]`
    /// chain errors both ways and the editor's move operation repairs it.
    /// Single-mask chains and unconstrained chains stay clean.
    #[test]
    fn udp_mask_order_gates_each_pinned_type_and_the_previous_chain_shape() {
        let order_findings = |list: &str| -> Vec<ValidationIssue> {
            let fm: FinalmaskModel = serde_json::from_str(&format!(r#"{{"udp":{list}}}"#))
                .expect("fixture is valid finalmask JSON");
            validate_finalmask(&fm)
                .into_iter()
                .filter(|issue| {
                    matches!(
                        issue.code,
                        ValidationCode::FinalmaskUdpMaskNotLast(_)
                            | ValidationCode::FinalmaskUdpMaskNotFirst(_)
                    )
                })
                .collect()
        };
        let paths = |findings: &[ValidationIssue]| -> Vec<Option<String>> {
            findings.iter().map(|issue| issue.path.clone()).collect()
        };

        const SALAMANDER: &str = r#"{"type":"salamander","settings":{"password":"pw"}}"#;
        const HEADER: &str = r#"{"type":"header-custom","settings":{}}"#;
        const SUDOKU: &str = r#"{"type":"sudoku","settings":{"password":"pw"}}"#;
        const REALM: &str = r#"{"type":"realm","settings":{"url":"realm://token@203.0.113.10:443/id","stunServers":["stun.example.com:3478"]}}"#;
        const XICMP: &str = r#"{"type":"xicmp","settings":{"ips":["192.0.2.1"]}}"#;
        const UDPHOP: &str =
            r#"{"type":"udphop","settings":{"mode":"perConnRemote","interval":"5-10"}}"#;

        // Single-entry chains fill the pinned slot for every type.
        for mask in [SALAMANDER, HEADER, SUDOKU, REALM, XICMP, UDPHOP] {
            assert!(
                order_findings(&format!("[{mask}]")).is_empty(),
                "a single-entry chain is legal for {mask}"
            );
        }

        // Both pinned ends at once: sudoku first, the last-slot type last.
        for chain in [
            format!("[{SUDOKU},{UDPHOP}]"),
            format!("[{SUDOKU},{REALM}]"),
            format!("[{SUDOKU},{XICMP}]"),
            format!("[{SUDOKU},{SALAMANDER},{UDPHOP}]"),
            format!("[{SUDOKU},{HEADER},{REALM}]"),
        ] {
            assert!(
                order_findings(&chain).is_empty(),
                "chain {chain} is correctly ordered"
            );
        }

        // Unconstrained types wrap in any order.
        for chain in [
            format!("[{SALAMANDER},{HEADER}]"),
            format!("[{HEADER},{SALAMANDER}]"),
            format!("[{HEADER},{SALAMANDER},{HEADER}]"),
        ] {
            assert!(
                order_findings(&chain).is_empty(),
                "chain {chain} has no pinned type"
            );
        }

        // The previously valid shape: realm was first, sudoku last. Both
        // entries now sit at the wrong end.
        let previous = order_findings(&format!("[{REALM},{SUDOKU}]"));
        assert_eq!(
            codes(&previous),
            vec![
                ValidationCode::FinalmaskUdpMaskNotLast("realm".into()),
                ValidationCode::FinalmaskUdpMaskNotFirst("sudoku".into()),
            ],
            "{previous:#?}"
        );
        assert_eq!(
            paths(&previous),
            vec![
                Some("finalmask.udp[0]".to_string()),
                Some("finalmask.udp[1]".to_string())
            ]
        );
        assert!(
            previous
                .iter()
                .all(|issue| issue.severity == Severity::Error)
        );

        // Each last-pinned type misordered at each non-last position.
        for (mask, name) in [(REALM, "realm"), (XICMP, "xicmp"), (UDPHOP, "udphop")] {
            let chain = format!("[{mask},{SALAMANDER}]");
            let found = order_findings(&chain);
            assert_eq!(
                codes(&found),
                vec![ValidationCode::FinalmaskUdpMaskNotLast(name.into())],
                "chain {chain}"
            );
            assert_eq!(paths(&found), vec![Some("finalmask.udp[0]".to_string())]);

            let chain = format!("[{SALAMANDER},{mask},{HEADER}]");
            let found = order_findings(&chain);
            assert_eq!(
                codes(&found),
                vec![ValidationCode::FinalmaskUdpMaskNotLast(name.into())],
                "chain {chain}"
            );
            assert_eq!(paths(&found), vec![Some("finalmask.udp[1]".to_string())]);
        }

        // The last-slot type directly before the end and sudoku anywhere but
        // the start each report on their own entry.
        let found = order_findings(&format!("[{SALAMANDER},{UDPHOP},{REALM}]"));
        assert_eq!(
            codes(&found),
            vec![ValidationCode::FinalmaskUdpMaskNotLast("udphop".into())],
            "{found:#?}"
        );
        let found = order_findings(&format!("[{SALAMANDER},{SUDOKU}]"));
        assert_eq!(
            codes(&found),
            vec![ValidationCode::FinalmaskUdpMaskNotFirst("sudoku".into())],
            "{found:#?}"
        );
        let found = order_findings(&format!("[{UDPHOP},{SUDOKU}]"));
        assert_eq!(
            codes(&found),
            vec![
                ValidationCode::FinalmaskUdpMaskNotLast("udphop".into()),
                ValidationCode::FinalmaskUdpMaskNotFirst("sudoku".into()),
            ],
            "{found:#?}"
        );

        // The editor's move buttons swap neighbouring entries: the old
        // shape becomes the new legal shape with one move.
        let mut fm: FinalmaskModel =
            serde_json::from_str(&format!(r#"{{"udp":[{REALM},{SUDOKU}]}}"#))
                .expect("fixture is valid finalmask JSON");
        assert!(!validate_finalmask(&fm).is_empty());
        fm.udp.swap(0, 1);
        assert!(
            validate_finalmask(&fm).iter().all(|issue| !matches!(
                issue.code,
                ValidationCode::FinalmaskUdpMaskNotLast(_)
                    | ValidationCode::FinalmaskUdpMaskNotFirst(_)
            )),
            "one move must repair the chain"
        );
    }

    /// An interval hop mode moves the outbound's socket, so only a transport
    /// whose connection migrates survives it: the QUIC-based hysteria2 and
    /// xhttp transports, or the WireGuard outbound. Everything else is a
    /// configuration warning (never a gate) and `perConnRemote` is always
    /// fine.
    #[test]
    fn udphop_interval_modes_warn_only_on_transports_that_cannot_migrate() {
        let interval_mask = |mode: &str| FinalmaskModel {
            udp: vec![
                serde_json::from_value(json!({
                    "type": "udphop",
                    "settings": {"mode": mode, "interval": "5-10"}
                }))
                .expect("the udphop envelope loads"),
            ],
            ..Default::default()
        };

        let advisory = |outbound: &OutboundModel| -> usize {
            validate_outbound(outbound)
                .iter()
                .filter(|issue| {
                    issue.code == ValidationCode::FinalmaskUdpHopIntervalTransportConflict
                })
                .count()
        };

        // Every interval spelling on a transport that cannot run a hop. The
        // mode parse mirrors the load build: case-insensitive, no trimming.
        for mode in [
            "intervalLocal",
            "intervalRemote",
            "intervalLocal,intervalRemote",
            "INTERVALREMOTE,INTERVALLOCAL",
        ] {
            let mut outbound = OutboundModel::new(Protocol::Vless);
            outbound.stream.finalmask = Some(interval_mask(mode));
            let issues = validate_outbound(&outbound);
            let found: Vec<_> = issues
                .iter()
                .filter(|issue| {
                    issue.code == ValidationCode::FinalmaskUdpHopIntervalTransportConflict
                })
                .collect();
            assert_eq!(found.len(), 1, "mode {mode:?}: {issues:#?}");
            assert_eq!(found[0].severity, Severity::Warning);
            assert_eq!(found[0].path, None);
        }

        // A whitespace-carrying component is the mode load error's business
        // alone: the advisory must not add a second message for one value.
        let mut spaced = OutboundModel::new(Protocol::Vless);
        spaced.stream.finalmask = Some(interval_mask("intervalLocal, intervalRemote"));
        let issues = validate_outbound(&spaced);
        assert!(
            issues
                .iter()
                .any(|issue| issue.code == ValidationCode::FinalmaskUdpHopModeInvalid),
            "{issues:#?}"
        );
        assert_eq!(advisory(&spaced), 0, "{issues:#?}");

        // Transports that never wrap the mask list, or cannot move a live
        // connection, warn the same way.
        for network in [
            Network::Ws,
            Network::Kcp,
            Network::Grpc,
            Network::Httpupgrade,
        ] {
            let mut outbound = OutboundModel::new(Protocol::Vless);
            outbound.stream.network = network;
            outbound.stream.finalmask = Some(interval_mask("intervalLocal"));
            assert_eq!(advisory(&outbound), 1, "network {network:?}");
        }

        // The transports that can run a hop never warn: hysteria2 and
        // WireGuard unconditionally, xhttp only in its HTTP/3 shape (TLS
        // with ALPN exactly ["h3"]).
        let mut hysteria = OutboundModel::new(Protocol::Vless);
        hysteria.stream.network = Network::Hysteria;
        hysteria.stream.finalmask = Some(interval_mask("intervalLocal"));
        assert_eq!(advisory(&hysteria), 0);

        let mut wireguard = OutboundModel::new(Protocol::Wireguard);
        wireguard.stream.finalmask = Some(interval_mask("intervalLocal,intervalRemote"));
        assert_eq!(advisory(&wireguard), 0);

        let xhttp_with_tls = |alpn: Vec<String>| {
            let mut outbound = OutboundModel::new(Protocol::Vless);
            outbound.stream.network = Network::Xhttp;
            outbound.stream.security = Security::Tls;
            outbound.stream.tls_settings = Some(crate::model::stream::TlsModel {
                alpn,
                ..Default::default()
            });
            outbound.stream.finalmask = Some(interval_mask("intervalLocal"));
            outbound
        };
        assert_eq!(advisory(&xhttp_with_tls(vec!["h3".into()])), 0);

        // Every non-HTTP/3 xhttp shape warns: no TLS (HTTP/1.1), an empty or
        // longer ALPN list and a non-h3 ALPN (HTTP/2), and REALITY, which
        // forces HTTP/2 before the ALPN is read.
        for alpn in [vec![], vec!["h2".into()], vec!["h3".into(), "h2".into()]] {
            assert_eq!(advisory(&xhttp_with_tls(alpn.clone())), 1, "alpn {alpn:?}");
        }
        let mut no_tls = OutboundModel::new(Protocol::Vless);
        no_tls.stream.network = Network::Xhttp;
        no_tls.stream.finalmask = Some(interval_mask("intervalLocal"));
        assert_eq!(advisory(&no_tls), 1);
        let mut reality = OutboundModel::new(Protocol::Vless);
        reality.stream.network = Network::Xhttp;
        reality.stream.security = Security::Reality;
        reality.stream.finalmask = Some(interval_mask("intervalLocal"));
        assert_eq!(advisory(&reality), 1);

        // `perConnRemote`, a mask-free stream, and an unparsable mode never
        // raise the advisory.
        let mut outbound = OutboundModel::new(Protocol::Vless);
        outbound.stream.finalmask = Some(interval_mask("perConnRemote"));
        assert_eq!(advisory(&outbound), 0);
        let mut outbound = OutboundModel::new(Protocol::Vless);
        outbound.stream.finalmask = Some(interval_mask("banana"));
        assert_eq!(advisory(&outbound), 0);
        assert_eq!(advisory(&OutboundModel::new(Protocol::Vless)), 0);

        // A non-hop mask with an unrelated mode-shaped extra stays quiet.
        let mut outbound = OutboundModel::new(Protocol::Vless);
        outbound.stream.finalmask = Some(FinalmaskModel {
            udp: vec![
                serde_json::from_value(json!({
                    "type": "salamander", "settings": {"password": "pw", "mode": "intervalLocal"}
                }))
                .expect("the salamander envelope loads"),
            ],
            ..Default::default()
        });
        assert_eq!(advisory(&outbound), 0);
    }

    /// The realm TLS allow-list is the canonical fingerprint vocabulary
    /// (src/model/fingerprint.rs): adding a fingerprint there must land in
    /// this validation context too, with the same ASCII-case tolerance the
    /// historical lowercased allow-list had. The wire-only names are part of
    /// this context's set even though the editor and links reject them.
    #[test]
    fn realm_tls_accepts_the_canonical_fingerprint_table_case_insensitively() {
        use crate::model::fingerprint::{FINGERPRINTS, VALIDATION_ONLY_FINGERPRINTS};
        use crate::model::stream::FinalmaskRealmTls;
        for &name in FINGERPRINTS.iter().chain(VALIDATION_ONLY_FINGERPRINTS) {
            for fingerprint in [name.to_owned(), name.to_ascii_uppercase()] {
                let mut issues = Vec::new();
                finalmask_validate_realm_tls(
                    "finalmask.udp[0].settings.tlsConfig",
                    &FinalmaskRealmTls {
                        fingerprint,
                        ..Default::default()
                    },
                    &mut issues,
                );
                assert!(
                    !issues.iter().any(|issue| {
                        issue.code == ValidationCode::FinalmaskRealmFingerprintUnknown
                    }),
                    "realm TLS validation rejects {name:?}: {issues:#?}"
                );
            }
        }
        // A name outside the table still reports the Unknown code.
        let mut issues = Vec::new();
        finalmask_validate_realm_tls(
            "finalmask.udp[0].settings.tlsConfig",
            &FinalmaskRealmTls {
                fingerprint: "hellobroccoli_3000".into(),
                ..Default::default()
            },
            &mut issues,
        );
        assert_eq!(
            codes(&issues),
            vec![ValidationCode::FinalmaskRealmFingerprintUnknown]
        );
    }

    #[test]
    fn sockopt_validation_reports_each_rule_code() {
        let sockopt = SockoptModel {
            domain_strategy: "future-strategy".into(),
            tcp_fast_open: Some(json!("not bool or number")),
            tcp_keep_alive_idle: Some(-1),
            tcp_keep_alive_interval: Some(30),
            custom_sockopt: vec![CustomSockopt {
                opt: String::new(),
                r#type: "future".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let issues = validate_sockopt(&sockopt, "stream.sockopt");
        let found = codes(&issues);
        for code in [
            ValidationCode::SockoptDomainStrategyInvalid,
            ValidationCode::SockoptTcpFastOpenType,
            ValidationCode::SockoptKeepaliveSigns,
            ValidationCode::SockoptCustomOptRequired,
            ValidationCode::SockoptCustomTypeInvalid,
        ] {
            assert!(found.contains(&code), "missing {code:?} in {found:#?}");
        }
    }

    // ---- stream/sockopt/strategy enum surfaces ----

    fn xhttp_stream(settings: XhttpSettings) -> StreamModel {
        StreamModel {
            network: crate::model::stream::Network::Xhttp,
            xhttp_settings: Some(settings),
            ..Default::default()
        }
    }

    /// Every xhttp code of the enum surface, in fire order.
    fn xhttp_codes(issues: &[ValidationIssue]) -> Vec<ValidationCode> {
        issues
            .iter()
            .map(|issue| issue.code.clone())
            .filter(|code| {
                matches!(
                    code,
                    ValidationCode::XhttpModeUnsupported
                        | ValidationCode::XhttpPaddingBytesInvalid
                        | ValidationCode::XhttpPaddingPlacementInvalid
                        | ValidationCode::XhttpPaddingMethodInvalid
                        | ValidationCode::XhttpUplinkDataPlacementInvalid
                        | ValidationCode::XhttpUplinkDataPlacementRequiresPacketUp
                        | ValidationCode::XhttpUplinkHttpMethodRequiresPacketUp
                        | ValidationCode::XhttpSessionIdPlacementInvalid
                        | ValidationCode::XhttpSeqPlacementInvalid
                        | ValidationCode::XhttpSessionIdLengthRequired
                        | ValidationCode::XhttpSessionIdTableInvalid
                        | ValidationCode::XhttpXmuxLimitsExclusive
                        | ValidationCode::StreamOneNoDownload
                )
            })
            .collect()
    }

    #[test]
    fn xhttp_canonical_settings_fire_no_xhttp_code() {
        let canonical = XhttpSettings {
            mode: "packet-up".into(),
            x_padding_bytes: Some(Int32Range::new(100, 200)),
            x_padding_placement: "cookie".into(),
            x_padding_method: "tokenish".into(),
            uplink_data_placement: "cookie".into(),
            uplink_http_method: "GET".into(),
            session_id_placement: "query".into(),
            session_id_table: "ALPHABET".into(),
            session_id_length: Some(Int32Range::new(31, 31)),
            seq_placement: "header".into(),
            xmux: Some(XmuxConfig {
                max_concurrency: Some(Int32Range::single(8)),
                ..Default::default()
            }),
            ..Default::default()
        };
        let issues = validate_stream(&xhttp_stream(canonical));
        assert!(
            xhttp_codes(&issues).is_empty(),
            "canonical xhttp state must be silent: {issues:#?}"
        );
        // stream-one with a download is the pre-existing rule; unchanged.
        let stream_one = XhttpSettings {
            mode: "stream-one".into(),
            ..Default::default()
        };
        assert!(xhttp_codes(&validate_stream(&xhttp_stream(stream_one))).is_empty());
    }

    #[test]
    fn xhttp_vocabulary_refusals_fire_per_field_with_wire_paths() {
        let hostile = XhttpSettings {
            mode: "quic".into(),
            x_padding_placement: "body".into(),
            x_padding_method: "aes".into(),
            uplink_data_placement: "path".into(),
            session_id_placement: "auto".into(),
            seq_placement: "auto".into(),
            ..Default::default()
        };
        let issues = validate_stream(&xhttp_stream(hostile));
        let found = xhttp_codes(&issues);
        for code in [
            ValidationCode::XhttpModeUnsupported,
            ValidationCode::XhttpPaddingPlacementInvalid,
            ValidationCode::XhttpPaddingMethodInvalid,
            ValidationCode::XhttpUplinkDataPlacementInvalid,
            ValidationCode::XhttpSessionIdPlacementInvalid,
            ValidationCode::XhttpSeqPlacementInvalid,
        ] {
            assert!(found.contains(&code), "missing {code:?} in {found:#?}");
            let finding = issues
                .iter()
                .find(|issue| issue.code == code)
                .expect("issue present");
            assert_eq!(finding.severity, Severity::Error);
        }
        assert_eq!(issues[0].path.as_deref(), Some("stream.xhttpSettings.mode"));
        assert_eq!(
            issues.len(),
            6,
            "exactly the six vocab refusals: {issues:#?}"
        );
    }

    #[test]
    fn xhttp_cross_field_and_bounds_rules_fire_with_wire_paths() {
        // stream-up mode with cookie placement, GET method, a negative
        // xPaddingBytes range, a both-set xmux, and an insufficient
        // sessionIDTable pair.
        let hostile = XhttpSettings {
            mode: "stream-up".into(),
            x_padding_bytes: Some(Int32Range::new(-1, 100)),
            uplink_data_placement: "cookie".into(),
            uplink_http_method: "get".into(),
            session_id_table: "AB".into(),
            session_id_length: Some(Int32Range::new(2, 2)),
            xmux: Some(XmuxConfig {
                max_concurrency: Some(Int32Range::single(8)),
                max_connections: Some(Int32Range::single(3)),
                ..Default::default()
            }),
            ..Default::default()
        };
        let issues = validate_stream(&xhttp_stream(hostile));
        let found = xhttp_codes(&issues);
        for code in [
            ValidationCode::XhttpPaddingBytesInvalid,
            ValidationCode::XhttpUplinkDataPlacementRequiresPacketUp,
            ValidationCode::XhttpUplinkHttpMethodRequiresPacketUp,
            ValidationCode::XhttpSessionIdTableInvalid,
            ValidationCode::XhttpXmuxLimitsExclusive,
        ] {
            assert!(found.contains(&code), "missing {code:?} in {found:#?}");
        }
        // Every finding is Error tier (Xray refuses these at conf load).
        for issue in &issues {
            assert_eq!(issue.severity, Severity::Error, "{issue:?}");
        }
        let paths: Vec<Option<&str>> = issues.iter().map(|issue| issue.path.as_deref()).collect();
        for path in [
            Some("stream.xhttpSettings.xPaddingBytes"),
            Some("stream.xhttpSettings.uplinkDataPlacement"),
            Some("stream.xhttpSettings.uplinkHTTPMethod"),
            Some("stream.xhttpSettings.sessionIDTable"),
            Some("stream.xhttpSettings.xmux"),
        ] {
            assert!(paths.contains(&path), "missing path {path:?} in {paths:?}");
        }
    }

    #[test]
    fn xhttp_placement_and_get_are_legal_in_packet_up_and_placements_fold_in_ascii_room() {
        // The same values are canonical in packet-up mode.
        let packet_up = XhttpSettings {
            mode: "packet-up".into(),
            uplink_data_placement: "cookie".into(),
            uplink_http_method: "GET".into(),
            ..Default::default()
        };
        assert!(xhttp_codes(&validate_stream(&xhttp_stream(packet_up))).is_empty());

        // A zero xPaddingBytes range is the "padding off" shape — legal.
        let zero_padding = XhttpSettings {
            mode: "auto".into(),
            x_padding_bytes: Some(Int32Range::single(0)),
            ..Default::default()
        };
        assert!(xhttp_codes(&validate_stream(&xhttp_stream(zero_padding))).is_empty());

        // sessionIDLength from ≥ 31 opens 2^31 combinations for any ASCII
        // table of at least two characters; a non-ASCII table cannot.
        let big_room = XhttpSettings {
            session_id_table: "xy".into(),
            session_id_length: Some(Int32Range::new(31, 40)),
            ..Default::default()
        };
        assert!(xhttp_codes(&validate_stream(&xhttp_stream(big_room))).is_empty());
        let non_ascii = XhttpSettings {
            session_id_table: "表x".into(),
            session_id_length: Some(Int32Range::new(31, 31)),
            ..Default::default()
        };
        assert!(
            xhttp_codes(&validate_stream(&xhttp_stream(non_ascii)))
                .contains(&ValidationCode::XhttpSessionIdTableInvalid)
        );
        // from ≤ 0 is refused by the same room predicate.
        let zero_from = XhttpSettings {
            session_id_table: "AB".into(),
            session_id_length: Some(Int32Range::new(0, 31)),
            ..Default::default()
        };
        assert!(
            xhttp_codes(&validate_stream(&xhttp_stream(zero_from)))
                .contains(&ValidationCode::XhttpSessionIdTableInvalid)
        );
    }

    #[test]
    fn xhttp_session_table_without_length_is_refused() {
        let issues = validate_stream(&xhttp_stream(XhttpSettings {
            session_id_table: "ABCD".into(),
            ..Default::default()
        }));
        let finding = issues
            .iter()
            .find(|issue| issue.code == ValidationCode::XhttpSessionIdLengthRequired)
            .expect("table without length is refused");
        assert_eq!(finding.severity, Severity::Error);
        assert_eq!(
            finding.path.as_deref(),
            Some("stream.xhttpSettings.sessionIDLength")
        );
    }

    #[test]
    fn xhttp_download_settings_are_revalidated_recursively() {
        let top = XhttpSettings {
            download_settings: Some(Box::new(xhttp_stream(XhttpSettings {
                mode: "fragment".into(),
                ..Default::default()
            }))),
            ..Default::default()
        };
        let issues = validate_stream(&xhttp_stream(top));
        assert!(
            issues
                .iter()
                .any(|issue| issue.code == ValidationCode::XhttpModeUnsupported)
        );
    }

    #[test]
    fn kcp_outside_documented_range_warns_without_blocking() {
        // Canonical values inside the documented band stay silent.
        let canonical = KcpSettings {
            mtu: Some(1350),
            tti: Some(50),
            ..Default::default()
        };
        assert!(
            validate_stream(&StreamModel {
                network: crate::model::stream::Network::Kcp,
                kcp_settings: Some(canonical),
                ..Default::default()
            })
            .is_empty()
        );

        // Values outside the documented band warn (docs-soft advisory):
        // Xray still loads and runs them. Values outside Xray's hard load
        // bounds (mtu < 21, tti outside 10..=1000) are the Error tier —
        // covered by `kcp_outside_hard_load_bounds_errors` below.
        let cases: [(Option<u32>, Option<u32>, &str); 4] = [
            (Some(100), None, "stream.kcpSettings.mtu"), // below the docs band, above the import floor
            (Some(1500), None, "stream.kcpSettings.mtu"),
            (Some(576), None, ""),
            (None, Some(500), "stream.kcpSettings.tti"), // inside Xray's 10..=1000 load window
        ];
        for (mtu, tti, path) in cases {
            let issues = validate_stream(&StreamModel {
                network: crate::model::stream::Network::Kcp,
                kcp_settings: Some(KcpSettings {
                    mtu,
                    tti,
                    ..Default::default()
                }),
                ..Default::default()
            });
            let findings: Vec<&ValidationIssue> = issues
                .iter()
                .filter(|issue| issue.code == ValidationCode::KcpRangeSoft)
                .collect();
            if path.is_empty() {
                assert!(findings.is_empty(), "mtu 576 is in range: {issues:#?}");
            } else {
                assert_eq!(findings.len(), 1, "{issues:#?}");
                assert_eq!(findings[0].severity, Severity::Warning, "{:?}", findings[0]);
                assert_eq!(findings[0].path.as_deref(), Some(path));
            }
        }
        // Both knobs out of range warn twice.
        let both = validate_stream(&StreamModel {
            network: crate::model::stream::Network::Kcp,
            kcp_settings: Some(KcpSettings {
                mtu: Some(100),
                tti: Some(500),
                ..Default::default()
            }),
            ..Default::default()
        });
        assert_eq!(
            both.iter()
                .filter(|issue| issue.code == ValidationCode::KcpRangeSoft)
                .count(),
            2
        );
    }

    #[test]
    fn kcp_outside_hard_load_bounds_errors_and_never_soft_warns() {
        // Xray's KCPConfig.Build load-refuses mtu < 21 and tti outside
        // [10, 1000] (infra/conf/transport_method.go) — the model's Error
        // tier, matching the import grammar.
        let cases: [(Option<u32>, Option<u32>, &str); 3] = [
            (Some(20), None, "stream.kcpSettings.mtu"),
            (None, Some(5), "stream.kcpSettings.tti"),
            (None, Some(1001), "stream.kcpSettings.tti"),
        ];
        for (mtu, tti, path) in cases {
            let issues = validate_stream(&StreamModel {
                network: crate::model::stream::Network::Kcp,
                kcp_settings: Some(KcpSettings {
                    mtu,
                    tti,
                    ..Default::default()
                }),
                ..Default::default()
            });
            assert_eq!(issues.len(), 1, "{issues:#?}");
            assert_eq!(issues[0].code, ValidationCode::KcpRangeInvalid);
            assert_eq!(issues[0].severity, Severity::Error, "{:?}", issues[0]);
            assert_eq!(issues[0].path.as_deref(), Some(path));
        }
        // The hard-refused band never double-reports the docs warning.
        let both_issues = validate_stream(&StreamModel {
            network: crate::model::stream::Network::Kcp,
            kcp_settings: Some(KcpSettings {
                mtu: Some(20),
                tti: Some(5),
                ..Default::default()
            }),
            ..Default::default()
        });
        assert_eq!(both_issues.len(), 2, "{both_issues:#?}");
        assert!(
            both_issues
                .iter()
                .all(|issue| issue.code == ValidationCode::KcpRangeInvalid)
        );
    }

    #[test]
    fn xhttp_negative_server_max_header_bytes_errors() {
        // SplitHTTPConfig.Build load-refuses negatives, mirrored by the
        // import grammar.
        let settings = XhttpSettings {
            server_max_header_bytes: Some(-1),
            ..Default::default()
        };
        let issues = validate_stream(&xhttp_stream(settings));
        assert_eq!(issues.len(), 1, "{issues:#?}");
        assert_eq!(
            issues[0].code,
            ValidationCode::XhttpServerMaxHeaderBytesInvalid
        );
        assert_eq!(issues[0].severity, Severity::Error, "{:?}", issues[0]);
        assert_eq!(
            issues[0].path.as_deref(),
            Some("stream.xhttpSettings.serverMaxHeaderBytes")
        );
        // Zero (the Go default) and positive values stay silent.
        assert!(
            validate_stream(&xhttp_stream(XhttpSettings {
                server_max_header_bytes: Some(0),
                ..Default::default()
            }))
            .is_empty()
        );
        assert!(
            validate_stream(&xhttp_stream(XhttpSettings {
                server_max_header_bytes: Some(4096),
                ..Default::default()
            }))
            .is_empty()
        );
    }

    #[test]
    fn grpc_negative_knobs_warn_and_zero_is_intentional() {
        let settings = GrpcSettings {
            idle_timeout: Some(-1),
            health_check_timeout: Some(0),
            initial_windows_size: Some(-1000),
            ..Default::default()
        };
        let issues = validate_stream(&StreamModel {
            network: crate::model::stream::Network::Grpc,
            grpc_settings: Some(settings),
            ..Default::default()
        });
        let findings: Vec<&ValidationIssue> = issues
            .iter()
            .filter(|issue| issue.code == ValidationCode::GrpcNegativeClamp)
            .collect();
        assert_eq!(findings.len(), 2, "{issues:#?}");
        for finding in &findings {
            assert_eq!(finding.severity, Severity::Warning);
        }
        let paths: Vec<Option<&str>> = findings.iter().map(|issue| issue.path.as_deref()).collect();
        assert!(paths.contains(&Some("stream.grpcSettings.idle_timeout")));
        assert!(paths.contains(&Some("stream.grpcSettings.initial_windows_size")));

        // Zero (disabled / Xray default) and positive values never warn.
        let zeroed = GrpcSettings {
            idle_timeout: Some(0),
            health_check_timeout: Some(0),
            initial_windows_size: Some(0),
            ..Default::default()
        };
        assert!(
            validate_stream(&StreamModel {
                network: crate::model::stream::Network::Grpc,
                grpc_settings: Some(zeroed),
                ..Default::default()
            })
            .is_empty()
        );
        let positive = GrpcSettings {
            idle_timeout: Some(60),
            health_check_timeout: Some(10),
            initial_windows_size: Some(1_048_576),
            ..Default::default()
        };
        assert!(
            validate_stream(&StreamModel {
                network: crate::model::stream::Network::Grpc,
                grpc_settings: Some(positive),
                ..Default::default()
            })
            .is_empty()
        );
    }

    #[test]
    fn sockopt_tproxy_silently_off_warns_only_outside_the_accepted_vocab() {
        // The accepted vocabulary — off included (the explicit spelling
        // of Xray's Off default, honored as-is) — never warns; casing is
        // tolerated because Xray lowercases the value.
        for tproxy in [
            None,
            Some(String::new()),
            Some("off".into()),
            Some("OFF".into()),
            Some("tproxy".into()),
            Some("TProxy".into()),
            Some("redirect".into()),
        ] {
            let issues = validate_sockopt(
                &SockoptModel {
                    tproxy: tproxy.clone(),
                    ..Default::default()
                },
                "stream.sockopt",
            );
            assert!(
                issues
                    .iter()
                    .all(|issue| issue.code != ValidationCode::SockoptTproxySilentOff),
                "{tproxy:?}: {issues:#?}"
            );
        }
        for typo in ["tpory", "redirected", "enabled", "off "] {
            let issues = validate_sockopt(
                &SockoptModel {
                    tproxy: Some(typo.to_string()),
                    ..Default::default()
                },
                "stream.sockopt",
            );
            let finding = issues
                .iter()
                .find(|issue| issue.code == ValidationCode::SockoptTproxySilentOff)
                .expect("typo warns");
            assert_eq!(finding.severity, Severity::Warning);
            assert_eq!(finding.path.as_deref(), Some("stream.sockopt.tproxy"));
        }
        // The prefix scopes the ECH-DNS sockopt block the same way.
        let ech = validate_sockopt(
            &SockoptModel {
                tproxy: Some("tpory".into()),
                ..Default::default()
            },
            "stream.tlsSettings.echSockopt",
        );
        assert_eq!(
            ech[0].path.as_deref(),
            Some("stream.tlsSettings.echSockopt.tproxy")
        );
    }

    #[test]
    fn sniffing_dest_override_refuses_unknown_protocols_case_insensitively() {
        for item in [
            "http",
            "tls",
            "https",
            "ssl",
            "quic",
            "fakedns",
            "fakedns+others",
            "HTTP",
            "TLS",
            "FAKEDNS+OTHERS",
        ] {
            let sniffing = Sniffing {
                dest_override: vec![item.into()],
                ..Default::default()
            };
            assert!(
                validate_sniffing(&sniffing, "localInbounds[0].sniffing").is_empty(),
                "{item:?} must be accepted"
            );
        }
        for item in ["tcp", "h2", "fakedns2", "http2", "  tls"] {
            let sniffing = Sniffing {
                dest_override: vec![item.into()],
                ..Default::default()
            };
            let issues = validate_sniffing(&sniffing, "localInbounds[0].sniffing");
            let finding = issues
                .iter()
                .find(|issue| issue.code == ValidationCode::SniffingDestOverrideInvalid)
                .expect("junk item refused");
            assert_eq!(finding.severity, Severity::Error);
            assert_eq!(
                finding.path.as_deref(),
                Some("localInbounds[0].sniffing.destOverride")
            );
        }
        // One issue per offending item; the default state and the fakedns
        // wire form the generator appends itself stay clean.
        let junk = Sniffing {
            dest_override: vec!["http".into(), "tcp".into(), "quic".into(), "nope".into()],
            ..Default::default()
        };
        let issues = validate_sniffing(&junk, "dokodemo[3].sniffing");
        assert_eq!(issues.len(), 2, "{issues:#?}");
        assert!(validate_sniffing(&Sniffing::default(), "localInbounds[0].sniffing").is_empty());
    }

    #[test]
    fn outbound_target_strategy_outside_vocab_is_refused() {
        // Canonical: None, empty, and every strategy in any case pass.
        let canonical_values: Vec<Option<&str>> = [
            None,
            Some(""),
            Some("asis"),
            Some("AsIs"),
            Some("useip"),
            Some("UseIP"),
            Some("useipv4"),
            Some("useipv6"),
            Some("useipv4v6"),
            Some("useipv6v4"),
            Some("forceip"),
            Some("forceipv4"),
            Some("forceipv6"),
            Some("forceipv4v6"),
            Some("forceipv6v4"),
            Some("FORCEIPV4V6"),
        ]
        .into_iter()
        .collect();
        for value in canonical_values {
            let mut outbound = OutboundModel::new(Protocol::Vless);
            outbound.target_strategy = value.map(str::to_string);
            let issues = validate_outbound(&outbound);
            assert!(
                issues
                    .iter()
                    .all(|issue| issue.code != ValidationCode::OutboundTargetStrategyInvalid),
                "{value:?}: {issues:#?}"
            );
        }
        for junk in ["origin", "random", "forceipv7"] {
            let mut outbound = OutboundModel::new(Protocol::Vless);
            outbound.target_strategy = Some(junk.into());
            let issues = validate_outbound(&outbound);
            let finding = issues
                .iter()
                .find(|issue| issue.code == ValidationCode::OutboundTargetStrategyInvalid)
                .expect("junk strategy refused");
            assert_eq!(finding.severity, Severity::Error);
            assert_eq!(finding.path.as_deref(), Some("targetStrategy"));
        }
    }

    #[test]
    fn loopback_outbound_sniffing_gates_through_validate_outbound() {
        // Xray's loopback outbound builds its sniffing block through the
        // same SniffingConfig.Build as inbound envelopes
        // (infra/conf/loopback.go), so an out-of-vocab item is a load
        // refusal here too, with the settings-level path.
        let mut outbound = OutboundModel::new(Protocol::Loopback);
        if let ProtocolSettings::Loopback(settings) = &mut outbound.settings {
            settings.sniffing = Some(Sniffing {
                dest_override: vec!["tcp".into()],
                ..Default::default()
            });
        }
        let issues = validate_outbound(&outbound);
        let finding = issues
            .iter()
            .find(|issue| issue.code == ValidationCode::SniffingDestOverrideInvalid)
            .expect("junk destOverride refused on loopback");
        assert_eq!(finding.severity, Severity::Error);
        assert_eq!(
            finding.path.as_deref(),
            Some("settings.sniffing.destOverride")
        );

        // Canonical loopback sniffing stays silent.
        if let ProtocolSettings::Loopback(settings) = &mut outbound.settings {
            settings.sniffing = Some(Sniffing {
                dest_override: vec!["http".into(), "quic".into()],
                ..Default::default()
            });
        }
        assert!(
            validate_outbound(&outbound)
                .iter()
                .all(|issue| issue.code != ValidationCode::SniffingDestOverrideInvalid)
        );
    }

    #[test]
    fn listen_address_rejects_non_ip_literals() {
        for ok in ["127.0.0.1", "0.0.0.0", "::", "::1", "192.168.1.5"] {
            assert!(validate_listen_address(ok).is_ok(), "{ok:?}");
        }
        for bad in ["", "localhost", "not-an-ip", "127.0.0.1:8080"] {
            assert_eq!(
                validate_listen_address(bad),
                Err(ValidationCode::ListenAddressInvalid),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn vision_precedence_over_public_plaintext() {
        let mut outbound = OutboundModel::new(Protocol::Vless);
        let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.address = "plain.example.com".into();
        settings.port = 443;
        settings.id = "b831381d-6324-4d53-ad4f-8cda48b30811".into();
        settings.flow = "xtls-rprx-vision".into();
        settings.encryption = "none".into();
        let issues = validate_outbound(&outbound);
        assert_eq!(
            codes(&issues),
            vec![ValidationCode::VisionRequiresTlsOrReality]
        );
    }

    #[test]
    fn public_plaintext_vless_and_trojan_report_their_own_codes() {
        let mut vless = OutboundModel::new(Protocol::Vless);
        {
            let ProtocolSettings::Vless(settings) = &mut vless.settings else {
                unreachable!()
            };
            settings.address = "example.com".into();
            settings.port = 443;
            settings.id = "b831381d-6324-4d53-ad4f-8cda48b30811".into();
            settings.encryption = "none".into();
        }
        assert!(
            codes(&validate_outbound(&vless))
                .contains(&ValidationCode::PublicVlessRequiresTlsOrEncryption)
        );

        {
            let ProtocolSettings::Vless(settings) = &mut vless.settings else {
                unreachable!()
            };
            settings.encryption = "mlkem768x25519plus.native.0rtt.key".into();
        }
        assert!(
            codes(&validate_outbound(&vless)).contains(&ValidationCode::VlessEncryptionUnsupported),
            "an all-short-key value must be refused"
        );
        {
            let ProtocolSettings::Vless(settings) = &mut vless.settings else {
                unreachable!()
            };
            settings.encryption =
                "mlkem768x25519plus.native.0rtt.AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA".into();
        }
        assert!(validate_outbound(&vless).is_empty());
        let _ = vless.stream.select_security(Security::Tls);
        assert!(validate_outbound(&vless).is_empty());

        let mut trojan = OutboundModel::new(Protocol::Trojan);
        {
            let ProtocolSettings::Trojan(settings) = &mut trojan.settings else {
                unreachable!()
            };
            settings.address = "8.8.8.8".into();
            settings.port = 443;
            settings.password = "secret".into();
        }
        assert!(
            codes(&validate_outbound(&trojan))
                .contains(&ValidationCode::PublicTrojanRequiresTlsOrReality)
        );
        {
            let ProtocolSettings::Trojan(settings) = &mut trojan.settings else {
                unreachable!()
            };
            settings.address = "router.local".into();
        }
        assert!(validate_outbound(&trojan).is_empty());
    }

    #[test]
    fn shadowsocks_level_and_blackhole_response_are_protocol_rules() {
        let mut ss = OutboundModel::new(Protocol::Shadowsocks);
        {
            let ProtocolSettings::Shadowsocks(settings) = &mut ss.settings else {
                unreachable!()
            };
            settings.address = "example.com".into();
            settings.port = 8388;
            settings.method = "aes-128-gcm".into();
            settings.password = "secret".into();
            settings.level = Some(256);
        }
        assert!(codes(&validate_outbound(&ss)).contains(&ValidationCode::ShadowsocksLevelRange));
        {
            let ProtocolSettings::Shadowsocks(settings) = &mut ss.settings else {
                unreachable!()
            };
            settings.level = Some(255);
        }
        assert!(validate_outbound(&ss).is_empty());

        let mut bh = OutboundModel::new(Protocol::Blackhole);
        {
            let ProtocolSettings::Blackhole(settings) = &mut bh.settings else {
                unreachable!()
            };
            settings.response = Some(crate::model::outbound::BlackholeResponse {
                r#type: "future".into(),
                ..Default::default()
            });
        }
        assert!(codes(&validate_outbound(&bh)).contains(&ValidationCode::BlackholeResponseInvalid));
    }

    #[test]
    fn blackhole_custom_response_base64_gates_only_for_the_custom_type() {
        fn set(bh: &mut OutboundModel, r#type: &str, data: &str) {
            let ProtocolSettings::Blackhole(settings) = &mut bh.settings else {
                unreachable!()
            };
            settings.response = Some(crate::model::outbound::BlackholeResponse {
                r#type: r#type.into(),
                custom_response_data: data.into(),
                ..Default::default()
            });
        }

        let mut bh = OutboundModel::new(Protocol::Blackhole);

        set(&mut bh, "custom", "aGk=");
        assert!(validate_outbound(&bh).is_empty());

        // An absent payload is a valid empty response body, not a decode error.
        set(&mut bh, "custom", "");
        assert!(validate_outbound(&bh).is_empty());

        set(&mut bh, "custom", "not base64!");
        let issues = validate_outbound(&bh);
        assert!(codes(&issues).contains(&ValidationCode::BlackholeCustomResponseDataInvalid));
        let finding = issues
            .iter()
            .find(|issue| issue.code == ValidationCode::BlackholeCustomResponseDataInvalid)
            .expect("custom payload finding");
        assert_eq!(
            finding.path.as_deref(),
            Some("settings.response.customResponseData")
        );
        assert_eq!(
            crate::i18n::validation_issue_message(finding, crate::model::settings::Language::En),
            "settings.response.customResponseData: Blackhole custom response data must be \
             standard base64 with the = padding."
        );

        // Xray only decodes the payload for the custom type (blackhole.go
        // conf build), so a stray value under none/http must not gate.
        set(&mut bh, "none", "not base64!");
        assert!(validate_outbound(&bh).is_empty());
        set(&mut bh, "http", "not base64!");
        assert!(validate_outbound(&bh).is_empty());

        // The custom match is the same lowercased one (infra/conf/blackhole.go:24,31),
        // so a case-variant custom spelling still decodes the payload.
        set(&mut bh, "Custom", "not base64!");
        let issues = validate_outbound(&bh);
        assert!(codes(&issues).contains(&ValidationCode::BlackholeCustomResponseDataInvalid));
        let finding = issues
            .iter()
            .find(|issue| issue.code == ValidationCode::BlackholeCustomResponseDataInvalid)
            .expect("custom payload finding");
        assert_eq!(
            finding.path.as_deref(),
            Some("settings.response.customResponseData")
        );
        set(&mut bh, "Custom", "aGk=");
        assert!(validate_outbound(&bh).is_empty());
        set(&mut bh, "HTTP", "not base64!");
        assert!(validate_outbound(&bh).is_empty());

        set(&mut bh, "future", "");
        assert!(codes(&validate_outbound(&bh)).contains(&ValidationCode::BlackholeResponseInvalid));
    }

    #[test]
    fn blackhole_response_type_accepts_the_vocabulary_in_any_case() {
        fn set(bh: &mut OutboundModel, r#type: &str) {
            let ProtocolSettings::Blackhole(settings) = &mut bh.settings else {
                unreachable!()
            };
            settings.response = Some(crate::model::outbound::BlackholeResponse {
                r#type: r#type.into(),
                ..Default::default()
            });
        }

        let mut bh = OutboundModel::new(Protocol::Blackhole);
        // Xray lowercases the stored value before matching its vocabulary
        // (infra/conf/blackhole.go:24-26): every spelling below loads
        // upstream (the empty spelling alongside `none` selects no
        // response), so none of them may gate here.
        for spelling in [
            "", "none", "None", "NONE", "http", "Http", "HTTP", "custom", "Custom", "CUSTOM",
        ] {
            set(&mut bh, spelling);
            assert!(
                validate_outbound(&bh).is_empty(),
                "{spelling:?} is accepted by the core and must not gate"
            );
        }

        // The vocabulary is closed: anything else fails the build upstream.
        for spelling in ["future", "customs", "none ", "custom-response"] {
            set(&mut bh, spelling);
            assert!(
                codes(&validate_outbound(&bh)).contains(&ValidationCode::BlackholeResponseInvalid),
                "{spelling:?} is refused by the core and must gate"
            );
        }
    }

    #[test]
    fn reality_settings_missing_is_reported() {
        let mut outbound = OutboundModel::new(Protocol::Vless);
        outbound.stream.security = Security::Reality;
        outbound.stream.network = crate::model::stream::Network::Raw;
        let issues = validate_outbound(&outbound);
        assert!(codes(&issues).contains(&ValidationCode::RealitySettingsMissing));
    }

    #[test]
    fn download_depth_exceeds_safety_depth() {
        let mut stream = crate::model::stream::StreamModel::default();
        let mut current = &mut stream;
        for _ in 0..=MAX_XHTTP_DOWNLOAD_DEPTH {
            current.network = Network::Xhttp;
            let settings = current
                .xhttp_settings
                .get_or_insert_with(crate::model::stream::XhttpSettings::default);
            current = settings
                .download_settings
                .get_or_insert_with(|| Box::new(StreamModel::default()))
                .as_mut();
        }
        let issues = validate_stream(&stream);
        assert!(codes(&issues).contains(&ValidationCode::XhttpDepthExceeded));
    }

    #[test]
    fn master_key_log_is_rejected_in_tls_and_reality() {
        // TLS variant: non-empty tlsSettings.masterKeyLog is refused.
        let tls_stream = StreamModel {
            security: Security::Tls,
            tls_settings: Some(crate::model::stream::TlsModel {
                master_key_log: "C:\\xray-keys.log".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let issues = validate_stream(&tls_stream);
        assert_eq!(
            issues,
            vec![issue(
                ValidationCode::MasterKeyLogNotSupported,
                Some("stream.tlsSettings.masterKeyLog".into()),
            )]
        );

        // Reality variant: non-empty realitySettings.masterKeyLog is refused.
        let reality_stream = StreamModel {
            security: Security::Reality,
            reality_settings: Some(crate::model::stream::RealityModel {
                master_key_log: "C:\\xray-keys.log".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let issues = validate_stream(&reality_stream);
        assert_eq!(
            issues,
            vec![
                // Security refusals report before the format rules
                // (same block): masterKeyLog first, then the empty public
                // key (itself refused by Xray's REALITY client build).
                issue(
                    ValidationCode::MasterKeyLogNotSupported,
                    Some("stream.realitySettings.masterKeyLog".into()),
                ),
                issue(
                    ValidationCode::RealityPublicKeyInvalid,
                    Some("stream.realitySettings.publicKey".into()),
                ),
            ]
        );

        // The visit recursion must reach a nested xhttp download stream too.
        let mut parent = StreamModel {
            network: Network::Xhttp,
            ..Default::default()
        };
        let download = StreamModel {
            security: Security::Tls,
            tls_settings: Some(crate::model::stream::TlsModel {
                master_key_log: "C:\\keys.log".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        parent.xhttp_settings = Some(crate::model::stream::XhttpSettings {
            download_settings: Some(Box::new(download)),
            ..Default::default()
        });
        let issues = validate_stream(&parent);
        assert!(codes(&issues).contains(&ValidationCode::MasterKeyLogNotSupported));
    }
    #[test]
    fn tls_allow_insecure_is_rejected_unless_false() {
        // `tlsSettings.allowInsecure` was removed by Xray: `true` hard-fails
        // TLSConfig.Build (PrintRemovedFeatureError) and a non-bool value fails
        // Xray's `allowInsecure bool` JSON unmarshal — both land in the TlsModel
        // `extra` flatten map and must be refused on validation.
        let mut stream = StreamModel::default();
        stream.security = Security::Tls;
        stream.tls_settings = Some(crate::model::stream::TlsModel {
            extra: json!({"allowInsecure": true}).as_object().unwrap().clone(),
            ..Default::default()
        });
        let issues = validate_stream(&stream);
        assert_eq!(
            issues,
            vec![issue(
                ValidationCode::TlsAllowInsecureRemoved,
                Some("stream.tlsSettings.allowInsecure".into()),
            )]
        );

        // A non-boolean value would break Xray's bool unmarshal at startup —
        // refused the same way.
        let string_stream = StreamModel {
            security: Security::Tls,
            tls_settings: Some(crate::model::stream::TlsModel {
                extra: json!({"allowInsecure": "true"})
                    .as_object()
                    .unwrap()
                    .clone(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let issues = validate_stream(&string_stream);
        assert!(codes(&issues).contains(&ValidationCode::TlsAllowInsecureRemoved));

        // `false` is the Go zero value — Xray runs it fine, so it stays valid.
        let false_stream = StreamModel {
            security: Security::Tls,
            tls_settings: Some(crate::model::stream::TlsModel {
                extra: json!({"allowInsecure": false}).as_object().unwrap().clone(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let issues = validate_stream(&false_stream);
        assert!(issues.is_empty(), "{issues:?}");

        // The visit recursion must reach a nested xhttp download stream too.
        let mut parent = StreamModel {
            network: Network::Xhttp,
            ..Default::default()
        };
        let download = StreamModel {
            security: Security::Tls,
            tls_settings: Some(crate::model::stream::TlsModel {
                extra: json!({"allowInsecure": true}).as_object().unwrap().clone(),
                ..Default::default()
            }),
            ..Default::default()
        };
        parent.xhttp_settings = Some(crate::model::stream::XhttpSettings {
            download_settings: Some(Box::new(download)),
            ..Default::default()
        });
        let issues = validate_stream(&parent);
        assert!(codes(&issues).contains(&ValidationCode::TlsAllowInsecureRemoved));
    }

    #[test]
    fn master_key_log_case_variants_in_extra_are_rejected() {
        // serde binds only the exact-case `masterKeyLog` to the model field; a
        // case variant lands in the flattened `extra` map, is still flattened
        // verbatim into the generated config, and Go's case-insensitive JSON
        // unmarshal sets MasterKeyLog regardless — so the attacker-chosen
        // file write survives unless the validator scans `extra`
        // case-insensitively.
        for key in [
            "masterkeylog",
            "MASTERKEYLOG",
            "MasterKeyLog",
            "mAsTeRkEyLoG",
        ] {
            let tls_stream = StreamModel {
                security: Security::Tls,
                tls_settings: Some(crate::model::stream::TlsModel {
                    extra: std::iter::once((key.to_string(), json!("C:\\xray-keys.log"))).collect(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let issues = validate_stream(&tls_stream);
            assert_eq!(
                issues,
                vec![issue(
                    ValidationCode::MasterKeyLogNotSupported,
                    Some("stream.tlsSettings.masterKeyLog".into()),
                )],
                "tls extra key {key:?} must be rejected like the exact-case field"
            );

            let reality_stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(crate::model::stream::RealityModel {
                    extra: std::iter::once((key.to_string(), json!("C:\\xray-keys.log"))).collect(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let issues = validate_stream(&reality_stream);
            assert_eq!(
                issues,
                vec![
                    // Security refusals report before the format
                    // rules: masterKeyLog first, then the empty public key.
                    issue(
                        ValidationCode::MasterKeyLogNotSupported,
                        Some("stream.realitySettings.masterKeyLog".into()),
                    ),
                    issue(
                        ValidationCode::RealityPublicKeyInvalid,
                        Some("stream.realitySettings.publicKey".into()),
                    ),
                ],
                "reality extra key {key:?} must be rejected like the exact-case field"
            );
        }
    }

    #[test]
    fn allow_insecure_case_variants_in_extra_are_rejected() {
        // Go's JSON unmarshal matches field names case-insensitively, so a
        // case variant of `allowInsecure` still sets AllowInsecure in the
        // generated config and Xray's TLSConfig.Build hard-fails with
        // PrintRemovedFeatureError — the validator must scan `extra`
        // case-insensitively.
        for key in [
            "allowinsecure",
            "ALLOWINSECURE",
            "AllowInsecure",
            "allowInSecure",
        ] {
            let mut stream = StreamModel::default();
            stream.security = Security::Tls;
            stream.tls_settings = Some(crate::model::stream::TlsModel {
                extra: std::iter::once((key.to_string(), json!(true))).collect(),
                ..Default::default()
            });
            let issues = validate_stream(&stream);
            assert_eq!(
                issues,
                vec![issue(
                    ValidationCode::TlsAllowInsecureRemoved,
                    Some("stream.tlsSettings.allowInsecure".into()),
                )],
                "tls extra key {key:?} with true must be rejected"
            );
        }
        // `false`/`null` are the Go zero value — Xray runs them fine, so they
        // stay valid regardless of the key's case.
        for key in ["allowinsecure", "allowInSecure"] {
            let false_stream = StreamModel {
                security: Security::Tls,
                tls_settings: Some(crate::model::stream::TlsModel {
                    extra: std::iter::once((key.to_string(), json!(false))).collect(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let issues = validate_stream(&false_stream);
            assert!(
                issues.is_empty(),
                "allowInsecure=false ({key:?}) must stay valid: {issues:?}"
            );

            let null_stream = StreamModel {
                security: Security::Tls,
                tls_settings: Some(crate::model::stream::TlsModel {
                    extra: std::iter::once((key.to_string(), Value::Null)).collect(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let issues = validate_stream(&null_stream);
            assert!(
                issues.is_empty(),
                "allowInsecure=null ({key:?}) must stay valid: {issues:?}"
            );
        }
    }

    // ---------- extra-passthrough scans ----------
    //
    // The pins below sit beside the masterKeyLog/allowInsecure case-variant
    // pins: one test per case asserts the code fires case-insensitively on a
    // profile carrying the extra key, with the wire path and severity of the
    // case, and that canonical profiles validate clean. Removed-feature keys
    // are Error (Xray refuses at conf load); inert keys are Warning
    // (advisory, never gating).

    fn trojan_canonical() -> OutboundModel {
        let mut outbound = OutboundModel::new(Protocol::Trojan);
        let ProtocolSettings::Trojan(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.address = "10.0.0.1".into();
        settings.port = 443;
        settings.password = "secret".into();
        outbound
    }

    fn freedom_canonical() -> OutboundModel {
        OutboundModel::new(Protocol::Freedom)
    }

    fn kcp_extra_stream(extra: Map<String, Value>) -> StreamModel {
        StreamModel {
            network: Network::Kcp,
            kcp_settings: Some(KcpSettings {
                extra,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn trojan_flow_extra_is_refused_like_the_removed_feature() {
        // Xray's TrojanClientConfig.Build refuses a non-empty
        // `flow` with PrintRemovedFeatureError (conf/trojan.go) — any case
        // variant binds the same field, so the extra scan must refuse it
        // exactly like the masterKeyLog scans.
        for key in ["flow", "FLOW", "Flow"] {
            let mut outbound = trojan_canonical();
            let ProtocolSettings::Trojan(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings
                .extra
                .insert(key.to_string(), json!("xtls-rprx-vision"));
            let issues = validate_outbound(&outbound);
            assert_eq!(
                issues,
                vec![issue(
                    ValidationCode::TrojanFlowRemoved,
                    Some("settings.flow".into()),
                )],
                "extra key {key:?} must refuse like the removed feature"
            );
        }
        // The zero shapes stay silent: JSON null and the empty string both
        // leave Xray's `Flow string` at its zero value.
        for value in [Value::Null, json!("")] {
            let mut outbound = trojan_canonical();
            let ProtocolSettings::Trojan(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings.extra.insert("flow".into(), value);
            assert!(
                validate_outbound(&outbound).is_empty(),
                "flow zero shapes must stay valid"
            );
        }
        // Canonical Trojan profiles (no extras) stay clean.
        assert!(validate_outbound(&trojan_canonical()).is_empty());
    }

    #[test]
    fn kcp_seed_and_header_extras_are_refused_and_header_type_warns() {
        // KCPConfig.Build refuses a set `seed` or `header` object
        // with PrintRemovedFeatureError (conf/transport_method.go). Both
        // wire keys, any case, fire the removal Error with per-key paths.
        for (key, path, value) in [
            ("seed", "stream.kcpSettings.seed", json!("s3cret")),
            ("SEED", "stream.kcpSettings.seed", json!("s3cret")),
            (
                "header",
                "stream.kcpSettings.header",
                json!({"type": "dtls"}),
            ),
            (
                "Header",
                "stream.kcpSettings.header",
                json!({"type": "utp"}),
            ),
        ] {
            let stream = kcp_extra_stream(std::iter::once((key.to_string(), value)).collect());
            let issues = validate_stream(&stream);
            assert_eq!(
                issues,
                vec![issue(
                    ValidationCode::KcpSeedHeaderRemoved,
                    Some(path.into())
                )],
                "extra key {key:?} must refuse like the removed feature"
            );
        }
        // JSON null is the Go zero shape (nil pointer / nil RawMessage) and
        // stays silent for both keys.
        for key in ["seed", "header"] {
            let stream =
                kcp_extra_stream(std::iter::once((key.to_string(), Value::Null)).collect());
            assert!(
                validate_stream(&stream).is_empty(),
                "null {key:?} must stay valid"
            );
        }
        // `headerType` never was an Xray JSON key — Xray's unmarshal
        // silently ignores it, so the model warns (Severity::Warning).
        // [Clone-corrected note: the removed-feature citation covers the
        // `header`/`seed` wire keys only; the clone has no `headerType`
        // field anywhere.]
        for key in ["headerType", "HEADERTYPE"] {
            let stream =
                kcp_extra_stream(std::iter::once((key.to_string(), json!("dtls"))).collect());
            let issues = validate_stream(&stream);
            assert_eq!(
                issues,
                vec![warning(
                    ValidationCode::KcpHeaderTypeIgnored,
                    Some("stream.kcpSettings.headerType".into()),
                )],
                "extra key {key:?} must warn exactly once"
            );
        }
        // seed + headerType together: the removal Error and the advisory
        // both render, in scan order.
        let stream = kcp_extra_stream(
            [
                ("seed".to_string(), json!("s3cret")),
                ("headerType".to_string(), json!("dtls")),
            ]
            .into_iter()
            .collect(),
        );
        let issues = validate_stream(&stream);
        assert_eq!(
            codes(&issues),
            vec![
                ValidationCode::KcpSeedHeaderRemoved,
                ValidationCode::KcpHeaderTypeIgnored,
            ]
        );
        // A canonical mKCP block with no extras stays clean.
        assert!(validate_stream(&kcp_extra_stream(Map::new())).is_empty());
    }

    #[test]
    fn vmess_alter_id_and_aid_extras_warn_as_inert() {
        // conf/vmess.go has no alterId/aid field (VMess is
        // AEAD-only), so Xray silently ignores any carried value — the
        // import grammar refuses both spellings; the model scan is the
        // state-path counterpart and stays advisory.
        for (key, path) in [("alterId", "settings.alterId"), ("AID", "settings.aid")] {
            let mut outbound = vmess_canonical();
            let ProtocolSettings::Vmess(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings.extra.insert(key.to_string(), json!(1));
            let issues = validate_outbound(&outbound);
            assert_eq!(
                issues,
                vec![warning(
                    ValidationCode::VmessAlterIdIgnored,
                    Some(path.into()),
                )],
                "extra key {key:?} must warn exactly once"
            );
        }
        // Both spellings at once: one advisory per carried key.
        let mut outbound = vmess_canonical();
        {
            let ProtocolSettings::Vmess(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings.extra.insert("alterId".into(), json!(1));
            settings.extra.insert("aid".into(), json!(0));
        }
        let issues = validate_outbound(&outbound);
        let alter_id_issues: Vec<&ValidationIssue> = issues
            .iter()
            .filter(|issue| issue.code == ValidationCode::VmessAlterIdIgnored)
            .collect();
        assert_eq!(alter_id_issues.len(), 2, "{issues:#?}");
        assert_eq!(alter_id_issues[0].path.as_deref(), Some("settings.alterId"));
        assert_eq!(alter_id_issues[1].path.as_deref(), Some("settings.aid"));
        assert!(
            alter_id_issues
                .iter()
                .all(|issue| issue.severity == Severity::Warning)
        );
    }

    #[test]
    fn vless_seed_extra_warns_as_inert() {
        // The VLESS conf struct still parses `seed` but Build never
        // assigns it — the assignment is commented out upstream
        // (conf/vless.go) — so Xray silently drops any carried value and the
        // model warns.
        for key in ["seed", "SEED"] {
            let mut outbound = vless_canonical();
            let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
                unreachable!()
            };
            // Private literal: keeps the public-plaintext TLS rule off this
            // fixture so the exact vector below isolates VlessSeedIgnored.
            settings.address = "10.0.0.1".into();
            settings.extra.insert(key.to_string(), json!("legacy-obfs"));
            let issues = validate_outbound(&outbound);
            assert_eq!(
                issues,
                vec![warning(
                    ValidationCode::VlessSeedIgnored,
                    Some("settings.seed".into()),
                )],
                "extra key {key:?} must warn exactly once"
            );
        }
        // Canonical VLESS settings (no extras) never fire the scan (the
        // shared fixture carries a public literal, so the plaintext-TLS rule
        // may fire — only VlessSeedIgnored must stay absent).
        let canonical_issues = validate_outbound(&vless_canonical());
        assert!(
            !codes(&canonical_issues).contains(&ValidationCode::VlessSeedIgnored),
            "{canonical_issues:#?}"
        );
    }

    #[test]
    fn freedom_singular_noise_extra_is_refused_and_the_noises_field_stays_legal() {
        // conf/freedom.go refuses a non-null singular `noise`
        // object with PrintRemovedFeatureError naming `noises` as the
        // migration. Null is the Go zero shape and stays silent, and the
        // modeled plural `noises` field is the legal spelling — it never
        // trips the extra scan.
        for key in ["noise", "NOISE"] {
            let mut outbound = freedom_canonical();
            let ProtocolSettings::Freedom(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings
                .extra
                .insert(key.to_string(), json!({"type": "rand", "packet": "1-3"}));
            let issues = validate_outbound(&outbound);
            assert_eq!(
                issues,
                vec![issue(
                    ValidationCode::FreedomNoiseRemoved,
                    Some("settings.noise".into()),
                )],
                "extra key {key:?} must refuse like the removed feature"
            );
        }
        let mut silent = freedom_canonical();
        {
            let ProtocolSettings::Freedom(settings) = &mut silent.settings else {
                unreachable!()
            };
            settings.extra.insert("noise".into(), Value::Null);
        }
        assert!(validate_outbound(&silent).is_empty());

        let mut plural = freedom_canonical();
        {
            let ProtocolSettings::Freedom(settings) = &mut plural.settings else {
                unreachable!()
            };
            settings.noises = vec![crate::model::outbound::Noise {
                r#type: "rand".into(),
                packet: "1-3".into(),
                ..Default::default()
            }];
        }
        let issues = validate_outbound(&plural);
        assert!(
            !codes(&issues).contains(&ValidationCode::FreedomNoiseRemoved),
            "the modeled noises field must never trip the singular scan: {issues:#?}"
        );
    }

    #[test]
    fn freedom_domain_strategy_extra_outside_the_vocabulary_is_refused() {
        // Xray's freedom Build lowercases `domainStrategy` and
        // switches over the ten strategies (conf/freedom.go) — values in the
        // vocabulary work on the wire in any case and stay silent; every
        // other non-null value refuses the outbound at load (non-string
        // JSON shapes included — Go's `string` unmarshal fails them).
        for strategy in ["asis", "useipv4", "ForceIPV6", "useipv4v6", "forceipv6v4"] {
            let mut outbound = freedom_canonical();
            let ProtocolSettings::Freedom(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings
                .extra
                .insert("domainStrategy".into(), json!(strategy));
            let issues = validate_outbound(&outbound);
            assert!(
                issues.is_empty(),
                "domainStrategy {strategy:?} must stay silent: {issues:#?}"
            );
        }
        // Empty and null are the zero shapes (the wire default `asis`).
        for value in [json!(""), Value::Null] {
            let mut outbound = freedom_canonical();
            let ProtocolSettings::Freedom(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings.extra.insert("domainStrategy".into(), value);
            assert!(validate_outbound(&outbound).is_empty());
        }
        for (key, value) in [
            ("domainStrategy", json!("tlshello")),
            ("DomainStrategy", json!("bogus")),
            ("domainstrategy", json!(42)),
        ] {
            let mut outbound = freedom_canonical();
            let ProtocolSettings::Freedom(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings.extra.insert(key.to_string(), value);
            let issues = validate_outbound(&outbound);
            assert_eq!(
                issues,
                vec![issue(
                    ValidationCode::FreedomDomainStrategyUnsupported,
                    Some("settings.domainStrategy".into()),
                )],
                "key {key:?} with an out-of-vocabulary value must refuse"
            );
        }
    }

    #[test]
    fn reality_server_form_extra_keys_warn_on_client_profiles() {
        // Server-form keys carried on a client REALITY block are
        // never read by the client build, and a set dest/target flips
        // REALITYConfig.Build onto the server branch
        // (conf/transport_security.go) — carried verbatim, so the model
        // warns (advisory; refusal could false-positive on tooling that
        // deliberately carries server-form material).
        let quiet = || StreamModel {
            security: Security::Reality,
            reality_settings: Some(crate::model::stream::RealityModel {
                server_name: "fallback.example.com".into(),
                fingerprint: "chrome".into(),
                password: URL_SAFE_NO_PAD.encode([7_u8; 32]),
                ..Default::default()
            }),
            ..Default::default()
        };
        for (key, path) in [
            ("dest", "stream.realitySettings.dest"),
            ("target", "stream.realitySettings.target"),
            ("privateKey", "stream.realitySettings.privateKey"),
            ("serverNames", "stream.realitySettings.serverNames"),
            ("shortIds", "stream.realitySettings.shortIds"),
            ("mldsa65Seed", "stream.realitySettings.mldsa65Seed"),
        ] {
            let mut stream = quiet();
            stream
                .reality_settings
                .as_mut()
                .unwrap()
                .extra
                .insert(key.to_string(), json!("x"));
            let issues = validate_stream(&stream);
            assert_eq!(
                issues,
                vec![warning(
                    ValidationCode::RealityServerFormKeysInert,
                    Some(path.into()),
                )],
                "server-form key {key:?} must warn exactly once"
            );
        }
        // Case variants bind the same REALITYConfig fields (Go's
        // case-insensitive unmarshal), so they warn identically.
        let mut stream = quiet();
        stream
            .reality_settings
            .as_mut()
            .unwrap()
            .extra
            .insert("DEST".into(), json!("1.2.3.4:443"));
        let issues = validate_stream(&stream);
        assert_eq!(
            issues,
            vec![warning(
                ValidationCode::RealityServerFormKeysInert,
                Some("stream.realitySettings.dest".into()),
            )]
        );
        // A canonical client REALITY block without server-form keys stays
        // silent.
        assert!(validate_stream(&quiet()).is_empty());

        // JSON-null server-form keys are the Go zero value — nothing is
        // carried and the dest/target server-branch flip never triggers,
        // so they must not warn (extra_key_set semantics).
        let mut stream = quiet();
        stream
            .reality_settings
            .as_mut()
            .unwrap()
            .extra
            .insert("dest".into(), Value::Null);
        stream
            .reality_settings
            .as_mut()
            .unwrap()
            .extra
            .insert("privateKey".into(), Value::Null);
        assert!(
            validate_stream(&stream).is_empty(),
            "{:#?}",
            validate_stream(&stream)
        );
    }

    #[test]
    fn hysteria_legacy_quic_knob_extras_warn_moved_to_finalmask() {
        // HysteriaConfig parses congestion/up/down/udphop, logs an
        // upstream warning ("…move to finalmask/quicParams") and drops them
        // (conf/transport_method.go) — the config loads and runs without
        // the knobs, so the model warns (advisory, never gating).
        for (key, path) in [
            ("congestion", "stream.hysteriaSettings.congestion"),
            ("CONGESTION", "stream.hysteriaSettings.congestion"),
            ("up", "stream.hysteriaSettings.up"),
            ("down", "stream.hysteriaSettings.down"),
            ("udphop", "stream.hysteriaSettings.udphop"),
        ] {
            let mut outbound = OutboundModel::new(Protocol::Hysteria);
            outbound
                .stream
                .hysteria_settings
                .as_mut()
                .unwrap()
                .extra
                .insert(key.to_string(), json!("50 mbps"));
            let issues = validate_outbound(&outbound);
            assert_eq!(
                issues,
                vec![warning(
                    ValidationCode::HysteriaQuicKnobsMoved,
                    Some(path.into()),
                )],
                "legacy knob {key:?} must warn exactly once"
            );
        }
        // JSON null is the Go zero shape and stays silent; a canonical
        // hysteria profile stays clean.
        let mut null_knob = OutboundModel::new(Protocol::Hysteria);
        null_knob
            .stream
            .hysteria_settings
            .as_mut()
            .unwrap()
            .extra
            .insert("congestion".into(), Value::Null);
        assert!(validate_outbound(&null_knob).is_empty());
        assert!(validate_outbound(&OutboundModel::new(Protocol::Hysteria)).is_empty());
    }

    #[test]
    fn extra_keys_fire_after_deserialization_the_state_path() {
        // The state path end to end: unknown keys in the settings /
        // streamSettings JSON land in the flattened `extra` maps through
        // serde (the share-link grammar refuses these keys on import, so
        // the model scan is the counterpart for deserialized profiles) and
        // must fire with the same codes as the hand-built fixtures above.
        let profile: OutboundModel = serde_json::from_value(json!({
            "protocol": "trojan",
            "settings": {
                "address": "1.2.3.4",
                "port": 443,
                "password": "secret",
                "flow": "xtls-rprx-vision"
            },
            "streamSettings": {
                "network": "kcp",
                "kcpSettings": {"mtu": 1200, "seed": "legacy"}
            }
        }))
        .unwrap();
        let issues = validate_outbound(&profile);
        let found = codes(&issues);
        assert!(
            found.contains(&ValidationCode::TrojanFlowRemoved),
            "{issues:#?}"
        );
        assert!(
            found.contains(&ValidationCode::KcpSeedHeaderRemoved),
            "{issues:#?}"
        );
    }

    /// Every parameterized code carries the bounded excerpt
    /// form of the hostile source value at construction — never the full
    /// attacker string — so the rendered issue message stays small end to end
    /// and no render site needs its own truncation.
    #[test]
    fn hostile_finalmask_values_reach_codes_and_messages_only_as_excerpts() {
        use crate::i18n::validation_issue_message;
        use crate::model::settings::Language;

        let hostile = "u".repeat(65_536);
        let excerpted = format!("{}…", &hostile[..crate::links::MAX_ERROR_EXCERPT_CHARS]);
        let quoted = format!("\"{excerpted}\"");
        let fm: FinalmaskModel = serde_json::from_str(&format!(
            r#"{{"tcp":[{{"type":"{hostile}","settings":{{}}}}],
                "udp":[
                    {{"type":"{hostile}","settings":{{}}}},
                    {{"type":"noise","settings":{{"noise":[
                        {{"type":"{hostile}","packet":"00"}},
                        {{"type":"{hostile}"}}
                    ]}}}},
                    {{"type":"realm","settings":{{"url":"no-scheme-host","stunServers":["h:1"]}}}},
                    {{"type":"udphop","settings":{{"mode":"intervalLocal","interval":"5-10",
                        "remotePorts":"1-5,{hostile}"}}}}
                ],
                "quicParams":{{"congestion":"bbr","brutalUp":"1 {hostile}"}}}}"#
        ))
        .expect("fixture is valid finalmask JSON");
        let issues = validate_finalmask(&fm);
        // The chain is deliberately misordered (`realm` sits before the last,
        // `udphop`, entry), so the order gate reports `realm` between the TCP
        // findings and the UDP per-mask findings; every entry still renders
        // bounded.
        assert_eq!(issues.len(), 8, "{issues:#?}");

        let payloads = [
            Some(&excerpted), // FinalmaskUnknownTcpMask
            None,             // FinalmaskUdpMaskNotLast (the chain is misordered)
            Some(&excerpted), // FinalmaskUnknownUdpMask
            Some(&quoted),    // FinalmaskUnknownByteSyntax
            Some(&excerpted), // FinalmaskBytesValueRequired
            None,             // FinalmaskRealmUrlSyntax (url crate error text)
            Some(&quoted),    // FinalmaskPortListInvalid
            Some(&excerpted), // FinalmaskQuicBandwidthUnitInvalid
        ];
        for (issue, expected) in issues.iter().zip(payloads) {
            let message = validation_issue_message(issue, Language::En);
            assert!(
                message.len() < 1024,
                "rendered message must stay bounded: {message:?}"
            );
            assert!(
                !message.contains(&hostile),
                "message must not embed the full hostile value: {message:?}"
            );
            match (&issue.code, expected) {
                (
                    ValidationCode::FinalmaskUnknownTcpMask(Some(payload))
                    | ValidationCode::FinalmaskUnknownUdpMask(Some(payload))
                    | ValidationCode::FinalmaskBytesValueRequired(payload)
                    | ValidationCode::FinalmaskUnknownByteSyntax(payload)
                    | ValidationCode::FinalmaskQuicBandwidthUnitInvalid(payload)
                    | ValidationCode::FinalmaskPortListInvalid(payload),
                    Some(expected),
                ) => assert_eq!(payload, expected, "{issue:?}"),
                (
                    ValidationCode::FinalmaskUdpMaskNotLast(name)
                    | ValidationCode::FinalmaskUdpMaskNotFirst(name),
                    None,
                ) => assert_eq!(name, "realm", "{issue:?}"),
                (ValidationCode::FinalmaskRealmUrlSyntax(payload), None) => assert!(
                    payload.len() < 256
                        && payload.chars().count() <= crate::links::MAX_ERROR_EXCERPT_CHARS + 1,
                    "realm parse-error payload must stay bounded: {payload:?}"
                ),
                (code, _) => panic!("unexpected issue {code:?}"),
            }
        }
    }

    /// Regression pins for the excerpt cut-over: short values render
    /// byte-identical messages to the pre-excerpt behavior, because the
    /// excerpt helper is identity below the bound.
    #[test]
    fn short_values_render_byte_identical_messages() {
        use crate::i18n::validation_issue_message;
        use crate::model::settings::Language;
        let render = |json: &str| {
            let fm: FinalmaskModel =
                serde_json::from_str(json).expect("fixture is valid finalmask JSON");
            let issues = validate_finalmask(&fm);
            assert_eq!(issues.len(), 1, "{issues:#?}");
            validation_issue_message(&issues[0], Language::En)
        };

        assert_eq!(
            render(
                r#"{"udp":[{"type":"udphop","settings":{"mode":"intervalLocal","interval":"5-10","remotePorts":"1-5,oops"}}]}"#
            ),
            "finalmask.udp[0].settings.remotePorts: \"oops\" is not a port, port \
             range, or env:NAME entry"
        );
        assert_eq!(
            render(r#"{"quicParams":{"congestion":"bbr","brutalUp":"1 zap"}}"#),
            "finalmask.quicParams.brutalUp: unsupported unit zap. Use bps, \
             kbps, mbps, gbps, or tbps"
        );
        assert_eq!(
            render(
                r#"{"udp":[{"type":"noise","settings":{"noise":[{"type":"future","packet":"00"}]}}]}"#
            ),
            "finalmask.udp[0].settings.noise[0].packet: unknown byte syntax \
             \"future\". Choose array, str, hex, or base64"
        );
        assert_eq!(
            render(r#"{"udp":[{"type":"future-udp","settings":{}}]}"#),
            "finalmask.udp[0]: unsupported future UDP mask discriminator \
             Some(\"future-udp\"). The raw value is preserved"
        );
    }

    // ---------- configuration-warning tier ----------

    /// A TLS-protected VLESS outbound that trips no other rule, so the
    /// mux/vision matrix below isolates MuxWithVisionFlow. (Carries the
    /// canonical essentials — port, UUID id — so those rules stay
    /// silent too.)
    fn vless_over_tls() -> OutboundModel {
        let mut outbound = OutboundModel::new(Protocol::Vless);
        let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.address = "example.com".into();
        settings.port = 443;
        settings.id = "b831381d-6324-4d53-ad4f-8cda48b30811".into();
        settings.encryption = "none".into();
        let _ = outbound.stream.select_security(Security::Tls);
        outbound
    }

    fn mux_finding(issues: &[ValidationIssue]) -> Option<&ValidationIssue> {
        issues
            .iter()
            .find(|issue| issue.code == ValidationCode::MuxWithVisionFlow)
    }

    #[test]
    fn vision_flow_with_enabled_tcp_mux_warns_and_carries_warning_severity() {
        let mut outbound = vless_over_tls();
        let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.flow = "xtls-rprx-vision".into();
        outbound.mux.enabled = true;
        // concurrency unset (None → Xray's default 8) and an explicit
        // positive value both carry TCP over smux — both must warn.
        let issues = validate_outbound(&outbound);
        let finding = mux_finding(&issues).expect("vision + enabled mux must warn");
        assert_eq!(finding.path.as_deref(), Some("mux"));
        assert_eq!(finding.severity, Severity::Warning);

        outbound.mux.concurrency = Some(8);
        let issues = validate_outbound(&outbound);
        assert!(mux_finding(&issues).is_some(), "{issues:#?}");

        // concurrency -1 is the TCP-direct escape hatch (XUDP stays
        // available): the combination must not warn.
        outbound.mux.concurrency = Some(-1);
        assert!(
            mux_finding(&validate_outbound(&outbound)).is_none(),
            "concurrency -1 keeps TCP direct; no warning may fire"
        );
    }

    #[test]
    fn xudp_knobs_alone_never_trigger_the_vision_warning_and_do_not_suppress_it() {
        // XUDP-only multiplexing — the knobs without enabled TCP mux — is
        // the sanctioned vision-flow path: the MuxWithVisionFlow warning
        // never fires here. (The separate MuxXudpKnobsInert
        // dead-knob warning legitimately does — a different predicate,
        // pinned in its own tests below.)
        let mut outbound = vless_over_tls();
        let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.flow = "xtls-rprx-vision-udp443".into();
        outbound.mux.xudp_concurrency = Some(8);
        outbound.mux.xudp_proxy_udp443 = Some("allow".into());
        assert!(
            mux_finding(&validate_outbound(&outbound)).is_none(),
            "XUDP knobs without enabled mux must not trigger the vision warning"
        );

        // XUDP knobs do NOT suppress the rule once TCP mux is enabled:
        // Xray builds XUDP inside the mux.Enabled block and TCP always
        // rides smux while enabled ∧ concurrency ≥ 0.
        outbound.mux.enabled = true;
        outbound.mux.concurrency = Some(8);
        assert!(
            mux_finding(&validate_outbound(&outbound)).is_some(),
            "XUDP knobs must not suppress the vision+mux warning"
        );
    }

    #[test]
    fn vision_or_mux_alone_and_non_vless_protocols_never_warn() {
        // Vision flow without mux.
        let mut outbound = vless_over_tls();
        {
            let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings.flow = "xtls-rprx-vision".into();
        }
        assert!(mux_finding(&validate_outbound(&outbound)).is_none());

        // Enabled mux without a vision flow (empty and non-vision flows).
        outbound.mux.enabled = true;
        outbound.mux.concurrency = Some(8);
        for flow in ["", "xtls-rprx-xray"] {
            {
                let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
                    unreachable!()
                };
                settings.flow = flow.into();
            }
            let issues = validate_outbound(&outbound);
            assert!(
                mux_finding(&issues).is_none(),
                "flow {flow:?} with enabled mux must not warn: {issues:#?}"
            );
        }

        // A non-VLESS protocol carrying enabled mux never warns.
        let mut trojan = OutboundModel::new(Protocol::Trojan);
        {
            let ProtocolSettings::Trojan(settings) = &mut trojan.settings else {
                unreachable!()
            };
            settings.address = "router.local".into();
        }
        trojan.mux.enabled = true;
        trojan.mux.concurrency = Some(8);
        assert!(mux_finding(&validate_outbound(&trojan)).is_none());
    }

    /// The severity tier: the two new codes are Warning; every pre-existing
    /// rule stays Error (they keep gating save/import/apply).
    #[test]
    fn warning_codes_are_advisory_and_existing_codes_stay_blocking() {
        let mut outbound = vless_over_tls();
        let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.flow = "xtls-rprx-vision".into();
        outbound.mux.enabled = true;
        outbound.stream.tls_settings = Some(crate::model::stream::TlsModel {
            server_name: "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d".into(),
            ..Default::default()
        });
        let issues = validate_outbound(&outbound);
        for issue in &issues {
            assert_eq!(
                issue.severity,
                Severity::Warning,
                "{issue:?} must be advisory"
            );
        }
        // A blocking fixture (masterKeyLog is refused) must still carry
        // Severity::Error end to end.
        let tls_stream = StreamModel {
            security: Security::Tls,
            tls_settings: Some(crate::model::stream::TlsModel {
                master_key_log: "C:\\xray-keys.log".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let issues = validate_stream(&tls_stream);
        assert_eq!(issues[0].severity, Severity::Error);
    }

    // ---------- mux-block semantics ----------

    /// The mux fixtures reuse `vless_over_tls` (canonical VLESS/TLS
    /// with no vision flow), so every code set asserted below is exact: no
    /// other rule can fire on these profiles.
    #[test]
    fn xudp_proxy_udp443_outside_the_whitelist_errors_and_canonical_values_stay_silent() {
        // Xray's mux Build switch is an exact, case-sensitive match
        // (infra/conf/xray.go MuxConfig.Build): every non-empty value
        // outside {reject, allow, skip} — case variants included — refuses
        // the config at load, so the model refuses it too (Error tier).
        for value in ["Reject", "ALLOW", "reject-udp", "skip ", "auto", "0"] {
            let mut outbound = vless_over_tls();
            // Enabled block: the 1.24 dead-knob rule stays off, isolating
            // the whitelist Error under test.
            outbound.mux.enabled = true;
            outbound.mux.xudp_proxy_udp443 = Some(value.into());
            let issues = validate_outbound(&outbound);
            assert_eq!(
                codes(&issues),
                vec![ValidationCode::MuxXudpProxyUdp443Unsupported],
                "xudpProxyUDP443 {value:?} must error exactly once: {issues:#?}"
            );
            let finding = finding(&issues, &ValidationCode::MuxXudpProxyUdp443Unsupported).unwrap();
            assert_eq!(finding.severity, Severity::Error);
            assert_eq!(finding.path.as_deref(), Some("mux.xudpProxyUDP443"));
        }

        // Still refused on a disabled block: the vocabulary switch runs in
        // Build, before the handler ever looks at `enabled`. (The 1.24
        // dead-knob warning fires alongside — asserted in the coexistence
        // test below.)
        let mut disabled = vless_over_tls();
        disabled.mux.xudp_proxy_udp443 = Some("auto".into());
        let issues = validate_outbound(&disabled);
        assert!(
            codes(&issues).contains(&ValidationCode::MuxXudpProxyUdp443Unsupported),
            "{issues:#?}"
        );

        // Canonical over a live block: unset, empty (Xray defaults it to
        // `reject` on the wire), and each whitelisted mode never fire.
        for value in [None, Some(""), Some("reject"), Some("allow"), Some("skip")] {
            let mut outbound = vless_over_tls();
            outbound.mux.enabled = true;
            outbound.mux.xudp_proxy_udp443 = value.map(str::to_string);
            let issues = validate_outbound(&outbound);
            assert!(
                issues.is_empty(),
                "xudpProxyUDP443 {value:?} must stay silent: {issues:#?}"
            );
        }
    }

    #[test]
    fn concurrency_outside_documented_bounds_warns_only_while_mux_is_enabled() {
        // Reinterpreted values over an enabled block: 0 → 8, > 128 →
        // clamp 128, negatives other than -1 → mux off (TCP direct).
        for value in [Some(0), Some(-2), Some(-100), Some(129), Some(1024)] {
            let mut outbound = vless_over_tls();
            outbound.mux.enabled = true;
            outbound.mux.concurrency = value;
            let issues = validate_outbound(&outbound);
            assert_eq!(
                codes(&issues),
                vec![ValidationCode::MuxConcurrencyReinterpreted],
                "concurrency {value:?} over enabled mux must warn exactly once: {issues:#?}"
            );
            let finding = finding(&issues, &ValidationCode::MuxConcurrencyReinterpreted).unwrap();
            assert_eq!(finding.severity, Severity::Warning);
            assert_eq!(finding.path.as_deref(), Some("mux.concurrency"));
        }

        // Documented values never warn: unset (the wire default 8), the
        // -1 TCP-direct escape, and 1..=128.
        for value in [None, Some(-1), Some(1), Some(8), Some(128)] {
            let mut outbound = vless_over_tls();
            outbound.mux.enabled = true;
            outbound.mux.concurrency = value;
            let issues = validate_outbound(&outbound);
            assert!(
                issues.is_empty(),
                "concurrency {value:?} over enabled mux must stay silent: {issues:#?}"
            );
        }

        // Disabled block: Xray never reads `concurrency` (the whole mux
        // block is inert), so nothing is reinterpreted and nothing warns —
        // an out-of-band value there is dead, not changed in meaning.
        for value in [Some(0), Some(-2), Some(300)] {
            let mut outbound = vless_over_tls();
            outbound.mux.enabled = false;
            outbound.mux.concurrency = value;
            let issues = validate_outbound(&outbound);
            assert!(
                issues.is_empty(),
                "concurrency {value:?} on a disabled mux block must stay silent: {issues:#?}"
            );
        }
    }

    #[test]
    fn xudp_knobs_without_enabled_warn_and_are_silent_with_enabled() {
        // Each knob alone and both together surface the dead-knob warning
        // on the mux.enabled gate.
        for (xudp_concurrency, xudp_proxy_udp443) in [
            (Some(8), None),
            (None, Some("allow")),
            (Some(8), Some("skip")),
        ] {
            let mut outbound = vless_over_tls();
            outbound.mux.xudp_concurrency = xudp_concurrency;
            outbound.mux.xudp_proxy_udp443 = xudp_proxy_udp443.map(str::to_string);
            let issues = validate_outbound(&outbound);
            assert_eq!(
                codes(&issues),
                vec![ValidationCode::MuxXudpKnobsInert],
                "{xudp_concurrency:?}/{xudp_proxy_udp443:?} without enabled must warn \
                 exactly once: {issues:#?}"
            );
            let finding = finding(&issues, &ValidationCode::MuxXudpKnobsInert).unwrap();
            assert_eq!(finding.severity, Severity::Warning);
            assert_eq!(finding.path.as_deref(), Some("mux.enabled"));
        }

        // Canonical: the knobs with mux enabled — including the XUDP-only
        // wire shape (concurrency -1) — stay silent, and a bare enabled
        // block with no knobs stays silent.
        for (enabled, concurrency) in [(true, None), (true, Some(-1)), (true, Some(8))] {
            let mut outbound = vless_over_tls();
            outbound.mux.enabled = enabled;
            outbound.mux.concurrency = concurrency;
            outbound.mux.xudp_concurrency = Some(8);
            outbound.mux.xudp_proxy_udp443 = Some("allow".into());
            let issues = validate_outbound(&outbound);
            assert!(
                issues.is_empty(),
                "XUDP knobs over enabled mux (concurrency {concurrency:?}) must stay silent: \
                 {issues:#?}"
            );
        }
        let issues = validate_outbound(&vless_over_tls());
        assert!(issues.is_empty());
    }

    #[test]
    fn mux_warnings_coexist_with_the_vision_warning_and_never_suppress() {
        // The concurrency warning and the vision warning apply to the same
        // enabled block (concurrency -2 is a reinterpreted negative AND
        // carries TCP over smux under a vision flow): both render.
        let mut outbound = vless_over_tls();
        let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.flow = "xtls-rprx-vision".into();
        outbound.mux.enabled = true;
        outbound.mux.concurrency = Some(-2);
        let issues = validate_outbound(&outbound);
        let found = codes(&issues);
        assert!(
            found.contains(&ValidationCode::MuxWithVisionFlow),
            "{issues:#?}"
        );
        assert!(
            found.contains(&ValidationCode::MuxConcurrencyReinterpreted),
            "{issues:#?}"
        );

        // The dead-knob and out-of-vocabulary rules on the same disabled block:
        // the dead-knob warning and the load-refusal Error both render (Xray
        // would refuse the value at conf load AND ignore the block at run time).
        let mut dead = vless_over_tls();
        dead.mux.xudp_proxy_udp443 = Some("auto".into());
        let issues = validate_outbound(&dead);
        assert!(
            codes(&issues).contains(&ValidationCode::MuxXudpKnobsInert),
            "{issues:#?}"
        );
        assert!(
            codes(&issues).contains(&ValidationCode::MuxXudpProxyUdp443Unsupported),
            "{issues:#?}"
        );

        // The sanctioned XUDP-only vision profile — enabled, concurrency
        // -1, XUDP knobs, vision-udp443 flow — trips none of the mux rules
        // (escape semantics intact end to end).
        let mut xudp_only = vless_over_tls();
        let ProtocolSettings::Vless(settings) = &mut xudp_only.settings else {
            unreachable!()
        };
        settings.flow = "xtls-rprx-vision-udp443".into();
        xudp_only.mux.enabled = true;
        xudp_only.mux.concurrency = Some(-1);
        xudp_only.mux.xudp_concurrency = Some(8);
        xudp_only.mux.xudp_proxy_udp443 = Some("allow".into());
        let issues = validate_outbound(&xudp_only);
        assert!(
            issues.is_empty(),
            "the XUDP-only vision profile must stay clean: {issues:#?}"
        );
    }

    #[test]
    fn server_name_implausible_shapes_warn_on_tls_and_reality_blocks() {
        for server_name in [
            "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
            // UUID hex is case-insensitive.
            "9B1DEB4D-3B7D-4BAD-9BDD-2B0D7B3DCB6D",
            "b10a8db164e0754105b7a99be72e3fe5",
            "a b",
            "https://x",
            "x/y",
            "exa🙂mple.com",
        ] {
            let tls_stream = StreamModel {
                security: Security::Tls,
                tls_settings: Some(crate::model::stream::TlsModel {
                    server_name: server_name.into(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let issues = validate_stream(&tls_stream);
            let finding = issues
                .iter()
                .find(|issue| issue.code == ValidationCode::ServerNameImplausible);
            assert!(
                finding.is_some(),
                "TLS serverName {server_name:?} must warn: {issues:#?}"
            );
            assert_eq!(
                finding.unwrap().path.as_deref(),
                Some("stream.tlsSettings.serverName")
            );

            let reality_stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(crate::model::stream::RealityModel {
                    server_name: server_name.into(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let issues = validate_stream(&reality_stream);
            let finding = issues
                .iter()
                .find(|issue| issue.code == ValidationCode::ServerNameImplausible);
            assert!(
                finding.is_some(),
                "REALITY serverName {server_name:?} must warn: {issues:#?}"
            );
            assert_eq!(
                finding.unwrap().path.as_deref(),
                Some("stream.realitySettings.serverName")
            );
        }
    }

    #[test]
    fn plausible_server_names_never_warn() {
        for server_name in [
            "",
            "fts.rbxcdn.com",
            "xn--bcher-kva.example",
            "例え.jp",
            "192.168.1.1",
            "2001:db8::1",
            "my_host.local",
            "router",
            "example.com",
            "8-4-4-4-12",
        ] {
            let tls_stream = StreamModel {
                security: Security::Tls,
                tls_settings: Some(crate::model::stream::TlsModel {
                    server_name: server_name.into(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            assert!(
                !validate_stream(&tls_stream)
                    .iter()
                    .any(|issue| issue.code == ValidationCode::ServerNameImplausible),
                "TLS serverName {server_name:?} must not warn"
            );
            let reality_stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(crate::model::stream::RealityModel {
                    server_name: server_name.into(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            assert!(
                !validate_stream(&reality_stream)
                    .iter()
                    .any(|issue| issue.code == ValidationCode::ServerNameImplausible),
                "REALITY serverName {server_name:?} must not warn"
            );
        }
    }

    // ---------- TLS/REALITY security-format rules ----------
    //
    // Tests beside the existing pins:
    // each code fires on a crafted block with its wire path and severity,
    // and is absent on the canonical value. Sources: Xray conf-load
    // rejections (conf/transport_security.go) — Errors gate exactly like an
    // import refusal — and the class-E version-string drop (tls/config.go),
    // which warns. Fingerprint expectations derive from the canonical table
    // in `crate::model::fingerprint`, never from a duplicated literal list.

    fn reality_base() -> crate::model::stream::RealityModel {
        // Canonical REALITY essentials: everything the client branch of
        // Xray's conf build accepts, with the optional formats empty.
        crate::model::stream::RealityModel {
            fingerprint: "chrome".into(),
            password: URL_SAFE_NO_PAD.encode([7_u8; 32]),
            ..Default::default()
        }
    }

    fn reality_base_with_fingerprint(fingerprint: &str) -> crate::model::stream::RealityModel {
        crate::model::stream::RealityModel {
            fingerprint: fingerprint.into(),
            ..reality_base()
        }
    }

    fn finding_with_code(
        issues: &[ValidationIssue],
        code: ValidationCode,
    ) -> Option<&ValidationIssue> {
        issues.iter().find(|issue| issue.code == code)
    }

    #[test]
    fn canonical_tls_and_reality_blocks_never_fire() {
        let tls = StreamModel {
            security: Security::Tls,
            tls_settings: Some(crate::model::stream::TlsModel {
                fingerprint: "randomizedalpn".into(), // wire-only name: legal
                pinned_peer_cert_sha256: "01ab".repeat(16),
                min_version: "1.2".into(),
                max_version: "1.3".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(
            validate_stream(&tls).is_empty(),
            "{:?}",
            validate_stream(&tls)
        );

        let reality = StreamModel {
            security: Security::Reality,
            reality_settings: Some(crate::model::stream::RealityModel {
                fingerprint: "chrome".into(),
                password: URL_SAFE_NO_PAD.encode([7_u8; 32]),
                short_id: "0123abcd".into(),
                spider_x: "/search?q=broccoli".into(),
                mldsa65_verify: URL_SAFE_NO_PAD.encode([9_u8; 1952]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(
            validate_stream(&reality).is_empty(),
            "{:?}",
            validate_stream(&reality)
        );
    }

    /// An outbound TLS certificate row that names no file and carries no
    /// non-blank PEM line has no key material for Xray's conf build to load,
    /// which refuses the entry (infra/conf: both file and bytes are empty).
    /// A whitespace-only path opens no file and a blank-only line list parses
    /// no certificate, so both count as absent. The rule fires from the model
    /// pass with the offending row's index — the row the user has to fill in —
    /// and stays silent in a block `security` does not select, which Xray
    /// never reads.
    #[test]
    fn tls_certificate_row_without_material_gates_from_the_model_pass() {
        let tls_stream = |tls: crate::model::stream::TlsModel| StreamModel {
            security: Security::Tls,
            tls_settings: Some(tls),
            ..Default::default()
        };

        let issues = validate_stream(&tls_stream(crate::model::stream::TlsModel {
            certificates: vec![
                crate::model::stream::TlsCert::default(),
                crate::model::stream::TlsCert {
                    certificate_file: "   ".into(),
                    ..Default::default()
                },
                crate::model::stream::TlsCert {
                    certificate: vec!["  ".into(), "\t".into()],
                    ..Default::default()
                },
                crate::model::stream::TlsCert {
                    certificate_file: "c.pem".into(),
                    ..Default::default()
                },
                crate::model::stream::TlsCert {
                    certificate: vec!["-----BEGIN CERTIFICATE-----".into()],
                    ..Default::default()
                },
            ],
            ..Default::default()
        }));
        let certificate = finding_with_code(&issues, ValidationCode::TlsCertificateRequired)
            .unwrap_or_else(|| panic!("an empty certificate row must gate: {issues:#?}"));
        assert_eq!(
            certificate.path.as_deref(),
            Some("stream.tlsSettings.certificates[0]")
        );
        assert_eq!(certificate.severity, Severity::Error);
        assert_eq!(
            issues
                .iter()
                .filter(|issue| issue.code == ValidationCode::TlsCertificateRequired)
                .map(|issue| issue.path.as_deref())
                .collect::<Vec<_>>(),
            [
                Some("stream.tlsSettings.certificates[0]"),
                Some("stream.tlsSettings.certificates[1]"),
                Some("stream.tlsSettings.certificates[2]"),
            ],
            "only the rows without material — blank-only text included — may fire: {issues:#?}"
        );

        // A block under another security selection is inert state (the wire
        // pass drops it and Xray never reads it), so the rule stays silent.
        let mut inert = tls_stream(crate::model::stream::TlsModel {
            certificates: vec![crate::model::stream::TlsCert::default()],
            ..Default::default()
        });
        inert.security = Security::Reality;
        inert.reality_settings = Some(reality_base());
        let issues = validate_stream(&inert);
        assert!(
            !issues
                .iter()
                .any(|issue| issue.code == ValidationCode::TlsCertificateRequired),
            "an unselected TLS block must stay silent: {issues:#?}"
        );
    }

    /// An outbound TLS `alpn` list carrying `fromMitm` beside another name is
    /// refused by Xray's conf build (infra/conf/transport_security.go: only
    /// one element is allowed in "alpn" when using "fromMitm" in it), so the
    /// model pass gates it on the field path; a sole `fromMitm` and any
    /// fromMitm-free list stay valid.
    #[test]
    fn tls_from_mitm_alpn_beside_another_name_gates_from_the_model_pass() {
        let tls_stream = |alpn: &[String]| StreamModel {
            security: Security::Tls,
            tls_settings: Some(crate::model::stream::TlsModel {
                alpn: alpn.to_vec(),
                ..Default::default()
            }),
            ..Default::default()
        };

        let issues = validate_stream(&tls_stream(&["fromMitm".to_string(), "h2".to_string()]));
        let alpn = finding_with_code(&issues, ValidationCode::TlsFromMitmAlpnShort)
            .unwrap_or_else(|| panic!("fromMitm beside another element must gate: {issues:#?}"));
        assert_eq!(alpn.path.as_deref(), Some("stream.tlsSettings.alpn"));
        assert_eq!(alpn.severity, Severity::Error);

        for alpn in [
            Vec::new(),
            vec!["fromMitm".to_string()],
            vec!["h2".to_string(), "http/1.1".to_string()],
        ] {
            let issues = validate_stream(&tls_stream(&alpn));
            assert!(
                !issues
                    .iter()
                    .any(|issue| issue.code == ValidationCode::TlsFromMitmAlpnShort),
                "a sole fromMitm or a fromMitm-free list must not gate for {alpn:?}: {issues:#?}"
            );
        }
    }

    #[test]
    fn reality_client_format_errors_carry_wire_paths_and_gate() {
        // publicKey: empty, malformed, and wrong-length values all fire on
        // the wire path with Error severity (Xray refuses each at conf load).
        let short_pbk = URL_SAFE_NO_PAD.encode([7_u8; 31]);
        let long_pbk = URL_SAFE_NO_PAD.encode([7_u8; 33]);
        for password in [
            "",
            "AAA",
            "not base64url!",
            short_pbk.as_str(),
            long_pbk.as_str(),
        ] {
            let stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(crate::model::stream::RealityModel {
                    password: password.into(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let issues = validate_stream(&stream);
            let finding = finding_with_code(&issues, ValidationCode::RealityPublicKeyInvalid)
                .expect("password {password:?} must fire RealityPublicKeyInvalid");
            assert_eq!(
                finding.path.as_deref(),
                Some("stream.realitySettings.publicKey")
            );
            assert_eq!(finding.severity, Severity::Error);
        }
        // shortId: odd-length hex, non-hex, and >16 chars fire; empty and
        // even-length ≤16 hex do not.
        for short_id in ["abc", "12zz", "0123456789abcdef0"] {
            let mut reality = reality_base();
            reality.short_id = short_id.into();
            let stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(reality),
                ..Default::default()
            };
            let issues = validate_stream(&stream);
            let finding = finding_with_code(&issues, ValidationCode::RealityShortIdInvalid)
                .expect("shortId {short_id:?} must fire RealityShortIdInvalid");
            assert_eq!(
                finding.path.as_deref(),
                Some("stream.realitySettings.shortId")
            );
            assert_eq!(finding.severity, Severity::Error);
        }
        for short_id in ["", "00", "0123abcd", "ABCDEF0123456789"] {
            let mut reality = reality_base();
            reality.short_id = short_id.into();
            let stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(reality),
                ..Default::default()
            };
            assert!(
                !validate_stream(&stream)
                    .iter()
                    .any(|issue| issue.code == ValidationCode::RealityShortIdInvalid),
                "shortId {short_id:?} must stay valid"
            );
        }
        // spiderX: anything not starting with '/' fires; empty stays valid.
        for spider_x in ["relative", "/has\ttab", "\u{1}/leading-control"] {
            let mut reality = reality_base();
            reality.spider_x = spider_x.into();
            let stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(reality),
                ..Default::default()
            };
            let issues = validate_stream(&stream);
            let finding = finding_with_code(&issues, ValidationCode::RealitySpiderXInvalid)
                .expect("spiderX {spider_x:?} must fire RealitySpiderXInvalid");
            assert_eq!(
                finding.path.as_deref(),
                Some("stream.realitySettings.spiderX")
            );
            assert_eq!(finding.severity, Severity::Error);
        }
        for spider_x in ["", "/", "/search?q=1", "/a/b/c%20d"] {
            let mut reality = reality_base();
            reality.spider_x = spider_x.into();
            let stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(reality),
                ..Default::default()
            };
            assert!(
                !validate_stream(&stream)
                    .iter()
                    .any(|issue| issue.code == ValidationCode::RealitySpiderXInvalid),
                "spiderX {spider_x:?} must stay valid"
            );
        }
        // mldsa65Verify: non-empty values that are not base64url of exactly
        // 1952 bytes fire; empty stays valid.
        let short_mldsa = URL_SAFE_NO_PAD.encode([9_u8; 1951]);
        for mldsa65_verify in ["AAA", "not base64url!", short_mldsa.as_str()] {
            let mut reality = reality_base();
            reality.mldsa65_verify = mldsa65_verify.into();
            let stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(reality),
                ..Default::default()
            };
            let issues = validate_stream(&stream);
            let finding = finding_with_code(&issues, ValidationCode::RealityMldsa65Invalid)
                .expect("mldsa65Verify must fire RealityMldsa65Invalid");
            assert_eq!(
                finding.path.as_deref(),
                Some("stream.realitySettings.mldsa65Verify")
            );
            assert_eq!(finding.severity, Severity::Error);
        }
        let mut reality = reality_base();
        reality.mldsa65_verify = URL_SAFE_NO_PAD.encode([9_u8; 1952]);
        let stream = StreamModel {
            security: Security::Reality,
            reality_settings: Some(reality),
            ..Default::default()
        };
        assert!(
            !validate_stream(&stream)
                .iter()
                .any(|issue| issue.code == ValidationCode::RealityMldsa65Invalid)
        );
    }

    #[test]
    fn tls_fingerprint_follows_the_wire_vocabulary() {
        // TLS accepts the full canonical table — editor names, wire-only
        // names, empty, `unsafe`/`hellogolang` (native Go TLS), and any
        // ASCII casing (Xray lowercases before lookup).
        for &name in crate::model::fingerprint::FINGERPRINTS
            .iter()
            .chain(crate::model::fingerprint::VALIDATION_ONLY_FINGERPRINTS)
        {
            let tls = StreamModel {
                security: Security::Tls,
                tls_settings: Some(crate::model::stream::TlsModel {
                    fingerprint: name.into(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            assert!(
                !validate_stream(&tls)
                    .iter()
                    .any(|issue| issue.code == ValidationCode::TlsFingerprintUnsupported),
                "TLS fingerprint {name:?} is wire-valid and must not fire"
            );
        }
        for name in ["Chrome", "RANDOMIZEDNOALPN"] {
            let tls = StreamModel {
                security: Security::Tls,
                tls_settings: Some(crate::model::stream::TlsModel {
                    fingerprint: name.into(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            assert!(
                !validate_stream(&tls)
                    .iter()
                    .any(|issue| issue.code == ValidationCode::TlsFingerprintUnsupported),
                "TLS fingerprint {name:?} matches case-insensitively and must not fire"
            );
        }
        // Out-of-vocabulary values are conf-load errors on the wire path.
        for name in ["bogus", "hellofirefox_999", "Chrome2"] {
            let tls = StreamModel {
                security: Security::Tls,
                tls_settings: Some(crate::model::stream::TlsModel {
                    fingerprint: name.into(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let issues = validate_stream(&tls);
            let finding = finding_with_code(&issues, ValidationCode::TlsFingerprintUnsupported)
                .expect("TLS fingerprint {name:?} must fire");
            assert_eq!(
                finding.path.as_deref(),
                Some("stream.tlsSettings.fingerprint")
            );
            assert_eq!(finding.severity, Severity::Error);
        }
    }

    #[test]
    fn reality_fingerprint_excludes_exactly_unsafe_and_hellogolang() {
        use crate::model::fingerprint::{FINGERPRINTS, VALIDATION_ONLY_FINGERPRINTS};
        // The full canonical table: only `unsafe` and `hellogolang` fire —
        // empty and wire-only names stay legal (Xray's client build rejects
        // exactly {unsafe, hellogolang} plus unknown names).
        for &name in FINGERPRINTS.iter().chain(VALIDATION_ONLY_FINGERPRINTS) {
            let stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(reality_base_with_fingerprint(name)),
                ..Default::default()
            };
            let issues = validate_stream(&stream);
            let expected = matches!(name, "unsafe" | "hellogolang");
            assert_eq!(
                issues
                    .iter()
                    .any(|issue| issue.code == ValidationCode::RealityFingerprintUnsupported),
                expected,
                "REALITY fingerprint {name:?} verdict mismatch: {issues:#?}"
            );
        }
        // The wire exclusion is ASCII case-insensitive (Xray lowercases the
        // fingerprint first); table names in any casing stay accepted.
        for name in ["UNSAFE", "Hellogolang"] {
            let stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(reality_base_with_fingerprint(name)),
                ..Default::default()
            };
            assert!(
                validate_stream(&stream)
                    .iter()
                    .any(|issue| issue.code == ValidationCode::RealityFingerprintUnsupported),
                "REALITY fingerprint {name:?} must fire"
            );
        }
        for name in ["chrome", "randomizedalpn", "Chrome"] {
            let stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(reality_base_with_fingerprint(name)),
                ..Default::default()
            };
            let issues = validate_stream(&stream);
            assert!(
                !issues
                    .iter()
                    .any(|issue| issue.code == ValidationCode::RealityFingerprintUnsupported),
                "REALITY fingerprint {name:?} must not fire"
            );
            // A firing value carries the block path and Error severity.
        }
        let stream = StreamModel {
            security: Security::Reality,
            reality_settings: Some(reality_base_with_fingerprint("unsafe")),
            ..Default::default()
        };
        let issues = validate_stream(&stream);
        let finding =
            finding_with_code(&issues, ValidationCode::RealityFingerprintUnsupported).unwrap();
        assert_eq!(
            finding.path.as_deref(),
            Some("stream.realitySettings.fingerprint")
        );
        assert_eq!(finding.severity, Severity::Error);
    }

    /// The REALITY fingerprint advisory: a wire-valid name outside the
    /// known-good set the editor offers warns exactly once on the field
    /// path, the empty default and the three names upstream's REALITY
    /// scenarios exercise stay silent, and an invalid name keeps exactly its
    /// blocking finding with no advisory beside it.
    #[test]
    fn reality_fingerprint_outside_known_good_warns_once_on_the_field_path() {
        let pointer = || Some("stream.realitySettings.fingerprint".to_string());
        for name in [
            "ios",
            "edge",
            "qq",
            "android",
            "randomized",
            "randomizedalpn",
        ] {
            let stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(reality_base_with_fingerprint(name)),
                ..Default::default()
            };
            let issues = validate_stream(&stream);
            assert_eq!(
                issues,
                vec![warning(
                    ValidationCode::RealityFingerprintUntested(name.into()),
                    pointer()
                )],
                "REALITY fingerprint {name:?} must warn once: {issues:#?}"
            );
        }
        // The empty default (the uTLS Chrome_Auto preset) and the three
        // names upstream's REALITY scenarios exercise are inside the
        // known-good set; a casing of a known name is the same wire value
        // (Xray lowercases the fingerprint before its checks).
        for name in ["", "chrome", "firefox", "safari", "Chrome", "Firefox"] {
            let stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(reality_base_with_fingerprint(name)),
                ..Default::default()
            };
            let issues = validate_stream(&stream);
            assert!(
                issues.is_empty(),
                "REALITY fingerprint {name:?} must not warn: {issues:#?}"
            );
        }
        // `unsafe`, `hellogolang`, and unknown names stay conf-load Errors:
        // exactly the existing finding, never a second advisory.
        for name in ["unsafe", "hellogolang", "bogus"] {
            let stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(reality_base_with_fingerprint(name)),
                ..Default::default()
            };
            let issues = validate_stream(&stream);
            assert_eq!(
                issues,
                vec![issue(
                    ValidationCode::RealityFingerprintUnsupported,
                    pointer()
                )],
                "REALITY fingerprint {name:?} must keep exactly its Error: {issues:#?}"
            );
        }
    }

    #[test]
    fn pcs_rule_covers_the_whole_entry_grammar() {
        // Canonical: empty, one 64-hex pin, colon-separated OpenSSL form,
        // multiple pins with whitespace, uppercase hex — all clean. Empty
        // comma segments are skipped, exactly like Xray's split.
        let colon_pins = "ab:".repeat(31) + "ab";
        let two_pins = format!("{}, {}", "ab".repeat(32), "cd".repeat(32));
        let upper_pin = "AB".repeat(32);
        let empty_segment_pins = format!("{},,{}", "ab".repeat(32), "cd".repeat(32));
        for pins in [
            "",
            "01ab".repeat(16).as_str(),
            colon_pins.as_str(),
            two_pins.as_str(),
            upper_pin.as_str(),
            empty_segment_pins.as_str(),
        ] {
            let tls = StreamModel {
                security: Security::Tls,
                tls_settings: Some(crate::model::stream::TlsModel {
                    fingerprint: "chrome".into(),
                    pinned_peer_cert_sha256: pins.into(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            assert!(
                !validate_stream(&tls)
                    .iter()
                    .any(|issue| issue.code == ValidationCode::PinnedPeerCertSha256Invalid),
                "pcs {pins:?} must stay valid"
            );
        }
        // Non-hex, wrong-length, and whitespace-only entries fire with the
        // wire path and Error severity.
        let short_pin = "ab".repeat(31);
        for pins in ["zz".repeat(32).as_str(), short_pin.as_str(), "gg"] {
            let tls = StreamModel {
                security: Security::Tls,
                tls_settings: Some(crate::model::stream::TlsModel {
                    fingerprint: "chrome".into(),
                    pinned_peer_cert_sha256: pins.into(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let issues = validate_stream(&tls);
            let finding = finding_with_code(&issues, ValidationCode::PinnedPeerCertSha256Invalid)
                .expect("pcs {pins:?} must fire PinnedPeerCertSha256Invalid");
            assert_eq!(
                finding.path.as_deref(),
                Some("stream.tlsSettings.pinnedPeerCertSha256")
            );
            assert_eq!(finding.severity, Severity::Error);
        }
    }

    #[test]
    fn version_strings_outside_the_range_warn_with_paths_and_never_gate() {
        let version_stream = |min: &str, max: &str| StreamModel {
            security: Security::Tls,
            tls_settings: Some(crate::model::stream::TlsModel {
                fingerprint: "chrome".into(),
                min_version: min.into(),
                max_version: max.into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        // In-range values and empty defaults never warn.
        for (min, max) in [("", ""), ("1.0", "1.3"), ("1.2", "1.2")] {
            assert!(
                !validate_stream(&version_stream(min, max))
                    .iter()
                    .any(|issue| issue.code == ValidationCode::TlsVersionRangeInvalid),
                "versions {min:?}/{max:?} must not warn"
            );
        }
        // One warning per offending field, Warning severity, on the field's
        // own wire path.
        for version in ["1.4", "2.0", "0.9", "tls1.2", "1.2.3"] {
            for (field, path) in [
                (version, "stream.tlsSettings.minVersion"),
                (version, "stream.tlsSettings.maxVersion"),
            ] {
                let stream = version_stream(
                    if path.ends_with("minVersion") {
                        field
                    } else {
                        "1.2"
                    },
                    if path.ends_with("maxVersion") {
                        field
                    } else {
                        "1.2"
                    },
                );
                let issues = validate_stream(&stream);
                let finding = finding_with_code(&issues, ValidationCode::TlsVersionRangeInvalid)
                    .expect("version {field:?} at {path} must warn");
                assert_eq!(finding.path.as_deref(), Some(path));
                assert_eq!(finding.severity, Severity::Warning);
            }
        }
        // Both fields out of range: two warnings, one per field.
        let issues = validate_stream(&version_stream("1.4", "2.1"));
        let version_issues: Vec<&ValidationIssue> = issues
            .iter()
            .filter(|issue| issue.code == ValidationCode::TlsVersionRangeInvalid)
            .collect();
        assert_eq!(version_issues.len(), 2, "{issues:#?}");
        assert_eq!(
            version_issues[0].path.as_deref(),
            Some("stream.tlsSettings.minVersion")
        );
        assert_eq!(
            version_issues[1].path.as_deref(),
            Some("stream.tlsSettings.maxVersion")
        );
    }

    // ---------- repro-gated rules batch ----------
    //
    // Every rule below shipped only after a live xray 26.7.28 reproduction
    // (2026-09-06): the TLS in-range min > max inversion and
    // xhttpSettings.extra shadowing. The dropped candidates (ALPN h2-first /
    // uTLS override, vision + non-RAW transports, vision + pinned TLS ≤ 1.2)
    // ship no code.

    #[test]
    fn tls_min_exceeds_max_warns_never_gates() {
        let version_stream = |min: &str, max: &str| StreamModel {
            security: Security::Tls,
            tls_settings: Some(crate::model::stream::TlsModel {
                fingerprint: "chrome".into(),
                min_version: min.into(),
                max_version: max.into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        // Inverted in-range pairs warn exactly once, on the block path,
        // Warning severity (config loads and the version pins silently
        // never apply — repro 2026-09-06).
        for (min, max) in [("1.3", "1.2"), ("1.2", "1.1"), ("1.3", "1.0")] {
            let issues = validate_stream(&version_stream(min, max));
            let findings: Vec<&ValidationIssue> = issues
                .iter()
                .filter(|issue| issue.code == ValidationCode::TlsMinExceedsMax)
                .collect();
            assert_eq!(findings.len(), 1, "min {min:?} > max {max:?}: {issues:#?}");
            assert_eq!(
                findings[0].path.as_deref(),
                Some("stream.tlsSettings"),
                "min {min:?} > max {max:?}"
            );
            assert_eq!(findings[0].severity, Severity::Warning);
        }
        // Equal and ordered ranges, empty defaults, and out-of-vocabulary
        // strings never fire this rule — the out-of-vocabulary pair stays
        // TlsVersionRangeInvalid's business.
        for (min, max) in [
            ("", ""),
            ("1.0", "1.3"),
            ("1.2", "1.2"),
            ("1.0", "1.0"),
            ("1.4", "2.1"),
        ] {
            assert!(
                !validate_stream(&version_stream(min, max))
                    .iter()
                    .any(|issue| issue.code == ValidationCode::TlsMinExceedsMax),
                "versions {min:?}/{max:?} must not fire TlsMinExceedsMax"
            );
        }
    }

    #[test]
    fn xhttp_extra_key_shadowing_warns_with_the_key() {
        let with_extra = XhttpSettings {
            x_padding_method: "tokenish".into(),
            ..Default::default()
        };
        let mut with_extra = with_extra;
        with_extra
            .extra
            .insert("xPaddingMethod".into(), json!("bogus"));
        let issues = validate_stream(&xhttp_stream(with_extra));
        let finding = issues
            .iter()
            .find(|issue| {
                matches!(
                    &issue.code,
                    ValidationCode::XhttpExtraShadowsSettings(key)
                        if key == "xPaddingMethod"
                )
            })
            .expect("xPaddingMethod in extra must warn");
        assert_eq!(
            finding.path.as_deref(),
            Some("stream.xhttpSettings.xPaddingMethod")
        );
        assert_eq!(finding.severity, Severity::Warning);
        // The rendered message carries the offending key (fill arm).
        let rendered = crate::i18n::validation_issue_message(
            &warning(
                ValidationCode::XhttpExtraShadowsSettings("xPaddingMethod".into()),
                Some("stream.xhttpSettings.xPaddingMethod".into()),
            ),
            crate::model::settings::Language::En,
        );
        assert!(rendered.contains("xPaddingMethod"), "{rendered}");
        // Case-insensitive extra keys are caught too (serde flatten is
        // exact-case, but Go's JSON unmarshal is not).
        let mut case_extra = XhttpSettings::default();
        case_extra
            .extra
            .insert("XPADDINGMETHOD".into(), json!("bogus"));
        let issues = validate_stream(&xhttp_stream(case_extra));
        assert!(issues.iter().any(|issue| {
            matches!(
                &issue.code,
                ValidationCode::XhttpExtraShadowsSettings(key)
                    if key == "xPaddingMethod"
            )
        }));
        // An unmodeled extra key stays silent, and so does canonical state.
        let mut other_extra = XhttpSettings::default();
        other_extra.extra.insert("xPaddingCaps".into(), json!(42));
        assert!(validate_stream(&xhttp_stream(other_extra)).is_empty());
        assert!(validate_stream(&xhttp_stream(XhttpSettings::default())).is_empty());
    }

    // ---------- protocol-settings vocabulary / required values ----------
    //
    // Tests beside the existing pins: each new code fires on a crafted
    // profile with its wire path and is absent on the canonical value. All
    // fixtures use a private-literal address and canonical essentials so no
    // transport-security or draft-noise rules obscure the assertions.
    // (The settings `protocol` mismatch guard in the model constructors is
    // bypassed the same way the existing pins do it.)

    const CANONICAL_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn vless_canonical() -> OutboundModel {
        let mut outbound = OutboundModel::new(Protocol::Vless);
        let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.address = "1.2.3.4".into();
        settings.port = 443;
        settings.id = CANONICAL_UUID.into();
        settings.encryption = "none".into();
        outbound
    }

    fn vmess_canonical() -> OutboundModel {
        let mut outbound = OutboundModel::new(Protocol::Vmess);
        let ProtocolSettings::Vmess(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.address = "1.2.3.4".into();
        settings.port = 443;
        settings.id = CANONICAL_UUID.into();
        outbound
    }

    fn shadowsocks_canonical() -> OutboundModel {
        let mut outbound = OutboundModel::new(Protocol::Shadowsocks);
        let ProtocolSettings::Shadowsocks(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.address = "1.2.3.4".into();
        settings.port = 8388;
        settings.method = "aes-128-gcm".into();
        settings.password = "secret".into();
        outbound
    }

    fn finding<'a>(
        issues: &'a [ValidationIssue],
        code: &ValidationCode,
    ) -> Option<&'a ValidationIssue> {
        issues.iter().find(|issue| &issue.code == code)
    }

    const MUST_NOT_FIRE_CODES: &[ValidationCode] = &[
        ValidationCode::VlessFlowUnsupported,
        ValidationCode::VlessEncryptionUnsupported,
        ValidationCode::ShadowsocksMethodUnsupported,
        ValidationCode::Shadowsocks2022KeyInvalid,
        ValidationCode::TrojanSettingsIncomplete,
        ValidationCode::ShadowsocksSettingsIncomplete,
        ValidationCode::SettingsPortZero,
        ValidationCode::SettingsIdNotUuid,
    ];

    #[test]
    fn canonical_protocol_settings_never_fire() {
        for outbound in [
            vless_canonical(),
            vmess_canonical(),
            OutboundModel::new(Protocol::Trojan),
            shadowsocks_canonical(),
        ] {
            let mut outbound = outbound;
            if let ProtocolSettings::Trojan(settings) = &mut outbound.settings {
                settings.address = "1.2.3.4".into();
                settings.port = 443;
                settings.password = "secret".into();
            }
            let issues = validate_outbound(&outbound);
            for code in MUST_NOT_FIRE_CODES {
                assert!(
                    !issues.iter().any(|issue| &issue.code == code),
                    "{code:?} fired on a canonical profile: {issues:#?}"
                );
            }
        }
    }

    #[test]
    fn vless_out_of_vocab_values_fire_errors_with_wire_paths() {
        let mut outbound = vless_canonical();
        let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.flow = "xtls-rprx-xtls".into();
        settings.encryption = "aes-128-gcm".into();
        settings.port = 0;
        settings.id = "short-not-a-uuid".into();
        let issues = validate_outbound(&outbound);
        for (code, path) in [
            (ValidationCode::VlessFlowUnsupported, "settings.flow"),
            (
                ValidationCode::VlessEncryptionUnsupported,
                "settings.encryption",
            ),
            (ValidationCode::SettingsPortZero, "settings.port"),
            (ValidationCode::SettingsIdNotUuid, "settings.id"),
        ] {
            let issue = finding(&issues, &code).unwrap_or_else(|| {
                panic!("{code:?} must fire on the crafted VLESS profile: {issues:#?}")
            });
            assert_eq!(issue.path.as_deref(), Some(path));
            assert_eq!(issue.severity, Severity::Error, "{issue:?}");
        }
    }

    #[test]
    fn vless_encryption_rejects_every_padding_and_key_mismatch_class() {
        // The core reads a part shorter than 20 characters as a padding
        // token (infra/conf/vless.go:352-356). With no key part at all its
        // padding slice runs past the end of the value and panics (:370);
        // a short token after a key part cuts the padding out of that key,
        // so handler creation fails with `failed to use encryption`
        // (proxy/vless/outbound/outbound.go:95). A padding prefix must
        // satisfy the grammar the core's client parses
        // (proxy/vless/encryption/common.go:223-257), and a 1184-byte key
        // must hold ML-KEM-768 coefficients below q = 3329. The model
        // refuses every such shape. Junk in a key stays refused even where
        // the core's decoder skips it (a newline) — the recorded deliberate
        // strictness.
        const X25519: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";
        let mlkem = URL_SAFE_NO_PAD.encode([7_u8; 1184]);
        // ML-KEM-768 bodies around the core's coefficient boundary: each of
        // the 384 three-byte chunks of the first 1152 bytes holds two 12-bit
        // little-endian coefficients, both must stay below q = 3329, and the
        // trailing 32-byte rho is unchecked.
        let mlkem_key = |mutate: fn(&mut [u8; 1184])| {
            let mut body = [0_u8; 1184];
            mutate(&mut body);
            URL_SAFE_NO_PAD.encode(body)
        };
        let first_coeff_3328 = mlkem_key(|body| body[1] = 0x0d);
        let first_coeff_3329 = mlkem_key(|body| {
            body[0] = 0x01;
            body[1] = 0x0d;
        });
        let second_coeff_3328 = mlkem_key(|body| body[2] = 0xd0);
        let second_coeff_4080 = mlkem_key(|body| body[2] = 0xff);
        let last_coeff_4080 = mlkem_key(|body| body[1151] = 0xff);
        let rho_max = mlkem_key(|body| {
            body[1] = 0x0d;
            body[1152..].fill(0xff);
        });
        let body_max = mlkem_key(|body| body.fill(0xff));
        // Go's decoder tolerates non-zero trailing bits: the spare bit in
        // the 43rd character decodes to the same 32 bytes.
        let trailing_bits = format!("{}B", &X25519[..42]);
        let cases = [
            // `none`, a real X25519 key, a real ML-KEM key, and keys behind
            // valid padding prefixes stay accepted; only the even-index
            // items in a padding prefix count toward the 65553 total.
            ("none".to_string(), true),
            (format!("mlkem768x25519plus.native.1rtt.{X25519}"), true),
            (format!("mlkem768x25519plus.xorpub.0rtt.{mlkem}"), true),
            (
                format!("mlkem768x25519plus.random.1rtt.100-35-35.{X25519}"),
                true,
            ),
            (
                format!(
                    "mlkem768x25519plus.random.1rtt.100-111-1111.50-0-3333.200-100-2000.{X25519}"
                ),
                true,
            ),
            // A lone empty token joins to the empty padding string the core
            // returns on before parsing (common.go:224-226), so it loads.
            (format!("mlkem768x25519plus.native.1rtt..{X25519}"), true),
            // A fourth `-` field is ignored, exactly as the core reads the
            // first three and drops the rest.
            (
                format!("mlkem768x25519plus.native.1rtt.100-35-35-999.{X25519}"),
                true,
            ),
            // ML-KEM coefficient boundaries: 3328 in either coefficient of
            // the first chunk loads, a 0xFF-filled rho loads, and non-zero
            // trailing bits decode to the same X25519 key.
            (
                format!("mlkem768x25519plus.xorpub.0rtt.{first_coeff_3328}"),
                true,
            ),
            (
                format!("mlkem768x25519plus.xorpub.0rtt.{second_coeff_3328}"),
                true,
            ),
            (format!("mlkem768x25519plus.xorpub.0rtt.{rho_max}"), true),
            (
                format!("mlkem768x25519plus.native.1rtt.{trailing_bits}"),
                true,
            ),
            // A coefficient of 3329 or larger anywhere in the first 1152
            // bytes fails handler creation with `invalid polynomial
            // encoding`, as does a 0xFF-filled body.
            (
                format!("mlkem768x25519plus.xorpub.0rtt.{first_coeff_3329}"),
                false,
            ),
            (
                format!("mlkem768x25519plus.xorpub.0rtt.{second_coeff_4080}"),
                false,
            ),
            (
                format!("mlkem768x25519plus.xorpub.0rtt.{last_coeff_4080}"),
                false,
            ),
            (format!("mlkem768x25519plus.xorpub.0rtt.{body_max}"), false),
            // Every part short: the core panics at config load.
            ("mlkem768x25519plus.native.1rtt.key".to_string(), false),
            ("mlkem768x25519plus.native.1rtt.KEY".to_string(), false),
            ("mlkem768x25519plus.native.1rtt.".to_string(), false),
            ("mlkem768x25519plus.native.1rtt.ab".to_string(), false),
            ("mlkem768x25519plus.native.1rtt.a.b".to_string(), false),
            (
                "mlkem768x25519plus.native.1rtt.key.extra".to_string(),
                false,
            ),
            // A short token after a key part: handler creation fails.
            (format!("mlkem768x25519plus.native.1rtt.{X25519}.ab"), false),
            // A short token before the key part is padding, and this one
            // fails the padding grammar (fewer than three `-` fields).
            (format!("mlkem768x25519plus.native.1rtt.ab.{X25519}"), false),
            // Two empty tokens join to a dot, not to an empty string, and
            // the core refuses that padding item.
            (format!("mlkem768x25519plus.native.1rtt...{X25519}"), false),
            // Padding prefixes the core's grammar refuses: the first item
            // is under 100, an item has two fields, and the even-index
            // total exceeds 65553.
            (
                format!("mlkem768x25519plus.native.1rtt.99-35-35.{X25519}"),
                false,
            ),
            (
                format!("mlkem768x25519plus.native.1rtt.100-35.{X25519}"),
                false,
            ),
            (
                format!(
                    "mlkem768x25519plus.native.1rtt.100-35-65535.100-35-35.100-35-65535.{X25519}"
                ),
                false,
            ),
            // A key-shaped part that decodes to neither 32 nor 1184 bytes,
            // a real key with trailing junk, an extra character, `=` padding
            // (not part of the raw grammar), and a key with a newline the
            // core's decoder skips — the app refuses every byte outside the
            // alphabet, the recorded strictness.
            (
                "mlkem768x25519plus.native.1rtt.AAAAAAAAAAAAAAAAAAAA".to_string(),
                false,
            ),
            (format!("mlkem768x25519plus.native.1rtt.{X25519}!"), false),
            (format!("mlkem768x25519plus.native.1rtt.{X25519}A"), false),
            (format!("mlkem768x25519plus.native.1rtt.{X25519}="), false),
            (format!("mlkem768x25519plus.native.1rtt.{X25519}\n"), false),
        ];
        let mut outbound = vless_canonical();
        for (value, accepted) in cases {
            let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings.encryption = value.clone();
            let issues = validate_outbound(&outbound);
            let reported = finding(&issues, &ValidationCode::VlessEncryptionUnsupported).is_some();
            assert_eq!(!reported, accepted, "{value:?}: {issues:#?}");
        }
    }

    #[test]
    fn vless_empty_states_are_accepted_by_the_model() {
        // `""` encryption/flow/id are the state seam's defaults (a fresh
        // profile before the editor's enforce_invariants normalization);
        // the model accepts them — the required-value rules live in the
        // editor's draft sweep. Fields are cleared *after*
        // `OutboundModel::new` (whose enforce_invariants would already have
        // normalized encryption to "none"); address/port are pinned so no
        // other rule distracts.
        let mut outbound = OutboundModel::new(Protocol::Vless);
        {
            let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings.address = "1.2.3.4".into();
            settings.port = 443;
            settings.id.clear();
            settings.flow.clear();
            settings.encryption.clear();
        }
        let issues = validate_outbound(&outbound);
        for code in MUST_NOT_FIRE_CODES {
            assert!(
                !issues.iter().any(|issue| &issue.code == code),
                "{code:?} must not fire on empty default settings: {issues:#?}"
            );
        }
    }

    #[test]
    fn vmess_port_zero_and_short_id_fire_with_wire_paths() {
        let mut outbound = vmess_canonical();
        let ProtocolSettings::Vmess(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.port = 0;
        settings.id = "b831381d".into(); // 8 chars: sha1-mapped by Xray, refused here
        let issues = validate_outbound(&outbound);
        for code in [
            ValidationCode::SettingsPortZero,
            ValidationCode::SettingsIdNotUuid,
        ] {
            let issue = finding(&issues, &code)
                .unwrap_or_else(|| panic!("{code:?} must fire: {issues:#?}"));
            assert_eq!(issue.severity, Severity::Error, "{issue:?}");
        }
        assert_eq!(
            finding(&issues, &ValidationCode::SettingsPortZero)
                .unwrap()
                .path
                .as_deref(),
            Some("settings.port")
        );
        assert_eq!(
            finding(&issues, &ValidationCode::SettingsIdNotUuid)
                .unwrap()
                .path
                .as_deref(),
            Some("settings.id")
        );
    }

    #[test]
    fn trojan_required_values_fire_one_issue_per_missing_field() {
        let outbound = OutboundModel::new(Protocol::Trojan);
        let issues = validate_outbound(&outbound);
        let trojan_issues: Vec<&ValidationIssue> = issues
            .iter()
            .filter(|issue| issue.code == ValidationCode::TrojanSettingsIncomplete)
            .collect();
        assert_eq!(trojan_issues.len(), 3, "{issues:#?}");
        let mut paths: Vec<&str> = trojan_issues
            .iter()
            .map(|issue| issue.path.as_deref().unwrap())
            .collect();
        paths.sort_unstable();
        assert_eq!(
            paths,
            ["settings.address", "settings.password", "settings.port"]
        );
        for issue in trojan_issues {
            assert_eq!(issue.severity, Severity::Error, "{issue:?}");
        }
    }

    #[test]
    fn shadowsocks_required_values_and_method_vocabulary() {
        // Defaults: empty address/password/port and an empty method — the
        // essentials fire per field and the empty method is out of the
        // vocabulary (Xray's unknown-cipher error), all Errors.
        let outbound = OutboundModel::new(Protocol::Shadowsocks);
        let issues = validate_outbound(&outbound);
        let mut paths: Vec<&str> = issues
            .iter()
            .filter(|issue| issue.code == ValidationCode::ShadowsocksSettingsIncomplete)
            .map(|issue| issue.path.as_deref().unwrap())
            .collect();
        paths.sort_unstable();
        assert_eq!(
            paths,
            ["settings.address", "settings.password", "settings.port"]
        );
        let method_issue = finding(&issues, &ValidationCode::ShadowsocksMethodUnsupported)
            .unwrap_or_else(|| panic!("empty method is unsupported: {issues:#?}"));
        assert_eq!(method_issue.path.as_deref(), Some("settings.method"));
        assert_eq!(method_issue.severity, Severity::Error);
        for issue in issues.iter().filter(|issue| {
            issue.code == ValidationCode::ShadowsocksSettingsIncomplete
                || issue.code == ValidationCode::ShadowsocksMethodUnsupported
        }) {
            assert_eq!(issue.severity, Severity::Error, "{issue:?}");
        }

        // The accepted vocabulary mirrors the import whitelist: AEAD methods
        // (case-insensitive, legacy alias spellings included), exact 2022
        // names — and nothing else. Legacy stream ciphers hit the same
        // unknown-cipher load error and are refused.
        let key_32b = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="; // base64 of 32 bytes
        for (method, password) in [
            ("AES-128-GCM", "opaque"),
            ("aead_aes_256_gcm", "opaque"),
            ("chacha20-ietf-poly1305", "opaque"),
            ("xchacha20-poly1305", "opaque"),
            ("aead_xchacha20_poly1305", "opaque"),
            ("2022-blake3-aes-128-gcm", "MDEyMzQ1Njc4OWFiY2RlZg=="),
            ("2022-blake3-aes-256-gcm", key_32b),
            ("2022-blake3-chacha20-poly1305", key_32b),
        ] {
            let mut outbound = shadowsocks_canonical();
            let ProtocolSettings::Shadowsocks(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings.method = method.into();
            settings.password = password.into();
            let issues = validate_outbound(&outbound);
            for code in [
                ValidationCode::ShadowsocksMethodUnsupported,
                ValidationCode::Shadowsocks2022KeyInvalid,
            ] {
                assert!(
                    !issues.iter().any(|issue| issue.code == code),
                    "{code:?} fired for accepted method {method:?}: {issues:#?}"
                );
            }
        }

        for method in ["aes-256-cfb", "rc4-md5", "2022-blake3-unsupported"] {
            let mut outbound = shadowsocks_canonical();
            let ProtocolSettings::Shadowsocks(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings.method = method.into();
            let issues = validate_outbound(&outbound);
            let issue = finding(&issues, &ValidationCode::ShadowsocksMethodUnsupported)
                .unwrap_or_else(|| panic!("{method:?} must be refused: {issues:#?}"));
            assert_eq!(issue.severity, Severity::Error, "{issue:?}");
            assert_eq!(issue.path.as_deref(), Some("settings.method"));
        }
    }

    #[test]
    fn shadowsocks2022_key_rule_warns_and_never_gates() {
        // Wrong-length key for the method: xray `run -test` accepts the
        // config (live repro 2026-09-05) and the session fails at dial/auth
        // time — advisory, never blocking.
        let mut outbound = shadowsocks_canonical();
        let ProtocolSettings::Shadowsocks(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.method = "2022-blake3-aes-128-gcm".into();
        // Base64 of 24 bytes — not the required 16 — for the AES-128 method.
        settings.password = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3".into();
        let issues = validate_outbound(&outbound);
        let key_issue = finding(&issues, &ValidationCode::Shadowsocks2022KeyInvalid)
            .unwrap_or_else(|| panic!("wrong-length 2022 key must warn: {issues:#?}"));
        assert_eq!(key_issue.severity, Severity::Warning, "{key_issue:?}");
        assert_eq!(key_issue.path.as_deref(), Some("settings.password"));
        assert!(
            !issues
                .iter()
                .filter(|issue| issue.severity == Severity::Error)
                .any(|issue| issue.code == ValidationCode::Shadowsocks2022KeyInvalid),
            "a Warning finding must never gate"
        );

        // ChaCha20 2022 rejects the multi-psk colon form.
        let mut outbound = shadowsocks_canonical();
        let ProtocolSettings::Shadowsocks(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.method = "2022-blake3-chacha20-poly1305".into();
        let key: String =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [b'0'; 32]);
        settings.password = format!("{key}:{key}");
        let issues = validate_outbound(&outbound);
        assert!(
            finding(&issues, &ValidationCode::Shadowsocks2022KeyInvalid).is_some(),
            "colon-separated ChaCha20-2022 key must warn: {issues:#?}"
        );

        // An empty password on a 2022 method belongs to the required-value
        // Error rule only — the advisory key rule must not double-report.
        let mut outbound = shadowsocks_canonical();
        let ProtocolSettings::Shadowsocks(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.method = "2022-blake3-aes-128-gcm".into();
        settings.password = String::new();
        let issues = validate_outbound(&outbound);
        assert!(
            issues.iter().any(|issue| {
                issue.code == ValidationCode::ShadowsocksSettingsIncomplete
                    && issue.path.as_deref() == Some("settings.password")
            }),
            "empty 2022 password must stay an Error: {issues:#?}"
        );
        assert!(
            !issues
                .iter()
                .any(|issue| issue.code == ValidationCode::Shadowsocks2022KeyInvalid),
            "empty 2022 password must not double-report as a key warning: {issues:#?}"
        );

        // Non-2022 methods treat the password as opaque.
        let mut outbound = shadowsocks_canonical();
        let ProtocolSettings::Shadowsocks(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.password = "any-garbage!!".into();
        let issues = validate_outbound(&outbound);
        assert!(
            !issues
                .iter()
                .any(|issue| issue.code == ValidationCode::Shadowsocks2022KeyInvalid),
            "classic AEAD passwords are opaque: {issues:#?}"
        );
    }

    #[test]
    fn canonical_uuid_predicate_is_parse_str_and_nothing_more() {
        for accepted in [
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            // Hex is case-insensitive.
            "B831381D-6324-4D53-AD4F-8CDA48B30811",
            // `Uuid::parse_str` also accepts its unhyphenated 32-hex
            // "simple" form, and all four callers have always shared that
            // verdict.
            "b10a8db164e0754105b7a99be72e3fe5",
        ] {
            assert!(is_canonical_uuid(accepted), "{accepted:?} must pass");
        }
        for rejected in [
            // 1-30-char strings: Xray sha1-maps these to another account.
            "some-account-name",
            // Canonical shape cut short (the import grammar's own case).
            "b831381d-6324-4d53-ad4f-8cda48b3081",
            "",
            // 32 characters, one of them not hex.
            "b10a8db164e0754105b7a99be72e3feG",
            // Canonical shape, non-hex digits.
            "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz",
        ] {
            assert!(!is_canonical_uuid(rejected), "{rejected:?} must be refused");
        }
    }

    #[test]
    fn uuid_rule_fires_only_for_nonempty_noncanonical_ids() {
        for id in [
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            "B831381D-6324-4D53-AD4F-8CDA48B30811",
        ] {
            let mut outbound = vless_canonical();
            let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings.id = id.into();
            let issues = validate_outbound(&outbound);
            assert!(
                !issues
                    .iter()
                    .any(|issue| issue.code == ValidationCode::SettingsIdNotUuid),
                "canonical id {id:?} must pass: {issues:#?}"
            );
        }
        // The divergence: Xray sha1-maps 1-30-char strings to a deterministic
        // v5 UUID (different account) and accepts 32-36-char hex forms;
        // broccoli's policy is UUID-only (the single `is_canonical_uuid`
        // predicate the import check_uuid and the UI field validators call).
        for id in [
            "b831381d-6324-4d53-ad4f-8cda48b3081",
            "some-account-name",
            "not a uuid",
            "b831381d-6324-4d53-ad4f-8cda48b3081x",
        ] {
            let mut outbound = vless_canonical();
            let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings.id = id.into();
            let issues = validate_outbound(&outbound);
            let issue = finding(&issues, &ValidationCode::SettingsIdNotUuid)
                .unwrap_or_else(|| panic!("non-canonical id {id:?} must be refused: {issues:#?}"));
            assert_eq!(issue.severity, Severity::Error, "{issue:?}");
            assert_eq!(issue.path.as_deref(), Some("settings.id"));
        }
    }

    #[test]
    fn mux_vision_warning_still_fires_exactly_as_before() {
        // Regression guard: the VLESS additions must not disturb
        // the mux/vision Warning rule (same predicate, same path).
        let mut outbound = vless_canonical();
        let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.flow = "xtls-rprx-vision".into();
        // Vision needs TLS/REALITY to be error-free; the mux warning must
        // still be the only finding besides it.
        let _ = outbound.stream.select_security(Security::Tls);
        outbound.mux.enabled = true;
        outbound.mux.concurrency = Some(8);
        let issues = validate_outbound(&outbound);
        let mux_issue = finding(&issues, &ValidationCode::MuxWithVisionFlow)
            .unwrap_or_else(|| panic!("mux+vision must keep warning: {issues:#?}"));
        assert_eq!(mux_issue.severity, Severity::Warning, "{mux_issue:?}");
        assert_eq!(mux_issue.path.as_deref(), Some("mux"));
        // The canonical profile stays error-free end to end.
        assert!(
            !issues.iter().any(|issue| issue.severity == Severity::Error),
            "no Error may fire on the canonical mux+vision profile: {issues:#?}"
        );
    }

    // ---------- settings-level verdict (validate_settings) ----------

    fn named_profile(id: &str, name: &str, outbound: OutboundModel) -> ServerProfile {
        ServerProfile {
            id: id.into(),
            name: name.into(),
            outbound,
            latency_ms: None,
            extra: Map::new(),
        }
    }

    #[test]
    fn settings_verdict_surfaces_the_moved_editor_rules() {
        // `sendThrough`, freedom final-rule actions, and DNS-rule actions
        // used to be editor-only errors; the settings verdict must carry all
        // three as blocking codes now.
        let mut freedom = OutboundModel::new(Protocol::Freedom);
        let ProtocolSettings::Freedom(settings) = &mut freedom.settings else {
            unreachable!()
        };
        settings
            .final_rules
            .push(crate::model::outbound::FreedomFinalRule {
                action: "proxy".into(),
                ..Default::default()
            });
        freedom.send_through = Some("10.0.0.0/33".into());

        let mut dns = OutboundModel::new(Protocol::Dns);
        let ProtocolSettings::Dns(settings) = &mut dns.settings else {
            unreachable!()
        };
        settings.rules.push(crate::model::outbound::DnsOutRule {
            action: String::new(),
            ..Default::default()
        });

        let servers = ServersFile {
            profiles: vec![
                named_profile("aaaaaaaa11111111", "edge", freedom),
                named_profile("bbbbbbbb22222222", "resolver", dns),
            ],
            ..Default::default()
        };
        let issues = validate_settings(&Settings::default(), &servers, 10853);
        for code in [
            ValidationCode::SendThroughInvalid,
            ValidationCode::FreedomFinalRuleInvalid,
            ValidationCode::DnsRuleActionInvalid,
        ] {
            let issue = finding(&issues, &code).unwrap_or_else(|| {
                panic!("{code:?} must fire through the settings verdict: {issues:#?}")
            });
            assert_eq!(issue.severity, Severity::Error, "{issue:?}");
        }
    }

    #[test]
    fn moved_editor_predicates_keep_their_vocabularies() {
        for accepted in ["origin", "srcip", "127.0.0.1", "10.0.0.0/8", "fd00::/64"] {
            assert!(send_through_supported(accepted), "{accepted:?}");
        }
        for refused in ["bogus", "", "10.0.0.0/33"] {
            assert!(!send_through_supported(refused), "{refused:?}");
        }

        for accepted in ["allow", "block", "ALLOW", "Block"] {
            assert!(freedom_final_rule_supported(accepted), "{accepted:?}");
        }
        for refused in ["", "proxy", "deny"] {
            assert!(!freedom_final_rule_supported(refused), "{refused:?}");
        }

        for accepted in DNS_OUT_ACTIONS {
            assert!(dns_out_action_supported(accepted), "{accepted:?}");
        }
        for refused in ["", "proxy", "Direct"] {
            assert!(!dns_out_action_supported(refused), "{refused:?}");
        }
    }

    #[test]
    fn settings_verdict_walks_the_generator_rules_in_order() {
        use crate::i18n::{Key, t};
        use crate::model::settings::Language;

        let mut settings = Settings::default();
        settings
            .routing
            .balancers
            .push(crate::model::routing::Balancer::default());
        settings
            .routing
            .rules
            .push(crate::model::routing::Rule::default());
        settings.dns.servers.clear();
        settings.dns.servers.push(Default::default());
        settings.dns.fakedns.pools.clear();
        settings
            .dns
            .fakedns
            .pools
            .push(crate::model::dns::FakeDnsPool {
                ip_pool: "not-a-cidr".into(),
                pool_size: 0,
                extra: Map::new(),
            });

        let found = codes(&validate_settings(
            &settings,
            &ServersFile::default(),
            10853,
        ));
        let position = |code: &ValidationCode| {
            found
                .iter()
                .position(|candidate| candidate == code)
                .unwrap_or_else(|| panic!("{code:?} must fire in one pass: {found:#?}"))
        };
        let balancer = position(&ValidationCode::BalancerTagMissing(1));
        // The rule's own rejection rides its keyed integrity sentence.
        let rule_target = t(Language::En, Key::IntegrityRuleTargetRequired).to_string();
        let rule = position(&ValidationCode::RoutingRuleTarget(1, rule_target));
        let server = position(&ValidationCode::DnsServerAddressMissing(1));
        let pool_cidr = position(&ValidationCode::FakeDnsPoolCidrInvalid(1));
        let pool_size = position(&ValidationCode::FakeDnsPoolSizeInvalid(1));
        assert!(
            balancer < rule && rule < server && server < pool_cidr && pool_cidr < pool_size,
            "rules must stay in the generator's order: {found:#?}"
        );
    }

    #[test]
    fn settings_verdict_reports_profile_chains_and_the_profile_location() {
        let mut first = named_profile(
            "aaaaaaaa11111111",
            "",
            OutboundModel::new(Protocol::Freedom),
        );
        first.outbound.chain_via("srv-bbbbbbbb");
        first.outbound.send_through = Some("bogus".into());
        let mut second = named_profile(
            "bbbbbbbb22222222",
            "second",
            OutboundModel::new(Protocol::Freedom),
        );
        second.outbound.chain_via("srv-aaaaaaaa");
        let servers = ServersFile {
            profiles: vec![first, second],
            ..Default::default()
        };

        let issues = validate_settings(&Settings::default(), &servers, 10853);
        let scoped = finding(&issues, &ValidationCode::SendThroughInvalid)
            .expect("the profile's own rule must fire");
        assert_eq!(
            scoped.path.as_deref(),
            Some("srv-aaaaaaaa"),
            "a profile-scoped finding carries the profile's display name"
        );
        finding(
            &issues,
            &ValidationCode::OutboundChainCycle(
                "srv-aaaaaaaa -> srv-bbbbbbbb -> srv-aaaaaaaa".into(),
            ),
        )
        .unwrap_or_else(|| panic!("the chain cycle must be reported: {issues:#?}"));
    }

    #[test]
    fn retired_proxy_settings_key_gates_every_shape_with_the_profile_location() {
        use crate::i18n::validation_issue_message;
        use crate::model::settings::Language;

        // Every non-null JSON shape loads — a wrong-typed or malformed value
        // must not fail the load (Xray models the key as a raw message) — and
        // each one leaves the profile gated under its own location until the
        // user resolves it. The fix-it text names the replacement.
        for value in [
            json!({"tag": "srv-bbbbbbbb"}),
            json!("srv-bbbbbbbb"),
            json!({"tag": 7}),
            json!(7),
            json!(true),
            json!(["srv-bbbbbbbb"]),
        ] {
            let profile: ServerProfile = serde_json::from_value(json!({
                "id": "aaaaaaaa11111111",
                "name": "first",
                "outbound": {"protocol": "freedom", "proxySettings": value},
            }))
            .unwrap_or_else(|error| panic!("{value} must load: {error}"));

            let issues = validate_profiles(std::slice::from_ref(&profile), None, false);
            let found = finding(&issues, &ValidationCode::OutboundProxySettingsRemoved)
                .unwrap_or_else(|| panic!("{value} must gate: {issues:#?}"));
            assert_eq!(found.severity, Severity::Error, "{value}");
            assert_eq!(found.path.as_deref(), Some("first"), "{value}");
            let rendered = validation_issue_message(found, Language::En);
            assert!(
                rendered.contains("streamSettings.sockopt.dialerProxy"),
                "{value}: {rendered}"
            );
            assert!(rendered.contains("proxySettings"), "{value}: {rendered}");

            // An edit clears the mark, and the profile validates clean: the
            // key is not part of the model, so nothing remains to report.
            let mut edited = profile;
            edited.outbound.retired_proxy_settings = None;
            let issues = validate_profiles(std::slice::from_ref(&edited), None, false);
            assert!(issues.is_empty(), "{value}: {issues:#?}");
        }

        // JSON `null` is the Go zero shape — the pinned core accepts it — so
        // the profile drives no finding and the key is gone from the model
        // (and therefore from the next save).
        let nulled: ServerProfile = serde_json::from_value(json!({
            "id": "aaaaaaaa11111111",
            "name": "first",
            "outbound": {"protocol": "freedom", "proxySettings": null},
        }))
        .expect("a null value must load");
        assert!(nulled.outbound.retired_proxy_settings.is_none());
        let issues = validate_profiles(std::slice::from_ref(&nulled), None, false);
        assert!(issues.is_empty(), "{issues:#?}");
        let persisted = serde_json::to_value(&nulled).expect("the profile serializes");
        assert!(
            persisted["outbound"].get("proxySettings").is_none(),
            "{persisted}"
        );
    }

    #[test]
    fn oversized_profile_identity_fields_render_bounded_findings() {
        // A hand-edited state file can carry multi-KB ids and names; every
        // parameterized payload and the per-profile finding path are bounded
        // with `links::excerpt` at construction (the enum's own contract), so
        // no render site can be inflated by them.
        use crate::i18n::validation_issue_message;
        use crate::model::settings::Language;

        let huge = "p".repeat(4096);
        let mut first = named_profile(&huge, &huge, OutboundModel::new(Protocol::Freedom));
        first.outbound.send_through = Some(huge.clone());
        let second = named_profile(&huge, "", OutboundModel::new(Protocol::Freedom));
        let servers = ServersFile {
            active: Some(huge.clone()),
            profiles: vec![first, second],
            ..Default::default()
        };

        let issues = validate_settings(&Settings::default(), &servers, 10853);
        assert!(
            issues.iter().any(|issue| matches!(
                issue.code,
                ValidationCode::ActiveProfileAmbiguous(..)
                    | ValidationCode::ProfileIdDuplicated(..)
            )),
            "the fixture must produce parameterized findings: {issues:#?}"
        );
        let scoped = finding(&issues, &ValidationCode::SendThroughInvalid)
            .expect("the profile's own rule must fire");
        let path = scoped.path.as_deref().expect("profile findings are scoped");
        assert!(
            path.chars().count() <= crate::links::MAX_ERROR_EXCERPT_CHARS + 1,
            "the profile location must be excerpted: {path:?}"
        );
        for issue in &issues {
            let message = validation_issue_message(issue, Language::En);
            assert!(
                !message.contains(&huge),
                "finding must not embed the raw value: {message}"
            );
            assert!(
                message.len() < 1024,
                "finding must stay bounded, got {} chars: {message}",
                message.len()
            );
        }
    }

    #[test]
    fn default_settings_verdict_is_error_free() {
        // Golden generation starts from the defaults; a spurious Error here
        // would block every one of them.
        let issues = validate_settings(&Settings::default(), &ServersFile::default(), 10853);
        assert!(
            !issues.iter().any(|issue| issue.severity == Severity::Error),
            "{issues:#?}"
        );
    }

    /// The collision walk judges exactly the entries the emitter carries: a tag
    /// shared with an entry `emit` leaves off the wire is no collision, and
    /// turning that entry on is one. The expectations are read from the
    /// emitter's own enablement predicates, so a walk that keeps its own copy
    /// of the policy fails here; `emit`'s emitted-document agreement test pins
    /// the other reader against the same predicates.
    #[test]
    fn inbound_collisions_follow_the_emitted_entries() {
        use crate::model::DokodemoCfg;

        let duplicates = |settings: &Settings| {
            validate_settings(settings, &ServersFile::default(), 10853)
                .into_iter()
                .filter(|issue| matches!(issue.code, ValidationCode::InboundTagDuplicated(_)))
                .collect::<Vec<_>>()
        };

        // The dokodemo arm: the disabled listener reuses an emitted endpoint's
        // tag, but it is off the wire, so nothing collides.
        let mut settings = Settings::default();
        let seeded_tag = settings.local_inbounds[0].tag.clone();
        assert!(
            emit::local_inbound_emitted(&settings.local_inbounds[0]),
            "the seeded endpoint is on the wire"
        );
        settings.dokodemo = vec![DokodemoCfg {
            tag: seeded_tag.clone(),
            ..Default::default()
        }];
        assert!(!emit::dokodemo_emitted(&settings.dokodemo[0]));
        assert!(
            duplicates(&settings).is_empty(),
            "a listener the emitter drops cannot collide"
        );

        settings.dokodemo[0].enabled = true;
        assert!(emit::dokodemo_emitted(&settings.dokodemo[0]));
        let found = duplicates(&settings);
        assert_eq!(
            found.len(),
            1,
            "the emitted listener collides on the shared tag: {found:#?}"
        );
        assert_eq!(
            found[0].code,
            ValidationCode::InboundTagDuplicated(seeded_tag.clone())
        );
        assert_eq!(found[0].path, None, "a tag collision carries no path");

        // The local-endpoint arm: a disabled duplicate of an emitted tag is
        // off the wire too.
        let mut settings = Settings::default();
        let mut copy = settings.local_inbounds[0].clone();
        copy.enabled = false;
        settings.local_inbounds.push(copy);
        let copy_index = settings.local_inbounds.len() - 1;
        assert!(!emit::local_inbound_emitted(
            &settings.local_inbounds[copy_index]
        ));
        assert!(
            duplicates(&settings).is_empty(),
            "an endpoint the emitter drops cannot collide"
        );

        settings.local_inbounds[copy_index].enabled = true;
        assert!(emit::local_inbound_emitted(
            &settings.local_inbounds[copy_index]
        ));
        assert_eq!(
            duplicates(&settings).len(),
            1,
            "the emitted endpoint collides on the shared tag"
        );
    }
}
