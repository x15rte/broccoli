//! Model validation pass — the single seam shared by the share-link importer/
//! exporter, the config generator, and the editor.
//!
//! Pure model checks: no i18n here. Every issue carries a [`ValidationCode`],
//! an optional wire path, and its [`Severity`] tier; callers render codes
//! through `crate::i18n::validation_message`. Each pass returns a [`Verdict`],
//! which answers the tier questions (`blocking`, `advisory`, `first_blocking`)
//! so no caller re-filters findings by severity. One pass per model, no
//! short-circuit — a single `validate_outbound` call surfaces every protocol,
//! stream, and transport-security problem.
//!
//! The passes nest, and which one a gate asks is the gate's scope:
//!
//! - [`validate_outbound`] — one profile's protocol, stream and transport
//!   security. What the share-link paste gate and the editor sweep judge.
//! - [`validate_profiles`] — that plus the profile-set rules (identity,
//!   generated tags, the dial graph's chain findings), judged against the
//!   emitted outbound universe. `active_id` and `require_nonempty` are the
//!   scope's own inputs: the latency probe requires at least one profile and
//!   judges no active selection.
//! - [`validate_settings`] — that plus every settings-wide rule (balancers,
//!   listeners, TUN, routing, DNS, geodata), including the listener collisions
//!   the control-plane port participates in — which is why generation, the one
//!   caller that knows the port it is about to bind, supplies it. Every gate
//!   that can apply a configuration judges this scope (`gen::generate`).
//!
//! `Network::supports_reality` stays in `stream.rs` as the shared fact; this
//! module only consumes it.
//!
//! The rules live in three scope files, each with its own tests: `stream.rs`
//! holds the stream/transport vocabularies (protocol settings,
//! transport-security formats, the stream/sockopt/strategy enum surfaces) and
//! the finalmask validator, `outbound.rs` the outbound envelope and DNS-rule
//! vocabularies, and `settings.rs` the settings-level verdict with its
//! per-field queries. This module holds the taxonomy and the vocabulary more
//! than one scope reads ([`ValidationCode`], [`Severity`],
//! [`ValidationIssue`], [`Verdict`], their constructors), and re-exports every
//! scope item, so `crate::model::validation::X` stays the one path a caller
//! imports.

use crate::links::{excerpt, excerpt_debug};
use crate::model::stream::Network;
use serde_json::{Map, Value};

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
    /// alias vocabulary (`infra/conf/shadowsocks.go` `cipherFromString`,
    /// case-insensitive, and `proxy/shadowsocks_2022.GetCipherMethod`, also
    /// case-insensitive; legacy stream ciphers hit the same unknown-cipher
    /// load error). Vocabulary mirrors the import whitelist.
    ShadowsocksMethodUnsupported,
    /// Shadowsocks-2022 `settings.password` cannot be used: the rewritten core
    /// parses each colon-separated part through `ParseKey`
    /// (`proxy/shadowsocks_2022/kdf.go`), which decodes standard base64 and
    /// falls back to the raw bytes, then refuses the whole config unless the
    /// result is exactly the method's key size (16 B for
    /// `2022-blake3-aes-128-gcm`, 32 B for the other 2022 methods); the
    /// ChaCha20 2022 method rejects the colon-joined multi-psk form
    /// (`outbound.go`). Error tier: the profile gates until the key is fixed.
    Shadowsocks2022KeyInvalid,
    /// VMess `settings.security` names a cipher the core does not read: the
    /// account build lowercases the value and maps anything outside
    /// {auto, aes-128-gcm, chacha20-poly1305} onto `auto`
    /// (infra/conf/vmess.go:27-36), so the configuration loads and runs with
    /// `auto` — an accepted value silently reinterpreted, and the generated
    /// document carries that same fallback. Advisory (Severity::Warning); the
    /// empty zero value is `auto`'s own spelling and stays silent.
    VmessSecurityUnsupported,
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
    /// moved to the `udphop` UDP mask, the core's `QuicParamsConfig`
    /// (`infra/conf/transport_finalmask.go`) no longer declares it, and the
    /// core ignores the unknown key silently, so the config
    /// applies without the hop until the user rebuilds it as a mask. The key
    /// is kept for the settings file (JSON `null` is the Go zero shape and
    /// counts as absent), never serialized to the wire, and never migrated.
    /// Advisory (Severity::Warning), never a gate.
    FinalmaskQuicHopMoved,
    /// The `udphop` mask `mode` is not a comma-separated set of
    /// `intervalLocal` / `intervalRemote` / `perConnRemote` — the mask build
    /// refuses every other component at config load
    /// (`infra/conf/transport_finalmask.go:930-940`).
    FinalmaskUdpHopModeInvalid,
    /// The `udphop` mask `interval` states an endpoint below the core's
    /// 5-second floor. The mask build replaces a fully unset `0/0` range with
    /// its own `30/30` default and then refuses anything below 5
    /// (`infra/conf/transport_finalmask.go:1098-1104`), and the wrap refuses
    /// either endpoint below 5 at dial (`udphop/conn.go:56-58`). An unset
    /// `0/0` stays legal and the key is omitted; any other shape with an
    /// endpoint below 5 gates.
    FinalmaskUdpHopIntervalTooSmall,
    /// The `udphop` mask carried the retired `sockopt` key: the mask build
    /// dropped the field (`infra/conf/transport_finalmask.go:1063-1068`,
    /// proto field 1 reserved) and the core ignores the unknown key, so the
    /// per-hop socket options never take effect. The value stays for the
    /// settings file and is stripped from the generated document. Advisory
    /// (Severity::Warning), never a gate.
    FinalmaskUdpHopSockoptRetired,
    /// A `udphop` mask `remoteIPs` entry is neither an address nor a CIDR
    /// prefix — the mask build refuses the entry at config load
    /// (`infra/conf/transport_finalmask.go:950-960`).
    FinalmaskUdpHopIpInvalid,
    /// A `udphop` / `xicmp` UDP mask sits anywhere but the last list entry.
    /// `NewFinalMask` reverses both mask slices at construction and the wrap
    /// runs forward (`transport/internet/finalmask/finalmask.go:44-46`), so
    /// the JSON list's last entry is the outermost wrap. A mask that declares
    /// `HandleDial` or `HandleListen` owns the outbound's own socket and must
    /// sit at index 0 after that reversal — `udphop` declares `HandleDial`
    /// (`.../udphop/config.go:9`) and `xicmp` both (`.../xicmp/config.go:10-12`)
    /// — and the core refuses any other index with `incorrect index: %d %T`
    /// (`finalmask.go:149-152` for `HandleDial`, `:218-221` for
    /// `HandleListen`). The core starts and every dial fails, so this gates.
    /// Carries the mask type name.
    FinalmaskUdpMaskNotLast(String),
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
    /// A `noise` item declares `type: "exp"` but its `packet` is absent or
    /// not a JSON string: the mask build unmarshals `packet` into a `string`
    /// and refuses the whole config otherwise
    /// (`infra/conf/transport_finalmask.go:319-322`). Error tier.
    FinalmaskNoiseExpPacketNotString,
    /// A `noise` `exp` expression holds no token at all (or only
    /// whitespace): the mask build refuses an empty parse
    /// (`infra/conf/transport_finalmask.go:389-391`). Error tier.
    FinalmaskNoiseExpEmpty,
    /// A `noise` `exp` expression carries text outside its `<token>` pieces:
    /// the mask build refuses any non-whitespace between and after the
    /// matched tokens, naming the text
    /// (`infra/conf/transport_finalmask.go:366-388`). Error tier.
    FinalmaskNoiseExpTrailingText(String),
    /// A `noise` `exp` token is outside the token set (`b`, `r`, `rc`, `rd`,
    /// `t`, `c`, `n`): the mask build refuses the unknown key
    /// (`infra/conf/transport_finalmask.go:429-431`). The payload is the
    /// token name. Error tier.
    FinalmaskNoiseExpUnknownToken(String),
    /// A sized `noise` `exp` token (`r`, `rc`, `rd`) carries no size: the
    /// mask build refuses the missing argument
    /// (`infra/conf/transport_finalmask.go:396-398`). The payload is the
    /// token name. Error tier.
    FinalmaskNoiseExpMissingSize(String),
    /// A sized `noise` `exp` token carries a size outside `0..=65535` or a
    /// reversed range (`lo > hi`), or one that is not a range at all: the
    /// mask build refuses it (`infra/conf/transport_finalmask.go:399-405`).
    /// The payload is the size argument. Error tier.
    FinalmaskNoiseExpSizeInvalid(String),
    /// The `noise` `exp` `<b>` token carries no hexadecimal digits, an
    /// odd count, or a non-hex character: the mask build refuses the bytes
    /// (`infra/conf/transport_finalmask.go:407-417`). The payload is the
    /// argument. Error tier.
    FinalmaskNoiseExpBytesInvalid(String),
    /// A `noise` `exp` token that takes no size (`t`, `c`, `n`) carries one:
    /// the mask build refuses the argument
    /// (`infra/conf/transport_finalmask.go:419-428`). The payload is the
    /// token name. Error tier.
    FinalmaskNoiseExpArgumentNotAllowed(String),
    FinalmaskSalamanderPacketSize,
    /// A retired `xdns` spelling: the removed `domain` key, or a string where
    /// `domains`/`resolvers` now hold objects. The value is retained in the
    /// settings file and never reaches the wire, so the mask runs without it.
    /// Advisory (Severity::Warning), never a gate.
    FinalmaskXdnsShapeRetired,
    /// An `xdns` domain `types` list is empty or names a type outside A (1),
    /// CNAME (5), TXT (16), and AAAA (28): the domain build refuses it
    /// (`transport/internet/finalmask/xdns/domain.go:88-98`). Error tier.
    FinalmaskXdnsDomainTypesInvalid,
    /// An `xdns` domain `name` holds two dots in a row: the domain build
    /// refuses it (`transport/internet/finalmask/xdns/domain.go:83-85`).
    /// Error tier.
    FinalmaskXdnsDomainNameInvalid,
    /// An `xdns` domain length limit is outside its range — `lenLimit` above
    /// 255, `labelLimit` above 63, either negative, or `edns0` neither 0 nor
    /// 512 through 4096 (`transport/internet/finalmask/xdns/domain.go:88-98`).
    /// Error tier.
    FinalmaskXdnsDomainLimitInvalid,
    /// An `xdns` domain's limits leave too little room: `lenLimit` sits below
    /// the wire length of the name plus one, or the generated labels' derived
    /// capacity is below 17 bytes
    /// (`transport/internet/finalmask/xdns/domain.go:112-128`). Error tier.
    FinalmaskXdnsDomainCapacityInvalid,
    /// An `xdns` resolver `type` folds to neither `tcp` nor `udp`: the loader
    /// reports an unknown config id
    /// (`infra/conf/transport_finalmask.go:818-821`). Error tier.
    FinalmaskXdnsResolverTypeUnknown,
    /// An `xdns` resolver `settings.addr` is missing or is not the `host:port`
    /// the mask parses before it dials
    /// (`transport/internet/finalmask/xdns/resolver_tcp.go:28`,
    /// `resolver_udp.go:26`). Error tier.
    FinalmaskXdnsResolverAddrInvalid,
    /// An `xdns` `extraPoll` is outside 0 through 3: the mask build refuses it
    /// (`infra/conf/transport_finalmask.go:872-874`). Error tier.
    FinalmaskXdnsExtraPollInvalid,
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
    /// A `filter` source-IP rule the mask build refuses
    /// (`common/geodata/rule_parser.go` via `ParseIPRules`,
    /// `infra/conf/transport_finalmask.go:105-115`): the whole configuration
    /// fails to load. The value carries the offending rule. Error tier.
    FinalmaskFilterIpRuleInvalid(String),
    /// A `filter` mask on an outbound. The loader builds it, but only a
    /// listener consults it (`transport/internet/finalmask/filter/config.go`),
    /// so the dial runs with the mask inert. Warning tier.
    FinalmaskFilterOnOutbound,
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
    /// A WireGuard `settings.remoteDNS` list holds an entry that is not an
    /// IP literal. The pinned core builds the in-network resolver set with
    /// `netip.MustParseAddr` while it creates the outbound
    /// (proxy/wireguard/client.go:102-108), so any other entry — the retired
    /// `local` sentinel and every near-miss spelling included — panics the
    /// whole process during config load: the config can never start. Error
    /// tier: the profile gates until the list is fixed.
    WireguardRemoteDnsInvalid,
    /// WireGuard `settings.domainStrategy` carried a value the pinned core no
    /// longer reads: the field and the strategy switch that read it are gone
    /// (infra/conf/wireguard.go), and the loader ignores an unknown key, so
    /// the value never takes effect. The value stays for the settings file and
    /// is stripped from the generated document. Advisory (Severity::Warning),
    /// never a gate; the replacement is `streamSettings.sockopt.domainStrategy`.
    WireguardDomainStrategyRetired,
    /// WireGuard `settings.secretKey` is empty or is not a key the pinned
    /// core builds: `WireGuardConfig.Build` runs it through
    /// `ParseWireGuardKey` (infra/conf/wireguard.go), which refuses the
    /// empty string and anything that is neither 64 hexadecimal digits nor
    /// the raw base64 of the same 32 bytes, so the whole config fails to
    /// load. Error tier: the profile gates until the key is fixed.
    WireguardSecretKeyInvalid,
    /// WireGuard `settings.reserved` is set and is not exactly three bytes:
    /// `WireGuardConfig.Build` refuses a non-empty value of any other length
    /// at config load (infra/conf/wireguard.go), and the value is spliced
    /// into the header ahead of the handshake (proxy/wireguard/bind.go), so
    /// no other length can run. An empty list is the core's zero shape and
    /// stays silent. Error tier.
    WireguardReservedKeyBytes,
    /// WireGuard `settings.peers` is empty: the pinned core refuses the
    /// outbound while it constructs the handler at config load — `NewClient`
    /// returns "empty peers" (proxy/wireguard/client.go). Error tier.
    WireguardPeersRequired,
    /// A WireGuard peer's `publicKey` is empty or is not a key the pinned
    /// core builds: an empty key fails `NewClient` ("peer without
    /// publickey") and a non-empty one fails `ParseWireGuardKey` in the
    /// peer's `Build` (infra/conf/wireguard.go) — both at config load.
    /// Error tier.
    WireguardPeerPublicKeyRequired,
    /// A WireGuard peer's `endpoint` is empty or blank: `NewClient` refuses
    /// the outbound at config load when it is empty ("peer without
    /// endpoint"), and a blank one leaves the dial no target either. Error
    /// tier: the field must name a target.
    WireguardPeerEndpointRequired,
    /// A set WireGuard peer `preSharedKey` is not a key the pinned core
    /// builds: the peer's `Build` runs it through `ParseWireGuardKey`
    /// (infra/conf/wireguard.go) and the config fails to load. Error tier.
    WireguardPresharedKeyInvalid,
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
    /// the mode parser's error text). `Network.Build` maps an unknown or empty
    /// token onto `Network_Unknown` and the core starts without listening on
    /// anything (infra/conf/common.go:77; live on the pinned binary: the
    /// process runs and logs no listening endpoint), so this is an accepted
    /// value that cannot work as configured — advisory
    /// (Severity::Warning), never a gate.
    DokodemoNetworkInvalid(String, String),
    /// A dokodemo UNIX listener without a socket path (tag). Error tier: the
    /// emitted inbound carries the blank path as its top-level `listen` with
    /// no port, and the core refuses the whole document at load ("Listen on
    /// AnyIP but no Port(s) set in InboundDetour"; live on the pinned
    /// binary), so the profile never runs.
    DokodemoUnixSocketRequired(String),
    /// Two dokodemo UNIX listeners normalize to the same socket path
    /// (tag, other tag, path). Error tier: the second listener cannot bind and
    /// the core exits at start ("failed to listen Unix Domain Socket on ...",
    /// live on the pinned binary), so the profile never runs.
    DokodemoUnixSocketConflict(String, String, String),
    /// A dokodemo IP listener with listen port 0 (tag). Advisory
    /// (Severity::Warning): the core drops a numeric zero port
    /// (infra/conf/common.go:274-276) and creates no worker, so the inbound
    /// binds nothing — an accepted value that cannot work as configured, the
    /// same shape as [`Self::DokodemoNetworkInvalid`]. Live on the pinned
    /// binary: the process starts and logs no listening endpoint.
    DokodemoPortZero(String),
    /// TUN mode without an IPv4 gateway: the adapter would carry no address
    /// while the in-tun DNS listener pins an address no adapter owns.
    TunIpv4GatewayRequired,
    /// A non-empty leak block beside an empty routing table. The core's
    /// filter install rides the routes of `autoSystemRoutingTable` and its
    /// build refuses the pair ("autoSystemWfpBlockLeak needs
    /// autoSystemRoutingTable to be set", live on the pinned binary), so the
    /// configuration never loads. Error tier.
    TunLeakRoutingTableRequired,
    /// A leak-block value outside {`dns`, `misconfigtun`} (the offending
    /// value, bounded). The core's build refuses any other spelling with
    /// "unknown autoSystemWfpBlockLeak value: ..." (live on the pinned
    /// binary), so the configuration never loads. Values fold
    /// case-insensitively, so a mixed-case `DNS` is the same half. Error
    /// tier.
    TunLeakValueUnknown(String),
    /// The emitted leak block leaves the unrouted-family half out: an address
    /// family the routing table does not route into the tunnel can then send
    /// traffic outside it. Advisory (Severity::Warning): the core loads and
    /// runs the document, only without that filter.
    TunLeakMisconfigTunOff,
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
    /// The GUI bootstrap override is an endpoint the generator cannot turn
    /// into the scoped `+local` server that resolves proxy-server domains: a
    /// domain host would need the very resolution the entry provides, and an
    /// unknown scheme has no `+local` form at all. The typed override then
    /// has no effect and the emitted document shows nothing — a configuration
    /// warning (Severity::Warning), never a gate; Xray loads and runs the
    /// document with the entry absent.
    DnsBootstrapNotResolvable,
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
    /// Freedom `settings.finalRules` beside a `sockopt.dialerProxy`: freedom
    /// is not the final outbound then, so its handler returns before it
    /// builds any final rule — the whole set is inert, which it reports once
    /// as `The "finalRules" setting is ignored when "sockopt.dialerProxy" is
    /// set, since freedom is not the final outbound.`
    /// (proxy/freedom/freedom.go:193-197). The document loads and runs
    /// without the rules, and the dialerProxy value itself is legal, so this
    /// is a configuration warning (Severity::Warning), never a gate.
    FreedomFinalRulesIgnored,
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
    /// A transport's `xmux` `maxConnections` and `maxConcurrency` both in use
    /// (`to > 0` each): Xray refuses them together on every transport whose
    /// conf build reads the block (infra/conf/transport_method.go). Error
    /// tier.
    XmuxLimitsExclusive,
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
    /// A freedom outbound whose effective `sockopt.addressPortStrategy` is
    /// neither the empty spelling nor `none`: `infra/conf/xray.go` builds the
    /// freedom handler from the whole document and refuses the outbound with
    /// `freedom outbound does not support "sockopt.addressPortStrategy"`
    /// because freedom's own dialer never reads the field
    /// (infra/conf/xray.go:343-346). Both of those spellings map to
    /// `AddressPortStrategy_None` (infra/conf/transport_sockopt.go:137-155)
    /// and stay silent; an out-of-vocabulary value is
    /// [`Self::SockoptAddressPortStrategyInvalid`]'s finding instead.
    FreedomAddressPortStrategyUnsupported,
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
    /// `.udphop`: the pinned core's `HysteriaConfig` declares none of them
    /// (infra/conf/transport_method.go), so Go's JSON unmarshal ignores the
    /// keys and nothing is logged — the values live in
    /// `finalmask.quicParams` (`congestion`, `brutalUp` / `brutalDown`,
    /// `udpHop`). The config loads and runs without the knobs, so the model
    /// warns — advisory (Severity::Warning). JSON `null` is the Go zero shape
    /// and stays silent.
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
    /// The `masque` transport is carried by an outbound whose protocol is not
    /// `masque`: the pinned core refuses the document while it builds the
    /// outbound (`the masque transport can only be used by the masque
    /// outbound`, infra/conf/xray.go:351-353). Error tier: the profile gates
    /// until the protocol or the transport changes.
    MasqueTransportRequiresMasqueOutbound,
    /// A `masque` outbound does not carry the `masque` transport. The core
    /// loads the document and refuses the outbound while it creates the
    /// handler (`not masque transport`, proxy/masque/client.go:59-61), so a
    /// config-file check never sees it — the model reports it instead. Error
    /// tier: the profile cannot start.
    MasqueOutboundRequiresMasqueTransport,
    /// The `masque` transport without `security: tls`. The core loads the
    /// document and refuses the outbound while it creates the handler
    /// (``MASQUE requires "security": "tls"``, proxy/masque/client.go:61-63);
    /// REALITY is refused earlier by the transport itself, and no other
    /// security mode carries TLS. Error tier.
    MasqueTransportRequiresTls,
    /// A `masque` outbound with an empty `settings.address` or a zero
    /// `settings.port`: the core's own conf build refuses both at load
    /// (``MASQUE: "address" is not set`` / ``MASQUE: "port" is not set``,
    /// infra/conf/masque.go:20-26). One rule, path-disambiguated. Error tier.
    MasqueSettingsIncomplete,
    /// A `masque` `settings.remoteDNS` entry is not an address literal: the
    /// core parses every entry with `netip.ParseAddr` while it builds the
    /// outbound (infra/conf/masque.go:27-30) and refuses the document. An
    /// empty list stays legal — the core substitutes its own default. Error
    /// tier.
    MasqueRemoteDnsInvalid,
    /// `stream.masqueSettings.path` is neither empty (the core's own default)
    /// nor a `/`-prefixed string whose only placeholders are `{target}` and
    /// `{ipproto}`: the core rewrites those two and refuses a path with a
    /// leading character other than `/` or any brace left over
    /// (infra/conf/transport_method.go:801-813). Error tier.
    MasquePathInvalid,
    /// `stream.masqueSettings.host` is not a bare `host[:port]` authority:
    /// the core parses `"https://" + host` and requires the parsed authority
    /// to equal the input (infra/conf/transport_method.go:813-817), so a
    /// scheme, path, query, fragment or userinfo is refused. Error tier.
    MasqueHostInvalid,
    /// A `stream.masqueSettings.headers` entry the core's HTTP field-name or
    /// field-value check refuses (infra/conf/transport_method.go:818-822).
    /// The code carries the offending header name. Error tier.
    MasqueHeaderInvalid(String),
    /// A `stream.masqueSettings.headers` entry named `host` or
    /// `capsule-protocol` (case-insensitively): the core reserves both and
    /// refuses the document (infra/conf/transport_method.go:823-825). The
    /// code carries the offending spelling. Error tier.
    MasqueReservedHeader(String),
    /// `stream.masqueSettings.headers` carries an `authorization` entry while
    /// `user` or `pass` is set: the core synthesizes that header itself and
    /// refuses the clash (infra/conf/transport_method.go:826-830). Error
    /// tier.
    MasqueAuthorizationConflict,
    /// `stream.masqueSettings.user` carries a `:`, which the basic-auth
    /// header cannot represent; the core refuses it
    /// (infra/conf/transport_method.go:833-835). Error tier.
    MasqueUserColon,
    /// Configuration warning (Severity::Warning): `stream.tlsSettings.alpn`
    /// carries both `h2` and `h3` on a `masque` stream. The transport dials
    /// HTTP/2 only when `h2` is present and `h3` is absent
    /// (transport/internet/masque/dialer.go:132-134), so the pair silently
    /// picks HTTP/3; the core accepts the config and runs it.
    MasqueAlpnPrefersHttp3,
    /// `stream.xdriveSettings.service` outside `local`, `Google Drive` and
    /// `template`: the core's conf build refuses the whole document with
    /// `unsupported service` (infra/conf/transport_method.go:876-887). The
    /// code carries the rejected spelling so the message names it. Error
    /// tier.
    XdriveServiceUnsupported(String),
    /// `stream.xdriveSettings.service` is empty — a choice never made. The
    /// core's conf build refuses it the same way it refuses any other
    /// unsupported service (infra/conf/transport_method.go:876-887); this
    /// rule exists so the message asks for a choice. Error tier.
    XdriveServiceMissing,
    /// A `Google Drive` `xdriveSettings` without exactly three non-empty
    /// secrets in the order ClientID, ClientSecret, RefreshToken: the core's
    /// conf build refuses the document (infra/conf/transport_method.go:
    /// 878-881), and its storage build re-checks the same count and each
    /// value (transport/internet/xdrive/drive.go:66-73). Error tier.
    XdriveDriveSecretsInvalid,
    /// The `template` service without a `template` object: the core's conf
    /// build refuses the document (`service "template" needs a "template"
    /// object`, infra/conf/transport_method.go:882-884). Error tier.
    XdriveTemplateMissing,
    /// A `local` or `Google Drive` `xdriveSettings` with an empty
    /// `remoteFolder`: both storages refuse it while the transport is built
    /// (`empty "remoteFolder"`, transport/internet/xdrive/local.go:20-22;
    /// `empty "remoteFolder", it must be a Google Drive folder id`,
    /// drive.go:62-64) — a start-time refusal the config-file check never
    /// sees. One rule, path-disambiguated by the service. Error tier.
    XdriveRemoteFolderRequired,
    /// A `template` operation without a `url`: the template storage is built
    /// when the transport is first used and refuses the document
    /// (`template needs put, get, list and delete operations`,
    /// transport/internet/xdrive/template.go:74-76) — a start-time refusal.
    /// The code carries the operation's name. Error tier.
    XdriveTemplateOperationUrlRequired(String),
    /// A `template` `list.namesRegex` with no capture group (an empty pattern
    /// included): the template storage refuses it
    /// (`namesRegex needs one capture group`, transport/internet/xdrive/
    /// template.go:77-87). Error tier. A pattern the regexp engine rejects is
    /// the core's own refusal when the transport is built.
    XdriveTemplateNamesRegexInvalid,
    /// A `template` `auth.type` outside `none`, `static`, `oauth2` and
    /// `basic`: the runtime refuses the first request
    /// (`unsupported auth type`, transport/internet/xdrive/template.go:
    /// 184-186). The code carries the rejected spelling. Error tier.
    XdriveTemplateAuthTypeUnsupported(String),
    /// An `oauth2` `template` auth without a `tokenUrl`: the token request is
    /// built at the first request and cannot succeed without one
    /// (transport/internet/xdrive/template.go:206-212). Error tier.
    XdriveTemplateTokenUrlRequired,
    /// A `template` header map carrying a value that is not a string: the
    /// runtime unmarshals the template into Go `map[string]string` fields
    /// (transport/internet/xdrive/template.go:19-36), so any other shape
    /// fails the storage build. One rule; the path names the map. Error
    /// tier.
    XdriveTemplateHeaderValuesNotStrings,
    /// Configuration warning (Severity::Warning): an `xdriveSettings` scalar
    /// outside the range the runtime honours. `segmentBytes` above 16 MiB and
    /// `concurrency` above 64 are capped while the transport is built
    /// (transport/internet/xdrive/params.go:13-16, :43-50), a template
    /// `concurrency` above 256 is capped (template.go:89-95, :104), and
    /// `maxPollIntervalMs` below `pollIntervalMs` is raised to it
    /// (params.go:65-67). The value is legal and the core silently rewrites
    /// it, so the rule advises instead of gating.
    XdriveScalarClamped,
    /// The `xdrive` transport on any outbound whose protocol is not VLESS:
    /// the core's outbound build refuses every other account type
    /// (`the xdrive transport can only be used by VLESS`,
    /// infra/conf/xray.go:315). Error tier.
    XdriveRequiresVless,
    /// An xdrive VLESS outbound with a non-empty `flow`: the core refuses it
    /// (`the xdrive transport doesn't support VLESS "flow"`,
    /// infra/conf/xray.go:284-286). Error tier.
    XdriveVlessFlowUnsupported,
    /// An xdrive VLESS outbound without a usable `encryption`: the core
    /// refuses the empty and `none` spellings and points at `xray vlessenc`
    /// (`the xdrive transport needs VLESS "encryption"`,
    /// infra/conf/xray.go:287-289). The editor's Generate action runs that
    /// command. Error tier.
    XdriveVlessEncryptionRequired,
    /// An xdrive VLESS outbound with Mux.Cool disabled: the core refuses it
    /// because the transport needs one mux connection
    /// (`the xdrive transport needs "mux" enabled`, infra/conf/xray.go:
    /// 290-293). A reverse-proxy account is exempt because it opens its own
    /// mux (the core's `account.Reverse == nil` guard). Error tier.
    XdriveMuxRequired,
    /// An xdrive VLESS outbound with a negative `mux.concurrency` or
    /// `mux.xudpConcurrency`: the core refuses both (infra/conf/xray.go:
    /// 290-293). One rule; the path names the offending field. Error tier.
    XdriveMuxConcurrencyNegative,
    /// An xdrive VLESS outbound with `mux.xudpProxyUDP443` set to `skip`:
    /// the core refuses that mode for the transport
    /// (infra/conf/xray.go:290-293). Error tier.
    XdriveMuxXudpProxyUdp443Skip,
    /// An xdrive VLESS outbound with a non-zero `testpre`: the core refuses
    /// it (`the xdrive transport doesn't support VLESS "testpre"`,
    /// infra/conf/xray.go:294-296). The field is not modeled and survives
    /// only in a hand-edited `settings.extra`. Error tier.
    XdriveVlessTestpreUnsupported,
    /// Configuration warning (Severity::Warning): the stored profile carries
    /// the retired `Google Drive` service spelling. It is migrated to
    /// `google-drive` on load and saved in the current spelling; the warning
    /// names the replacement for the one session that still sees the stored
    /// value.
    XdriveDriveServiceRenamed,
    /// A `google-drive` xdrive outbound in its h3 form — TLS ALPN exactly
    /// `["h3"]` — carrying a UDP mask other than `noise`: only noise composes
    /// with the QUIC datagrams the drive transport sends
    /// (infra/conf/transport_internet.go:266-276). The code carries the
    /// rejected mask type. Error tier.
    XdriveH3MaskNotNoise(String),
    /// An xdrive outbound in its h3 form with `finalmask.quicParams`
    /// congestion `brutal` or `force-brutal`: brutal is a Hysteria
    /// controller, and over h3 the core accepts `bbr` or `reno`
    /// (infra/conf/transport_internet.go:266-276). Error tier.
    XdriveH3CongestionBrutal,

    // ---- draft requirements ----
    //
    // The rules below judge a *server draft*: the empty field a fresh draft
    // starts from, the value a widget can only judge while the user types it.
    // Every one of them is a value the wire accepts — Xray builds a config
    // with an empty VLESS id as readily as it builds an empty string — so no
    // model sweep emits them and no stored profile is refused for carrying
    // them. The editor's own sweep emits them so a draft rule has an identity
    // (code + tier) instead of a rendered sentence. Their messages name the
    // field the user is looking at, so none carries a wire path.
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
    /// Freedom `settings.fragment` cannot load: `Fragment.Build`
    /// (`infra/conf/freedom.go`) refuses a `packets` value it cannot read, a
    /// `length` or `interval` that is absent, and a `length` that starts at 0.
    FreedomFragmentInvalid,
    /// A Freedom `settings.noises` entry cannot load: `ParseNoise`
    /// (`infra/conf/freedom.go`) refuses a `type` outside rand/str/hex/base64,
    /// a `packet` that does not decode for its type (a `rand` start of 0
    /// included), and an `applyTo` outside its vocabulary.
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

/// The verdict of one validation scope: every finding a pass produced, in
/// pass order, with the severity tier answered here instead of at each call
/// site — "the first thing that refuses this" and "the amber ones the UI
/// shows" were spellings of `Severity::Error`/`Severity::Warning` filters
/// repeated at every consumer.
///
/// It reads as the finding list it is (`Deref` to the slice), so a caller
/// that wants the raw order and a caller that wants the tier do not need
/// different values.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Verdict {
    issues: Vec<ValidationIssue>,
}

impl PartialEq<Vec<ValidationIssue>> for Verdict {
    fn eq(&self, other: &Vec<ValidationIssue>) -> bool {
        self.issues == *other
    }
}

impl PartialEq<[ValidationIssue]> for Verdict {
    fn eq(&self, other: &[ValidationIssue]) -> bool {
        self.issues == other
    }
}

impl Verdict {
    fn from_issues(issues: Vec<ValidationIssue>) -> Self {
        Self { issues }
    }

    /// The blocking findings — [`Severity::Error`] — in pass order: what
    /// refuses save, import and apply.
    pub fn blocking(&self) -> impl Iterator<Item = &ValidationIssue> {
        self.issues
            .iter()
            .filter(|issue| issue.severity == Severity::Error)
    }

    /// The advisory findings — [`Severity::Warning`]: legal configurations
    /// whose value cannot work as written, surfaced beside the editors.
    pub fn advisory(&self) -> impl Iterator<Item = &ValidationIssue> {
        self.issues
            .iter()
            .filter(|issue| issue.severity == Severity::Warning)
    }

    /// Whether any finding refuses the configuration.
    pub fn has_blocking(&self) -> bool {
        self.issues
            .iter()
            .any(|issue| issue.severity == Severity::Error)
    }

    /// The first blocking finding, consuming the verdict: the refusal a gate
    /// reports.
    pub fn into_first_blocking(self) -> Option<ValidationIssue> {
        self.issues
            .into_iter()
            .find(|issue| issue.severity == Severity::Error)
    }

    /// The findings as the plain list, for the callers that store or extend
    /// one.
    pub fn into_issues(self) -> Vec<ValidationIssue> {
        self.issues
    }
}

impl std::ops::Deref for Verdict {
    type Target = [ValidationIssue];

    fn deref(&self) -> &Self::Target {
        &self.issues
    }
}

impl IntoIterator for Verdict {
    type Item = ValidationIssue;
    type IntoIter = std::vec::IntoIter<ValidationIssue>;

    fn into_iter(self) -> Self::IntoIter {
        self.issues.into_iter()
    }
}

impl<'a> IntoIterator for &'a Verdict {
    type Item = &'a ValidationIssue;
    type IntoIter = std::slice::Iter<'a, ValidationIssue>;

    fn into_iter(self) -> Self::IntoIter {
        self.issues.iter()
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

mod outbound;
mod settings;
mod stream;

pub use outbound::{
    DNS_OUT_ACTIONS, XUDP_PROXY_UDP443_MODES, dns_out_action_supported,
    freedom_final_rule_supported, masque_remote_dns_verdict, mux_conflicts_with_vision_flow,
    send_through_supported, sniffing_dest_override_supported, validate_outbound, validate_sniffing,
    wireguard_peer_public_key_verdict, wireguard_preshared_key_verdict,
    wireguard_remote_dns_verdict, wireguard_secret_key_verdict,
};
pub(crate) use settings::normalize_windows_socket_path;
pub use settings::{
    inbound_auth_trap, local_inbound_auth_verdict, sniffing_row_verdict, tun_gateway_verdict,
    tun_ipv4_gateway, tun_ipv6_gateway, tun_leak_misconfig_tun_off, validate_listen_address,
    validate_profiles, validate_settings,
};
pub use stream::{
    SEQ_PLACEMENT_OPTIONS, SESSION_ID_PLACEMENT_OPTIONS, SOCKOPT_ADDRESS_PORT_STRATEGY_OPTIONS,
    SOCKOPT_DOMAIN_STRATEGY_OPTIONS, SS_METHOD_OPTIONS, TARGET_STRATEGY_OPTIONS,
    TLS_VERSION_OPTIONS, TPROXY_MODES, UPLINK_DATA_PLACEMENT_OPTIONS,
    UPLINK_STREAM_PLACEMENT_OPTIONS, VMESS_SECURITY_OPTIONS, X_PADDING_PLACEMENT_OPTIONS,
    XHTTP_MODE_OPTIONS, XPADDING_METHOD_OPTIONS, ech_sockopt_emitted, kcp_mtu_hard_ok,
    kcp_tti_hard_ok, noise_exp_finding, noise_exp_packet_finding, pinned_peer_cert_sha256_valid,
    reality_mldsa65_verify_valid, reality_public_key_valid, reality_short_id_valid,
    reality_spider_x_valid, seq_placement_supported, server_max_header_bytes_ok,
    server_name_implausible, session_id_placement_supported, shadowsocks_2022_key_usable,
    shadowsocks_method_supported, sockopt_address_port_strategy_supported,
    sockopt_domain_strategy_supported, tls_version_rank, tls_version_supported,
    uplink_data_placement_supported, uplink_http_method_mode_supported,
    uplink_placement_mode_supported, validate_finalmask, validate_sockopt, validate_stream,
    vmess_security_supported, xhttp_mode_supported, xmux_limits_conflict, xpadding_bytes_supported,
    xpadding_method_supported, xpadding_placement_supported,
};
pub(crate) use stream::{is_canonical_uuid, range_has_session_room};

#[cfg(test)]
mod tests {
    use super::*;
    /// Helpers more than one scope's tests read.
    pub(super) fn codes(issues: &[ValidationIssue]) -> Vec<ValidationCode> {
        issues.iter().map(|issue| issue.code.clone()).collect()
    }

    pub(super) fn finding<'a>(
        issues: &'a [ValidationIssue],
        code: &ValidationCode,
    ) -> Option<&'a ValidationIssue> {
        issues.iter().find(|issue| &issue.code == code)
    }
}
