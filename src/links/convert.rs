//! Document converters: Clash YAML, sing-box/Xray JSON, SIP008, WireGuard and
//! Hysteria 2 YAML in, import records out.
//!
//! Every converter follows the share-link importer's contract: a field the
//! persisted model cannot express is dropped and named as a compatibility
//! parameter; an entry is refused only when its protocol cannot be dialed by
//! the pinned core or a required field is missing. Non-server document
//! sections are ignored and named for the report.
//!
//! A converter writes into the one [`ImportBatch`]: it allocates an ordinal
//! per source entry, pushes the accepted profile with the parameters it
//! dropped, and refuses with a keyed reason. No converter renders a sentence.

use super::body::CompatibilityParameter;
use super::import::{ImportBatch, ImportReason};
use crate::diag::Diag;
use crate::i18n::Key;
use crate::model::ServerProfile;
use crate::model::outbound::{
    HttpSettings, HysteriaSettings, MasqueSettings, OutboundModel, Protocol, ProtocolSettings,
    ShadowsocksSettings, SocksSettings, TrojanSettings, VlessSettings, VmessSettings,
    WireguardPeer, WireguardSettings,
};
use crate::model::stream::{
    GrpcSettings, HttpupgradeSettings, HysteriaTransport, Network, RealityModel, Security,
    StreamModel, TlsModel, WsSettings, XhttpSettings,
};
use serde_json::Value;
use std::collections::BTreeMap;

/// One converted entry: the profile plus the compatibility parameters the
/// document parser dropped.
struct Converted {
    profile: ServerProfile,
    ignored: Vec<CompatibilityParameter>,
}

/// A document entry the converter cannot accept: either refused with its
/// keyed reason, or skipped as a non-server section.
enum Refusal {
    Refused(ImportReason),
    Ignored(String),
}

impl Refusal {
    fn refused(reason: ImportReason) -> Self {
        Self::Refused(reason)
    }
    fn ignored(name: impl Into<String>) -> Self {
        Self::Ignored(name.into())
    }
}

/// Wrap one converted entry after the model's own verdict: an entry the
/// model refuses is refused here with its keyed reason, so a document import
/// never emits a profile the profile-validation step would reject as a
/// grammar finding.
fn converted(
    profile: ServerProfile,
    ignored: Vec<CompatibilityParameter>,
) -> Result<Converted, Refusal> {
    super::validate_profile(&profile)
        .map_err(|error| Refusal::refused(ImportReason::link(error)))?;
    Ok(Converted { profile, ignored })
}

/// Protocols the pinned core can dial as an outbound.
const DIALABLE: &[&str] = &[
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "ss",
    "socks",
    "socks5",
    "http",
    "https",
    "wireguard",
    "hysteria2",
    "hysteria",
    "masque",
];

/// Protocols an entry may name but this app cannot dial: refused with raw.
const UNDIALABLE: &[&str] = &[
    "tuic",
    "anytls",
    "naive",
    "ssr",
    "ssh",
    "snell",
    "mieru",
    "juicity",
    "shadowtls",
    "awg",
];

/// Convert `text` when it is a document shape into `batch`; `false` leaves
/// it to the link pipeline.
pub fn convert_document(text: &str, batch: &mut ImportBatch) -> bool {
    let trimmed = text.trim_start();
    if (trimmed.starts_with('{') || trimmed.starts_with('['))
        && let Ok(value) = serde_json::from_str::<Value>(text)
    {
        if value.get("outbounds").and_then(Value::as_array).is_some() {
            convert_json_document(&value, batch);
            return true;
        }
        if value.get("servers").and_then(Value::as_array).is_some() {
            convert_sip008(&value, batch);
            return true;
        }
    }
    if let Ok(value) = serde_saphyr::from_str::<Value>(text) {
        if value.get("proxies").and_then(Value::as_array).is_some() {
            convert_clash(&value, batch);
            return true;
        }
        if value.get("inbounds").is_none()
            && value.get("outbounds").is_none()
            && value.get("server").is_some()
        {
            convert_hysteria2(&value, batch);
            return true;
        }
    }
    if trimmed.contains("[Interface]") || trimmed.contains("[Peer]") {
        convert_wireguard_conf(text, batch);
        return true;
    }
    false
}

/// A refusal whose message is the grammar's keyed diagnostic.
fn malformed_reason(diag: Diag) -> ImportReason {
    ImportReason::link(super::malformed(diag))
}

// ---------- Clash ----------

fn convert_clash(document: &Value, batch: &mut ImportBatch) {
    for section in ["rules", "proxy-groups", "dns"] {
        if document.get(section).is_some() {
            let ordinal = batch.begin_item();
            batch.push_ignored_section(ordinal, section);
        }
    }
    let Some(proxies) = document.get("proxies").and_then(Value::as_array) else {
        return;
    };
    for proxy in proxies {
        let ordinal = batch.begin_item();
        let raw = bound(proxy);
        match clash_entry(proxy) {
            Ok(mut entry) => {
                for parameter in &mut entry.ignored {
                    parameter.raw.clone_from(&raw);
                }
                batch.push_accepted(ordinal, entry.profile, raw, entry.ignored);
            }
            Err(Refusal::Ignored(name)) => batch.push_ignored_section(ordinal, name),
            Err(Refusal::Refused(reason)) => batch.push_refused(ordinal, "", reason, raw),
        }
    }
}

fn clash_entry(proxy: &Value) -> Result<Converted, Refusal> {
    let ty = field(proxy, "type").to_ascii_lowercase();
    if UNDIALABLE.contains(&ty.as_str()) {
        return Err(Refusal::refused(malformed_reason(
            Diag::new(Key::LinkEntryUnsupportedProtocol).arg(&ty),
        )));
    }
    if !DIALABLE.contains(&ty.as_str()) {
        let name = field(proxy, "name");
        return Err(Refusal::ignored(if name.is_empty() {
            format!("{ty} entry")
        } else {
            name.to_owned()
        }));
    }
    let protocol = match ty.as_str() {
        "vless" => Protocol::Vless,
        "vmess" => Protocol::Vmess,
        "trojan" => Protocol::Trojan,
        "ss" | "shadowsocks" => Protocol::Shadowsocks,
        "socks" | "socks5" => Protocol::Socks,
        "http" | "https" => Protocol::Http,
        "wireguard" => Protocol::Wireguard,
        "hysteria2" | "hy2" => Protocol::Hysteria,
        "hysteria" => {
            return Err(Refusal::refused(malformed_reason(Diag::new(
                Key::LinkUnsupportedHysteria1,
            ))));
        }
        "masque" => Protocol::Masque,
        other => {
            return Err(Refusal::refused(malformed_reason(
                Diag::new(Key::LinkEntryUnsupportedProtocol).arg(other),
            )));
        }
    };
    let server = field(proxy, "server").trim();
    let port = number(proxy, "port").unwrap_or_default();
    if server.is_empty() || port == 0 {
        return Err(Refusal::refused(malformed_reason(Diag::new(
            Key::LinkEntryMissingEndpoint,
        ))));
    }
    let name = field(proxy, "name").trim().to_owned();
    let name = if name.is_empty() {
        format!("{server}:{port}")
    } else {
        name
    };
    let mut ignored = Vec::new();
    require_credentials(proxy, protocol, "uuid", "password")?;
    let mut outbound = OutboundModel::new(protocol);
    outbound.settings = match protocol {
        Protocol::Vless => ProtocolSettings::Vless(VlessSettings {
            address: server.into(),
            port,
            id: field(proxy, "uuid").into(),
            flow: field(proxy, "flow").into(),
            encryption: "none".into(),
            ..Default::default()
        }),
        Protocol::Vmess => ProtocolSettings::Vmess(VmessSettings {
            address: server.into(),
            port,
            id: field(proxy, "uuid").into(),
            security: field(proxy, "cipher").into(),
            ..Default::default()
        }),
        Protocol::Trojan => ProtocolSettings::Trojan(TrojanSettings {
            address: server.into(),
            port,
            password: field(proxy, "password").into(),
            ..Default::default()
        }),
        Protocol::Shadowsocks => ProtocolSettings::Shadowsocks(ShadowsocksSettings {
            address: server.into(),
            port,
            method: field(proxy, "cipher").into(),
            password: field(proxy, "password").into(),
            ..Default::default()
        }),
        Protocol::Socks => ProtocolSettings::Socks(SocksSettings {
            address: server.into(),
            port,
            user: field(proxy, "username").into(),
            pass: field(proxy, "password").into(),
            ..Default::default()
        }),
        Protocol::Http => ProtocolSettings::Http(HttpSettings {
            address: server.into(),
            port,
            user: field(proxy, "username").into(),
            pass: field(proxy, "password").into(),
            ..Default::default()
        }),
        Protocol::Wireguard => ProtocolSettings::Wireguard(clash_wireguard(proxy, &mut ignored)),
        Protocol::Hysteria => ProtocolSettings::Hysteria(HysteriaSettings {
            address: server.into(),
            port,
            ..Default::default()
        }),
        Protocol::Masque => ProtocolSettings::Masque(MasqueSettings {
            address: server.into(),
            port,
            ..Default::default()
        }),
        _ => {
            return Err(Refusal::refused(malformed_reason(
                Diag::new(Key::LinkEntryUnsupportedProtocol).arg(protocol.as_str()),
            )));
        }
    };
    outbound.stream = clash_stream(proxy, protocol, &mut ignored);
    if bool_field(proxy, "udp") {
        // The model has no per-outbound UDP switch; the core dials UDP as
        // the protocol allows.
        ignored.push("udp".into());
    }
    const CLASH_KEYS: &[&str] = &[
        "name",
        "type",
        "server",
        "port",
        "uuid",
        "password",
        "cipher",
        "username",
        "flow",
        "tls",
        "servername",
        "sni",
        "client-fingerprint",
        "reality-opts",
        "alpn",
        "skip-cert-verify",
        "network",
        "ws-opts",
        "grpc-opts",
        "http-upgrade-opts",
        "xhttp-opts",
        "udp",
        "alterId",
        "ipv6",
        "plugin",
        "plugin-opts",
        "private-key",
        "public-key",
        "preshared-key",
        "ip",
        "mtu",
        "reserved",
    ];
    for key in proxy
        .as_object()
        .into_iter()
        .flat_map(|object| object.keys())
    {
        if !CLASH_KEYS.contains(&key.as_str()) {
            ignored.push(key.as_str().into());
        }
    }
    for key in ["alterId", "cipher", "ipv6", "plugin"] {
        if key == "cipher" && protocol == Protocol::Vmess {
            continue;
        }
        if key == "cipher" && protocol == Protocol::Shadowsocks {
            continue;
        }
        if key == "plugin" && protocol == Protocol::Shadowsocks {
            // A plugin the model cannot express is reported, not dropped
            // silently; the plain entry still dials.
        }
        if proxy.get(key).is_some() {
            ignored.push(key.into());
        }
    }
    let profile = ServerProfile::new(name, outbound);
    converted(profile, ignored)
}

fn clash_wireguard(proxy: &Value, ignored: &mut Vec<CompatibilityParameter>) -> WireguardSettings {
    let mut settings = WireguardSettings {
        secret_key: field(proxy, "private-key").into(),
        address: string_list(proxy, "ip"),
        mtu: number(proxy, "mtu").unwrap_or(1420),
        ..Default::default()
    };
    settings.peers.push(WireguardPeer {
        public_key: field(proxy, "public-key").into(),
        pre_shared_key: field(proxy, "preshared-key").into(),
        endpoint: {
            let server = field(proxy, "server");
            let port = number(proxy, "port").unwrap_or_default();
            if server.is_empty() {
                String::new()
            } else {
                crate::model::addr::format_host_port(server, port)
            }
        },
        allowed_ips: string_list(proxy, "allowed-ips"),
        ..Default::default()
    });
    if let Some(reserved) = proxy.get("reserved").and_then(Value::as_array) {
        let bytes: Vec<u8> = reserved
            .iter()
            .filter_map(Value::as_u64)
            .filter_map(|byte| u8::try_from(byte).ok())
            .collect();
        if bytes.len() == 3 {
            settings.reserved = Some(bytes);
        } else {
            ignored.push("reserved".into());
        }
    }
    settings
}

fn clash_stream(
    proxy: &Value,
    protocol: Protocol,
    ignored: &mut Vec<CompatibilityParameter>,
) -> StreamModel {
    let mut stream = StreamModel::default();
    let network = field(proxy, "network").to_ascii_lowercase();
    match network.as_str() {
        "" | "tcp" | "raw" => {}
        "ws" => {
            stream.network = Network::Ws;
            let opts = proxy.get("ws-opts");
            stream.ws_settings = Some(WsSettings {
                path: opts.map_or("", |opts| field(opts, "path")).into(),
                host: opts
                    .and_then(|opts| opts.get("headers"))
                    .map_or("", |headers| field(headers, "Host"))
                    .into(),
                headers: opts
                    .and_then(|opts| opts.get("headers"))
                    .and_then(Value::as_object)
                    .cloned()
                    .unwrap_or_default(),
                ..Default::default()
            });
        }
        "grpc" => {
            stream.network = Network::Grpc;
            let opts = proxy.get("grpc-opts");
            stream.grpc_settings = Some(GrpcSettings {
                service_name: opts
                    .map_or("", |opts| field(opts, "grpc-service-name"))
                    .into(),
                ..Default::default()
            });
        }
        "httpupgrade" => {
            stream.network = Network::Httpupgrade;
            let opts = proxy.get("http-upgrade-opts");
            stream.httpupgrade_settings = Some(HttpupgradeSettings {
                path: opts.map_or("", |opts| field(opts, "path")).into(),
                host: opts.map_or("", |opts| field(opts, "host")).into(),
                ..Default::default()
            });
        }
        "xhttp" | "splithttp" => {
            stream.network = Network::Xhttp;
            let opts = proxy.get("xhttp-opts");
            stream.xhttp_settings = Some(XhttpSettings {
                path: opts.map_or("", |opts| field(opts, "path")).into(),
                host: opts.map_or("", |opts| field(opts, "host")).into(),
                ..Default::default()
            });
        }
        "h2" | "http" => {
            // The pinned core has no HTTP/1.1 or HTTP/2 transport.
            ignored.push(format!("network {network}").into());
        }
        other => ignored.push(format!("network {other}").into()),
    }
    if protocol == Protocol::Hysteria {
        let _ = stream.select_network(Network::Hysteria);
        if let Some(settings) = stream.hysteria_settings.as_mut() {
            settings.auth = field(proxy, "password").into();
        }
    }
    if protocol == Protocol::Masque {
        let _ = stream.select_network(Network::Masque);
    }
    let tls_on = bool_field(proxy, "tls") || proxy.get("reality-opts").is_some();
    if tls_on {
        let server_name = {
            let name = field(proxy, "servername");
            if name.is_empty() {
                field(proxy, "sni").to_owned()
            } else {
                name.to_owned()
            }
        };
        let fingerprint = {
            let fp = field(proxy, "client-fingerprint");
            if fp.is_empty() {
                "chrome".to_owned()
            } else {
                fp.to_owned()
            }
        };
        let reality = proxy.get("reality-opts");
        if let Some(reality) = reality {
            stream.security = Security::Reality;
            stream.reality_settings = Some(RealityModel {
                server_name,
                fingerprint,
                password: field(reality, "public-key").into(),
                short_id: field(reality, "short-id").into(),
                ..Default::default()
            });
        } else {
            stream.security = Security::Tls;
            stream.tls_settings = Some(TlsModel {
                server_name,
                fingerprint,
                alpn: string_list(proxy, "alpn"),
                ..Default::default()
            });
        }
    }
    if proxy.get("skip-cert-verify").is_some() {
        ignored.push("skip-cert-verify".into());
    }
    stream
}

// ---------- sing-box / Xray JSON ----------

fn convert_json_document(document: &Value, batch: &mut ImportBatch) {
    for section in ["inbounds", "routing", "route", "dns", "log"] {
        if document.get(section).is_some() {
            let ordinal = batch.begin_item();
            batch.push_ignored_section(ordinal, section);
        }
    }
    let Some(outbounds) = document.get("outbounds").and_then(Value::as_array) else {
        return;
    };
    for outbound in outbounds {
        let ordinal = batch.begin_item();
        let raw = bound(outbound);
        if let Some(protocol) = outbound.get("protocol").and_then(Value::as_str) {
            // Xray outbound object: the persisted model is the same shape.
            let protocol = protocol.to_ascii_lowercase();
            if matches!(protocol.as_str(), "freedom" | "blackhole" | "dns") {
                let name = outbound
                    .get("tag")
                    .and_then(Value::as_str)
                    .unwrap_or(&protocol);
                batch.push_ignored_section(ordinal, name);
                continue;
            }
            if UNDIALABLE.contains(&protocol.as_str()) {
                batch.push_refused(
                    ordinal,
                    "",
                    malformed_reason(Diag::new(Key::LinkEntryUnsupportedProtocol).arg(&protocol)),
                    raw,
                );
                continue;
            }
            match serde_json::from_value::<OutboundModel>(outbound.clone()) {
                Ok(mut model) => {
                    // The document grammar has no `encryption` key: the wire
                    // default `none` is the model value the link grammar
                    // writes, so a stored profile validates and exports.
                    if let ProtocolSettings::Vless(settings) = &mut model.settings
                        && settings.encryption.is_empty()
                    {
                        settings.encryption = "none".into();
                    }
                    let name = profile_name(outbound, &model);
                    let profile = ServerProfile::new(name, model);
                    match super::validate_profile(&profile) {
                        Ok(()) => batch.push_accepted(ordinal, profile, raw, Vec::new()),
                        Err(error) => {
                            batch.push_refused(ordinal, "", ImportReason::link(error), raw);
                        }
                    }
                }
                Err(error) => batch.push_refused(
                    ordinal,
                    "",
                    malformed_reason(Diag::new(Key::LinkEntryJsonInvalid).arg(error.to_string())),
                    raw,
                ),
            }
            continue;
        }
        let ty = field(outbound, "type").to_ascii_lowercase();
        if ty.is_empty() {
            batch.push_ignored_section(ordinal, field(outbound, "tag"));
            continue;
        }
        match sing_box_entry(outbound) {
            Ok(mut entry) => {
                for parameter in &mut entry.ignored {
                    parameter.raw.clone_from(&raw);
                }
                batch.push_accepted(ordinal, entry.profile, raw, entry.ignored);
            }
            Err(Refusal::Ignored(name)) => batch.push_ignored_section(ordinal, name),
            Err(Refusal::Refused(reason)) => batch.push_refused(ordinal, "", reason, raw),
        }
    }
}

fn profile_name(outbound: &Value, model: &OutboundModel) -> String {
    let name = field(outbound, "tag").trim();
    if !name.is_empty() {
        return name.to_owned();
    }
    model
        .settings
        .server_address()
        .unwrap_or_else(|| "server".into())
}

fn sing_box_entry(outbound: &Value) -> Result<Converted, Refusal> {
    let ty = field(outbound, "type").to_ascii_lowercase();
    if UNDIALABLE.contains(&ty.as_str()) {
        return Err(Refusal::refused(malformed_reason(
            Diag::new(Key::LinkEntryUnsupportedProtocol).arg(&ty),
        )));
    }
    if !DIALABLE.contains(&ty.as_str()) {
        let name = field(outbound, "tag");
        return Err(Refusal::ignored(if name.is_empty() {
            format!("{ty} entry")
        } else {
            name.to_owned()
        }));
    }
    let server = field(outbound, "server").trim();
    let port = number(outbound, "server_port").unwrap_or_default();
    if server.is_empty() || port == 0 {
        return Err(Refusal::refused(malformed_reason(Diag::new(
            Key::LinkEntryMissingEndpoint,
        ))));
    }
    let name = field(outbound, "tag").trim().to_owned();
    let name = if name.is_empty() {
        format!("{server}:{port}")
    } else {
        name
    };
    let mut ignored = Vec::new();
    let protocol = match ty.as_str() {
        "vless" => Protocol::Vless,
        "vmess" => Protocol::Vmess,
        "trojan" => Protocol::Trojan,
        "shadowsocks" => Protocol::Shadowsocks,
        "socks" => Protocol::Socks,
        "http" => Protocol::Http,
        "wireguard" => Protocol::Wireguard,
        "hysteria2" | "hy2" => Protocol::Hysteria,
        "hysteria" => {
            return Err(Refusal::refused(malformed_reason(Diag::new(
                Key::LinkUnsupportedHysteria1,
            ))));
        }
        "masque" => Protocol::Masque,
        other => {
            return Err(Refusal::refused(malformed_reason(
                Diag::new(Key::LinkEntryUnsupportedProtocol).arg(other),
            )));
        }
    };
    require_credentials(outbound, protocol, "uuid", "password")?;
    let mut outbound_model = OutboundModel::new(protocol);
    outbound_model.settings = match protocol {
        Protocol::Vless => ProtocolSettings::Vless(VlessSettings {
            address: server.into(),
            port,
            id: field(outbound, "uuid").into(),
            flow: field(outbound, "flow").into(),
            encryption: "none".into(),
            ..Default::default()
        }),
        Protocol::Vmess => ProtocolSettings::Vmess(VmessSettings {
            address: server.into(),
            port,
            id: field(outbound, "uuid").into(),
            security: field(outbound, "security").into(),
            ..Default::default()
        }),
        Protocol::Trojan => ProtocolSettings::Trojan(TrojanSettings {
            address: server.into(),
            port,
            password: field(outbound, "password").into(),
            ..Default::default()
        }),
        Protocol::Shadowsocks => ProtocolSettings::Shadowsocks(ShadowsocksSettings {
            address: server.into(),
            port,
            method: field(outbound, "method").into(),
            password: field(outbound, "password").into(),
            ..Default::default()
        }),
        Protocol::Socks => ProtocolSettings::Socks(SocksSettings {
            address: server.into(),
            port,
            user: field(outbound, "username").into(),
            pass: field(outbound, "password").into(),
            ..Default::default()
        }),
        Protocol::Http => ProtocolSettings::Http(HttpSettings {
            address: server.into(),
            port,
            user: field(outbound, "username").into(),
            pass: field(outbound, "password").into(),
            ..Default::default()
        }),
        Protocol::Wireguard => ProtocolSettings::Wireguard(sing_box_wireguard(outbound)),
        Protocol::Hysteria => ProtocolSettings::Hysteria(HysteriaSettings {
            address: server.into(),
            port,
            ..Default::default()
        }),
        Protocol::Masque => ProtocolSettings::Masque(MasqueSettings {
            address: server.into(),
            port,
            ..Default::default()
        }),
        _ => {
            return Err(Refusal::refused(malformed_reason(
                Diag::new(Key::LinkEntryUnsupportedProtocol).arg(protocol.as_str()),
            )));
        }
    };
    const SING_BOX_KEYS: &[&str] = &[
        "type",
        "tag",
        "server",
        "server_port",
        "uuid",
        "password",
        "security",
        "method",
        "username",
        "flow",
        "tls",
        "transport",
        "private_key",
        "peer_public_key",
        "pre_shared_key",
        "local_address",
        "allowed_ips",
        "mtu",
        "reserved",
        "multiplex",
        "udp",
        "packet_encoding",
        "domain_strategy",
    ];
    for key in outbound
        .as_object()
        .into_iter()
        .flat_map(|object| object.keys())
    {
        if !SING_BOX_KEYS.contains(&key.as_str()) {
            ignored.push(key.as_str().into());
        }
    }
    for key in ["multiplex", "udp", "packet_encoding", "domain_strategy"] {
        if outbound.get(key).is_some() {
            ignored.push(key.into());
        }
    }
    outbound_model.stream = sing_box_stream(outbound, protocol, &mut ignored);
    converted(ServerProfile::new(name, outbound_model), ignored)
}

fn sing_box_wireguard(outbound: &Value) -> WireguardSettings {
    let mut settings = WireguardSettings {
        secret_key: field(outbound, "private_key").into(),
        address: string_list(outbound, "local_address"),
        mtu: number(outbound, "mtu").unwrap_or(1420),
        ..Default::default()
    };
    settings.peers.push(WireguardPeer {
        public_key: field(outbound, "peer_public_key").into(),
        pre_shared_key: field(outbound, "pre_shared_key").into(),
        endpoint: {
            let server = field(outbound, "server");
            let port = number(outbound, "server_port").unwrap_or_default();
            crate::model::addr::format_host_port(server, port)
        },
        allowed_ips: string_list(outbound, "allowed_ips"),
        ..Default::default()
    });
    if let Some(reserved) = outbound.get("reserved").and_then(Value::as_array) {
        let bytes: Vec<u8> = reserved
            .iter()
            .filter_map(Value::as_u64)
            .filter_map(|byte| u8::try_from(byte).ok())
            .collect();
        if bytes.len() == 3 {
            settings.reserved = Some(bytes);
        }
    }
    settings
}

fn sing_box_stream(
    outbound: &Value,
    protocol: Protocol,
    ignored: &mut Vec<CompatibilityParameter>,
) -> StreamModel {
    let mut stream = StreamModel::default();
    if let Some(transport) = outbound.get("transport") {
        let ty = field(transport, "type").to_ascii_lowercase();
        match ty.as_str() {
            "ws" => {
                stream.network = Network::Ws;
                stream.ws_settings = Some(WsSettings {
                    path: field(transport, "path").into(),
                    host: transport
                        .get("headers")
                        .map_or("", |headers| field(headers, "Host"))
                        .into(),
                    headers: transport
                        .get("headers")
                        .and_then(Value::as_object)
                        .cloned()
                        .unwrap_or_default(),
                    ..Default::default()
                });
            }
            "grpc" => {
                stream.network = Network::Grpc;
                stream.grpc_settings = Some(GrpcSettings {
                    service_name: field(transport, "service_name").into(),
                    ..Default::default()
                });
            }
            "httpupgrade" => {
                stream.network = Network::Httpupgrade;
                stream.httpupgrade_settings = Some(HttpupgradeSettings {
                    path: field(transport, "path").into(),
                    host: transport
                        .get("headers")
                        .map_or("", |headers| field(headers, "Host"))
                        .into(),
                    ..Default::default()
                });
            }
            "xhttp" | "splithttp" => {
                stream.network = Network::Xhttp;
                stream.xhttp_settings = Some(XhttpSettings {
                    path: field(transport, "path").into(),
                    host: field(transport, "host").into(),
                    ..Default::default()
                });
            }
            "http" | "h2" => ignored.push(format!("transport {ty}").into()),
            _ if ty.is_empty() => {}
            other => ignored.push(format!("transport {other}").into()),
        }
    }
    if protocol == Protocol::Hysteria {
        let _ = stream.select_network(Network::Hysteria);
        if let Some(settings) = stream.hysteria_settings.as_mut() {
            settings.auth = field(outbound, "password").into();
        }
    }
    if protocol == Protocol::Masque {
        let _ = stream.select_network(Network::Masque);
    }
    if let Some(tls) = outbound.get("tls")
        && bool_field(tls, "enabled")
    {
        let server_name = field(tls, "server_name");
        let fingerprint = {
            let fp = tls
                .get("utls")
                .map_or("", |utls| field(utls, "fingerprint"));
            if fp.is_empty() {
                "chrome".to_owned()
            } else {
                fp.to_owned()
            }
        };
        let reality = tls
            .get("reality")
            .filter(|value| bool_field(value, "enabled"));
        if let Some(reality) = reality {
            stream.security = Security::Reality;
            stream.reality_settings = Some(RealityModel {
                server_name: server_name.into(),
                fingerprint,
                password: field(reality, "public_key").into(),
                short_id: field(reality, "short_id").into(),
                ..Default::default()
            });
        } else {
            stream.security = Security::Tls;
            stream.tls_settings = Some(TlsModel {
                server_name: server_name.into(),
                fingerprint,
                alpn: string_list(tls, "alpn"),
                ..Default::default()
            });
        }
        if bool_field(tls, "insecure") {
            ignored.push("tls.insecure".into());
        }
    }
    stream
}

// ---------- SIP008 ----------

fn convert_sip008(document: &Value, batch: &mut ImportBatch) {
    let Some(servers) = document.get("servers").and_then(Value::as_array) else {
        return;
    };
    for server in servers {
        let ordinal = batch.begin_item();
        let raw = bound(server);
        let address = field(server, "server").trim().to_owned();
        let port = number(server, "server_port").unwrap_or_default();
        let method = field(server, "method").to_owned();
        let password = field(server, "password").to_owned();
        if address.is_empty() || port == 0 || method.is_empty() {
            batch.push_refused(
                ordinal,
                "",
                malformed_reason(Diag::new(Key::LinkEntrySip008Incomplete)),
                raw,
            );
            continue;
        }
        let remarks = field(server, "remarks").trim();
        let name = if remarks.is_empty() {
            format!("{address}:{port}")
        } else {
            remarks.to_owned()
        };
        let mut outbound = OutboundModel::new(Protocol::Shadowsocks);
        outbound.settings = ProtocolSettings::Shadowsocks(ShadowsocksSettings {
            address,
            port,
            method,
            password,
            ..Default::default()
        });
        let profile = ServerProfile::new(name, outbound);
        match super::validate_profile(&profile) {
            Ok(()) => batch.push_accepted(ordinal, profile, raw, Vec::new()),
            Err(error) => batch.push_refused(ordinal, "", ImportReason::link(error), raw),
        }
    }
}

// ---------- WireGuard configuration ----------

fn convert_wireguard_conf(text: &str, batch: &mut ImportBatch) {
    let ordinal = batch.begin_item();
    let mut section = String::new();
    let mut interface: BTreeMap<String, String> = BTreeMap::new();
    let mut peer: BTreeMap<String, String> = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            section = line.trim_matches(['[', ']']).to_ascii_lowercase();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim().to_owned();
        match section.as_str() {
            "interface" => {
                interface.insert(key, value);
            }
            "peer" => {
                peer.insert(key, value);
            }
            _ => {}
        }
    }
    if interface.is_empty() && peer.is_empty() {
        batch.push_ignored_section(ordinal, "wireguard");
        return;
    }
    let private = interface.get("privatekey").cloned().unwrap_or_default();
    let public = peer.get("publickey").cloned().unwrap_or_default();
    if private.trim().is_empty() || public.trim().is_empty() {
        batch.push_refused(
            ordinal,
            "",
            malformed_reason(Diag::new(Key::LinkEntryMissingCredentials)),
            bound_text(text),
        );
        return;
    }
    let server = peer.get("endpoint").cloned().unwrap_or_default();
    let name = if server.is_empty() {
        "wireguard".to_owned()
    } else {
        server.clone()
    };
    let mut ignored: Vec<CompatibilityParameter> = Vec::new();
    let mut settings = WireguardSettings {
        secret_key: private,
        address: split_list(interface.get("address")),
        mtu: interface
            .get("mtu")
            .and_then(|mtu| mtu.parse().ok())
            .unwrap_or(1420),
        remote_dns: split_list(interface.get("dns")),
        ..Default::default()
    };
    settings.peers.push(WireguardPeer {
        public_key: public,
        pre_shared_key: peer.get("presharedkey").cloned().unwrap_or_default(),
        endpoint: server,
        allowed_ips: split_list(peer.get("allowedips")),
        keep_alive: peer
            .get("persistentkeepalive")
            .and_then(|value| value.parse().ok()),
        ..Default::default()
    });
    let mut outbound = OutboundModel::new(Protocol::Wireguard);
    outbound.settings = ProtocolSettings::Wireguard(settings);
    outbound.stream = StreamModel::default();
    if let Some(table) = interface.get("table") {
        ignored.push(format!("Table {table}").into());
    }
    let raw = bound_text(text);
    for parameter in &mut ignored {
        parameter.raw.clone_from(&raw);
    }
    let profile = ServerProfile::new(name, outbound);
    match super::validate_profile(&profile) {
        Ok(()) => batch.push_accepted(ordinal, profile, raw, ignored),
        Err(error) => batch.push_refused(ordinal, "", ImportReason::link(error), raw),
    }
}

// ---------- Hysteria 2 YAML ----------

fn convert_hysteria2(document: &Value, batch: &mut ImportBatch) {
    let ordinal = batch.begin_item();
    let server = field(document, "server").trim();
    let port = number(document, "port").unwrap_or(443);
    if server.is_empty() {
        batch.push_refused(
            ordinal,
            "",
            malformed_reason(Diag::new(Key::LinkEntryMissingServer)),
            bound(document),
        );
        return;
    }
    let name = {
        let name = field(document, "name").trim();
        if name.is_empty() {
            format!("{server}:{port}")
        } else {
            name.to_owned()
        }
    };
    let mut ignored: Vec<CompatibilityParameter> = Vec::new();
    for key in ["obfs", "fastOpen", "lazy"] {
        if document.get(key).is_some() {
            ignored.push(key.into());
        }
    }
    let bandwidth = |key: &str| -> String {
        let value = match document.get(key) {
            Some(Value::String(text)) => text.trim().to_owned(),
            Some(Value::Number(number)) => number.to_string(),
            _ => String::new(),
        };
        if value.is_empty() {
            String::new()
        } else if value
            .chars()
            .all(|character| character.is_ascii_digit() || character == '.')
        {
            format!("{value} mbps")
        } else {
            value
        }
    };
    let brutal_up = bandwidth("up");
    let brutal_down = bandwidth("down");
    let mut outbound = OutboundModel::new(Protocol::Hysteria);
    outbound.settings = ProtocolSettings::Hysteria(HysteriaSettings {
        address: server.into(),
        port,
        ..Default::default()
    });
    let mut stream = StreamModel {
        network: Network::Hysteria,
        hysteria_settings: Some(HysteriaTransport {
            version: 2,
            auth: field(document, "auth").into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let tls = document.get("tls").unwrap_or(document);
    let sni = {
        let name = field(tls, "sni");
        if name.is_empty() {
            field(document, "sni").to_owned()
        } else {
            name.to_owned()
        }
    };
    if !brutal_up.is_empty() || !brutal_down.is_empty() {
        stream.finalmask = Some(crate::model::stream::FinalmaskModel {
            quic_params: Some(crate::model::stream::FinalmaskQuicParams {
                congestion: "brutal".into(),
                brutal_up,
                brutal_down,
                ..Default::default()
            }),
            ..Default::default()
        });
    }
    stream.security = Security::Tls;
    stream.tls_settings = Some(TlsModel {
        server_name: sni,
        alpn: string_list(tls, "alpn"),
        ..Default::default()
    });
    if bool_field(document, "skip-cert-verify") {
        ignored.push("skip-cert-verify".into());
    }
    let raw = bound(document);
    for parameter in &mut ignored {
        parameter.raw.clone_from(&raw);
    }
    outbound.stream = stream;
    let profile = ServerProfile::new(name, outbound);
    match super::validate_profile(&profile) {
        Ok(()) => batch.push_accepted(ordinal, profile, raw, ignored),
        Err(error) => batch.push_refused(ordinal, "", ImportReason::link(error), raw),
    }
}

/// Refuse an entry whose credentials are required but empty. `uuid_key` and
/// `password_key` name the document's fields.
fn require_credentials(
    value: &Value,
    protocol: Protocol,
    uuid_key: &str,
    password_key: &str,
) -> Result<(), Refusal> {
    let missing = match protocol {
        Protocol::Vless | Protocol::Vmess => field(value, uuid_key).trim().is_empty(),
        Protocol::Trojan => field(value, password_key).trim().is_empty(),
        Protocol::Shadowsocks => {
            let method_missing = field(value, "method").trim().is_empty()
                && field(value, "cipher").trim().is_empty();
            method_missing || field(value, "password").trim().is_empty()
        }
        Protocol::Wireguard => {
            let private = field(value, "private-key").trim().is_empty()
                && field(value, "private_key").trim().is_empty();
            let public = field(value, "public-key").trim().is_empty()
                && field(value, "public_key").trim().is_empty();
            private || public
        }
        _ => false,
    };
    if missing {
        Err(Refusal::refused(malformed_reason(Diag::new(
            Key::LinkEntryMissingCredentials,
        ))))
    } else {
        Ok(())
    }
}

// ---------- helpers ----------

fn field<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn number(value: &Value, key: &str) -> Option<u16> {
    value.get(key).and_then(|value| {
        value
            .as_u64()
            .and_then(|number| u16::try_from(number).ok())
            .or_else(|| {
                value
                    .as_str()
                    .and_then(|text| text.trim().parse::<u16>().ok())
            })
    })
}

fn bool_field(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn string_list(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .map(|value| match value {
            Value::Array(items) => items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
            Value::String(text) => vec![text.clone()],
            _ => Vec::new(),
        })
        .unwrap_or_default()
}

fn split_list(value: Option<&String>) -> Vec<String> {
    value
        .map(|text| {
            text.split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn bound(value: &Value) -> String {
    serde_json::to_string(value)
        .unwrap_or_default()
        .chars()
        .take(super::body::MAX_RAW_CHARS)
        .collect()
}

/// The bounded copy of a source document's text.
fn bound_text(text: &str) -> String {
    text.chars().take(super::body::MAX_RAW_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::settings::Language;

    fn convert(text: &str) -> ImportBatch {
        let mut batch = ImportBatch::default();
        assert!(convert_document(text, &mut batch), "document was claimed");
        batch
    }

    fn profiles(batch: &ImportBatch) -> Vec<&ServerProfile> {
        batch
            .entries()
            .into_iter()
            .map(|entry| entry.profile)
            .collect()
    }

    #[test]
    fn clash_proxies_convert_and_undialable_entries_are_refused() {
        let document = r#"
proxies:
  - name: "Tokyo"
    type: vless
    server: tokyo.example.com
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    tls: true
    servername: example.com
    network: ws
    ws-opts:
      path: /ws
  - name: "Cap"
    type: tuic
    server: tuic.example.com
    port: 443
rules:
  - MATCH,DIRECT
"#;
        let batch = convert(document);
        let refused: Vec<String> = batch
            .refused()
            .filter_map(|record| record.reason())
            .map(|reason| reason.text(Language::En))
            .collect();
        let profiles = profiles(&batch);
        assert_eq!(profiles.len(), 1, "refused: {refused:?}");
        assert_eq!(profiles[0].outbound.stream.network, Network::Ws);
        assert_eq!(batch.refused().count(), 1);
        assert_eq!(batch.ignored().count(), 1);
        let refusal = batch.refused().next().expect("one refused entry");
        let reason = refusal.reason().expect("a refused record carries a reason");
        assert!(reason.text(Language::En).contains("tuic"));
    }

    #[test]
    fn clash_hysteria2_entries_carry_tls() {
        let document = r#"
proxies:
  - name: "HY"
    type: hysteria2
    server: hy.example.com
    port: 443
    password: secret
"#;
        let batch = convert(document);
        let profiles = profiles(&batch);
        assert_eq!(profiles[0].outbound.stream.network, Network::Hysteria);
        assert_eq!(profiles[0].outbound.stream.security, Security::Tls);
    }

    #[test]
    fn entries_missing_required_credentials_are_refused() {
        let clash = r#"
proxies:
  - name: "NoId"
    type: vless
    server: v.example.com
    port: 443
"#;
        let batch = convert(clash);
        assert_eq!(batch.entries().len(), 0);
        assert_eq!(batch.refused().count(), 1);

        let json = r#"{"outbounds":[{"type":"trojan","tag":"NoPass","server":"t.example.com","server_port":443}]}"#;
        let batch = convert(json);
        assert_eq!(batch.entries().len(), 0);
        assert_eq!(batch.refused().count(), 1);
    }

    #[test]
    fn hysteria1_is_refused_and_hysteria2_bandwidth_maps() {
        let v1 = r#"{"outbounds":[{"type":"hysteria","tag":"H1","server":"h.example.com","server_port":443}]}"#;
        let batch = convert(v1);
        assert_eq!(batch.entries().len(), 0);
        assert_eq!(batch.refused().count(), 1);

        let v2 = "server: h.example.com\nport: 443\nauth: secret\nup: 100\ndown: 50\n";
        let batch = convert(v2);
        let profiles = profiles(&batch);
        let quic = profiles[0]
            .outbound
            .stream
            .finalmask
            .as_ref()
            .and_then(|mask| mask.quic_params.as_ref());
        let quic = quic.expect("bandwidth maps to quicParams");
        assert_eq!(quic.brutal_up, "100 mbps");
        assert_eq!(quic.brutal_down, "50 mbps");
    }

    #[test]
    fn unknown_document_fields_are_reported() {
        let document = r#"
proxies:
  - name: "Future"
    type: ss
    server: s.example.com
    port: 8388
    cipher: aes-128-gcm
    password: pw
    some-future-key: 1
"#;
        let batch = convert(document);
        let dropped: Vec<&CompatibilityParameter> = batch
            .ignored()
            .filter_map(|record| record.parameter())
            .collect();
        assert!(
            dropped
                .iter()
                .any(|parameter| parameter.name == "some-future-key")
        );
        assert!(
            dropped.iter().all(|parameter| !parameter.raw.is_empty()
                && parameter.raw.chars().count() <= super::super::body::MAX_RAW_CHARS),
            "a document parameter still points at its bounded source: {dropped:?}"
        );
        let json = r#"{"outbounds":[{"type":"socks","tag":"S","server":"s.example.com","server_port":1080,"future_field":true}]}"#;
        let batch = convert(json);
        assert!(
            batch
                .ignored()
                .filter_map(|record| record.parameter())
                .any(|parameter| parameter.name == "future_field")
        );
    }

    #[test]
    fn sip008_servers_convert() {
        let document = r#"{"version":1,"servers":[
            {"server":"ss.example.com","server_port":8388,"method":"aes-128-gcm","password":"pw","remarks":"SS"}
        ]}"#;
        let batch = convert(document);
        let profiles = profiles(&batch);
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "SS");
    }

    #[test]
    fn sing_box_json_outbounds_convert_and_routing_is_ignored() {
        let document = r#"{"outbounds":[
            {"type":"vless","tag":"SB","server":"sb.example.com","server_port":443,
             "uuid":"11111111-2222-3333-4444-555555555555",
             "tls":{"enabled":true,"server_name":"example.com","utls":{"fingerprint":"chrome"}},
             "transport":{"type":"ws","path":"/ws"}}
        ],"route":{"rules":[]},"inbounds":[]}"#;
        let batch = convert(document);
        let profiles = profiles(&batch);
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "SB");
        assert_eq!(profiles[0].outbound.stream.network, Network::Ws);
        assert_eq!(profiles[0].outbound.stream.security, Security::Tls);
        assert_eq!(batch.ignored().count(), 2);
    }

    #[test]
    fn xray_json_outbounds_convert() {
        let document = r#"{"outbounds":[
            {"protocol":"vless","tag":"Xray","settings":{"address":"x.example.com","port":443,
             "id":"11111111-2222-3333-4444-555555555555"},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com"}}},
            {"protocol":"freedom","tag":"direct"}
        ]}"#;
        let batch = convert(document);
        let profiles = profiles(&batch);
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "Xray");
        assert_eq!(batch.ignored().count(), 1);
    }

    #[test]
    fn hysteria2_yaml_converts() {
        let document = "server: hy.example.com\nport: 443\nauth: secret\nsni: example.com\nskip-cert-verify: true\n";
        let batch = convert(document);
        let profiles = profiles(&batch);
        assert_eq!(profiles.len(), 1);
        let profile = profiles[0];
        assert_eq!(profile.outbound.stream.network, Network::Hysteria);
        assert_eq!(
            profile
                .outbound
                .stream
                .hysteria_settings
                .as_ref()
                .map(|settings| settings.auth.as_str()),
            Some("secret")
        );
    }

    #[test]
    fn undialable_json_protocols_are_refused_with_raw_text() {
        let document = r#"{"outbounds":[{"type":"tuic","tag":"T","server":"t.example.com","server_port":443}]}"#;
        let batch = convert(document);
        assert_eq!(batch.entries().len(), 0);
        assert_eq!(batch.refused().count(), 1);
        assert!(
            batch
                .refused()
                .next()
                .expect("one refusal")
                .raw()
                .contains("tuic")
        );
    }

    #[test]
    fn wireguard_configuration_converts() {
        let document = "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.0.0.2/32\nMTU = 1280\n\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = wg.example.com:51820\nAllowedIPs = 0.0.0.0/0\n";
        let batch = convert(document);
        let profiles = profiles(&batch);
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "wg.example.com:51820");
    }
}
