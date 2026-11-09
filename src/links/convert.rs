//! Document converters: Clash YAML, sing-box/Xray JSON, SIP008, WireGuard and
//! Hysteria 2 YAML in, server profiles out.
//!
//! Every converter follows the share-link importer's contract: a field the
//! persisted model cannot express is dropped and named as a compatibility
//! parameter; an entry is refused only when its protocol cannot be dialed by
//! the pinned core or a required field is missing. Non-server document
//! sections are ignored and named for the report.

use super::body::{BodyEntry, BodyRefusal, CompatibilityParameter, IgnoredSection};
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

/// One converter's outcome.
#[derive(Debug, Clone, Default)]
pub struct ConvertOutcome {
    pub entries: Vec<BodyEntry>,
    pub refused: Vec<BodyRefusal>,
    pub ignored: Vec<IgnoredSection>,
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

/// Convert `text` when it is a document shape; `None` leaves it to the link
/// pipeline.
pub fn convert_document(text: &str) -> Option<ConvertOutcome> {
    let trimmed = text.trim_start();
    if (trimmed.starts_with('{') || trimmed.starts_with('['))
        && let Ok(value) = serde_json::from_str::<Value>(text)
    {
        if value.get("outbounds").and_then(Value::as_array).is_some() {
            return Some(convert_json_document(&value));
        }
        if value.get("servers").and_then(Value::as_array).is_some() {
            return Some(convert_sip008(&value));
        }
    }
    if let Ok(value) = serde_saphyr::from_str::<Value>(text) {
        if value.get("proxies").and_then(Value::as_array).is_some() {
            return Some(convert_clash(&value));
        }
        if value.get("inbounds").is_none()
            && value.get("outbounds").is_none()
            && value.get("server").is_some()
        {
            return Some(convert_hysteria2(&value));
        }
    }
    if trimmed.contains("[Interface]") || trimmed.contains("[Peer]") {
        return Some(convert_wireguard_conf(text));
    }
    None
}

// ---------- Clash ----------

fn convert_clash(document: &Value) -> ConvertOutcome {
    let mut outcome = ConvertOutcome::default();
    for section in ["rules", "proxy-groups", "dns"] {
        if document.get(section).is_some() {
            outcome.ignored.push(IgnoredSection::section(section));
        }
    }
    let Some(proxies) = document.get("proxies").and_then(Value::as_array) else {
        return outcome;
    };
    for proxy in proxies {
        let raw = bound(proxy);
        match clash_entry(proxy) {
            Ok(mut entry) => {
                for parameter in &mut entry.ignored {
                    parameter.raw.clone_from(&raw);
                }
                outcome.entries.push(entry);
            }
            Err(Refusal { error, ignored }) if error.is_empty() => {
                // Non-server entry (a selector, a group reference).
                outcome.ignored.push(IgnoredSection::section(ignored));
            }
            Err(Refusal { error, .. }) => outcome.refused.push(BodyRefusal { raw, error }),
        }
    }
    outcome
}

struct Refusal {
    error: String,
    ignored: String,
}

impl Refusal {
    fn refused(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            ignored: String::new(),
        }
    }
    fn ignored(name: impl Into<String>) -> Self {
        Self {
            error: String::new(),
            ignored: name.into(),
        }
    }
}

fn clash_entry(proxy: &Value) -> Result<BodyEntry, Refusal> {
    let ty = field(proxy, "type").to_ascii_lowercase();
    if UNDIALABLE.contains(&ty.as_str()) {
        return Err(Refusal::refused(format!("unsupported protocol {ty}")));
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
            return Err(Refusal::refused(
                "Hysteria 1 is not dialable; use Hysteria 2".to_owned(),
            ));
        }
        "masque" => Protocol::Masque,
        other => return Err(Refusal::refused(format!("unsupported protocol {other}"))),
    };
    let server = field(proxy, "server").trim();
    let port = number(proxy, "port").unwrap_or_default();
    if server.is_empty() || port == 0 {
        return Err(Refusal::refused("missing server or port"));
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
        _ => return Err(Refusal::refused("unsupported protocol")),
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
    Ok(BodyEntry {
        profile,
        raw: String::new(),
        ignored,
    })
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

fn convert_json_document(document: &Value) -> ConvertOutcome {
    let mut outcome = ConvertOutcome::default();
    for section in ["inbounds", "routing", "route", "dns", "log"] {
        if document.get(section).is_some() {
            outcome.ignored.push(IgnoredSection::section(section));
        }
    }
    let Some(outbounds) = document.get("outbounds").and_then(Value::as_array) else {
        return outcome;
    };
    for outbound in outbounds {
        let raw = bound(outbound);
        if let Some(protocol) = outbound.get("protocol").and_then(Value::as_str) {
            // Xray outbound object: the persisted model is the same shape.
            let protocol = protocol.to_ascii_lowercase();
            if matches!(protocol.as_str(), "freedom" | "blackhole" | "dns") {
                let name = outbound
                    .get("tag")
                    .and_then(Value::as_str)
                    .unwrap_or(&protocol);
                outcome.ignored.push(IgnoredSection::section(name));
                continue;
            }
            if UNDIALABLE.contains(&protocol.as_str()) {
                outcome.refused.push(BodyRefusal {
                    raw,
                    error: format!("unsupported protocol {protocol}"),
                });
                continue;
            }
            match serde_json::from_value::<OutboundModel>(outbound.clone()) {
                Ok(model) => {
                    let name = profile_name(outbound, &model);
                    outcome.entries.push(BodyEntry {
                        profile: ServerProfile::new(name, model),
                        raw,
                        ignored: Vec::new(),
                    });
                }
                Err(error) => outcome.refused.push(BodyRefusal {
                    raw,
                    error: error.to_string(),
                }),
            }
            continue;
        }
        let ty = field(outbound, "type").to_ascii_lowercase();
        if ty.is_empty() {
            outcome
                .ignored
                .push(IgnoredSection::section(field(outbound, "tag")));
            continue;
        }
        match sing_box_entry(outbound) {
            Ok(mut entry) => {
                for parameter in &mut entry.ignored {
                    parameter.raw.clone_from(&raw);
                }
                outcome.entries.push(entry);
            }
            Err(Refusal { error, ignored }) if error.is_empty() => {
                outcome.ignored.push(IgnoredSection::section(ignored));
            }
            Err(Refusal { error, .. }) => outcome.refused.push(BodyRefusal { raw, error }),
        }
    }
    outcome
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

fn sing_box_entry(outbound: &Value) -> Result<BodyEntry, Refusal> {
    let ty = field(outbound, "type").to_ascii_lowercase();
    if UNDIALABLE.contains(&ty.as_str()) {
        return Err(Refusal::refused(format!("unsupported protocol {ty}")));
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
        return Err(Refusal::refused("missing server or port"));
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
            return Err(Refusal::refused(
                "Hysteria 1 is not dialable; use Hysteria 2".to_owned(),
            ));
        }
        "masque" => Protocol::Masque,
        other => return Err(Refusal::refused(format!("unsupported protocol {other}"))),
    };
    require_credentials(outbound, protocol, "uuid", "password")?;
    let mut outbound_model = OutboundModel::new(protocol);
    outbound_model.settings = match protocol {
        Protocol::Vless => ProtocolSettings::Vless(VlessSettings {
            address: server.into(),
            port,
            id: field(outbound, "uuid").into(),
            flow: field(outbound, "flow").into(),
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
        _ => return Err(Refusal::refused("unsupported protocol")),
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
    Ok(BodyEntry {
        profile: ServerProfile::new(name, outbound_model),
        raw: String::new(),
        ignored,
    })
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

fn convert_sip008(document: &Value) -> ConvertOutcome {
    let mut outcome = ConvertOutcome::default();
    let Some(servers) = document.get("servers").and_then(Value::as_array) else {
        return outcome;
    };
    for server in servers {
        let raw = bound(server);
        let address = field(server, "server").trim().to_owned();
        let port = number(server, "server_port").unwrap_or_default();
        let method = field(server, "method").to_owned();
        let password = field(server, "password").to_owned();
        if address.is_empty() || port == 0 || method.is_empty() {
            outcome.refused.push(BodyRefusal {
                raw,
                error: "missing server, port or method".into(),
            });
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
        outcome.entries.push(BodyEntry {
            profile: ServerProfile::new(name, outbound),
            raw,
            ignored: Vec::new(),
        });
    }
    outcome
}

// ---------- WireGuard configuration ----------

fn convert_wireguard_conf(text: &str) -> ConvertOutcome {
    let mut outcome = ConvertOutcome::default();
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
        outcome.ignored.push(IgnoredSection::section("wireguard"));
        return outcome;
    }
    let private = interface.get("privatekey").cloned().unwrap_or_default();
    let public = peer.get("publickey").cloned().unwrap_or_default();
    if private.trim().is_empty() || public.trim().is_empty() {
        outcome.refused.push(BodyRefusal {
            raw: text.chars().take(super::body::MAX_RAW_CHARS).collect(),
            error: "missing required credentials".into(),
        });
        return outcome;
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
    let raw: String = text.chars().take(super::body::MAX_RAW_CHARS).collect();
    for parameter in &mut ignored {
        parameter.raw.clone_from(&raw);
    }
    outcome.entries.push(BodyEntry {
        profile: ServerProfile::new(name, outbound),
        raw: String::new(),
        ignored,
    });
    outcome
}

// ---------- Hysteria 2 YAML ----------

fn convert_hysteria2(document: &Value) -> ConvertOutcome {
    let mut outcome = ConvertOutcome::default();
    let server = field(document, "server").trim();
    let port = number(document, "port").unwrap_or(443);
    if server.is_empty() {
        outcome.refused.push(BodyRefusal {
            raw: bound(document),
            error: "missing server".into(),
        });
        return outcome;
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
    outcome.entries.push(BodyEntry {
        profile: ServerProfile::new(name, outbound),
        raw: String::new(),
        ignored,
    });
    outcome
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
        Err(Refusal::refused("missing required credentials"))
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

use std::collections::BTreeMap;

#[cfg(test)]
mod tests {
    use super::*;

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
        let outcome = convert_document(document).expect("clash document");
        assert_eq!(outcome.entries.len(), 1);
        assert_eq!(outcome.entries[0].profile.name, "Tokyo");
        assert_eq!(
            outcome.entries[0].profile.outbound.stream.network,
            Network::Ws
        );
        assert_eq!(outcome.refused.len(), 1);
        assert_eq!(outcome.ignored.len(), 1);
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
        let outcome = convert_document(document).expect("clash");
        let profile = &outcome.entries[0].profile;
        assert_eq!(profile.outbound.stream.network, Network::Hysteria);
        assert_eq!(profile.outbound.stream.security, Security::Tls);
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
        let outcome = convert_document(clash).expect("clash");
        assert_eq!(outcome.entries.len(), 0);
        assert_eq!(outcome.refused.len(), 1);

        let json = r#"{"outbounds":[{"type":"trojan","tag":"NoPass","server":"t.example.com","server_port":443}]}"#;
        let outcome = convert_document(json).expect("json");
        assert_eq!(outcome.entries.len(), 0);
        assert_eq!(outcome.refused.len(), 1);
    }

    #[test]
    fn hysteria1_is_refused_and_hysteria2_bandwidth_maps() {
        let v1 = r#"{"outbounds":[{"type":"hysteria","tag":"H1","server":"h.example.com","server_port":443}]}"#;
        let outcome = convert_document(v1).expect("json");
        assert_eq!(outcome.entries.len(), 0);
        assert_eq!(outcome.refused.len(), 1);

        let v2 = "server: h.example.com\nport: 443\nauth: secret\nup: 100\ndown: 50\n";
        let outcome = convert_document(v2).expect("hysteria2");
        let quic = outcome.entries[0]
            .profile
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
        let outcome = convert_document(document).expect("clash");
        assert!(
            outcome.entries[0]
                .ignored
                .iter()
                .any(|parameter| parameter.name == "some-future-key")
        );
        assert!(
            outcome.entries[0]
                .ignored
                .iter()
                .all(|parameter| !parameter.raw.is_empty()
                    && parameter.raw.chars().count() <= crate::links::body::MAX_RAW_CHARS),
            "a document parameter still points at its bounded source: {:?}",
            outcome.entries[0].ignored
        );
        let json = r#"{"outbounds":[{"type":"socks","tag":"S","server":"s.example.com","server_port":1080,"future_field":true}]}"#;
        let outcome = convert_document(json).expect("json");
        assert!(
            outcome.entries[0]
                .ignored
                .iter()
                .any(|parameter| parameter.name == "future_field")
        );
    }

    #[test]
    fn sip008_servers_convert() {
        let document = r#"{"version":1,"servers":[
            {"server":"ss.example.com","server_port":8388,"method":"aes-128-gcm","password":"pw","remarks":"SS"}
        ]}"#;
        let outcome = convert_document(document).expect("sip008");
        assert_eq!(outcome.entries.len(), 1);
        assert_eq!(outcome.entries[0].profile.name, "SS");
    }

    #[test]
    fn sing_box_json_outbounds_convert_and_routing_is_ignored() {
        let document = r#"{"outbounds":[
            {"type":"vless","tag":"SB","server":"sb.example.com","server_port":443,
             "uuid":"11111111-2222-3333-4444-555555555555",
             "tls":{"enabled":true,"server_name":"example.com","utls":{"fingerprint":"chrome"}},
             "transport":{"type":"ws","path":"/ws"}}
        ],"route":{"rules":[]},"inbounds":[]}"#;
        let outcome = convert_document(document).expect("sing-box");
        assert_eq!(outcome.entries.len(), 1);
        assert_eq!(outcome.entries[0].profile.name, "SB");
        assert_eq!(
            outcome.entries[0].profile.outbound.stream.network,
            Network::Ws
        );
        assert_eq!(
            outcome.entries[0].profile.outbound.stream.security,
            Security::Tls
        );
        assert_eq!(outcome.ignored.len(), 2);
    }

    #[test]
    fn xray_json_outbounds_convert() {
        let document = r#"{"outbounds":[
            {"protocol":"vless","tag":"Xray","settings":{"address":"x.example.com","port":443,
             "id":"11111111-2222-3333-4444-555555555555"},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com"}}},
            {"protocol":"freedom","tag":"direct"}
        ]}"#;
        let outcome = convert_document(document).expect("xray");
        assert_eq!(outcome.entries.len(), 1);
        assert_eq!(outcome.entries[0].profile.name, "Xray");
        assert_eq!(outcome.ignored.len(), 1);
    }

    #[test]
    fn hysteria2_yaml_converts() {
        let document = "server: hy.example.com\nport: 443\nauth: secret\nsni: example.com\nskip-cert-verify: true\n";
        let outcome = convert_document(document).expect("hysteria2");
        assert_eq!(outcome.entries.len(), 1);
        let profile = &outcome.entries[0].profile;
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
        let outcome = convert_document(document).expect("json");
        assert_eq!(outcome.entries.len(), 0);
        assert_eq!(outcome.refused.len(), 1);
        assert!(outcome.refused[0].raw.contains("tuic"));
    }

    #[test]
    fn wireguard_configuration_converts() {
        let document = "[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/32\nMTU = 1280\n\n[Peer]\nPublicKey = def\nEndpoint = wg.example.com:51820\nAllowedIPs = 0.0.0.0/0\n";
        let outcome = convert_document(document).expect("wireguard");
        assert_eq!(outcome.entries.len(), 1);
        assert_eq!(outcome.entries[0].profile.name, "wg.example.com:51820");
    }
}
