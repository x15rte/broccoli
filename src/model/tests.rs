//! Round-trip tests: every model type survives serialize → deserialize →
//! serialize byte-identical (as parsed Values), incl. extra-map passthrough.

use super::*;
use crate::links::excerpt;
use crate::sys::appdata::with_appdata;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

/// parse input → re-serialize → must equal input (canonical wire form).
fn check<T>(input: Value)
where
    T: Serialize + DeserializeOwned,
{
    let parsed: T = serde_json::from_value(input.clone())
        .unwrap_or_else(|e| panic!("deserialize {} failed: {e}", std::any::type_name::<T>()));
    let out = serde_json::to_value(&parsed).unwrap();
    assert_eq!(
        input,
        out,
        "round trip mismatch for {}",
        std::any::type_name::<T>()
    );
}

/// value → serialize → parse → serialize: stable.
fn check_value<T>(v: &T)
where
    T: Serialize + DeserializeOwned,
{
    let a = serde_json::to_value(v).unwrap();
    let b: T = serde_json::from_value(a.clone()).unwrap();
    let c = serde_json::to_value(&b).unwrap();
    assert_eq!(
        a,
        c,
        "value round trip mismatch for {}",
        std::any::type_name::<T>()
    );
}

#[test]
fn int32_range_forms() {
    assert_eq!(
        serde_json::to_value(Int32Range::single(5)).unwrap(),
        json!(5)
    );
    assert_eq!(
        serde_json::to_value(Int32Range::new(100, 200)).unwrap(),
        json!("100-200")
    );
    assert_eq!(
        serde_json::to_value(Int32Range::new(-114, 514)).unwrap(),
        json!("-114-514")
    );
    let r: Int32Range = serde_json::from_value(json!("-114-514")).unwrap();
    assert_eq!(r, Int32Range::new(-114, 514));
    let r: Int32Range = serde_json::from_value(json!(7)).unwrap();
    assert_eq!(r, Int32Range::single(7));
    let r: Int32Range = serde_json::from_value(json!("10-20")).unwrap();
    assert_eq!(r, Int32Range::new(10, 20));
    assert!(serde_json::from_value::<Int32Range>(json!("nope")).is_err());
    assert_eq!(
        serde_json::from_value::<Int32Range>(json!(i32::MIN)).unwrap(),
        Int32Range::single(i32::MIN)
    );
    assert_eq!(
        serde_json::from_value::<Int32Range>(json!(i32::MAX)).unwrap(),
        Int32Range::single(i32::MAX)
    );
    assert!(serde_json::from_value::<Int32Range>(json!(i64::from(i32::MIN) - 1)).is_err());
    assert!(serde_json::from_value::<Int32Range>(json!(i64::from(i32::MAX) + 1)).is_err());
    assert!(serde_json::from_value::<Int32Range>(json!(u64::MAX)).is_err());
}

#[test]
fn duration_go_strings() {
    assert_eq!(DurationMs::secs(10).to_go_string(), "10s");
    assert_eq!(DurationMs::millis(500).to_go_string(), "500ms");
    assert_eq!(DurationMs::millis(90_000).to_go_string(), "1m30s");
    assert_eq!(DurationMs::millis(1500).to_go_string(), "1.5s");
    assert_eq!(DurationMs::millis(3_600_000).to_go_string(), "1h0m0s");
    assert_eq!(DurationMs::parse("10s"), Some(DurationMs::secs(10)));
    assert_eq!(DurationMs::parse("1m30s"), Some(DurationMs::millis(90_000)));
    assert_eq!(DurationMs::parse("500ms"), Some(DurationMs::millis(500)));
    assert_eq!(DurationMs::parse("1.5s"), Some(DurationMs::millis(1500)));
    assert_eq!(DurationMs::parse("2h"), Some(DurationMs::millis(7_200_000)));
    assert_eq!(
        serde_json::to_value(DurationMs::secs(10)).unwrap(),
        json!("10s")
    );
    let d: DurationMs = serde_json::from_value(json!("10s")).unwrap();
    assert_eq!(d, DurationMs::secs(10));
    assert!(serde_json::from_value::<DurationMs>(json!(-1)).is_err());
    assert_eq!(DurationMs::parse("1e100h"), None);
    assert_eq!(
        DurationMs::parse("999999999999999999999999999999999999h"),
        None
    );
    assert_eq!(DurationMs::parse("-1ms"), None);
}

/// A multi-KB invalid `Int32Range` string in a state file must
/// yield a bounded 48-char excerpt in the semantic error, never an echo of
/// the full value (the error surfaces verbatim in the UI via `load_state`).
#[test]
fn int32_range_error_excerpts_oversized_value() {
    let huge = "z".repeat(4096);
    let err = serde_json::from_value::<Int32Range>(json!(huge)).unwrap_err();
    let msg = err.to_string();
    let prefix = "invalid Int32Range: \"";
    assert!(msg.starts_with(prefix), "unexpected message: {msg:?}");
    assert!(msg.ends_with("…\""), "unexpected message: {msg:?}");
    let embedded = &msg[prefix.len()..msg.len() - 1]; // excerpt + ellipsis, minus closing quote
    assert_eq!(
        embedded.chars().count(),
        49,
        "exactly 48 excerpt chars plus the ellipsis, got: {embedded:?}"
    );
    assert!(embedded.starts_with(&"z".repeat(48)));
    assert!(
        !msg.contains(&"z".repeat(64)),
        "value beyond the excerpt must not be echoed"
    );
    // Short values still surface verbatim (no truncation).
    let err = serde_json::from_value::<Int32Range>(json!("nope")).unwrap_err();
    assert!(err.to_string().ends_with("\"nope\""));
}

/// Same bounded-excerpt guarantee for the `DurationMs` visitor.
#[test]
fn duration_ms_error_excerpts_oversized_value() {
    let huge = "w".repeat(4096);
    let err = serde_json::from_value::<DurationMs>(json!(huge)).unwrap_err();
    let msg = err.to_string();
    let prefix = "invalid duration: \"";
    assert!(msg.starts_with(prefix), "unexpected message: {msg:?}");
    assert!(msg.ends_with("…\""), "unexpected message: {msg:?}");
    let embedded = &msg[prefix.len()..msg.len() - 1];
    assert_eq!(
        embedded.chars().count(),
        49,
        "exactly 48 excerpt chars plus the ellipsis, got: {embedded:?}"
    );
    assert!(embedded.starts_with(&"w".repeat(48)));
    assert!(
        !msg.contains(&"w".repeat(64)),
        "value beyond the excerpt must not be echoed"
    );
    // Short values still surface verbatim (no truncation).
    let err = serde_json::from_value::<DurationMs>(json!("xyz")).unwrap_err();
    assert!(err.to_string().ends_with("\"xyz\""));
}

#[test]
fn protocol_wire_strings() {
    let expect = [
        (Protocol::Vless, "vless"),
        (Protocol::Vmess, "vmess"),
        (Protocol::Trojan, "trojan"),
        (Protocol::Shadowsocks, "shadowsocks"),
        (Protocol::Socks, "socks"),
        (Protocol::Http, "http"),
        (Protocol::Wireguard, "wireguard"),
        (Protocol::Freedom, "freedom"),
        (Protocol::Blackhole, "blackhole"),
        (Protocol::Dns, "dns"),
        (Protocol::Loopback, "loopback"),
        (Protocol::Hysteria, "hysteria"),
    ];
    for (p, s) in expect {
        assert_eq!(p.as_str(), s);
        assert_eq!(Protocol::from_str_lossy(s), p);
        assert_eq!(serde_json::to_value(p).unwrap(), json!(s));
    }
    assert_eq!(Protocol::from_str_lossy("direct"), Protocol::Freedom);
    assert_eq!(Protocol::from_str_lossy("block"), Protocol::Blackhole);
    assert_eq!(Protocol::ALL.len(), 12);
}

#[test]
fn roundtrip_protocol_settings() {
    check::<VlessSettings>(json!({
        "address": "a.example.com", "port": 443, "id": "11111111-2222-3333-4444-555555555555",
        "flow": "xtls-rprx-vision", "encryption": "none", "level": 0, "email": "u@x",
        "reverse": {"tag": "rev", "sniffing": {"enabled": true, "destOverride": ["http"]}}
    }));
    check::<VmessSettings>(json!({
        "address": "v.example.com", "port": 443, "id": "x", "security": "aes-128-gcm",
        "experiments": "AuthenticatedLength"
    }));
    check::<TrojanSettings>(json!({"address": "t.example.com", "port": 443, "password": "pw"}));
    check::<ShadowsocksSettings>(json!({
        "address": "s.example.com", "port": 8388, "method": "2022-blake3-aes-128-gcm",
        "password": "key:key2"
    }));
    check::<SocksSettings>(json!({"address": "10.0.0.2", "port": 1080, "user": "u", "pass": "p"}));
    check::<HttpSettings>(json!({
        "address": "10.0.0.3", "port": 8080, "user": "u", "pass": "p",
        "headers": {"User-Agent": "curl/8"}
    }));
    check::<WireguardSettings>(json!({
        "secretKey": "k", "address": ["10.0.0.1/32"], "mtu": 1420, "domainStrategy": "forceip",
        "reserved": [1, 2, 3], "noKernelTun": true,
        "peers": [{"publicKey": "pk", "preSharedKey": "psk", "endpoint": "e:51820",
                   "keepAlive": 25, "allowedIPs": ["0.0.0.0/0"], "level": 1, "email": "e@x"}]
    }));
    check::<FreedomSettings>(json!({
        "targetStrategy": "UseIP", "redirect": "1.2.3.4:80", "userLevel": 0,
        "fragment": {"packets": "tlshello", "length": "100-200", "interval": 5, "maxSplit": "1-3"},
        "noises": [{"type": "rand", "packet": "50-100", "delay": "1-5", "applyTo": "ipv4"}],
        "proxyProtocol": 1,
        "finalRules": [{"action": "block", "network": "udp", "port": "443",
                        "ip": ["203.0.113.0/24"], "blockDelay": "10-20"}]
    }));
    check::<BlackholeSettings>(json!({"response": {"type": "http"}}));
    check::<DnsOutboundSettings>(json!({
        "rewriteNetwork": "udp", "rewriteAddress": "1.1.1.1", "rewritePort": 53, "userLevel": 0,
        "rules": [{"action": "hijack", "qType": "1,2", "domain": ["geosite:ads"], "rCode": 3}]
    }));
    check::<LoopbackSettings>(json!({
        "inboundTag": "in-socks", "sniffing": {"enabled": true, "destOverride": ["tls"]}
    }));
    check::<HysteriaSettings>(json!({"version": 2, "address": "h.example.com", "port": 443}));
}

#[test]
fn roundtrip_stream() {
    check::<MuxModel>(
        json!({"enabled": true, "concurrency": 8, "xudpConcurrency": 16, "xudpProxyUDP443": "skip"}),
    );

    check::<StreamModel>(json!({"network": "raw"}));
    check::<StreamModel>(json!({
        "network": "raw",
        "tcpSettings": {"header": {"type": "http",
            "request": {"version": "1.1", "method": "GET", "path": ["/a", "/b"],
                        "headers": {"Host": ["x.com", "y.com"], "User-Agent": "ua"}},
            "response": {"version": "1.1", "status": "200", "reason": "OK",
                         "headers": {"Content-Type": "text/html"}}}}
    }));
    check::<StreamModel>(json!({
        "network": "xhttp",
        "xhttpSettings": {
            "host": "h", "path": "/p", "mode": "packet-up", "headers": {"A": "b"},
            "uplinkHTTPMethod": "POST", "uplinkDataPlacement": "cookie", "uplinkDataKey": "k",
            "uplinkChunkSize": "2000-4000",
            "xPaddingBytes": "100-200", "xPaddingObfsMode": true, "xPaddingKey": "pk",
            "xPaddingHeader": "ph", "xPaddingPlacement": "query", "xPaddingMethod": "repeat-x",
            "sessionIDPlacement": "header", "sessionIDKey": "sk", "sessionIDTable": "st",
            "sessionIDLength": 16, "seqPlacement": "query", "seqKey": "sq",
            "noGRPCHeader": true, "noSSEHeader": true,
            "scMaxEachPostBytes": 1000000, "scMinPostsIntervalMs": "10-30",
            "scMaxBufferedPosts": 5, "scStreamUpServerSecs": "20-80", "serverMaxHeaderBytes": 4096,
            "xmux": {"maxConcurrency": "8-16", "cMaxReuseTimes": 100, "hMaxRequestTimes": 200,
                     "hMaxReusableSecs": 300, "hKeepAlivePeriod": 30},
            "downloadSettings": {"network": "raw", "security": "tls",
                                 "tlsSettings": {"serverName": "dl.example.com"}}
        },
        "security": "tls",
        "tlsSettings": {"serverName": "h"}
    }));
    check::<StreamModel>(json!({
        "network": "kcp",
        "kcpSettings": {"mtu": 1350, "tti": 50, "uplinkCapacity": 5, "downlinkCapacity": 20,
                        "cwndMultiplier": 1, "maxSendingWindow": 2097152}
    }));
    check::<StreamModel>(json!({
        "network": "grpc",
        "grpcSettings": {"authority": "a", "serviceName": "svc", "multiMode": true,
                         "idle_timeout": 60, "health_check_timeout": 20,
                         "permit_without_stream": true, "initial_windows_size": 65535,
                         "user_agent": "ua"}
    }));
    check::<StreamModel>(json!({
        "network": "ws",
        "wsSettings": {"host": "h", "path": "/ws?ed=2048", "headers": {"Host": "h"},
                       "heartbeatPeriod": 30}
    }));
    check::<StreamModel>(json!({
        "network": "httpupgrade",
        "httpupgradeSettings": {"host": "h", "path": "/hu", "headers": {"A": "b"}}
    }));
    check::<StreamModel>(json!({
        "network": "hysteria",
        "hysteriaSettings": {"version": 2, "auth": "pw", "udpIdleTimeout": 60},
        "finalmask": {
            "udp": [{"type": "salamander", "settings": {"password": "x"}}],
            "quicParams": {"congestion": "brutal", "brutalUp": "50 mbps"}
        }
    }));
    check::<StreamModel>(json!({
        "network": "raw", "security": "tls",
        "tlsSettings": {
            "serverName": "s", "alpn": ["h2", "http/1.1"], "fingerprint": "chrome",
            "minVersion": "1.2", "maxVersion": "1.3", "cipherSuites": "TLS_AES_128_GCM_SHA256",
            "curvePreferences": ["x25519mlkem768"],
            "certificates": [{"certificateFile": "c.pem", "keyFile": "k.pem", "usage": "verify",
                              "ocspStapling": 3600, "oneTimeLoading": true, "buildChain": true}],
            "disableSystemRoot": true, "enableSessionResumption": false,
            "pinnedPeerCertSha256": "ab:cd", "verifyPeerCertByName": "x.com",
            "masterKeyLog": "keys.log", "echConfigList": "https://1.1.1.1/dns-query",
            "echSockopt": {"dialerProxy": "direct"}
        }
    }));
    check::<StreamModel>(json!({
        "network": "raw", "security": "reality",
        "realitySettings": {"serverName": "s", "fingerprint": "chrome", "password": "pub",
                            "shortId": "ab12", "spiderX": "/", "mldsa65Verify": "mk",
                            "show": true, "masterKeyLog": "k.log"}
    }));
    check::<StreamModel>(json!({
        "network": "raw",
        "sockopt": {
            "domainStrategy": "useip", "dialerProxy": "direct", "interface": "Ethernet0",
            "tcpFastOpen": true, "tcpKeepAliveIdle": 60, "tcpKeepAliveInterval": 10,
            "tcpCongestion": "bbr", "tcpWindowClamp": 600, "tcpMaxSeg": 1440,
            "tcpUserTimeout": 10000, "tcpMptcp": true, "penetrate": true, "mark": 255,
            "tproxy": "off", "v6only": false,
            "customSockopt": [{"type": "int", "opt": "1", "value": "2", "level": "6"}],
            "addressPortStrategy": "srvportonly",
            "happyEyeballs": {"prioritizeIPv6": true, "tryDelayMs": 250, "interleave": 1,
                              "maxConcurrentTry": 4}
        }
    }));
    // allowInsecure must NOT exist as a field: it lands in extra and round-trips verbatim.
    let v: StreamModel = serde_json::from_value(
        json!({"network": "raw", "security": "tls", "tlsSettings": {"allowInsecure": true}}),
    )
    .unwrap();
    let out = serde_json::to_value(&v).unwrap();
    assert_eq!(out["tlsSettings"]["allowInsecure"], json!(true)); // passthrough only
}

#[test]
fn roundtrip_outbound_envelope() {
    check::<OutboundModel>(json!({
        "protocol": "trojan",
        "settings": {"address": "t.example.com", "port": 443, "password": "pw"},
        "streamSettings": {"network": "raw", "security": "tls",
                           "tlsSettings": {"serverName": "t.example.com"}},
        "proxySettings": {"tag": "srv-deadbeef"},
        "sendThrough": "192.168.1.10",
        "targetStrategy": "useip",
        "mux": {"enabled": true, "concurrency": 8}
    }));
    // variant selection is driven by protocol:
    let ob: OutboundModel = serde_json::from_value(json!({
        "protocol": "wireguard",
        "settings": {"secretKey": "k", "address": ["10.0.0.1"], "mtu": 1420, "domainStrategy": "forceip"}
    }))
    .unwrap();
    assert!(matches!(ob.settings, ProtocolSettings::Wireguard(_)));
    assert_eq!(ob.settings.protocol(), ob.protocol);
    // to_wire injects tag
    let wire = ob.to_wire("srv-01234567");
    assert_eq!(wire["tag"], json!("srv-01234567"));
}

#[test]
fn roundtrip_inbounds() {
    check::<Sniffing>(json!({
        "enabled": true, "destOverride": ["http", "tls", "quic", "fakedns"],
        "domainsExcluded": ["x.com"], "ipsExcluded": ["1.1.1.1"], "routeOnly": true
    }));
    check::<LocalInboundCfg>(json!({
        "protocol": "socks", "tag": "in-socks", "enabled": true, "port": 10808,
        "listen": "127.0.0.1", "udp": true, "auth": "password",
        "accounts": [{"user": "u", "pass": "p"}],
        "sniffing": {"enabled": true, "destOverride": ["http"]}
    }));
    check::<LocalInboundCfg>(json!({
        "protocol": "http", "tag": "in-http", "enabled": true, "port": 10809,
        "listen": "127.0.0.1", "udp": true, "auth": "noauth", "allowTransparent": true,
        "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"]}
    }));
    check::<LocalInboundCfg>(json!({
        "protocol": "socks", "tag": "in-socks-1", "enabled": false, "port": 10880,
        "listen": "0.0.0.0", "udp": true, "ip": "10.0.0.2", "userLevel": 1,
        "auth": "password", "accounts": [{"user": "u", "pass": "p"}],
        "sniffing": {"enabled": true, "destOverride": ["http"]},
        "futureSocks": {"preserved": true}
    }));
    check::<DokodemoCfg>(json!({
        "enabled": true, "listenPort": 5353, "listen": "127.0.0.1",
        "network": "tcp,udp", "address": "8.8.8.8",
        "port": 53, "followRedirect": true,
        "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"]}
    }));
    check::<TunCfg>(json!({
        "name": "broccoli0", "desc": "Wintun", "mtu": 1500,
        "gateway": ["10.255.0.1/30"], "dns": ["1.1.1.1", "8.8.8.8"], "userLevel": 0,
        "autoSystemRoutingTable": ["0.0.0.0/1", "128.0.0.0/1"],
        "autoOutboundsInterface": "auto",
        "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"]}
    }));
}

#[test]
fn roundtrip_routing() {
    check::<Rule>(json!({
        "ruleTag": "11111111-2222-3333-4444-555555555555", "balancerTag": "bal",
        "domain": ["geosite:cn", "full:example.com"], "ip": ["geoip:private"],
        "port": "443", "sourcePort": "1000-2000", "localPort": "8080", "network": "tcp",
        "source": ["10.0.0.0/8"], "localIP": ["192.168.0.0/16"], "user": ["u@x"],
        "inboundTag": ["in-socks"], "protocol": ["http", "tls"],
        "attrs": {":path": "^/api"}, "vlessRoute": "443",
        "process": ["chrome.exe"], "webhook": {"url": "https://h", "deduplication": 60,
                                               "headers": {"X": "y"}}
    }));
    check::<Balancer>(json!({
        "tag": "bal", "selector": ["srv-"], "fallbackTag": "direct",
        "strategy": {"type": "leastload",
                     "settings": {"costs": [{"regexp": true, "match": "srv-", "value": 2.0}],
                                  "baselines": ["1s"], "expected": 1, "maxRTT": "5s",
                                  "tolerance": 0.5}}
    }));
    check::<ObservatoryCfg>(json!({
        "enabled": true, "subjectSelector": ["srv-"],
        "probeURL": "https://www.google.com/generate_204",
        "probeInterval": "10s", "enableConcurrency": true
    }));
    check::<BurstObservatoryCfg>(json!({
        "enabled": true, "subjectSelector": ["srv-"],
        "pingConfig": {"destination": "https://connectivitycheck.gstatic.com/generate_204",
                       "connectivity": "https://c", "interval": "5s", "sampling": 3,
                       "timeout": "2s", "httpMethod": "HEAD"}
    }));
    let r = Rule::new();
    assert!(!r.rule_tag.is_empty());
    check_value(&RoutingCfg::default());
}

#[test]
fn roundtrip_dns() {
    check::<DnsServer>(json!({
        "address": "https://dns.google/dns-query", "port": 443, "domains": ["geosite:cn"],
        "expectedIPs": ["geoip:cn"], "unexpectedIPs": ["1.2.3.4"], "skipFallback": true,
        "clientIp": "203.0.113.1", "queryStrategy": "useip4", "tag": "d1",
        "timeoutMs": 3000, "finalQuery": true
    }));
    check::<DnsCfg>(json!({
        "servers": [{"address": "1.1.1.1"}, {"address": "fakedns"}],
        "hosts": {"example.com": "1.2.3.4", "multi": ["1.1.1.1", "2.2.2.2"]},
        "clientIp": "203.0.113.1", "tag": "dns", "queryStrategy": "useip4",
        "disableCache": true, "serveStale": true, "serveExpiredTTL": 3600,
        "disableFallback": true, "disableFallbackIfMatch": true,
        "enableParallelQuery": true, "useSystemHosts": true,
        "bootstrap": "localhost",
        "fakedns": {"enabled": true, "pools": [
            {"ipPool": "198.18.0.0/15", "poolSize": 65535}
        ]}
    }));
    check_value(&DnsCfg::default());
}

#[test]
fn cleared_dns_collapses_to_no_wire_block_and_survives_the_round_trip() {
    // The seeded defaults (1.1.1.1, parallel on, serveStale on, 86400 TTL)
    // must not resurrect after the user clears DNS: cleared states serialize
    // explicitly and load back identical, and to_wire collapses to None.
    let cleared = DnsCfg {
        servers: Vec::new(),
        bootstrap: String::new(),
        enable_parallel_query: false,
        serve_stale: false,
        serve_expired_ttl: None,
        ..Default::default()
    };
    let stored = serde_json::to_value(&cleared).unwrap();
    let reloaded: DnsCfg = serde_json::from_value(stored.clone()).unwrap();
    assert_eq!(
        stored,
        serde_json::to_value(&reloaded).unwrap(),
        "cleared DNS state must survive the save/load round trip"
    );
    assert!(
        cleared.is_effectively_empty(),
        "cleared DNS must emit no dns block on the wire"
    );
}

#[test]
fn off_stale_options_round_trip_and_strip_from_the_wire() {
    // serveStale off and a cleared stale-TTL (None) persist explicitly so a
    // later load cannot reseed them; the wire stays minimal (core defaults).
    let cfg = DnsCfg {
        serve_stale: false,
        serve_expired_ttl: None,
        ..Default::default()
    };
    let stored = serde_json::to_value(&cfg).unwrap();
    assert_eq!(stored["serveStale"], json!(false), "off must be stored");
    assert_eq!(
        stored["serveExpiredTTL"],
        Value::Null,
        "cleared TTL must be stored as null"
    );
    let wire = cfg.to_wire(false).expect("seeded config has a wire form");
    assert!(
        wire.get("serveStale").is_none() && wire.get("serveExpiredTTL").is_none(),
        "off/null stale options must not reach the wire: {wire}"
    );
    let reloaded: DnsCfg = serde_json::from_value(stored).unwrap();
    assert!(!reloaded.serve_stale);
    assert_eq!(reloaded.serve_expired_ttl, None);
}

#[test]
fn roundtrip_settings_and_servers() {
    check::<PolicyCfg>(json!({
        "levels": {"0": {
            "handshake": 4, "connIdle": 300, "uplinkOnly": 5,
            "downlinkOnly": 30, "bufferSize": -1
        }}
    }));
    assert!(PolicyCfg::default().is_empty());
    assert_eq!(serde_json::to_value(Mode::Off).unwrap(), json!("off"));
    let m: Mode = serde_json::from_value(json!("tun")).unwrap();
    assert_eq!(m, Mode::Tun);
    assert_eq!(
        Mode::default(),
        Mode::Off,
        "first run must not alter Windows networking"
    );
    check_value(&Settings::default());

    let mut sf = ServersFile::default();
    let mut p = ServerProfile::new("test", OutboundModel::new(Protocol::Trojan));
    p.latency_ms = Some(42);
    sf.active = Some(p.id.clone());
    sf.profiles.push(p);
    let v = serde_json::to_value(&sf).unwrap();
    assert!(
        v["profiles"][0].get("latencyMs").is_none(),
        "latency_ms must not persist"
    );
    assert!(v["profiles"][0].get("latency_ms").is_none());
    let back: ServersFile = serde_json::from_value(v.clone()).unwrap();
    assert_eq!(back.profiles[0].latency_ms, None);
    assert_eq!(serde_json::to_value(&back).unwrap(), v);
    assert!(matches!(
        back.profiles[0].outbound.settings,
        ProtocolSettings::Trojan(_)
    ));
}

#[test]
fn settings_without_inbound_keys_default_to_the_seed_list() {
    // A file without a `localInbounds` key must load the fresh-install
    // seed: SOCKS 127.0.0.1:10808 + HTTP 127.0.0.1:10809.
    let seed = serde_json::to_value(default_local_inbounds()).unwrap();
    for raw in [
        json!({"version": 1, "routing": {}, "dns": {}, "tun": {}, "mode": "off",
               "policy": {}, "geodata": {}}),
        json!({}),
    ] {
        let settings: Settings = serde_json::from_value(raw).unwrap();
        assert_eq!(
            serde_json::to_value(&settings.local_inbounds).unwrap(),
            seed,
            "a file without localInbounds must seed the defaults"
        );
    }
    assert_eq!(
        serde_json::to_value(&Settings::default().local_inbounds).unwrap(),
        seed,
        "the in-memory Default is the same seed list"
    );
}

#[test]
fn tag_seq_high_water_marks_persist_round_trip() {
    // The per-protocol allocator marks are GUI-owned persisted
    // state — removed tag numbers must never be reissued, so they survive
    // save/load like any other settings field.
    let mut settings = Settings::default();
    assert_eq!(settings.socks_tag_seq, 0);
    assert_eq!(settings.http_tag_seq, 0);
    let value = serde_json::to_value(&settings).unwrap();
    assert!(
        value.get("socksTagSeq").is_none() && value.get("httpTagSeq").is_none(),
        "zero marks serialize as absent: {value}"
    );

    settings.socks_tag_seq = 3;
    settings.http_tag_seq = 7;
    let value = serde_json::to_value(&settings).unwrap();
    assert_eq!(value["socksTagSeq"], 3);
    assert_eq!(value["httpTagSeq"], 7);

    let reloaded: Settings = serde_json::from_value(value).unwrap();
    assert_eq!(reloaded.socks_tag_seq, 3);
    assert_eq!(reloaded.http_tag_seq, 7);

    // A file whose mark keys are absent — zero marks serialize as absent,
    // so any saved file, hand-edited file, or file predating the marks
    // lacks them — loads back at 0: no removed number is ever reissued.
    let no_marks: Settings = serde_json::from_value(json!({
        "version": 1,
        "routing": {}, "dns": {}, "tun": {}, "mode": "off", "policy": {}, "geodata": {}
    }))
    .unwrap();
    assert_eq!(no_marks.socks_tag_seq, 0, "absent mark keys load as 0");
    assert_eq!(no_marks.http_tag_seq, 0);
}

#[test]
fn next_local_tag_allocates_increasing_tags_per_protocol() {
    let mut hw = 0;
    assert_eq!(
        next_local_tag(&[], LocalInboundProtocol::Socks, &mut hw),
        "in-socks-1"
    );
    assert_eq!(hw, 1, "the issued number becomes the high-water mark");
    assert_eq!(
        next_local_tag(&[], LocalInboundProtocol::Http, &mut hw),
        "in-http-2",
        "http numbering is independent of the socks entries"
    );

    let mut entries = vec![LocalInboundCfg::socks_default("in-socks-1")];
    assert_eq!(
        next_local_tag(&entries, LocalInboundProtocol::Socks, &mut hw),
        "in-socks-3",
        "a hand-edited entry below the mark does not rewind it"
    );
    entries.push(LocalInboundCfg::socks_default("in-socks-2"));
    assert_eq!(
        next_local_tag(&entries, LocalInboundProtocol::Socks, &mut hw),
        "in-socks-4",
        "the mark moves past the highest live suffix"
    );
}

#[test]
fn next_local_tag_never_reuses_a_removed_number() {
    // The high-water mark persists across removals: a removed
    // entry's number is gone for good — a dangling routing-rule reference
    // to it must keep failing validation instead of silently retargeting a
    // new entry. The removed-max case is the trap: recomputing from the
    // live list alone would reissue it.
    let mut hw = 2; // in-socks-1 and in-socks-2 were allocated; in-socks-2 was then removed
    let entries = vec![LocalInboundCfg::socks_default("in-socks-1")];
    assert_eq!(
        next_local_tag(&entries, LocalInboundProtocol::Socks, &mut hw),
        "in-socks-3",
        "removing the highest-numbered entry must not reissue its number"
    );

    let mut hw = 0;
    let entries = vec![
        LocalInboundCfg::socks_default("in-socks-1"),
        LocalInboundCfg::socks_default("in-socks-3"),
    ];
    assert_eq!(
        next_local_tag(&entries, LocalInboundProtocol::Socks, &mut hw),
        "in-socks-4"
    );
}

#[test]
fn next_local_tag_skips_tags_held_across_protocols() {
    // A hand-edited http entry squatting on a socks number forces the
    // allocator past it; the mark then keeps it there.
    let mut hw = 0;
    let entries = vec![
        LocalInboundCfg::socks_default("in-socks-1"),
        LocalInboundCfg::http_default("in-socks-2"),
    ];
    assert_eq!(
        next_local_tag(&entries, LocalInboundProtocol::Socks, &mut hw),
        "in-socks-3"
    );
    assert_eq!(hw, 3);

    // …and vice versa: a socks entry holding an http number.
    let mut hw = 0;
    let entries = vec![LocalInboundCfg::socks_default("in-http-1")];
    assert_eq!(
        next_local_tag(&entries, LocalInboundProtocol::Http, &mut hw),
        "in-http-2"
    );
}

#[test]
fn next_local_tag_falls_back_to_uuid_at_suffix_overflow() {
    // A hand-edited tag at the u32 suffix ceiling must not overflow
    // (debug panic / release wrap); the allocator falls back to a
    // UUID-suffixed tag and never reissues the ceiling number.
    let mut hw = 0;
    let entries = vec![LocalInboundCfg::socks_default("in-socks-4294967295")];
    let tag = next_local_tag(&entries, LocalInboundProtocol::Socks, &mut hw);
    assert!(
        tag.starts_with("in-socks-"),
        "uuid fallback keeps the prefix: {tag}"
    );
    assert_ne!(
        tag, "in-socks-4294967295",
        "the ceiling suffix must never be reissued"
    );
    assert_eq!(hw, 0, "no numeric mark is claimed by the uuid fallback");

    let mut hw = u32::MAX;
    let tag = next_local_tag(&[], LocalInboundProtocol::Http, &mut hw);
    assert!(
        tag.starts_with("in-http-") && tag != "in-http-4294967295",
        "a maxed mark must fall back to uuid: {tag}"
    );
}

#[test]
fn profile_tag_contract() {
    let p = ServerProfile {
        id: "0123456789abcdef".into(),
        ..ServerProfile::new("x", OutboundModel::default())
    };
    assert_eq!(p.tag(), "srv-01234567");
    let short = ServerProfile {
        id: "abc".into(),
        ..ServerProfile::new("x", OutboundModel::default())
    };
    assert_eq!(short.tag(), "srv-abc");
    let unicode = ServerProfile {
        id: "服务器αβ".into(),
        ..ServerProfile::new("x", OutboundModel::default())
    };
    assert_eq!(unicode.tag(), "srv-服务器αβ");
}

#[test]
fn settings_save_still_fails_closed_when_state_dir_dacl_fails() {
    // Settings/servers saves keep the fail-closed DACL: when the dirs
    // cannot be secured, no state file may be written. The DACL is applied
    // at directory creation (`paths::ensure_dirs`), so the failure seam
    // lives there.
    with_appdata(|| {
        crate::sys::paths::set_fail_dir_dacl(true);
        let result = save_state("settings.json", &Settings::default());
        crate::sys::paths::set_fail_dir_dacl(false);
        let error =
            result.expect_err("settings save must fail closed when the DACL cannot be applied");
        assert!(
            error.to_string().contains("DACL"),
            "names the cause: {error}"
        );
        assert!(
            !state_file("settings.json").exists(),
            "no settings file may be written when the DACL fails"
        );
    });
}

// ---------- restrictive DACL on state/config dirs ----------

use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, CONTAINER_INHERIT_ACE, CreateWellKnownSid, DACL_SECURITY_INFORMATION,
    EqualSid, GetAce, GetFileSecurityW, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
    IsValidSecurityDescriptor, OBJECT_INHERIT_ACE, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PRESENT,
    SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR_CONTROL, TOKEN_QUERY, WinWorldSid,
};
use windows::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows::core::{BOOL, PCWSTR};

/// The current process's user SID, via the shared `sys::security` module —
/// the single home of the token/SID machinery. The DACL
/// read-back helpers only need the principal to compare ACE SIDs against.
fn current_user_sid() -> crate::sys::security::Sid {
    let token = crate::sys::security::TokenHandle::open_current_process(TOKEN_QUERY)
        .expect("open the current process token");
    crate::sys::security::Sid::token_user(&token).expect("read the current user SID")
}

/// Load `path`'s DACL (plus control bits). Returns the descriptor buffer
/// (which owns the DACL memory), the descriptor pointer, the DACL pointer,
/// and the control bits; the returned pointers are valid as long as the
/// buffer is alive.
fn read_dacl(
    path: &std::path::Path,
) -> (
    Vec<u8>,
    PSECURITY_DESCRIPTOR,
    *mut ACL,
    SECURITY_DESCRIPTOR_CONTROL,
) {
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut required = 0u32;
    // SAFETY: `wide` is a NUL-terminated wide path valid for the call; a null
    // descriptor buffer with 0 length is the documented sizing query (the
    // ERROR_INSUFFICIENT_BUFFER result is deliberately ignored).
    let _ = unsafe {
        GetFileSecurityW(
            PCWSTR(wide.as_ptr()),
            DACL_SECURITY_INFORMATION.0,
            None,
            0,
            &mut required,
        )
    };
    assert!(required > 0, "sizing query must report a descriptor size");
    let mut bytes = vec![0u8; required as usize];
    let descriptor = PSECURITY_DESCRIPTOR(bytes.as_mut_ptr().cast());
    // SAFETY: `bytes` is sized exactly from the sizing query and stays alive
    // through all reads; `descriptor` points into it, so the kernel writes at
    // most `required` bytes; the global-allocator allocation satisfies the
    // descriptor's alignment (MIN_ALIGN >= 8 on x64). The result is checked
    // via `loaded.as_bool()`.
    let loaded = unsafe {
        GetFileSecurityW(
            PCWSTR(wide.as_ptr()),
            DACL_SECURITY_INFORMATION.0,
            Some(descriptor),
            required,
            &mut required,
        )
    };
    assert!(
        loaded.as_bool(),
        "reading {} DACL failed: {}",
        path.display(),
        windows::core::Error::from_thread()
    );

    let mut control = SECURITY_DESCRIPTOR_CONTROL(0);
    let mut revision = 0u32;
    // SAFETY: `descriptor` is the valid, initialized descriptor written by
    // `GetFileSecurityW` into the live `bytes` buffer; `control` and
    // `revision` are valid out-parameters and the return is checked.
    unsafe { GetSecurityDescriptorControl(descriptor, &mut control.0, &mut revision) }
        .expect("read DACL control");

    let mut dacl_present = BOOL(0);
    let mut dacl_defaulted = BOOL(0);
    let mut dacl = std::ptr::null_mut::<ACL>();
    // SAFETY: `descriptor` is the valid descriptor in the live `bytes` buffer;
    // the out-parameters are valid, the return is checked, and on success
    // `dacl` (when `dacl_present`) points into the same buffer.
    unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    }
    .expect("read DACL");
    assert!(
        dacl_present.as_bool() && !dacl.is_null(),
        "{} DACL must be present and non-null",
        path.display()
    );
    (bytes, descriptor, dacl, control)
}

/// Assert `dir`'s DACL grants `FILE_ALL_ACCESS` to exactly one principal —
/// the current user — with object/container inheritance, and is protected
/// from the parent's inheritable ACEs. Fails the test on any
/// deviation: an extra principal, a missing DACL, or missing protection.
fn assert_user_only_dacl(dir: &std::path::Path) {
    let (_bytes, _descriptor, dacl, control) = read_dacl(dir);
    assert!(
        control.contains(SE_DACL_PRESENT) && control.contains(SE_DACL_PROTECTED),
        "{} DACL must be present and protected from inheritance",
        dir.display()
    );
    // SAFETY: `dacl` is the valid, non-null DACL returned by `read_dacl`
    // (checked above); its header (AceCount at offset 2) is initialized
    // because the descriptor was fully loaded.
    assert_eq!(
        unsafe { (*dacl).AceCount },
        1,
        "{} DACL must grant exactly one principal",
        dir.display()
    );

    let mut raw_ace = std::ptr::null_mut();
    // SAFETY: `dacl` is the valid, non-null DACL; index 0 is within the
    // AceCount (== 1) just verified; `raw_ace` is a valid out-parameter and
    // the return is checked.
    unsafe { GetAce(dacl, 0, &mut raw_ace) }.expect("read DACL ACE");
    // SAFETY: `GetAce` succeeded, so `raw_ace` points at a valid ACE inside
    // the DACL; its declared `AceSize` covers the fields read here (header at
    // 0, `Mask` at 4, `SidStart` at 8 — the fixed prefix shared by all ACE
    // types that carry a SID). The DACL buffer stays alive, and a wrong ACE
    // type is rejected by the `AceType != 0` check.
    let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
    assert_eq!(ace.Header.AceType, 0, "ACE must be access-allowed");
    assert_eq!(
        ace.Header.AceFlags,
        (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE).0 as u8,
        "ACE must inherit to files and subdirectories"
    );
    assert_eq!(ace.Mask, FILE_ALL_ACCESS.0, "ACE must grant full access");

    let user_sid = current_user_sid();
    let user_sid = user_sid.psid();
    let sid = PSID((std::ptr::addr_of!(ace.SidStart) as *mut u32).cast::<core::ffi::c_void>());
    // SAFETY: `sid` points at the embedded SID in the live DACL buffer (its
    // length fits the ACE's `AceSize`); `user_sid` is the SID owned by the
    // `current_user_sid` value bound above. EqualSid only reads both.
    assert!(
        unsafe { EqualSid(sid, user_sid) }.is_ok(),
        "{} DACL must grant access only to the current user",
        dir.display()
    );
}

/// A state file created under a protected dir inherits the user-only ACE: its
/// DACL must carry an allow-full-control ACE for the current user and must
/// grant nothing to `Everyone` (acceptance: ACL on a freshly created
/// state file). Extra ACEs from the process default DACL (e.g. SYSTEM) are
/// tolerated — the restrictive user-bound ACE is present and no broad
/// principal is admitted.
fn assert_state_file_user_only(path: &std::path::Path) {
    let (_bytes, _descriptor, dacl, _control) = read_dacl(path);
    let mut world_storage = [0u8; 68];
    let mut world_len = world_storage.len() as u32;
    let world = PSID(world_storage.as_mut_ptr().cast());
    // SAFETY: `world_storage` is 68 bytes (`SECURITY_MAX_SID_SIZE`), the
    // documented capacity for any well-known SID, so the cast pointer is
    // writable for `world_len` bytes and stays alive for the call; `None`
    // domain SID is valid for alias types. On success the buffer holds a
    // valid SID whose address is returned.
    unsafe { CreateWellKnownSid(WinWorldSid, None, Some(world), &mut world_len) }
        .expect("build Everyone SID");

    let user_sid = current_user_sid();
    let user_sid = user_sid.psid();

    // SAFETY: `dacl` is the valid, non-null DACL returned by `read_dacl`; its
    // header (AceCount at offset 2) is initialized because the descriptor was
    // fully loaded. AceCount is a u16; `GetAce` takes a u32 index.
    let ace_count = u32::from(unsafe { (*dacl).AceCount });
    let mut saw_user_full = false;
    for index in 0..ace_count {
        let mut raw_ace = std::ptr::null_mut();
        // SAFETY: `dacl` is the valid, non-null DACL; `index` is within the
        // AceCount just read; `raw_ace` is a valid out-parameter and the
        // return is checked.
        unsafe { GetAce(dacl, index, &mut raw_ace) }.expect("read state file ACE");
        // SAFETY: `GetAce` succeeded, so `raw_ace` points at a valid ACE
        // inside the live DACL buffer; its `AceSize` covers the fields read
        // here (header at 0, `Mask` at 4, `SidStart` at 8). The buffer stays
        // alive, and a non-allow ACE is rejected by the `AceType != 0` check.
        let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
        if ace.Header.AceType != 0 {
            panic!("state file {} has a non-allow ACE", path.display());
        }
        let sid = PSID((std::ptr::addr_of!(ace.SidStart) as *mut u32).cast::<core::ffi::c_void>());
        // SAFETY: `sid` is the embedded SID in the live DACL buffer (its
        // length fits the ACE's `AceSize`); `world` is the well-known Everyone
        // SID built above; `user_sid` is the current user SID. EqualSid only
        // reads both.
        if unsafe { EqualSid(sid, world) }.is_ok() {
            panic!("state file {} grants Everyone access", path.display());
        }
        if unsafe { EqualSid(sid, user_sid) }.is_ok() && ace.Mask == FILE_ALL_ACCESS.0 {
            saw_user_full = true;
        }
    }
    assert!(
        saw_user_full,
        "state file {} must carry the inherited user-only full-access ACE",
        path.display()
    );
}

#[test]
fn user_restricted_attributes_carry_a_valid_dacl() {
    let built = with_user_restricted_attributes(FILE_ALL_ACCESS.0, |attributes| {
        assert!(!attributes.is_null());
        // SAFETY: `attributes` is the valid, alive pointer built by
        // `with_user_restricted_attributes` for the duration of this closure;
        // the descriptor it references is initialized.
        let security = unsafe { &*attributes };
        assert_eq!(
            security.nLength,
            std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32
        );
        assert_eq!(security.bInheritHandle, BOOL(0));
        assert!(!security.lpSecurityDescriptor.is_null());
        let descriptor = PSECURITY_DESCRIPTOR(security.lpSecurityDescriptor);
        // SAFETY: `descriptor` is the initialized, alive security descriptor
        // built by the helper; the Win32 validators read it without modifying
        // it.
        unsafe {
            assert!(IsValidSecurityDescriptor(descriptor).as_bool());
            let mut dacl_present = BOOL(0);
            let mut dacl = std::ptr::null_mut();
            let mut dacl_defaulted = BOOL(0);
            assert!(
                GetSecurityDescriptorDacl(
                    descriptor,
                    &mut dacl_present,
                    &mut dacl,
                    &mut dacl_defaulted,
                )
                .is_ok()
            );
            assert!(dacl_present.as_bool(), "DACL must be present");
            assert!(!dacl.is_null(), "DACL must be non-null");
        }
    });
    assert!(
        built.is_some(),
        "user-restricted attributes must be buildable"
    );
}

#[test]
fn save_creates_state_and_config_dirs_with_user_only_dacl() {
    with_appdata(|| {
        // The first save must create the state and config dirs and restrict
        // both to the current user before any state file lands in them.
        save_state("servers.json", &ServersFile::default()).expect("save creates secured dirs");
        for dir in [
            crate::sys::paths::state_dir(),
            crate::sys::paths::config_dir(),
        ] {
            assert!(dir.is_dir(), "{} must exist", dir.display());
            assert_user_only_dacl(&dir);
        }
        // The freshly created state file inherits the user-only ACE and is
        // never world-readable (acceptance: ACL on a freshly created state
        // file).
        assert_state_file_user_only(&state_file("servers.json"));
    });
}

/// Every root `ensure_dirs` creates must carry
/// the user-only, inheritable, protected DACL from its first byte — plain
/// `create_dir_all` no longer produces unprotected roots, so no flow (fresh
/// install, error-blocked session, config apply) can land a credential file
/// under the inherited `%APPDATA%` ACLs.
#[test]
fn ensure_dirs_creates_every_root_with_user_only_dacl() {
    with_appdata(|| {
        crate::sys::paths::ensure_dirs().expect("create secured dirs");
        for dir in [
            crate::sys::paths::core_dir(),
            crate::sys::paths::config_dir(),
            crate::sys::paths::state_dir(),
            crate::sys::paths::logs_dir(),
        ] {
            assert!(dir.is_dir(), "{} must exist", dir.display());
            assert_user_only_dacl(&dir);
        }
    });
}

/// Re-running `ensure_dirs` must be effect-free — the protected
/// DACL shape is re-applied idempotently, never double-accumulated (still
/// exactly one ACE, still protected) and never an error.
#[test]
fn ensure_dirs_second_run_is_idempotent() {
    with_appdata(|| {
        crate::sys::paths::ensure_dirs().expect("first run");
        crate::sys::paths::ensure_dirs().expect("second run must not fail");
        for dir in [
            crate::sys::paths::core_dir(),
            crate::sys::paths::config_dir(),
            crate::sys::paths::state_dir(),
            crate::sys::paths::logs_dir(),
        ] {
            assert_user_only_dacl(&dir);
        }
    });
}

/// A pre-existing root created by an older release under the
/// inherited `%APPDATA%` ACL (not protected, not `SE_DACL_PROTECTED`) must
/// be hardened by the next `ensure_dirs` run.
#[test]
fn ensure_dirs_hardens_pre_existing_unprotected_roots() {
    with_appdata(|| {
        // Simulate an older release: plain `create_dir_all`, no DACL step.
        // The dirs inherit whatever the temp root's ACL grants and carry no
        // `SE_DACL_PROTECTED` protection — i.e. not the user-only shape.
        for dir in [
            crate::sys::paths::core_dir(),
            crate::sys::paths::config_dir(),
            crate::sys::paths::state_dir(),
            crate::sys::paths::logs_dir(),
        ] {
            std::fs::create_dir_all(&dir).expect("create unprotected root");
            let (_bytes, _descriptor, _dacl, control) = read_dacl(&dir);
            assert!(
                !control.contains(SE_DACL_PROTECTED),
                "precondition: {} must start unprotected",
                dir.display()
            );
        }
        crate::sys::paths::ensure_dirs().expect("hardening run");
        for dir in [
            crate::sys::paths::core_dir(),
            crate::sys::paths::config_dir(),
            crate::sys::paths::state_dir(),
            crate::sys::paths::logs_dir(),
        ] {
            assert_user_only_dacl(&dir);
        }
    });
}

/// A config written through the real apply/write path
/// (`rt::apply::write_candidate`/`commit`, the flow the shell drives after
/// startup `ensure_dirs`) must land in a user-only config dir and inherit
/// the user-only ACE onto the file itself.
#[test]
fn config_written_through_the_apply_path_is_user_only() {
    with_appdata(|| {
        crate::sys::paths::ensure_dirs().expect("create secured dirs");
        let config = serde_json::json!({
            "log": {"loglevel": "warning"},
            "api": {"tag": "api", "listen": "127.0.0.1:0", "services": ["StatsService"]},
            "inbounds": [],
            "outbounds": [{"protocol": "freedom"}],
        });
        let candidate = crate::rt::apply::write_candidate(&config).expect("write candidate config");
        assert!(
            candidate.starts_with(crate::sys::paths::config_dir()),
            "candidate must live in the config dir"
        );
        assert_user_only_dacl(&crate::sys::paths::config_dir());
        assert_state_file_user_only(&candidate);
        crate::rt::apply::commit().expect("commit the candidate config");
        assert_state_file_user_only(&crate::sys::paths::config_dir().join("config.json"));
    });
}

// ---------- wipe-then-delete of `.broken-*` quarantines ----------

/// A corrupt load must leave no plaintext quarantine: the renamed `.broken-*`
/// copy is zeroed and deleted. The zeroing step itself is unit-tested here;
/// the deletion is covered by `wipe_and_delete_removes_the_file`.
#[test]
fn zero_file_overwrites_content_with_zeros() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("servers.json.broken-123");
    let known = b"wireguard-private-key + server passwords".as_slice();
    std::fs::write(&path, known).expect("write fixture");
    zero_file(&path).expect("zero the file");
    assert_eq!(
        std::fs::read(&path).expect("read back zeroed file"),
        vec![0u8; known.len()],
        "the content must be overwritten with zeros, length preserved"
    );
}

#[test]
fn wipe_and_delete_removes_the_file() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("settings.json.broken-123");
    std::fs::write(&path, b"server profiles with secrets").expect("write fixture");
    wipe_and_delete(&path).expect("wipe-then-delete");
    assert!(!path.exists(), "the wiped quarantine must be gone");
    // A missing file is success: nothing to wipe or delete.
    wipe_and_delete(&path).expect("missing file is a no-op");
}

#[test]
fn corrupt_state_load_wipes_the_quarantine() {
    with_appdata(|| {
        crate::sys::paths::ensure_dirs().expect("create dirs");
        let path = state_file("servers.json");
        std::fs::write(&path, b"{ corrupt server profiles with secrets")
            .expect("write corrupt state");
        let loaded: ServersFile = load_state("servers.json")
            .expect("structural corruption must quarantine and fall back to defaults");
        assert!(
            loaded.profiles.is_empty() && loaded.active.is_none(),
            "corrupt state must fall back to defaults"
        );
        assert!(!path.exists(), "the corrupt live file must not remain");
        // No `.broken-*` plaintext copy may remain on disk.
        let leftovers: Vec<_> = std::fs::read_dir(crate::sys::paths::state_dir())
            .expect("read state dir")
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().contains(".broken-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "no .broken-* quarantine may remain, found: {leftovers:?}"
        );
    });
}

#[test]
fn unknown_enum_value_in_servers_errors_with_file_intact() {
    with_appdata(|| {
        crate::sys::paths::ensure_dirs().expect("create dirs");
        let path = state_file("servers.json");
        // Valid JSON, but the transport is a typo'd/whitespace value. The old
        // lenient parser silently switched it to raw; it must now fail the
        // load naming the field and the value.
        let bad = br#"{"version":1,"profiles":[{"id":"a","outbound":{"protocol":"vless","streamSettings":{"network":"xhttp "}}}]}"#;
        std::fs::write(&path, bad).expect("write state with unknown network");
        let original = std::fs::read(&path).expect("read back state");

        let error = load_state::<ServersFile>("servers.json")
            .expect_err("unknown network value must fail the load");
        let message = format!("{error}");
        assert!(message.contains("network"), "names the field: {message}");
        assert!(message.contains("xhttp "), "names the value: {message}");

        // The file stays byte-for-byte intact — no rename, no wipe, no
        // quarantine (older broccoli must not destroy newer broccoli's
        // state).
        assert_eq!(
            std::fs::read(&path).expect("read back state"),
            original,
            "the state file must not be touched by a semantic failure"
        );
        // Same contract for a typo'd `security` value: fail naming the field
        // and value, leave the file intact (no plaintext downgrade).
        let bad_security =
            br#"{"version":1,"profiles":[{"id":"a","outbound":{"protocol":"vless","streamSettings":{"network":"tcp","security":"tls "}}}]}"#;
        std::fs::write(&path, bad_security).expect("write state with unknown security");
        let security_original = std::fs::read(&path).expect("read back state");
        let error = load_state::<ServersFile>("servers.json")
            .expect_err("unknown security value must fail the load");
        let message = format!("{error}");
        assert!(message.contains("security"), "names the field: {message}");
        assert!(message.contains("tls "), "names the value: {message}");
        assert_eq!(
            std::fs::read(&path).expect("read back state"),
            security_original,
            "the state file must not be touched by a semantic failure"
        );
        let leftovers: Vec<_> = std::fs::read_dir(crate::sys::paths::state_dir())
            .expect("read state dir")
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().contains(".broken-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "no .broken-* quarantine may be created, found: {leftovers:?}"
        );
    });
}

#[test]
fn unknown_enum_value_in_settings_errors_with_file_intact() {
    with_appdata(|| {
        crate::sys::paths::ensure_dirs().expect("create dirs");
        let path = state_file("settings.json");
        // Any serde data error on valid JSON — here an unknown `mode` variant —
        // must fail the load without touching the file.
        let bad = br#"{"mode":"turbo","socks":{}}"#;
        std::fs::write(&path, bad).expect("write settings with unknown mode");
        let original = std::fs::read(&path).expect("read back settings");

        let error = load_state::<Settings>("settings.json")
            .expect_err("unknown mode value must fail the load");
        let message = format!("{error}");
        assert!(message.contains("mode"), "names the field: {message}");
        assert!(message.contains("turbo"), "names the value: {message}");

        assert_eq!(
            std::fs::read(&path).expect("read back settings"),
            original,
            "settings.json must not be touched by a semantic failure"
        );
    });
}

/// A multi-MB hostile token hand-edited into a state file
/// must not echo verbatim into the semantic error — the general load path
/// applies the 48-char excerpt convention (the same helper the custom
/// visitors use, no duplicated constant) before the message can reach the
/// rotating log or the top-bar label. The full field path and the error code
/// survive; the token does not.
#[test]
fn state_load_semantic_error_excerpts_hostile_tokens() {
    with_appdata(|| {
        crate::sys::paths::ensure_dirs().expect("create dirs");
        let path = state_file("settings.json");
        let hostile = "z".repeat(4 << 20);
        let document = format!(r#"{{"mode": "{hostile}"}}"#);
        std::fs::write(&path, &document).expect("write hostile settings state");

        let error = load_state::<Settings>("settings.json")
            .expect_err("hostile mode value must fail the load");
        let message = format!("{error}");
        // The full field path and the error code survive.
        assert!(
            message.starts_with("mode: "),
            "must keep the full field path: {message}"
        );
        assert!(
            message.contains("unknown variant"),
            "must keep the error code: {message}"
        );
        // The message must be exactly the full path plus the shared excerpt
        // helper's output over the raw serde error text — same helper, no
        // duplicated constant, so the byte bound is the helper's by
        // construction. The raw text is recovered by parsing the same
        // document without the path wrapper.
        let raw: Result<Settings, _> = serde_json::from_str(&document);
        let raw_text = raw
            .expect_err("the hostile document must fail a plain parse")
            .to_string();
        assert!(
            raw_text.len() > 4096,
            "precondition: the raw error text must itself be oversized"
        );
        let expected = format!("mode: {}", excerpt(&raw_text));
        assert_eq!(message, expected, "semantic message must be path + excerpt");
        assert!(
            !message.contains(&"z".repeat(64)),
            "token beyond the excerpt must not be echoed"
        );

        // The same bounded message is the only unbounded input of the two
        // surfaces that echo it — the rotating log line and the top-bar
        // label embed the message verbatim — so the composed lines are
        // byte-bounded too (asserted far below any echoed-token size).
        let log_line =
            format!("settings.json is valid JSON but could not be loaded (left intact): {message}");
        assert!(
            log_line.len() < 1024,
            "log line must stay byte-bounded, got {} bytes",
            log_line.len()
        );
        let label = crate::i18n::t_fmt(
            crate::model::settings::Language::En,
            crate::i18n::Key::StateFileLoadFailed,
            &[&"settings.json", &message],
        );
        assert!(
            label.len() < 1024,
            "rendered label text must stay byte-bounded, got {} bytes",
            label.len()
        );
    });
}

/// Nested: a multi-MB hostile token under a wrapper chain
/// (constant prefixes push serde's own unbounded unknown-variant echo past
/// the head) must still land byte-bounded and echo nothing beyond the
/// excerpt — shape-agnostic, since derived-enum vs custom-visitor parsing
/// decides which bound applies.
#[test]
fn nested_hostile_token_loads_land_bounded_without_echo() {
    with_appdata(|| {
        crate::sys::paths::ensure_dirs().expect("create dirs");
        let path = state_file("servers.json");
        let hostile = "q".repeat(4 << 20);
        let document = format!(
            r#"{{"version":1,"profiles":[{{"id":"a","outbound":{{"protocol":"{hostile}"}}}}]}}"#
        );
        std::fs::write(&path, &document).expect("write hostile nested state");

        let error = load_state::<ServersFile>("servers.json")
            .expect_err("hostile nested value must fail the load");
        let message = format!("{error}");
        assert!(
            message.contains("protocol") || message.contains("outbound"),
            "the field location must survive: {message}"
        );
        assert!(
            !message.contains(&"q".repeat(64)),
            "nested token beyond the excerpt must never echo: {message}"
        );
        assert!(
            message.len() < 1024,
            "nested hostile message must stay byte-bounded, got {} bytes",
            message.len()
        );
    });
}

#[test]
fn valid_state_files_load_unchanged() {
    with_appdata(|| {
        crate::sys::paths::ensure_dirs().expect("create dirs");
        // A server profile exercising the transport enums end-to-end.
        let mut servers = ServersFile::default();
        let mut outbound = OutboundModel::new(Protocol::Vless);
        outbound.stream.network = Network::Xhttp;
        outbound.stream.security = Security::Tls;
        outbound.stream.tls_settings = Some(TlsModel {
            server_name: "cdn.example.com".into(),
            ..Default::default()
        });
        servers.profiles.push(ServerProfile::new("valid", outbound));
        servers.save().expect("save servers.json");

        let mut settings = Settings::default();
        settings.set_mode(Mode::Tun);
        settings.save().expect("save settings.json");

        let loaded_servers = ServersFile::load().expect("valid servers.json must load");
        let profile = &loaded_servers.profiles[0];
        assert_eq!(profile.outbound.protocol, Protocol::Vless);
        assert_eq!(profile.outbound.stream.network, Network::Xhttp);
        assert_eq!(profile.outbound.stream.security, Security::Tls);
        assert_eq!(
            profile
                .outbound
                .stream
                .tls_settings
                .as_ref()
                .map(|tls| tls.server_name.as_str()),
            Some("cdn.example.com")
        );
        let loaded_settings = Settings::load().expect("valid settings.json must load");
        assert_eq!(loaded_settings.mode, Mode::Tun);
        assert_eq!(
            serde_json::to_value(&loaded_settings).unwrap(),
            serde_json::to_value(&settings).unwrap(),
            "settings.json must round-trip unchanged"
        );
    });
}

#[test]
fn activating_a_profile_moves_it_to_the_front_of_the_list() {
    let mut servers = ServersFile {
        version: 1,
        active: Some("a".into()),
        profiles: ["a", "b", "c"]
            .into_iter()
            .map(|id| ServerProfile {
                id: id.into(),
                outbound: OutboundModel::new(Protocol::Freedom),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    };
    let ids = |servers: &ServersFile| -> Vec<String> {
        servers
            .profiles
            .iter()
            .map(|profile| profile.id.clone())
            .collect()
    };

    servers.activate("c");
    assert_eq!(ids(&servers), ["c", "a", "b"], "the choice leads the list");
    assert_eq!(servers.active.as_deref(), Some("c"));

    // Re-activating the profile already in the slot changes nothing.
    servers.activate("c");
    assert_eq!(ids(&servers), ["c", "a", "b"]);

    // An id naming no profile is ignored — the old-choice tests rely on the
    // profile-set validation reporting it — and never drops the slot.
    servers.activate("missing");
    assert_eq!(ids(&servers), ["c", "a", "b"]);
    assert_eq!(servers.active.as_deref(), Some("c"));
}

#[test]
fn loading_servers_keeps_the_default_server_in_the_first_slot() {
    with_appdata(|| {
        crate::sys::paths::ensure_dirs().expect("create dirs");
        // A file written before the top-row rule: `active` names a middle
        // profile while the list leads with another.
        let mut servers = ServersFile::default();
        for name in ["first", "default", "third"] {
            servers.profiles.push(ServerProfile::new(
                name,
                OutboundModel::new(Protocol::Freedom),
            ));
        }
        servers.active = Some(servers.profiles[1].id.clone());
        servers.save().expect("save servers.json");

        let loaded = ServersFile::load().expect("servers.json must load");
        let names: Vec<&str> = loaded.profiles.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            ["default", "first", "third"],
            "the named default moves to the front instead of the default route changing"
        );
        assert_eq!(
            loaded.active.as_deref(),
            Some(loaded.profiles[0].id.as_str()),
            "the active slot names the first profile"
        );

        // A file with profiles but no choice gains the default its config
        // already had: the first row.
        let mut servers = ServersFile::default();
        for name in ["first", "second"] {
            servers.profiles.push(ServerProfile::new(
                name,
                OutboundModel::new(Protocol::Freedom),
            ));
        }
        servers.save().expect("save servers.json without a choice");
        let loaded = ServersFile::load().expect("servers.json must load");
        assert_eq!(
            loaded.active.as_deref(),
            Some(loaded.profiles[0].id.as_str()),
            "an empty active slot defaults to the first row"
        );
    });
}

// ---------- atomic write cleanup ----------

/// A failed save must not leave `<file>.tmp` behind: it carries the full
/// plaintext state (profiles, secrets).
#[test]
fn failed_atomic_state_write_removes_the_temp_file() {
    let dir = tempfile::tempdir().expect("temp dir");
    // A directory at the target name makes the final rename fail on Windows
    // (a file cannot replace a directory) after the temp file has been
    // created, written, and flushed.
    let target = dir.path().join("servers.json");
    std::fs::create_dir(&target).expect("create the blocking directory");

    let result = write_state_atomic(&target, b"{}");
    assert!(result.is_err(), "renaming onto a directory must fail");
    assert!(
        !dir.path().join("servers.json.tmp").exists(),
        "the failed write must not leave the temp file behind"
    );
}
