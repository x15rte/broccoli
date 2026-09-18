//! Server profiles (GUI state: %APPDATA%\broccoli\state\servers.json).

use super::outbound::{OutboundModel, ProtocolSettings};
use super::{StateLoadError, load_state, save_state, skip_empty_vec};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ServersFile {
    pub version: u32,
    /// id of the active profile
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<String>,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub profiles: Vec<ServerProfile>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for ServersFile {
    fn default() -> Self {
        Self {
            version: 1,
            active: None,
            profiles: Vec::new(),
            extra: Map::new(),
        }
    }
}

impl ServersFile {
    /// Load servers.json. Missing or structurally corrupt files fall back to
    /// `Default` (the corrupt file is quarantined); a
    /// semantically invalid file (valid JSON, bad content — e.g. an unknown
    /// `security`/`network` value) returns an error naming the field and is
    /// left intact for the user to fix.
    pub fn load() -> Result<Self, StateLoadError> {
        let mut servers: Self = load_state("servers.json")?;
        // The active (default) profile is the list's first entry — see
        // [`Self::activate`]. A file written before that rule (or hand-edited)
        // still names its default route in `active`, so that row moves to the
        // front instead of the default route silently changing under it; the
        // emitted config is byte-for-byte the same order the old pinning
        // produced. A file with profiles but no active choice gains the
        // default its config already had: the first row.
        match servers.active.clone() {
            Some(id) => servers.activate(&id),
            None => servers.active = servers.profiles.first().map(|p| p.id.clone()),
        }
        Ok(servers)
    }
    /// Atomic save (tmp + rename).
    pub fn save(&self) -> anyhow::Result<()> {
        save_state("servers.json", self)
    }
    pub fn active_profile(&self) -> Option<&ServerProfile> {
        let id = self.active.as_deref()?;
        self.profiles.iter().find(|p| p.id == id)
    }
    /// Make `id` the active (default) profile by moving it to the front of
    /// the list.
    ///
    /// The list order is the outbound order [`generate`](crate::gen::generate)
    /// emits, and Xray's default route is the first outbound, so the default
    /// server is always `profiles[0]`: this method — the only writer of
    /// `active` that moves rows — keeps the marker and the default route the
    /// same server. An id naming no profile is ignored (the profile-set
    /// validation reports it), leaving `active` untouched.
    pub fn activate(&mut self, id: &str) {
        let Some(index) = self.profiles.iter().position(|profile| profile.id == id) else {
            return;
        };
        if index > 0 {
            let profile = self.profiles.remove(index);
            self.profiles.insert(0, profile);
        }
        self.active = Some(id.to_owned());
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ServerProfile {
    pub id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    pub outbound: OutboundModel,
    /// last measured latency — runtime cache, never persisted
    #[serde(skip)]
    pub latency_ms: Option<i64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl ServerProfile {
    pub fn new(name: impl Into<String>, outbound: OutboundModel) -> Self {
        Self {
            id: uuid::Uuid::new_v4().simple().to_string(),
            name: name.into(),
            outbound,
            latency_ms: None,
            extra: Map::new(),
        }
    }
    /// `srv-<id8>` — outbound tag used in generated configs, routing and stats.
    pub fn tag(&self) -> String {
        let end = self
            .id
            .char_indices()
            .nth(8)
            .map_or(self.id.len(), |(index, _)| index);
        format!("srv-{}", &self.id[..end])
    }
    /// The outbound tag this profile dials through, if any —
    /// `streamSettings.sockopt.dialerProxy`, the one spelling the pinned core
    /// still reads. Validation rejects a chain target naming no outbound.
    pub fn chain_target(&self) -> Option<&str> {
        self.outbound
            .stream
            .sockopt
            .as_ref()
            .map(|sockopt| sockopt.dialer_proxy.as_str())
            .filter(|tag| !tag.is_empty())
    }
    /// The remote server endpoint as `host:port` (IPv6 bracketed), or `None`
    /// when the protocol carries no usable address. WireGuard's endpoint is
    /// its first peer's non-empty `endpoint` string, returned verbatim (not
    /// re-formatted or port-checked); protocols without a server address
    /// (freedom, blackhole, dns, loopback) yield `None`.
    pub fn server_address(&self) -> Option<String> {
        let (address, port) = match &self.outbound.settings {
            ProtocolSettings::Vless(settings) => (&settings.address, settings.port),
            ProtocolSettings::Vmess(settings) => (&settings.address, settings.port),
            ProtocolSettings::Trojan(settings) => (&settings.address, settings.port),
            ProtocolSettings::Shadowsocks(settings) => (&settings.address, settings.port),
            ProtocolSettings::Socks(settings) => (&settings.address, settings.port),
            ProtocolSettings::Http(settings) => (&settings.address, settings.port),
            ProtocolSettings::Hysteria(settings) => (&settings.address, settings.port),
            ProtocolSettings::Wireguard(settings) => {
                let endpoint = settings
                    .peers
                    .iter()
                    .find_map(|peer| (!peer.endpoint.is_empty()).then_some(peer.endpoint.as_str()));
                return endpoint.map(str::to_owned);
            }
            ProtocolSettings::Freedom(_)
            | ProtocolSettings::Blackhole(_)
            | ProtocolSettings::Dns(_)
            | ProtocolSettings::Loopback(_) => return None,
        };
        if address.is_empty() || port == 0 {
            return None;
        }
        Some(if address.contains(':') {
            format!("[{address}]:{port}")
        } else {
            format!("{address}:{port}")
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::outbound::{OutboundModel, Protocol, ProtocolSettings};

    fn profile_with_address(address: &str, port: u16) -> ServerProfile {
        let mut profile = ServerProfile::new("srv", OutboundModel::new(Protocol::Vless));
        let ProtocolSettings::Vless(settings) = &mut profile.outbound.settings else {
            unreachable!("Vless is the default protocol");
        };
        settings.address = address.into();
        settings.port = port;
        profile
    }

    #[test]
    fn server_address_formats_host_port_and_brackets_ipv6() {
        assert_eq!(
            profile_with_address("1.2.3.4", 443)
                .server_address()
                .as_deref(),
            Some("1.2.3.4:443")
        );
        assert_eq!(
            profile_with_address("2001:db8::1", 443)
                .server_address()
                .as_deref(),
            Some("[2001:db8::1]:443")
        );
    }

    #[test]
    fn server_address_omitted_when_host_or_port_unusable() {
        assert_eq!(profile_with_address("", 443).server_address(), None);
        assert_eq!(profile_with_address("1.2.3.4", 0).server_address(), None);
        let freedom = ServerProfile::new("direct", OutboundModel::new(Protocol::Freedom));
        assert_eq!(freedom.server_address(), None);
    }

    #[test]
    fn chain_target_reads_the_dialer_proxy_spelling_only() {
        let mut profile = ServerProfile::new("hop", OutboundModel::new(Protocol::Freedom));
        assert_eq!(profile.chain_target(), None);
        profile.outbound.chain_via("srv-exit");
        assert_eq!(profile.chain_target(), Some("srv-exit"));
        // An empty value is no chain.
        if let Some(sockopt) = profile.outbound.stream.sockopt.as_mut() {
            sockopt.dialer_proxy.clear();
        }
        assert_eq!(profile.chain_target(), None);
    }

    #[test]
    fn stored_retired_proxy_settings_key_survives_an_unrelated_save_and_the_gate() {
        use crate::model::validation::{Severity, ValidationCode, validate_profiles};
        use crate::sys::appdata::with_appdata;

        with_appdata(|| {
            // A stored profile from a build that still used the retired key:
            // Xray refuses to build it now, and the model must not fail the
            // load over it.
            let stored = serde_json::json!({
                "version": 1,
                "active": "aaaaaaaa11111111",
                "profiles": [{
                    "id": "aaaaaaaa11111111",
                    "name": "hop",
                    "outbound": {"protocol": "freedom", "proxySettings": {"tag": "srv-exit"}}
                }]
            });
            save_state("servers.json", &stored).expect("write the stored file");

            let mut servers = ServersFile::load().expect("a retired key must not fail the load");
            assert_eq!(
                servers.profiles[0].outbound.retired_proxy_settings,
                Some(serde_json::json!({"tag": "srv-exit"}))
            );
            assert_eq!(
                servers.profiles[0].chain_target(),
                None,
                "the retired key is never converted into a chain"
            );
            let gated = |servers: &ServersFile| {
                validate_profiles(&servers.profiles, servers.active.as_deref(), false)
                    .iter()
                    .any(|issue| {
                        issue.code == ValidationCode::OutboundProxySettingsRemoved
                            && issue.severity == Severity::Error
                    })
            };
            assert!(gated(&servers), "the profile must gate until resolved");

            // An unrelated edit (the display name) saves the file and the
            // gate survives the reload: the key stays on disk until the user
            // resolves the profile.
            servers.profiles[0].name = "hop-renamed".into();
            servers.save().expect("save servers.json");
            let saved: Value = load_state("servers.json").expect("reload the saved file");
            assert_eq!(
                saved["profiles"][0]["outbound"]["proxySettings"],
                serde_json::json!({"tag": "srv-exit"}),
                "an unrelated save must keep the retired key: {saved}"
            );
            let reloaded = ServersFile::load().expect("reload the saved file");
            assert_eq!(reloaded.profiles[0].name, "hop-renamed");
            assert!(gated(&reloaded), "the gate must survive the reload");

            // A duplicated profile inherits the raw key (the list's Duplicate
            // action clones the stored profile): the copy stays gated and its
            // saved file carries the key until the user resolves it.
            let mut duplicated = reloaded.clone();
            let mut copy = duplicated.profiles[0].clone();
            copy.id = "cccccccc33333333".into();
            copy.name = "hop copy".into();
            duplicated.profiles.push(copy);
            assert!(gated(&duplicated), "the copy must stay gated");
            duplicated.save().expect("save the duplicated profile set");
            let saved: Value = load_state("servers.json").expect("reload the saved file");
            assert_eq!(
                saved["profiles"][1]["outbound"]["proxySettings"],
                serde_json::json!({"tag": "srv-exit"}),
                "the copy's file must keep the retired key: {saved}"
            );

            // The user resolves the chain — the editor clears the key — and
            // the next save drops it.
            let mut resolved = reloaded;
            resolved.profiles[0].outbound.chain_via("srv-exit");
            resolved.profiles[0].outbound.retired_proxy_settings = None;
            resolved.save().expect("save servers.json");
            let saved: Value = load_state("servers.json").expect("reload the saved file");
            assert_eq!(
                saved["profiles"][0]["outbound"]["streamSettings"]["sockopt"]["dialerProxy"],
                serde_json::json!("srv-exit")
            );
            let key_present =
                saved["profiles"][0]["outbound"]
                    .as_object()
                    .is_some_and(|outbound| {
                        outbound
                            .keys()
                            .any(|key| key.eq_ignore_ascii_case("proxySettings"))
                    });
            assert!(
                !key_present,
                "the resolved profile must drop the key: {saved}"
            );
            let reloaded = ServersFile::load().expect("reload the saved file");
            assert_eq!(reloaded.profiles[0].chain_target(), Some("srv-exit"));
            assert!(
                reloaded.profiles[0]
                    .outbound
                    .retired_proxy_settings
                    .is_none()
            );
        });
    }

    #[test]
    fn server_address_wireguard_takes_first_peer_endpoint() {
        let mut profile = ServerProfile::new("wg", OutboundModel::new(Protocol::Wireguard));
        {
            let ProtocolSettings::Wireguard(settings) = &mut profile.outbound.settings else {
                unreachable!();
            };
            settings.peers.push(crate::model::outbound::WireguardPeer {
                endpoint: "10.9.0.1:51820".into(),
                ..Default::default()
            });
        }
        assert_eq!(profile.server_address().as_deref(), Some("10.9.0.1:51820"));
        {
            let ProtocolSettings::Wireguard(settings) = &mut profile.outbound.settings else {
                unreachable!();
            };
            settings.peers[0].endpoint.clear();
        }
        assert_eq!(profile.server_address(), None);
    }
}
