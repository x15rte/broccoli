//! The servers screen's helper-tool session: the one in-flight helper run,
//! and the two stages that turn its stdout into a profile edit.
//!
//! One session per screen owns the job slot, so "another helper is already
//! running" has one definition, and the tab renderers and the derive dialog
//! only call [`ToolSession::request`] or read [`ToolSession::is_running`] —
//! neither sees the request or the slot. [`ToolSession::take_terminal`] drops
//! a delivered result whose draft target is no longer open before anything
//! parses it, so a verdict never lands in a draft it was not staged from.
//!
//! The output is handled in two stages so neither absorbs the other's work:
//! [`parse`] extracts and validates the value from the helper's stdout and
//! touches no profile and no screen state; [`apply`] writes a prepared value
//! into one profile through the model's generated-secret path or the field's
//! own, and answers with what the caller presents ([`Applied`]). A probe
//! output yields its handshake verdict and pins instead of writing a profile,
//! which is why [`apply`] takes an optional profile: probe verdicts have none.

use std::sync::atomic::Ordering;

use crate::diag::Diag;
use crate::i18n::{Key, t, t_fmt};
use crate::model::ServerProfile;
use crate::model::outbound::GeneratedSecret;
use crate::model::settings::Language;
use crate::model::validation::{
    pinned_peer_cert_sha256_valid, reality_mldsa65_verify_valid, reality_public_key_valid,
};
use crate::rt::ToolTarget;
use crate::tls_ping::{ca_pins_from_probe_output, leaf_pin_from_probe_output};
use crate::ui::request::{Request, Terminal};

use super::keygen::{PRIV_PREFIXES, PUB_PREFIXES, keygen_value};
use super::validators::{v_uuid, v_vless_encryption, v_wg_secret_key};
use super::xray_tool::{self, XrayToolKind};

/// The screen's one helper-tool session: at most one run in flight, and the
/// stale-target filter every delivered result passes.
#[derive(Default)]
pub(super) struct ToolSession {
    job: Option<ToolJob>,
}

/// The single in-flight run: what it is for, and the request carrying its
/// stdout or the adapter's error. The request is the only owner of the worker
/// thread, so dropping the session cancels a run that never lands.
struct ToolJob {
    target: ToolTarget,
    kind: XrayToolKind,
    request: Request<Result<String, String>>,
}

/// One finished helper run, still keyed by what it was for: the draft target
/// the result is applied to and the verb whose output it is.
pub(super) struct ToolRun {
    pub(super) target: ToolTarget,
    pub(super) kind: XrayToolKind,
    pub(super) outcome: ToolOutcome,
}

/// The producer's terminal, as the screen presents it.
pub(super) enum ToolOutcome {
    /// The adapter answered: its stdout, or the error it rendered.
    Answered(Result<String, String>),
    /// The worker exited without a terminal.
    Exited,
}

impl ToolSession {
    /// Whether a helper run holds the slot. The controls that cannot start
    /// another run read this instead of the job.
    pub(super) fn is_running(&self) -> bool {
        self.job.is_some()
    }

    /// Start `kind` against `target` off the UI thread. Refuses while another
    /// run holds the slot, so the single-flight rule lives here rather than at
    /// each button.
    ///
    /// The cooperative stop flag ends a cancelled run: the verb's adapter
    /// abandons its work on the same flag, and a verdict for a cancelled
    /// request is dropped instead of delivered, so the stale-target filter
    /// never sees it.
    pub(super) fn request(
        &mut self,
        kind: XrayToolKind,
        target: ToolTarget,
        args: Vec<String>,
        repaint: egui::Context,
        lang: Language,
    ) -> Result<(), String> {
        if self.job.is_some() {
            return Err(t(lang, Key::SrvAnotherToolRunning).into());
        }
        let request = Request::worker("broccoli-xray-tool", &repaint, move |stop| {
            if stop.load(Ordering::Acquire) {
                return None;
            }
            let result = xray_tool::run(kind, lang, &args, stop);
            if stop.load(Ordering::Acquire) {
                return None;
            }
            Some(result)
        })
        .map_err(|error| t_fmt(lang, Key::SrvSpawnToolFailed, &[&error]))?;
        self.job = Some(ToolJob {
            target,
            kind,
            request,
        });
        Ok(())
    }

    /// Poll the slot. A delivered result is handed back once, and only while
    /// `is_current` still names its target: a result for a draft that was
    /// edited, replaced or closed since the request went out is dropped here,
    /// before its payload is parsed.
    pub(super) fn take_terminal(
        &mut self,
        is_current: impl Fn(&ToolTarget) -> bool,
    ) -> Option<ToolRun> {
        let terminal = self.job.as_mut()?.request.poll()?;
        let job = self.job.take()?;
        if !is_current(&job.target) {
            return None;
        }
        let outcome = match terminal {
            Terminal::Answered(result) => ToolOutcome::Answered(result),
            Terminal::Exited => ToolOutcome::Exited,
        };
        Some(ToolRun {
            target: job.target,
            kind: job.kind,
            outcome,
        })
    }
}

/// A helper value that passed extraction and format validation: everything
/// the write stage needs, and nothing about the profile it will land in.
pub(super) enum Prepared {
    /// One generated-secret slot and the value that fills it.
    Secret {
        secret: GeneratedSecret,
        value: String,
    },
    /// The REALITY ML-DSA-65 verify key.
    Mldsa65Verify(String),
    /// The leaf pin computed from a certificate file.
    LeafPin(String),
    /// A completed TLS handshake: the raw transcript and the pins it carried.
    Probe(ProbeReport),
    /// The REALITY x25519 public key.
    RealityPublicKey(String),
}

/// One probe transcript's handshake verdict: the raw output the probe panel
/// shows, plus the pins parsed out of it.
pub(super) struct ProbeReport {
    pub(super) output: String,
    pub(super) leaf_pin: Option<String>,
    pub(super) ca_pins: Vec<(String, String)>,
}

/// What one write stage did, as the caller presents it. The screen routes each
/// case to the surface it belongs to (status line, probe panel, derive dialog)
/// and bumps the draft generation where a profile changed.
pub(super) enum Applied {
    /// A generated value landed in the profile's own field; the status line
    /// shows the notice.
    Field(String),
    /// A leaf pin landed; the probe panel's output window shows the notice.
    LeafPin { output: String },
    /// A probe's verdict and pins for the probe panel; no profile changed.
    Probe(ProbeReport),
    /// The REALITY public key landed; the derive dialog closes and the status
    /// line shows the notice.
    RealityPublicKey(String),
}

/// Extract and validate the value one helper output carries. This stage reads
/// the adapter's stdout and the format rules only — no profile, no screen
/// state — so a malformed output is refused before anything is touched.
pub(super) fn parse(kind: XrayToolKind, output: &str, lang: Language) -> Result<Prepared, Diag> {
    match kind {
        XrayToolKind::Uuid => {
            let value = output.trim();
            if v_uuid(lang, value).is_some() {
                return Err(Diag::new(Key::SrvUuidInvalid));
            }
            Ok(Prepared::Secret {
                secret: GeneratedSecret::Id,
                value: value.to_owned(),
            })
        }
        XrayToolKind::VlessEncryption => {
            let Some(value) = keygen_value(output, &["\"encryption\":"]) else {
                return Err(Diag::new(Key::SrvVlessencNoValue));
            };
            let value = value.trim_matches('"');
            if v_vless_encryption(lang, value).is_some() {
                return Err(Diag::new(Key::SrvVlessencInvalid));
            }
            Ok(Prepared::Secret {
                secret: GeneratedSecret::VlessEncryption,
                value: value.to_owned(),
            })
        }
        XrayToolKind::WireguardSecret => {
            let Some(value) = keygen_value(output, PRIV_PREFIXES) else {
                return Err(Diag::new(Key::SrvWgCouldNotParse));
            };
            if v_wg_secret_key(lang, &value).is_some() {
                return Err(Diag::new(Key::SrvWgInvalidPrivateKey));
            }
            Ok(Prepared::Secret {
                secret: GeneratedSecret::WireguardSecretKey,
                value,
            })
        }
        XrayToolKind::Mldsa65Verify => {
            let Some(value) = keygen_value(output, &["Verify:", "verify:"]) else {
                return Err(Diag::new(Key::SrvMldsa65CouldNotParse));
            };
            if !reality_mldsa65_verify_valid(&value) {
                return Err(Diag::new(Key::SrvMldsa65InvalidKey));
            }
            Ok(Prepared::Mldsa65Verify(value))
        }
        XrayToolKind::TlsPin => {
            let Some(value) = keygen_value(output, &["Leaf SHA256:"]) else {
                return Err(Diag::new(Key::SrvTlsPinNoHash));
            };
            if !pinned_peer_cert_sha256_valid(&value) {
                return Err(Diag::new(Key::SrvTlsPinMalformed));
            }
            Ok(Prepared::LeafPin(value))
        }
        XrayToolKind::TlsPing | XrayToolKind::TlsPingQuic => {
            if !output.contains("Handshake succeeded") {
                return Err(Diag::new(Key::SrvTlsProbeNoHandshake).arg(output.trim()));
            }
            Ok(Prepared::Probe(ProbeReport {
                output: output.to_owned(),
                leaf_pin: leaf_pin_from_probe_output(output),
                ca_pins: ca_pins_from_probe_output(output),
            }))
        }
        XrayToolKind::RealityPublicKey => {
            let Some(value) = keygen_value(output, PUB_PREFIXES) else {
                return Err(Diag::new(Key::SrvX25519CouldNotParse));
            };
            if !reality_public_key_valid(&value) {
                return Err(Diag::new(Key::SrvX25519InvalidPublicKey));
            }
            Ok(Prepared::RealityPublicKey(value))
        }
    }
}

/// Write one prepared value into `profile` through the field's own path. A
/// profile that is gone is the tool-target refusal; a profile whose protocol
/// or security block has no such field is the field's own target refusal. A
/// probe verdict writes nothing and comes back as [`Applied::Probe`].
pub(super) fn apply(
    prepared: Prepared,
    profile: Option<&mut ServerProfile>,
    lang: Language,
) -> Result<Applied, Diag> {
    match prepared {
        Prepared::Secret { secret, value } => {
            let (refusal, notice) = match secret {
                GeneratedSecret::Id => (Key::SrvUuidTargetNoId, Key::SrvUuidGenerated),
                GeneratedSecret::VlessEncryption => (
                    Key::SrvVlessencTargetFieldNotFound,
                    Key::SrvClientEncryptionGenerated,
                ),
                GeneratedSecret::WireguardSecretKey => {
                    (Key::SrvWgTargetFieldNotFound, Key::SrvWgSecretGenerated)
                }
            };
            let profile = profile.ok_or_else(|| Diag::new(Key::SrvToolTargetFieldNotFound))?;
            profile
                .outbound
                .settings
                .write_generated_secret(secret, &value)
                .map_err(|()| Diag::new(refusal))?;
            Ok(Applied::Field(t(lang, notice).into()))
        }
        Prepared::Mldsa65Verify(value) => {
            let reality = reality_settings(profile, Key::SrvMldsa65TargetFieldNotFound)?;
            reality.mldsa65_verify = value;
            Ok(Applied::Field(t(lang, Key::SrvMldsa65Generated).into()))
        }
        Prepared::LeafPin(value) => {
            let profile = profile.ok_or_else(|| Diag::new(Key::SrvToolTargetFieldNotFound))?;
            let tls = profile
                .outbound
                .stream
                .tls_settings
                .as_mut()
                .ok_or_else(|| Diag::new(Key::SrvTlsPinTargetFieldNotFound))?;
            let output = t_fmt(lang, Key::SrvTlsPinComputedLeaf, &[&value]);
            tls.pinned_peer_cert_sha256 = value;
            Ok(Applied::LeafPin { output })
        }
        Prepared::Probe(report) => Ok(Applied::Probe(report)),
        Prepared::RealityPublicKey(value) => {
            let reality = reality_settings(profile, Key::SrvRealityTargetFieldNotFound)?;
            reality.password = value;
            Ok(Applied::RealityPublicKey(
                t(lang, Key::SrvRealityPubKeyDerived).into(),
            ))
        }
    }
}

/// The REALITY block a derived value writes into: a gone profile is the
/// tool-target refusal, a profile without REALITY settings is `refusal`.
fn reality_settings(
    profile: Option<&mut ServerProfile>,
    refusal: Key,
) -> Result<&mut crate::model::RealityModel, Diag> {
    profile
        .ok_or_else(|| Diag::new(Key::SrvToolTargetFieldNotFound))?
        .outbound
        .stream
        .reality_settings
        .as_mut()
        .ok_or_else(|| Diag::new(refusal))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::outbound::{Protocol, ProtocolSettings};
    use crate::model::{OutboundModel, RealityModel, TlsModel};
    use crate::ui::request::Request;
    use base64::engine::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use tokio::sync::oneshot;

    const UUID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const WG_SECRET: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    /// The unpadded base64url spelling the REALITY and VLESS grammars accept.
    fn url_key(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn encryption() -> String {
        format!("mlkem768x25519plus.native.0rtt.{}", url_key(&[1u8; 32]))
    }

    fn probe_output() -> String {
        format!(
            "Handshake succeeded\nCert's leaf SHA256:\t{PIN}\n\
             Cert's CA <Test CA> SHA256:\t{PIN}\n"
        )
    }

    fn vless() -> ServerProfile {
        ServerProfile::new("vless", OutboundModel::new(Protocol::Vless))
    }

    fn wireguard() -> ServerProfile {
        ServerProfile::new("wg", OutboundModel::new(Protocol::Wireguard))
    }

    fn trojan() -> ServerProfile {
        ServerProfile::new("trojan", OutboundModel::new(Protocol::Trojan))
    }

    fn with_tls(mut profile: ServerProfile) -> ServerProfile {
        profile.outbound.stream.tls_settings = Some(TlsModel::default());
        profile
    }

    fn with_reality(mut profile: ServerProfile) -> ServerProfile {
        profile.outbound.stream.reality_settings = Some(RealityModel::default());
        profile
    }

    fn refused(result: Result<Prepared, Diag>, key: Key) {
        let diag = result.err().expect("the output must be refused");
        assert_eq!(diag.key(), key, "the refusal is the field's own");
    }

    #[test]
    fn a_generated_uuid_applies_to_the_id_field() {
        let mut profile = vless();
        let prepared = parse(XrayToolKind::Uuid, &format!("  {UUID}\n"), Language::En)
            .expect("a canonical UUID parses");
        assert!(
            matches!(
                apply(prepared, Some(&mut profile), Language::En),
                Ok(Applied::Field(_))
            ),
            "the id write reports a field write"
        );
        match &profile.outbound.settings {
            ProtocolSettings::Vless(settings) => assert_eq!(settings.id, UUID),
            _ => panic!("the fixture is VLESS"),
        }
    }

    #[test]
    fn a_malformed_uuid_is_refused_by_key() {
        refused(
            parse(XrayToolKind::Uuid, "not-a-uuid", Language::En),
            Key::SrvUuidInvalid,
        );
    }

    #[test]
    fn a_uuid_on_a_profile_without_the_field_is_refused_by_key() {
        let mut profile = trojan();
        let prepared = parse(XrayToolKind::Uuid, UUID, Language::En).expect("the value parses");
        let diag = apply(prepared, Some(&mut profile), Language::En)
            .err()
            .expect("a Trojan profile carries no id slot");
        assert_eq!(diag.key(), Key::SrvUuidTargetNoId);
    }

    #[test]
    fn a_generated_vless_encryption_applies_to_the_encryption_field() {
        let output = format!(
            "Choose one Authentication to use.\n\"decryption\": \"server-secret\"\n\
             \"encryption\": \"{}\"\n",
            encryption()
        );
        let mut profile = vless();
        let prepared =
            parse(XrayToolKind::VlessEncryption, &output, Language::En).expect("the value parses");
        assert!(matches!(
            apply(prepared, Some(&mut profile), Language::En),
            Ok(Applied::Field(_))
        ));
        match &profile.outbound.settings {
            ProtocolSettings::Vless(settings) => assert_eq!(settings.encryption, encryption()),
            _ => panic!("the fixture is VLESS"),
        }
    }

    #[test]
    fn a_malformed_vless_encryption_is_refused_by_key() {
        refused(
            parse(
                XrayToolKind::VlessEncryption,
                "\"encryption\": \"nonsense\"",
                Language::En,
            ),
            Key::SrvVlessencInvalid,
        );
    }

    #[test]
    fn vless_encryption_on_a_profile_without_the_field_is_refused_by_key() {
        let mut profile = trojan();
        let prepared = parse(
            XrayToolKind::VlessEncryption,
            &format!("\"encryption\": \"{}\"", encryption()),
            Language::En,
        )
        .expect("the value parses");
        let diag = apply(prepared, Some(&mut profile), Language::En)
            .err()
            .expect("a Trojan profile carries no encryption slot");
        assert_eq!(diag.key(), Key::SrvVlessencTargetFieldNotFound);
    }

    #[test]
    fn a_generated_wireguard_secret_applies_to_the_secret_key_field() {
        let mut profile = wireguard();
        let prepared = parse(
            XrayToolKind::WireguardSecret,
            &format!("PrivateKey: {WG_SECRET}\n"),
            Language::En,
        )
        .expect("a 64-hex key parses");
        assert!(matches!(
            apply(prepared, Some(&mut profile), Language::En),
            Ok(Applied::Field(_))
        ));
        match &profile.outbound.settings {
            ProtocolSettings::Wireguard(settings) => assert_eq!(settings.secret_key, WG_SECRET),
            _ => panic!("the fixture is WireGuard"),
        }
    }

    #[test]
    fn a_malformed_wireguard_secret_is_refused_by_key() {
        refused(
            parse(
                XrayToolKind::WireguardSecret,
                "PrivateKey: not-a-key",
                Language::En,
            ),
            Key::SrvWgInvalidPrivateKey,
        );
    }

    #[test]
    fn a_wireguard_secret_on_a_profile_without_the_field_is_refused_by_key() {
        let mut profile = vless();
        let prepared = parse(
            XrayToolKind::WireguardSecret,
            &format!("PrivateKey: {WG_SECRET}"),
            Language::En,
        )
        .expect("the value parses");
        let diag = apply(prepared, Some(&mut profile), Language::En)
            .err()
            .expect("a VLESS profile carries no WireGuard slot");
        assert_eq!(diag.key(), Key::SrvWgTargetFieldNotFound);
    }

    #[test]
    fn a_generated_mldsa65_key_applies_to_reality() {
        let key = url_key(&[7u8; 1952]);
        let mut profile = with_reality(vless());
        let prepared = parse(
            XrayToolKind::Mldsa65Verify,
            &format!("Verify: {key}\n"),
            Language::En,
        )
        .expect("a 1952-byte key parses");
        assert!(matches!(
            apply(prepared, Some(&mut profile), Language::En),
            Ok(Applied::Field(_))
        ));
        let reality = profile
            .outbound
            .stream
            .reality_settings
            .as_ref()
            .expect("the fixture carries REALITY");
        assert_eq!(reality.mldsa65_verify, key);
    }

    #[test]
    fn a_malformed_mldsa65_key_is_refused_by_key() {
        refused(
            parse(
                XrayToolKind::Mldsa65Verify,
                "Verify: not-a-key",
                Language::En,
            ),
            Key::SrvMldsa65InvalidKey,
        );
    }

    #[test]
    fn an_mldsa65_key_on_a_profile_without_reality_is_refused_by_key() {
        let mut profile = vless();
        let prepared = parse(
            XrayToolKind::Mldsa65Verify,
            &format!("Verify: {}", url_key(&[7u8; 1952])),
            Language::En,
        )
        .expect("the value parses");
        let diag = apply(prepared, Some(&mut profile), Language::En)
            .err()
            .expect("the profile has no REALITY block");
        assert_eq!(diag.key(), Key::SrvMldsa65TargetFieldNotFound);
    }

    #[test]
    fn a_computed_leaf_pin_applies_to_tls() {
        let mut profile = with_tls(vless());
        let prepared = parse(
            XrayToolKind::TlsPin,
            &format!("Leaf SHA256: {PIN}\n"),
            Language::En,
        )
        .expect("a 64-hex pin parses");
        let applied = apply(prepared, Some(&mut profile), Language::En).expect("TLS exists");
        assert!(
            matches!(&applied, Applied::LeafPin { output } if output.contains(PIN)),
            "the probe panel shows the computed pin"
        );
        let tls = profile
            .outbound
            .stream
            .tls_settings
            .as_ref()
            .expect("the fixture carries TLS");
        assert_eq!(tls.pinned_peer_cert_sha256, PIN);
    }

    #[test]
    fn a_malformed_leaf_pin_is_refused_by_key() {
        refused(
            parse(XrayToolKind::TlsPin, "Leaf SHA256: xyz", Language::En),
            Key::SrvTlsPinMalformed,
        );
    }

    #[test]
    fn a_leaf_pin_on_a_profile_without_tls_is_refused_by_key() {
        let mut profile = vless();
        let prepared = parse(
            XrayToolKind::TlsPin,
            &format!("Leaf SHA256: {PIN}"),
            Language::En,
        )
        .expect("the value parses");
        let diag = apply(prepared, Some(&mut profile), Language::En)
            .err()
            .expect("the profile has no TLS block");
        assert_eq!(diag.key(), Key::SrvTlsPinTargetFieldNotFound);
    }

    #[test]
    fn a_probe_handshake_yields_its_verdict_and_pins() {
        let prepared =
            parse(XrayToolKind::TlsPing, &probe_output(), Language::En).expect("the probe ran");
        let applied = apply(prepared, None, Language::En).expect("a probe writes no profile");
        let Applied::Probe(report) = applied else {
            panic!("a probe yields its own verdict");
        };
        assert_eq!(report.leaf_pin.as_deref(), Some(PIN));
        assert_eq!(report.ca_pins, vec![("Test CA".to_owned(), PIN.to_owned())]);
        assert!(report.output.contains("Handshake succeeded"));
    }

    #[test]
    fn a_probe_without_a_handshake_is_refused_by_key() {
        refused(
            parse(
                XrayToolKind::TlsPingQuic,
                "Handshake failed: timeout",
                Language::En,
            ),
            Key::SrvTlsProbeNoHandshake,
        );
    }

    #[test]
    fn a_derived_reality_public_key_applies_to_the_password_field() {
        let key = url_key(&[3u8; 32]);
        let mut profile = with_reality(vless());
        let prepared = parse(
            XrayToolKind::RealityPublicKey,
            &format!("PublicKey: {key}\n"),
            Language::En,
        )
        .expect("a 32-byte key parses");
        assert!(matches!(
            apply(prepared, Some(&mut profile), Language::En),
            Ok(Applied::RealityPublicKey(_))
        ));
        let reality = profile
            .outbound
            .stream
            .reality_settings
            .as_ref()
            .expect("the fixture carries REALITY");
        assert_eq!(reality.password, key);
    }

    #[test]
    fn a_malformed_reality_public_key_is_refused_by_key() {
        refused(
            parse(
                XrayToolKind::RealityPublicKey,
                "PublicKey: not-a-key",
                Language::En,
            ),
            Key::SrvX25519InvalidPublicKey,
        );
    }

    #[test]
    fn a_reality_key_on_a_profile_without_reality_is_refused_by_key() {
        let mut profile = vless();
        let prepared = parse(
            XrayToolKind::RealityPublicKey,
            &format!("PublicKey: {}", url_key(&[3u8; 32])),
            Language::En,
        )
        .expect("the value parses");
        let diag = apply(prepared, Some(&mut profile), Language::En)
            .err()
            .expect("the profile has no REALITY block");
        assert_eq!(diag.key(), Key::SrvRealityTargetFieldNotFound);
    }

    /// A session holding `kind` for `target` with a pending answer channel;
    /// the returned sender completes the run when the test sends it.
    fn staged(
        kind: XrayToolKind,
        target: ToolTarget,
    ) -> (ToolSession, oneshot::Sender<Result<String, String>>) {
        let (tx, rx) = oneshot::channel();
        let session = ToolSession {
            job: Some(ToolJob {
                target,
                kind,
                request: Request::reply(rx),
            }),
        };
        (session, tx)
    }

    fn target(id: &str, generation: u64) -> ToolTarget {
        ToolTarget::ExistingDraft {
            profile_id: id.to_owned(),
            generation,
        }
    }

    #[test]
    fn a_second_request_while_one_is_running_is_refused() {
        let (mut session, _tx) = staged(XrayToolKind::Uuid, target("a", 0));
        assert!(session.is_running());
        let error = session
            .request(
                XrayToolKind::Uuid,
                target("a", 0),
                vec!["uuid".into()],
                egui::Context::default(),
                Language::En,
            )
            .expect_err("the slot is taken");
        assert_eq!(error, t(Language::En, Key::SrvAnotherToolRunning));
    }

    #[test]
    fn a_result_for_a_closed_target_is_dropped() {
        let (mut session, tx) = staged(XrayToolKind::Uuid, target("a", 0));
        tx.send(Ok(UUID.to_owned())).expect("the result lands");
        assert!(
            session.take_terminal(|_| false).is_none(),
            "a result whose target is gone is dropped"
        );
        assert!(
            !session.is_running(),
            "the dropped result still ends the run"
        );
        assert!(
            session.take_terminal(|_| true).is_none(),
            "a dropped result is never handed back later"
        );
    }

    #[test]
    fn a_live_result_is_handed_back_once() {
        let (mut session, tx) = staged(XrayToolKind::Uuid, target("a", 7));
        tx.send(Ok(UUID.to_owned())).expect("the result lands");
        let run = session
            .take_terminal(|target| target.generation() == 7)
            .expect("the live target takes its result");
        assert_eq!(run.kind, XrayToolKind::Uuid);
        assert!(matches!(
            &run.outcome,
            ToolOutcome::Answered(Ok(output)) if output == UUID
        ));
        assert!(
            session.take_terminal(|_| true).is_none(),
            "a delivered result is never handed back twice"
        );
    }
}
