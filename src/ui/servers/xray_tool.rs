//! The servers screen's helper verbs: one dispatch over the two adapters that
//! answer them — a bounded `xray.exe` child and the in-app QUIC certificate
//! capture — each run under the verb's own budget and the request's
//! cooperative stop flag.

use std::sync::atomic::AtomicBool;
use std::time::Duration;

use crate::model::settings::Language;

use super::keygen;

/// Wall-clock budget of one `xray.exe` helper invocation. On expiry the child
/// is killed and reaped, and the deadline error is rendered with redacted
/// args.
const CORE_TOOL_BUDGET: Duration = Duration::from_secs(20);

/// Wall-clock budget of one in-app QUIC capture: DNS plus the handshake. A
/// UDP-blackholed server must fail fast.
const QUIC_PROBE_BUDGET: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum XrayToolKind {
    Uuid,
    VlessEncryption,
    WireguardSecret,
    Mldsa65Verify,
    TlsPin,
    TlsPing,
    /// In-app QUIC certificate capture: the transcript has the
    /// same "Cert's leaf SHA256:" shape as `xray tls ping`, so the TlsPing
    /// success/error handling applies unchanged.
    TlsPingQuic,
    RealityPublicKey,
}

impl XrayToolKind {
    /// The adapter that answers this verb; callers of [`run`] never pick
    /// between the two themselves.
    fn adapter(self) -> &'static dyn ToolAdapter {
        match self {
            Self::TlsPingQuic => &QUIC_PROBE_ADAPTER,
            _ => &CORE_TOOL_ADAPTER,
        }
    }

    /// The wall-clock bound one invocation of this verb spends: the
    /// subprocess verbs keep the core helper's 20 s, the in-app QUIC capture
    /// its 10 s.
    fn budget(self) -> Duration {
        match self {
            Self::TlsPingQuic => QUIC_PROBE_BUDGET,
            _ => CORE_TOOL_BUDGET,
        }
    }
}

/// One backend that can answer a helper verb. Both take the verb's arguments
/// plus the run's budget and stop flag, so [`XrayToolKind::adapter`] is the
/// only place that knows which backend a verb uses.
trait ToolAdapter {
    fn run(
        &self,
        lang: Language,
        args: &[String],
        budget: Duration,
        stop: &AtomicBool,
    ) -> Result<String, String>;
}

/// The bounded `xray.exe` child, whose provenance check, kill and reaping
/// live in the keygen helpers.
struct CoreToolAdapter;

impl ToolAdapter for CoreToolAdapter {
    fn run(
        &self,
        lang: Language,
        args: &[String],
        budget: Duration,
        stop: &AtomicBool,
    ) -> Result<String, String> {
        keygen::run_xray_bounded(lang, args, budget, stop)
    }
}

/// The in-app QUIC capture, for a server that answers no TCP port the core's
/// `tls ping` could dial.
struct QuicProbeAdapter;

impl ToolAdapter for QuicProbeAdapter {
    fn run(
        &self,
        lang: Language,
        args: &[String],
        budget: Duration,
        stop: &AtomicBool,
    ) -> Result<String, String> {
        crate::quic_probe::run(lang, args, budget, stop)
    }
}

static CORE_TOOL_ADAPTER: CoreToolAdapter = CoreToolAdapter;
static QUIC_PROBE_ADAPTER: QuicProbeAdapter = QuicProbeAdapter;

/// Runs one helper verb off the UI thread under its budget, honouring `stop`;
/// a run the flag cancelled returns an error the caller discards.
pub(super) fn run(
    kind: XrayToolKind,
    lang: Language,
    args: &[String],
    stop: &AtomicBool,
) -> Result<String, String> {
    kind.adapter().run(lang, args, kind.budget(), stop)
}
