//! Probe-verdict shaping: the single source of truth for the
//! latency probe's dead-verdict sentence and warn summary.
//!
//! Both consumers compose their text here: the runtime log writer calls
//! [`warn_summary`] with the English pack, the UI feedback formatter calls
//! [`warn_summary`] and [`dead_verdict_line`] with the user's language. The
//! sentences are derived from the i18n keys (`LatencyProbeOneDead*`,
//! `LatencyFeedbackPartialWarn`), so the log and the label can never drift:
//! a composition change lands in exactly one place.
//!
//! Lives at the crate root (next to `i18n`) as the module shared by both
//! consumers — `rt` must not import `ui`, and neither layer owns text that
//! both render. Its seam is pinned to `rt::OutboundStatusView` (the status
//! rows both consumers already hold), so the module reads from `rt`; if a
//! future crate split needs this below `rt`, the seam must narrow to a
//! plain-field input owned here or in `model`.

use crate::i18n::{Key, t, t_fmt};
use crate::model::ServerProfile;
use crate::model::settings::Language;
use crate::rt::OutboundStatusView;

/// Append the diagnostics wall — the "Xray diagnostics:" header key and the
/// captured tail — to a message when a tail exists; an empty tail returns the
/// message unchanged, so a failure or dead verdict without captured child
/// output degrades to the headline-only text. The single source of the wall's
/// header and shape for every failure surface (whole-probe failures, dead
/// verdicts, connect errors, dashboard details), so log records and UI text
/// cannot drift.
pub(crate) fn with_diagnostics_wall(language: Language, mut message: String, tail: &str) -> String {
    if tail.is_empty() {
        return message;
    }
    message.push('\n');
    message.push_str(t(language, Key::ProbeDiagnosticsWall));
    message.push('\n');
    message.push_str(tail);
    message
}

/// The dead-verdict sentence "Server '{}' ({}) did not respond: {}." with
/// graceful degradation: the address is omitted when the profile has none
/// usable, the reason when the Observatory reported none — falling back to
/// the bare "Server '{}' did not respond.". Each combination is its own i18n
/// key so translations never splice English fragments.
pub(crate) fn dead_verdict_line(
    language: Language,
    label: &str,
    address: Option<&str>,
    reason: Option<&str>,
) -> String {
    // A blank reason is no reason: only reported error text earns the
    // reason-bearing sentence.
    let reason = reason.filter(|reason| !reason.is_empty());
    match (address, reason) {
        (Some(address), Some(reason)) => t_fmt(
            language,
            Key::LatencyProbeOneDeadAtReason,
            &[&label, &address, &reason],
        ),
        (Some(address), None) => t_fmt(language, Key::LatencyProbeOneDeadAt, &[&label, &address]),
        (None, Some(reason)) => t_fmt(language, Key::LatencyProbeOneDeadReason, &[&label, &reason]),
        (None, None) => t_fmt(language, Key::LatencyProbeOneDead, &[&label]),
    }
}

/// Compose the probe warn summary: "N of M outbounds responded." plus one
/// dead-verdict line per dead server, in probe order. Used by the runtime
/// log writer (English) and the UI feedback label (user's language) for both
/// probe scopes; a dead row whose profile vanished mid-probe falls back to
/// the raw status tag as the label.
///
/// One probe run is one child, so the dead rows of a run share a
/// run-level diagnostics tail; when the run produced one, the summary
/// appends the "Xray diagnostics:" wall once after the last verdict —
/// exactly the shape the whole-probe failure log records use. Rows without
/// diagnostics (live observatory rows, output-less probe runs) degrade to
/// the headline-only summary.
pub(crate) fn warn_summary(
    language: Language,
    profiles: &[ServerProfile],
    statuses: &[OutboundStatusView],
) -> String {
    let dead: Vec<&OutboundStatusView> = statuses.iter().filter(|status| !status.alive).collect();
    let responded = statuses.len() - dead.len();
    let mut summary = t_fmt(
        language,
        Key::LatencyFeedbackPartialWarn,
        &[&responded, &statuses.len()],
    );
    for status in &dead {
        let profile = profiles.iter().find(|profile| profile.tag() == status.tag);
        let label = profile
            .map(|profile| profile.name.as_str())
            .unwrap_or(status.tag.as_str());
        let address = profile.and_then(ServerProfile::server_address);
        summary.push('\n');
        summary.push_str(&dead_verdict_line(
            language,
            label,
            address.as_deref(),
            status.last_error.as_deref(),
        ));
    }
    let tail = dead
        .iter()
        .find_map(|status| status.diagnostics.as_deref())
        .unwrap_or("");
    with_diagnostics_wall(language, summary, tail)
}

#[cfg(test)]
mod tests {
    use super::{dead_verdict_line, warn_summary, with_diagnostics_wall};
    use crate::i18n::{Key, t};
    use crate::model::settings::Language;
    use crate::model::{OutboundModel, Protocol, ProtocolSettings, ServerProfile};
    use crate::rt::OutboundStatusView;

    fn vless_profile(name: &str, address: &str, port: u16) -> ServerProfile {
        let mut profile = ServerProfile::new(name, OutboundModel::new(Protocol::Vless));
        let ProtocolSettings::Vless(settings) = &mut profile.outbound.settings else {
            unreachable!("Vless is the default protocol");
        };
        settings.address = address.into();
        settings.port = port;
        profile
    }
    fn status(
        tag: &str,
        alive: bool,
        delay_ms: i64,
        last_error: Option<&str>,
    ) -> OutboundStatusView {
        OutboundStatusView {
            health_ping: None,
            tag: tag.into(),
            alive,
            delay_ms,
            last_error: last_error.map(str::to_owned),
            diagnostics: None,
        }
    }

    #[test]
    fn dead_verdict_bare_when_no_address_or_reason() {
        assert_eq!(
            dead_verdict_line(Language::En, "Tokyo edge", None, None),
            "Server 'Tokyo edge' did not respond."
        );
    }

    #[test]
    fn dead_verdict_reason_only_when_no_address() {
        assert_eq!(
            dead_verdict_line(Language::En, "Tokyo edge", None, Some("connection refused")),
            "Server 'Tokyo edge' did not respond: connection refused."
        );
    }

    #[test]
    fn dead_verdict_address_only_when_reason_empty() {
        assert_eq!(
            dead_verdict_line(Language::En, "Tokyo edge", Some("1.2.3.4:443"), None),
            "Server 'Tokyo edge' (1.2.3.4:443) did not respond."
        );
    }

    #[test]
    fn dead_verdict_address_and_reason() {
        assert_eq!(
            dead_verdict_line(
                Language::En,
                "Tokyo edge",
                Some("1.2.3.4:443"),
                Some("connection refused")
            ),
            "Server 'Tokyo edge' (1.2.3.4:443) did not respond: connection refused."
        );
    }

    #[test]
    fn warn_summary_counts_responded_and_lists_dead_verdicts() {
        let tokyo = vless_profile("Tokyo edge", "1.2.3.4", 443);
        let osaka = vless_profile("Osaka", "10.0.0.2", 443);
        let tokyo_tag = tokyo.tag();
        let osaka_tag = osaka.tag();
        let summary = warn_summary(
            Language::En,
            &[tokyo, osaka],
            &[
                status(&tokyo_tag, true, 10, None),
                status(&osaka_tag, false, 0, Some("connection refused")),
            ],
        );
        assert_eq!(
            summary,
            "1 of 2 outbounds responded.\n\
             Server 'Osaka' (10.0.0.2:443) did not respond: connection refused."
        );
    }

    #[test]
    fn warn_summary_zero_responded_single_dead() {
        let tokyo = vless_profile("Tokyo edge", "1.2.3.4", 443);
        let tokyo_tag = tokyo.tag();
        let summary = warn_summary(
            Language::En,
            &[tokyo],
            &[status(&tokyo_tag, false, 0, Some("connection refused"))],
        );
        assert_eq!(
            summary,
            "0 of 1 outbounds responded.\n\
             Server 'Tokyo edge' (1.2.3.4:443) did not respond: connection refused."
        );
    }

    #[test]
    fn warn_summary_keeps_dead_rows_in_probe_order() {
        let tokyo = vless_profile("Tokyo edge", "1.2.3.4", 443);
        let osaka = vless_profile("Osaka", "10.0.0.2", 443);
        let nagoya = vless_profile("Nagoya", "10.0.0.3", 443);
        let tokyo_tag = tokyo.tag();
        let osaka_tag = osaka.tag();
        let nagoya_tag = nagoya.tag();
        let summary = warn_summary(
            Language::En,
            &[tokyo, osaka, nagoya],
            &[
                status(&tokyo_tag, false, 0, Some("refused")),
                status(&osaka_tag, true, 20, None),
                status(&nagoya_tag, false, 0, Some("timeout")),
            ],
        );
        assert_eq!(
            summary,
            "1 of 3 outbounds responded.\n\
             Server 'Tokyo edge' (1.2.3.4:443) did not respond: refused.\n\
             Server 'Nagoya' (10.0.0.3:443) did not respond: timeout."
        );
    }

    #[test]
    fn warn_summary_falls_back_to_raw_tag_when_profile_vanished() {
        let summary = warn_summary(
            Language::En,
            &[],
            &[status("srv-x", false, 0, Some("boom"))],
        );
        assert_eq!(
            summary,
            "0 of 1 outbounds responded.\nServer 'srv-x' did not respond: boom."
        );
    }

    #[test]
    fn with_diagnostics_wall_appends_the_shared_header_exactly() {
        let wall = t(Language::En, Key::ProbeDiagnosticsWall);
        assert_eq!(
            with_diagnostics_wall(
                Language::En,
                "boom".into(),
                "[stdout] connecting\n[stderr] fail"
            ),
            format!("boom\n{wall}\n[stdout] connecting\n[stderr] fail")
        );
        assert_eq!(
            with_diagnostics_wall(Language::En, "boom".into(), ""),
            "boom",
            "no tail leaves the message unchanged"
        );
    }

    #[test]
    fn warn_summary_appends_the_wall_once_when_a_dead_row_carries_diagnostics() {
        // One probe run is one child: the run-level tail rides each dead row
        // of the run, and the summary must append the wall exactly once,
        // after the last verdict — never once per dead server.
        let tokyo = vless_profile("Tokyo edge", "1.2.3.4", 443);
        let osaka = vless_profile("Osaka", "10.0.0.2", 443);
        let tokyo_tag = tokyo.tag();
        let osaka_tag = osaka.tag();
        let dead_with_tail = status(&tokyo_tag, false, 0, Some("refused"));
        let dead_with_tail = OutboundStatusView {
            health_ping: None,
            diagnostics: Some("[stderr] tls handshake failed".into()),
            ..dead_with_tail
        };
        let summary = warn_summary(
            Language::En,
            &[tokyo, osaka],
            &[
                dead_with_tail,
                status(&osaka_tag, false, 0, Some("timeout")),
                status(&tokyo_tag, true, 10, None),
            ],
        );
        assert_eq!(
            summary,
            format!(
                "1 of 3 outbounds responded.\n\
                 Server 'Tokyo edge' (1.2.3.4:443) did not respond: refused.\n\
                 Server 'Osaka' (10.0.0.2:443) did not respond: timeout.\n\
                 {}\n\
                 [stderr] tls handshake failed",
                t(Language::En, Key::ProbeDiagnosticsWall)
            )
        );
    }

    #[test]
    fn warn_summary_without_diagnostics_keeps_the_headline_only_shape() {
        // Rows without diagnostics (live observatory rows, output-less probe
        // runs) must degrade to exactly today's summary text.
        let tokyo = vless_profile("Tokyo edge", "1.2.3.4", 443);
        let tokyo_tag = tokyo.tag();
        let summary = warn_summary(
            Language::En,
            &[tokyo],
            &[
                status(&tokyo_tag, false, 0, Some("refused")),
                OutboundStatusView {
                    health_ping: None,
                    tag: "srv-other".into(),
                    alive: false,
                    delay_ms: 0,
                    last_error: Some("boom".into()),
                    diagnostics: None,
                },
            ],
        );
        assert_eq!(
            summary,
            "0 of 2 outbounds responded.\n\
             Server 'Tokyo edge' (1.2.3.4:443) did not respond: refused.\n\
             Server 'srv-other' did not respond: boom."
        );
    }
}
