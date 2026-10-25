//! Host/port text shared by the model, the share-link grammar, the generator,
//! and the probe targets.
//!
//! One grammar for "what is the host, and does it carry a port": a bracketed
//! IPv6 literal may carry one, a bare IP literal (v4 or v6) is a whole host,
//! and any other text splits at its last colon. Callers keep their own
//! validation — the share-link grammar's `#716` accept-set and the Xray
//! address rules are different contracts — so this module owns the split and
//! the rendering, never the accept decision.

use std::net::IpAddr;

/// One `host[:port]` split. `host` never carries brackets; `port` is the
/// text after the colon, unvalidated (a caller decides what a port is).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostPort<'a> {
    pub host: &'a str,
    pub port: Option<&'a str>,
}

/// Split `host[:port]` / `[host][:port]` / a bare host.
///
/// Brackets only delimit the host: anything may sit between them, because the
/// core's own `SplitHostPort` accepts a bracketed name and resolves it later.
/// Returns `None` when the text is not host-shaped: an unclosed bracket, a
/// bracket in an unbracketed host, or text after a bracketed host that is not
/// a port.
pub fn split(input: &str) -> Option<HostPort<'_>> {
    if let Some(rest) = input.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        return match tail.strip_prefix(':') {
            Some(port) => Some(HostPort {
                host,
                port: Some(port),
            }),
            None if tail.is_empty() => Some(HostPort { host, port: None }),
            None => None,
        };
    }
    if input.contains(['[', ']']) {
        return None;
    }
    // A bare IP literal is a whole host: an IPv6 literal's colons would
    // otherwise read as a port.
    if input.parse::<IpAddr>().is_ok() {
        return Some(HostPort {
            host: input,
            port: None,
        });
    }
    match input.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => Some(HostPort {
            host,
            port: Some(port),
        }),
        Some(_) => None,
        None => Some(HostPort {
            host: input,
            port: None,
        }),
    }
}

/// `host:port`, re-bracketing an IPv6 host.
pub fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// The authority part of `text`: everything before the first `/`, `?` or `#`.
pub fn authority(text: &str) -> &str {
    text.split(['/', '?', '#']).next().unwrap_or(text)
}

/// [`authority`] with any `userinfo@` dropped, as Go's URL parser hands the
/// host to a mask build.
pub fn host_authority(text: &str) -> &str {
    authority(text).rsplit('@').next().unwrap_or(text)
}

#[cfg(test)]
mod tests {
    use super::{authority, format_host_port, host_authority, split};

    #[test]
    fn split_reads_every_grammar_the_app_carries() {
        assert_eq!(
            split("example.com:443"),
            Some(super::HostPort {
                host: "example.com",
                port: Some("443")
            })
        );
        assert_eq!(
            split("example.com"),
            Some(super::HostPort {
                host: "example.com",
                port: None
            })
        );
        assert_eq!(
            split("[2001:db8::1]:443"),
            Some(super::HostPort {
                host: "2001:db8::1",
                port: Some("443")
            })
        );
        assert_eq!(
            split("[2001:db8::1]"),
            Some(super::HostPort {
                host: "2001:db8::1",
                port: None
            })
        );
        // A bare IPv6 literal is a whole host, port-less even though it is
        // full of colons.
        assert_eq!(
            split("2001:db8::1"),
            Some(super::HostPort {
                host: "2001:db8::1",
                port: None
            })
        );
        assert_eq!(
            split("192.0.2.1:53"),
            Some(super::HostPort {
                host: "192.0.2.1",
                port: Some("53")
            })
        );
    }

    #[test]
    fn split_refuses_malformed_authorities() {
        assert_eq!(split("[2001:db8::1"), None, "unclosed bracket");
        assert_eq!(split("[2001:db8::1]tail"), None, "text after the bracket");
        assert_eq!(split("host[0]"), None, "bracket in an unbracketed host");
        assert_eq!(split(":443"), None, "empty host");
        assert_eq!(split("[]:443"), None, "empty bracketed host");
    }

    #[test]
    fn split_accepts_a_bracketed_name_the_core_resolves_later() {
        // Go's `SplitHostPort` only treats the brackets as delimiters, so a
        // bracketed DNS name is a host, not a malformed IPv6 literal.
        assert_eq!(
            split("[stun.example.com]:3478"),
            Some(super::HostPort {
                host: "stun.example.com",
                port: Some("3478")
            })
        );
        assert_eq!(
            split("[stun.example.com]"),
            Some(super::HostPort {
                host: "stun.example.com",
                port: None
            })
        );
    }

    #[test]
    fn format_brackets_only_ipv6() {
        assert_eq!(format_host_port("example.com", 443), "example.com:443");
        assert_eq!(format_host_port("192.0.2.1", 53), "192.0.2.1:53");
        assert_eq!(format_host_port("2001:db8::1", 443), "[2001:db8::1]:443");
    }

    #[test]
    fn authority_cuts_path_query_fragment_and_userinfo() {
        assert_eq!(authority("example.com:443/a?b#c"), "example.com:443");
        assert_eq!(authority("example.com"), "example.com");
        assert_eq!(
            host_authority("user:pass@example.com:443/x"),
            "example.com:443"
        );
        assert_eq!(host_authority("example.com:443"), "example.com:443");
    }
}
