//! The `xray tls ping` certificate transcript: one home for the line grammar
//! the pin panel parses and the in-app QUIC capture renders.
//!
//! Xray-core prints the certificate block in
//! `main/commands/all/tls/ping.go` (`printCertificates`): one
//! `Cert's leaf SHA256:` line, one `Cert's CA <name> SHA256:` line per
//! issuing certificate, and the leaf's `Cert's allowed domains:` line. The
//! core writes the block through a tabwriter (padding 2, space padchar), so
//! the labels are followed by a tab here and the parser trims both sides.
//!
//! The facts — the chain's names, pins and allowed domains — are the
//! producer's half (the QUIC capture parses the certificates); this module
//! owns the lines they are written on, so producer and parser cannot drift.

use std::fmt::Write as _;

/// Prefix of the leaf-certificate SHA256 line in `xray tls ping` output
/// (Xray-core `main/commands/all/tls/ping.go` `printCertificates`).
pub const TLS_PROBE_LEAF_PREFIX: &str = "Cert's leaf SHA256:";

/// Prefix of a CA-certificate SHA256 line; the CA name sits between the
/// angle brackets.
pub const TLS_PROBE_CA_PREFIX: &str = "Cert's CA <";

/// Suffix closing a CA-certificate SHA256 line's name.
pub const TLS_PROBE_CA_SUFFIX: &str = "> SHA256:";

/// The leaf certificate SHA256 pin from `xray tls ping` output: the trimmed
/// rest of the first "Cert's leaf SHA256:" line (the core's tabwriter pads
/// the separator with spaces). `None` when no such line exists.
pub fn leaf_pin_from_probe_output(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        line.trim()
            .strip_prefix(TLS_PROBE_LEAF_PREFIX)
            .map(str::trim)
            .filter(|pin| !pin.is_empty())
            .map(str::to_owned)
    })
}

/// Every CA certificate SHA256 pin from `xray tls ping` output as
/// (name, pin) in line order — one entry per "Cert's CA <name> SHA256:"
/// line, so the without-SNI and with-SNI blocks both contribute when the
/// chain repeats.
pub fn ca_pins_from_probe_output(output: &str) -> Vec<(String, String)> {
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix(TLS_PROBE_CA_PREFIX)?;
            let (name, value) = rest.split_once(TLS_PROBE_CA_SUFFIX)?;
            let pin = value.trim();
            (!pin.is_empty()).then(|| (name.trim().to_owned(), pin.to_owned()))
        })
        .collect()
}

/// One certificate of a captured chain, in chain order (leaf first):
/// everything the certificate block prints about it.
pub struct CertRow {
    /// The certificate's common name, when it has one. The leaf's own row
    /// prints its pin without a name, so its label is ignored; an issuing
    /// certificate without a common name prints its position in the chain
    /// (`#<n>`), the same shape `tls ping` prints.
    pub common_name: Option<String>,
    /// Lowercase hex SHA256 of the certificate's DER encoding.
    pub sha256: String,
}

/// The facts one `xray tls ping`-shaped transcript is rendered from. The
/// producer computes them — the certificate block is written for a capture
/// the producer performed, not derived here — so this module needs neither a
/// QUIC stack nor an X.509 parser.
pub struct Transcript<'a> {
    /// The probe target, as dialled.
    pub host: &'a str,
    /// The port the probe dialled.
    pub port: u16,
    /// The SNI the handshake carried.
    pub sni: &'a str,
    /// The negotiated TLS version, as `tls ping` prints it (`TLS 1.3`).
    pub tls_version: &'a str,
    /// The negotiated ALPN protocol (`h3` for the QUIC capture).
    pub alpn: &'a str,
    /// The sum of the chain's DER lengths.
    pub chain_total_len: usize,
    /// The chain in order, leaf first; the certificate lines are written
    /// from it, so an empty chain prints no certificate at all.
    pub certs: &'a [CertRow],
    /// Comma-joined DNS names and IP addresses of the leaf's
    /// subjectAltName, when it has any; the line is omitted otherwise.
    pub allowed_domains: Option<&'a str>,
}

impl Transcript<'_> {
    /// Renders the transcript the pin panel reads. The certificate lines are
    /// written from the prefixes above — the same constants
    /// [`leaf_pin_from_probe_output`] and [`ca_pins_from_probe_output`]
    /// strip — so a rendered transcript parses back to the facts it was
    /// built from.
    pub fn render(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "QUIC handshake:  {}:{}", self.host, self.port);
        let _ = writeln!(out, "SNI:  {}", self.sni);
        let _ = writeln!(out, "Handshake succeeded");
        let _ = writeln!(out, "TLS Version:  {}", self.tls_version);
        let _ = writeln!(out, "ALPN:  {}", self.alpn);
        let _ = writeln!(
            out,
            "Certificate chain's total length:\t{} (certs count: {})",
            self.chain_total_len,
            self.certs.len()
        );
        let Some((leaf, issuing)) = self.certs.split_first() else {
            return out;
        };
        let _ = writeln!(out, "{TLS_PROBE_LEAF_PREFIX}\t{}", leaf.sha256);
        for (index, cert) in issuing.iter().enumerate() {
            // The fallback is the certificate's position in the chain, and it
            // is built only for the certificates that need it.
            let position;
            let name = match cert.common_name.as_deref() {
                Some(name) => name,
                None => {
                    position = format!("#{}", index + 1);
                    &position
                }
            };
            let _ = writeln!(
                out,
                "{TLS_PROBE_CA_PREFIX}{name}{TLS_PROBE_CA_SUFFIX}\t{}",
                cert.sha256
            );
        }
        if let Some(domains) = self.allowed_domains {
            let _ = writeln!(out, "Cert's allowed domains:\t[{domains}]");
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A chain whose leaf has a pin, whose first issuer has a common name and
    /// whose second has none, so the round trip covers the named and the
    /// positional CA rows.
    fn fixture() -> [CertRow; 3] {
        [
            CertRow {
                common_name: None,
                sha256: "1111111111111111111111111111111111111111111111111111111111111111".into(),
            },
            CertRow {
                common_name: Some("Fixture Intermediate".into()),
                sha256: "2222222222222222222222222222222222222222222222222222222222222222".into(),
            },
            CertRow {
                common_name: None,
                sha256: "3333333333333333333333333333333333333333333333333333333333333333".into(),
            },
        ]
    }

    #[test]
    fn rendered_transcript_parses_back_to_the_facts_it_was_built_from() {
        let certs = fixture();
        let transcript = Transcript {
            host: "quic.example.com",
            port: 9443,
            sni: "quic.example.com",
            tls_version: "TLS 1.3",
            alpn: "h3",
            chain_total_len: 4242,
            certs: &certs,
            allowed_domains: Some("quic.example.com, www.quic.example.com"),
        };
        let rendered = transcript.render();
        assert!(rendered.starts_with("QUIC handshake:  quic.example.com:9443\n"));
        assert!(rendered.contains("Certificate chain's total length:\t4242 (certs count: 3)\n"));
        assert_eq!(
            leaf_pin_from_probe_output(&rendered),
            Some(certs[0].sha256.clone())
        );
        assert_eq!(
            ca_pins_from_probe_output(&rendered),
            vec![
                ("Fixture Intermediate".to_owned(), certs[1].sha256.clone()),
                ("#2".to_owned(), certs[2].sha256.clone()),
            ]
        );
    }

    #[test]
    fn leaf_pin_from_probe_output_parses_the_golden_probe_output() {
        // Realistic `xray tls ping` output: the tabwriter (padding 2, space
        // padchar) aligns every value column; both the without-SNI and the
        // with-SNI connection print the same chain. The hex literals below
        // are the fixture's own values (independent source of truth).
        let output = r#"TLS ping:  example.com
Using IP:  93.184.216.34:443
-------------------
Pinging without SNI
Handshake succeeded
TLS Version:                                          TLS 1.3
TLS Post-Quantum key exchange:                        false (RSA Exchange)
Certificate chain's total length:                     2144 (certs count: 2)
Cert's signature algorithm:                           SHA256-RSA
Cert's publicKey algorithm:                           RSA
Cert's leaf SHA256:                                   7f9c2b3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9
Cert's CA <DigiCert TLS RSA SHA256 2020 CA1> SHA256:  a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90
Cert's CA <DigiCert Global Root R11> SHA256:          c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2
Cert's allowed domains:                               [example.com]
-------------------
Pinging with SNI
Handshake succeeded
TLS Version:                                          TLS 1.3
TLS Post-Quantum key exchange:                        false (RSA Exchange)
Certificate chain's total length:                     2144 (certs count: 2)
Cert's signature algorithm:                           SHA256-RSA
Cert's publicKey algorithm:                           RSA
Cert's leaf SHA256:                                   7f9c2b3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9
Cert's CA <DigiCert TLS RSA SHA256 2020 CA1> SHA256:  a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90
Cert's CA <DigiCert Global Root R11> SHA256:          c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2
Cert's allowed domains:                               [example.com]
-------------------
TLS ping finished"#;
        assert_eq!(
            leaf_pin_from_probe_output(output),
            Some("7f9c2b3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9".to_owned())
        );
    }

    #[test]
    fn leaf_pin_from_probe_output_none_without_a_leaf_line() {
        // A successful handshake whose chain has no leaf with DNSNames
        // prints no certificate detail lines at all.
        let output = r#"TLS ping:  10.0.0.5
Using IP:  10.0.0.5:443
-------------------
Pinging without SNI
Handshake succeeded
TLS Version:                       TLS 1.3
TLS Post-Quantum key exchange:     false (RSA Exchange)
Certificate chain's total length:  1024 (certs count: 1)
-------------------
Pinging with SNI
Handshake succeeded
TLS Version:                       TLS 1.3
TLS Post-Quantum key exchange:     false (RSA Exchange)
Certificate chain's total length:  1024 (certs count: 1)
-------------------
TLS ping finished"#;
        assert_eq!(leaf_pin_from_probe_output(output), None);
    }

    #[test]
    fn ca_pins_from_probe_output_parses_every_ca_line_in_order() {
        let output = r#"TLS ping:  example.com
Using IP:  93.184.216.34:443
-------------------
Pinging without SNI
Handshake succeeded
TLS Version:                                          TLS 1.3
TLS Post-Quantum key exchange:                        false (RSA Exchange)
Certificate chain's total length:                     2144 (certs count: 2)
Cert's signature algorithm:                           SHA256-RSA
Cert's publicKey algorithm:                           RSA
Cert's leaf SHA256:                                   7f9c2b3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9
Cert's CA <DigiCert TLS RSA SHA256 2020 CA1> SHA256:  a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90
Cert's CA <DigiCert Global Root R11> SHA256:          c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2
Cert's allowed domains:                               [example.com]
-------------------
Pinging with SNI
Handshake succeeded
TLS Version:                                          TLS 1.3
TLS Post-Quantum key exchange:                        false (RSA Exchange)
Certificate chain's total length:                     2144 (certs count: 2)
Cert's signature algorithm:                           SHA256-RSA
Cert's publicKey algorithm:                           RSA
Cert's leaf SHA256:                                   7f9c2b3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9
Cert's CA <DigiCert TLS RSA SHA256 2020 CA1> SHA256:  a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90
Cert's CA <DigiCert Global Root R11> SHA256:          c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2
Cert's allowed domains:                               [example.com]
-------------------
TLS ping finished"#;
        assert_eq!(
            ca_pins_from_probe_output(output),
            vec![
                (
                    "DigiCert TLS RSA SHA256 2020 CA1".to_owned(),
                    "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90".to_owned(),
                ),
                (
                    "DigiCert Global Root R11".to_owned(),
                    "c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2".to_owned(),
                ),
                (
                    "DigiCert TLS RSA SHA256 2020 CA1".to_owned(),
                    "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90".to_owned(),
                ),
                (
                    "DigiCert Global Root R11".to_owned(),
                    "c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2".to_owned(),
                ),
            ]
        );
    }

    #[test]
    fn ca_pins_from_probe_output_empty_without_ca_lines() {
        let output = r#"TLS ping:  10.0.0.5
Using IP:  10.0.0.5:443
-------------------
Pinging without SNI
Handshake succeeded
TLS Version:                       TLS 1.3
TLS Post-Quantum key exchange:     false (RSA Exchange)
Certificate chain's total length:  1024 (certs count: 1)
-------------------
Pinging with SNI
Handshake succeeded
TLS Version:                       TLS 1.3
TLS Post-Quantum key exchange:     false (RSA Exchange)
Certificate chain's total length:  1024 (certs count: 1)
-------------------
TLS ping finished"#;
        assert!(ca_pins_from_probe_output(output).is_empty());
    }
}
