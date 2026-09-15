//! In-app QUIC certificate capture for the Security-tab pin tool.
//!
//! `xray tls ping` dials TCP, so a QUIC-only server (Hysteria2) is
//! unreachable by the core tool and no pin can be obtained from it.
//! This module performs a
//! raw QUIC handshake with quinn/rustls — the same rustls 0.23/aws-lc-rs
//! stack the app already ships for reqwest — accepts whatever certificate
//! the server presents (the displayed pin is a TOFU trust decision by the
//! user, the same role the unverified `tls ping` transcript plays), and
//! renders the transcript in the exact "Cert's leaf SHA256:" shape the pin
//! panel parses.
//!
//! The handshake negotiates ALPN "h3" (HTTP/3): hysteria's TLS listener
//! requires it (`transport/internet/hysteria/hub.go` in Xray-core), so a
//! server that answers QUIC at all completes the handshake and reveals its
//! certificate.

use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use x509_parser::prelude::{GeneralName, X509Certificate, parse_x509_certificate};

use crate::i18n::{Key, t, t_fmt};
use crate::model::settings::Language;

/// Port used when the probe domain carries no explicit `:port`.
const DEFAULT_QUIC_PORT: u16 = 443;
/// Hysteria2 negotiates ALPN "h3" (its traffic masquerades as HTTP/3).
const H3_ALPN: &[u8] = b"h3";
/// Total budget for DNS + handshake; a UDP-blackholed server must fail fast.
const QUIC_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Shared slot holding the DER chain (leaf first) captured by the last
/// accepted verification.
type CapturedChain = Arc<Mutex<Option<Vec<Vec<u8>>>>>;

/// Accepts any server certificate and records the presented chain: the
/// probe's job is to surface the leaf for the user to pin, not to validate
/// it. The captured chain is shared through the `Arc` so the caller can read
/// it after the handshake (quinn 0.11 exposes `peer_identity` only as
/// `Box<dyn Any>`, and the verifier sees the raw DER chain anyway).
#[derive(Debug, Default)]
struct AcceptAllVerifier {
    captured: CapturedChain,
}

impl AcceptAllVerifier {
    fn new() -> (Self, CapturedChain) {
        let captured = Arc::new(Mutex::new(None));
        (
            Self {
                captured: captured.clone(),
            },
            captured,
        )
    }
}

impl ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut chain = Vec::with_capacity(1 + intermediates.len());
        chain.push(end_entity.as_ref().to_vec());
        chain.extend(intermediates.iter().map(|cert| cert.as_ref().to_vec()));
        *self.captured.lock().unwrap() = Some(chain);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Runs a QUIC certificate capture against `args[0]` (the probe domain,
/// `host` or `host:port`) and `args[1]` (optional IP override), mirroring
/// `run_xray_bounded`'s signature so the probe job thread stays uniform.
/// Returns the transcript on success; the panel's `tls_probe_*` parsers
/// consume it exactly like `xray tls ping` output.
pub fn run(lang: Language, args: &[String]) -> Result<String, String> {
    let domain = args.first().map(String::as_str).unwrap_or("");
    let ip_override = args.get(1).map(String::as_str).unwrap_or("");
    let (host, port) = split_host_port(domain)
        .map_err(|error| t_fmt(lang, Key::SrvQuicProbeDomainInvalid, &[&error]))?;
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?
        .block_on(async {
            tokio::time::timeout(QUIC_PROBE_TIMEOUT, async {
                let addrs = resolve(&host, port, ip_override).await?;
                capture(&addrs, &host).await
            })
            .await
        });
    let chain = match result {
        Err(_elapsed) => return Err(t(lang, Key::SrvQuicProbeTimeout).into()),
        Ok(Err(error)) => {
            return Err(t_fmt(lang, Key::SrvQuicProbeHandshakeFailed, &[&error]));
        }
        Ok(Ok(chain)) => chain,
    };
    if chain.is_empty() {
        return Err(t(lang, Key::SrvQuicProbeNoCert).into());
    }
    Ok(render_transcript(&host, port, &host, &chain))
}

/// Resolves the capture target: the IP override wins when present, then an
/// IP-literal host, then DNS (all addresses, tried in order by `capture`).
async fn resolve(host: &str, port: u16, ip_override: &str) -> Result<Vec<SocketAddr>, String> {
    if !ip_override.is_empty() {
        let ip: IpAddr = ip_override
            .parse()
            .map_err(|_| format!("invalid IP override {ip_override:?}"))?;
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((bare, port))
        .await
        .map_err(|error| format!("{bare}: {error}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("{bare}: no addresses"));
    }
    Ok(addrs)
}

/// Connects over QUIC and returns the DER certificate chain the server
/// presented. The verifier accepts any certificate; the transcript's pin is
/// the trust decision.
async fn capture(addrs: &[SocketAddr], sni: &str) -> Result<Vec<Vec<u8>>, String> {
    let (verifier, captured) = AcceptAllVerifier::new();
    let mut rustls_config =
        rustls::ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|error| format!("rustls: {error}"))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
    rustls_config.alpn_protocols = vec![H3_ALPN.to_vec()];

    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
        .map_err(|error| format!("rustls: {error}"))?;
    let mut quic_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(Duration::from_secs(10))
                .map_err(|_| "bad idle timeout")?,
        ))
        .keep_alive_interval(None);
    quic_config.transport_config(Arc::new(transport));

    let mut last_error = String::from("no usable addresses");
    for &addr in addrs {
        let bind: SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()
        .unwrap();
        let mut endpoint = match quinn::Endpoint::client(bind) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                last_error = format!("endpoint: {error}");
                continue;
            }
        };
        endpoint.set_default_client_config(quic_config.clone());
        let connecting = match endpoint.connect(addr, sni) {
            Ok(connecting) => connecting,
            Err(error) => {
                last_error = format!("connect: {error}");
                continue;
            }
        };
        if let Err(error) = connecting.await {
            last_error = format!("handshake: {error}");
            continue;
        }
        let chain = captured.lock().unwrap().take().unwrap_or_default();
        // Dropping the endpoint releases the UDP socket; the server needs no
        // graceful goodbye for a probe.
        return Ok(chain);
    }
    Err(last_error)
}

/// Renders the captured chain in `xray tls ping`'s output shape so
/// [`crate::ui::servers::leaf_pin_from_probe_output`] and
/// [`crate::ui::servers::ca_pins_from_probe_output`] parse it unchanged.
fn render_transcript(host: &str, port: u16, sni: &str, chain: &[Vec<u8>]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "QUIC handshake:  {host}:{port}");
    let _ = writeln!(out, "SNI:  {sni}");
    let _ = writeln!(out, "Handshake succeeded");
    let _ = writeln!(out, "TLS Version:  TLS 1.3");
    let _ = writeln!(out, "ALPN:  h3");
    let total_len: usize = chain.iter().map(Vec::len).sum();
    let _ = writeln!(
        out,
        "Certificate chain's total length:\t{total_len} (certs count: {})",
        chain.len()
    );
    if let Some(leaf) = chain.first() {
        let _ = writeln!(out, "Cert's leaf SHA256:\t{}", sha256_hex(leaf));
        for (index, cert) in chain.iter().enumerate().skip(1) {
            let name = cert_common_name(cert).unwrap_or_else(|| format!("#{index}"));
            let _ = writeln!(out, "Cert's CA <{name}> SHA256:\t{}", sha256_hex(cert));
        }
        if let Some(domains) = cert_allowed_domains(leaf) {
            let _ = writeln!(out, "Cert's allowed domains:\t[{domains}]");
        }
    }
    out
}

fn sha256_hex(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    let mut out = String::with_capacity(64);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn parse_cert(der: &[u8]) -> Option<X509Certificate<'_>> {
    parse_x509_certificate(der).ok().map(|(_, cert)| cert)
}

/// CN of the certificate, when present; used for the CA row label (the same
/// `Cert's CA <name> SHA256:` shape `tls ping` prints).
fn cert_common_name(der: &[u8]) -> Option<String> {
    let cert = parse_cert(der)?;
    cert.subject()
        .iter_common_name()
        .next()
        .and_then(|attribute| attribute.as_str().ok())
        .map(str::to_owned)
}

/// Comma-joined DNS names and IP addresses of the certificate's
/// subjectAltName extension, mirroring `tls ping`'s allowed-domains line.
fn cert_allowed_domains(der: &[u8]) -> Option<String> {
    let cert = parse_cert(der)?;
    let san = cert.subject_alternative_name().ok().flatten()?;
    let mut names: Vec<String> = Vec::new();
    for name in &san.value.general_names {
        match name {
            GeneralName::DNSName(name) => names.push((*name).to_owned()),
            GeneralName::IPAddress(bytes) => names.push(render_ip_bytes(bytes)),
            _ => {}
        }
    }
    if names.is_empty() {
        return None;
    }
    Some(names.join(", "))
}

/// Renders an encoded IP SAN (4 or 16 bytes) as text.
fn render_ip_bytes(bytes: &[u8]) -> String {
    match bytes {
        [a, b, c, d] => format!("{a}.{b}.{c}.{d}"),
        bytes if bytes.len() == 16 => bytes
            .chunks_exact(2)
            .map(|pair| format!("{:02x}{:02x}", pair[0], pair[1]))
            .collect::<Vec<_>>()
            .join(":"),
        _ => hex_bytes(bytes),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Splits the probe domain into (host, port): "host" defaults to port 443
/// (mirroring the core's SplitHostPort); "host:port" splits on the last
/// colon; a bare IPv6 literal without brackets is kept whole; "[v6]:port"
/// splits normally.
fn split_host_port(domain: &str) -> Result<(String, u16), String> {
    let domain = domain.trim();
    if domain.is_empty() {
        return Err("domain is empty".into());
    }
    if domain.starts_with('[') {
        let Some((rest, port)) = domain.rsplit_once(']') else {
            return Err("unbalanced '[' in domain".into());
        };
        let host = rest.trim_start_matches('[');
        if host.is_empty() {
            return Err("empty host".into());
        }
        if port.is_empty() {
            return Ok((host.to_string(), DEFAULT_QUIC_PORT));
        }
        let port = port
            .strip_prefix(':')
            .ok_or_else(|| format!("expected ':port' after ']' in {domain:?}"))?;
        let port: u16 = port.parse().map_err(|_| format!("invalid port {port:?}"))?;
        return Ok((host.to_string(), port));
    }
    match domain.rsplit_once(':') {
        Some((host, _)) if host.contains(':') => {
            // Bare IPv6 literal without brackets; treat the whole as host.
            Ok((domain.to_string(), DEFAULT_QUIC_PORT))
        }
        Some((host, port)) => {
            if host.is_empty() {
                return Err("empty host".into());
            }
            let port: u16 = port.parse().map_err(|_| format!("invalid port {port:?}"))?;
            Ok((host.to_string(), port))
        }
        None => Ok((domain.to_string(), DEFAULT_QUIC_PORT)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DnType, KeyPair};

    fn make_cert(common_name: &str, dns_names: &[String]) -> Vec<u8> {
        let mut params = CertificateParams::new(dns_names.to_vec()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        let key = KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    #[test]
    fn transcript_matches_probe_parsers() {
        let leaf = make_cert(
            "leaf.example.com",
            &["example.com".into(), "www.example.com".into()],
        );
        let ca = make_cert("Probe Intermediate", &[]);
        let transcript = render_transcript(
            "rm-eco.example.com",
            9000,
            "rm-eco.example.com",
            &[leaf.clone(), ca.clone()],
        );
        assert!(transcript.starts_with("QUIC handshake:  rm-eco.example.com:9000\n"));
        assert!(transcript.contains("SNI:  rm-eco.example.com\n"));
        assert!(transcript.contains("Handshake succeeded\n"));
        assert!(transcript.contains("TLS Version:  TLS 1.3\n"));
        assert!(transcript.contains("ALPN:  h3\n"));
        assert!(transcript.contains(&format!(
            "Certificate chain's total length:\t{} (certs count: 2)\n",
            leaf.len() + ca.len()
        )));
        assert!(transcript.contains(&format!("Cert's leaf SHA256:\t{}\n", sha256_hex(&leaf))));
        assert!(transcript.contains(&format!(
            "Cert's CA <Probe Intermediate> SHA256:\t{}\n",
            sha256_hex(&ca)
        )));
        assert!(transcript.contains("Cert's allowed domains:\t[example.com, www.example.com]\n"));
        // The pin panel parses the transcript with the same prefixes as
        // `xray tls ping` output; assert the exact line shapes here.
        let leaf_line = format!("Cert's leaf SHA256:\t{}", sha256_hex(&leaf));
        assert_eq!(
            transcript
                .lines()
                .find(|line| line.starts_with("Cert's leaf SHA256:"))
                .unwrap(),
            leaf_line
        );
        let ca_line = format!(
            "Cert's CA <Probe Intermediate> SHA256:\t{}",
            sha256_hex(&ca)
        );
        assert_eq!(
            transcript
                .lines()
                .find(|line| line.starts_with("Cert's CA <"))
                .unwrap(),
            ca_line
        );
    }

    #[test]
    fn transcript_with_single_leaf_cert() {
        let leaf = make_cert("node.example.com", &["node.example.com".into()]);
        let transcript = render_transcript("node.example.com", 443, "node.example.com", &[leaf]);
        assert!(transcript.contains("(certs count: 1)"));
        assert!(!transcript.contains("Cert's CA <"));
    }

    #[test]
    fn split_host_port_cases() {
        assert_eq!(
            split_host_port("example.com"),
            Ok(("example.com".into(), 443))
        );
        assert_eq!(
            split_host_port("example.com:9000"),
            Ok(("example.com".into(), 9000))
        );
        assert_eq!(
            split_host_port("example.com:65536"),
            Err("invalid port \"65536\"".into())
        );
        assert_eq!(
            split_host_port("example.com:abc"),
            Err("invalid port \"abc\"".into())
        );
        assert_eq!(split_host_port(""), Err("domain is empty".into()));
        assert_eq!(split_host_port(":9000"), Err("empty host".into()));
        assert_eq!(split_host_port("::1"), Ok(("::1".into(), 443)));
        assert_eq!(split_host_port("[::1]:9000"), Ok(("::1".into(), 9000)));
        assert_eq!(
            split_host_port("[2001:db8::1]"),
            Ok(("2001:db8::1".into(), 443))
        );
    }

    #[test]
    fn sha256_hex_matches_sha2_direct() {
        let der = make_cert("h.example.com", &["h.example.com".into()]);
        let digest = Sha256::digest(&der);
        let expected: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(sha256_hex(&der), expected);
    }

    #[test]
    fn render_ip_bytes_forms() {
        assert_eq!(render_ip_bytes(&[1, 2, 3, 4]), "1.2.3.4");
        assert_eq!(
            render_ip_bytes(&[
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ]),
            "2001:0db8:0000:0000:0000:0000:0000:0001"
        );
        assert_eq!(render_ip_bytes(&[0xab]), "ab");
    }

    /// Point it at another server with BROCCOLI_QUIC_HOST/PORT.
    #[tokio::test]
    #[ignore = "network; run manually"]
    async fn live_capture_smoke() {
        let host = std::env::var("BROCCOLI_QUIC_HOST").unwrap_or_else(|_| "cloudflare.com".into());
        let port: u16 = std::env::var("BROCCOLI_QUIC_PORT")
            .ok()
            .and_then(|port| port.parse().ok())
            .unwrap_or(443);
        let addrs = resolve(&host, port, "").await.unwrap();
        let chain = capture(&addrs, &host).await.unwrap();
        assert!(!chain.is_empty());
        let transcript = render_transcript(&host, port, &host, &chain);
        assert!(transcript.contains("Cert's leaf SHA256:\t"));
    }
}
