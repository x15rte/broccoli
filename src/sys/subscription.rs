//! Subscription fetch: one GET with the app's own limits.
//!
//! User-triggered only — no timer, no refresh on launch. One attempt per
//! fetch: 15 s total, 10 s connect, 16 MiB body, redirects capped at 10. The
//! request takes the resolved outbound carrier: Bind NIC binds the physical
//! uplink the latency probe resolves, Native follows the OS stack (so TUN
//! intercepts it while up), and SOCKS5 dials the configured proxy. The fetch
//! never substitutes one carrier for another.

use std::time::Duration;

/// The body cap.
pub const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
/// The whole-request deadline.
pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(15);
/// The connect deadline.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The redirect hop cap.
pub const MAX_REDIRECTS: usize = 10;

/// The carrier one fetch uses. The caller resolves it from the effective
/// outbound path ([`crate::sys::outbound_path`]) before starting the worker;
/// the fetch itself never falls back to another carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchTransport {
    /// Follow the OS stack; with TUN up the tunnel captures the request.
    Native,
    /// Bind the request's sockets to this source address (Bind NIC).
    Bind(std::net::IpAddr),
    /// Dial through a SOCKS5 proxy. The target's host name is resolved by the
    /// proxy (`socks5h`), so the fetch leaks no lookup to the OS stack, and
    /// the connection to the proxy itself takes no extra bind — the user's
    /// routing owns that leg.
    Socks5 {
        host: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
    },
}

/// The provider headers this client reads.
#[derive(Debug, Clone, Default)]
pub struct FetchHeaders {
    pub subscription_userinfo: String,
    pub profile_title: String,
    pub profile_update_interval: String,
    pub profile_web_page_url: String,
    pub support_url: String,
    pub announce: String,
}

/// One successful fetch.
#[derive(Debug, Clone, Default)]
pub struct FetchOutcome {
    pub body: String,
    pub headers: FetchHeaders,
}

/// Why a fetch failed. The UI renders the headline through its own keys and
/// keeps `detail` as the provider/transport text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// The URL is not a URL this client can request.
    Url(String),
    /// The client could not be built.
    Client(String),
    /// The SOCKS5 carrier is unusable: a required field is missing, or the
    /// proxy could not be configured. Never falls back to the OS stack.
    Socks5(String),
    /// The request failed before a response arrived.
    Request(String),
    /// The response status was not 2xx.
    Status(u16),
    /// The body crossed the size cap.
    TooLarge,
    /// The deadline elapsed.
    Timeout,
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Url(detail) => write!(f, "invalid URL: {detail}"),
            Self::Client(detail) => write!(f, "client setup failed: {detail}"),
            Self::Socks5(detail) => write!(f, "socks5 proxy unusable: {detail}"),
            Self::Request(detail) => write!(f, "request failed: {detail}"),
            Self::Status(status) => write!(f, "HTTP status {status}"),
            Self::TooLarge => write!(f, "body exceeds {MAX_BODY_BYTES} bytes"),
            Self::Timeout => write!(f, "request timed out after {TOTAL_TIMEOUT:?}"),
        }
    }
}

/// Fetch `url` over `transport`. `user_agent` empty means no `User-Agent`
/// header.
pub fn fetch(
    url: &str,
    user_agent: &str,
    transport: FetchTransport,
) -> Result<FetchOutcome, FetchError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| FetchError::Client(error.to_string()))?;
    runtime.block_on(fetch_async(url, user_agent, transport))
}

async fn fetch_async(
    url: &str,
    user_agent: &str,
    transport: FetchTransport,
) -> Result<FetchOutcome, FetchError> {
    let (parsed, basic) = request_target(url)?;

    let builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(MAX_REDIRECTS))
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(TOTAL_TIMEOUT);
    let builder = match transport {
        FetchTransport::Native => builder,
        FetchTransport::Bind(address) => builder.local_address(address),
        FetchTransport::Socks5 {
            host,
            port,
            username,
            password,
        } => builder.proxy(socks5_proxy(
            &host,
            port,
            username.as_deref(),
            password.as_deref(),
        )?),
    };
    let client = builder
        .build()
        .map_err(|error| FetchError::Client(error.to_string()))?;

    let mut request = client.get(parsed);
    if !user_agent.is_empty() {
        request = request.header(reqwest::header::USER_AGENT, user_agent);
    }
    if let Some((username, password)) = basic {
        request = request.basic_auth(username, Some(password));
    }

    let deadline = tokio::time::Instant::now() + TOTAL_TIMEOUT;
    let response = match tokio::time::timeout_at(deadline, request.send()).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            if error.is_timeout() {
                return Err(FetchError::Timeout);
            }
            return Err(FetchError::Request(error.to_string()));
        }
        Err(_) => return Err(FetchError::Timeout),
    };
    let status = response.status();
    if !status.is_success() {
        return Err(FetchError::Status(status.as_u16()));
    }
    let headers = headers_of(&response);

    let mut body = Vec::new();
    let mut response = response;
    loop {
        let chunk = match tokio::time::timeout_at(deadline, response.chunk()).await {
            Ok(Ok(chunk)) => chunk,
            Ok(Err(error)) => return Err(FetchError::Request(error.to_string())),
            Err(_) => return Err(FetchError::Timeout),
        };
        let Some(chunk) = chunk else {
            break;
        };
        if body.len() + chunk.len() > MAX_BODY_BYTES {
            return Err(FetchError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }

    Ok(FetchOutcome {
        body: String::from_utf8_lossy(&body).into_owned(),
        headers,
    })
}

/// The SOCKS5 client proxy. A blank host or a zero port is refused here so a
/// half-filled configuration never silently becomes a Native fetch, and the
/// credentials travel through `Proxy::basic_auth` rather than the proxy URL.
fn socks5_proxy(
    host: &str,
    port: u16,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<reqwest::Proxy, FetchError> {
    let url = socks5_proxy_url(host, port)?;
    let mut proxy =
        reqwest::Proxy::all(url).map_err(|error| FetchError::Socks5(error.to_string()))?;
    if let Some(username) = username.filter(|name| !name.trim().is_empty()) {
        proxy = proxy.basic_auth(username, password.unwrap_or_default());
    }
    Ok(proxy)
}

/// The proxy URL `socks5_proxy` dials. `socks5h` makes the proxy resolve the
/// target's host name, so the fetch does not leak a DNS lookup to the OS
/// stack. An IPv6 literal is bracketed for the URL parser.
fn socks5_proxy_url(host: &str, port: u16) -> Result<String, FetchError> {
    let host = host.trim();
    if host.is_empty() {
        return Err(FetchError::Socks5("host is unset".into()));
    }
    if port == 0 {
        return Err(FetchError::Socks5("port is unset".into()));
    }
    let bracketed = host.starts_with('[') && host.ends_with(']');
    if host.contains(':') && !bracketed {
        return Ok(format!("socks5h://[{host}]:{port}"));
    }
    Ok(format!("socks5h://{host}:{port}"))
}

/// Parse the URL and lift `user:password@` out of it into Basic-auth
/// credentials; the request URL itself carries no credentials.
fn request_target(url: &str) -> Result<(url::Url, Option<(String, String)>), FetchError> {
    let mut parsed = url::Url::parse(url).map_err(|error| FetchError::Url(error.to_string()))?;
    let username = parsed.username();
    let basic = if username.is_empty() {
        None
    } else {
        let password = parsed.password().unwrap_or_default();
        let decode = |text: &str| {
            percent_encoding::percent_decode_str(text)
                .decode_utf8_lossy()
                .into_owned()
        };
        let credentials = (decode(username), decode(password));
        parsed.set_username("").ok();
        parsed.set_password(None).ok();
        Some(credentials)
    };
    Ok((parsed, basic))
}

fn headers_of(response: &reqwest::Response) -> FetchHeaders {
    let get = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    };
    FetchHeaders {
        subscription_userinfo: get("subscription-userinfo"),
        profile_title: get("profile-title"),
        profile_update_interval: get("profile-update-interval"),
        profile_web_page_url: get("profile-web-page-url"),
        support_url: get("support-url"),
        announce: get("announce"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_invalid_url_fails_before_any_request() {
        assert!(matches!(
            fetch("not a url", "", FetchTransport::Native),
            Err(FetchError::Url(_))
        ));
    }

    #[test]
    fn credentials_move_from_the_url_to_basic_auth() {
        let (url, basic) = request_target("https://user:p%40ss@example.com/feed?x=1").expect("url");
        assert_eq!(url.as_str(), "https://example.com/feed?x=1");
        assert_eq!(basic, Some(("user".to_owned(), "p@ss".to_owned())));
        let (url, basic) = request_target("https://example.com/feed").expect("url");
        assert_eq!(url.as_str(), "https://example.com/feed");
        assert!(basic.is_none());
    }

    #[test]
    fn socks5_proxy_url_names_the_host_and_port() {
        assert_eq!(
            socks5_proxy_url("proxy.example", 1080).expect("url"),
            "socks5h://proxy.example:1080",
            "the proxy resolves the target name, so the OS stack sees no lookup"
        );
        assert_eq!(
            socks5_proxy_url("  proxy.example  ", 1080).expect("url"),
            "socks5h://proxy.example:1080",
            "the host is trimmed"
        );
        assert_eq!(
            socks5_proxy_url("::1", 1080).expect("url"),
            "socks5h://[::1]:1080",
            "an IPv6 literal is bracketed for the URL parser"
        );
        assert_eq!(
            socks5_proxy_url("[::1]", 1080).expect("url"),
            "socks5h://[::1]:1080",
            "an already bracketed literal is not bracketed twice"
        );
        let url = socks5_proxy_url("proxy.example", 1080).expect("url");
        assert!(
            !url.contains('@'),
            "the proxy URL must carry no credentials: {url}"
        );
    }

    #[test]
    fn missing_socks5_fields_fail_before_any_request() {
        for host in ["", "   "] {
            let error = fetch(
                "https://example.com/feed",
                "",
                FetchTransport::Socks5 {
                    host: host.into(),
                    port: 1080,
                    username: None,
                    password: None,
                },
            )
            .expect_err("a blank host must fail loudly");
            assert!(
                matches!(&error, FetchError::Socks5(detail) if detail.contains("host")),
                "{error:?}"
            );
        }

        let error = fetch(
            "https://example.com/feed",
            "",
            FetchTransport::Socks5 {
                host: "proxy.example".into(),
                port: 0,
                username: None,
                password: None,
            },
        )
        .expect_err("an unset port must fail loudly");
        assert!(
            matches!(&error, FetchError::Socks5(detail) if detail.contains("port")),
            "{error:?}"
        );
    }

    #[test]
    fn socks5_proxy_builds_with_and_without_credentials() {
        socks5_proxy("proxy.example", 1080, None, None).expect("credential-free proxy");
        socks5_proxy("proxy.example", 1080, Some("alice"), Some("s3cr3t"))
            .expect("proxy with auth");
        socks5_proxy("proxy.example", 1080, Some("alice"), None)
            .expect("username without password");
        socks5_proxy("proxy.example", 1080, Some("   "), Some("s3cr3t"))
            .expect("a blank username is treated as absent");
    }
}
