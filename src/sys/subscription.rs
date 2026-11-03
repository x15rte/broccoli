//! Subscription fetch: one GET with the app's own limits.
//!
//! User-triggered only — no timer, no refresh on launch. One attempt per
//! fetch: 15 s total, 10 s connect, 16 MiB body, redirects capped at 10. The
//! request optionally binds the physical uplink the latency probe resolves;
//! otherwise it follows the OS stack (so TUN intercepts it while up).

use std::time::Duration;

/// The body cap.
pub const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
/// The whole-request deadline.
pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(15);
/// The connect deadline.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The redirect hop cap.
pub const MAX_REDIRECTS: usize = 10;

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
            Self::Request(detail) => write!(f, "request failed: {detail}"),
            Self::Status(status) => write!(f, "HTTP status {status}"),
            Self::TooLarge => write!(f, "body exceeds {MAX_BODY_BYTES} bytes"),
            Self::Timeout => write!(f, "request timed out after {TOTAL_TIMEOUT:?}"),
        }
    }
}

/// Fetch `url`. `user_agent` empty means no `User-Agent` header;
/// `bind_address` is the uplink adapter's source address the sockets bind to,
/// or `None` for the OS stack.
pub fn fetch(
    url: &str,
    user_agent: &str,
    bind_address: Option<std::net::IpAddr>,
) -> Result<FetchOutcome, FetchError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| FetchError::Client(error.to_string()))?;
    runtime.block_on(fetch_async(url, user_agent, bind_address))
}

async fn fetch_async(
    url: &str,
    user_agent: &str,
    bind_address: Option<std::net::IpAddr>,
) -> Result<FetchOutcome, FetchError> {
    let (parsed, basic) = request_target(url)?;

    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(MAX_REDIRECTS))
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(TOTAL_TIMEOUT);
    if let Some(address) = bind_address {
        builder = builder.local_address(address);
    }
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
            fetch("not a url", "", None),
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
}
