//! Plain-data HTTP requests / responses and shared handling: origin checks, redirects, size limits, status code mapping.

use std::fmt;
use std::time::Duration;

use url::Url;

use crate::error::CloudError;

/// An HTTP method. Executors should send [`Method::as_str`] rather than match on the variants, so new methods need no
/// change on their side.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Method {
    /// `GET`.
    Get,
    /// `PUT`.
    Put,
    /// `PATCH`.
    Patch,
    /// `POST`.
    Post,
    /// `DELETE`.
    Delete,
    /// WebDAV `PROPFIND` (RFC 4918).
    Propfind,
    /// WebDAV `MKCOL` (RFC 4918).
    Mkcol,
    /// WebDAV `MOVE` (RFC 4918).
    Move,
}

impl Method {
    /// The method name as sent on the wire, such as `"PROPFIND"`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Post => "POST",
            Self::Delete => "DELETE",
            Self::Propfind => "PROPFIND",
            Self::Mkcol => "MKCOL",
            Self::Move => "MOVE",
        }
    }
}

/// A request built by the crate for the caller to execute. Send it as is: do not follow redirects, store cookies or use
/// a cache.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HttpRequest {
    /// The request method.
    pub method: Method,
    /// The absolute URL, including the query string.
    pub url: String,
    /// Header names and values, in order. Names may repeat.
    pub headers: Vec<(String, String)>,
    /// The request body; empty when there is none.
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// A request without headers or body.
    #[must_use]
    pub fn new(method: Method, url: impl Into<String>) -> Self {
        Self { method, url: url.into(), headers: Vec::new(), body: Vec::new() }
    }

    /// Adds a header.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Sets the body.
    #[must_use]
    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// The value of the first header with this name, compared case-insensitively, with surrounding whitespace trimmed.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        find_header(&self.headers, name)
    }
}

/// `Debug` omits header values and the body: they may contain credentials or user data.
impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self.headers.iter().map(|(name, _)| name.as_str()).collect();
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &redacted_url(&self.url))
            .field("headers", &names)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// The response the caller builds after executing a request. Header names are case-insensitive.
///
/// ```
/// # use cloudset::HttpResponse;
/// let response = HttpResponse::new(207).with_header("Content-Type", "application/xml").with_body(b"<multistatus/>".to_vec());
/// assert_eq!(response.header("content-type"), Some("application/xml"));
/// ```
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HttpResponse {
    /// The status code, including 1xx–5xx codes as received (redirects are not followed by the executor).
    pub status: u16,
    /// Header names and values, in order.
    pub headers: Vec<(String, String)>,
    /// The body, read up to [`Limits::max_body_bytes`] + 1 bytes.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// A response with this status, no headers and an empty body.
    #[must_use]
    pub fn new(status: u16) -> Self {
        Self { status, headers: Vec::new(), body: Vec::new() }
    }

    /// Adds a header.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Adds several headers.
    #[must_use]
    pub fn with_headers<N: Into<String>, V: Into<String>>(mut self, headers: impl IntoIterator<Item = (N, V)>) -> Self {
        self.headers.extend(headers.into_iter().map(|(name, value)| (name.into(), value.into())));
        self
    }

    /// Sets the body.
    #[must_use]
    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// The value of the first header with this name, compared case-insensitively, with surrounding whitespace trimmed.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        find_header(&self.headers, name)
    }

    /// Whether the status is 2xx.
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponse").field("status", &self.status).field("body_len", &self.body.len()).finish()
    }
}

fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.trim())
}

/// A pre-signed URL can carry a credential in its path as well as its query.
fn redacted_url(url: &str) -> String {
    Url::parse(url).map(|parsed| parsed.origin().ascii_serialization()).unwrap_or_else(|_| "<invalid url>".to_owned())
}

/// Resource limits. Data from the remote is checked against them before it is parsed.
///
/// ```
/// # use cloudset::Limits;
/// let limits = Limits::default().with_max_body_bytes(256 * 1024 * 1024);
/// assert_eq!(limits.max_body_bytes, 256 * 1024 * 1024);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// Maximum bytes in one response body, and so the largest file [`crate::Client::read`] returns. The executor reads
    /// at most this many bytes plus one; anything longer is reported as [`CloudError::TooLarge`]. Default: 16 MiB.
    pub max_body_bytes: usize,
    /// Maximum entries accepted from one directory listing. Default: 10,000.
    pub max_entries: usize,
    /// Maximum redirects followed for one request. Default: 5.
    pub max_redirects: u8,
    /// Size of one request body in a chunked upload. Dropbox, OneDrive and Google Drive upload a file larger than this
    /// (on Google Drive, larger than 5 MiB) through an upload session in pieces of this size, rounded down to what the
    /// provider accepts (a multiple of 4 MiB on Dropbox, 320 KiB on OneDrive and 256 KiB on Google Drive), but at least
    /// one such unit. Default: 10 MiB.
    ///
    /// OneDrive rejects revision-matched writes that require an upload session.
    pub upload_chunk_bytes: usize,
}

impl Limits {
    /// Sets [`Limits::max_body_bytes`].
    #[must_use]
    pub fn with_max_body_bytes(mut self, bytes: usize) -> Self {
        self.max_body_bytes = bytes;
        self
    }

    /// Sets [`Limits::max_entries`].
    #[must_use]
    pub fn with_max_entries(mut self, entries: usize) -> Self {
        self.max_entries = entries;
        self
    }

    /// Sets [`Limits::max_redirects`].
    #[must_use]
    pub fn with_max_redirects(mut self, redirects: u8) -> Self {
        self.max_redirects = redirects;
        self
    }

    /// Sets [`Limits::upload_chunk_bytes`].
    #[must_use]
    pub fn with_upload_chunk_bytes(mut self, bytes: usize) -> Self {
        self.upload_chunk_bytes = bytes;
        self
    }

    /// The chunk size for a provider whose chunks must be a multiple of `unit` and at most `max` bytes.
    pub(crate) fn chunk_size(&self, unit: usize, max: usize) -> usize {
        (self.upload_chunk_bytes.min(max) / unit).max(1) * unit
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self { max_body_bytes: 16 * 1024 * 1024, max_entries: 10_000, max_redirects: 5, upload_chunk_bytes: 10 * 1024 * 1024 }
    }
}

/// Scheme + host + port. Requests may only go to the origin configured for the connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Origin {
    secure: bool,
    host: String,
    port: Option<u16>,
}

impl Origin {
    pub(crate) fn of(url: &Url) -> Self {
        Self {
            secure: url.scheme() == "https",
            host: url.host_str().unwrap_or_default().to_ascii_lowercase(),
            port: url.port_or_known_default(),
        }
    }

    /// Same origin, or an upgrade from HTTP to HTTPS on the same host (ports compared using scheme defaults). Downgrades are
    /// never accepted.
    pub(crate) fn admits(&self, url: &Url) -> bool {
        let other = Self::of(url);
        if !matches!(url.scheme(), "http" | "https") || other.host != self.host {
            return false;
        }
        match (self.secure, other.secure) {
            (true, true) | (false, false) => other.port == self.port,
            (false, true) => other.port == Some(443) && self.port == Some(80),
            (true, false) => false,
        }
    }
}

/// One request round trip: follows same-origin redirects, checks the response size, and hands the final response to the
/// caller to interpret.
#[derive(Clone, Debug)]
pub(crate) struct Exchange {
    request: HttpRequest,
    redirects: u8,
    /// Off for protocols that use 3xx codes for something else (308 "Resume Incomplete" in Google's resumable uploads).
    follow_redirects: bool,
}

pub(crate) enum Received {
    /// Must be sent again (redirect).
    Resend(HttpRequest),
    /// Final response.
    Final(HttpResponse),
}

impl Exchange {
    pub(crate) fn new(request: HttpRequest) -> Self {
        Self { request, redirects: 0, follow_redirects: true }
    }

    pub(crate) fn without_redirects(mut self) -> Self {
        self.follow_redirects = false;
        self
    }

    pub(crate) fn request(&self) -> HttpRequest {
        self.request.clone()
    }

    pub(crate) fn receive(&mut self, response: HttpResponse, origin: &Origin, limits: &Limits) -> Result<Received, CloudError> {
        if response.body.len() > limits.max_body_bytes {
            return Err(CloudError::TooLarge);
        }
        if !self.follow_redirects || !matches!(response.status, 301 | 302 | 303 | 307 | 308) {
            return Ok(Received::Final(response));
        }
        if self.redirects >= limits.max_redirects {
            return Err(CloudError::TooManyRedirects);
        }
        let location = response.header("Location").ok_or(CloudError::InvalidResponse("redirect without location"))?;
        let current = Url::parse(&self.request.url).map_err(|_| CloudError::InvalidResponse("request url"))?;
        let mut target = current.join(location).map_err(|_| CloudError::InvalidResponse("redirect location"))?;
        // Credentials in the URL would reach the transport as a second, server-chosen identity.
        let has_userinfo = !target.username().is_empty() || target.password().is_some();
        if has_userinfo || !origin.admits(&target) || (current.scheme() == "https" && target.scheme() != "https") {
            return Err(CloudError::InsecureRedirect);
        }
        // 303 answers with a different resource, to be fetched with GET. Following it for any other method would run
        // a GET in place of the request and report that GET's status as the outcome of a write.
        if response.status == 303 && self.request.method != Method::Get {
            return Err(CloudError::InvalidResponse("unexpected redirect"));
        }
        target.set_fragment(None);
        // Other codes keep the method and body (WebDAV methods must be kept on 301 / 302 too). A `Destination` on the
        // old origin moves along, so a `MOVE` upgraded to HTTPS does not name a destination on another scheme.
        for (name, value) in &mut self.request.headers {
            if name.eq_ignore_ascii_case("Destination")
                && let Ok(destination) = Url::parse(value)
                && destination.origin() == current.origin()
                && destination.origin() != target.origin()
            {
                let mut moved = target.clone();
                moved.set_path(destination.path());
                moved.set_query(destination.query());
                *value = moved.to_string();
            }
        }
        self.redirects += 1;
        self.request.url = target.to_string();
        Ok(Received::Resend(self.request.clone()))
    }
}

/// Common mapping for unexpected status codes.
pub(crate) fn status_error(response: &HttpResponse) -> CloudError {
    match response.status {
        401 => CloudError::ReauthRequired,
        403 => CloudError::Forbidden,
        404 | 410 => CloudError::NotFound,
        412 => CloudError::PreconditionFailed,
        507 => CloudError::QuotaExceeded,
        429 | 503 => CloudError::RateLimited { retry_after: retry_after(response) },
        status => CloudError::Server { status },
    }
}

pub(crate) fn retry_after(response: &HttpResponse) -> Option<Duration> {
    let value = response.header("Retry-After")?;
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    // The HTTP-date form cannot be turned into a delay without the current time; leave it to the caller's default backoff.
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin(url: &str) -> Origin {
        Origin::of(&Url::parse(url).unwrap())
    }

    fn redirect(status: u16, location: &str) -> HttpResponse {
        HttpResponse { status, headers: vec![("location".into(), location.into())], body: Vec::new() }
    }

    fn request(method: Method, url: &str) -> HttpRequest {
        HttpRequest { method, url: url.into(), headers: vec![("Content-Type".into(), "text/xml".into())], body: b"x".to_vec() }
    }

    #[test]
    fn origin_rules() {
        let https = origin("https://Example.com/dav/");
        assert!(https.admits(&Url::parse("https://example.com:443/other").unwrap()));
        assert!(!https.admits(&Url::parse("http://example.com/dav/").unwrap()), "no downgrade");
        assert!(!https.admits(&Url::parse("https://example.com:8443/").unwrap()));
        assert!(!https.admits(&Url::parse("https://evil.com/").unwrap()));
        let http = origin("http://nas.local:8080/");
        assert!(http.admits(&Url::parse("http://nas.local:8080/x").unwrap()));
        assert!(!http.admits(&Url::parse("https://nas.local/x").unwrap()), "a non-default port is not treated as an upgrade");
        assert!(origin("http://nas.local/").admits(&Url::parse("https://nas.local/x").unwrap()), "default port upgrades to HTTPS");
    }

    #[test]
    fn follows_same_origin_redirects_preserving_method() {
        let limits = Limits::default();
        let origin = origin("https://example.com/");
        let mut exchange = Exchange::new(request(Method::Propfind, "https://example.com/dav/a"));
        let Received::Resend(next) = exchange.receive(redirect(301, "/dav/a/"), &origin, &limits).unwrap() else { panic!() };
        assert_eq!((next.method, next.url.as_str(), next.body.as_slice()), (Method::Propfind, "https://example.com/dav/a/", &b"x"[..]));
        // 303 points at another resource: never a stand-in for the outcome of a write.
        assert_eq!(exchange.receive(redirect(303, "b"), &origin, &limits).err(), Some(CloudError::InvalidResponse("unexpected redirect")));
        let mut get = Exchange::new(HttpRequest::new(Method::Get, "https://example.com/dav/a"));
        let Received::Resend(next) = get.receive(redirect(303, "b#section"), &origin, &limits).unwrap() else { panic!() };
        assert_eq!((next.method, next.url.as_str()), (Method::Get, "https://example.com/dav/b"), "the fragment is dropped");
    }

    #[test]
    fn redirects_stay_on_http_and_carry_the_destination_along() {
        let limits = Limits::default();
        let http = origin("http://nas.local/");
        for location in ["ws://nas.local/x", "ftp://nas.local:80/x", "app://nas.local:80/run"] {
            assert!(!http.admits(&Url::parse(location).unwrap()), "{location}");
            let mut exchange = Exchange::new(request(Method::Get, "http://nas.local/dav/a"));
            assert_eq!(exchange.receive(redirect(307, location), &http, &limits).err(), Some(CloudError::InsecureRedirect));
        }
        let mut exchange = Exchange::new(request(Method::Get, "http://nas.local/dav/a"));
        assert_eq!(exchange.receive(redirect(302, "http://user:pw@nas.local/x"), &http, &limits).err(), Some(CloudError::InsecureRedirect));

        let mut moving = Exchange::new(
            HttpRequest::new(Method::Move, "http://nas.local/dav/a").with_header("Destination", "http://nas.local/dav/b%20c?x=1"),
        );
        let Received::Resend(next) = moving.receive(redirect(301, "https://nas.local/dav/a"), &http, &limits).unwrap() else { panic!() };
        assert_eq!((next.url.as_str(), next.header("Destination")), ("https://nas.local/dav/a", Some("https://nas.local/dav/b%20c?x=1")));
        let mut elsewhere =
            Exchange::new(HttpRequest::new(Method::Move, "http://nas.local/dav/a").with_header("Destination", "http://other.local/dav/b"));
        let Received::Resend(next) = elsewhere.receive(redirect(301, "https://nas.local/dav/a"), &http, &limits).unwrap() else { panic!() };
        assert_eq!(next.header("Destination"), Some("http://other.local/dav/b"), "only a destination on the old origin moves");
    }

    #[test]
    fn refuses_unsafe_redirects() {
        let limits = Limits { max_redirects: 1, ..Limits::default() };
        let origin = origin("https://example.com/");
        let mut exchange = Exchange::new(request(Method::Get, "https://example.com/a"));
        assert_eq!(exchange.receive(redirect(302, "https://evil.com/"), &origin, &limits).err(), Some(CloudError::InsecureRedirect));
        assert_eq!(exchange.receive(redirect(302, "http://example.com/"), &origin, &limits).err(), Some(CloudError::InsecureRedirect));
        assert!(matches!(exchange.receive(redirect(302, "/b"), &origin, &limits), Ok(Received::Resend(_))));
        assert_eq!(exchange.receive(redirect(302, "/c"), &origin, &limits).err(), Some(CloudError::TooManyRedirects));
        let mut missing = Exchange::new(request(Method::Get, "https://example.com/a"));
        assert!(matches!(missing.receive(HttpResponse::new(302), &origin, &limits), Err(CloudError::InvalidResponse(_))));
    }

    #[test]
    fn enforces_body_limit_and_maps_status() {
        let limits = Limits { max_body_bytes: 2, ..Limits::default() };
        let origin = origin("https://example.com/");
        let mut exchange = Exchange::new(request(Method::Get, "https://example.com/a"));
        let big = HttpResponse { status: 200, headers: Vec::new(), body: vec![0; 3] };
        assert_eq!(exchange.receive(big, &origin, &limits).err(), Some(CloudError::TooLarge));

        let limited = HttpResponse { status: 429, headers: vec![("Retry-After".into(), "120".into())], body: Vec::new() };
        assert_eq!(status_error(&limited), CloudError::RateLimited { retry_after: Some(Duration::from_secs(120)) });
        assert_eq!(status_error(&HttpResponse::new(401)), CloudError::ReauthRequired);
        assert_eq!(status_error(&HttpResponse::new(507)), CloudError::QuotaExceeded);
        assert_eq!(status_error(&HttpResponse::new(500)), CloudError::Server { status: 500 });
    }

    #[test]
    fn debug_hides_secrets() {
        let mut request = request(Method::Get, "https://example.com/secret-path?token=secret");
        request.headers.push(("Authorization".into(), "Basic c2VjcmV0".into()));
        let text = format!("{request:?}");
        assert!(!text.contains("secret") && !text.contains("c2VjcmV0"), "{text}");
    }
}
