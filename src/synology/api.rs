//! Synology Web API plumbing shared by sign-in, the session driver and the file operations: requests to `entry.cgi`,
//! the `{"success": …, "data" | "error": …}` envelope, and error codes.
//!
//! Error codes come from Synology's "File Station API Guide" and "DSM Login Web API Guide": 1xx are common to every
//! API, 4xx (in `SYNO.API.Auth`) are sign-in errors, and 4xx and up (in `SYNO.FileStation.*`) are file errors.

use std::time::{Duration, UNIX_EPOCH};

use serde_json::Value;
use zeroize::Zeroizing;

use crate::client::ClientConfig;
use crate::connection::{Endpoint, SynologyCredential};
use crate::entry::Entry;
use crate::error::CloudError;
use crate::http::{HttpRequest, HttpResponse, Method, status_error};
use crate::path::RemotePath;

const ENTRY: &str = "webapi/entry.cgi";
const AUTH: &str = "SYNO.API.Auth";
/// `SYNO.API.Auth` version 6 is DSM 7's, and the first with trusted-device tokens.
const AUTH_VERSION: u8 = 6;
/// The session name DSM shows for the sign-in, and the one `logout` ends.
const SESSION: &str = "FileStation";
/// `additional` fields for listings and lookups.
pub(crate) const ADDITIONAL: &str = r#"["size","time"]"#;
/// Error codes of a session DSM no longer accepts: timed out (106), replaced by another sign-in (107), unknown (119), or
/// used from another IP than the one it was created from (150, unless the administrator turned that check off). Sign
/// in again and replay.
pub(crate) const SESSION_ERRORS: [i64; 4] = [106, 107, 119, 150];
/// File Station: no such file or directory.
pub(crate) const NO_SUCH_FILE: i64 = 408;

/// One Web API call: `api`, `version`, `method`, and parameters.
pub(crate) fn call(api: &str, version: u8, method: &str) -> Vec<(String, String)> {
    vec![("api".into(), api.into()), ("version".into(), version.to_string()), ("method".into(), method.into())]
}

fn entry_url(endpoint: &Endpoint) -> Result<url::Url, CloudError> {
    endpoint.join(ENTRY)
}

/// A form-encoded POST to `entry.cgi`.
pub(crate) fn post(endpoint: &Endpoint, params: &[(String, String)]) -> Result<HttpRequest, CloudError> {
    let body = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(params).finish();
    Ok(HttpRequest::new(Method::Post, entry_url(endpoint)?.as_str())
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_header("Accept", "application/json")
        .with_body(Zeroizing::new(body).as_bytes()))
}

/// A GET to `entry.cgi` with the parameters in the query string (downloads).
pub(crate) fn get(endpoint: &Endpoint, params: &[(String, String)]) -> Result<HttpRequest, CloudError> {
    let mut url = entry_url(endpoint)?;
    url.query_pairs_mut().extend_pairs(params);
    Ok(HttpRequest::new(Method::Get, url.as_str()))
}

/// Adds the session ID to a request's query string.
pub(crate) fn with_session(request: &mut HttpRequest, session: &str) -> Result<(), CloudError> {
    let mut url = url::Url::parse(&request.url).map_err(|_| CloudError::InvalidEndpoint("url"))?;
    url.query_pairs_mut().append_pair("_sid", session);
    request.url = url.into();
    Ok(())
}

/// A JSON array of strings, the form File Station takes for path lists (names may contain commas).
pub(crate) fn json_list(items: &[&str]) -> String {
    Value::from(items.iter().map(|item| Value::from(*item)).collect::<Vec<_>>()).to_string()
}

/// The File Station path of `path` under the connection's root folder: `/<shared folder>/…`.
pub(crate) fn absolute(root: &RemotePath, path: &RemotePath) -> String {
    root.segments().iter().chain(path.segments()).fold(String::new(), |mut out, segment| {
        out.push('/');
        out.push_str(segment);
        out
    })
}

/// The answer of one call.
pub(crate) enum Reply {
    /// `success: true`, with its `data` (`null` when there is none).
    Data(Value),
    /// `success: false`, with the most specific error code: the first per-path code when there is one.
    Failed(i64),
}

impl Reply {
    pub(crate) fn of(response: &HttpResponse) -> Result<Self, CloudError> {
        if !response.is_success() {
            return Err(status_error(response));
        }
        let body: Value = serde_json::from_slice(&response.body).map_err(|_| CloudError::InvalidResponse("json"))?;
        match body.get("success").and_then(Value::as_bool) {
            Some(true) => Ok(Self::Data(body.get("data").cloned().unwrap_or(Value::Null))),
            Some(false) => Ok(Self::Failed(error_code(&body).ok_or(CloudError::InvalidResponse("error code"))?)),
            None => Err(CloudError::InvalidResponse("synology envelope")),
        }
    }

    /// The data, or the error mapped with [`file_error`].
    pub(crate) fn data(self) -> Result<Value, CloudError> {
        match self {
            Self::Data(data) => Ok(data),
            Self::Failed(code) => Err(file_error(code)),
        }
    }
}

fn error_code(body: &Value) -> Option<i64> {
    body.pointer("/error/errors/0/code").and_then(Value::as_i64).or_else(|| body.pointer("/error/code").and_then(Value::as_i64))
}

/// The error code when a response says the session is no longer accepted. Download bodies are file contents, so only a
/// small JSON envelope counts, and not when the server labels the body as something other than JSON.
pub(crate) fn session_error(response: &HttpResponse) -> Option<i64> {
    const ENVELOPE_LIMIT: usize = 4096;
    let labeled_other = response.header("Content-Type").is_some_and(|value| !value.to_ascii_lowercase().contains("json"));
    if response.status != 200 || labeled_other || response.body.len() > ENVELOPE_LIMIT || response.body.first() != Some(&b'{') {
        return None;
    }
    match Reply::of(response) {
        Ok(Reply::Failed(code)) if SESSION_ERRORS.contains(&code) => Some(code),
        _ => None,
    }
}

/// Maps a common or File Station error code.
pub(crate) fn file_error(code: i64) -> CloudError {
    match code {
        // No privilege, no permission for the file or File Station (160), or a file in the folder's way.
        105 | 160 | 403..=407 | 411 | 1004 | 1007 | 1804 => CloudError::Forbidden,
        110 | 402 | 421 => CloudError::RateLimited { retry_after: None },
        NO_SUCH_FILE => CloudError::NotFound,
        // Exists already (CreateFolder, Rename), or the upload or move refused to overwrite it.
        414 | 1003 | 1805 => CloudError::PreconditionFailed,
        415 | 416 => CloudError::QuotaExceeded,
        412 | 413 | 418..=420 | 1006 => CloudError::InvalidPath,
        // Including session codes the driver did not see as such: the password may well still be valid.
        code => CloudError::Provider { code },
    }
}

/// Maps a `SYNO.API.Auth` login error code.
fn login_error(code: i64) -> CloudError {
    match code {
        400 => CloudError::ReauthRequired,
        // 403: a one-time code is needed; 404: the one given was wrong.
        403 | 404 => CloudError::OtpRequired,
        // Disabled account, no permission, two-step verification enforced but not set up, blocked IP, expired password.
        401 | 402 | 406..=410 => CloudError::Forbidden,
        code => file_error(code),
    }
}

/// The sign-in request. With a one-time code, DSM is asked to trust this device, so later sign-ins can do without one.
pub(crate) fn login_request(
    credential: &SynologyCredential,
    otp_code: Option<&str>,
    config: &ClientConfig,
) -> Result<HttpRequest, CloudError> {
    let mut params = call(AUTH, AUTH_VERSION, "login");
    params.extend([
        ("account".into(), credential.username.clone()),
        ("passwd".into(), credential.password.to_string()),
        ("session".into(), SESSION.into()),
        ("format".into(), "sid".into()),
    ]);
    if let Some(code) = otp_code {
        params.extend([
            ("otp_code".into(), code.to_owned()),
            ("enable_device_token".into(), "yes".into()),
            ("device_name".into(), config.user_agent.clone()),
        ]);
    } else if let Some(token) = &credential.device_token {
        params.extend([("device_id".into(), token.to_string()), ("device_name".into(), config.user_agent.clone())]);
    }
    let request = post(&credential.endpoint, &params);
    for (_, value) in &mut params {
        zeroize::Zeroize::zeroize(value);
    }
    request
}

/// Stores the session (and a new device token) from a sign-in response.
pub(crate) fn apply_login(credential: &mut SynologyCredential, response: &HttpResponse) -> Result<(), CloudError> {
    let data = match Reply::of(response)? {
        Reply::Data(data) => data,
        Reply::Failed(code) => return Err(login_error(code)),
    };
    let session = data.get("sid").and_then(Value::as_str).filter(|sid| !sid.is_empty()).ok_or(CloudError::InvalidResponse("sid"))?;
    credential.session = Some(Zeroizing::new(session.to_owned()));
    if let Some(token) = data.get("did").and_then(Value::as_str).filter(|did| !did.is_empty()) {
        credential.device_token = Some(Zeroizing::new(token.to_owned()));
    }
    Ok(())
}

/// Ends the session.
pub(crate) fn logout_request(endpoint: &Endpoint) -> Result<HttpRequest, CloudError> {
    let mut params = call(AUTH, AUTH_VERSION, "logout");
    params.push(("session".into(), SESSION.into()));
    post(endpoint, &params)
}

/// An entry from a File Station file object (`list` and `getinfo`). `path` is the path the caller already knows.
pub(crate) fn entry(item: &Value, path: RemotePath) -> Result<Entry, CloudError> {
    let is_dir = item.get("isdir").and_then(Value::as_bool).ok_or(CloudError::InvalidResponse("isdir"))?;
    let additional = item.get("additional");
    Ok(Entry {
        path,
        is_dir,
        size: additional.and_then(|additional| additional.get("size")).and_then(Value::as_u64).filter(|_| !is_dir),
        modified_at: additional
            .and_then(|additional| additional.pointer("/time/mtime"))
            .and_then(Value::as_u64)
            .and_then(|secs| UNIX_EPOCH.checked_add(Duration::from_secs(secs))),
        revision: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(body: &str) -> HttpResponse {
        HttpResponse::new(200).with_body(body.as_bytes().to_vec())
    }

    #[test]
    fn reads_envelopes_and_prefers_per_path_codes() {
        assert!(matches!(Reply::of(&response(r#"{"success":true}"#)), Ok(Reply::Data(Value::Null))));
        let nested = r#"{"success":false,"error":{"code":900,"errors":[{"code":408,"path":"/home/a"}]}}"#;
        assert!(matches!(Reply::of(&response(nested)), Ok(Reply::Failed(408))));
        assert!(matches!(Reply::of(&response(r#"{"success":false,"error":{"code":119}}"#)), Ok(Reply::Failed(119))));
        assert!(Reply::of(&response(r#"{"data":{}}"#)).is_err());
        assert!(Reply::of(&response(r#"{"success":false}"#)).is_err());
        assert_eq!(Reply::of(&HttpResponse::new(502)).err(), Some(CloudError::Server { status: 502 }));
    }

    #[test]
    fn recognizes_session_errors_only_in_small_envelopes() {
        let expired = r#"{"success":false,"error":{"code":106}}"#;
        assert_eq!(session_error(&response(expired)), Some(106));
        assert_eq!(session_error(&response(expired).with_header("Content-Type", "application/json; charset=UTF-8")), Some(106));
        assert_eq!(session_error(&response(r#"{"success":false,"error":{"code":150}}"#)), Some(150));
        assert_eq!(session_error(&response(r#"{"success":false,"error":{"code":408}}"#)), None);
        assert_eq!(session_error(&response(&format!(r#"{{"success":false,"error":{{"code":119}}}}{}"#, " ".repeat(5000)))), None);
        assert_eq!(session_error(&HttpResponse::new(200).with_body(b"binary".to_vec())), None);
        assert_eq!(
            session_error(&response(expired).with_header("Content-Type", "application/octet-stream")),
            None,
            "a downloaded file that looks like an envelope"
        );
    }

    #[test]
    fn maps_error_codes() {
        assert_eq!(file_error(408), CloudError::NotFound);
        assert_eq!(file_error(1805), CloudError::PreconditionFailed);
        assert_eq!(file_error(416), CloudError::QuotaExceeded);
        assert_eq!(file_error(419), CloudError::InvalidPath);
        assert_eq!(file_error(119), CloudError::Provider { code: 119 }, "not proof of a wrong password");
        assert_eq!(file_error(1100), CloudError::Provider { code: 1100 });
        assert_eq!(file_error(401), CloudError::Provider { code: 401 }, "not an HTTP status");
        assert_eq!(login_error(400), CloudError::ReauthRequired);
        assert_eq!(login_error(403), CloudError::OtpRequired);
        assert_eq!(login_error(407), CloudError::Forbidden);
    }

    #[test]
    fn builds_paths_and_lists() {
        let root = RemotePath::parse("home/Backups").unwrap();
        assert_eq!(absolute(&root, &RemotePath::parse("a b/c,d.txt").unwrap()), "/home/Backups/a b/c,d.txt");
        assert_eq!(absolute(&root, &RemotePath::root()), "/home/Backups");
        assert_eq!(json_list(&["/a,b", "/\"q\""]), r#"["/a,b","/\"q\""]"#);
    }
}
