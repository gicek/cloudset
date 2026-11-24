//! Server addresses and connections (address + credentials). A connection serializes to an opaque blob that the caller
//! stores in the system keychain without parsing it.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::error::CloudError;
use crate::http::Origin;
use crate::path::RemotePath;
use crate::synology::quickconnect::{QuickConnectId, Region};

/// A storage provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProviderKind {
    /// Any WebDAV server (RFC 4918).
    WebDav,
    /// Nextcloud, signed in with Login Flow v2 and accessed over WebDAV.
    Nextcloud,
    /// Dropbox (API v2).
    Dropbox,
    /// OneDrive (Microsoft Graph).
    OneDrive,
    /// Google Drive (Drive API v3).
    GoogleDrive,
    /// Synology DSM 7 through the File Station API, reached directly or through QuickConnect (see [`crate::synology`]).
    Synology,
}

impl ProviderKind {
    /// Supported access scopes, in order of preference. Providers with an app-specific folder list `AppFolder` first:
    /// callers use it by default and treat it directly as the working directory, so users need not browse remote
    /// directories. WebDAV, Nextcloud and Synology have no app folder and their credentials reach the whole account, so
    /// they only offer `Full`.
    #[must_use]
    pub fn access_scopes(self) -> &'static [AccessScope] {
        match self {
            Self::Dropbox | Self::OneDrive | Self::GoogleDrive => &[AccessScope::AppFolder, AccessScope::Full],
            Self::WebDav | Self::Nextcloud | Self::Synology => &[AccessScope::Full],
        }
    }
}

/// Whether plain HTTP is allowed. Pass `AllowInsecureHttp` only for self-hosted servers the user explicitly confirmed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Transport {
    /// Only `https://` addresses.
    RequireHttps,
    /// `http://` addresses too.
    AllowInsecureHttp,
}

/// A validated server address: `http(s)://host[:port]/path/`, without user info, query string, or fragment; the path ends
/// with `/`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    url: Url,
}

impl Endpoint {
    /// Completes the scheme of a server address typed by the user. Input that already has `scheme://` is returned as is
    /// (trimmed). Otherwise, an IP address host (IPv4, or IPv6 in brackets) gets `http://`, since LAN NAS devices rarely
    /// have certificates, and anything else (a domain name) gets `https://`. The platform uses the completed address to
    /// decide whether plain HTTP must be confirmed first, then passes it to [`Endpoint::parse`].
    ///
    /// ```
    /// # use cloudset::Endpoint;
    /// assert_eq!(Endpoint::complete_address("cloud.example.com"), "https://cloud.example.com");
    /// assert_eq!(Endpoint::complete_address("192.168.1.10:5005/dav"), "http://192.168.1.10:5005/dav");
    /// ```
    #[must_use]
    pub fn complete_address(input: &str) -> String {
        let text = input.trim();
        // A scheme only counts in front of the address, not inside its path or query.
        let has_scheme = text.find("://").is_some_and(|colon| text.find(['/', '?', '#']) == Some(colon + 1));
        if text.is_empty() || has_scheme {
            return text.to_owned();
        }
        let authority = text.split(['/', '?', '#']).next().unwrap_or_default();
        let host = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
        let is_ip = if let Some(rest) = host.strip_prefix('[') {
            rest.split(']').next().is_some_and(|inner| inner.parse::<std::net::Ipv6Addr>().is_ok())
        } else {
            host.split(':').next().is_some_and(|name| name.parse::<std::net::Ipv4Addr>().is_ok())
        };
        format!("{}://{text}", if is_ip { "http" } else { "https" })
    }

    /// Parses and validates a server address. A trailing `/` is added to the path.
    ///
    /// # Errors
    ///
    /// [`CloudError::InsecureEndpoint`] for `http://` with [`Transport::RequireHttps`]; [`CloudError::InvalidEndpoint`]
    /// for anything that is not an `http(s)://` URL with a host, or that has user info, a query string or a fragment.
    pub fn parse(text: &str, transport: Transport) -> Result<Self, CloudError> {
        let mut url = Url::parse(text.trim()).map_err(|_| CloudError::InvalidEndpoint("not a url"))?;
        match url.scheme() {
            "https" => {}
            "http" if transport == Transport::AllowInsecureHttp => {}
            "http" => return Err(CloudError::InsecureEndpoint),
            _ => return Err(CloudError::InvalidEndpoint("scheme")),
        }
        if url.host_str().is_none_or(str::is_empty) {
            return Err(CloudError::InvalidEndpoint("host"));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(CloudError::InvalidEndpoint("credentials in url"));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(CloudError::InvalidEndpoint("query"));
        }
        if !url.path().ends_with('/') {
            let path = format!("{}/", url.path());
            url.set_path(&path);
        }
        Ok(Self { url })
    }

    /// The normalized address.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    /// Whether the address is `https://`.
    #[must_use]
    pub fn is_secure(&self) -> bool {
        self.url.scheme() == "https"
    }

    /// The host name.
    #[must_use]
    pub fn host(&self) -> &str {
        self.url.host_str().unwrap_or_default()
    }

    pub(crate) fn url(&self) -> &Url {
        &self.url
    }

    pub(crate) fn origin(&self) -> Origin {
        Origin::of(&self.url)
    }

    /// URL of a path under this address; directories end with `/`. Each segment is encoded by URL path rules.
    pub(crate) fn resolve(&self, path: &RemotePath, is_dir: bool) -> Result<Url, CloudError> {
        let mut url = self.url.clone();
        {
            let mut segments = url.path_segments_mut().map_err(|()| CloudError::InvalidEndpoint("base"))?;
            segments.pop_if_empty().extend(path.segments());
            if is_dir {
                segments.push("");
            }
        }
        // RFC 3986 does not allow these in a path, and strict servers answer 400 to them unencoded.
        if url.path().contains(['[', ']', '|', '^']) {
            let path = url.path().replace('[', "%5B").replace(']', "%5D").replace('|', "%7C").replace('^', "%5E");
            url.set_path(&path);
        }
        Ok(url)
    }

    /// A relative reference under this address (`index.php/login/v2`).
    pub(crate) fn join(&self, relative: &str) -> Result<Url, CloudError> {
        self.url.join(relative).map_err(|_| CloudError::InvalidEndpoint("join"))
    }
}

/// A server certificate the user confirmed: SHA-256 of the leaf certificate DER. When system validation fails, the
/// executor accepts only a certificate that matches it exactly. Fingerprints are not secret, so `Debug` prints it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PinnedCertificate([u8; 32]);

impl PinnedCertificate {
    /// A fingerprint from the 32 bytes of a SHA-256 digest.
    ///
    /// # Errors
    ///
    /// [`CloudError::InvalidEndpoint`] unless `bytes` is exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CloudError> {
        <[u8; 32]>::try_from(bytes).map(Self).map_err(|_| CloudError::InvalidEndpoint("certificate fingerprint"))
    }

    /// The digest.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn to_hex(self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// Accepts only 64 lowercase hex digits (as written by [`Self::to_hex`]).
    fn from_hex(text: &str) -> Option<Self> {
        if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return None;
        }
        let mut bytes = [0; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
        }
        Some(Self(bytes))
    }
}

impl fmt::Debug for PinnedCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PinnedCertificate({})", self.to_hex())
    }
}

/// A pinned certificate and the origin it applies to: only requests to this origin (same scheme, host, and port) carry
/// it; all other requests use system validation alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificatePin {
    certificate: PinnedCertificate,
    origin: Origin,
}

impl CertificatePin {
    /// A pin for the origin of `endpoint`.
    ///
    /// # Errors
    ///
    /// [`CloudError::InvalidEndpoint`] for a plain HTTP address, which has no certificate.
    pub fn new(endpoint: &Endpoint, certificate: PinnedCertificate) -> Result<Self, CloudError> {
        if !endpoint.is_secure() {
            return Err(CloudError::InvalidEndpoint("certificate pin needs https"));
        }
        Ok(Self { certificate, origin: endpoint.origin() })
    }

    /// The pinned fingerprint.
    #[must_use]
    pub fn certificate(&self) -> PinnedCertificate {
        self.certificate
    }

    /// Whether requests to `url` carry this pinned certificate.
    #[must_use]
    pub fn applies_to(&self, url: &str) -> bool {
        Url::parse(url).is_ok_and(|url| Origin::of(&url) == self.origin)
    }
}

/// Access scope of an OAuth provider: read and write only the app-specific folder, or the whole drive (directory chosen
/// by the user).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AccessScope {
    /// Only the app's own folder; paths are relative to it.
    AppFolder,
    /// The whole drive; paths are relative to its root.
    Full,
}

/// Credentials of an OAuth connection: the access token is used in memory only and serialized with the connection so
/// every launch need not refresh; the refresh token is the long-lived credential.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct OAuthCredential {
    pub provider: ProviderKind,
    pub access: AccessScope,
    pub client_id: String,
    /// The client secret of a Google desktop client, needed again for every refresh. `None` for clients without one.
    pub client_secret: Option<Zeroizing<String>>,
    pub access_token: Zeroizing<String>,
    pub refresh_token: Zeroizing<String>,
    pub expires_at: Option<SystemTime>,
    /// Account shown to the user (email or display name).
    pub account: String,
    /// Google Drive with the app folder scope: name of the folder in the drive root that serves as the app folder (Drive
    /// has no app folder of its own). `None` everywhere else.
    pub folder_name: Option<String>,
}

/// Credentials of a Synology connection. The password stays because DSM sessions expire and have to be renewed without
/// the user; the device token lets that renewal skip two-step verification.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SynologyCredential {
    /// The DSM address (`https://nas.example.com:5001/`, or a QuickConnect route).
    pub endpoint: Endpoint,
    /// The folder that serves as the connection root: a shared folder, optionally followed by a path inside it.
    pub root: RemotePath,
    pub username: String,
    pub password: Zeroizing<String>,
    /// Trusted-device token (`did`) issued at a sign-in with a one-time code.
    pub device_token: Option<Zeroizing<String>>,
    /// The current session ID (`sid`); `None` until the first sign-in or after it was revoked.
    pub session: Option<Zeroizing<String>>,
    /// The QuickConnect ID this address was resolved from, and the region of its control host.
    pub quickconnect: Option<(QuickConnectId, Region)>,
    pub certificate: Option<PinnedCertificate>,
}

#[derive(Clone, PartialEq, Eq)]
enum Kind {
    WebDav {
        endpoint: Endpoint,
        username: String,
        password: Zeroizing<String>,
        certificate: Option<PinnedCertificate>,
    },
    /// Nextcloud: besides the WebDAV address, remembers the server root address for revoking the app password.
    Nextcloud {
        server: Endpoint,
        endpoint: Endpoint,
        username: String,
        password: Zeroizing<String>,
        certificate: Option<PinnedCertificate>,
    },
    OAuth(OAuthCredential),
    Synology(SynologyCredential),
}

/// Everything needed to access one storage. `Debug` does not print passwords or tokens.
#[derive(Clone, PartialEq, Eq)]
pub struct Connection {
    kind: Kind,
}

const STORED_VERSION: u8 = 1;

/// Serialized form: one flat table, with `provider` deciding which fields are required and which are forbidden.
#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Stored {
    version: u8,
    provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    access: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    access_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    /// Unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account: Option<String>,
    /// Google Drive app folder name; present exactly when the provider is Google Drive with the app folder scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    app_folder: Option<String>,
    /// Lowercase hex SHA-256 of the pinned certificate; only present on `https://` WebDAV / Nextcloud / Synology.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pinned_certificate: Option<String>,
    /// Synology: the root folder (`shared folder/path`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    root: Option<String>,
    /// Synology: the trusted-device token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_token: Option<String>,
    /// Synology: the current session ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session: Option<String>,
    /// Synology: the QuickConnect ID the address came from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    quickconnect_id: Option<String>,
    /// Synology: the QuickConnect region; present exactly when `quickconnect_id` is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    region: Option<String>,
}

impl Stored {
    fn has_oauth_fields(&self) -> bool {
        self.access.is_some()
            || self.client_id.is_some()
            || self.client_secret.is_some()
            || self.access_token.is_some()
            || self.refresh_token.is_some()
            || self.expires_at.is_some()
            || self.account.is_some()
            || self.app_folder.is_some()
    }

    fn has_synology_fields(&self) -> bool {
        self.root.is_some()
            || self.device_token.is_some()
            || self.session.is_some()
            || self.quickconnect_id.is_some()
            || self.region.is_some()
    }

    fn pinned_certificate(&self) -> Result<Option<PinnedCertificate>, CloudError> {
        self.pinned_certificate.as_deref().map(|hex| PinnedCertificate::from_hex(hex).ok_or(CloudError::InvalidConnection)).transpose()
    }
}

impl Drop for Stored {
    /// Wipes the passwords and tokens in intermediate copies.
    fn drop(&mut self) {
        let secrets = [
            &mut self.password,
            &mut self.client_secret,
            &mut self.access_token,
            &mut self.refresh_token,
            &mut self.device_token,
            &mut self.session,
        ];
        for secret in secrets.into_iter().flatten() {
            secret.zeroize();
        }
    }
}

fn provider_name(provider: ProviderKind) -> &'static str {
    match provider {
        ProviderKind::WebDav => "webdav",
        ProviderKind::Nextcloud => "nextcloud",
        ProviderKind::Dropbox => "dropbox",
        ProviderKind::OneDrive => "onedrive",
        ProviderKind::GoogleDrive => "googledrive",
        ProviderKind::Synology => "synology",
    }
}

impl Connection {
    /// A WebDAV connection. `endpoint` is the collection used as the root; the user name and password are sent with
    /// HTTP Basic authentication. For Nextcloud, prefer an app password (see [`crate::nextcloud`]).
    #[must_use]
    pub fn webdav(endpoint: Endpoint, username: impl Into<String>, password: impl Into<String>) -> Self {
        Self { kind: Kind::WebDav { endpoint, username: username.into(), password: Zeroizing::new(password.into()), certificate: None } }
    }

    pub(crate) fn nextcloud(server: Endpoint, endpoint: Endpoint, username: String, password: String) -> Self {
        Self { kind: Kind::Nextcloud { server, endpoint, username, password: Zeroizing::new(password), certificate: None } }
    }

    /// Pins a server certificate the user confirmed. Only WebDAV, Nextcloud and Synology connections whose addresses are
    /// all `https://` can do this.
    ///
    /// # Errors
    ///
    /// [`CloudError::InvalidEndpoint`] for OAuth providers, which must be trusted by the system, and for plain HTTP,
    /// which has no certificate.
    pub fn with_pinned_certificate(mut self, pinned: PinnedCertificate) -> Result<Self, CloudError> {
        let refused = CloudError::InvalidEndpoint("certificate pin needs https");
        match &mut self.kind {
            Kind::WebDav { endpoint, certificate, .. } if endpoint.is_secure() => *certificate = Some(pinned),
            Kind::Nextcloud { server, endpoint, certificate, .. } if server.is_secure() && endpoint.is_secure() => {
                *certificate = Some(pinned);
            }
            Kind::Synology(credential) if credential.endpoint.is_secure() => credential.certificate = Some(pinned),
            _ => return Err(refused),
        }
        Ok(self)
    }

    /// The pinned certificate and its origin (the origin of the WebDAV or DSM address; for Nextcloud, the server's origin,
    /// which the WebDAV address shares).
    #[must_use]
    pub fn certificate_pin(&self) -> Option<CertificatePin> {
        let (origin_of, certificate) = match &self.kind {
            Kind::WebDav { endpoint, certificate, .. } => (endpoint, certificate),
            Kind::Nextcloud { server, certificate, .. } => (server, certificate),
            Kind::Synology(credential) => (&credential.endpoint, &credential.certificate),
            Kind::OAuth(_) => return None,
        };
        certificate.and_then(|certificate| CertificatePin::new(origin_of, certificate).ok())
    }

    pub(crate) fn oauth(credential: OAuthCredential) -> Self {
        Self { kind: Kind::OAuth(credential) }
    }

    pub(crate) fn synology(credential: SynologyCredential) -> Self {
        Self { kind: Kind::Synology(credential) }
    }

    pub(crate) fn synology_credential(&self) -> Option<&SynologyCredential> {
        match &self.kind {
            Kind::Synology(credential) => Some(credential),
            _ => None,
        }
    }

    /// Moves a Synology connection to another address of the same device, such as a QuickConnect route that
    /// [`Resolution::probe`](crate::synology::quickconnect::Resolution::probe) found. The password goes to the new
    /// address from then on, protected by its certificate. When the origin changes, the pinned certificate (which belongs
    /// to the old origin) and the session (DSM ties it to the client's IP) are dropped; the next operation signs in again.
    /// The old session is not signed out: DSM ends it after its idle timeout.
    ///
    /// # Errors
    ///
    /// [`CloudError::InvalidConnection`] for any other provider, whose address is fixed, and
    /// [`CloudError::InsecureEndpoint`] for a move from `https://` to plain HTTP.
    pub fn with_endpoint(mut self, endpoint: Endpoint) -> Result<Self, CloudError> {
        let Kind::Synology(credential) = &mut self.kind else { return Err(CloudError::InvalidConnection) };
        if credential.endpoint.is_secure() && !endpoint.is_secure() {
            return Err(CloudError::InsecureEndpoint);
        }
        if credential.endpoint.origin() != endpoint.origin() {
            credential.certificate = None;
            credential.session = None;
        }
        credential.endpoint = endpoint;
        Ok(self)
    }

    /// The QuickConnect ID a Synology connection was resolved from and the region of its control host; resolve it again
    /// when the stored address stops answering (the device moved, or the client left the local network).
    #[must_use]
    pub fn quickconnect(&self) -> Option<(&QuickConnectId, Region)> {
        match &self.kind {
            Kind::Synology(SynologyCredential { quickconnect: Some((id, region)), .. }) => Some((id, *region)),
            _ => None,
        }
    }

    /// The provider.
    #[must_use]
    pub fn provider(&self) -> ProviderKind {
        match &self.kind {
            Kind::WebDav { .. } => ProviderKind::WebDav,
            Kind::Nextcloud { .. } => ProviderKind::Nextcloud,
            Kind::OAuth(credential) => credential.provider,
            Kind::Synology(_) => ProviderKind::Synology,
        }
    }

    /// WebDAV root address (`…/remote.php/dav/files/<user>/` on Nextcloud), or the DSM address on Synology; `None` for
    /// OAuth providers.
    #[must_use]
    pub fn endpoint(&self) -> Option<&Endpoint> {
        match &self.kind {
            Kind::WebDav { endpoint, .. } | Kind::Nextcloud { endpoint, .. } => Some(endpoint),
            Kind::Synology(credential) => Some(&credential.endpoint),
            Kind::OAuth(_) => None,
        }
    }

    /// The Synology root folder (`shared folder/path`) that paths are relative to; `None` for everything else.
    #[must_use]
    pub fn root_folder(&self) -> Option<&RemotePath> {
        self.synology_credential().map(|credential| &credential.root)
    }

    /// Nextcloud server root address; `None` for everything else.
    #[must_use]
    pub fn server(&self) -> Option<&Endpoint> {
        match &self.kind {
            Kind::Nextcloud { server, .. } => Some(server),
            _ => None,
        }
    }

    /// The account to show the user: the WebDAV or DSM user name, the Nextcloud login name, or the email address (or,
    /// when the provider has none, the display name) of an OAuth account.
    #[must_use]
    pub fn account(&self) -> &str {
        match &self.kind {
            Kind::WebDav { username, .. } | Kind::Nextcloud { username, .. } => username,
            Kind::Synology(credential) => &credential.username,
            Kind::OAuth(credential) => &credential.account,
        }
    }

    /// Host name for display.
    #[must_use]
    pub fn host(&self) -> &str {
        match &self.kind {
            Kind::WebDav { endpoint, .. } => endpoint.host(),
            Kind::Nextcloud { server, .. } => server.host(),
            Kind::Synology(credential) => credential.endpoint.host(),
            Kind::OAuth(credential) => match credential.provider {
                ProviderKind::Dropbox => "dropbox.com",
                ProviderKind::OneDrive => "onedrive.live.com",
                ProviderKind::GoogleDrive => "drive.google.com",
                ProviderKind::WebDav | ProviderKind::Nextcloud | ProviderKind::Synology => "",
            },
        }
    }

    /// Whether the transport is encrypted: false only for plain-HTTP WebDAV / Nextcloud / Synology the user confirmed.
    #[must_use]
    pub fn is_secure(&self) -> bool {
        match &self.kind {
            Kind::WebDav { endpoint, .. } => endpoint.is_secure(),
            Kind::Nextcloud { server, .. } => server.is_secure(),
            Kind::Synology(credential) => credential.endpoint.is_secure(),
            Kind::OAuth(_) => true,
        }
    }

    /// Access scope of an OAuth provider; `None` for everything else (WebDAV reaches the whole account anyway).
    #[must_use]
    pub fn access_scope(&self) -> Option<AccessScope> {
        match &self.kind {
            Kind::OAuth(credential) => Some(credential.access),
            _ => None,
        }
    }

    pub(crate) fn oauth_credential(&self) -> Option<&OAuthCredential> {
        match &self.kind {
            Kind::OAuth(credential) => Some(credential),
            _ => None,
        }
    }

    pub(crate) fn basic_authorization(&self) -> Zeroizing<String> {
        let (username, password) = match &self.kind {
            Kind::WebDav { username, password, .. } | Kind::Nextcloud { username, password, .. } => (username.as_str(), password.as_str()),
            Kind::OAuth(_) | Kind::Synology(_) => ("", ""),
        };
        let credentials = Zeroizing::new(format!("{username}:{password}"));
        Zeroizing::new(format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes())))
    }

    /// The connection, credentials included, as an opaque versioned blob. Store it in the system keychain or credential
    /// manager as is.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut stored = Stored::default();
        stored.version = STORED_VERSION;
        stored.provider = provider_name(self.provider()).to_owned();
        match &self.kind {
            Kind::WebDav { endpoint, username, password, certificate } => {
                stored.endpoint = Some(endpoint.as_str().to_owned());
                stored.username = Some(username.clone());
                stored.password = Some(password.to_string());
                stored.pinned_certificate = certificate.map(PinnedCertificate::to_hex);
            }
            Kind::Nextcloud { server, endpoint, username, password, certificate } => {
                stored.endpoint = Some(endpoint.as_str().to_owned());
                stored.server = Some(server.as_str().to_owned());
                stored.username = Some(username.clone());
                stored.password = Some(password.to_string());
                stored.pinned_certificate = certificate.map(PinnedCertificate::to_hex);
            }
            Kind::OAuth(credential) => {
                stored.access = Some(match credential.access {
                    AccessScope::AppFolder => "appFolder".to_owned(),
                    AccessScope::Full => "full".to_owned(),
                });
                stored.client_id = Some(credential.client_id.clone());
                stored.client_secret = credential.client_secret.as_ref().map(|secret| secret.to_string());
                stored.access_token = Some(credential.access_token.to_string());
                stored.refresh_token = Some(credential.refresh_token.to_string());
                stored.expires_at = credential.expires_at.and_then(|at| at.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs());
                stored.account = Some(credential.account.clone());
                stored.app_folder = credential.folder_name.clone();
            }
            Kind::Synology(credential) => {
                stored.endpoint = Some(credential.endpoint.as_str().to_owned());
                stored.root = Some(credential.root.to_string());
                stored.username = Some(credential.username.clone());
                stored.password = Some(credential.password.to_string());
                stored.device_token = credential.device_token.as_ref().map(|token| token.to_string());
                stored.session = credential.session.as_ref().map(|session| session.to_string());
                if let Some((id, region)) = &credential.quickconnect {
                    stored.quickconnect_id = Some(id.as_str().to_owned());
                    stored.region = Some(region.as_str().to_owned());
                }
                stored.pinned_certificate = credential.certificate.map(PinnedCertificate::to_hex);
            }
        }
        Zeroizing::new(serde_json::to_vec(&stored).unwrap_or_default())
    }

    /// Restores a connection from [`Connection::to_bytes`]. Stored addresses were already confirmed by the user, so plain
    /// HTTP is accepted.
    ///
    /// # Errors
    ///
    /// [`CloudError::InvalidConnection`] for anything unreadable: an unknown version, missing or extra fields, or an
    /// invalid address.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CloudError> {
        let mut stored: Stored = serde_json::from_slice(bytes).map_err(|_| CloudError::InvalidConnection)?;
        if stored.version != STORED_VERSION {
            return Err(CloudError::InvalidConnection);
        }
        let parse = |text: &str| Endpoint::parse(text, Transport::AllowInsecureHttp).map_err(|_| CloudError::InvalidConnection);
        let invalid = || CloudError::InvalidConnection;
        let kind = match stored.provider.as_str() {
            "webdav" | "nextcloud" => {
                if stored.has_oauth_fields() || stored.has_synology_fields() {
                    return Err(invalid());
                }
                let endpoint = parse(stored.endpoint.as_deref().ok_or_else(invalid)?)?;
                let username = stored.username.take().ok_or_else(invalid)?;
                let password = Zeroizing::new(stored.password.take().ok_or_else(invalid)?);
                let certificate = stored.pinned_certificate()?;
                let kind = match (stored.provider.as_str(), stored.server.as_deref()) {
                    ("webdav", None) => Kind::WebDav { endpoint, username, password, certificate: None },
                    ("nextcloud", Some(server)) => {
                        Kind::Nextcloud { server: parse(server)?, endpoint, username, password, certificate: None }
                    }
                    _ => return Err(invalid()),
                };
                // A pinned certificate may only sit on an https address (the same rule as `with_pinned_certificate`).
                let connection = Self { kind };
                return match certificate {
                    Some(certificate) => connection.with_pinned_certificate(certificate).map_err(|_| invalid()),
                    None => Ok(connection),
                };
            }
            "synology" => {
                if stored.has_oauth_fields() || stored.server.is_some() {
                    return Err(invalid());
                }
                let quickconnect = match (stored.quickconnect_id.as_deref(), stored.region.as_deref()) {
                    (Some(id), Some(region)) => {
                        Some((QuickConnectId::parse(id).map_err(|_| invalid())?, Region::from_name(region).ok_or_else(invalid)?))
                    }
                    (None, None) => None,
                    _ => return Err(invalid()),
                };
                let certificate = stored.pinned_certificate()?;
                let non_empty = |value: Option<String>| value.filter(|value| !value.is_empty()).map(Zeroizing::new);
                let credential = SynologyCredential {
                    endpoint: parse(stored.endpoint.as_deref().ok_or_else(invalid)?)?,
                    root: stored
                        .root
                        .as_deref()
                        .and_then(|root| RemotePath::parse(root).ok())
                        .filter(|root| !root.is_root())
                        .ok_or_else(invalid)?,
                    username: stored.username.take().filter(|name| !name.is_empty()).ok_or_else(invalid)?,
                    password: Zeroizing::new(stored.password.take().ok_or_else(invalid)?),
                    device_token: non_empty(stored.device_token.take()),
                    session: non_empty(stored.session.take()),
                    quickconnect,
                    certificate: None,
                };
                let connection = Self::synology(credential);
                return match certificate {
                    Some(certificate) => connection.with_pinned_certificate(certificate).map_err(|_| invalid()),
                    None => Ok(connection),
                };
            }
            "dropbox" | "onedrive" | "googledrive" => {
                if stored.has_synology_fields()
                    || stored.endpoint.is_some()
                    || stored.server.is_some()
                    || stored.username.is_some()
                    || stored.password.is_some()
                    || stored.pinned_certificate.is_some()
                {
                    return Err(invalid());
                }
                let access = match stored.access.as_deref() {
                    Some("appFolder") => AccessScope::AppFolder,
                    Some("full") => AccessScope::Full,
                    _ => return Err(invalid()),
                };
                let provider = match stored.provider.as_str() {
                    "dropbox" => ProviderKind::Dropbox,
                    "onedrive" => ProviderKind::OneDrive,
                    _ => ProviderKind::GoogleDrive,
                };
                // The Google Drive app folder is a named folder: required with that scope, meaningless anywhere else.
                let folder_name = match (provider, access, stored.app_folder.take()) {
                    (ProviderKind::GoogleDrive, AccessScope::AppFolder, Some(name)) if RemotePath::root().join(&name).is_ok() => Some(name),
                    (ProviderKind::GoogleDrive, AccessScope::AppFolder, _) => return Err(invalid()),
                    (_, _, None) => None,
                    (_, _, Some(_)) => return Err(invalid()),
                };
                Kind::OAuth(OAuthCredential {
                    provider,
                    access,
                    client_id: stored.client_id.take().filter(|id| !id.is_empty()).ok_or_else(invalid)?,
                    client_secret: match stored.client_secret.take() {
                        Some(secret) if secret.is_empty() => return Err(invalid()),
                        secret => secret.map(Zeroizing::new),
                    },
                    access_token: Zeroizing::new(stored.access_token.take().ok_or_else(invalid)?),
                    refresh_token: Zeroizing::new(stored.refresh_token.take().filter(|token| !token.is_empty()).ok_or_else(invalid)?),
                    expires_at: stored
                        .expires_at
                        .map(|secs| UNIX_EPOCH.checked_add(Duration::from_secs(secs)).ok_or_else(invalid))
                        .transpose()?,
                    account: stored.account.take().unwrap_or_default(),
                    folder_name,
                })
            }
            _ => return Err(invalid()),
        };
        Ok(Self { kind })
    }
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("provider", &self.provider())
            .field("host", &self.host())
            .field("account", &self.account())
            .field("secret", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn completes_missing_schemes_by_host_kind() {
        assert_eq!(Endpoint::complete_address("cloud.example.com"), "https://cloud.example.com");
        assert_eq!(Endpoint::complete_address("  nas.example.com:8443/dav/ "), "https://nas.example.com:8443/dav/");
        assert_eq!(Endpoint::complete_address("192.168.1.10"), "http://192.168.1.10");
        assert_eq!(Endpoint::complete_address("192.168.1.10:5005/webdav"), "http://192.168.1.10:5005/webdav");
        assert_eq!(Endpoint::complete_address("[fd00::1]:8080/dav"), "http://[fd00::1]:8080/dav");
        assert_eq!(Endpoint::complete_address("https://192.168.1.10"), "https://192.168.1.10", "an explicit scheme is kept");
        assert_eq!(Endpoint::complete_address("http://cloud.example.com"), "http://cloud.example.com");
        assert_eq!(Endpoint::complete_address("999.1.1.1"), "https://999.1.1.1", "an invalid IP is treated as a domain name");
        assert_eq!(Endpoint::complete_address("   "), "");
        assert_eq!(Endpoint::complete_address("example.com/dav?next=http://x"), "https://example.com/dav?next=http://x");
        assert_eq!(Endpoint::complete_address("192.168.1.10/a://b"), "http://192.168.1.10/a://b");
        assert!(
            Endpoint::parse(&Endpoint::complete_address("192.168.1.10"), Transport::RequireHttps).is_err(),
            "an IP gets plain HTTP, which must be confirmed first"
        );
    }

    use super::*;

    #[test]
    fn app_folder_comes_first_where_it_exists() {
        for provider in [ProviderKind::Dropbox, ProviderKind::OneDrive, ProviderKind::GoogleDrive] {
            assert_eq!(provider.access_scopes(), [AccessScope::AppFolder, AccessScope::Full]);
        }
        for provider in [ProviderKind::WebDav, ProviderKind::Nextcloud, ProviderKind::Synology] {
            assert_eq!(provider.access_scopes(), [AccessScope::Full]);
        }
    }

    fn synology() -> Connection {
        Connection::synology(SynologyCredential {
            endpoint: Endpoint::parse("https://my-nas.cn4.quickconnect.cn/", Transport::RequireHttps).unwrap(),
            root: RemotePath::parse("home/Notes").unwrap(),
            username: "alice".into(),
            password: Zeroizing::new("dsm-password".into()),
            device_token: Some(Zeroizing::new("device-token".into())),
            session: Some(Zeroizing::new("session-id".into())),
            quickconnect: Some((QuickConnectId::parse("my-nas").unwrap(), Region::ChinaMainland)),
            certificate: None,
        })
    }

    #[test]
    fn synology_connections_round_trip_and_validate() {
        let connection = synology();
        let restored = Connection::from_bytes(&connection.to_bytes()).unwrap();
        assert_eq!(restored, connection);
        assert_eq!(
            (restored.provider(), restored.host(), restored.account()),
            (ProviderKind::Synology, "my-nas.cn4.quickconnect.cn", "alice")
        );
        assert_eq!(restored.root_folder().map(ToString::to_string).as_deref(), Some("home/Notes"));
        assert_eq!(restored.quickconnect().map(|(id, region)| (id.as_str(), region)), Some(("my-nas", Region::ChinaMainland)));
        assert_eq!(restored.access_scope(), None);
        let debug = format!("{connection:?}");
        assert!(!["dsm-password", "device-token", "session-id"].iter().any(|secret| debug.contains(secret)), "{debug}");

        let base = r#""version":1,"provider":"synology","endpoint":"https://nas.local:5001/","username":"a","password":"b""#;
        assert!(Connection::from_bytes(format!(r#"{{{base},"root":"home"}}"#).as_bytes()).unwrap().quickconnect().is_none());
        for bad in [
            format!("{{{base}}}"),
            format!(r#"{{{base},"root":""}}"#),
            format!(r#"{{{base},"root":"a/../b"}}"#),
            format!(r#"{{{base},"root":"home","quickconnectId":"my-nas"}}"#),
            format!(r#"{{{base},"root":"home","quickconnectId":"my-nas","region":"mars"}}"#),
            format!(r#"{{{base},"root":"home","quickconnectId":"-bad","region":"global"}}"#),
            format!(r#"{{{base},"root":"home","region":"global"}}"#),
            format!(r#"{{{base},"root":"home","accessToken":"t"}}"#),
            format!(r#"{{{base},"root":"home","server":"https://x/"}}"#),
            r#"{"version":1,"provider":"synology","endpoint":"http://nas.local:5000/","username":"a","password":"b","root":"home","pinnedCertificate":"abababababababababababababababababababababababababababababababab"}"#.to_owned(),
            r#"{"version":1,"provider":"webdav","endpoint":"https://x/","username":"a","password":"b","root":"home"}"#.to_owned(),
            r#"{"version":1,"provider":"dropbox","access":"full","clientId":"k","accessToken":"a","refreshToken":"r","session":"s"}"#.to_owned(),
        ] {
            assert_eq!(Connection::from_bytes(bad.as_bytes()), Err(CloudError::InvalidConnection), "{bad}");
        }
    }

    #[test]
    fn validates_endpoints() {
        let endpoint = Endpoint::parse(" https://dav.example.com/remote.php/webdav ", Transport::RequireHttps).unwrap();
        assert_eq!(endpoint.as_str(), "https://dav.example.com/remote.php/webdav/");
        assert!(endpoint.is_secure());
        assert_eq!(endpoint.host(), "dav.example.com");

        assert_eq!(Endpoint::parse("http://nas.local:5005/", Transport::RequireHttps), Err(CloudError::InsecureEndpoint));
        assert!(Endpoint::parse("http://nas.local:5005/", Transport::AllowInsecureHttp).is_ok());
        for bad in ["ftp://x/", "https://user:pw@x/", "https://x/?a=1", "https://x/#f", "not a url", "file:///etc/"] {
            assert!(Endpoint::parse(bad, Transport::AllowInsecureHttp).is_err(), "{bad}");
        }
    }

    #[test]
    fn pins_certificates_only_on_https_servers() {
        let certificate = PinnedCertificate::from_slice(&[0xab; 32]).unwrap();
        assert!(PinnedCertificate::from_slice(&[0; 31]).is_err() && PinnedCertificate::from_slice(&[0; 33]).is_err());

        let https = Endpoint::parse("https://nas.local:5006/dav/", Transport::RequireHttps).unwrap();
        let pinned = Connection::webdav(https.clone(), "alice", "pw").with_pinned_certificate(certificate).unwrap();
        let restored = Connection::from_bytes(&pinned.to_bytes()).unwrap();
        assert_eq!(restored, pinned);
        let pin = restored.certificate_pin().unwrap();
        assert_eq!(pin.certificate(), certificate);
        assert!(pin.applies_to("https://nas.local:5006/dav/Backups/data.bin"));
        assert!(pin.applies_to("https://NAS.local:5006/other/"), "host names are case-insensitive");
        for other in ["https://nas.local/dav/", "http://nas.local:5006/dav/", "https://evil.local:5006/dav/", "not a url"] {
            assert!(!pin.applies_to(other), "{other}");
        }
        assert!(Connection::webdav(https.clone(), "alice", "pw").certificate_pin().is_none());

        let http = Endpoint::parse("http://nas.local/dav/", Transport::AllowInsecureHttp).unwrap();
        assert!(Connection::webdav(http.clone(), "a", "b").with_pinned_certificate(certificate).is_err());
        assert!(CertificatePin::new(&http, certificate).is_err());

        let nextcloud =
            Connection::nextcloud(https.clone(), https.clone(), "alice".into(), "app".into()).with_pinned_certificate(certificate).unwrap();
        assert_eq!(Connection::from_bytes(&nextcloud.to_bytes()).unwrap().certificate_pin(), nextcloud.certificate_pin());
        assert!(Connection::nextcloud(http.clone(), https, "a".into(), "b".into()).with_pinned_certificate(certificate).is_err());

        let oauth = Connection::oauth(OAuthCredential {
            provider: ProviderKind::OneDrive,
            access: AccessScope::AppFolder,
            client_id: "id".into(),
            client_secret: None,
            access_token: Zeroizing::new("a".into()),
            refresh_token: Zeroizing::new("r".into()),
            expires_at: None,
            account: String::new(),
            folder_name: None,
        });
        assert!(oauth.with_pinned_certificate(certificate).is_err(), "OAuth providers must be system-trusted");

        let hex = "ab".repeat(32);
        let stored = |provider: &str, endpoint: &str, pin: &str| {
            format!(
                r#"{{"version":1,"provider":"{provider}","endpoint":"{endpoint}","username":"a","password":"b","pinnedCertificate":"{pin}"}}"#
            )
        };
        assert!(Connection::from_bytes(stored("webdav", "https://x/", &hex).as_bytes()).is_ok());
        for bad in [
            stored("webdav", "http://x/", &hex),
            stored("webdav", "https://x/", &"AB".repeat(32)),
            stored("webdav", "https://x/", &"ab".repeat(31)),
            stored("webdav", "https://x/", &"zz".repeat(32)),
            format!(
                r#"{{"version":1,"provider":"dropbox","access":"full","clientId":"k","accessToken":"a","refreshToken":"r","pinnedCertificate":"{hex}"}}"#
            ),
        ] {
            assert_eq!(Connection::from_bytes(bad.as_bytes()), Err(CloudError::InvalidConnection), "{bad}");
        }
    }

    #[test]
    fn resolves_paths_with_encoding() {
        let endpoint = Endpoint::parse("https://x.com/dav/", Transport::RequireHttps).unwrap();
        let path = RemotePath::parse("备份/a b#?.txt").unwrap();
        assert_eq!(endpoint.resolve(&path, false).unwrap().as_str(), "https://x.com/dav/%E5%A4%87%E4%BB%BD/a%20b%23%3F.txt");
        assert_eq!(endpoint.resolve(&RemotePath::parse("Backups").unwrap(), true).unwrap().as_str(), "https://x.com/dav/Backups/");
        assert_eq!(endpoint.resolve(&RemotePath::root(), true).unwrap().as_str(), "https://x.com/dav/");
        let brackets = RemotePath::parse("report[1]|^.txt").unwrap();
        assert_eq!(endpoint.resolve(&brackets, false).unwrap().as_str(), "https://x.com/dav/report%5B1%5D%7C%5E.txt");
    }

    #[test]
    fn round_trips_and_redacts() {
        let endpoint = Endpoint::parse("http://nas.local/dav/", Transport::AllowInsecureHttp).unwrap();
        let connection = Connection::webdav(endpoint.clone(), "alice", "s3cret:pw");
        assert_eq!(Connection::from_bytes(&connection.to_bytes()).unwrap(), connection);
        assert_eq!(connection.basic_authorization().as_str(), "Basic YWxpY2U6czNjcmV0OnB3");
        assert!(!format!("{connection:?}").contains("s3cret"));

        let server = Endpoint::parse("https://cloud.example.com/", Transport::RequireHttps).unwrap();
        let nextcloud = Connection::nextcloud(server.clone(), endpoint, "alice".into(), "app".into());
        let restored = Connection::from_bytes(&nextcloud.to_bytes()).unwrap();
        assert_eq!((restored.provider(), restored.server()), (ProviderKind::Nextcloud, Some(&server)));
        assert_eq!(restored.host(), "cloud.example.com");

        let oauth = Connection::oauth(OAuthCredential {
            provider: ProviderKind::Dropbox,
            access: AccessScope::Full,
            client_id: "app-key".into(),
            client_secret: None,
            access_token: Zeroizing::new("sl.access-token".into()),
            refresh_token: Zeroizing::new("refresh-token".into()),
            expires_at: Some(UNIX_EPOCH + Duration::from_secs(1_800_000_000)),
            account: "alice@example.com".into(),
            folder_name: None,
        });
        let restored = Connection::from_bytes(&oauth.to_bytes()).unwrap();
        assert_eq!(restored, oauth);
        assert_eq!((restored.host(), restored.account(), restored.is_secure()), ("dropbox.com", "alice@example.com", true));
        assert_eq!(restored.access_scope(), Some(AccessScope::Full));
        assert!(restored.endpoint().is_none());
        let debug = format!("{oauth:?}");
        assert!(!debug.contains("sl.access-token") && !debug.contains("refresh-token"), "{debug}");

        let google = Connection::oauth(OAuthCredential {
            provider: ProviderKind::GoogleDrive,
            access: AccessScope::AppFolder,
            client_id: "123-abc.apps.googleusercontent.com".into(),
            client_secret: None,
            access_token: Zeroizing::new("ya29.token".into()),
            refresh_token: Zeroizing::new("1//refresh".into()),
            expires_at: None,
            account: "alice@gmail.com".into(),
            folder_name: Some("My App".into()),
        });
        let restored = Connection::from_bytes(&google.to_bytes()).unwrap();
        assert_eq!(restored, google, "the app folder name survives serialization");
        assert_eq!((restored.provider(), restored.host()), (ProviderKind::GoogleDrive, "drive.google.com"));

        for bad in [
            &b"{}"[..],
            b"not json",
            br#"{"version":2,"provider":"webdav","endpoint":"https://x/","username":"a","password":"b"}"#,
            br#"{"version":1,"provider":"webdav","endpoint":"https://x/","server":"https://x/","username":"a","password":"b"}"#,
            br#"{"version":1,"provider":"nextcloud","endpoint":"https://x/","username":"a","password":"b"}"#,
            br#"{"version":1,"provider":"webdav","endpoint":"ftp://x/","username":"a","password":"b"}"#,
            br#"{"version":1,"provider":"webdav","endpoint":"https://x/","username":"a","password":"b","accessToken":"t"}"#,
            br#"{"version":1,"provider":"dropbox","access":"full","clientId":"k","accessToken":"a","refreshToken":""}"#,
            br#"{"version":1,"provider":"onedrive","access":"everything","clientId":"k","accessToken":"a","refreshToken":"r"}"#,
            br#"{"version":1,"provider":"dropbox","access":"full","clientId":"k","accessToken":"a","refreshToken":"r","password":"p"}"#,
            br#"{"version":1,"provider":"gdrive","access":"full","clientId":"k","accessToken":"a","refreshToken":"r"}"#,
            br#"{"version":1,"provider":"googledrive","access":"appFolder","clientId":"k","accessToken":"a","refreshToken":"r"}"#,
            br#"{"version":1,"provider":"googledrive","access":"appFolder","clientId":"k","accessToken":"a","refreshToken":"r","appFolder":"a/b"}"#,
            br#"{"version":1,"provider":"googledrive","access":"full","clientId":"k","accessToken":"a","refreshToken":"r","appFolder":"App"}"#,
            br#"{"version":1,"provider":"onedrive","access":"appFolder","clientId":"k","accessToken":"a","refreshToken":"r","appFolder":"App"}"#,
            br#"{"version":1,"provider":"webdav","endpoint":"https://x/","username":"a","password":"b","appFolder":"App"}"#,
        ] {
            assert_eq!(Connection::from_bytes(bad), Err(CloudError::InvalidConnection));
        }
    }
}
