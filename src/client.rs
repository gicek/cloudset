use std::time::SystemTime;

use crate::connection::{Connection, ProviderKind};
use crate::entry::{Entry, File, Precondition};
use crate::error::CloudError;
use crate::http::Limits;
use crate::operation::BoxOperation;
use crate::operation::Ready;
use crate::path::RemotePath;
use crate::webdav::Dav;
use crate::{dropbox, gdrive, nextcloud, onedrive};

/// Settings shared by every request of a [`Client`].
///
/// ```
/// # use std::time::SystemTime;
/// # use cloudset::{ClientConfig, Limits};
/// let config = ClientConfig::new("MyApp/1.0 (macOS)")
///     .with_limits(Limits::default().with_max_body_bytes(64 * 1024 * 1024))
///     .with_now(SystemTime::now());
/// # let _ = config;
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ClientConfig {
    /// The `User-Agent` header. Nextcloud also shows it as the device name under "Devices & sessions".
    pub user_agent: String,
    /// Resource limits.
    pub limits: Limits,
    /// The current time; the crate never reads the clock. When set, OAuth tokens are refreshed shortly before they
    /// expire; otherwise only after a 401. Set it again for long-lived clients.
    pub now: Option<SystemTime>,
}

impl ClientConfig {
    /// Default limits and no current time.
    #[must_use]
    pub fn new(user_agent: impl Into<String>) -> Self {
        Self { user_agent: user_agent.into(), limits: Limits::default(), now: None }
    }

    /// Sets [`ClientConfig::now`].
    #[must_use]
    pub fn with_now(mut self, now: SystemTime) -> Self {
        self.now = Some(now);
        self
    }

    /// Sets [`ClientConfig::limits`].
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }
}

/// File operations on one connection. Each method returns an independent [`crate::Operation`]; nothing is sent until you
/// advance it.
///
/// Paths are relative to the connection's root: the WebDAV address, the app folder, or the drive root, depending on the
/// provider and [`crate::AccessScope`].
#[derive(Clone, Debug)]
pub struct Client {
    connection: Connection,
    config: ClientConfig,
}

impl Client {
    /// A client for one connection.
    #[must_use]
    pub fn new(connection: Connection, config: ClientConfig) -> Self {
        Self { connection, config }
    }

    /// The connection this client uses.
    #[must_use]
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// The configuration this client uses.
    #[must_use]
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// The same configuration with another connection, such as the refreshed one from [`crate::Done::connection`].
    #[must_use]
    pub fn with_connection(&self, connection: Connection) -> Self {
        Self { connection, config: self.config.clone() }
    }

    /// The same connection with another configuration, such as one with a newer [`ClientConfig::now`].
    #[must_use]
    pub fn with_config(&self, config: ClientConfig) -> Self {
        Self { connection: self.connection.clone(), config }
    }

    fn dav(&self) -> Result<Dav, CloudError> {
        Dav::new(self.connection.clone(), self.config.clone())
    }

    /// Metadata of a file or directory; `None` if it does not exist.
    pub fn stat(&self, path: RemotePath) -> BoxOperation<Option<Entry>> {
        match self.connection.provider() {
            ProviderKind::WebDav | ProviderKind::Nextcloud => dispatch(self.dav(), |dav| dav.stat(path)),
            ProviderKind::Dropbox => dropbox::stat(&self.connection, &self.config, path),
            ProviderKind::OneDrive => onedrive::stat(&self.connection, &self.config, path),
            ProviderKind::GoogleDrive => gdrive::stat(&self.connection, &self.config, path),
        }
    }

    /// Direct children of a directory, sorted by path; a missing directory reports `NotFound`.
    pub fn list(&self, dir: RemotePath) -> BoxOperation<Vec<Entry>> {
        match self.connection.provider() {
            ProviderKind::WebDav | ProviderKind::Nextcloud => dispatch(self.dav(), |dav| dav.list(dir)),
            ProviderKind::Dropbox => dropbox::list(&self.connection, &self.config, dir),
            ProviderKind::OneDrive => onedrive::list(&self.connection, &self.config, dir),
            ProviderKind::GoogleDrive => gdrive::list(&self.connection, &self.config, dir),
        }
    }

    /// File contents with the metadata of the same version; `None` if it does not exist. The file must fit in
    /// [`Limits::max_body_bytes`], otherwise the read fails with [`CloudError::TooLarge`].
    pub fn read(&self, path: RemotePath) -> BoxOperation<Option<File>> {
        match self.connection.provider() {
            ProviderKind::WebDav | ProviderKind::Nextcloud => dispatch(self.dav(), |dav| dav.read(path)),
            ProviderKind::Dropbox => dropbox::read(&self.connection, &self.config, path),
            ProviderKind::OneDrive => onedrive::read(&self.connection, &self.config, path),
            ProviderKind::GoogleDrive => gdrive::read(&self.connection, &self.config, path),
        }
    }

    /// Whether this backend can enforce the requested condition for this payload.
    /// The server can still reject a supported write due to a conflict or permissions.
    #[must_use]
    pub fn supports_write_precondition(&self, size: usize, precondition: &Precondition) -> bool {
        match self.connection.provider() {
            ProviderKind::GoogleDrive => matches!(precondition, Precondition::None),
            ProviderKind::OneDrive => onedrive::supports_write_precondition(&self.config, size, precondition),
            ProviderKind::WebDav | ProviderKind::Nextcloud => !matches!(precondition, Precondition::Matches(rev) if !rev.is_strong_etag()),
            ProviderKind::Dropbox => true,
        }
    }

    /// Writes a file. An unavailable guarantee returns [`CloudError::UnsupportedPrecondition`] before mutation.
    /// A rejected condition returns [`CloudError::PreconditionFailed`]. If confirmation fails after submission,
    /// reconcile the remote content before retrying. Use [`Self::supports_write_precondition`] for capability discovery.
    /// A missing parent directory reports [`CloudError::NotFound`] on WebDAV; Dropbox, OneDrive and Google Drive create
    /// it.
    ///
    /// On Google Drive, where names are not unique, a file created at the same moment as another device's reports
    /// [`CloudError::CommitUnconfirmed`]; the path then resolves to the other device's file.
    ///
    /// On Dropbox, OneDrive and Google Drive, files larger than [`Limits::upload_chunk_bytes`] go up in pieces through an
    /// upload session, so their size is not bound by the providers' single-request limits. The whole file is kept in
    /// memory either way.
    pub fn write(&self, path: RemotePath, data: Vec<u8>, precondition: Precondition) -> BoxOperation<Entry> {
        if path.is_root() {
            return Box::new(Ready::err(CloudError::InvalidPath));
        }
        match self.connection.provider() {
            ProviderKind::WebDav | ProviderKind::Nextcloud => dispatch(self.dav(), |dav| dav.write(path, data, precondition)),
            ProviderKind::Dropbox => dropbox::write(&self.connection, &self.config, path, data, precondition),
            ProviderKind::OneDrive => onedrive::write(&self.connection, &self.config, path, data, precondition),
            ProviderKind::GoogleDrive => gdrive::write(&self.connection, &self.config, path, data, precondition),
        }
    }

    /// Creates a directory; an existing one counts as success, a file with the same name reports `Forbidden`, and a
    /// missing parent reports `NotFound`.
    pub fn create_dir(&self, path: RemotePath) -> BoxOperation<()> {
        match self.connection.provider() {
            ProviderKind::WebDav | ProviderKind::Nextcloud => dispatch(self.dav(), |dav| dav.create_dir(path)),
            ProviderKind::Dropbox => dropbox::create_dir(&self.connection, &self.config, path),
            ProviderKind::OneDrive => onedrive::create_dir(&self.connection, &self.config, path),
            ProviderKind::GoogleDrive => gdrive::create_dir(&self.connection, &self.config, path),
        }
    }

    /// Deletes a file or directory; a missing one counts as success. Deleting the connection root returns `InvalidPath`.
    pub fn delete(&self, path: RemotePath) -> BoxOperation<()> {
        if path.is_root() {
            return Box::new(Ready::err(CloudError::InvalidPath));
        }
        match self.connection.provider() {
            ProviderKind::WebDav | ProviderKind::Nextcloud => dispatch(self.dav(), |dav| dav.delete(path)),
            ProviderKind::Dropbox => dropbox::delete(&self.connection, &self.config, path),
            ProviderKind::OneDrive => onedrive::delete(&self.connection, &self.config, path),
            ProviderKind::GoogleDrive => gdrive::delete_path(&self.connection, &self.config, path),
        }
    }

    /// Moves or renames a file or directory. The destination must not exist and its parent directory must; on success
    /// the result is the entry at its new path.
    ///
    /// Fails with [`CloudError::PreconditionFailed`] when something already exists at `to`, [`CloudError::NotFound`]
    /// when `from` or the parent of `to` is missing, and [`CloudError::InvalidPath`] when either path is the root or
    /// `to` lies inside `from`. On Google Drive, where names are not unique, a concurrent create of the same name is
    /// checked afterwards. An ambiguous result reports [`CloudError::CommitUnconfirmed`] and leaves both items in place.
    pub fn rename(&self, from: RemotePath, to: RemotePath) -> BoxOperation<Entry> {
        if from.is_root() || to.is_root() || to.starts_with(&from) {
            return Box::new(Ready::err(CloudError::InvalidPath));
        }
        match self.connection.provider() {
            ProviderKind::WebDav | ProviderKind::Nextcloud => dispatch(self.dav(), |dav| dav.rename(from, to)),
            ProviderKind::Dropbox => dropbox::rename(&self.connection, &self.config, from, to),
            ProviderKind::OneDrive => onedrive::rename(&self.connection, &self.config, from, to),
            ProviderKind::GoogleDrive => gdrive::rename(&self.connection, &self.config, from, to),
        }
    }

    /// Best-effort revocation of the server-side authorization: Nextcloud deletes the app password, Dropbox and Google
    /// revoke the token (on Google, the whole grant). WebDAV and OneDrive have no revocation endpoint (on OneDrive the user removes the app under "App access"
    /// at account.live.com).
    pub fn revoke(&self) -> BoxOperation<()> {
        match self.connection.provider() {
            ProviderKind::WebDav | ProviderKind::Nextcloud => nextcloud::revoke(&self.connection, &self.config),
            ProviderKind::Dropbox => dropbox::revoke(&self.connection, &self.config),
            ProviderKind::GoogleDrive => gdrive::revoke(&self.connection, &self.config),
            ProviderKind::OneDrive => Box::new(Ready::ok(())),
        }
    }
}

fn dispatch<T: Send + 'static>(dav: Result<Dav, CloudError>, run: impl FnOnce(Dav) -> BoxOperation<T>) -> BoxOperation<T> {
    match dav {
        Ok(dav) => run(dav),
        Err(error) => Box::new(Ready::err(error)),
    }
}
