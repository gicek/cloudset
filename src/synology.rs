//! Synology DSM 7 through the File Station API, reached directly or through QuickConnect.
//!
//! 1. Find the device. With a QuickConnect ID, [`quickconnect::resolve`] lists its addresses, [`Resolution::probe`]
//!    picks one that answers as this device, and [`Resolution::request_relay`] opens Synology's relay when none does.
//!    With an address the user typed, use [`Endpoint::parse`] (DSM listens on 5001 for HTTPS and 5000 for HTTP).
//! 2. [`sign_in`] signs in with the DSM user name and password, and the one-time code when the account uses two-step
//!    verification ([`CloudError::OtpRequired`] says it does). It checks the root folder and yields a [`Connection`].
//! 3. [`Client`](crate::Client) runs the file operations. Sessions expire; the driver signs in again on its own with the
//!    stored password (and the trusted-device token, so no new one-time code is needed) and hands the renewed
//!    connection back like a refreshed OAuth token: persist [`Operation::take_connection`](crate::Operation) updates.
//!
//! Paths are relative to the root folder: a shared folder (`home`, `Backups`), optionally followed by a path inside it.
//! The DSM user needs the File Station application permission and access to that shared folder.
//!
//! ```no_run
//! use cloudset::synology::{self, SignIn, quickconnect::{self, QuickConnectId, Region}};
//! use cloudset::{ClientConfig, RemotePath};
//! # fn run<T>(_: cloudset::BoxOperation<T>) -> Result<T, Box<dyn std::error::Error>> { unimplemented!() }
//! # use cloudset::synology::quickconnect::{Candidate, Resolution};
//! # fn first_answering(_: &Resolution, _: &[Candidate], _: &ClientConfig) -> Option<Candidate> { None }
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = ClientConfig::new("MyApp/1.0 (iPhone)");
//! let input = "quickconnect.cn/my-nas";
//! let id = QuickConnectId::parse(input)?;
//! let region = Region::from_address(input).unwrap_or(Region::Global);
//! let resolution = run(quickconnect::resolve(&id, region, &config))?;
//!
//! // `first_answering` runs `resolution.probe` for every candidate concurrently, with a timeout of a few seconds each
//! // (a transport error counts as `false`), and returns the first candidate in list order that answered.
//! let endpoint = match first_answering(&resolution, resolution.candidates(), &config) {
//!     Some(candidate) => candidate.endpoint,
//!     None => {
//!         let relays = run(resolution.request_relay(&config))?;
//!         first_answering(&resolution, &relays, &config).ok_or("the device is offline")?.endpoint
//!     }
//! };
//!
//! let sign_in = SignIn::new(endpoint, RemotePath::parse("home/Notes")?, "alice", "password").with_quickconnect(id, resolution.region());
//! let connection = run(synology::sign_in(sign_in, &config))?;
//! # let _ = connection;
//! # Ok(())
//! # }
//! ```

use std::fmt;

use zeroize::Zeroizing;

use crate::client::ClientConfig;
use crate::connection::{Connection, Endpoint, SynologyCredential};
use crate::error::CloudError;
use crate::http::HttpResponse;
use crate::operation::{BoxOperation, Done, Operation, Ready, Step};
use crate::path::RemotePath;

mod api;
mod files;
pub mod quickconnect;
mod session;

pub(crate) use files::{create_dir, delete, list, read, rename, revoke, stat, supports_write_precondition, write};
#[cfg(doc)]
use quickconnect::Resolution;
use quickconnect::{QuickConnectId, Region};

/// What [`sign_in`] needs. `Debug` does not print the password or the one-time code.
#[derive(Clone)]
pub struct SignIn {
    endpoint: Endpoint,
    root: RemotePath,
    username: String,
    password: Zeroizing<String>,
    otp_code: Option<Zeroizing<String>>,
    quickconnect: Option<(QuickConnectId, Region)>,
}

impl SignIn {
    /// Signs in to DSM at `endpoint` as `username`; `root` is the folder that paths are relative to (a shared folder,
    /// optionally followed by a path inside it).
    #[must_use]
    pub fn new(endpoint: Endpoint, root: RemotePath, username: impl Into<String>, password: impl Into<String>) -> Self {
        Self { endpoint, root, username: username.into(), password: Zeroizing::new(password.into()), otp_code: None, quickconnect: None }
    }

    /// The one-time code from the authenticator app, after a sign-in reported [`CloudError::OtpRequired`]. DSM then
    /// trusts this device (named after [`ClientConfig::user_agent`]), so later sign-ins need no code.
    #[must_use]
    pub fn with_otp_code(mut self, code: impl Into<String>) -> Self {
        self.otp_code = Some(Zeroizing::new(code.into()));
        self
    }

    /// Remembers the QuickConnect ID the address came from, so the connection can be resolved again later
    /// ([`Connection::quickconnect`]).
    #[must_use]
    pub fn with_quickconnect(mut self, id: QuickConnectId, region: Region) -> Self {
        self.quickconnect = Some((id, region));
        self
    }
}

impl fmt::Debug for SignIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignIn")
            .field("endpoint", &self.endpoint.as_str())
            .field("root", &self.root)
            .field("username", &self.username)
            .field("quickconnect", &self.quickconnect)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Signs in, checks that the root folder exists, and yields the connection.
///
/// # Errors
///
/// The operation reports [`CloudError::ReauthRequired`] for a wrong user name or password, [`CloudError::OtpRequired`]
/// when a one-time code is needed or the one given was wrong, [`CloudError::Forbidden`] for a disabled account, a
/// blocked address or an expired password, [`CloudError::NotFound`] when the root folder does not exist, and
/// [`CloudError::InvalidPath`] for an empty root.
///
/// The root folder can only be checked once signed in. When that check fails after a sign-in with a one-time code, DSM
/// has already trusted the device; the next attempt needs a new code and adds another trusted-device entry. With an
/// account that uses two-step verification, sign in with a folder that is sure to exist (`home`, when DSM user homes
/// are on), then let the user pick the folder to use from [`Client::list`](crate::Client::list) and sign in with it
/// as the root once the device is trusted.
pub fn sign_in(request: SignIn, config: &ClientConfig) -> BoxOperation<Connection> {
    if request.root.is_root() {
        return Box::new(Ready::err(CloudError::InvalidPath));
    }
    let credential = SynologyCredential {
        endpoint: request.endpoint,
        root: request.root,
        username: request.username,
        password: request.password,
        device_token: None,
        session: None,
        quickconnect: request.quickconnect,
        certificate: None,
    };
    let steps = files::RootExists::new(&credential.endpoint, &credential.root);
    Box::new(SigningIn { session: session::Session::signing_in(steps, credential, request.otp_code, config), connection: None })
}

/// Runs the root folder lookup through a signing-in session and yields the session's connection.
struct SigningIn {
    session: session::Session<files::RootExists>,
    connection: Option<Connection>,
}

impl Operation for SigningIn {
    type Output = Connection;

    fn advance(&mut self, response: Option<HttpResponse>) -> Result<Step<Connection>, CloudError> {
        let step = self.session.advance(response);
        if let Some(connection) = self.session.take_connection() {
            self.connection = Some(connection);
        }
        match step? {
            Step::Send(request) => Ok(Step::Send(request)),
            Step::Done(Done { value: true, connection }) => connection
                .or_else(|| self.connection.take())
                .map(|connection| Step::Done(Done::new(connection)))
                .ok_or(CloudError::OutOfOrder),
            Step::Done(_) => Err(CloudError::NotFound),
        }
    }
}
