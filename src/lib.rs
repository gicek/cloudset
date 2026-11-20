//! A sans-IO cloud storage client for WebDAV, Nextcloud, Dropbox, OneDrive and Google Drive.
//!
//! The crate builds HTTP requests, parses responses and advances state machines. It never opens a socket, reads a file,
//! the clock or the environment, or produces random numbers: you send the requests with any HTTP stack, keep the
//! credentials in your own secure storage, and run the browser sign-in. One protocol implementation can therefore be
//! driven from any runtime, blocking or async, and its tests are fully deterministic.
//!
//! # Overview
//!
//! - A [`Connection`] says where and how to sign in: [`Connection::webdav`] for WebDAV and Nextcloud app passwords,
//!   [`nextcloud::begin_login`] for Nextcloud Login Flow v2, and [`oauth::begin`] for Dropbox, OneDrive and Google Drive.
//!   Persist it with [`Connection::to_bytes`] and [`Connection::from_bytes`].
//! - A [`Client`] turns each file operation ([`stat`](Client::stat), [`list`](Client::list), [`read`](Client::read),
//!   [`write`](Client::write), [`create_dir`](Client::create_dir), [`rename`](Client::rename),
//!   [`delete`](Client::delete), [`revoke`](Client::revoke)) into an [`Operation`].
//! - [`Operation::advance`] returns [`Step::Send`] with an [`HttpRequest`] to execute, or [`Step::Done`] with the result.
//!   Persist [`Operation::take_connection`] after each advance and any outstanding [`Done::connection`] on completion.
//! - [`run`] drives an operation with a transport function that cannot fail, such as an in-memory test server;
//!   [`run_with_updates`] also hands over connection updates as they happen.
//!
//! # Example
//!
//! ```no_run
//! use cloudset::{Client, ClientConfig, Connection, Endpoint, HttpRequest, HttpResponse, Precondition, RemotePath, Step, Transport};
//!
//! # fn send(_request: HttpRequest) -> Result<HttpResponse, std::io::Error> { unimplemented!() }
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let endpoint = Endpoint::parse("https://dav.example.com/remote.php/webdav/", Transport::RequireHttps)?;
//! let client = Client::new(Connection::webdav(endpoint, "alice", "app-password"), ClientConfig::new("MyApp/1.0"));
//!
//! let mut write = client.write(RemotePath::parse("Documents/notes.txt")?, b"hello".to_vec(), Precondition::Absent);
//! let mut response = None;
//! let entry = loop {
//!     match write.advance(response.take())? {
//!         // Send it as is: no redirects, no cookies, the body read up to `Limits::max_body_bytes + 1`.
//!         Step::Send(request) => response = Some(send(request)?),
//!         Step::Done(done) => break done.value,
//!     }
//! };
//! println!("revision {:?}", entry.revision);
//! # Ok(())
//! # }
//! ```
//!
//! # Further reading
//!
//! The README lists the executor contract and each provider's behavior. The usage guide (`docs/GUIDE.md` in the
//! repository) covers sign-in, storing connections, conflicts, large files, errors, composite operations and testing.
//! The `testing` feature adds in-memory servers for every provider ([`testing`]).

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod authorized;
mod client;
mod connection;
mod dropbox;
mod entry;
mod error;
mod gdrive;
mod http;
mod multistatus;
pub mod nextcloud;
pub mod oauth;
mod onedrive;
mod operation;
mod path;
mod providers;
#[cfg(feature = "testing")]
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
pub mod testing;
mod webdav;

pub use client::{Client, ClientConfig};
pub use connection::{AccessScope, CertificatePin, Connection, Endpoint, PinnedCertificate, ProviderKind, Transport};
pub use entry::{Entry, File, Precondition, Revision};
pub use error::CloudError;
pub use http::{HttpRequest, HttpResponse, Limits, Method};
pub use oauth::{Authorization, DropboxAppRequest, OAuthClient};
pub use operation::{BoxOperation, Done, Operation, Progress, Step, Subtask, map, run, run_with_updates};
pub use path::RemotePath;
