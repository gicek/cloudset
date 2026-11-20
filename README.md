# cloudset

[![CI](https://github.com/gicek/cloudset/actions/workflows/ci.yml/badge.svg)](https://github.com/gicek/cloudset/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/cloudset.svg)](https://crates.io/crates/cloudset)
[![docs.rs](https://img.shields.io/docsrs/cloudset)](https://docs.rs/cloudset)
[![MSRV 1.88](https://img.shields.io/badge/MSRV-1.88-blue)](#minimum-supported-rust-version)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

One file API for WebDAV, Nextcloud, Dropbox, OneDrive and Google Drive, written as a sans-IO library: cloudset builds
the HTTP requests and parses the responses, and you send them with the HTTP client you already use.

- **Bring your own transport.** No sockets, no async runtime, no TLS stack. Operations are plain state machines, so the
  same code runs with `ureq`, `reqwest`, `hyper`, a platform HTTP API over FFI, or an in-memory test server.
- **Conditional writes.** Check `Client::supports_write_precondition` for the payload and revision. A strict write
  returns `UnsupportedPrecondition` if the backend cannot enforce it. See the [provider matrix](docs/PROVIDERS.md).
- **Sign-in included.** OAuth 2.0 with PKCE for Dropbox, OneDrive and Google Drive, with a custom scheme or loopback
  redirect, and Nextcloud Login Flow v2. Tokens refresh automatically.
- **Careful with untrusted input.** Credentials only go to the provider's own origin, redirects never downgrade to HTTP,
  XML and JSON are bounded, and `Debug` output never shows tokens or passwords. No `unsafe` code.
- **Testable.** The `testing` feature ships in-memory servers for all five providers, so your own tests can drive real
  sign-ins, conflicts and token refreshes without a network.

## Installation

```toml
[dependencies]
cloudset = "0.3"

[dev-dependencies]
cloudset = { version = "0.3", features = ["testing"] }
```

| Feature | Default | What it adds |
| --- | --- | --- |
| `testing` | off | `cloudset::testing`: in-memory WebDAV (`MemoryDav`) and Dropbox, OneDrive and Google Drive (`testing::oauth::MemoryCloud`) servers. For tests only. |

## Quick start

```rust
use cloudset::{Client, ClientConfig, Connection, Endpoint, Precondition, RemotePath, Step, Transport};

let endpoint = Endpoint::parse("https://dav.example.com/remote.php/webdav/", Transport::RequireHttps)?;
let client = Client::new(Connection::webdav(endpoint, "alice", app_password), ClientConfig::new("MyApp/1.0"));

let mut write = client.write(RemotePath::parse("Documents/notes.txt")?, bytes, Precondition::Absent);
let mut response = None;
let entry = loop {
    match write.advance(response.take())? {
        Step::Send(request) => response = Some(my_http_client.execute(request)?), // see "Executor contract"
        Step::Done(done) => break done.value,
    }
};
```

- Every file operation returns an `Operation`: `stat`, `list`, `read`, `write`, `create_dir`, `rename`, `delete` and
  `revoke`.
- OAuth drivers should call `operation.take_connection()` after each advance and persist updates before sending the next
  request. Successful operations also return any outstanding update in `Done.connection`.
- `Connection::to_bytes` and `Connection::from_bytes` turn a connection into an opaque, versioned blob for the system
  keychain.
- `cloudset::run(operation, |request| response)` drives an operation with a transport that cannot fail, such as the
  in-memory test servers. `cloudset::run_with_updates` also passes connection updates to a callback as they happen.

## Documentation

- [API reference](https://docs.rs/cloudset)
- [Usage guide](docs/GUIDE.md): connections, sign-in, conflicts, large files, errors, writing an executor, composite
  operations and testing.
- [Provider notes](docs/PROVIDERS.md): how each provider maps paths, versions, conditional writes, uploads and moves.
- [Changelog](CHANGELOG.md)

## Examples

| Example | Shows | Run |
| --- | --- | --- |
| [`webdav_memory`](examples/webdav_memory.rs) | Every file operation, conditional writes, storing a connection | `cargo run --example webdav_memory --features testing` |
| [`oauth_memory`](examples/oauth_memory.rs) | PKCE sign-in, automatic token refresh, revocation | `cargo run --example oauth_memory --features testing` |
| [`custom_operation`](examples/custom_operation.rs) | A composite operation built with `Subtask` | `cargo run --example custom_operation --features testing` |
| [`ureq_executor`](examples/ureq_executor.rs) | A blocking executor with `ureq` | `cargo run --example ureq_executor -- <folder>` |
| [`reqwest_executor`](examples/reqwest_executor.rs) | An async executor with `reqwest` and `tokio` | `cargo run --example reqwest_executor -- <folder>` |

The two executor examples list a folder on a real WebDAV server; set `CLOUDSET_URL`, `CLOUDSET_USER` and
`CLOUDSET_PASSWORD` first.

## Executor contract

The code that sends requests is yours, so it has to keep a few promises:

- Send each `HttpRequest` exactly as given: method (including `PROPFIND`, `MKCOL` and `MOVE`; use `Method::as_str`),
  URL, headers and body.
- **Do not follow redirects.** Return 3xx responses as they are; cloudset follows same-origin redirects itself and never
  downgrades from HTTPS to HTTP. Store no cookies and use no cache.
- Return every status code as an `HttpResponse`, errors included.
- Read at most `Limits::max_body_bytes + 1` bytes of a body; cloudset reports anything longer as `TooLarge`.
- Keep transport failures (offline, timeout, TLS) in your own error type; they never enter cloudset.
- **Pinned certificates**: `Connection::certificate_pin()` returns a certificate the user confirmed (SHA-256 of the leaf
  certificate DER) and the origin it covers. For a covered request (`CertificatePin::applies_to`), run system validation
  first; if it fails, accept only a certificate with exactly that fingerprint (compared in constant time, host name not
  checked) and report "certificate changed" on a mismatch. Other requests use system validation alone.
- Never log URL query strings, headers or bodies. The `Debug` output of `HttpRequest`, `HttpResponse` and `Connection` is
  already redacted.

## Access scopes

OAuth providers offer two scopes (`AccessScope`), and you choose:

- `AppFolder`: only the folder the provider gives the app (Dropbox "Apps › your app" for an App folder app, OneDrive
  `special/approot`, and on Google Drive a visible folder named `OAuthClient::folder_name` in My Drive under the
  `drive.file` scope). Cloudset resolves paths relative to that folder. On Google Drive the grant applies to
  app-authorized files, including files moved outside it.
- `Full`: the whole drive; paths are relative to its root.

`ProviderKind::access_scopes()` lists the scopes in order of preference; default to the first. WebDAV and Nextcloud only
offer `Full`. [Provider notes](docs/PROVIDERS.md#access-scopes) explain how each provider requests them.

## Scope and limits

cloudset is built for apps that keep their own files in the user's cloud storage: documents, settings, sync data and
backups. It deliberately leaves out:

- **Streaming.** Files are read and written as whole `Vec<u8>` values. Reads are capped by `Limits::max_body_bytes`
  (16 MiB by default; raise it for larger files). Writes have no size cap: on Dropbox, OneDrive and Google Drive, files
  larger than `Limits::upload_chunk_bytes` (10 MiB by default) go up in pieces through an upload session, so the
  providers' single-request limits do not apply.
- **Resuming after a transport failure.** Re-read the destination before restarting a mutation whose response was lost.
  The server may already have committed it.
- **Browsing features.** No search, sharing, thumbnails, quotas, trash or change feeds.
- **Other providers.** iCloud Drive and S3-compatible storage are not supported.

## Testing and verification

- Every operation runs against in-memory servers for all five providers, once per access scope, including concurrent
  writers, weak ETags, paging, redirects, token refresh and revocation (`tests/`).
- `golden/` holds responses in the shapes Nextcloud, Apache mod_dav and NAS devices send, and from the Dropbox,
  Microsoft Graph and Google Drive APIs, taken from their documentation and live testing, including fields cloudset
  ignores.
- PKCE is checked against the RFC 7636 test vector; XML parsing is tested with hostile input.
- The CI matrix runs on Linux, macOS and Windows with the minimum supported Rust version and stable, checks formatting,
  Clippy, documentation, minimal dependency versions, and licenses and advisories with `cargo-deny`.

## Minimum supported Rust version

Rust 1.88. Raising it is a minor version change.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report security issues privately as described in [SECURITY.md](SECURITY.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you, as
defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
