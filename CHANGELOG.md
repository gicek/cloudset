# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow semantic versioning.

## [Unreleased]

## [0.2.0] - 2026-11-19

Adds Dropbox, OneDrive and Google Drive, chunked uploads for large files, moving and renaming, and pinned certificates.
This release changes the public API; see "Changed" for the migration.

### Added

- `Client::rename` moves or renames a file or directory on every provider. It never overwrites: an existing destination
  is `PreconditionFailed`, a missing source or destination parent is `NotFound`. WebDAV uses `MOVE` with
  `Overwrite: F` (new `Method::Move`); on Google Drive a concurrent create of the same name undoes the move.
- Chunked uploads: Dropbox upload sessions, OneDrive upload sessions and Google Drive resumable uploads, for files larger
  than the new `Limits::upload_chunk_bytes` (10 MiB by default, rounded to what each provider accepts). Preconditions
  are checked when the file is committed (on OneDrive, `Matches` when the session opens), and Google Drive's emulated
  preconditions cover them too.
- Constructors and builders for the types that are now `#[non_exhaustive]`: `HttpRequest::new` / `with_header` /
  `with_body`, `HttpResponse::with_header` / `with_headers` / `with_body`, `Done::new` / `with_connection`,
  `Limits::with_*`, `ClientConfig::with_limits`, plus `Client::config` and `Client::with_config`.
- `RemotePath::starts_with`.
- Testing: `MemoryDav` handles `MOVE` and has `is_dir`; `MemoryCloud` serves upload sessions, resumable uploads and moves
  (`testing::oauth::ONEDRIVE_UPLOAD_HOST`, `Races::before_move`).

- OAuth 2.0 authorization code + PKCE S256 (public client): `oauth::begin` derives the verifier and `state` from random
  bytes supplied by the caller; `Authorization::complete` checks the callback (URL, with an empty path equal to `/` when
  there is a host; `state` compared in constant time; `error`) before exchanging the code and looking up the account
  name; `accepts` only checks. The scope is sent to the token endpoint only where the provider requires it (Microsoft).
  New errors `CloudError::StateMismatch` / `AuthorizationDenied`.
- A shared driver for OAuth operations: adds the bearer token, refreshes before expiry (`ClientConfig::now`) or after a
  401 and replays once, sends credentials only to the provider's API origin, and hands a refreshed connection back in
  `Done.connection`.
- `AccessScope` (app folder / whole drive), listed in order of preference by `ProviderKind::access_scopes()`.
- Dropbox (API v2): `stat`, `list` (paged), `read`, `write` (three preconditions), `create_dir`, `delete`, `revoke`.
  Authorization through the official Dropbox app: `Authorization::dropbox_app_request` / `complete_dropbox_app` (Android
  app-to-app protocol) and `dropbox_app_url` / `complete_dropbox_app_callback` (iOS URL scheme protocol, accepting both
  `oauth_code` and `oauth_token=oauth2code:` callbacks).
- OneDrive (Microsoft Graph): `stat`, `list` (paged), `read`, `write` (three preconditions), `create_dir`, `delete`.
  Both scopes request `User.Read` and the account name comes from `/me`, since `/me/drive` returns 403 under the app
  folder scope.
- Google Drive (Drive API v3): `ProviderKind::GoogleDrive` with `stat`, `list` (paged), `read`, `write` (all three
  preconditions), `create_dir`, `delete` and `revoke`. Paths resolve one segment at a time from the root; among items
  with the same name the oldest (creation time, then ID) wins everywhere, listings included. Conditional writes are
  emulated (Drive v3 has none): `Matches` checks `headRevisionId` before uploading and the revision list afterwards, and
  puts an overtaken writer's revision back on top before reporting `PreconditionFailed`; `Absent` looks the name up again
  after creating and the newer of two concurrent files is deleted by its writer. Folders created on the way are
  deduplicated the same way. New files are a single `multipart/related` upload. Sign-in checks the scopes actually
  granted: without the Drive scope it reports `AuthorizationDenied`. The account name comes from Drive's `about`.
- `OAuthClient` (`OAuthClient::new` / `with_folder_name`): `folder_name` is the app folder for providers that have none of
  their own; Google Drive's `drive.file` scope keeps it as a visible folder in the root of My Drive, created on first
  access. Stored in the connection as `appFolder`, required exactly for Google Drive with the app folder scope.
- `Method::Patch`.
- `Endpoint::complete_address`: adds `http://` (IPv4, bracketed IPv6) or `https://` to addresses typed without a scheme.
- Pinned certificates: `PinnedCertificate` (SHA-256 of the leaf certificate DER), `CertificatePin::applies_to`,
  `Connection::with_pinned_certificate` / `certificate_pin`; only WebDAV / Nextcloud with all-`https://` addresses, and the
  serialized `pinnedCertificate` field makes any other connection `InvalidConnection`.
- `testing::oauth::MemoryCloud`: in-memory Dropbox / OneDrive / Google Drive with authorization pages and token endpoints,
  isolating the access scopes like the real services (Google Drive as an ID-based store with duplicate names,
  `drive.file` visibility, revisions and multipart uploads), plus `Races` to simulate another device writing at the wrong
  moment; `golden/oauth.json` with the real response formats of all three.

### Changed

- Breaking: `CloudError`, `ProviderKind`, `AccessScope`, `Transport`, `Method` and `Precondition` are
  `#[non_exhaustive]`, as are the structs `HttpRequest`, `HttpResponse`, `Entry`, `File`, `Limits`, `ClientConfig`,
  `Done`, `OAuthClient`, `DropboxAppRequest` and `LoginFlow`. Match with a fallback arm, and build values with the new
  constructors instead of struct literals. Executors should send `Method::as_str()` instead of matching methods.
- Breaking: `drive` is now `run`.
- Breaking: `Connection::username` is now `Connection::account`.
- `Connection::webdav` takes `impl Into<String>` for the user name and password.
- `Connection` gained OAuth connections (a flat table validated per `provider`; WebDAV / Nextcloud fields unchanged);
  `endpoint()` now returns an `Option`; new `host()`, `is_secure()`, `access_scope()`.
- `Operation` is `#[must_use]`.
- Dependencies use caret requirements instead of exact pins.
- Licensed under MIT OR Apache-2.0 (previously MIT).
- The minimum supported Rust version is 1.88.

## 0.1.0 - 2026-10-28

### Added

- Sans-IO operation state machines (`Operation` / `Step` / `Done`) and the synchronous driver `drive`.
- Plain-data HTTP model, same-origin redirect following (never downgrading), response size limits, mapping of status
  codes to `CloudError`; redacted `Debug` output.
- `RemotePath` (rejects empty segments, `.` / `..`, control characters), `Endpoint` (checks scheme, host, user info and
  query; plain HTTP must be allowed explicitly), `Connection` (opaque versioned serialization; passwords are zeroized).
- WebDAV: `stat`, `list`, `read` (`PROPFIND` + conditional `GET`, retried on concurrent changes), `write` (conditional
  `PUT` + `PROPFIND`; weak ETags fall back to comparing before writing), `create_dir`, `delete`; safe multistatus parsing.
- Composition helpers: `map` (change the result type), `Subtask` / `Progress` (sub-operation errors go back to the
  composer, connection updates propagate upwards), `Client::with_connection`.
- `testing` feature: the in-memory WebDAV server `cloudset::testing::MemoryDav`, so callers can drive the real state
  machines in their tests.
- `CloudError::InsecureEndpoint`: a plain HTTP address that was not allowed, distinct from other address errors (so a UI
  can ask the user to confirm).
- `create_dir`: an `MKCOL` 405 is only treated as "exists" after confirming the folder is there, otherwise `Forbidden`
  (many servers also answer 405 without permission); `testing::MemoryDav::mkcol_forbidden_in` simulates such servers.
- Nextcloud: Login Flow v2 (`begin_login` / `poll_login`, looking up the user ID for the WebDAV address) and revocation of
  the app password.

[Unreleased]: https://github.com/gicek/cloudset/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/gicek/cloudset/releases/tag/v0.2.0
