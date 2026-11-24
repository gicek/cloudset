# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow semantic versioning.

## [Unreleased]

## [0.4.0] - 2026-11-24

Adds Synology DSM 7 as a provider, reached directly or through QuickConnect, including devices and users in mainland
China. Existing providers behave as before; matches on `ProviderKind` and `CloudError` need an arm for the new
variants only if they had no fallback arm, which `#[non_exhaustive]` already requires.

### Added

- Synology DSM 7 as a provider (`ProviderKind::Synology`), through the File Station API. `synology::sign_in` signs in
  with the DSM password and, for accounts with two-step verification, a one-time code; DSM then trusts the device, so
  expired sessions renew without the user. Paths are relative to a root folder (a shared folder and a path inside it).
  `Precondition::Absent` is enforced by DSM; `Precondition::Matches` returns `UnsupportedPrecondition`, because File
  Station has no version identifier.
- `synology::quickconnect` finds a device by its QuickConnect ID: `resolve` asks the control hosts and follows regional
  redirects, `Resolution::probe` checks that an address answers as this exact device, and `Resolution::request_relay`
  opens Synology's relay. `Region::ChinaMainland` starts at `global.quickconnect.cn` and keeps relays on
  `quickconnect.cn`.
- `Connection::with_endpoint` moves a Synology connection to another address of the same device (never from HTTPS to
  plain HTTP; the session and a pinned certificate are dropped when the origin changes); `Connection::quickconnect`
  and `Connection::root_folder` describe it.
- `CloudError::OtpRequired`: a Synology sign-in needs a one-time code, or the one given was wrong.
- `CloudError::Provider { code }`: an error code from the provider's own API that has no closer match; unlike
  `Server`, it is not an HTTP status.
- Testing: `testing::synology::MemorySynology`, an in-memory device with QuickConnect control hosts in both regions.
- Example: `synology_memory` (QuickConnect in mainland China, relay fallback, two-step sign-in).

## [0.3.0] - 2026-11-20

Makes write guarantees explicit: a condition a provider cannot enforce is refused before anything is sent, and a write
whose outcome could not be verified is reported as such. Adds sign-in with Google "Desktop app" clients over a
loopback redirect. This release changes behavior; see "Changed" for the migration.

### Added

- `Client::supports_write_precondition(size, &precondition)` tells whether the backend can enforce a condition for a
  payload of that size.
- `CloudError::UnsupportedPrecondition`: the provider cannot enforce the requested condition; nothing was sent.
- `CloudError::CommitUnconfirmed`: a mutation may have been committed but could not be verified. Read the remote
  again and compare before retrying or recording a successful sync.
- `Operation::take_connection()` hands over a refreshed connection right after the advance that produced it, so a
  rotated credential survives an operation that fails or is dropped afterwards. `Done::connection` still carries any
  update that was not taken. `run_with_updates` is `run` with a callback for these updates.
- `OAuthClient::with_client_secret` for Google "Desktop app" clients, whose token endpoint answers
  `client_secret is missing` without it. The secret is sent with the code exchange and every refresh and is stored
  in the connection. Together with a loopback redirect (`http://127.0.0.1:<port>/`) this covers sign-in on Windows,
  Linux and macOS.
- Testing: `MemoryCloud::client_secret` makes the token endpoint require a client secret.
- Testing: `MemoryCloud::bare_etags` makes the OneDrive server return unquoted `eTag` tokens, as personal accounts do.

### Changed

- Google Drive refuses `Precondition::Absent` and `Precondition::Matches` with `UnsupportedPrecondition`. The earlier
  emulation could not close the race, and it no longer replays historical revisions or deletes folders. Use
  `Precondition::None` with your own conflict handling.
- Google Drive: when another device creates the same name concurrently, `write` removes the file it just created and
  reports `CommitUnconfirmed`; `rename` leaves both items and reports `CommitUnconfirmed` instead of undoing the move.
  A duplicate folder is left in place and the oldest one is used.
- OneDrive refuses `Matches` for a payload that needs an upload session (larger than `Limits::upload_chunk_bytes`),
  because Graph only checks it when the session opens. Smaller writes use a single `PUT` up to that limit. A
  revision that is a wildcard, a weak tag or a list is refused as well; quoted and bare `eTag` values both match.
- WebDAV refuses `Matches` with a weak or malformed ETag instead of comparing before writing. Reads from a server
  without strong ETags return no revision and no modification time.
- WebDAV writes read the file back and compare it with what was sent before returning its revision, which costs one
  more `PROPFIND` and `GET`. A payload larger than `Limits::max_body_bytes` skips the check and returns no revision.
- An OAuth callback must arrive on the port of the registered redirect, not only its scheme, host and path.
- `write` and `delete` on the connection root report `InvalidPath` on every provider.
- `Debug` output of requests shows only the origin of the URL; pre-signed URLs carry credentials in the path.
- The published source archive includes the integration guide, provider notes and contributor and security policies.

### Fixed

- A WebDAV write no longer returns the revision of a write another device made right after it.
- Google Drive name lookups follow pagination, including pages without items, and refuse incomplete search results.
- OneDrive upload fragments stay strictly below 60 MiB.
- An expiry time far in the future no longer overflows; a stored connection with one is `InvalidConnection`.
- A `303` redirect is only followed for `GET`. For any other request it is an `InvalidResponse`, where it used to run
  a `GET` and report that as the result of the delete or the new directory.
- Redirects only lead to `http` and `https` URLs without credentials in them, drop the fragment, and carry a `MOVE`
  `Destination` along when the server upgrades to HTTPS. Nextcloud sign-in refuses a login or poll URL with another
  scheme.
- WebDAV `list` no longer returns an empty directory when the server's paths do not match the endpoint
  (`InvalidResponse`) or when the path is a file, and only returns direct children when the server ignores `Depth`.
- WebDAV: a `404` or `403` status for a whole multistatus entry is honored (`stat` returns `None`, `list` leaves the
  entry out), elements nested in a property value are not read as entries, and any number of `propstat` elements is
  merged without growing memory.
- WebDAV paths encode `[`, `]`, `|` and `^`.
- Nextcloud sign-in: when the user ID lookup fails after the app password was issued, the connection uses
  `remote.php/webdav/` instead of losing the password. A server reached over HTTP that names its HTTPS address is
  used over HTTPS from then on.
- Dropbox: `too_many_write_operations` is `RateLimited`, a move without space is `QuotaExceeded`, listing a file is
  `NotFound`, and a file or folder in the way of a write is `Forbidden` instead of `PreconditionFailed`. Revoking a
  grant the user already removed succeeds.
- OneDrive: `create_dir` works in the app folder, where Graph answers `invalidRequest` to a folder created by path;
  the parent is looked up and the folder created under its ID.
- OneDrive: a `Matches` write to a file that no longer exists is `PreconditionFailed` and leaves nothing behind.
  Graph ignores `If-Match` there and creates the file, which used to count as a successful write.
- OneDrive: a folder in the way of a write is `Forbidden` (`PreconditionFailed` for `Absent`), listing a file is
  `NotFound`, and a move whose source is missing is `NotFound` instead of `InvalidPath`.
- OneDrive: a refusal from a pre-signed download or upload URL is `Server` instead of `ReauthRequired`, `Forbidden`
  or `InvalidPath`.
- Google Drive: a partially acknowledged chunk no longer overflows with a very large `Limits::upload_chunk_bytes`.
- Token endpoints: `temporarily_unavailable` is `RateLimited` and `server_error` is `Server` instead of
  `ReauthRequired`.
- Timestamps outside 1970–9999 or with negative fields from a provider are ignored instead of overflowing.
- A single-request operation that failed reports `OutOfOrder` when advanced again, as documented.
- `Endpoint::complete_address` adds the scheme to an address whose path or query contains `://`.

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

[Unreleased]: https://github.com/gicek/cloudset/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/gicek/cloudset/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/gicek/cloudset/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/gicek/cloudset/releases/tag/v0.2.0
