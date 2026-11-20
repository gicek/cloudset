# Usage guide

This guide walks through a typical integration: connect, store the connection, run file operations, handle conflicts
and errors, and test without a network. The [README](../README.md) lists the executor contract,
[Provider notes](PROVIDERS.md) describe each provider, and the [API reference](https://docs.rs/cloudset) documents every
type.

## The model

cloudset never performs IO. Every call returns a state machine that you drive:

```rust
use cloudset::{Operation, Step};

let mut operation = client.read(path);
let mut response = None;
let file = loop {
    let step = operation.advance(response.take());
    if let Some(connection) = operation.take_connection() {
        store(&connection)?;
    }
    match step? {
        Step::Send(request) => response = Some(send(request)?), // your HTTP stack
        Step::Done(done) => {
            if let Some(connection) = done.connection {
                store(&connection)?; // a refreshed token: replace the stored copy
            }
            break done.value;
        }
    }
};
```

- Pass `None` on the first `advance`, then the response to the previous request. Do not call `advance` again after
  `Done` or an error; doing so reports `CloudError::OutOfOrder`.
- An operation may send several requests (a metadata lookup and a download, a redirect, a token refresh and a replay).
  Treat it as one unit of work.
- Operations are `Send`, so you can drive them on a worker thread or inside an async task. The crate itself never
  blocks.
- Dropping an operation cancels it; nothing needs cleaning up.
- `cloudset::run(operation.as_mut(), |request| response)` is the same loop for a transport that cannot fail, such as the
  in-memory test servers. It returns a connection update only on success; `cloudset::run_with_updates` takes a
  callback that receives each update as it happens, also when the operation fails afterwards.

## Connections

A `Connection` describes one signed-in storage location.

| Provider | How to get a connection |
| --- | --- |
| WebDAV | `Connection::webdav(Endpoint::parse(url, transport)?, user_name, password)` |
| Nextcloud | `nextcloud::begin_login` + `nextcloud::poll_login`, or `Connection::webdav` with an app password |
| Dropbox, OneDrive, Google Drive | `oauth::begin` + `Authorization::complete` |

### Server addresses

- `Endpoint::complete_address(input)` adds a scheme to an address typed without one: `http://` for IP addresses,
  `https://` for host names.
- `Endpoint::parse(text, Transport::RequireHttps)` rejects plain HTTP with `CloudError::InsecureEndpoint`. Ask the user
  for explicit consent, then parse again with `Transport::AllowInsecureHttp`.
- A server with a self-signed certificate can be trusted by fingerprint: after the user confirms the certificate, call
  `connection.with_pinned_certificate(PinnedCertificate::from_slice(&sha256_of_leaf_der)?)`. Your executor then checks
  `connection.certificate_pin()` for every request, as the README describes.

### Storing a connection

`Connection::to_bytes()` returns an opaque, versioned blob (in a `Zeroizing<Vec<u8>>`) that contains the credentials.
Store it in the system keychain or credential manager as is, never in a plain file or a log. Restore it with
`Connection::from_bytes(&bytes)`; a blob from an unknown version reports `CloudError::InvalidConnection`, and the user
should sign in again.

Persist updates from `take_connection()` before the next network request and use the new connection for subsequent
operations. Persist any outstanding update in `Done.connection`. Serialize refreshes for operations sharing rotating
credentials. Providers may rotate the refresh token, so an old blob can stop working.

## Signing in with OAuth

Dropbox, OneDrive and Google Drive use the authorization code flow with PKCE. You register a public client with each
provider and get a client ID and a redirect URI.

```rust
use cloudset::{oauth, AccessScope, OAuthClient, ProviderKind};

let client = OAuthClient::new(client_id, "com.example.app.oauth://callback")
    .with_folder_name("Example App"); // the app folder on Google Drive
let access = ProviderKind::GoogleDrive.access_scopes()[0]; // AccessScope::AppFolder
let authorization = oauth::begin(ProviderKind::GoogleDrive, access, client, &random_64_bytes_from_a_csprng)?;

// Open authorization.url() in the system authentication session, listening for authorization.callback_scheme().
// When the callback arrives:
if authorization.accepts(&callback_url) {
    let mut exchange = authorization.complete(&callback_url, &config)?;
    let connection = run(exchange)?; // drive it like any operation
}
```

- Keep the `Authorization` in memory until the callback arrives; it holds the PKCE verifier. Start a new one for each
  attempt.
- `complete` checks the callback URL and `state` before it sends anything. A forged or stale callback reports
  `CloudError::StateMismatch`; a canceled or denied sign-in reports `CloudError::AuthorizationDenied`.
- `connection.account()` returns the account email (or name) to show the user.

### Redirects and client types

The callback reaches the app in one of two ways, and `OAuthClient::redirect_uri` is the exact URL either way:

- **A custom scheme** the app registers with the system, such as `com.example.app.oauth://callback`. On Google this
  needs an iOS client, whose scheme is the reversed client ID (`com.googleusercontent.apps.<id>:/oauth2redirect`).
- **A loopback address**: listen on a free port of `127.0.0.1` for the duration of the sign-in and pass
  `http://127.0.0.1:<port>/`. The callback must arrive on that host, port and path. This is what Google expects of
  Windows, Linux and macOS apps, with a "Desktop app" client.

```rust
// Google "Desktop app" client: its token endpoint refuses requests without the client secret.
let client = OAuthClient::new(client_id, format!("http://127.0.0.1:{port}/"))
    .with_client_secret(client_secret)
    .with_folder_name("Example App");
```

Google issues that secret to desktop clients although it ships inside the app; PKCE is what protects the sign-in. It
goes into the token requests only, never into the browser, and is stored in the connection because refreshing needs
it. `Debug` output leaves it out. Clients registered without a secret (Google iOS clients, Microsoft "Mobile and
desktop applications", Dropbox with PKCE) need none.

| Provider | Loopback redirect to register |
| --- | --- |
| Google Drive | Nothing: a "Desktop app" client accepts `http://127.0.0.1:<any port>` |
| OneDrive | `http://localhost` once; the port is ignored when matching, so pass `http://localhost:<port>/` |
| Dropbox | The exact URL including the port, so the app needs a fixed port |

On Android, Google does not accept custom schemes for clients of the "Android" type, nor loopback redirects on
mobile. What it documents instead is its own SDK, which is outside this crate. The redirect of an iOS client
(`com.googleusercontent.apps.<id>:/oauth2redirect`) is tied to the client, not to the platform that opens the
browser, so one iOS client can serve every platform: an Android app registers that scheme for its redirect activity
and opens the sign-in page in a Custom Tab. This works on Android devices and from a macOS app (checked in November
2026), but Google does not document it and may start checking the platform. An HTTPS App Link redirect is the
fallback.

A sign-in without a browser redirect (the device flow of TVs and command-line tools) is not supported.
- On Dropbox, the access scope is a property of the app: register one app per scope and pass the matching client ID. On
  OneDrive and Google Drive, the same client ID requests different scopes.
- Dropbox can also sign in through its official app; see `Authorization::dropbox_app_request` (Android) and
  `Authorization::dropbox_app_url` (iOS).

### Access scopes

`ProviderKind::access_scopes()` lists the supported scopes in order of preference. Default to the first. With
`AccessScope::AppFolder`, every Cloudset path is relative to the app folder. Google grants access per app-authorized
file. With `AccessScope::Full`, paths are relative to the drive root; let the user pick a folder.

## Signing in to Nextcloud

Login Flow v2 trades a browser sign-in for an app password:

```rust
use cloudset::nextcloud;

let server = Endpoint::parse(&Endpoint::complete_address(&typed), Transport::RequireHttps)?;
let flow = run(nextcloud::begin_login(&server, &config))?;
open_in_browser(&flow.login_url);
let connection = loop {
    if let Some(connection) = run(nextcloud::poll_login(&flow.poll, &config))? {
        break connection;
    }
    sleep(Duration::from_secs(2)); // give up after a few minutes
};
```

`config.user_agent` is the device name the user sees under "Devices & sessions" in Nextcloud. `client.revoke()` deletes
the app password when the user disconnects.

## File operations

| Method | Result | Notes |
| --- | --- | --- |
| `stat(path)` | `Option<Entry>` | `None` when nothing is there |
| `list(dir)` | `Vec<Entry>` | Direct children sorted by path; a missing directory is `NotFound` |
| `read(path)` | `Option<File>` | Data and the metadata of the same version |
| `write(path, data, precondition)` | `Entry` | Metadata after the write |
| `create_dir(path)` | `()` | An existing directory counts as success |
| `rename(from, to)` | `Entry` | Moves or renames; see provider-specific conflict handling |
| `delete(path)` | `()` | A missing item counts as success |
| `revoke()` | `()` | Best effort; see the README for each provider |

`RemotePath::parse("Backups/data.bin")` validates a path: no empty segments, no `.` or `..`, no control characters.
`RemotePath::root()`, `join`, `parent` and `name` build and take apart paths.

### Revisions and conflicts

Every `Entry` carries a `revision` when the provider reports one. Use it to write safely when several devices share a
file:

1. Read the file and keep `file.entry.revision`.
2. Write with `Precondition::Matches(revision)`. Use `Precondition::Absent` to create a file only if it does not exist,
   or `Precondition::None` to overwrite unconditionally.
3. On `CloudError::PreconditionFailed`, someone else wrote first. Read again, merge, and retry with the new revision.

Check `client.supports_write_precondition(data.len(), &condition)` before offering conditional sync.
`UnsupportedPrecondition` leaves the file untouched. Let users resolve the conflict explicitly.
For `CommitUnconfirmed` or a transport failure during mutation, read the file again and compare its contents to
the intended bytes before advancing your sync baseline. Only persist a revision bound to those bytes.
A missing revision permits a read but cannot authorize a conditional replacement.

#### Without conditional writes

Google Drive, a WebDAV server with weak ETags and OneDrive uploads that need a session cannot enforce `Matches`.
`Precondition::None` still works there, with a window in which another device's write can be overwritten. Narrow it
like this:

1. Keep the revision of the last version you synced.
2. Right before writing, `stat` the file. A different revision means another device wrote: read, merge, and start over.
3. Write with `Precondition::None`, then read the file back. If the content is not what you sent, another device
   wrote after you: merge again.

A write between steps 2 and 3 is still lost on the remote, so keep what your users cannot afford to lose recoverable
on the device, such as the last synced copy, until a later sync confirms it. Where that is not good enough, ask the
user before overwriting instead of syncing automatically.

### Moving and renaming

`client.rename(from, to)` moves a file or directory, and returns the entry at its new path. Check the result before
recording the new location:

- `PreconditionFailed`: something already exists at `to`;
- `NotFound`: `from` or the parent directory of `to` is missing;
- `InvalidPath`: either path is the root, or `to` lies inside `from`.
- `CommitUnconfirmed`: inspect both paths before a retry.

To replace a file atomically, write the new content with `Precondition::Matches` instead.

### Large files

Files are read and written as whole `Vec<u8>` values, so they must fit in memory.

- **Reads** are capped by `Limits::max_body_bytes`, 16 MiB by default; a larger file fails with `TooLarge`. Raise the
  limit for larger files, and make your executor read up to the same limit.
- **Writes** have no cap. On Dropbox, OneDrive and Google Drive, a file larger than `Limits::upload_chunk_bytes` (10 MiB
  by default, capped at 5 MiB for Google single requests) uses an upload session.
  OneDrive rejects `Matches` when the payload requires a session.
- Keep the backup size within the restore limit in both the crate and executor.
  If the final response is lost, reconcile the remote file before retrying.

```rust
let config = ClientConfig::new("MyApp/1.0")
    .with_limits(Limits::default().with_max_body_bytes(512 * 1024 * 1024).with_upload_chunk_bytes(32 * 1024 * 1024));
```

### Limits

`ClientConfig::limits` also caps the entries of one listing (10,000) and the redirects followed for one request (5).

## Errors

`CloudError` describes protocol outcomes only; transport failures (offline, timeout, TLS) stay in your executor's own
error type. A typical mapping for a user interface:

| Error | What to tell the user or do |
| --- | --- |
| `ReauthRequired` | Sign in again |
| `Forbidden`, `NotFound` | Check the folder and permissions |
| `PreconditionFailed` | Re-read and retry; another device wrote first |
| `UnsupportedPrecondition` | This provider cannot safely perform the requested automatic write |
| `CommitUnconfirmed` | Read again and compare the content before updating sync state |
| `QuotaExceeded` | The storage is full |
| `RateLimited { retry_after }` | Retry after the given delay, or back off |
| `InsecureEndpoint` | Ask whether to allow plain HTTP |
| `InvalidEndpoint`, `InvalidPath` | Fix the address or path |
| `TooLarge` | Raise `Limits::max_body_bytes`, or the server sent too much |
| `StateMismatch`, `AuthorizationDenied` | Start the sign-in again |
| `InvalidConnection` | The stored connection is unreadable; sign in again |
| `Server`, `InvalidResponse`, `InsecureRedirect`, `TooManyRedirects` | The server misbehaved; try again later |
| `OutOfOrder` | A bug in your drive loop |

`CloudError` is `#[non_exhaustive]`: keep a fallback arm when you match it.

## Writing an executor

The [`ureq_executor`](../examples/ureq_executor.rs) (blocking) and [`reqwest_executor`](../examples/reqwest_executor.rs)
(async) examples are complete executors. Any HTTP client works if it:

- sends the method (`Method::as_str`), URL, headers and body exactly as given, including the WebDAV methods
  `PROPFIND`, `MKCOL` and `MOVE`;
- does not follow redirects, store cookies or cache responses;
- returns every status code, including 3xx, 4xx and 5xx, as an `HttpResponse`;
- reads at most `Limits::max_body_bytes + 1` bytes of the body;
- never logs URLs, headers or bodies (the crate's own `Debug` output is redacted).

Build the response with `HttpResponse::new(status).with_headers(headers).with_body(body)`.

For async code, drive the same loop inside a task and `await` your client in the `Step::Send` branch.

## Composite operations

Implement `Operation` to combine operations into one unit, such as "create the folder if it is missing, then write".
Wrap each sub-operation in a `Subtask`: its errors come back to you as `Progress::Finished(Err(_))` instead of ending
the whole operation, and a refreshed connection is recorded so you can return it in `Done.connection`. Build the next
sub-operation with `client.with_connection(latest)` so it uses the refreshed token, and finish with
`Done::new(value).with_connection(latest)`. `cloudset::map` changes the result
type of an operation without touching its requests. The
[`custom_operation`](../examples/custom_operation.rs) example shows the full pattern.

## Testing

Enable the `testing` feature in `[dev-dependencies]` and drive the real state machines against in-memory servers:

```rust
use cloudset::testing::{BASE, MemoryDav};

let mut server = MemoryDav::new("Basic YWxpY2U6c2VjcmV0"); // the exact Authorization header it accepts
let endpoint = Endpoint::parse(BASE, Transport::RequireHttps)?;
let client = Client::new(Connection::webdav(endpoint, "alice", "secret"), ClientConfig::new("test"));
let mut write = client.write(RemotePath::parse("a.txt")?, b"x".to_vec(), Precondition::Absent);
cloudset::run(write.as_mut(), |request| server.handle(request))?;
assert_eq!(server.data("a.txt").as_deref(), Some(&b"x"[..]));
```

- `MemoryDav` can simulate another device (`put_external`, `modify_before_get`), weak ETags (`weak_etags`) and servers
  that refuse `MKCOL` (`mkcol_forbidden_in`). `requests` records everything the crate sent.
- `testing::oauth::MemoryCloud::new(FakeProvider::Dropbox | OneDrive | GoogleDrive)` serves sign-in, token refresh and
  file APIs. `authorize(url)` plays the user on the authorization page and returns the callback URL;
  `expire_access_token()` forces a refresh; `races()` simulates concurrent writers and moves on Google Drive.
- Pass a fixed time with `ClientConfig::with_now` to make token expiry deterministic.
