# Provider notes

How cloudset maps its operations onto each provider. The [README](../README.md) describes the shared contract; this page
is for when you need to know exactly what goes over the wire.

## Overview

| | WebDAV / Nextcloud | Dropbox | OneDrive | Google Drive |
| --- | --- | --- | --- | --- |
| Sign-in | User name and password, or Nextcloud Login Flow v2 | OAuth 2.0 + PKCE | OAuth 2.0 + PKCE | OAuth 2.0 + PKCE |
| Access scopes | `Full` | `AppFolder`, `Full` | `AppFolder`, `Full` | `AppFolder`, `Full` |
| Version (`Revision`) | `getetag` from `PROPFIND` | `rev` | `eTag` | `headRevisionId` |
| Conditional writes | Strong ETag for `Matches`; `If-None-Match: *` for `Absent` | Upload `mode` | `Matches` for single-request uploads only; `Absent` uses `conflictBehavior=fail` | Both strict conditions return `UnsupportedPrecondition` |
| Large uploads | One `PUT` | Upload session | Upload session | Resumable upload |
| Move or rename | `MOVE`, `Overwrite: F` | `files/move_v2` | `PATCH` with `parentReference` | `PATCH` with `addParents` / `removeParents` |
| Missing parent on write | `NotFound` | Created | Created | Created |
| `revoke` | Nextcloud deletes the app password; WebDAV does nothing | Revokes the token | Nothing (no endpoint) | Revokes the whole grant |

Every provider: `rename` requires the destination's parent to exist and the destination to be free; on Google Drive a
race may leave the move unconfirmed.

## WebDAV and Nextcloud

- **Versions** always come from `getetag` in `PROPFIND`. The `ETag` header of `GET` and `PUT` responses is ignored,
  because servers do not always write it the same way.
- **Reads** bind metadata to the body with a strong ETag and conditional GET. Without a strong ETag, content is
  returned with its actual length and without a revision or modification time.
- **Writes** send the precondition with PUT. Weak or malformed ETags cannot authorize a replacement. For payloads
  within the read budget, the client checks the remote content before handing a revision to the caller. A committed
  write whose verification fails reports `CommitUnconfirmed`. Larger writes return an acknowledgement without a revision.
- **Directories**: `MKCOL`. A 405 response means "already exists" in RFC 4918, but some servers also send it when
  permission is denied, so cloudset checks with `PROPFIND` before treating it as success.
- **Moves**: `MOVE` with `Destination` and `Overwrite: F`. A 412 response (destination exists) is `PreconditionFailed`;
  404 and 409 (missing source or parent) are `NotFound`.
- **Plain HTTP** is only accepted with `Transport::AllowInsecureHttp`, after the user agreed.
- **Pinned certificates** are only allowed when every address of the connection is `https://`.
- **Untrusted XML**: a `DOCTYPE` is rejected, custom entities are not expanded, and nesting depth and entry counts are
  capped. An `href` outside the root, or containing `..` or control characters, is dropped.
- **Listings** must contain the directory itself; otherwise the server's paths do not map onto the endpoint and the
  listing is an `InvalidResponse`, not an empty directory. Only direct children are returned.
- **Redirects** are followed on the same origin (or from HTTP to HTTPS on the same host), keeping the method. A `303`
  is only followed for `GET`.
- **Nextcloud Login Flow v2**: the poll endpoint, the login page and the returned server address must share the origin
  the user entered (an upgrade from HTTP to HTTPS on the same host is allowed, and the HTTPS address is then used for
  the connection). Files are addressed under `remote.php/dav/files/<user ID>/`; if the user ID cannot be looked up
  after the app password was issued, the connection uses `remote.php/webdav/`.

## OAuth providers

- `oauth::begin(provider, access, client, &random)` derives the PKCE verifier and `state` from 64 random bytes you take
  from a CSPRNG. Open `Authorization::url()` in the system authentication session and pass the callback URL to
  `complete`, which checks the URL and `state` (in constant time) before it sends anything. A callback on a loopback
  address must match the port too. Only Google "Desktop app" clients have a client secret; it is sent in the body of the
  code exchange and of every refresh.
- Tokens refresh shortly before they expire (60 seconds early, when `ClientConfig::now` is set) or after a 401, and the
  request is replayed once. A second 401 is `ReauthRequired`.
- Requests that carry the access token only go to the provider's API origin. Pre-signed URLs (OneDrive downloads and
  upload sessions) get no credentials and must be HTTPS.

### Access scopes

- **Dropbox** decides the scope by app type: an App folder app and a Full Dropbox app have different app keys, so pass
  the matching `OAuthClient` for each scope.
- **OneDrive** uses one client with different scopes (`Files.ReadWrite.AppFolder` or `Files.ReadWrite`, sent again on
  refresh), plus `User.Read` for the account email, because `/me/drive` returns 403 under the app folder scope.
- **Google Drive** uses one client with `drive.file` or `drive`. Under `drive.file`, the app folder is a visible folder
  named `OAuthClient::folder_name` in My Drive, created on first access. A sign-in where the user unticked the Drive
  permission fails with `AuthorizationDenied`.

## Dropbox

- Paths are relative to the app folder or the drive root. The version is `rev`; download results and upload responses
  agree on it.
- Conditional writes use the upload `mode` (`update`, `add` or `overwrite`) with `strict_conflict`, so `update` also
  fails when the file was deleted.
- Files over the chunk size (a multiple of 4 MiB, at most 150 MB) use `upload_session/start`, `append_v2` and `finish`;
  the commit carries the same `mode`, so the precondition is checked atomically when the file appears.
- Moves check that the destination's parent folder exists first (Dropbox would create it), then call `files/move_v2`
  with `autorename: false`.
- Sign-in can also go through the official Dropbox app: `Authorization::dropbox_app_request` (Android) and
  `Authorization::dropbox_app_url` (iOS).

## OneDrive

- The root is `special/approot` under `Files.ReadWrite.AppFolder`, or `root` under `Files.ReadWrite`. Items are
  addressed by path. The version is `eTag`.
- Reads download the pre-signed `downloadUrl` without credentials, then check the `eTag` again (retried up to three
  times).
- Small writes use PUT. Larger writes use an upload session with fragments aligned to 320 KiB and strictly below
  60 MiB. A session cannot protect `Matches` through commit, so Cloudset rejects that condition before upload.
- `Matches` sends the `eTag` as it was returned, quoted or bare; a wildcard, a weak tag or a list is refused before
  upload. Graph honors `If-Match` on `PUT …:/content` (412) although only the upload session page documents the
  header. For a file that no longer exists it ignores the header and creates the file; cloudset deletes that file
  again, that version only, and reports `PreconditionFailed`.
- Folders are created with `POST …/items/<parent ID>/children` after looking the parent up: in the app folder Graph
  refuses the same request addressed by path.
- Graph answers 501 `notSupported` to content written onto a folder, 422 `notSupported` to the children of a file,
  and 400 `invalidRequest` to a move whose source is missing as well as to an invalid name; cloudset tells the last
  two apart by looking at the source.
- Moves look up the destination folder's ID, then `PATCH` the item with `parentReference`, the new name and
  `conflictBehavior=fail`.
- Microsoft has no revocation endpoint: `revoke` succeeds without a request, and the user removes the app under "App
  access" in their Microsoft account.

## Google Drive

- Items are addressed by ID and names are not unique, so paths resolve one segment at a time from the root
  (intermediate segments match folders only). Among items with the same name, the oldest (creation time, then ID) always
  wins, in listings too.
- The version is `headRevisionId`. Reads download `alt=media` and check the version again (retried up to three times).
- Path-based creation and revision replacement cannot enforce atomic preconditions here. Both `Absent` and `Matches`
  return `UnsupportedPrecondition` before any network request. Use an application-specific conflict workflow or
  explicitly request an unconditional write. Historical revisions are never replayed as conflict compensation.
- New files up to 5 MiB are one `multipart/related` upload; larger files and revisions use a resumable upload session
  (chunks of a multiple of 256 KiB). Either way the file appears only when all of it has arrived.
- Creating a file or folder looks the name up again afterwards. A listing that does not show the new item yet counts
  as success. If an older file with the same name turned up, the file just created is deleted and the write reports
  `CommitUnconfirmed`: the path now resolves to the other device's file. A duplicate folder is left alone, because
  another device may already be writing into it, and the oldest one is used.
- A move checks the destination before and after changing the item. If another item with the name turned up, both stay
  and the move reports `CommitUnconfirmed`; inspect both paths.
- `revoke` revokes the refresh token, which ends the whole grant.
