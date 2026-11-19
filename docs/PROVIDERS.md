# Provider notes

How cloudset maps its operations onto each provider. The [README](../README.md) describes the shared contract; this page
is for when you need to know exactly what goes over the wire.

## Overview

| | WebDAV / Nextcloud | Dropbox | OneDrive | Google Drive |
| --- | --- | --- | --- | --- |
| Sign-in | User name and password, or Nextcloud Login Flow v2 | OAuth 2.0 + PKCE | OAuth 2.0 + PKCE | OAuth 2.0 + PKCE |
| Access scopes | `Full` | `AppFolder`, `Full` | `AppFolder`, `Full` | `AppFolder`, `Full` |
| Version (`Revision`) | `getetag` from `PROPFIND` | `rev` | `eTag` | `headRevisionId` |
| Conditional writes | `If-Match` / `If-None-Match: *` | Upload `mode` | `If-Match` / `conflictBehavior=fail` | Emulated |
| Large uploads | One `PUT` | Upload session | Upload session | Resumable upload |
| Move or rename | `MOVE`, `Overwrite: F` | `files/move_v2` | `PATCH` with `parentReference` | `PATCH` with `addParents` / `removeParents` |
| Missing parent on write | `NotFound` | Created | Created | Created |
| `revoke` | Nextcloud deletes the app password; WebDAV does nothing | Revokes the token | Nothing (no endpoint) | Revokes the whole grant |

Every provider: `rename` requires the destination's parent to exist and the destination to be free; it never overwrites.

## WebDAV and Nextcloud

- **Versions** always come from `getetag` in `PROPFIND`. The `ETag` header of `GET` and `PUT` responses is ignored,
  because servers do not always write it the same way.
- **Reads** are `PROPFIND`, then `GET` with `If-Match`, retried up to three times if the file changes in between.
- **Writes** are a conditional `PUT`, then `PROPFIND` for the new version. `Precondition::Absent` sends
  `If-None-Match: *`; `Matches` sends `If-Match`. A weak ETag (`W/"…"`) cannot be compared strongly, so cloudset compares
  the version before writing instead, which leaves a short race window.
- **Directories**: `MKCOL`. A 405 response means "already exists" in RFC 4918, but some servers also send it when
  permission is denied, so cloudset checks with `PROPFIND` before treating it as success.
- **Moves**: `MOVE` with `Destination` and `Overwrite: F`. A 412 response (destination exists) is `PreconditionFailed`;
  404 and 409 (missing source or parent) are `NotFound`.
- **Plain HTTP** is only accepted with `Transport::AllowInsecureHttp`, after the user agreed.
- **Pinned certificates** are only allowed when every address of the connection is `https://`.
- **Untrusted XML**: a `DOCTYPE` is rejected, custom entities are not expanded, and nesting depth and entry counts are
  capped. An `href` outside the root, or containing `..` or control characters, is dropped.
- **Nextcloud Login Flow v2**: the poll endpoint, the login page and the returned server address must share the origin
  the user entered (an upgrade from HTTP to HTTPS on the same host is allowed).

## OAuth providers

- `oauth::begin(provider, access, client, &random)` derives the PKCE verifier and `state` from 64 random bytes you take
  from a CSPRNG. Open `Authorization::url()` in the system authentication session and pass the callback URL to
  `complete`, which checks the URL and `state` (in constant time) before it sends anything. There is no client secret.
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
- Writes up to the chunk size are one `PUT …:/content`. Larger files use `createUploadSession` with the same `If-Match`
  and `conflictBehavior`, then chunks (multiples of 320 KiB, at most 60 MiB) sent to the session's pre-signed URL.
  Graph checks `If-Match` when the session is created, not when it completes, so a write by someone else during a
  chunked upload is overwritten. Raise `Limits::upload_chunk_bytes` above your file sizes if that window matters.
- Moves look up the destination folder's ID, then `PATCH` the item with `parentReference`, the new name and
  `conflictBehavior=fail`.
- Microsoft has no revocation endpoint: `revoke` succeeds without a request, and the user removes the app under "App
  access" in their Microsoft account.

## Google Drive

- Items are addressed by ID and names are not unique, so paths resolve one segment at a time from the root
  (intermediate segments match folders only). Among items with the same name, the oldest (creation time, then ID) always
  wins, in listings too.
- The version is `headRevisionId`. Reads download `alt=media` and check the version again (retried up to three times).
- Drive v3 has no conditional writes, so cloudset emulates them:
  - `Matches(rev)` compares the head revision before uploading and lists the revisions afterwards. If another writer got
    in between, its revision is uploaded again on top and the write reports `PreconditionFailed`, so no write is
    silently lost.
  - `Absent` looks the name up again after creating; of two concurrent files, the newer one is deleted by its writer.
- New files up to 5 MiB are one `multipart/related` upload; larger files and revisions use a resumable upload session
  (chunks of a multiple of 256 KiB). Either way the file appears only when all of it has arrived.
- Moves resolve both paths, `PATCH` the item's name and parents, then look the name up again. If any other item with
  the same name turned up meanwhile, the move is undone and reports `PreconditionFailed` (the moved item keeps its old
  creation time, so age cannot decide). At worst both writers report a conflict; no data is hidden.
- `revoke` revokes the refresh token, which ends the whole grant.
