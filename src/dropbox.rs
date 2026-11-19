//! Dropbox API v2 (<https://www.dropbox.com/developers/documentation/http/documentation>).
//!
//! Paths are relative to the storage root: for an App folder app the root is "Apps › &lt;app name&gt;", for a Full Dropbox app
//! it is the whole drive. The root is written as an empty string, everything else as `/a/b`. The version is the file's
//! `rev`: the `Dropbox-API-Result` header on downloads and the upload response carry the same kind of `rev`, so reads
//! and writes agree. Conditional writes use the upload `mode`: `update` (conflict if the rev differs), `add` (conflict
//! if it exists), or `overwrite`; all set `strict_conflict` so that `update` also reports a conflict when the remote file
//! was deleted.

use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::authorized::{Authorized, Next, Outgoing, Steps};
use crate::client::ClientConfig;
use crate::connection::Connection;
use crate::entry::{Entry, File, Precondition, Revision};
use crate::error::CloudError;
use crate::http::{HttpRequest, HttpResponse, Method, status_error};
use crate::operation::BoxOperation;
use crate::path::RemotePath;
use crate::providers::{json_request, parse_utc};

const API: &str = "https://api.dropboxapi.com/2";
const CONTENT: &str = "https://content.dropboxapi.com/2";

fn dropbox_path(path: &RemotePath) -> String {
    if path.is_root() { String::new() } else { format!("/{path}") }
}

fn rpc(endpoint: &str, args: &Value) -> Outgoing {
    Outgoing::authorized(json_request(Method::Post, &format!("{API}/{endpoint}"), Some(args)))
}

/// The `Dropbox-API-Arg` header must be ASCII: non-ASCII characters are written as `\uXXXX` (UTF-16, surrogate pairs
/// split).
fn header_json(value: &Value) -> String {
    let mut out = String::new();
    for c in value.to_string().chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            let mut units = [0u16; 2];
            for unit in c.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    out
}

fn content(endpoint: &str, args: &Value, body: Vec<u8>) -> Outgoing {
    let mut headers = vec![("Dropbox-API-Arg".to_owned(), header_json(args))];
    if !body.is_empty() || endpoint.starts_with("files/upload") {
        headers.push(("Content-Type".into(), "application/octet-stream".into()));
    }
    Outgoing::authorized(HttpRequest { method: Method::Post, url: format!("{CONTENT}/{endpoint}"), headers, body })
}

/// `error_summary` of a 409 (such as `path/not_found/..` or `path/conflict/file/..`).
fn error_summary(response: &HttpResponse) -> String {
    serde_json::from_slice::<Value>(&response.body)
        .ok()
        .and_then(|json| json.get("error_summary").and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_default()
}

fn error_for(response: &HttpResponse) -> CloudError {
    if response.status != 409 {
        return status_error(response);
    }
    let summary = error_summary(response);
    if summary.contains("not_found") {
        CloudError::NotFound
    } else if summary.contains("conflict") {
        CloudError::PreconditionFailed
    } else if summary.contains("insufficient_space") {
        CloudError::QuotaExceeded
    } else if ["malformed_path", "disallowed_name", "cant_move_folder_into_itself", "duplicated_or_nested_paths"]
        .iter()
        .any(|reason| summary.contains(reason))
    {
        CloudError::InvalidPath
    } else if summary.contains("no_write_permission") {
        CloudError::Forbidden
    } else {
        CloudError::Server { status: 409 }
    }
}

fn is_not_found(response: &HttpResponse) -> bool {
    response.status == 409 && error_summary(response).contains("not_found")
}

fn json_body(response: &HttpResponse) -> Result<Value, CloudError> {
    serde_json::from_slice(&response.body).map_err(|_| CloudError::InvalidResponse("json"))
}

/// Metadata -> entry. `path` is the path the caller already knows (so the casing of `path_display` does not matter).
/// `get_metadata` and `list_folder` return a union type with `.tag`; use [`file_entry`] for results that can only be
/// files.
fn entry(metadata: &Value, path: RemotePath) -> Result<Entry, CloudError> {
    let tag = metadata.get(".tag").and_then(Value::as_str).ok_or(CloudError::InvalidResponse("metadata"))?;
    entry_of_kind(metadata, path, tag == "folder")
}

/// The upload response and the `Dropbox-API-Result` download header are `FileMetadata` itself, without `.tag` (verified
/// against the live API).
fn file_entry(metadata: &Value, path: RemotePath) -> Result<Entry, CloudError> {
    if !metadata.is_object() {
        return Err(CloudError::InvalidResponse("file metadata"));
    }
    entry_of_kind(metadata, path, false)
}

fn entry_of_kind(metadata: &Value, path: RemotePath, is_dir: bool) -> Result<Entry, CloudError> {
    Ok(Entry {
        path,
        is_dir,
        size: metadata.get("size").and_then(Value::as_u64),
        modified_at: metadata.get("server_modified").and_then(Value::as_str).and_then(parse_utc),
        revision: metadata.get("rev").and_then(Value::as_str).map(Revision::new),
    })
}

fn root_entry() -> Entry {
    Entry { path: RemotePath::root(), is_dir: true, size: None, modified_at: None, revision: None }
}

fn op<S: Steps + 'static>(steps: S, connection: &Connection, config: &ClientConfig) -> BoxOperation<S::Output> {
    match Authorized::new(steps, connection, config) {
        Ok(operation) => Box::new(operation),
        Err(error) => Box::new(crate::operation::Ready::err(error)),
    }
}

// MARK: - Metadata

struct Stat {
    path: RemotePath,
}

impl Steps for Stat {
    type Output = Option<Entry>;

    fn first(&mut self) -> Result<Outgoing, CloudError> {
        Ok(rpc("files/get_metadata", &json!({ "path": dropbox_path(&self.path) })))
    }

    fn next(&mut self, response: HttpResponse) -> Result<Next<Option<Entry>>, CloudError> {
        match response.status {
            200 => Ok(Next::Done(Some(entry(&json_body(&response)?, self.path.clone())?))),
            _ if is_not_found(&response) => Ok(Next::Done(None)),
            _ => Err(error_for(&response)),
        }
    }
}

pub(crate) fn stat(connection: &Connection, config: &ClientConfig, path: RemotePath) -> BoxOperation<Option<Entry>> {
    // Dropbox does not support metadata for the root: the root always exists.
    if path.is_root() {
        return Box::new(crate::operation::Ready::ok(Some(root_entry())));
    }
    op(Stat { path }, connection, config)
}

// MARK: - Listing

struct List {
    dir: RemotePath,
    entries: Vec<Entry>,
    max_entries: usize,
}

impl Steps for List {
    type Output = Vec<Entry>;

    fn first(&mut self) -> Result<Outgoing, CloudError> {
        Ok(rpc("files/list_folder", &json!({ "path": dropbox_path(&self.dir), "recursive": false })))
    }

    fn next(&mut self, response: HttpResponse) -> Result<Next<Vec<Entry>>, CloudError> {
        if response.status != 200 {
            return Err(error_for(&response));
        }
        let json = json_body(&response)?;
        for item in json.get("entries").and_then(Value::as_array).ok_or(CloudError::InvalidResponse("entries"))? {
            let name = item.get("name").and_then(Value::as_str).ok_or(CloudError::InvalidResponse("name"))?;
            // Drop entries with invalid names (containing `/` or control characters) instead of joining them into a path.
            let Ok(path) = self.dir.join(name) else { continue };
            if self.entries.len() >= self.max_entries {
                return Err(CloudError::TooLarge);
            }
            self.entries.push(entry(item, path)?);
        }
        if json.get("has_more").and_then(Value::as_bool) == Some(true) {
            let cursor = json.get("cursor").and_then(Value::as_str).ok_or(CloudError::InvalidResponse("cursor"))?;
            return Ok(Next::Request(rpc("files/list_folder/continue", &json!({ "cursor": cursor }))));
        }
        let mut entries = std::mem::take(&mut self.entries);
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(Next::Done(entries))
    }
}

pub(crate) fn list(connection: &Connection, config: &ClientConfig, dir: RemotePath) -> BoxOperation<Vec<Entry>> {
    op(List { dir, entries: Vec::new(), max_entries: config.limits.max_entries }, connection, config)
}

// MARK: - Reading

struct Read {
    path: RemotePath,
}

impl Steps for Read {
    type Output = Option<File>;

    fn first(&mut self) -> Result<Outgoing, CloudError> {
        Ok(content("files/download", &json!({ "path": dropbox_path(&self.path) }), Vec::new()))
    }

    fn next(&mut self, response: HttpResponse) -> Result<Next<Option<File>>, CloudError> {
        match response.status {
            200 => {
                let metadata: Value = response
                    .header("Dropbox-API-Result")
                    .and_then(|text| serde_json::from_str(text).ok())
                    .ok_or(CloudError::InvalidResponse("download metadata"))?;
                let entry = file_entry(&metadata, self.path.clone())?;
                Ok(Next::Done(Some(File { data: response.body, entry })))
            }
            _ if is_not_found(&response) => Ok(Next::Done(None)),
            _ => Err(error_for(&response)),
        }
    }
}

pub(crate) fn read(connection: &Connection, config: &ClientConfig, path: RemotePath) -> BoxOperation<Option<File>> {
    op(Read { path }, connection, config)
}

// MARK: - Writing

/// `files/upload` takes at most 150 MB; larger files go through an upload session.
const MAX_REQUEST: usize = 150 * 1024 * 1024;
/// Session chunks are kept to multiples of 4 MiB, which every session type accepts.
const CHUNK_UNIT: usize = 4 * 1024 * 1024;

enum WriteState {
    Start,
    /// A single `files/upload`, or `upload_session/finish`: the response is the file's metadata.
    Committing,
    /// `upload_session/start` sent; its response carries the session ID.
    Starting,
    /// `upload_session/append_v2` sent.
    Appending {
        session: String,
    },
}

struct Write {
    path: RemotePath,
    data: Zeroizing<Vec<u8>>,
    precondition: Precondition,
    chunk: usize,
    /// Bytes handed to the session so far.
    offset: usize,
    state: WriteState,
}

impl Write {
    fn commit(&self) -> Value {
        let mode = match &self.precondition {
            Precondition::Matches(revision) => json!({ ".tag": "update", "update": revision.as_str() }),
            Precondition::Absent => json!("add"),
            Precondition::None => json!("overwrite"),
        };
        json!({
            "path": dropbox_path(&self.path),
            "mode": mode,
            "autorename": false,
            "mute": true,
            "strict_conflict": true,
        })
    }

    /// The next session request after `offset` bytes were accepted: another chunk, or the last one with the commit.
    fn continue_session(&mut self, session: String) -> Outgoing {
        let cursor = json!({ "session_id": session, "offset": self.offset });
        let end = (self.offset + self.chunk).min(self.data.len());
        let body = self.data[self.offset..end].to_vec();
        if end == self.data.len() {
            self.state = WriteState::Committing;
            return content("files/upload_session/finish", &json!({ "cursor": cursor, "commit": self.commit() }), body);
        }
        self.offset = end;
        self.state = WriteState::Appending { session };
        content("files/upload_session/append_v2", &json!({ "cursor": cursor, "close": false }), body)
    }
}

/// Errors of the session endpoints: the session itself failing is not the caller's file being missing.
fn session_error(response: &HttpResponse) -> CloudError {
    let summary = error_summary(response);
    if response.status == 409
        && ["lookup_failed", "incorrect_offset", "not_found", "closed", "not_closed"].iter().any(|prefix| summary.starts_with(prefix))
    {
        return CloudError::InvalidResponse("upload session");
    }
    error_for(response)
}

impl Steps for Write {
    type Output = Entry;

    fn first(&mut self) -> Result<Outgoing, CloudError> {
        if !matches!(self.state, WriteState::Start) {
            return Err(CloudError::OutOfOrder);
        }
        if self.data.len() <= self.chunk {
            self.state = WriteState::Committing;
            return Ok(content("files/upload", &self.commit(), self.data.to_vec()));
        }
        self.offset = self.chunk;
        self.state = WriteState::Starting;
        Ok(content("files/upload_session/start", &json!({ "close": false }), self.data[..self.chunk].to_vec()))
    }

    fn next(&mut self, response: HttpResponse) -> Result<Next<Entry>, CloudError> {
        match std::mem::replace(&mut self.state, WriteState::Start) {
            WriteState::Committing => match response.status {
                200 => Ok(Next::Done(file_entry(&json_body(&response)?, self.path.clone())?)),
                _ => Err(session_error(&response)),
            },
            WriteState::Starting => match response.status {
                200 => {
                    let json = json_body(&response)?;
                    let session = json.get("session_id").and_then(Value::as_str).ok_or(CloudError::InvalidResponse("session id"))?;
                    Ok(Next::Request(self.continue_session(session.to_owned())))
                }
                _ => Err(session_error(&response)),
            },
            WriteState::Appending { session } => match response.status {
                200 => Ok(Next::Request(self.continue_session(session))),
                _ => Err(session_error(&response)),
            },
            WriteState::Start => Err(CloudError::OutOfOrder),
        }
    }
}

pub(crate) fn write(
    connection: &Connection,
    config: &ClientConfig,
    path: RemotePath,
    data: Vec<u8>,
    precondition: Precondition,
) -> BoxOperation<Entry> {
    let chunk = config.limits.chunk_size(CHUNK_UNIT, MAX_REQUEST);
    op(Write { path, data: Zeroizing::new(data), precondition, chunk, offset: 0, state: WriteState::Start }, connection, config)
}

// MARK: - Moving

enum RenameState {
    /// Checking that the destination's parent folder exists (Dropbox would create it).
    Parent,
    Moving,
}

struct Rename {
    from: RemotePath,
    to: RemotePath,
    state: RenameState,
}

impl Rename {
    fn move_request(&mut self) -> Outgoing {
        self.state = RenameState::Moving;
        rpc(
            "files/move_v2",
            &json!({
                "from_path": dropbox_path(&self.from),
                "to_path": dropbox_path(&self.to),
                "autorename": false,
                "allow_ownership_transfer": false,
            }),
        )
    }
}

impl Steps for Rename {
    type Output = Entry;

    fn first(&mut self) -> Result<Outgoing, CloudError> {
        match self.to.parent().filter(|parent| !parent.is_root()) {
            Some(parent) => Ok(rpc("files/get_metadata", &json!({ "path": dropbox_path(&parent) }))),
            None => Ok(self.move_request()),
        }
    }

    fn next(&mut self, response: HttpResponse) -> Result<Next<Entry>, CloudError> {
        match self.state {
            RenameState::Parent => match response.status {
                200 if json_body(&response)?.get(".tag").and_then(Value::as_str) == Some("folder") => {
                    Ok(Next::Request(self.move_request()))
                }
                200 => Err(CloudError::NotFound),
                _ => Err(error_for(&response)),
            },
            RenameState::Moving => match response.status {
                200 => {
                    let json = json_body(&response)?;
                    Ok(Next::Done(entry(json.get("metadata").ok_or(CloudError::InvalidResponse("metadata"))?, self.to.clone())?))
                }
                _ => Err(error_for(&response)),
            },
        }
    }
}

pub(crate) fn rename(connection: &Connection, config: &ClientConfig, from: RemotePath, to: RemotePath) -> BoxOperation<Entry> {
    op(Rename { from, to, state: RenameState::Parent }, connection, config)
}

// MARK: - Directories and deletion

struct CreateDir {
    path: RemotePath,
}

impl Steps for CreateDir {
    type Output = ();

    fn first(&mut self) -> Result<Outgoing, CloudError> {
        Ok(rpc("files/create_folder_v2", &json!({ "path": dropbox_path(&self.path), "autorename": false })))
    }

    fn next(&mut self, response: HttpResponse) -> Result<Next<()>, CloudError> {
        match response.status {
            200 => Ok(Next::Done(())),
            // Already exists: success if it is a folder; a file with the same name cannot be used.
            409 if error_summary(&response).contains("conflict/folder") => Ok(Next::Done(())),
            409 if error_summary(&response).contains("conflict") => Err(CloudError::Forbidden),
            _ => Err(error_for(&response)),
        }
    }
}

pub(crate) fn create_dir(connection: &Connection, config: &ClientConfig, path: RemotePath) -> BoxOperation<()> {
    if path.is_root() {
        return Box::new(crate::operation::Ready::ok(()));
    }
    op(CreateDir { path }, connection, config)
}

struct Delete {
    path: RemotePath,
}

impl Steps for Delete {
    type Output = ();

    fn first(&mut self) -> Result<Outgoing, CloudError> {
        Ok(rpc("files/delete_v2", &json!({ "path": dropbox_path(&self.path) })))
    }

    fn next(&mut self, response: HttpResponse) -> Result<Next<()>, CloudError> {
        match response.status {
            200 => Ok(Next::Done(())),
            _ if is_not_found(&response) => Ok(Next::Done(())),
            _ => Err(error_for(&response)),
        }
    }
}

pub(crate) fn delete(connection: &Connection, config: &ClientConfig, path: RemotePath) -> BoxOperation<()> {
    op(Delete { path }, connection, config)
}

/// Revokes the current token (refresh tokens from the same authorization stop working too). An already invalid token
/// (401) counts as success.
struct Revoke;

impl Steps for Revoke {
    type Output = ();

    fn first(&mut self) -> Result<Outgoing, CloudError> {
        Ok(rpc("auth/token/revoke", &Value::Null))
    }

    fn next(&mut self, response: HttpResponse) -> Result<Next<()>, CloudError> {
        match response.status {
            200 | 401 => Ok(Next::Done(())),
            _ => Err(error_for(&response)),
        }
    }
}

pub(crate) fn revoke(connection: &Connection, config: &ClientConfig) -> BoxOperation<()> {
    op(Revoke, connection, config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_arguments_are_ascii() {
        let text = header_json(&json!({ "path": "/备份/😀.txt" }));
        assert!(text.is_ascii());
        assert_eq!(text, "{\"path\":\"/\\u5907\\u4efd/\\ud83d\\ude00.txt\"}");
    }

    #[test]
    fn maps_409_summaries() {
        let response = |summary: &str| HttpResponse {
            status: 409,
            headers: Vec::new(),
            body: json!({ "error_summary": summary }).to_string().into_bytes(),
        };
        assert_eq!(error_for(&response("path/not_found/..")), CloudError::NotFound);
        assert_eq!(error_for(&response("path/conflict/file/..")), CloudError::PreconditionFailed);
        assert_eq!(error_for(&response("path/insufficient_space/")), CloudError::QuotaExceeded);
        assert_eq!(error_for(&response("path/malformed_path/")), CloudError::InvalidPath);
        assert_eq!(error_for(&response("other/")), CloudError::Server { status: 409 });
    }
}
