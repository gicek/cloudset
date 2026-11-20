//! Google Drive (Drive API v3, <https://developers.google.com/workspace/drive/api/reference/rest/v3>).
//!
//! Drive addresses items by ID, and names are not unique within a folder, so a path is resolved one segment at a time
//! from the drive root ([`Walk`]): one name lookup per segment, folders only for the intermediate ones. Among items with
//! the same name the oldest wins (creation time, then ID), so every device picks the same one.
//!
//! The root depends on the access scope. `drive.file` only reaches files the app created, and Drive has no app folder of
//! its own: the app folder is a visible folder in My Drive named by the caller ([`crate::OAuthClient::folder_name`]),
//! created on first access. `drive` uses My Drive itself (`root`).
//!
//! The version is the file's `headRevisionId`. Reading downloads `alt=media`, then fetches the metadata again to check the
//! version, retrying if it changed in between (at most 3 times).
//!
//! Conditional path writes are refused before sending requests. A revision check followed by an upload cannot
//! protect a concurrent update, and Drive allows multiple files with the same name.
//!
//! Creating looks the name up again afterwards. A listing that does not show the new item yet is not a failure: the
//! create response already named it. When an older item with the same name turns up, another device created it
//! concurrently: a file just created here is deleted again (nothing else refers to it yet) and the write reports
//! `CommitUnconfirmed`; folders and moved items are left alone, because another device may already be using them.
//!
//! New files are created with one multipart upload (metadata + content), so no device ever sees an empty file. Files over
//! 5 MiB (or [`crate::Limits::upload_chunk_bytes`]) use a resumable upload session instead, which is just as atomic: the
//! file or revision appears when the last chunk arrives.

use std::collections::HashSet;
use std::time::SystemTime;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::authorized::{Authorized, Next, Outgoing, Steps};
use crate::client::ClientConfig;
use crate::connection::Connection;
use crate::entry::{Entry, File, Precondition, Revision};
use crate::error::CloudError;
use crate::http::{HttpRequest, HttpResponse, Method, retry_after, status_error};
use crate::operation::{BoxOperation, Ready};
use crate::path::RemotePath;
use crate::providers::{json_request, parse_utc};

mod upload;
mod walk;

use upload::{CHUNK_UNIT, Target, Upload, Uploaded};
use walk::{Drive, Lookup, LookupResult, Walk, Walked};

const API: &str = "https://www.googleapis.com/drive/v3";
const UPLOAD: &str = "https://www.googleapis.com/upload/drive/v3";
const REVOKE: &str = "https://oauth2.googleapis.com/revoke";
const FOLDER: &str = "application/vnd.google-apps.folder";
const FIELDS: &str = "id,name,mimeType,size,modifiedTime,createdTime,headRevisionId";
const READ_ATTEMPTS: u8 = 3;
/// Fetch duplicates in bounded pages, including ties across page boundaries.
const LOOKUP_PAGE: usize = 100;
/// The page size for listing a directory.
const LIST_PAGE: usize = 1000;
/// Drive may return a page without items but with a token for the next one. Pages with items are bounded by
/// [`crate::Limits::max_entries`]; this bounds the ones without.
const EMPTY_PAGES: usize = 32;
/// Drive IDs are `[A-Za-z0-9_-]`; anything else is encoded anyway before it goes into a URL path.
const ID: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_');

// MARK: - Items and requests

#[derive(Clone, Debug)]
struct Item {
    id: String,
    name: String,
    is_dir: bool,
    size: Option<u64>,
    modified_at: Option<SystemTime>,
    created_at: Option<SystemTime>,
    revision: Option<Revision>,
}

impl Item {
    /// My Drive (`root` is an alias Drive accepts wherever an ID is expected).
    fn drive_root() -> Self {
        Self { id: "root".into(), name: String::new(), is_dir: true, size: None, modified_at: None, created_at: None, revision: None }
    }

    fn parse(value: &Value) -> Result<Self, CloudError> {
        let text = |key: &str| value.get(key).and_then(Value::as_str);
        let id = text("id").filter(|id| !id.is_empty()).ok_or(CloudError::InvalidResponse("file id"))?;
        let is_dir = text("mimeType") == Some(FOLDER);
        // `size` is an int64 written as a JSON string.
        let size = match value.get("size") {
            Some(Value::String(size)) => size.parse().ok(),
            Some(size) => size.as_u64(),
            None => None,
        };
        Ok(Self {
            id: id.to_owned(),
            name: text("name").unwrap_or_default().to_owned(),
            is_dir,
            size: if is_dir { None } else { size },
            modified_at: text("modifiedTime").and_then(parse_utc),
            created_at: text("createdTime").and_then(parse_utc),
            revision: if is_dir { None } else { text("headRevisionId").map(Revision::new) },
        })
    }

    fn entry(&self, path: RemotePath) -> Entry {
        Entry { path, is_dir: self.is_dir, size: self.size, modified_at: self.modified_at, revision: self.revision.clone() }
    }
}

fn json_body(response: &HttpResponse) -> Result<Value, CloudError> {
    serde_json::from_slice(&response.body).map_err(|_| CloudError::InvalidResponse("json"))
}

/// Items of a `files.list` page, oldest first (ties broken by ID), and the next page token.
fn files(response: &HttpResponse) -> Result<(Vec<Item>, Option<String>), CloudError> {
    let json = json_body(response)?;
    if json.get("incompleteSearch").and_then(Value::as_bool) == Some(true) {
        return Err(CloudError::InvalidResponse("incomplete Drive search"));
    }
    let mut items = json
        .get("files")
        .and_then(Value::as_array)
        .ok_or(CloudError::InvalidResponse("files"))?
        .iter()
        .map(Item::parse)
        .collect::<Result<Vec<_>, _>>()?;
    oldest_first(&mut items);
    let next = json.get("nextPageToken").and_then(Value::as_str).filter(|token| !token.is_empty()).map(str::to_owned);
    Ok((items, next))
}

fn oldest_first(items: &mut [Item]) {
    items.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
}

fn reason(response: &HttpResponse) -> String {
    serde_json::from_slice::<Value>(&response.body)
        .ok()
        .and_then(|json| json.pointer("/error/errors/0/reason").and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_default()
}

/// Drive reports both a full drive and rate limits as 403 with a reason.
fn error_for(response: &HttpResponse) -> CloudError {
    if response.status != 403 {
        return status_error(response);
    }
    match reason(response).as_str() {
        "storageQuotaExceeded" => CloudError::QuotaExceeded,
        "userRateLimitExceeded" | "rateLimitExceeded" | "dailyLimitExceeded" | "sharingRateLimitExceeded" => {
            CloudError::RateLimited { retry_after: retry_after(response) }
        }
        _ => CloudError::Forbidden,
    }
}

/// A string literal in a `files.list` query: `'` and `\` are escaped with a backslash.
fn literal(text: &str) -> String {
    format!("'{}'", text.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn children_query(parent: &str, name: Option<&str>, folders_only: bool) -> String {
    let mut query = format!("{} in parents and trashed = false", literal(parent));
    if let Some(name) = name {
        query.push_str(&format!(" and name = {}", literal(name)));
    }
    if folders_only {
        query.push_str(&format!(" and mimeType = '{FOLDER}'"));
    }
    query
}

/// Oldest first, so that the oldest of many duplicates is on the first page of a lookup; results are sorted again locally
/// (with the ID as tie-breaker) because servers need not agree on ties.
fn search_url(query: &str, page_size: usize, page_token: Option<&str>) -> String {
    let mut params = url::form_urlencoded::Serializer::new(String::new());
    params
        .append_pair("q", query)
        .append_pair("orderBy", "createdTime")
        .append_pair("fields", &format!("nextPageToken,incompleteSearch,files({FIELDS})"))
        .append_pair("pageSize", &page_size.to_string())
        .append_pair("spaces", "drive");
    if let Some(token) = page_token {
        params.append_pair("pageToken", token);
    }
    format!("{API}/files?{}", params.finish())
}

fn file_url(base: &str, id: &str, suffix: &str) -> String {
    format!("{base}/files/{}{suffix}", utf8_percent_encode(id, ID))
}

fn get(url: String) -> Outgoing {
    Outgoing::authorized(json_request(Method::Get, &url, None))
}

/// Media downloads carry no `Accept: application/json`.
fn download(url: String) -> Outgoing {
    Outgoing::authorized(HttpRequest { method: Method::Get, url, headers: Vec::new(), body: Vec::new() })
}

fn metadata(id: &str) -> Outgoing {
    get(file_url(API, id, &format!("?fields={FIELDS}")))
}

fn delete(id: &str) -> Outgoing {
    Outgoing::authorized(json_request(Method::Delete, &file_url(API, id, ""), None))
}

fn create_folder(parent: &str, name: &str) -> Outgoing {
    let body = json!({ "name": name, "mimeType": FOLDER, "parents": [parent] });
    Outgoing::authorized(json_request(Method::Post, &format!("{API}/files?fields={FIELDS}"), Some(&body)))
}

/// Moves and renames an item in one request; parents are only sent when they change.
fn move_item(id: &str, name: &str, from_parent: &str, to_parent: &str) -> Outgoing {
    let mut url = file_url(API, id, &format!("?fields={FIELDS}"));
    if from_parent != to_parent {
        url.push_str(&format!("&addParents={}&removeParents={}", utf8_percent_encode(to_parent, ID), utf8_percent_encode(from_parent, ID)));
    }
    Outgoing::authorized(json_request(Method::Patch, &url, Some(&json!({ "name": name }))))
}

// MARK: - Path resolution

/// The first request of an operation: the walk must need one (operations whose walk finishes immediately are handled
/// before they start).
fn first_request(walked: Walked) -> Result<Outgoing, CloudError> {
    match walked {
        Walked::Send(outgoing) => Ok(outgoing),
        Walked::Found { .. } => Err(CloudError::OutOfOrder),
    }
}

fn op<S: Steps + 'static>(steps: Result<S, CloudError>, connection: &Connection, config: &ClientConfig) -> BoxOperation<S::Output> {
    match steps.and_then(|steps| Authorized::new(steps, connection, config)) {
        Ok(operation) => Box::new(operation),
        Err(error) => Box::new(Ready::err(error)),
    }
}

// MARK: - Metadata and listing

struct Stat {
    walk: Walk,
    path: RemotePath,
}

impl Steps for Stat {
    type Output = Option<Entry>;

    fn first(&mut self) -> Result<Outgoing, CloudError> {
        first_request(self.walk.step())
    }

    fn next(&mut self, response: HttpResponse) -> Result<Next<Option<Entry>>, CloudError> {
        match self.walk.receive(response)? {
            Walked::Send(outgoing) => Ok(Next::Request(outgoing)),
            Walked::Found { item, .. } => Ok(Next::Done(item.map(|item| item.entry(self.path.clone())))),
        }
    }
}

pub(crate) fn stat(connection: &Connection, config: &ClientConfig, path: RemotePath) -> BoxOperation<Option<Entry>> {
    match Drive::of(connection, config) {
        Ok(drive) if drive.is_drive_root(&path) => Box::new(Ready::ok(Some(Item::drive_root().entry(path)))),
        drive => op(drive.map(|drive| Stat { walk: drive.walk(&path, false), path }), connection, config),
    }
}

struct List {
    walk: Walk,
    dir: RemotePath,
    folder: Option<String>,
    items: Vec<Item>,
    max_entries: usize,
    empty_pages: usize,
}

impl List {
    fn page(&self, token: Option<&str>) -> Result<Outgoing, CloudError> {
        let folder = self.folder.as_deref().ok_or(CloudError::OutOfOrder)?;
        Ok(get(search_url(&children_query(folder, None, false), LIST_PAGE, token)))
    }

    fn found(&mut self, item: Option<Item>) -> Result<Outgoing, CloudError> {
        match item {
            Some(item) if item.is_dir => {
                self.folder = Some(item.id);
                self.page(None)
            }
            _ => Err(CloudError::NotFound),
        }
    }

    /// Duplicate names collapse to the oldest item, the one every other operation resolves to.
    fn finish(&mut self) -> Vec<Entry> {
        let mut items = std::mem::take(&mut self.items);
        oldest_first(&mut items);
        let mut seen = HashSet::new();
        let mut entries: Vec<Entry> = items
            .into_iter()
            .filter(|item| seen.insert(item.name.clone()))
            .filter_map(|item| self.dir.join(&item.name).ok().map(|path| item.entry(path)))
            .collect();
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        entries
    }
}

impl Steps for List {
    type Output = Vec<Entry>;

    fn first(&mut self) -> Result<Outgoing, CloudError> {
        match self.walk.step() {
            Walked::Send(outgoing) => Ok(outgoing),
            Walked::Found { item, .. } => self.found(item),
        }
    }

    fn next(&mut self, response: HttpResponse) -> Result<Next<Vec<Entry>>, CloudError> {
        if self.folder.is_none() {
            return match self.walk.receive(response)? {
                Walked::Send(outgoing) => Ok(Next::Request(outgoing)),
                Walked::Found { item, .. } => self.found(item).map(Next::Request),
            };
        }
        if response.status != 200 {
            return Err(match response.status {
                404 => CloudError::NotFound,
                _ => error_for(&response),
            });
        }
        let (items, next) = files(&response)?;
        if items.is_empty() && next.is_some() {
            self.empty_pages = self.empty_pages.checked_sub(1).ok_or(CloudError::TooLarge)?;
        }
        if self.items.len() + items.len() > self.max_entries {
            return Err(CloudError::TooLarge);
        }
        self.items.extend(items);
        match next {
            Some(token) => self.page(Some(&token)).map(Next::Request),
            None => Ok(Next::Done(self.finish())),
        }
    }
}

pub(crate) fn list(connection: &Connection, config: &ClientConfig, dir: RemotePath) -> BoxOperation<Vec<Entry>> {
    op(
        Drive::of(connection, config).map(|drive| List {
            walk: drive.walk(&dir, false),
            dir,
            folder: None,
            items: Vec::new(),
            max_entries: config.limits.max_entries,
            empty_pages: EMPTY_PAGES,
        }),
        connection,
        config,
    )
}

// MARK: - Reading

enum ReadState {
    Walking,
    Download(Item),
    Verify(Item, Vec<u8>),
}

struct Read {
    walk: Walk,
    path: RemotePath,
    attempts: u8,
    state: ReadState,
}

impl Read {
    fn download(&mut self, item: Item) -> Outgoing {
        self.attempts += 1;
        let request = download(file_url(API, &item.id, "?alt=media"));
        self.state = ReadState::Download(item);
        request
    }
}

impl Steps for Read {
    type Output = Option<File>;

    fn first(&mut self) -> Result<Outgoing, CloudError> {
        first_request(self.walk.step())
    }

    fn next(&mut self, response: HttpResponse) -> Result<Next<Option<File>>, CloudError> {
        match std::mem::replace(&mut self.state, ReadState::Walking) {
            ReadState::Walking => match self.walk.receive(response)? {
                Walked::Send(outgoing) => Ok(Next::Request(outgoing)),
                Walked::Found { item: None, .. } => Ok(Next::Done(None)),
                Walked::Found { item: Some(item), .. } if item.is_dir => Err(CloudError::InvalidResponse("expected a file")),
                Walked::Found { item: Some(item), .. } => Ok(Next::Request(self.download(item))),
            },
            ReadState::Download(item) => match response.status {
                200 => {
                    let verify = metadata(&item.id);
                    self.state = ReadState::Verify(item, response.body);
                    Ok(Next::Request(verify))
                }
                404 => Ok(Next::Done(None)),
                _ => Err(error_for(&response)),
            },
            ReadState::Verify(item, data) => {
                match response.status {
                    200 => {}
                    404 => return Ok(Next::Done(None)),
                    _ => return Err(error_for(&response)),
                }
                let current = Item::parse(&json_body(&response)?)?;
                if current.revision.is_some() && current.revision == item.revision {
                    return Ok(Next::Done(Some(File { data, entry: item.entry(self.path.clone()) })));
                }
                if self.attempts >= READ_ATTEMPTS {
                    return Err(CloudError::PreconditionFailed);
                }
                Ok(Next::Request(self.download(current)))
            }
        }
    }
}

pub(crate) fn read(connection: &Connection, config: &ClientConfig, path: RemotePath) -> BoxOperation<Option<File>> {
    if path.is_root() {
        return Box::new(Ready::err(CloudError::InvalidPath));
    }
    op(
        Drive::of(connection, config).map(|drive| Read { walk: drive.walk(&path, false), path, attempts: 0, state: ReadState::Walking }),
        connection,
        config,
    )
}

// MARK: - Writing

enum WriteState {
    Walking,
    Uploading {
        upload: Upload,
        parent: Option<Item>,
    },
    Verify {
        ours: Item,
        lookup: Lookup,
    },
    /// An older file with the name exists: deleting the one just created.
    Discard,
}

struct Write {
    walk: Walk,
    path: RemotePath,
    data: Zeroizing<Vec<u8>>,
    chunk: usize,
    state: WriteState,
}

impl Steps for Write {
    type Output = Entry;

    fn first(&mut self) -> Result<Outgoing, CloudError> {
        first_request(self.walk.step())
    }

    fn next(&mut self, response: HttpResponse) -> Result<Next<Entry>, CloudError> {
        match std::mem::replace(&mut self.state, WriteState::Walking) {
            WriteState::Walking => match self.walk.receive(response)? {
                Walked::Send(request) => Ok(Next::Request(request)),
                Walked::Found { item, parent } => {
                    let (target, parent) = match item {
                        Some(item) if item.is_dir => return Err(CloudError::Forbidden),
                        Some(item) => (Target::Existing { id: item.id }, None),
                        None => {
                            let parent = parent.ok_or(CloudError::NotFound)?;
                            let name = self.path.name().ok_or(CloudError::InvalidPath)?.to_owned();
                            (Target::New { parent: parent.id.clone(), name }, Some(parent))
                        }
                    };
                    let mut upload = Upload::new(target, std::mem::take(&mut *self.data), self.chunk);
                    let request = upload.start();
                    self.state = WriteState::Uploading { upload, parent };
                    Ok(Next::Request(request))
                }
            },
            WriteState::Uploading { mut upload, parent } => match upload.receive(response)? {
                Uploaded::Send(request) => {
                    self.state = WriteState::Uploading { upload, parent };
                    Ok(Next::Request(request))
                }
                Uploaded::Done(ours) => {
                    let Some(parent) = parent else { return Ok(Next::Done(ours.entry(self.path.clone()))) };
                    let name = self.path.name().ok_or(CloudError::InvalidPath)?;
                    let lookup = Lookup::new(&parent.id, name, false, self.walk.limit);
                    let request = lookup.page(None);
                    self.state = WriteState::Verify { ours, lookup };
                    Ok(Next::Request(request))
                }
                Uploaded::Failed(response) => Err(error_for(&response)),
            },
            WriteState::Verify { ours, mut lookup } => match lookup.receive(&response).map_err(|_| CloudError::CommitUnconfirmed)? {
                LookupResult::More(request) => {
                    self.state = WriteState::Verify { ours, lookup };
                    Ok(Next::Request(request))
                }
                // An empty result is the listing lagging behind the create.
                LookupResult::Found(None, _) => Ok(Next::Done(ours.entry(self.path.clone()))),
                LookupResult::Found(Some(item), _) if item.id == ours.id => Ok(Next::Done(ours.entry(self.path.clone()))),
                LookupResult::Found(Some(_), _) => {
                    self.state = WriteState::Discard;
                    Ok(Next::Request(delete(&ours.id)))
                }
            },
            // Deleted or not, the path resolves to the other device's file: the caller has to reconcile.
            WriteState::Discard => Err(CloudError::CommitUnconfirmed),
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
    if path.is_root() {
        return Box::new(Ready::err(CloudError::InvalidPath));
    }
    if !matches!(precondition, Precondition::None) {
        return Box::new(Ready::err(CloudError::UnsupportedPrecondition));
    }
    op(
        Drive::of(connection, config).map(|drive| Write {
            walk: drive.walk(&path, true),
            path,
            data: Zeroizing::new(data),
            chunk: config.limits.chunk_size(CHUNK_UNIT, usize::MAX),
            state: WriteState::Walking,
        }),
        connection,
        config,
    )
}

// MARK: - Directories and deletion

enum CreateState {
    Walking,
    Creating { parent: Item },
    Verify(Lookup),
}

struct CreateDir {
    walk: Walk,
    path: RemotePath,
    state: CreateState,
}

impl Steps for CreateDir {
    type Output = ();

    fn first(&mut self) -> Result<Outgoing, CloudError> {
        first_request(self.walk.step())
    }

    fn next(&mut self, response: HttpResponse) -> Result<Next<()>, CloudError> {
        let name = self.path.name().ok_or(CloudError::InvalidPath)?;
        match std::mem::replace(&mut self.state, CreateState::Walking) {
            CreateState::Walking => match self.walk.receive(response)? {
                Walked::Send(outgoing) => Ok(Next::Request(outgoing)),
                Walked::Found { item: Some(item), .. } if item.is_dir => Ok(Next::Done(())),
                Walked::Found { item: Some(_), .. } => Err(CloudError::Forbidden),
                Walked::Found { item: None, parent: None } => Err(CloudError::NotFound),
                Walked::Found { item: None, parent: Some(parent) } => {
                    let request = create_folder(&parent.id, name);
                    self.state = CreateState::Creating { parent };
                    Ok(Next::Request(request))
                }
            },
            CreateState::Creating { parent } => {
                if response.status != 200 {
                    return Err(error_for(&response));
                }
                let lookup = Lookup::new(&parent.id, name, false, self.walk.limit);
                let request = lookup.page(None);
                self.state = CreateState::Verify(lookup);
                Ok(Next::Request(request))
            }
            CreateState::Verify(mut lookup) => match lookup.receive(&response).map_err(|_| CloudError::CommitUnconfirmed)? {
                LookupResult::More(request) => {
                    self.state = CreateState::Verify(lookup);
                    Ok(Next::Request(request))
                }
                // An empty result is the listing lagging behind the create.
                LookupResult::Found(None, _) => Ok(Next::Done(())),
                LookupResult::Found(Some(item), _) if item.is_dir => Ok(Next::Done(())),
                LookupResult::Found(Some(_), _) => Err(CloudError::CommitUnconfirmed),
            },
        }
    }
}

pub(crate) fn create_dir(connection: &Connection, config: &ClientConfig, path: RemotePath) -> BoxOperation<()> {
    match Drive::of(connection, config) {
        Ok(drive) if drive.is_drive_root(&path) => Box::new(Ready::ok(())),
        drive => op(drive.map(|drive| CreateDir { walk: drive.walk(&path, false), path, state: CreateState::Walking }), connection, config),
    }
}

struct Delete {
    walk: Walk,
    deleting: bool,
}

impl Steps for Delete {
    type Output = ();

    fn first(&mut self) -> Result<Outgoing, CloudError> {
        first_request(self.walk.step())
    }

    fn next(&mut self, response: HttpResponse) -> Result<Next<()>, CloudError> {
        if self.deleting {
            return match response.status {
                200 | 204 | 404 => Ok(Next::Done(())),
                _ => Err(error_for(&response)),
            };
        }
        match self.walk.receive(response)? {
            Walked::Send(outgoing) => Ok(Next::Request(outgoing)),
            Walked::Found { item: None, .. } => Ok(Next::Done(())),
            Walked::Found { item: Some(item), .. } => {
                self.deleting = true;
                Ok(Next::Request(delete(&item.id)))
            }
        }
    }
}

pub(crate) fn delete_path(connection: &Connection, config: &ClientConfig, path: RemotePath) -> BoxOperation<()> {
    if path.is_root() {
        return Box::new(Ready::err(CloudError::InvalidPath));
    }
    op(Drive::of(connection, config).map(|drive| Delete { walk: drive.walk(&path, false), deleting: false }), connection, config)
}

// MARK: - Moving

enum RenameState {
    /// Resolving the source.
    From,
    /// Resolving the destination, with the source and its parent.
    To {
        item: Item,
        parent: Item,
    },
    Moving {
        to_parent: Item,
    },
    Verify {
        ours: Item,
        lookup: Lookup,
    },
}

struct Rename {
    from_walk: Walk,
    to_walk: Walk,
    to: RemotePath,
    state: RenameState,
}

impl Rename {
    fn name(path: &RemotePath) -> Result<&str, CloudError> {
        path.name().ok_or(CloudError::InvalidPath)
    }
}

impl Steps for Rename {
    type Output = Entry;

    fn first(&mut self) -> Result<Outgoing, CloudError> {
        first_request(self.from_walk.step())
    }

    fn next(&mut self, response: HttpResponse) -> Result<Next<Entry>, CloudError> {
        match std::mem::replace(&mut self.state, RenameState::From) {
            RenameState::From => match self.from_walk.receive(response)? {
                Walked::Send(outgoing) => {
                    self.state = RenameState::From;
                    Ok(Next::Request(outgoing))
                }
                Walked::Found { item: Some(item), parent: Some(parent) } => {
                    self.state = RenameState::To { item, parent };
                    match self.to_walk.step() {
                        Walked::Send(outgoing) => Ok(Next::Request(outgoing)),
                        Walked::Found { .. } => Err(CloudError::InvalidPath),
                    }
                }
                Walked::Found { .. } => Err(CloudError::NotFound),
            },
            RenameState::To { item, parent } => match self.to_walk.receive(response)? {
                Walked::Send(outgoing) => {
                    self.state = RenameState::To { item, parent };
                    Ok(Next::Request(outgoing))
                }
                Walked::Found { item: Some(_), .. } => Err(CloudError::PreconditionFailed),
                Walked::Found { item: None, parent: None } => Err(CloudError::NotFound),
                Walked::Found { item: None, parent: Some(to_parent) } => {
                    let request = move_item(&item.id, Self::name(&self.to)?, &parent.id, &to_parent.id);
                    self.state = RenameState::Moving { to_parent };
                    Ok(Next::Request(request))
                }
            },
            RenameState::Moving { to_parent } => {
                if response.status != 200 {
                    return Err(error_for(&response));
                }
                let ours = json_body(&response).and_then(|json| Item::parse(&json)).map_err(|_| CloudError::CommitUnconfirmed)?;
                let lookup = Lookup::new(&to_parent.id, Self::name(&self.to)?, false, self.to_walk.limit);
                let request = lookup.page(None);
                self.state = RenameState::Verify { ours, lookup };
                Ok(Next::Request(request))
            }
            RenameState::Verify { ours, mut lookup } => match lookup.receive(&response).map_err(|_| CloudError::CommitUnconfirmed)? {
                LookupResult::More(request) => {
                    self.state = RenameState::Verify { ours, lookup };
                    Ok(Next::Request(request))
                }
                // An empty result is the listing lagging behind the move.
                LookupResult::Found(None, _) => Ok(Next::Done(ours.entry(self.to.clone()))),
                LookupResult::Found(Some(item), 1) if item.id == ours.id => Ok(Next::Done(ours.entry(self.to.clone()))),
                LookupResult::Found(Some(_), _) => Err(CloudError::CommitUnconfirmed),
            },
        }
    }
}

pub(crate) fn rename(connection: &Connection, config: &ClientConfig, from: RemotePath, to: RemotePath) -> BoxOperation<Entry> {
    op(
        Drive::of(connection, config).map(|drive| Rename {
            from_walk: drive.walk(&from, false),
            to_walk: drive.walk(&to, false),
            to,
            state: RenameState::From,
        }),
        connection,
        config,
    )
}

// MARK: - Revocation

/// Revoking the refresh token ends the whole grant. It goes to the OAuth origin without a bearer token; the token is the
/// form body. A token Google no longer knows (400) counts as revoked.
struct Revoke {
    token: Zeroizing<String>,
}

impl Steps for Revoke {
    type Output = ();

    fn first(&mut self) -> Result<Outgoing, CloudError> {
        let body = url::form_urlencoded::Serializer::new(String::new()).append_pair("token", &self.token).finish();
        Ok(Outgoing::anonymous(
            HttpRequest::new(Method::Post, REVOKE)
                .with_header("Content-Type", "application/x-www-form-urlencoded")
                .with_body(Zeroizing::new(body).as_bytes().to_vec()),
        ))
    }

    fn next(&mut self, response: HttpResponse) -> Result<Next<()>, CloudError> {
        match response.status {
            200 | 400 => Ok(Next::Done(())),
            _ => Err(status_error(&response)),
        }
    }
}

pub(crate) fn revoke(connection: &Connection, config: &ClientConfig) -> BoxOperation<()> {
    let token = connection.oauth_credential().map(|credential| credential.refresh_token.clone()).ok_or(CloudError::InvalidConnection);
    op(token.map(|token| Revoke { token }), connection, config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: u16, body: &str) -> HttpResponse {
        HttpResponse { status, headers: Vec::new(), body: body.as_bytes().to_vec() }
    }

    #[test]
    fn queries_escape_names() {
        assert_eq!(literal(r"O'Brien \ co"), r"'O\'Brien \\ co'");
        assert_eq!(
            children_query("root", Some("a'b"), true),
            "'root' in parents and trashed = false and name = 'a\\'b' and mimeType = 'application/vnd.google-apps.folder'"
        );
        let url = url::Url::parse(&search_url(&children_query("id-1", None, false), 7, Some("next/page"))).unwrap();
        let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(query["q"], "'id-1' in parents and trashed = false");
        assert_eq!((query["pageSize"].as_str(), query["pageToken"].as_str(), query["spaces"].as_str()), ("7", "next/page", "drive"));
        assert_eq!(file_url(API, "a/b?c", "?alt=media"), "https://www.googleapis.com/drive/v3/files/a%2Fb%3Fc?alt=media");
    }

    #[test]
    fn parses_items_and_picks_the_oldest_duplicate() {
        let item = Item::parse(&json!({
            "id": "f1", "name": "data.bin", "mimeType": "application/octet-stream", "size": "2741",
            "modifiedTime": "2026-10-28T09:12:40.123Z", "createdTime": "2026-10-01T00:00:00Z", "headRevisionId": "0B-rev"
        }))
        .unwrap();
        assert_eq!((item.is_dir, item.size, item.revision.as_ref().map(Revision::as_str)), (false, Some(2741), Some("0B-rev")));
        let folder = Item::parse(&json!({ "id": "d1", "name": "Docs", "mimeType": FOLDER, "headRevisionId": "x" })).unwrap();
        assert_eq!((folder.is_dir, folder.revision), (true, None));
        assert!(Item::parse(&json!({ "name": "no id" })).is_err());

        let page = response(
            200,
            r#"{"files":[
                {"id":"b","name":"x","createdTime":"2026-10-02T00:00:00Z"},
                {"id":"c","name":"x","createdTime":"2026-10-01T00:00:00Z"},
                {"id":"a","name":"x","createdTime":"2026-10-02T00:00:00Z"}
            ],"nextPageToken":"t"}"#,
        );
        let (items, next) = files(&page).unwrap();
        assert_eq!(items.iter().map(|item| item.id.as_str()).collect::<Vec<_>>(), ["c", "a", "b"], "creation time, then ID");
        assert_eq!(next.as_deref(), Some("t"));
    }

    #[test]
    fn lookups_match_names_exactly() {
        let page = response(
            200,
            r#"{"files":[
                {"id":"a","name":"Data.bin","createdTime":"2026-10-01T00:00:00Z"},
                {"id":"b","name":"data.bin","createdTime":"2026-10-02T00:00:00Z"}
            ]}"#,
        );
        let mut lookup = Lookup::new("root", "data.bin", false, 10);
        assert!(matches!(lookup.receive(&page).unwrap(), LookupResult::Found(Some(item), _) if item.id == "b"));
        let mut lookup = Lookup::new("root", "DATA.BIN", false, 10);
        assert!(matches!(lookup.receive(&page).unwrap(), LookupResult::Found(None, 0)));
        let url = url::Url::parse(&search_url("'root' in parents", 1, None)).unwrap();
        assert!(url.query_pairs().any(|(key, value)| key == "orderBy" && value == "createdTime"));
    }

    #[test]
    fn maps_drive_errors() {
        let error = |status: u16, reason: &str| {
            error_for(&response(status, &json!({ "error": { "code": status, "errors": [{ "reason": reason }] } }).to_string()))
        };
        assert_eq!(error(403, "storageQuotaExceeded"), CloudError::QuotaExceeded);
        assert_eq!(error(403, "userRateLimitExceeded"), CloudError::RateLimited { retry_after: None });
        assert_eq!(error(403, "insufficientFilePermissions"), CloudError::Forbidden);
        assert_eq!(error(404, "notFound"), CloudError::NotFound);
        assert_eq!(error(429, "rateLimitExceeded"), CloudError::RateLimited { retry_after: None });
    }
}
