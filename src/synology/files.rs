//! File operations through the File Station API (`SYNO.FileStation.*`, DSM 7).
//!
//! Paths are relative to the connection's root folder (`/<shared folder>/…` on the device), or to the device itself when
//! the connection has no root folder: its top level then lists the shared folders, which File Station cannot create,
//! change or delete, so such operations report `Forbidden` before anything is sent. File Station has no version
//! identifier: entries carry no revision, reads check size and modification time before and after the download, and
//! only `Precondition::None` and `Precondition::Absent` are supported. `Absent` leaves out the upload's `overwrite`
//! parameter, which makes DSM refuse to replace an existing file (error 1805).

use serde_json::Value;
use zeroize::Zeroizing;

use crate::authorized::{Next, Outgoing, Steps};
use crate::client::ClientConfig;
use crate::connection::{Connection, Endpoint};
use crate::entry::{Entry, File, Precondition};
use crate::error::CloudError;
use crate::http::{HttpResponse, Method, status_error};
use crate::operation::{BoxOperation, Done, Operation, Ready, Step};
use crate::path::RemotePath;
use crate::synology::api::{self, ADDITIONAL, NO_SUCH_FILE, Reply};
use crate::synology::session::op;

const LIST: &str = "SYNO.FileStation.List";
const DOWNLOAD: &str = "SYNO.FileStation.Download";
const UPLOAD: &str = "SYNO.FileStation.Upload";
const CREATE_FOLDER: &str = "SYNO.FileStation.CreateFolder";
const DELETE: &str = "SYNO.FileStation.Delete";
const RENAME: &str = "SYNO.FileStation.Rename";
const COPY_MOVE: &str = "SYNO.FileStation.CopyMove";
/// Entries per listing page.
const PAGE: usize = 1000;
/// A read whose file keeps changing gives up after this many downloads.
const READ_ATTEMPTS: u8 = 3;
/// A move between folders runs as a background task, polled back to back (the crate cannot wait) this many times at most
/// before its outcome counts as unknown: the task may still finish, and when the name changes too, the item then stays
/// at `<destination folder>/<old name>`. Moves on one volume finish at once.
const MAX_POLLS: u16 = 600;

/// Where the connection's files are.
#[derive(Clone)]
struct Folder {
    endpoint: Endpoint,
    root: RemotePath,
}

impl Folder {
    fn of(connection: &Connection) -> Result<Self, CloudError> {
        let credential = connection.synology_credential().ok_or(CloudError::InvalidConnection)?;
        Ok(Self { endpoint: credential.endpoint.clone(), root: credential.root.clone() })
    }

    fn absolute(&self, path: &RemotePath) -> String {
        api::absolute(&self.root, path)
    }

    fn post(
        &self,
        api: &str,
        version: u8,
        method: &str,
        params: impl IntoIterator<Item = (&'static str, String)>,
    ) -> Result<Outgoing, CloudError> {
        let mut all = api::call(api, version, method);
        all.extend(params.into_iter().map(|(name, value)| (name.to_owned(), value)));
        Ok(Outgoing::authorized(api::post(&self.endpoint, &all)?))
    }

    fn info(&self, path: &RemotePath) -> Result<Outgoing, CloudError> {
        self.post(LIST, 2, "getinfo", [("path", api::json_list(&[&self.absolute(path)])), ("additional", ADDITIONAL.into())])
    }
}

/// The entry from a `getinfo` response; `None` when nothing is there.
fn info_result(response: &HttpResponse, path: &RemotePath) -> Result<Option<Entry>, CloudError> {
    let data = match Reply::of(response)? {
        Reply::Failed(NO_SUCH_FILE) => return Ok(None),
        reply => reply.data()?,
    };
    let item = data.pointer("/files/0").ok_or(CloudError::InvalidResponse("files"))?;
    match item.get("code").and_then(Value::as_i64) {
        Some(NO_SUCH_FILE) => Ok(None),
        Some(code) => Err(api::file_error(code)),
        None => api::entry(item, path.clone()).map(Some),
    }
}

/// Whether `path` is the device's top level or a shared folder on a connection without a root folder: File Station can
/// list these but cannot create, change or delete them.
fn is_top_level(connection: &Connection, path: &RemotePath) -> bool {
    connection.synology_credential().is_some_and(|credential| credential.root.is_root()) && path.segments().len() <= 1
}

fn forbidden<T: Send + 'static>() -> BoxOperation<T> {
    Box::new(Ready::err(CloudError::Forbidden))
}

fn steps<S: Steps + 'static>(connection: &Connection, config: &ClientConfig, make: impl FnOnce(Folder) -> S) -> BoxOperation<S::Output> {
    match Folder::of(connection) {
        Ok(folder) => op(make(folder), connection, config),
        Err(error) => Box::new(Ready::err(error)),
    }
}

// MARK: - Metadata

struct Stat {
    folder: Folder,
    path: RemotePath,
}

impl Steps for Stat {
    type Output = Option<Entry>;

    fn first(&mut self) -> Result<Outgoing, CloudError> {
        self.folder.info(&self.path)
    }

    fn next(&mut self, response: HttpResponse) -> Result<Next<Option<Entry>>, CloudError> {
        info_result(&response, &self.path).map(Next::Done)
    }
}

pub(crate) fn stat(connection: &Connection, config: &ClientConfig, path: RemotePath) -> BoxOperation<Option<Entry>> {
    // The device's top level has no File Station path; it is always there.
    if path.is_root() && is_top_level(connection, &path) {
        return Box::new(Ready::ok(Some(Entry { path, is_dir: true, size: None, modified_at: None, revision: None })));
    }
    steps(connection, config, |folder| Stat { folder, path })
}

/// Whether the root folder exists as a folder, for sign-in. Without a root folder, whether the shared folders can be
/// listed.
pub(crate) struct RootExists {
    folder: Folder,
}

impl RootExists {
    pub(crate) fn new(endpoint: &Endpoint, root: &RemotePath) -> Self {
        Self { folder: Folder { endpoint: endpoint.clone(), root: root.clone() } }
    }
}

impl Steps for RootExists {
    type Output = bool;

    fn first(&mut self) -> Result<Outgoing, CloudError> {
        if self.folder.root.is_root() {
            return self.folder.post(LIST, 2, "list_share", [("offset", "0".into()), ("limit", "1".into())]);
        }
        self.folder.info(&RemotePath::root())
    }

    fn next(&mut self, response: HttpResponse) -> Result<Next<bool>, CloudError> {
        if self.folder.root.is_root() {
            return Reply::of(&response)?.data().map(|_| Next::Done(true));
        }
        Ok(Next::Done(info_result(&response, &RemotePath::root())?.is_some_and(|entry| entry.is_dir)))
    }
}

// MARK: - Listing

struct List {
    folder: Folder,
    dir: RemotePath,
    /// The device's top level: the shared folders the user can see (`list_share`).
    shares: bool,
    entries: Vec<Entry>,
    max_entries: usize,
    /// Entries asked for so far.
    offset: usize,
}

impl List {
    fn page(&self) -> Result<Outgoing, CloudError> {
        if self.shares {
            return self.folder.post(
                LIST,
                2,
                "list_share",
                [
                    ("offset", self.offset.to_string()),
                    ("limit", PAGE.to_string()),
                    ("sort_by", "name".into()),
                    ("additional", r#"["time"]"#.into()),
                ],
            );
        }
        self.folder.post(
            LIST,
            2,
            "list",
            [
                ("folder_path", self.folder.absolute(&self.dir)),
                ("offset", self.offset.to_string()),
                ("limit", PAGE.to_string()),
                ("sort_by", "name".into()),
                ("additional", ADDITIONAL.into()),
            ],
        )
    }
}

impl Steps for List {
    type Output = Vec<Entry>;

    fn first(&mut self) -> Result<Outgoing, CloudError> {
        self.page()
    }

    fn next(&mut self, response: HttpResponse) -> Result<Next<Vec<Entry>>, CloudError> {
        let data = Reply::of(&response)?.data()?;
        let key = if self.shares { "shares" } else { "files" };
        let files = data.get(key).and_then(Value::as_array).ok_or(CloudError::InvalidResponse("files"))?;
        let total = data.get("total").and_then(Value::as_u64).ok_or(CloudError::InvalidResponse("total"))?;
        for item in files {
            let name = item.get("name").and_then(Value::as_str).ok_or(CloudError::InvalidResponse("name"))?;
            // Drop entries with names that are not a valid segment instead of joining them into a path.
            let Ok(path) = self.dir.join(name) else { continue };
            if self.entries.len() >= self.max_entries {
                return Err(CloudError::TooLarge);
            }
            self.entries.push(api::entry(item, path)?);
        }
        self.offset += files.len();
        if !files.is_empty() && (self.offset as u64) < total {
            return Ok(Next::Request(self.page()?));
        }
        let mut entries = std::mem::take(&mut self.entries);
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(Next::Done(entries))
    }
}

pub(crate) fn list(connection: &Connection, config: &ClientConfig, dir: RemotePath) -> BoxOperation<Vec<Entry>> {
    let max_entries = config.limits.max_entries;
    let shares = dir.is_root() && is_top_level(connection, &dir);
    steps(connection, config, |folder| List { folder, dir, shares, entries: Vec::new(), max_entries, offset: 0 })
}

// MARK: - Reading

enum ReadState {
    Info,
    Download(Entry),
    Verify(Entry, Vec<u8>),
}

struct Read {
    folder: Folder,
    path: RemotePath,
    attempts: u8,
    state: ReadState,
}

impl Read {
    fn download(&self) -> Result<Outgoing, CloudError> {
        let mut params = api::call(DOWNLOAD, 2, "download");
        params.extend([("path".into(), api::json_list(&[&self.folder.absolute(&self.path)])), ("mode".into(), "download".into())]);
        Ok(Outgoing::authorized(api::get(&self.folder.endpoint, &params)?))
    }
}

/// A download that failed answers with a JSON error envelope instead of the file. A file can look like one, so the
/// envelope only counts when the server labels it JSON or its length is not the file's.
fn download_error(response: &HttpResponse, entry: &Entry) -> Option<i64> {
    let labeled_json = response.header("Content-Type").is_some_and(|value| value.to_ascii_lowercase().contains("json"));
    let not_the_file = entry.size != Some(response.body.len() as u64);
    match Reply::of(response) {
        Ok(Reply::Failed(code)) if labeled_json || not_the_file => Some(code),
        _ => None,
    }
}

impl Steps for Read {
    type Output = Option<File>;

    fn first(&mut self) -> Result<Outgoing, CloudError> {
        self.attempts = 1;
        self.folder.info(&self.path)
    }

    fn next(&mut self, response: HttpResponse) -> Result<Next<Option<File>>, CloudError> {
        match std::mem::replace(&mut self.state, ReadState::Info) {
            ReadState::Info => {
                let Some(entry) = info_result(&response, &self.path)? else { return Ok(Next::Done(None)) };
                if entry.is_dir {
                    return Err(CloudError::InvalidResponse("expected a file"));
                }
                // Without either, nothing could tell the download apart from a version written meanwhile.
                if entry.size.is_none() && entry.modified_at.is_none() {
                    return Err(CloudError::InvalidResponse("file metadata"));
                }
                self.state = ReadState::Download(entry);
                Ok(Next::Request(self.download()?))
            }
            ReadState::Download(entry) => match response.status {
                404 => Ok(Next::Done(None)),
                200 => match download_error(&response, &entry) {
                    Some(NO_SUCH_FILE) => Ok(Next::Done(None)),
                    Some(code) => Err(api::file_error(code)),
                    None => {
                        self.state = ReadState::Verify(entry, response.body);
                        Ok(Next::Request(self.folder.info(&self.path)?))
                    }
                },
                _ => Err(status_error(&response)),
            },
            ReadState::Verify(entry, data) => {
                let Some(current) = info_result(&response, &self.path)? else { return Ok(Next::Done(None)) };
                // Size and modification time (whole seconds) are all File Station offers: a rewrite of the same size
                // within the same second goes unnoticed.
                let unchanged = current == entry && entry.size.is_none_or(|size| size == data.len() as u64);
                if unchanged {
                    return Ok(Next::Done(Some(File { data, entry })));
                }
                if current.is_dir || self.attempts >= READ_ATTEMPTS {
                    return Err(CloudError::PreconditionFailed);
                }
                if current.size.is_none() && current.modified_at.is_none() {
                    return Err(CloudError::InvalidResponse("file metadata"));
                }
                // The lookup just made describes the newest version: download that one.
                self.attempts += 1;
                self.state = ReadState::Download(current);
                Ok(Next::Request(self.download()?))
            }
        }
    }
}

pub(crate) fn read(connection: &Connection, config: &ClientConfig, path: RemotePath) -> BoxOperation<Option<File>> {
    if path.is_root() {
        return Box::new(Ready::err(CloudError::InvalidPath));
    }
    steps(connection, config, |folder| Read { folder, path, attempts: 0, state: ReadState::Info })
}

// MARK: - Writing

/// Whether this provider can enforce the condition: File Station has no version to match.
pub(crate) fn supports_write_precondition(precondition: &Precondition) -> bool {
    !matches!(precondition, Precondition::Matches(_))
}

struct Write {
    folder: Folder,
    path: RemotePath,
    data: Zeroizing<Vec<u8>>,
    precondition: Precondition,
    uploaded: bool,
}

impl Write {
    fn upload(&mut self) -> Result<Outgoing, CloudError> {
        let name = self.path.name().ok_or(CloudError::InvalidPath)?;
        let parent = self.path.parent().unwrap_or_default();
        let mut fields = vec![("path", self.folder.absolute(&parent)), ("create_parents", "false".to_owned())];
        // Without `overwrite`, DSM refuses to replace an existing file; `false` would skip it silently instead.
        if matches!(self.precondition, Precondition::None) {
            fields.push(("overwrite", "true".to_owned()));
        }
        let (content_type, body) = multipart(&fields, name, &self.data)?;
        let mut request = api::get(&self.folder.endpoint, &api::call(UPLOAD, 2, "upload"))?;
        request.method = Method::Post;
        request.headers.extend([("Content-Type".to_owned(), content_type), ("Accept".to_owned(), "application/json".to_owned())]);
        request.body = body;
        Ok(Outgoing::authorized(request))
    }

    fn upload_error(&self, code: i64) -> CloudError {
        match (api::file_error(code), &self.precondition) {
            // Something is at the path: for a create, that is the condition failing, whatever it is.
            (CloudError::Forbidden, Precondition::Absent) if code == 1004 => CloudError::PreconditionFailed,
            (error, _) => error,
        }
    }
}

/// A `multipart/form-data` body: the fields, then the file, which File Station needs last. The boundary is derived from
/// the contents (the crate has no randomness), so it cannot occur in them by accident.
fn multipart(fields: &[(&str, String)], name: &str, data: &[u8]) -> Result<(String, Vec<u8>), CloudError> {
    use sha2::{Digest, Sha256};
    // Header values cannot carry quotes or line breaks unescaped; DSM takes the name as raw UTF-8.
    if name.contains(['"', '\r', '\n']) {
        return Err(CloudError::InvalidPath);
    }
    let digest = Sha256::digest(data);
    let boundary = format!("cloudset-{}", digest.iter().take(16).map(|byte| format!("{byte:02x}")).collect::<String>());
    let mut body = Vec::with_capacity(data.len() + 512);
    for (field, value) in fields {
        body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"\r\n\r\n{value}\r\n").as_bytes());
    }
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(data);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Ok((format!("multipart/form-data; boundary={boundary}"), body))
}

impl Steps for Write {
    type Output = Entry;

    fn first(&mut self) -> Result<Outgoing, CloudError> {
        self.upload()
    }

    fn next(&mut self, response: HttpResponse) -> Result<Next<Entry>, CloudError> {
        if !self.uploaded {
            match Reply::of(&response)? {
                Reply::Data(_) => {}
                Reply::Failed(code) => return Err(self.upload_error(code)),
            }
            self.uploaded = true;
            return Ok(Next::Request(self.folder.info(&self.path)?));
        }
        // The upload went through; the file is the one written unless the lookup says otherwise.
        match info_result(&response, &self.path) {
            Ok(Some(entry)) if !entry.is_dir && entry.size == Some(self.data.len() as u64) => Ok(Next::Done(entry)),
            _ => Err(CloudError::CommitUnconfirmed),
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
    if !supports_write_precondition(&precondition) {
        return Box::new(Ready::err(CloudError::UnsupportedPrecondition));
    }
    if is_top_level(connection, &path) {
        return forbidden();
    }
    let data = Zeroizing::new(data);
    steps(connection, config, |folder| Write { folder, path, data, precondition, uploaded: false })
}

// MARK: - Directories and deletion

struct CreateDir {
    folder: Folder,
    path: RemotePath,
    /// The error code of a failed create, while the path is looked up.
    failed: Option<i64>,
}

impl Steps for CreateDir {
    type Output = ();

    fn first(&mut self) -> Result<Outgoing, CloudError> {
        let name = self.path.name().ok_or(CloudError::InvalidPath)?;
        let parent = self.folder.absolute(&self.path.parent().unwrap_or_default());
        self.folder.post(
            CREATE_FOLDER,
            2,
            "create",
            [("folder_path", api::json_list(&[&parent])), ("name", api::json_list(&[name])), ("force_parent", "false".into())],
        )
    }

    fn next(&mut self, response: HttpResponse) -> Result<Next<()>, CloudError> {
        let Some(code) = self.failed else {
            return match Reply::of(&response)? {
                Reply::Data(_) => Ok(Next::Done(())),
                // An existing folder is success, an existing file is in the way: one lookup tells which.
                Reply::Failed(code) => {
                    self.failed = Some(code);
                    Ok(Next::Request(self.folder.info(&self.path)?))
                }
            };
        };
        match info_result(&response, &self.path)? {
            Some(entry) if entry.is_dir => Ok(Next::Done(())),
            Some(_) => Err(CloudError::Forbidden),
            None => Err(api::file_error(code)),
        }
    }
}

pub(crate) fn create_dir(connection: &Connection, config: &ClientConfig, path: RemotePath) -> BoxOperation<()> {
    if path.is_root() {
        return Box::new(Ready::ok(()));
    }
    if is_top_level(connection, &path) {
        return forbidden();
    }
    steps(connection, config, |folder| CreateDir { folder, path, failed: None })
}

struct Delete {
    folder: Folder,
    path: RemotePath,
}

impl Steps for Delete {
    type Output = ();

    fn first(&mut self) -> Result<Outgoing, CloudError> {
        // `delete` is the blocking method: it answers once everything is gone.
        self.folder.post(
            DELETE,
            2,
            "delete",
            [("path", api::json_list(&[&self.folder.absolute(&self.path)])), ("recursive", "true".into())],
        )
    }

    fn next(&mut self, response: HttpResponse) -> Result<Next<()>, CloudError> {
        match Reply::of(&response)? {
            Reply::Data(_) | Reply::Failed(NO_SUCH_FILE) => Ok(Next::Done(())),
            Reply::Failed(code) => Err(api::file_error(code)),
        }
    }
}

pub(crate) fn delete(connection: &Connection, config: &ClientConfig, path: RemotePath) -> BoxOperation<()> {
    if is_top_level(connection, &path) {
        return forbidden();
    }
    steps(connection, config, |folder| Delete { folder, path })
}

// MARK: - Moving

enum RenameState {
    /// Looking up the source, which must exist.
    Source,
    /// Looking up the destination, which must not.
    Destination,
    /// Looking up the destination's parent folder, which must exist.
    Parent,
    /// A move between folders keeps the name: looking up `<destination folder>/<source name>`, which must be free.
    Intermediate,
    /// The rename within one folder.
    Renaming { last: bool },
    /// The move task is starting.
    Starting,
    /// The move task is running.
    Polling { task: String, polls: u16 },
    /// Looking up the result.
    Confirming,
}

struct Rename {
    folder: Folder,
    from: RemotePath,
    to: RemotePath,
    /// Whether the source is a folder, whose failed move may have moved part of it.
    from_is_dir: bool,
    state: RenameState,
}

impl Rename {
    fn to_parent(&self) -> RemotePath {
        self.to.parent().unwrap_or_default()
    }

    /// The path the item has after a move between folders, before it gets its new name.
    fn moved(&self) -> Result<RemotePath, CloudError> {
        self.to_parent().join(self.from.name().ok_or(CloudError::InvalidPath)?)
    }

    fn same_name(&self) -> bool {
        self.from.name() == self.to.name()
    }

    fn rename(&mut self, path: &RemotePath, last: bool) -> Result<Outgoing, CloudError> {
        self.state = RenameState::Renaming { last };
        let name = self.to.name().ok_or(CloudError::InvalidPath)?;
        self.folder.post(RENAME, 2, "rename", [("path", api::json_list(&[&self.folder.absolute(path)])), ("name", api::json_list(&[name]))])
    }

    fn start_move(&mut self) -> Result<Outgoing, CloudError> {
        self.state = RenameState::Starting;
        // No `overwrite`: DSM then refuses an existing item (1003) instead of replacing or skipping it.
        self.folder.post(
            COPY_MOVE,
            3,
            "start",
            [
                ("path", api::json_list(&[&self.folder.absolute(&self.from)])),
                ("dest_folder_path", self.folder.absolute(&self.to_parent())),
                ("remove_src", "true".into()),
            ],
        )
    }

    fn poll(&mut self, task: String, polls: u16) -> Result<Outgoing, CloudError> {
        let outgoing = self.folder.post(COPY_MOVE, 3, "status", [("taskid", task.clone())]);
        self.state = RenameState::Polling { task, polls };
        outgoing
    }

    fn confirm(&mut self) -> Result<Outgoing, CloudError> {
        self.state = RenameState::Confirming;
        self.folder.info(&self.to)
    }

    /// After the checks: a rename within the folder, or a move (that may need a rename afterwards).
    fn change(&mut self) -> Result<Outgoing, CloudError> {
        if self.from.parent() == self.to.parent() {
            let from = self.from.clone();
            return self.rename(&from, true);
        }
        if self.same_name() {
            return self.start_move();
        }
        self.state = RenameState::Intermediate;
        self.folder.info(&self.moved()?)
    }
}

impl Steps for Rename {
    type Output = Entry;

    fn first(&mut self) -> Result<Outgoing, CloudError> {
        self.folder.info(&self.from)
    }

    fn next(&mut self, response: HttpResponse) -> Result<Next<Entry>, CloudError> {
        let outgoing = match std::mem::replace(&mut self.state, RenameState::Source) {
            RenameState::Source => {
                self.from_is_dir = info_result(&response, &self.from)?.ok_or(CloudError::NotFound)?.is_dir;
                self.state = RenameState::Destination;
                self.folder.info(&self.to)?
            }
            RenameState::Destination => {
                if info_result(&response, &self.to)?.is_some() {
                    return Err(CloudError::PreconditionFailed);
                }
                if self.to_parent().is_root() {
                    self.change()?
                } else {
                    self.state = RenameState::Parent;
                    self.folder.info(&self.to_parent())?
                }
            }
            RenameState::Parent => match info_result(&response, &self.to_parent())? {
                Some(parent) if parent.is_dir => self.change()?,
                _ => return Err(CloudError::NotFound),
            },
            RenameState::Intermediate => {
                if info_result(&response, &self.moved()?)?.is_some() {
                    return Err(CloudError::PreconditionFailed);
                }
                self.start_move()?
            }
            RenameState::Renaming { last } => match Reply::of(&response)? {
                Reply::Data(_) => self.confirm()?,
                // The move already happened: the item now sits at the intermediate path.
                Reply::Failed(_) if !last => return Err(CloudError::CommitUnconfirmed),
                Reply::Failed(code) => return Err(api::file_error(code)),
            },
            RenameState::Starting => {
                let data = Reply::of(&response)?.data()?;
                let task = data.get("taskid").and_then(Value::as_str).ok_or(CloudError::InvalidResponse("taskid"))?;
                self.poll(task.to_owned(), 1)?
            }
            RenameState::Polling { task, polls } => {
                let finished = match Reply::of(&response)? {
                    Reply::Data(data) => data.get("finished").and_then(Value::as_bool) == Some(true),
                    // A taken destination stops a file's move before anything happens. Any other failure (an unknown task
                    // after the session was renewed, a copy across volumes that failed halfway, a folder moved in part)
                    // leaves the outcome open.
                    Reply::Failed(code) if !self.from_is_dir && api::file_error(code) == CloudError::PreconditionFailed => {
                        return Err(CloudError::PreconditionFailed);
                    }
                    Reply::Failed(_) => return Err(CloudError::CommitUnconfirmed),
                };
                match (finished, self.same_name()) {
                    (true, true) => self.confirm()?,
                    (true, false) => {
                        let moved = self.moved()?;
                        self.rename(&moved, false)?
                    }
                    (false, _) if polls >= MAX_POLLS => return Err(CloudError::CommitUnconfirmed),
                    (false, _) => self.poll(task, polls + 1)?,
                }
            }
            RenameState::Confirming => {
                return match info_result(&response, &self.to) {
                    Ok(Some(entry)) => Ok(Next::Done(entry)),
                    _ => Err(CloudError::CommitUnconfirmed),
                };
            }
        };
        Ok(Next::Request(outgoing))
    }
}

pub(crate) fn rename(connection: &Connection, config: &ClientConfig, from: RemotePath, to: RemotePath) -> BoxOperation<Entry> {
    if is_top_level(connection, &from) || is_top_level(connection, &to) {
        return forbidden();
    }
    steps(connection, config, |folder| Rename { folder, from, to, from_is_dir: false, state: RenameState::Source })
}

// MARK: - Sign-out

/// Ends the DSM session. A session that already expired counts as ended. The trusted-device token stays valid until the
/// user removes the device in DSM (Personal > Security > Trusted devices).
struct Logout {
    endpoint: Endpoint,
}

impl Steps for Logout {
    type Output = ();

    fn first(&mut self) -> Result<Outgoing, CloudError> {
        Ok(Outgoing::authorized(api::logout_request(&self.endpoint)?).without_refresh())
    }

    fn next(&mut self, response: HttpResponse) -> Result<Next<()>, CloudError> {
        match Reply::of(&response)? {
            Reply::Data(_) => Ok(Next::Done(())),
            // A session DSM no longer accepts is already over.
            Reply::Failed(code) if api::SESSION_ERRORS.contains(&code) => Ok(Next::Done(())),
            Reply::Failed(code) => Err(api::file_error(code)),
        }
    }
}

/// Ends the session and hands back the connection without it. The password stays: a later operation signs in again.
pub(crate) fn revoke(connection: &Connection, config: &ClientConfig) -> BoxOperation<()> {
    let Some(credential) = connection.synology_credential() else { return Box::new(Ready::err(CloudError::InvalidConnection)) };
    if credential.session.is_none() {
        return Box::new(Ready::ok(()));
    }
    let mut signed_out = credential.clone();
    signed_out.session = None;
    let logout = op(Logout { endpoint: credential.endpoint.clone() }, connection, config);
    Box::new(SignedOut { logout, connection: Some(Connection::synology(signed_out)) })
}

/// The logout, then the connection without its session.
struct SignedOut {
    logout: BoxOperation<()>,
    connection: Option<Connection>,
}

impl Operation for SignedOut {
    type Output = ();

    fn advance(&mut self, response: Option<HttpResponse>) -> Result<Step<()>, CloudError> {
        match self.logout.advance(response)? {
            Step::Done(_) => {
                let connection = self.connection.take().ok_or(CloudError::OutOfOrder)?;
                Ok(Step::Done(Done::new(()).with_connection(Some(connection))))
            }
            step => Ok(step),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multipart_puts_the_file_last_and_refuses_quotes() {
        let (content_type, body) = multipart(&[("path", "/home".into())], "备份.txt", b"data").unwrap();
        let boundary = content_type.strip_prefix("multipart/form-data; boundary=").unwrap();
        let text = String::from_utf8(body).unwrap();
        assert!(text.starts_with(&format!("--{boundary}\r\nContent-Disposition: form-data; name=\"path\"\r\n\r\n/home\r\n")));
        assert!(
            text.ends_with(&format!("filename=\"备份.txt\"\r\nContent-Type: application/octet-stream\r\n\r\ndata\r\n--{boundary}--\r\n"))
        );
        assert_eq!(multipart(&[], "a\"b", b"").err(), Some(CloudError::InvalidPath));
    }

    #[test]
    fn download_errors_need_a_label_or_a_size_mismatch() {
        let envelope = br#"{"success":false,"error":{"code":408}}"#.to_vec();
        let entry =
            |size: usize| Entry { path: RemotePath::root(), is_dir: false, size: Some(size as u64), modified_at: None, revision: None };
        let plain = HttpResponse::new(200).with_body(envelope.clone());
        assert_eq!(download_error(&plain, &entry(3)), Some(408));
        assert_eq!(download_error(&plain, &entry(envelope.len())), None, "a file that happens to look like an error");
        let labeled = plain.clone().with_header("Content-Type", "application/json; charset=\"UTF-8\"");
        assert_eq!(download_error(&labeled, &entry(envelope.len())), Some(408));
        assert_eq!(download_error(&HttpResponse::new(200).with_body(b"data".to_vec()), &entry(4)), None);
    }
}
