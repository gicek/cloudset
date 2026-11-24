//! In-memory Synology for tests (`testing` feature): QuickConnect control hosts for both regions (`quickconnect.to` and
//! `quickconnect.cn`) with regional redirects and relay tunnels, DSM's `pingpong.cgi`, and the File Station API the
//! crate uses, with the request and response shapes of Synology's API guides.
//!
//! The device is registered in [`MemorySynology::region`]. A control host of the other region answers with `sites`
//! pointing at the device's region, as the real service does. DSM answers on the addresses in
//! [`MemorySynology::reachable`] and, once a tunnel was requested, on the relay; any other address answers 502, which
//! stands in for a connection that fails.

use std::collections::{BTreeMap, HashMap};

use md5::{Digest, Md5};
use serde_json::{Value, json};
use url::Url;

use crate::http::{HttpRequest, HttpResponse, Method};
use crate::synology::quickconnect::Region;

/// The device's QuickConnect ID.
pub const QUICKCONNECT_ID: &str = "cloudset-nas";
/// The device's server ID, whose MD5 `pingpong.cgi` answers with.
pub const SERVER_ID: &str = "0123456789";
/// The shared folder that exists from the start.
pub const SHARE: &str = "home";
/// The device's address on its local network (a SmartDNS name).
pub const LAN_ADDRESS: &str = "https://192-168-1-20.cloudset-nas.direct.quickconnect.to:5001/";
/// The device's public address (SmartDNS name with the forwarded port).
pub const PUBLIC_ADDRESS: &str = "https://cloudset-nas.direct.quickconnect.to:15001/";

/// The relay region the device's tunnels open in.
#[must_use]
pub fn relay_region(region: Region) -> &'static str {
    match region {
        Region::ChinaMainland => "cn4",
        _ => "de3",
    }
}

/// The relay address of the device in `region`.
#[must_use]
pub fn relay_address(region: Region) -> String {
    format!("https://{QUICKCONNECT_ID}.{}.{}/", relay_region(region), domain(region))
}

fn domain(region: Region) -> &'static str {
    match region {
        Region::ChinaMainland => "quickconnect.cn",
        _ => "quickconnect.to",
    }
}

/// The regional control host that knows the device.
fn regional_host(region: Region) -> &'static str {
    match region {
        Region::ChinaMainland => "cnc.quickconnect.cn",
        _ => "usc.quickconnect.to",
    }
}

/// A move task: polls left until it finishes, and the error it finishes with.
#[derive(Debug)]
struct Task {
    remaining: u16,
    error: Option<(i64, String)>,
}

#[derive(Clone, Debug)]
enum Node {
    Dir,
    File { data: Vec<u8>, mtime: u64 },
}

/// A request's parameters (query, form or multipart fields) and its uploaded file.
struct Params {
    fields: HashMap<String, String>,
    file: Option<(String, Vec<u8>)>,
}

impl Params {
    fn get(&self, name: &str) -> &str {
        self.fields.get(name).map_or("", String::as_str)
    }

    /// A path list: a JSON array, or a single plain path.
    fn list(&self, name: &str) -> Vec<String> {
        let value = self.get(name);
        serde_json::from_str::<Vec<String>>(value).unwrap_or_else(|_| vec![value.to_owned()])
    }
}

fn reply(data: Value) -> HttpResponse {
    json_response(&json!({ "success": true, "data": data }))
}

fn failure(code: i64) -> HttpResponse {
    json_response(&json!({ "success": false, "error": { "code": code } }))
}

/// A failure with a per-path code, as file operations report them.
fn path_failure(code: i64, path_code: i64, path: &str) -> HttpResponse {
    json_response(&json!({ "success": false, "error": { "code": code, "errors": [{ "code": path_code, "path": path }] } }))
}

fn json_response(body: &Value) -> HttpResponse {
    HttpResponse::new(200).with_header("Content-Type", "application/json; charset=\"UTF-8\"").with_body(body.to_string())
}

fn split(path: &str) -> Vec<String> {
    path.split('/').filter(|part| !part.is_empty()).map(str::to_owned).collect()
}

/// In-memory Synology device with its QuickConnect registration.
#[derive(Debug)]
#[non_exhaustive]
pub struct MemorySynology {
    /// Where the device is registered.
    pub region: Region,
    /// DSM addresses that answer (as given to `Endpoint::parse`); the local network address by default.
    pub reachable: Vec<String>,
    /// DSM addresses that answer `pingpong.cgi` as another Synology device.
    pub other_device: Vec<String>,
    /// Control hosts that answer 503.
    pub failing_hosts: Vec<String>,
    /// Whether a relay tunnel was requested.
    pub tunnel_open: bool,
    /// The DSM account.
    pub username: String,
    /// Its password.
    pub password: String,
    /// The one-time code two-step verification expects; `None` when the account does not use it.
    pub otp_code: Option<String>,
    /// Status polls a move takes before it finishes.
    pub move_polls: u16,
    /// Before each of the next N downloads, "another device" modifies the target file first.
    pub modify_before_download: u8,
    /// The next download finds its session expired.
    pub expire_before_download: bool,
    /// Uploads report success but store nothing.
    pub lose_uploads: bool,
    /// `Rename` calls fail with File Station's generic rename error.
    pub fail_renames: bool,
    /// Every session is refused right after sign-in, as when another client keeps replacing it.
    pub refuse_sessions: bool,
    /// Moves find their destination taken by the time the task runs, as when another device got there first.
    pub race_moves: bool,
    /// The session expires during the next move's status poll, and DSM forgets the session's tasks with it.
    pub expire_during_move: bool,
    /// Every request received, in order.
    pub requests: Vec<HttpRequest>,
    /// Session IDs and the address they were created on: DSM refuses a session from another client IP (150).
    sessions: Vec<(String, String)>,
    device_tokens: Vec<String>,
    tasks: HashMap<String, Task>,
    nodes: BTreeMap<Vec<String>, Node>,
    issued: u32,
    clock: u64,
}

impl MemorySynology {
    /// A device registered in `region` with the shared folder [`SHARE`], user `alice` and password `secret`.
    #[must_use]
    pub fn new(region: Region) -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(vec![SHARE.to_owned()], Node::Dir);
        Self {
            region,
            reachable: vec![LAN_ADDRESS.to_owned()],
            other_device: Vec::new(),
            failing_hosts: Vec::new(),
            tunnel_open: false,
            username: "alice".into(),
            password: "secret".into(),
            otp_code: None,
            move_polls: 1,
            modify_before_download: 0,
            expire_before_download: false,
            lose_uploads: false,
            fail_renames: false,
            refuse_sessions: false,
            race_moves: false,
            expire_during_move: false,
            requests: Vec::new(),
            sessions: Vec::new(),
            device_tokens: Vec::new(),
            tasks: HashMap::new(),
            nodes,
            issued: 0,
            clock: 1_800_000_000,
        }
    }

    /// Ends every session, as DSM does after its idle timeout.
    pub fn expire_sessions(&mut self) {
        self.sessions.clear();
    }

    /// The client's IP changes (a phone switching networks): existing sessions are refused with 150 from now on.
    pub fn change_client_address(&mut self) {
        for (_, created_on) in &mut self.sessions {
            *created_on = "another client address".into();
        }
    }

    /// Writes a file directly as "another device"; `path` is absolute on the device (`home/a.txt`).
    pub fn put_external(&mut self, path: &str, data: &[u8]) {
        self.clock += 1;
        self.nodes.insert(split(path), Node::File { data: data.to_vec(), mtime: self.clock });
    }

    /// Creates a folder directly as "another device".
    pub fn mkdir_external(&mut self, path: &str) {
        self.nodes.insert(split(path), Node::Dir);
    }

    /// The contents of the file at `path`, if there is one.
    #[must_use]
    pub fn data(&self, path: &str) -> Option<Vec<u8>> {
        match self.nodes.get(&split(path)) {
            Some(Node::File { data, .. }) => Some(data.clone()),
            _ => None,
        }
    }

    /// Whether a folder exists at `path`.
    #[must_use]
    pub fn is_dir(&self, path: &str) -> bool {
        matches!(self.nodes.get(&split(path)), Some(Node::Dir))
    }

    /// Handles one request; every request is recorded in order in `requests`.
    pub fn handle(&mut self, request: HttpRequest) -> HttpResponse {
        self.requests.push(request.clone());
        let url = Url::parse(&request.url).expect("absolute url");
        let host = url.host_str().unwrap_or_default().to_owned();
        if url.path() == "/Serv.php" {
            return self.control(&host, &request);
        }
        let base = match url.port() {
            Some(port) => format!("{}://{host}:{port}/", url.scheme()),
            None => format!("{}://{host}/", url.scheme()),
        };
        if self.other_device.contains(&base) && url.path() == "/webman/pingpong.cgi" {
            return json_response(&json!({ "success": true, "ezid": md5_hex(b"another device") }));
        }
        let relay = self.tunnel_open && base == relay_address(self.region);
        if !relay && !self.reachable.contains(&base) {
            return HttpResponse::new(502);
        }
        match url.path() {
            "/webman/pingpong.cgi" => json_response(&json!({ "success": true, "boot_done": true, "ezid": md5_hex(SERVER_ID.as_bytes()) })),
            "/webapi/entry.cgi" => self.api(&url, &base, &request),
            _ => HttpResponse::new(404),
        }
    }

    // MARK: - QuickConnect

    fn control(&mut self, host: &str, request: &HttpRequest) -> HttpResponse {
        if self.failing_hosts.iter().any(|failing| failing == host) {
            return HttpResponse::new(503);
        }
        assert_eq!(request.method, Method::Post);
        let items: Vec<Value> = serde_json::from_slice(&request.body).expect("a JSON array");
        assert!(request.body.len() <= 350, "Serv.php answers 413 to larger bodies");
        let knows_device = host == self.region.control_host() || host == regional_host(self.region);
        let answers: Vec<Value> = items
            .iter()
            .map(|item| {
                let command = item["command"].as_str().unwrap_or_default();
                if item["serverID"] != QUICKCONNECT_ID {
                    return json!({ "command": command, "errno": 4, "suberrno": 2, "version": 1 });
                }
                if !knows_device {
                    return json!({ "command": command, "errno": 4, "suberrno": 1, "sites": [regional_host(self.region)], "version": 1 });
                }
                if command == "request_tunnel" {
                    self.tunnel_open = true;
                }
                self.server_info(command)
            })
            .collect();
        json_response(&Value::Array(answers))
    }

    fn server_info(&self, command: &str) -> Value {
        let smart_domain = format!("{QUICKCONNECT_ID}.direct.quickconnect.to");
        let mut service = json!({ "port": 5001, "ext_port": 15001, "pingpong": "DISCONNECTED", "pingpong_desc": [] });
        if command == "request_tunnel" {
            service["relay_ip"] = json!("198.51.100.4");
            service["relay_port"] = json!(30_000);
            service["relay_dn"] = json!(format!("synr-{}.{}", relay_region(self.region), domain(self.region)));
        }
        json!({
            "command": command,
            "errno": 0,
            "version": 1,
            "env": { "control_host": regional_host(self.region), "relay_region": relay_region(self.region) },
            "server": {
                "serverID": SERVER_ID,
                "ddns": "NULL",
                "fqdn": "NULL",
                "ds_state": "CONNECTED",
                "external": { "ip": "203.0.113.7", "ipv6": "::" },
                "interface": [{ "ip": "192.168.1.20", "mask": "255.255.255.0", "name": "eth0", "ipv6": [] }],
                "gateway": "192.168.1.1",
            },
            "service": service,
            "smartdns": { "host": smart_domain, "lan": [format!("192-168-1-20.{smart_domain}")] },
        })
    }

    // MARK: - File Station

    fn params(url: &Url, request: &HttpRequest) -> Params {
        let mut fields: HashMap<String, String> = url.query_pairs().into_owned().collect();
        let mut file = None;
        let content_type = request.header("Content-Type").unwrap_or_default().to_owned();
        if content_type.starts_with("application/x-www-form-urlencoded") {
            fields.extend(url::form_urlencoded::parse(&request.body).into_owned());
        } else if let Some(boundary) = content_type.strip_prefix("multipart/form-data; boundary=") {
            for (name, filename, content) in multipart_parts(&request.body, boundary) {
                match filename {
                    Some(filename) => file = Some((filename, content)),
                    None => {
                        assert!(file.is_none(), "File Station needs the file last");
                        fields.insert(name, String::from_utf8(content).expect("utf-8 field"));
                    }
                }
            }
        }
        Params { fields, file }
    }

    fn api(&mut self, url: &Url, base: &str, request: &HttpRequest) -> HttpResponse {
        let params = Self::params(url, request);
        let api = params.get("api").to_owned();
        let method = params.get("method").to_owned();
        if api == "SYNO.API.Auth" {
            return match method.as_str() {
                "login" => self.login(&params, base),
                "logout" => {
                    self.sessions.retain(|(session, _)| session != params.get("_sid"));
                    reply(Value::Null)
                }
                _ => failure(103),
            };
        }
        match self.sessions.iter().find(|(session, _)| session == params.get("_sid")) {
            None => return failure(119),
            Some((_, created_on)) if created_on != base => return failure(150),
            Some(_) if self.refuse_sessions => return failure(107),
            Some(_) => {}
        }
        match (api.as_str(), method.as_str()) {
            ("SYNO.FileStation.List", "getinfo") => self.getinfo(&params),
            ("SYNO.FileStation.List", "list") => self.list(&params),
            ("SYNO.FileStation.Download", "download") => self.download(&params),
            ("SYNO.FileStation.Upload", "upload") => self.upload(&params),
            ("SYNO.FileStation.CreateFolder", "create") => self.create_folder(&params),
            ("SYNO.FileStation.Delete", "delete") => self.delete(&params),
            ("SYNO.FileStation.Rename", "rename") => self.rename(&params),
            ("SYNO.FileStation.CopyMove", "start") => self.start_move(&params),
            ("SYNO.FileStation.CopyMove", "status") => self.move_status(&params),
            _ => failure(102),
        }
    }

    fn login(&mut self, params: &Params, base: &str) -> HttpResponse {
        if params.get("account") != self.username || params.get("passwd") != self.password {
            return failure(400);
        }
        let mut data = json!({});
        if let Some(expected) = &self.otp_code {
            let trusted = self.device_tokens.iter().any(|token| token == params.get("device_id"));
            if !trusted {
                match params.fields.get("otp_code") {
                    None => return failure(403),
                    Some(code) if code != expected => return failure(404),
                    Some(_) => {}
                }
                if params.get("enable_device_token") == "yes" {
                    self.issued += 1;
                    let token = format!("did-{}", self.issued);
                    self.device_tokens.push(token.clone());
                    data["did"] = json!(token);
                }
            }
        }
        self.issued += 1;
        let session = format!("sid-{}", self.issued);
        self.sessions.push((session.clone(), base.to_owned()));
        data["sid"] = json!(session);
        reply(data)
    }

    fn info(&self, key: &[String]) -> Option<Value> {
        let node = self.nodes.get(key)?;
        let path = format!("/{}", key.join("/"));
        let name = key.last().cloned().unwrap_or_default();
        Some(match node {
            Node::Dir => {
                json!({ "path": path, "name": name, "isdir": true, "additional": { "size": 4096, "time": { "mtime": 1_700_000_000 } } })
            }
            Node::File { data, mtime } => {
                json!({ "path": path, "name": name, "isdir": false, "additional": { "size": data.len(), "time": { "mtime": mtime } } })
            }
        })
    }

    fn getinfo(&self, params: &Params) -> HttpResponse {
        let files: Vec<Value> = params
            .list("path")
            .iter()
            .map(|path| self.info(&split(path)).unwrap_or_else(|| json!({ "code": 408, "path": path })))
            .collect();
        reply(json!({ "files": files }))
    }

    fn list(&self, params: &Params) -> HttpResponse {
        let key = split(params.get("folder_path"));
        if !matches!(self.nodes.get(&key), Some(Node::Dir)) {
            return failure(408);
        }
        let children: Vec<Value> = self
            .nodes
            .keys()
            .filter(|child| child.len() == key.len() + 1 && child.starts_with(&key))
            .filter_map(|child| self.info(child))
            .collect();
        let offset: usize = params.get("offset").parse().unwrap_or(0);
        let limit: usize = params.get("limit").parse().unwrap_or(usize::MAX);
        let page: Vec<Value> = children.iter().skip(offset).take(limit).cloned().collect();
        reply(json!({ "total": children.len(), "offset": offset, "files": page }))
    }

    fn download(&mut self, params: &Params) -> HttpResponse {
        let path = params.list("path").pop().unwrap_or_default();
        if std::mem::take(&mut self.expire_before_download) {
            self.expire_sessions();
            return failure(119);
        }
        if self.modify_before_download > 0 && self.data(&path).is_some() {
            self.modify_before_download -= 1;
            let data = [self.data(&path).unwrap_or_default(), b"+".to_vec()].concat();
            self.put_external(&path, &data);
        }
        match self.nodes.get(&split(&path)) {
            Some(Node::File { data, .. }) => {
                HttpResponse::new(200).with_header("Content-Type", "application/octet-stream").with_body(data.clone())
            }
            Some(Node::Dir) => failure(400),
            None => failure(408),
        }
    }

    fn upload(&mut self, params: &Params) -> HttpResponse {
        let (name, data) = params.file.clone().expect("a file part");
        let parent = split(params.get("path"));
        assert_eq!(params.get("create_parents"), "false");
        if !matches!(self.nodes.get(&parent), Some(Node::Dir)) {
            return failure(408);
        }
        let mut key = parent;
        key.push(name);
        match (self.nodes.get(&key), params.fields.get("overwrite").map(String::as_str)) {
            (Some(Node::Dir), _) => return failure(1004),
            (Some(_), None) => return failure(1805),
            (Some(_), Some("false")) => return reply(json!({ "blSkip": true })),
            _ => {}
        }
        if !self.lose_uploads {
            self.clock += 1;
            self.nodes.insert(key, Node::File { data, mtime: self.clock });
        }
        reply(json!({ "blSkip": false, "progress": 100 }))
    }

    fn create_folder(&mut self, params: &Params) -> HttpResponse {
        let parent = params.list("folder_path").pop().unwrap_or_default();
        let name = params.list("name").pop().unwrap_or_default();
        let mut key = split(&parent);
        if !matches!(self.nodes.get(&key), Some(Node::Dir)) {
            return path_failure(1100, 408, &parent);
        }
        key.push(name);
        if self.nodes.contains_key(&key) {
            return path_failure(1100, 414, &format!("/{}", key.join("/")));
        }
        self.nodes.insert(key, Node::Dir);
        reply(json!({ "folders": [] }))
    }

    fn delete(&mut self, params: &Params) -> HttpResponse {
        for path in params.list("path") {
            let key = split(&path);
            if !self.nodes.contains_key(&key) {
                return path_failure(900, 408, &path);
            }
            self.nodes.retain(|existing, _| !existing.starts_with(&key));
        }
        reply(Value::Null)
    }

    fn move_tree(&mut self, from: &[String], to: &[String]) {
        let moved: Vec<(Vec<String>, Node)> =
            self.nodes.iter().filter(|(key, _)| key.starts_with(from)).map(|(key, node)| (key.clone(), node.clone())).collect();
        self.nodes.retain(|key, _| !key.starts_with(from));
        for (old, node) in moved {
            let mut new = to.to_vec();
            new.extend_from_slice(&old[from.len()..]);
            self.nodes.insert(new, node);
        }
    }

    fn rename(&mut self, params: &Params) -> HttpResponse {
        let path = params.list("path").pop().unwrap_or_default();
        let name = params.list("name").pop().unwrap_or_default();
        let from = split(&path);
        if self.fail_renames {
            return failure(1200);
        }
        if !self.nodes.contains_key(&from) {
            return path_failure(1200, 408, &path);
        }
        let mut to = from[..from.len() - 1].to_vec();
        to.push(name);
        if self.nodes.contains_key(&to) {
            return path_failure(1200, 414, &path);
        }
        self.move_tree(&from, &to);
        reply(json!({ "files": [self.info(&to)] }))
    }

    fn start_move(&mut self, params: &Params) -> HttpResponse {
        let path = params.list("path").pop().unwrap_or_default();
        let from = split(&path);
        let dest = split(params.get("dest_folder_path"));
        assert_eq!(params.get("remove_src"), "true");
        if !self.nodes.contains_key(&from) || !matches!(self.nodes.get(&dest), Some(Node::Dir)) {
            return path_failure(1001, 408, &path);
        }
        let mut to = dest;
        to.push(from.last().cloned().unwrap_or_default());
        // Like DSM, `start` only queues the task: a conflict shows up in its status.
        let taken = self.race_moves || self.nodes.contains_key(&to);
        let error = (taken && !params.fields.contains_key("overwrite")).then(|| (1003, path.clone()));
        if error.is_none() {
            self.move_tree(&from, &to);
        }
        self.issued += 1;
        let task = format!("FileStation_{}", self.issued);
        self.tasks.insert(task.clone(), Task { remaining: self.move_polls, error });
        reply(json!({ "taskid": task }))
    }

    fn move_status(&mut self, params: &Params) -> HttpResponse {
        if std::mem::take(&mut self.expire_during_move) {
            self.expire_sessions();
            self.tasks.clear();
            return failure(119);
        }
        let Some(task) = self.tasks.get_mut(params.get("taskid")) else { return failure(599) };
        if let Some((code, path)) = &task.error {
            return path_failure(1001, *code, path);
        }
        task.remaining = task.remaining.saturating_sub(1);
        reply(json!({ "finished": task.remaining == 0, "progress": if task.remaining == 0 { 1.0 } else { 0.5 } }))
    }
}

/// `(name, filename, content)` of each part of a multipart body.
fn multipart_parts(body: &[u8], boundary: &str) -> Vec<(String, Option<String>, Vec<u8>)> {
    let delimiter = format!("--{boundary}");
    let mut parts = Vec::new();
    let mut rest = body;
    while let Some(start) = find(rest, delimiter.as_bytes()) {
        rest = &rest[start + delimiter.len()..];
        if rest.starts_with(b"--") {
            break;
        }
        let rest_after_crlf = rest.strip_prefix(b"\r\n").expect("CRLF after the boundary");
        let end = find(rest_after_crlf, delimiter.as_bytes()).expect("closing boundary");
        let part = &rest_after_crlf[..end - 2];
        let split_at = find(part, b"\r\n\r\n").expect("part headers");
        let headers = String::from_utf8(part[..split_at].to_vec()).expect("utf-8 headers");
        let attribute = |name: &str| {
            let marker = format!("{name}=\"");
            headers.find(&marker).map(|at| headers[at + marker.len()..].split('"').next().unwrap_or_default().to_owned())
        };
        parts.push((attribute(" name").unwrap_or_default(), attribute("filename"), part[split_at + 4..].to_vec()));
        rest = rest_after_crlf;
    }
    parts
}

fn md5_hex(data: &[u8]) -> String {
    Md5::digest(data).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}
