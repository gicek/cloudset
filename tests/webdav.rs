//! WebDAV end to end: the crate's operation state machines run against the in-memory server.

use cloudset::testing::{BASE, MemoryDav};
use cloudset::{
    Client, ClientConfig, CloudError, Connection, Endpoint, Entry, File, HttpResponse, Precondition, RemotePath, Revision, Step, Transport,
};

const AUTH: &str = "Basic YWxpY2U6cHc="; // alice:pw

fn client() -> Client {
    let endpoint = Endpoint::parse(BASE, Transport::RequireHttps).unwrap();
    Client::new(Connection::webdav(endpoint, "alice", "pw"), ClientConfig::new("cloudset-test/1"))
}

fn path(text: &str) -> RemotePath {
    RemotePath::parse(text).unwrap()
}

fn run<T>(server: &mut MemoryDav, mut operation: cloudset::BoxOperation<T>) -> Result<T, CloudError> {
    cloudset::run(operation.as_mut(), |request| server.handle(request)).map(|done| {
        assert!(done.connection.is_none(), "WebDAV never updates the connection");
        done.value
    })
}

fn write(server: &mut MemoryDav, at: &str, data: &[u8], precondition: Precondition) -> Result<Entry, CloudError> {
    run(server, client().write(path(at), data.to_vec(), precondition))
}

fn read(server: &mut MemoryDav, at: &str) -> Result<Option<File>, CloudError> {
    run(server, client().read(path(at)))
}

#[test]
fn writes_reads_and_versions_from_propfind() {
    let mut server = MemoryDav::new(AUTH);
    run(&mut server, client().create_dir(path("Backups"))).unwrap();
    let written = write(&mut server, "Backups/data.bin", b"one", Precondition::Absent).unwrap();
    assert_eq!((written.is_dir, written.size), (false, Some(3)));
    let revision = written.revision.clone().unwrap();
    assert!(revision.as_str().starts_with('"'), "the version comes from getetag, not the PUT response header: {revision:?}");

    let file = read(&mut server, "Backups/data.bin").unwrap().unwrap();
    assert_eq!(file.data, b"one");
    assert_eq!(file.entry, written, "metadata read back matches the metadata after the write");
    assert_eq!(run(&mut server, client().stat(path("Backups/data.bin"))).unwrap(), Some(written));

    for request in &server.requests {
        assert_eq!(request.header("Authorization"), Some(AUTH));
        assert_eq!(request.header("User-Agent"), Some("cloudset-test/1"));
        assert!(request.url.starts_with(BASE), "{}", request.url);
    }
}

#[test]
fn conditional_writes() {
    let mut server = MemoryDav::new(AUTH);
    let first = write(&mut server, "notes", b"1", Precondition::Absent).unwrap().revision.unwrap();
    assert_eq!(write(&mut server, "notes", b"x", Precondition::Absent), Err(CloudError::PreconditionFailed));

    server.put_external("notes", b"other device");
    assert_eq!(write(&mut server, "notes", b"2", Precondition::Matches(first.clone())), Err(CloudError::PreconditionFailed));
    assert_eq!(server.data("notes").unwrap(), b"other device", "a rejected write leaves the remote unchanged");

    let current = run(&mut server, client().stat(path("notes"))).unwrap().unwrap().revision.unwrap();
    let second = write(&mut server, "notes", b"2", Precondition::Matches(current.clone())).unwrap().revision.unwrap();
    assert_ne!(second, current);
    write(&mut server, "notes", b"3", Precondition::None).unwrap();
    assert_eq!(server.data("notes").unwrap(), b"3");
}

#[test]
fn weak_etags_do_not_authorize_writes_or_label_unconditional_reads() {
    let mut server = MemoryDav::new(AUTH);
    server.weak_etags = true;
    let written = write(&mut server, "notes", b"1", Precondition::Absent).unwrap();
    assert_eq!(written.revision, None);
    let weak = run(&mut server, client().stat(path("notes"))).unwrap().unwrap().revision.unwrap();
    let requests = server.requests.len();
    assert_eq!(write(&mut server, "notes", b"2", Precondition::Matches(weak)), Err(CloudError::UnsupportedPrecondition));
    assert_eq!(server.requests.len(), requests);
    server.modify_before_get = 1;
    let file = read(&mut server, "notes").unwrap().unwrap();
    assert_eq!(file.data, b"1+");
    assert_eq!((file.entry.size, file.entry.modified_at, file.entry.revision), (Some(2), None, None));
}

#[test]
fn a_second_writer_cannot_supply_the_revision_of_our_write() {
    let mut server = MemoryDav::new(AUTH);
    let result = cloudset::run(client().write(path("notes"), b"first".to_vec(), Precondition::Absent).as_mut(), |request| {
        let put = request.method == cloudset::Method::Put;
        let response = server.handle(request);
        if put {
            server.put_external("notes", b"second");
        }
        response
    });
    assert_eq!(result.unwrap_err(), CloudError::CommitUnconfirmed);
    assert_eq!(server.data("notes").as_deref(), Some(b"second".as_slice()));
}

#[test]
fn failed_readback_reports_an_unconfirmed_commit() {
    let mut server = MemoryDav::new(AUTH);
    let result = cloudset::run(client().write(path("notes"), b"saved".to_vec(), Precondition::Absent).as_mut(), |request| {
        if request.method == cloudset::Method::Propfind { HttpResponse::new(503) } else { server.handle(request) }
    });
    assert_eq!(result.unwrap_err(), CloudError::CommitUnconfirmed);
    assert_eq!(server.data("notes").as_deref(), Some(b"saved".as_slice()));
}

#[test]
fn writes_larger_than_the_read_limit_return_only_acknowledged_metadata() {
    let mut server = MemoryDav::new(AUTH);
    let config = ClientConfig::new("test").with_limits(cloudset::Limits::default().with_max_body_bytes(4));
    let client = client().with_config(config);
    let written = run(&mut server, client.write(path("notes"), b"large".to_vec(), Precondition::Absent)).unwrap();
    assert_eq!((written.size, written.revision, written.modified_at), (Some(5), None, None));
    assert_eq!(server.requests.len(), 1);
}

#[test]
fn read_retries_when_changed_between_stat_and_get() {
    let mut server = MemoryDav::new(AUTH);
    write(&mut server, "notes", b"a", Precondition::None).unwrap();
    server.modify_before_get = 1;
    let file = read(&mut server, "notes").unwrap().unwrap();
    assert_eq!(file.data, b"a+");
    assert_eq!(Some(file.entry), run(&mut server, client().stat(path("notes"))).unwrap(), "after a retry, version and contents agree");

    server.modify_before_get = 3;
    assert_eq!(read(&mut server, "notes").err(), Some(CloudError::PreconditionFailed));
}

#[test]
fn missing_things_and_directories() {
    let mut server = MemoryDav::new(AUTH);
    assert_eq!(read(&mut server, "nope").unwrap(), None);
    assert_eq!(run(&mut server, client().stat(path("nope"))).unwrap(), None);
    assert_eq!(write(&mut server, "missing/notes", b"x", Precondition::None), Err(CloudError::NotFound));
    assert_eq!(run(&mut server, client().create_dir(path("a/b"))), Err(CloudError::NotFound));
    assert_eq!(run(&mut server, client().list(path("nope"))), Err(CloudError::NotFound));

    run(&mut server, client().create_dir(path("备份 1"))).unwrap();
    run(&mut server, client().create_dir(path("备份 1"))).unwrap();
    server.put_external("备份 1/b#?&.txt", b"b");
    server.put_external("备份 1/a.txt", b"a");
    server.mkdir_external("备份 1/sub");

    let listed = run(&mut server, client().list(path("备份 1"))).unwrap();
    let names: Vec<(String, bool)> = listed.iter().map(|e| (e.path.to_string(), e.is_dir)).collect();
    assert_eq!(names, [("备份 1/a.txt".into(), false), ("备份 1/b#?&.txt".into(), false), ("备份 1/sub".into(), true)]);
    assert_eq!(read(&mut server, "备份 1/b#?&.txt").unwrap().unwrap().data, b"b");

    let dir = run(&mut server, client().stat(path("备份 1/sub"))).unwrap().unwrap();
    assert!(dir.is_dir, "the server answers 301 for a directory without a trailing slash, and the crate follows it");
    assert_eq!(read(&mut server, "备份 1/sub"), Err(CloudError::InvalidResponse("expected a file")));

    let root = run(&mut server, client().list(RemotePath::root())).unwrap();
    assert_eq!(root.len(), 1);

    run(&mut server, client().delete(path("备份 1/a.txt"))).unwrap();
    run(&mut server, client().delete(path("备份 1/a.txt"))).unwrap();
    assert_eq!(read(&mut server, "备份 1/a.txt").unwrap(), None);
}

#[test]
fn wrong_credentials_need_reauth() {
    let mut server = MemoryDav::new("Basic other");
    assert_eq!(read(&mut server, "notes"), Err(CloudError::ReauthRequired));
    assert_eq!(write(&mut server, "notes", b"x", Precondition::None), Err(CloudError::ReauthRequired));
}

#[test]
fn revoke_is_a_no_op_for_webdav() {
    let mut server = MemoryDav::new(AUTH);
    run(&mut server, client().revoke()).unwrap();
    assert!(server.requests.is_empty());
}

#[test]
fn rejects_out_of_order_driving() {
    let mut operation = client().stat(path("notes"));
    assert!(matches!(operation.advance(None), Ok(Step::Send(_))));
    assert_eq!(operation.advance(None).err(), Some(CloudError::OutOfOrder));

    let mut fresh = client().read(path("notes"));
    assert_eq!(fresh.advance(Some(HttpResponse::new(200))).err(), Some(CloudError::OutOfOrder));

    let mut finished = client().stat(path("notes"));
    finished.advance(None).unwrap();
    assert!(matches!(finished.advance(Some(HttpResponse::new(404))), Ok(Step::Done(_))));
    assert_eq!(finished.advance(Some(HttpResponse::new(404))).err(), Some(CloudError::OutOfOrder));
}

#[test]
fn revision_is_opaque() {
    assert_eq!(Revision::new("\"x\"").as_str(), "\"x\"");
}

#[test]
fn mkcol_405_is_checked_before_treating_it_as_existing() {
    let mut server = MemoryDav::new(AUTH);
    run(&mut server, client().create_dir(path("home"))).unwrap();
    run(&mut server, client().create_dir(path("home"))).unwrap();
    server.mkcol_forbidden_in.push(String::new());
    assert_eq!(
        run(&mut server, client().create_dir(path("Backups"))),
        Err(CloudError::Forbidden),
        "root is read-only: 405 does not mean it exists"
    );
    run(&mut server, client().create_dir(path("home"))).unwrap();
    run(&mut server, client().create_dir(path("home/Backups"))).unwrap();
    server.put_external("home/file", b"x");
    server.mkcol_forbidden_in.push("home".into());
    assert_eq!(run(&mut server, client().create_dir(path("home/file"))), Err(CloudError::Forbidden), "a file has that name");
}

#[test]
fn refuses_to_mutate_the_connection_root() {
    for mut operation in
        [client().delete(RemotePath::root()), cloudset::map(client().write(RemotePath::root(), vec![1], Precondition::None), |_| ())]
    {
        assert_eq!(operation.advance(None).unwrap_err(), CloudError::InvalidPath);
    }
}

fn multistatus(responses: &str) -> HttpResponse {
    HttpResponse::new(207).with_body(format!(r#"<d:multistatus xmlns:d="DAV:">{responses}</d:multistatus>"#).into_bytes())
}

fn dav_response(href: &str, is_dir: bool) -> String {
    let kind = if is_dir { "<d:collection/>" } else { "" };
    format!(
        "<d:response><d:href>{href}</d:href><d:propstat><d:prop><d:resourcetype>{kind}</d:resourcetype></d:prop>\
         <d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
    )
}

fn scripted<T>(mut operation: cloudset::BoxOperation<T>, response: HttpResponse) -> Result<T, CloudError> {
    cloudset::run(operation.as_mut(), |_| response.clone()).map(|done| done.value)
}

/// A listing must be about the directory that was asked for: hrefs that do not map onto the endpoint, a file, or a
/// server that ignores `Depth: 1` must not read as "this directory is empty" or add entries from elsewhere.
#[test]
fn list_only_trusts_answers_about_the_directory() {
    let base = Endpoint::parse(BASE, Transport::RequireHttps).unwrap();
    let prefix = url::Url::parse(base.as_str()).unwrap().path().to_owned();
    let elsewhere = multistatus(&(dav_response("/other/prefix/x/", true) + &dav_response("/other/prefix/x/a.txt", false)));
    assert_eq!(scripted(client().list(path("x")), elsewhere), Err(CloudError::InvalidResponse("missing entry")));

    let a_file = multistatus(&dav_response(&format!("{prefix}x"), false));
    assert_eq!(scripted(client().list(path("x")), a_file), Err(CloudError::InvalidResponse("not a directory")));

    let gone = multistatus(&format!("<d:response><d:href>{prefix}x/</d:href><d:status>HTTP/1.1 404 Not Found</d:status></d:response>"));
    assert_eq!(scripted(client().list(path("x")), gone.clone()), Err(CloudError::NotFound));
    assert_eq!(scripted(client().stat(path("x")), gone), Ok(None), "a 404 inside the multistatus is a missing file");

    let deep = multistatus(
        &[
            dav_response(&format!("{prefix}x/"), true),
            dav_response(&format!("{prefix}x/a.txt"), false),
            dav_response(&format!("{prefix}x/y/z.txt"), false),
            dav_response(&format!("{prefix}other.txt"), false),
            format!("<d:response><d:href>{prefix}x/hidden</d:href><d:status>HTTP/1.1 403 Forbidden</d:status></d:response>"),
        ]
        .concat(),
    );
    let listed = scripted(client().list(path("x")), deep).unwrap();
    assert_eq!(listed.iter().map(|entry| entry.path.to_string()).collect::<Vec<_>>(), ["x/a.txt"]);
}

/// A 303 would turn the request into a GET, whose 200 says nothing about the delete or the new directory.
#[test]
fn a_see_other_redirect_is_not_the_result_of_a_write() {
    for operation in [client().delete(path("a.txt")), client().create_dir(path("dir"))] {
        let mut operation = operation;
        let mut requests = 0;
        let result = cloudset::run(operation.as_mut(), |_| {
            requests += 1;
            if requests == 1 { HttpResponse::new(303).with_header("Location", "/login") } else { HttpResponse::new(200) }
        });
        assert_eq!(result.err(), Some(CloudError::InvalidResponse("unexpected redirect")));
        assert_eq!(requests, 1);
        assert_eq!(operation.advance(Some(HttpResponse::new(204))).err(), Some(CloudError::OutOfOrder), "an error ends the operation");
    }
}
