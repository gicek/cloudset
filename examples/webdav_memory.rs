//! Every file operation against the in-memory WebDAV server, with no network.
//!
//! Run with `cargo run --example webdav_memory --features testing`.

use cloudset::testing::{BASE, MemoryDav};
use cloudset::{BoxOperation, Client, ClientConfig, CloudError, Connection, Endpoint, Precondition, RemotePath, Transport};

/// `Authorization` header for `alice` / `secret`.
const AUTH: &str = "Basic YWxpY2U6c2VjcmV0";

/// Runs one operation to completion. The closure is the transport: here the in-memory server, in an app an HTTP client.
fn run<T>(server: &mut MemoryDav, mut operation: BoxOperation<T>) -> Result<T, CloudError> {
    cloudset::run(operation.as_mut(), |request| server.handle(request)).map(|done| done.value)
}

fn main() -> Result<(), CloudError> {
    let mut server = MemoryDav::new(AUTH);
    let endpoint = Endpoint::parse(BASE, Transport::RequireHttps)?;
    let client = Client::new(Connection::webdav(endpoint, "alice", "secret"), ClientConfig::new("example/1.0"));

    let dir = RemotePath::parse("Backups")?;
    let file = dir.join("data.bin")?;

    run(&mut server, client.create_dir(dir.clone()))?;

    // `Absent` creates the file only if nothing is there yet.
    let created = run(&mut server, client.write(file.clone(), b"first".to_vec(), Precondition::Absent))?;
    println!("created {} ({:?} bytes, revision {:?})", created.path, created.size, created.revision);

    // `Matches` overwrites only if nobody changed the file since we saw this revision.
    let revision = created.revision.expect("WebDAV reports a revision");
    let updated = run(&mut server, client.write(file.clone(), b"second".to_vec(), Precondition::Matches(revision.clone())))?;
    println!("updated to revision {:?}", updated.revision);

    // Writing again with the old revision is refused, and the remote stays as it was.
    match run(&mut server, client.write(file.clone(), b"stale".to_vec(), Precondition::Matches(revision))) {
        Err(CloudError::PreconditionFailed) => println!("stale write refused"),
        other => panic!("expected a conflict, got {other:?}"),
    }

    let read = run(&mut server, client.read(file.clone()))?.expect("the file exists");
    println!("read {:?}", String::from_utf8_lossy(&read.data));

    for entry in run(&mut server, client.list(dir.clone()))? {
        println!("listed {} (directory: {})", entry.path, entry.is_dir);
    }

    // Renaming never overwrites: an existing destination is `PreconditionFailed`.
    let renamed = run(&mut server, client.rename(file.clone(), dir.join("renamed.bin")?))?;
    println!("renamed to {}", renamed.path);

    run(&mut server, client.delete(renamed.path.clone()))?;
    assert!(run(&mut server, client.stat(renamed.path))?.is_none());
    assert!(run(&mut server, client.stat(file))?.is_none());

    // The connection is an opaque blob: store it in the system keychain and restore it later.
    let stored = client.connection().to_bytes();
    let restored = Connection::from_bytes(&stored)?;
    assert_eq!(&restored, client.connection());
    println!("{} requests sent", server.requests.len());
    Ok(())
}
