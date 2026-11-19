//! Moving and renaming on every provider: files and folders, into other folders, and every refusal.

mod common;

use cloudset::testing::oauth::{FakeProvider, MemoryCloud};
use cloudset::testing::{BASE, MemoryDav};
use cloudset::{BoxOperation, Client, ClientConfig, CloudError, Connection, Endpoint, Entry, Precondition, RemotePath, Transport};
use common::{PROVIDERS, SCOPES, config, path, run, sign_in};

/// One storage under test, so every case runs on WebDAV and on each OAuth provider alike.
trait Storage {
    fn run<T>(&mut self, make: impl FnOnce(&Client) -> BoxOperation<T>) -> Result<T, CloudError>;
    fn data(&self, path: &str) -> Option<Vec<u8>>;
    fn exists(&self, path: &str) -> bool;
}

struct Dav(MemoryDav, Client);

impl Storage for Dav {
    fn run<T>(&mut self, make: impl FnOnce(&Client) -> BoxOperation<T>) -> Result<T, CloudError> {
        let mut operation = make(&self.1);
        cloudset::run(operation.as_mut(), |request| self.0.handle(request)).map(|done| done.value)
    }
    fn data(&self, path: &str) -> Option<Vec<u8>> {
        self.0.data(path)
    }
    fn exists(&self, path: &str) -> bool {
        self.0.data(path).is_some() || self.0.is_dir(path)
    }
}

struct Cloud(MemoryCloud, Client);

impl Storage for Cloud {
    fn run<T>(&mut self, make: impl FnOnce(&Client) -> BoxOperation<T>) -> Result<T, CloudError> {
        run(&mut self.0, &mut self.1, make)
    }
    fn data(&self, path: &str) -> Option<Vec<u8>> {
        self.0.data(&self.0.storage_path(path))
    }
    fn exists(&self, path: &str) -> bool {
        self.0.exists(&self.0.storage_path(path))
    }
}

fn write(storage: &mut impl Storage, at: &str, data: &[u8]) {
    storage.run(|c| c.write(path(at), data.to_vec(), Precondition::None)).unwrap();
}

fn rename(storage: &mut impl Storage, from: &str, to: &str) -> Result<Entry, CloudError> {
    storage.run(|c| c.rename(path(from), path(to)))
}

fn check(storage: &mut impl Storage, case: &str) {
    write(storage, "a.txt", b"one");
    storage.run(|c| c.create_dir(path("Folder"))).unwrap();

    let renamed = rename(storage, "a.txt", "b.txt").unwrap();
    assert_eq!((renamed.path.to_string(), renamed.is_dir, renamed.size), ("b.txt".to_owned(), false, Some(3)), "{case}");
    assert!(!storage.exists("a.txt") && storage.data("b.txt").as_deref() == Some(&b"one"[..]), "{case}: renamed");

    let moved = rename(storage, "b.txt", "Folder/c.txt").unwrap();
    assert_eq!(moved.path, path("Folder/c.txt"), "{case}");
    assert_eq!(storage.data("Folder/c.txt").as_deref(), Some(&b"one"[..]), "{case}: moved into a folder");
    let read = storage.run(|c| c.read(path("Folder/c.txt"))).unwrap().unwrap();
    assert_eq!(read.entry.revision, moved.revision, "{case}: the returned revision is the file's");

    write(storage, "taken.txt", b"two");
    assert_eq!(rename(storage, "taken.txt", "Folder/c.txt").err(), Some(CloudError::PreconditionFailed), "{case}: destination exists");
    assert_eq!((storage.data("taken.txt"), storage.data("Folder/c.txt")), (Some(b"two".to_vec()), Some(b"one".to_vec())), "{case}");

    assert_eq!(rename(storage, "missing.txt", "x.txt").err(), Some(CloudError::NotFound), "{case}: missing source");
    assert_eq!(rename(storage, "taken.txt", "Nowhere/x.txt").err(), Some(CloudError::NotFound), "{case}: missing parent");
    assert!(!storage.exists("Nowhere"), "{case}: the missing parent was not created");
    assert_eq!(rename(storage, "taken.txt", "Folder/c.txt/x").err(), Some(CloudError::NotFound), "{case}: a file is no parent");

    let folder = rename(storage, "Folder", "Renamed").unwrap();
    assert!(folder.is_dir, "{case}");
    assert_eq!(storage.data("Renamed/c.txt").as_deref(), Some(&b"one"[..]), "{case}: folders move with their contents");
    assert!(!storage.exists("Folder"), "{case}");

    assert_eq!(rename(storage, "Renamed", "Renamed/inside").err(), Some(CloudError::InvalidPath), "{case}: into itself");
    assert_eq!(rename(storage, "Renamed", "Renamed").err(), Some(CloudError::InvalidPath), "{case}: onto itself");
    assert_eq!(storage.run(|c| c.rename(RemotePath::root(), path("x"))).err(), Some(CloudError::InvalidPath), "{case}: root");
}

#[test]
fn webdav() {
    let endpoint = Endpoint::parse(BASE, Transport::RequireHttps).unwrap();
    let client = Client::new(Connection::webdav(endpoint, "alice", "pw"), ClientConfig::new("cloudset-test/1"));
    let mut storage = Dav(MemoryDav::new("Basic YWxpY2U6cHc="), client);
    check(&mut storage, "WebDAV");
    let moves: Vec<_> = storage.0.requests.iter().filter(|request| request.method == cloudset::Method::Move).collect();
    assert!(moves.iter().all(|request| request.header("Overwrite") == Some("F")), "never overwrites");
    assert!(moves.iter().all(|request| request.header("Destination").is_some_and(|url| url.starts_with(BASE))));
}

#[test]
fn oauth_providers() {
    for provider in PROVIDERS {
        for access in SCOPES {
            let mut server = MemoryCloud::new(provider);
            let client = sign_in(&mut server, access, &config());
            check(&mut Cloud(server, client), &format!("{provider:?}/{access:?}"));
        }
    }
}

#[test]
fn google_drive_undoes_a_move_that_raced_a_create() {
    let mut server = MemoryCloud::new(FakeProvider::GoogleDrive);
    let mut client = sign_in(&mut server, cloudset::AccessScope::AppFolder, &config());
    run(&mut server, &mut client, |c| c.write(path("a.txt"), b"mine".to_vec(), Precondition::Absent)).unwrap();
    server.races().before_move = true;
    let result = run(&mut server, &mut client, |c| c.rename(path("a.txt"), path("b.txt")));
    assert_eq!(result.err(), Some(CloudError::PreconditionFailed));
    let storage = |p: &str| server.storage_path(p);
    assert_eq!(server.data(&storage("a.txt")).as_deref(), Some(&b"mine"[..]), "moved back");
    assert_eq!(server.data(&storage("b.txt")).as_deref(), Some(&b"other device"[..]), "the other device keeps the name");
    assert_eq!(server.copies(&storage("b.txt")), 1);
}

#[test]
fn google_drive_yields_to_a_newer_concurrent_create() {
    let mut server = MemoryCloud::new(FakeProvider::GoogleDrive);
    let mut client = sign_in(&mut server, cloudset::AccessScope::AppFolder, &config());
    run(&mut server, &mut client, |c| c.write(path("a.txt"), b"mine".to_vec(), Precondition::Absent)).unwrap();
    server.races().after_move = true;
    let result = run(&mut server, &mut client, |c| c.rename(path("a.txt"), path("b.txt")));
    assert_eq!(result.err(), Some(CloudError::PreconditionFailed), "the older moved item must not hide the new file");
    let storage = |p: &str| server.storage_path(p);
    assert_eq!(server.data(&storage("a.txt")).as_deref(), Some(&b"mine"[..]), "moved back");
    assert_eq!(server.data(&storage("b.txt")).as_deref(), Some(&b"other device"[..]));
    assert_eq!(server.copies(&storage("b.txt")), 1);
}
