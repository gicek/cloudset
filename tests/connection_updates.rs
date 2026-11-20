//! Rotating credentials survive failures in the file operation that triggered refresh.
mod common;

use cloudset::testing::oauth::{FakeProvider, MemoryCloud};
use cloudset::{AccessScope, HttpResponse, Step, map};
use common::{config, path, sign_in};

#[test]
fn mapped_operation_delivers_rotated_credentials_before_replay() {
    let mut server = MemoryCloud::new(FakeProvider::OneDrive);
    let client = sign_in(&mut server, AccessScope::AppFolder, &config());
    server.expire_access_token();
    let mut op = map(client.stat(path("missing")), |entry| entry.is_some());
    let mut response = None;
    let refreshed = loop {
        let step = op.advance(response.take()).unwrap();
        let Step::Send(request) = step else { panic!("expected request") };
        if let Some(updated) = op.take_connection() {
            assert!(op.take_connection().is_none());
            break updated;
        }
        response = Some(server.handle(request));
    };
    assert!(op.advance(Some(HttpResponse::new(503))).is_err());
    let before = server.requests.len();
    let latest = client.with_connection(refreshed);
    cloudset::run(latest.stat(path("missing")).as_mut(), |request| server.handle(request)).unwrap();
    assert!(server.requests[before..].iter().all(|request| !request.url.ends_with("/token")));
}

#[test]
fn run_with_updates_stores_the_refresh_of_a_failed_operation() {
    let mut server = MemoryCloud::new(FakeProvider::OneDrive);
    let client = sign_in(&mut server, AccessScope::AppFolder, &config());
    server.expire_access_token();
    let mut stored = Vec::new();
    let mut refreshed = false;
    let result = cloudset::run_with_updates(
        client.stat(path("missing")).as_mut(),
        |request| {
            if refreshed {
                return HttpResponse::new(503);
            }
            refreshed = request.url.ends_with("/token");
            server.handle(request)
        },
        |connection| stored.push(connection),
    );
    assert!(result.is_err());
    assert_eq!(stored.len(), 1);
    let before = server.requests.len();
    let latest = client.with_connection(stored.remove(0));
    assert!(
        cloudset::run_with_updates(latest.stat(path("missing")).as_mut(), |request| server.handle(request), |_| panic!("no update"))
            .unwrap()
            .is_none()
    );
    assert!(server.requests[before..].iter().all(|request| !request.url.ends_with("/token")));
}
