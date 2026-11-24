//! Synology end to end: QuickConnect resolution in both regions, sign-in with two-step verification, session renewal and
//! every file operation, against the in-memory device.

use cloudset::synology::quickconnect::{self, Candidate, QuickConnectId, Region, Resolution, Route};
use cloudset::synology::{self, SignIn};
use cloudset::testing::synology::{LAN_ADDRESS, MemorySynology, PUBLIC_ADDRESS, QUICKCONNECT_ID, SHARE, relay_address};
use cloudset::{
    BoxOperation, Client, ClientConfig, CloudError, Connection, Endpoint, HttpRequest, Precondition, ProviderKind, RemotePath, Transport,
    run, run_with_updates,
};

/// A password distinct enough to search for in `Debug` output.
const PASSWORD: &str = "pw-7f3k9-distinct";

fn config() -> ClientConfig {
    ClientConfig::new("cloudset-test/1")
}

fn path(text: &str) -> RemotePath {
    RemotePath::parse(text).unwrap()
}

fn endpoint(address: &str) -> Endpoint {
    Endpoint::parse(address, Transport::RequireHttps).unwrap()
}

fn drive<T>(server: &mut MemorySynology, mut operation: BoxOperation<T>) -> Result<T, CloudError> {
    run(operation.as_mut(), |request| server.handle(request)).map(|done| done.value)
}

fn hosts(requests: &[HttpRequest]) -> Vec<String> {
    requests.iter().map(|request| url::Url::parse(&request.url).unwrap().host_str().unwrap().to_owned()).collect()
}

fn resolve(server: &mut MemorySynology, region: Region) -> Result<Resolution, CloudError> {
    drive(server, quickconnect::resolve(&QuickConnectId::parse(QUICKCONNECT_ID).unwrap(), region, &config()))
}

/// The first candidate, in list order, whose probe succeeds.
fn first_reachable(server: &mut MemorySynology, resolution: &Resolution, candidates: &[Candidate]) -> Option<Candidate> {
    candidates.iter().find(|candidate| drive(server, resolution.probe(&candidate.endpoint, &config())).unwrap()).cloned()
}

fn sign_in(server: &mut MemorySynology, root: &str) -> Client {
    let request = SignIn::new(endpoint(LAN_ADDRESS), path(root), "alice", "secret");
    Client::new(drive(server, synology::sign_in(request, &config())).unwrap(), config())
}

/// Runs an operation and switches the client to a renewed connection.
fn run_op<T>(server: &mut MemorySynology, client: &mut Client, make: impl FnOnce(&Client) -> BoxOperation<T>) -> Result<T, CloudError> {
    let mut operation = make(client);
    let mut renewed = None;
    let result = run_with_updates(operation.as_mut(), |request| server.handle(request), |connection| renewed = Some(connection));
    if let Some(connection) = renewed {
        *client = client.with_connection(connection);
    }
    result
}

#[test]
fn resolves_a_device_on_the_local_network() {
    let mut server = MemorySynology::new(Region::Global);
    let resolution = resolve(&mut server, Region::Global).unwrap();
    assert_eq!(hosts(&server.requests), ["global.quickconnect.to"]);
    assert_eq!((resolution.id().as_str(), resolution.region()), (QUICKCONNECT_ID, Region::Global));

    let candidates = resolution.candidates();
    assert_eq!(candidates[0].endpoint.as_str(), LAN_ADDRESS);
    assert_eq!(candidates[0].route, Route::LocalNetwork);
    assert!(candidates.iter().any(|candidate| candidate.endpoint.as_str() == PUBLIC_ADDRESS && candidate.route == Route::Internet));
    assert!(candidates.iter().all(|candidate| candidate.endpoint.is_secure()), "only HTTPS candidates");

    let reachable = first_reachable(&mut server, &resolution, candidates).unwrap();
    assert_eq!(reachable.endpoint.as_str(), LAN_ADDRESS);
}

#[test]
fn a_device_in_mainland_china_is_found_through_the_global_host_and_reached_by_relay() {
    let mut server = MemorySynology::new(Region::ChinaMainland);
    server.reachable.clear(); // the client is outside the device's network and no port is forwarded

    let resolution = resolve(&mut server, Region::Global).unwrap();
    assert_eq!(hosts(&server.requests), ["global.quickconnect.to", "cnc.quickconnect.cn"], "follows the regional redirect");
    assert_eq!(resolution.region(), Region::ChinaMainland);
    assert!(first_reachable(&mut server, &resolution, resolution.candidates()).is_none());

    server.requests.clear();
    let relays = drive(&mut server, resolution.request_relay(&config())).unwrap();
    assert_eq!(hosts(&server.requests), ["cnc.quickconnect.cn"], "the tunnel is requested from the device's control host");
    assert_eq!(relays[0].endpoint.as_str(), relay_address(Region::ChinaMainland), "the relay stays on quickconnect.cn");
    assert!(relays.iter().all(|relay| relay.route == Route::Relay));
    let relay = first_reachable(&mut server, &resolution, &relays).unwrap();

    let sign_in =
        SignIn::new(relay.endpoint, path(SHARE), "alice", "secret").with_quickconnect(resolution.id().clone(), resolution.region());
    let connection = drive(&mut server, synology::sign_in(sign_in, &config())).unwrap();
    assert_eq!(connection.host(), format!("{QUICKCONNECT_ID}.cn4.quickconnect.cn"));
    assert_eq!(connection.quickconnect().map(|(id, region)| (id.as_str(), region)), Some((QUICKCONNECT_ID, Region::ChinaMainland)));
    let mut client = Client::new(connection, config());
    run_op(&mut server, &mut client, |client| client.write(path("relay.txt"), b"via relay".to_vec(), Precondition::Absent)).unwrap();
    assert_eq!(server.data("home/relay.txt").unwrap(), b"via relay");
}

#[test]
fn starts_at_the_china_host_and_falls_back_to_the_global_one() {
    let mut server = MemorySynology::new(Region::ChinaMainland);
    resolve(&mut server, Region::ChinaMainland).unwrap();
    assert_eq!(hosts(&server.requests), ["global.quickconnect.cn"], "no detour through quickconnect.to");

    server.requests.clear();
    server.failing_hosts.push("global.quickconnect.cn".into());
    let resolution = resolve(&mut server, Region::ChinaMainland).unwrap();
    assert_eq!(hosts(&server.requests), ["global.quickconnect.cn", "global.quickconnect.to", "cnc.quickconnect.cn"]);
    assert_eq!(resolution.region(), Region::ChinaMainland);
}

#[test]
fn unknown_ids_and_unavailable_control_hosts() {
    let mut server = MemorySynology::new(Region::Global);
    let unknown = QuickConnectId::parse("someone-else").unwrap();
    assert_eq!(drive(&mut server, quickconnect::resolve(&unknown, Region::Global, &config())).err(), Some(CloudError::NotFound));

    server.failing_hosts = vec!["global.quickconnect.to".into(), "global.quickconnect.cn".into()];
    assert_eq!(resolve(&mut server, Region::Global).err(), Some(CloudError::InvalidResponse("quickconnect unavailable")));
}

#[test]
fn probes_only_accept_this_exact_device() {
    let mut server = MemorySynology::new(Region::Global);
    let resolution = resolve(&mut server, Region::Global).unwrap();
    server.other_device.push(PUBLIC_ADDRESS.into());
    assert!(!drive(&mut server, resolution.probe(&endpoint(PUBLIC_ADDRESS), &config())).unwrap(), "another Synology device");
    assert!(!drive(&mut server, resolution.probe(&endpoint("https://unrelated.example.com/"), &config())).unwrap(), "no DSM");
    assert!(drive(&mut server, resolution.probe(&endpoint(LAN_ADDRESS), &config())).unwrap());
    let probe = server.requests.last().unwrap();
    assert_eq!(probe.url, format!("{LAN_ADDRESS}webman/pingpong.cgi?action=cors&quickconnect=true"));
    assert!(probe.header("Authorization").is_none() && !probe.url.contains("_sid"), "probes carry no credentials");
}

#[test]
fn file_operations() {
    let mut server = MemorySynology::new(Region::Global);
    let mut client = sign_in(&mut server, "home");
    assert_eq!(client.connection().provider(), ProviderKind::Synology);
    assert_eq!(client.connection().root_folder(), Some(&path("home")));

    run_op(&mut server, &mut client, |client| client.create_dir(path("Notes"))).unwrap();
    run_op(&mut server, &mut client, |client| client.create_dir(path("Notes"))).unwrap();
    let written =
        run_op(&mut server, &mut client, |client| client.write(path("Notes/备份 a,b.txt"), b"one".to_vec(), Precondition::Absent));
    let written = written.unwrap();
    assert_eq!((written.is_dir, written.size, written.revision.clone()), (false, Some(3), None));
    assert!(written.modified_at.is_some());
    assert_eq!(server.data("home/Notes/备份 a,b.txt").unwrap(), b"one");

    let file = run_op(&mut server, &mut client, |client| client.read(path("Notes/备份 a,b.txt"))).unwrap().unwrap();
    assert_eq!((file.data.as_slice(), &file.entry), (&b"one"[..], &written));
    assert_eq!(run_op(&mut server, &mut client, |client| client.stat(path("Notes/备份 a,b.txt"))).unwrap(), Some(written));
    assert_eq!(run_op(&mut server, &mut client, |client| client.stat(path("missing"))).unwrap(), None);
    assert_eq!(run_op(&mut server, &mut client, |client| client.read(path("missing"))).unwrap(), None);

    run_op(&mut server, &mut client, |client| client.write(path("Notes/b.txt"), b"two".to_vec(), Precondition::None)).unwrap();
    let names: Vec<String> = run_op(&mut server, &mut client, |client| client.list(path("Notes")))
        .unwrap()
        .into_iter()
        .map(|entry| entry.path.to_string())
        .collect();
    assert_eq!(names, ["Notes/b.txt", "Notes/备份 a,b.txt"]);
    assert_eq!(run_op(&mut server, &mut client, |client| client.list(path("missing"))).err(), Some(CloudError::NotFound));
    let root = run_op(&mut server, &mut client, |client| client.stat(RemotePath::root())).unwrap().unwrap();
    assert!(root.is_dir);

    assert_eq!(
        run_op(&mut server, &mut client, |client| client.create_dir(path("Notes/b.txt"))).err(),
        Some(CloudError::Forbidden),
        "a file is in the way"
    );
    assert_eq!(run_op(&mut server, &mut client, |client| client.create_dir(path("missing/dir"))).err(), Some(CloudError::NotFound));
    assert_eq!(
        run_op(&mut server, &mut client, |client| client.write(path("missing/a.txt"), b"x".to_vec(), Precondition::None)).err(),
        Some(CloudError::NotFound)
    );

    run_op(&mut server, &mut client, |client| client.delete(path("Notes/b.txt"))).unwrap();
    run_op(&mut server, &mut client, |client| client.delete(path("Notes/b.txt"))).unwrap();
    assert!(server.data("home/Notes/b.txt").is_none());
    run_op(&mut server, &mut client, |client| client.delete(path("Notes"))).unwrap();
    assert!(!server.is_dir("home/Notes"));
}

#[test]
fn conditional_writes() {
    let mut server = MemorySynology::new(Region::Global);
    let mut client = sign_in(&mut server, "home");
    run_op(&mut server, &mut client, |client| client.write(path("a.txt"), b"1".to_vec(), Precondition::Absent)).unwrap();
    let requests = server.requests.len();
    assert_eq!(
        run_op(&mut server, &mut client, |client| client.write(path("a.txt"), b"2".to_vec(), Precondition::Absent)).err(),
        Some(CloudError::PreconditionFailed)
    );
    assert_eq!(server.data("home/a.txt").unwrap(), b"1", "a rejected write leaves the file alone");
    assert_eq!(server.requests.len(), requests + 1, "DSM itself refuses the replacement");

    server.mkdir_external("home/folder");
    assert_eq!(
        run_op(&mut server, &mut client, |client| client.write(path("folder"), b"x".to_vec(), Precondition::Absent)).err(),
        Some(CloudError::PreconditionFailed)
    );
    assert_eq!(
        run_op(&mut server, &mut client, |client| client.write(path("folder"), b"x".to_vec(), Precondition::None)).err(),
        Some(CloudError::Forbidden)
    );

    let matches = Precondition::Matches(cloudset::Revision::new("anything"));
    assert!(!client.supports_write_precondition(1, &matches));
    assert!(client.supports_write_precondition(1, &Precondition::Absent) && client.supports_write_precondition(1, &Precondition::None));
    let requests = server.requests.len();
    assert_eq!(
        run_op(&mut server, &mut client, |client| client.write(path("a.txt"), b"3".to_vec(), matches)).err(),
        Some(CloudError::UnsupportedPrecondition)
    );
    assert_eq!(server.requests.len(), requests, "refused before anything is sent");

    run_op(&mut server, &mut client, |client| client.write(path("a.txt"), b"4".to_vec(), Precondition::None)).unwrap();
    assert_eq!(server.data("home/a.txt").unwrap(), b"4");
}

#[test]
fn reads_retry_while_the_file_changes() {
    let mut server = MemorySynology::new(Region::Global);
    let mut client = sign_in(&mut server, "home");
    server.put_external("home/a.txt", b"v1");
    server.modify_before_download = 1;
    let file = run_op(&mut server, &mut client, |client| client.read(path("a.txt"))).unwrap().unwrap();
    assert_eq!(file.data, b"v1+", "the second download matches the metadata around it");
    assert_eq!(file.entry.size, Some(3));

    server.modify_before_download = 3;
    assert_eq!(run_op(&mut server, &mut client, |client| client.read(path("a.txt"))).err(), Some(CloudError::PreconditionFailed));
}

#[test]
fn renames_within_and_across_folders() {
    let mut server = MemorySynology::new(Region::Global);
    let mut client = sign_in(&mut server, "home");
    server.put_external("home/a.txt", b"a");
    server.put_external("home/taken.txt", b"t");
    server.mkdir_external("home/dir");

    let renamed = run_op(&mut server, &mut client, |client| client.rename(path("a.txt"), path("b.txt"))).unwrap();
    assert_eq!((renamed.path.to_string(), renamed.size), ("b.txt".to_owned(), Some(1)));
    assert!(server.data("home/a.txt").is_none() && server.data("home/b.txt").is_some());

    server.move_polls = 3;
    run_op(&mut server, &mut client, |client| client.rename(path("b.txt"), path("dir/b.txt"))).unwrap();
    assert_eq!(server.data("home/dir/b.txt").unwrap(), b"a");
    let moved = run_op(&mut server, &mut client, |client| client.rename(path("dir/b.txt"), path("c.txt"))).unwrap();
    assert_eq!(moved.path, path("c.txt"), "moved, then renamed");
    assert_eq!(server.data("home/c.txt").unwrap(), b"a");

    let refused = [
        (path("c.txt"), path("taken.txt"), CloudError::PreconditionFailed),
        (path("missing.txt"), path("x.txt"), CloudError::NotFound),
        (path("c.txt"), path("missing/c.txt"), CloudError::NotFound),
        (path("c.txt"), path("taken.txt/c.txt"), CloudError::NotFound),
        (path("dir"), path("dir/inner"), CloudError::InvalidPath),
    ];
    for (from, to, error) in refused {
        assert_eq!(run_op(&mut server, &mut client, |client| client.rename(from.clone(), to.clone())).err(), Some(error), "{from} -> {to}");
    }
    server.put_external("home/dir/c.txt", b"in the way");
    assert_eq!(
        run_op(&mut server, &mut client, |client| client.rename(path("c.txt"), path("dir/d.txt"))).err(),
        Some(CloudError::PreconditionFailed),
        "the move would pass through dir/c.txt"
    );
    assert_eq!(server.data("home/c.txt").unwrap(), b"a", "nothing moved");
}

#[test]
fn two_step_verification_and_session_renewal() {
    let mut server = MemorySynology::new(Region::Global);
    server.otp_code = Some("123456".into());
    let request = SignIn::new(endpoint(LAN_ADDRESS), path("home"), "alice", "secret");
    assert_eq!(drive(&mut server, synology::sign_in(request.clone(), &config())).err(), Some(CloudError::OtpRequired));
    assert_eq!(
        drive(&mut server, synology::sign_in(request.clone().with_otp_code("000000"), &config())).err(),
        Some(CloudError::OtpRequired)
    );
    let connection = drive(&mut server, synology::sign_in(request.with_otp_code("123456"), &config())).unwrap();
    let mut client = Client::new(connection, config());

    // The session expires: the driver signs in again as a trusted device, without a code, and hands the renewal over.
    server.expire_sessions();
    let before = client.connection().clone();
    run_op(&mut server, &mut client, |client| client.write(path("a.txt"), b"x".to_vec(), Precondition::None)).unwrap();
    assert_ne!(client.connection(), &before, "the renewed session is handed over");
    let logins: Vec<&HttpRequest> =
        server.requests.iter().filter(|request| String::from_utf8_lossy(&request.body).contains("method=login")).collect();
    let last = String::from_utf8_lossy(&logins.last().unwrap().body).into_owned();
    assert!(last.contains("device_id=did-") && !last.contains("otp_code"), "{last}");

    // A changed password cannot be fixed without the user.
    server.expire_sessions();
    server.password = "changed".into();
    assert_eq!(run_op(&mut server, &mut client, |client| client.stat(path("a.txt"))).err(), Some(CloudError::ReauthRequired));
}

#[test]
fn sign_in_checks_the_password_and_the_root_folder() {
    let mut server = MemorySynology::new(Region::Global);
    let wrong = SignIn::new(endpoint(LAN_ADDRESS), path("home"), "alice", "wrong");
    assert_eq!(drive(&mut server, synology::sign_in(wrong, &config())).err(), Some(CloudError::ReauthRequired));
    let missing = SignIn::new(endpoint(LAN_ADDRESS), path("photo"), "alice", "secret");
    assert_eq!(drive(&mut server, synology::sign_in(missing, &config())).err(), Some(CloudError::NotFound));
    let root = SignIn::new(endpoint(LAN_ADDRESS), RemotePath::root(), "alice", "secret");
    assert_eq!(drive(&mut server, synology::sign_in(root, &config())).err(), Some(CloudError::InvalidPath));
    server.mkdir_external("home/Apps/Notes");
    let nested = SignIn::new(endpoint(LAN_ADDRESS), path("home/Apps/Notes"), "alice", "secret");
    let mut client = Client::new(drive(&mut server, synology::sign_in(nested, &config())).unwrap(), config());
    run_op(&mut server, &mut client, |client| client.write(path("n.txt"), b"n".to_vec(), Precondition::Absent)).unwrap();
    assert!(server.data("home/Apps/Notes/n.txt").is_some(), "paths are relative to the root folder");
}

#[test]
fn credentials_stay_on_the_device_and_out_of_debug_output() {
    let mut server = MemorySynology::new(Region::Global);
    server.password = PASSWORD.into();
    let request = SignIn::new(endpoint(LAN_ADDRESS), path("home"), "alice", PASSWORD);
    let mut client = Client::new(drive(&mut server, synology::sign_in(request, &config())).unwrap(), config());
    run_op(&mut server, &mut client, |client| client.stat(path("a"))).unwrap();
    for request in &server.requests {
        assert!(request.url.starts_with(LAN_ADDRESS), "{}", request.url);
        assert_eq!(request.header("User-Agent"), Some("cloudset-test/1"));
    }
    let debug = format!("{:?} {:?}", client.connection(), server.requests);
    assert!(!debug.contains(PASSWORD) && !debug.contains("sid-"), "{debug}");
    let sign_in = format!("{:?}", SignIn::new(endpoint(LAN_ADDRESS), path("home"), "alice", PASSWORD).with_otp_code("123456"));
    assert!(!sign_in.contains(PASSWORD) && !sign_in.contains("123456"), "{sign_in}");
}

#[test]
fn connections_round_trip_and_move_between_routes() {
    let mut server = MemorySynology::new(Region::ChinaMainland);
    let id = QuickConnectId::parse(QUICKCONNECT_ID).unwrap();
    let sign_in = SignIn::new(endpoint(LAN_ADDRESS), path("home"), "alice", "secret").with_quickconnect(id, Region::ChinaMainland);
    let connection = drive(&mut server, synology::sign_in(sign_in, &config())).unwrap();
    let restored = Connection::from_bytes(&connection.to_bytes()).unwrap();
    assert_eq!(restored, connection);
    assert_eq!((restored.account(), restored.is_secure()), ("alice", true));

    // The device is now only reachable through the relay. The session belonged to the old address, so the move drops it
    // and the next operation signs in again there.
    server.reachable.clear();
    server.tunnel_open = true;
    let relay = endpoint(&relay_address(Region::ChinaMainland));
    let pinned = connection.with_pinned_certificate(cloudset::PinnedCertificate::from_slice(&[7; 32]).unwrap()).unwrap();
    let moved = pinned.with_endpoint(relay.clone()).unwrap();
    assert_eq!(moved.endpoint(), Some(&relay));
    assert!(moved.certificate_pin().is_none(), "a pin belongs to the old origin");
    let mut client = Client::new(moved, config());
    let requests = server.requests.len();
    run_op(&mut server, &mut client, |client| client.write(path("r.txt"), b"r".to_vec(), Precondition::None)).unwrap();
    let sent = &server.requests[requests..];
    assert!(String::from_utf8_lossy(&sent[0].body).contains("method=login"), "signs in on the new address first");
    assert!(sent.iter().all(|request| request.url.starts_with(&relay_address(Region::ChinaMainland))));

    let plain = Endpoint::parse("http://192.168.1.20:5000/", Transport::AllowInsecureHttp).unwrap();
    assert_eq!(client.connection().clone().with_endpoint(plain).err(), Some(CloudError::InsecureEndpoint), "no downgrade");
    let webdav = Connection::webdav(endpoint("https://dav.example.com/"), "a", "b");
    assert_eq!(webdav.with_endpoint(relay).err(), Some(CloudError::InvalidConnection));
}

#[test]
fn revoke_ends_the_session_and_drops_it_from_the_connection() {
    let mut server = MemorySynology::new(Region::Global);
    let mut client = sign_in(&mut server, "home");
    let signed_in = client.connection().clone();
    run_op(&mut server, &mut client, |client| client.revoke()).unwrap();
    assert!(String::from_utf8_lossy(&server.requests.last().unwrap().body).contains("method=logout"));
    assert_ne!(client.connection(), &signed_in, "the connection without the ended session is handed back");
    let requests = server.requests.len();
    run_op(&mut server, &mut client, |client| client.revoke()).unwrap();
    assert_eq!(server.requests.len(), requests, "nothing to end");
    // The stored password still signs in again; forgetting it means deleting the stored connection.
    assert!(run_op(&mut server, &mut client, |client| client.stat(path("a"))).unwrap().is_none());

    // A session that already ended on the device counts as revoked too.
    server.expire_sessions();
    run_op(&mut server, &mut client, |client| client.revoke()).unwrap();
}

#[test]
fn sessions_renew_after_the_client_address_changes_or_mid_operation() {
    let mut server = MemorySynology::new(Region::Global);
    let mut client = sign_in(&mut server, "home");
    server.put_external("home/a.txt", b"data");

    server.change_client_address();
    assert!(run_op(&mut server, &mut client, |client| client.stat(path("a.txt"))).unwrap().is_some(), "150 renews the session");

    server.expire_before_download = true;
    let file = run_op(&mut server, &mut client, |client| client.read(path("a.txt"))).unwrap().unwrap();
    assert_eq!(file.data, b"data", "the download is replayed after signing in again");

    server.refuse_sessions = true;
    assert_eq!(
        run_op(&mut server, &mut client, |client| client.stat(path("a.txt"))).err(),
        Some(CloudError::Provider { code: 107 }),
        "a session refused right after signing in is not a wrong password"
    );
}

#[test]
fn a_two_step_account_without_a_trusted_device_needs_the_user() {
    let mut server = MemorySynology::new(Region::Global);
    let mut client = sign_in(&mut server, "home");
    server.otp_code = Some("123456".into()); // two-step verification turned on after this device signed in
    server.expire_sessions();
    assert_eq!(run_op(&mut server, &mut client, |client| client.stat(path("a"))).err(), Some(CloudError::ReauthRequired));
}

#[test]
fn lists_page_by_page_within_the_entry_limit() {
    let mut server = MemorySynology::new(Region::Global);
    let mut client = sign_in(&mut server, "home");
    for index in 0..1001 {
        server.put_external(&format!("home/f{index:04}"), b"");
    }
    let entries = run_op(&mut server, &mut client, |client| client.list(RemotePath::root())).unwrap();
    assert_eq!((entries.len(), entries[1000].path.to_string()), (1001, "f1000".to_owned()));
    assert!(server.requests.iter().any(|request| String::from_utf8_lossy(&request.body).contains("offset=1000")));

    let mut limited = client.with_config(config().with_limits(cloudset::Limits::default().with_max_entries(10)));
    assert_eq!(run_op(&mut server, &mut limited, |client| client.list(RemotePath::root())).err(), Some(CloudError::TooLarge));
}

#[test]
fn unconfirmed_writes_and_moves() {
    let mut server = MemorySynology::new(Region::Global);
    let mut client = sign_in(&mut server, "home");
    server.lose_uploads = true;
    assert_eq!(
        run_op(&mut server, &mut client, |client| client.write(path("a.txt"), b"x".to_vec(), Precondition::None)).err(),
        Some(CloudError::CommitUnconfirmed),
        "the upload said yes but the file is not there"
    );
    server.lose_uploads = false;

    server.put_external("home/a.txt", b"a");
    server.mkdir_external("home/dir");
    server.mkdir_external("home/folder");

    // Another device takes the destination between the checks and the move.
    server.race_moves = true;
    assert_eq!(
        run_op(&mut server, &mut client, |client| client.rename(path("a.txt"), path("dir/a.txt"))).err(),
        Some(CloudError::PreconditionFailed),
        "a file moves whole or not at all"
    );
    assert_eq!(
        run_op(&mut server, &mut client, |client| client.rename(path("folder"), path("dir/folder"))).err(),
        Some(CloudError::CommitUnconfirmed),
        "a folder may have moved in part"
    );
    server.race_moves = false;

    // The rename after a move between folders fails: the item is left at the intermediate path.
    server.fail_renames = true;
    assert_eq!(
        run_op(&mut server, &mut client, |client| client.rename(path("a.txt"), path("dir/b.txt"))).err(),
        Some(CloudError::CommitUnconfirmed)
    );
    assert!(server.data("home/dir/a.txt").is_some());
    server.fail_renames = false;

    // The session expires mid-poll and DSM forgets the task: the move happened, but nothing can say so.
    server.expire_during_move = true;
    assert_eq!(
        run_op(&mut server, &mut client, |client| client.rename(path("dir/a.txt"), path("a.txt"))).err(),
        Some(CloudError::CommitUnconfirmed)
    );
    assert!(server.data("home/a.txt").is_some(), "it did move");
    run_op(&mut server, &mut client, |client| client.rename(path("a.txt"), path("dir/a.txt"))).unwrap();

    // A move that never finishes stops polling.
    server.move_polls = 1000;
    let before = server.requests.len();
    assert_eq!(
        run_op(&mut server, &mut client, |client| client.rename(path("dir/a.txt"), path("a.txt"))).err(),
        Some(CloudError::CommitUnconfirmed)
    );
    let polls = server.requests[before..].iter().filter(|request| String::from_utf8_lossy(&request.body).contains("method=status")).count();
    assert_eq!(polls, 600);
}
