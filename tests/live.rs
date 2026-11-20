//! Opt-in protocol smoke test using a disposable test account. See CONTRIBUTING.md.
#[path = "../examples/support/ureq.rs"]
mod transport;

use std::time::{SystemTime, UNIX_EPOCH};

use cloudset::{Client, ClientConfig, CloudError, Connection, Limits, Precondition, RemotePath, run_with_updates};
use zeroize::Zeroizing;

#[test]
#[ignore = "requires a disposable provider account"]
fn provider_round_trip() {
    let secret = Zeroizing::new(std::env::var("CLOUDSET_TEST_CONNECTION").expect("set CLOUDSET_TEST_CONNECTION"));
    let connection = Connection::from_bytes(secret.as_bytes()).unwrap();
    assert!(connection.is_secure() && connection.certificate_pin().is_none(), "requires system-trusted HTTPS");
    let limits = Limits::default().with_upload_chunk_bytes(320 * 1024);
    let config = ClientConfig::new("cloudset-live-test").with_limits(limits);
    let mut client = Client::new(connection, config);
    let executor = transport::Executor::new(&limits);
    let name = format!("cloudset-test-{}-{}.bin", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());
    let path = RemotePath::parse(&name).unwrap();
    macro_rules! drive {
        ($operation:expr) => {{
            let mut op = $operation;
            let mut update = None;
            let result = run_with_updates(
                op.as_mut(),
                |request| executor.execute(request).expect("HTTPS request failed"),
                |connection| update = Some(connection),
            );
            if let Some(update) = update {
                client = client.with_connection(update);
            }
            result
        }};
    }
    assert!(drive!(client.stat(path.clone())).unwrap().is_none());
    let bytes = vec![0x53; 5 * 1024 * 1024 + 1];
    let create = if client.supports_write_precondition(bytes.len(), &Precondition::Absent) {
        Precondition::Absent
    } else {
        assert_eq!(drive!(client.write(path.clone(), vec![1], Precondition::Absent)), Err(CloudError::UnsupportedPrecondition));
        Precondition::None
    };
    let entry = drive!(client.write(path.clone(), bytes.clone(), create)).unwrap();
    let file = drive!(client.read(path.clone())).unwrap().unwrap();
    assert!(file.data == bytes);
    if let Some(revision) = entry.revision {
        assert_eq!(file.entry.revision, Some(revision.clone()));
        let check = Precondition::Matches(revision);
        if client.supports_write_precondition(1, &check) {
            drive!(client.write(path.clone(), vec![2], check.clone())).unwrap();
            assert_eq!(drive!(client.write(path.clone(), vec![3], check)), Err(CloudError::PreconditionFailed));
        } else {
            // Expected only for WebDAV servers with weak ETags and for Google Drive.
            eprintln!("revision matches are unsupported for this connection");
            assert_eq!(drive!(client.write(path.clone(), vec![2], check)), Err(CloudError::UnsupportedPrecondition));
        }
    } else {
        eprintln!("the write returned no revision");
    }
    drive!(client.delete(path.clone())).unwrap();
    assert!(drive!(client.stat(path)).unwrap().is_none());
    drop(client);
}
