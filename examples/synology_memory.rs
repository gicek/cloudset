//! QuickConnect resolution, relay fallback and two-step sign-in against the in-memory Synology device, with no network.
//! The device is registered in mainland China and the client is outside its network, so only the relay reaches it.
//!
//! Run with `cargo run --example synology_memory --features testing`.

use cloudset::synology::quickconnect::{self, Candidate, QuickConnectId, Region, Resolution};
use cloudset::synology::{self, SignIn};
use cloudset::testing::synology::{MemorySynology, SHARE};
use cloudset::{BoxOperation, Client, ClientConfig, CloudError, Precondition, RemotePath};

/// Runs one operation to completion. The closure is the transport: here the in-memory device, in an app an HTTP client.
fn run<T>(device: &mut MemorySynology, mut operation: BoxOperation<T>) -> Result<T, CloudError> {
    cloudset::run(operation.as_mut(), |request| device.handle(request)).map(|done| done.value)
}

/// The first candidate, in list order, that answers as this device. An app probes them concurrently with a timeout of a
/// few seconds each and counts a transport error as `false`.
fn reachable(device: &mut MemorySynology, resolution: &Resolution, candidates: &[Candidate], config: &ClientConfig) -> Option<Candidate> {
    candidates.iter().find(|candidate| run(device, resolution.probe(&candidate.endpoint, config)).unwrap_or(false)).cloned()
}

fn main() -> Result<(), CloudError> {
    let mut device = MemorySynology::new(Region::ChinaMainland);
    device.reachable.clear();
    device.otp_code = Some("246810".into());
    let config = ClientConfig::new("example/1.0");

    // The user typed an address on quickconnect.cn: start with the mainland China control host.
    let typed = "quickconnect.cn/cloudset-nas";
    let id = QuickConnectId::parse(typed)?;
    let region = Region::from_address(typed).unwrap_or(Region::Global);
    let resolution = run(&mut device, quickconnect::resolve(&id, region, &config))?;
    println!("{} is registered in {:?}, {} direct candidates", resolution.id(), resolution.region(), resolution.candidates().len());

    let endpoint = match reachable(&mut device, &resolution, resolution.candidates(), &config) {
        Some(candidate) => candidate.endpoint,
        None => {
            let relays = run(&mut device, resolution.request_relay(&config))?;
            reachable(&mut device, &resolution, &relays, &config).expect("the relay answers").endpoint
        }
    };
    println!("using {}", endpoint.as_str());

    // The account uses two-step verification: the first attempt says so, the second carries the code.
    let sign_in = SignIn::new(endpoint, RemotePath::parse(SHARE)?, "alice", "secret").with_quickconnect(id, resolution.region());
    let connection = match run(&mut device, synology::sign_in(sign_in.clone(), &config)) {
        Err(CloudError::OtpRequired) => run(&mut device, synology::sign_in(sign_in.with_otp_code("246810"), &config))?,
        other => other?,
    };
    // Store `connection.to_bytes()` in the keychain; later sessions renew without a code.
    let client = Client::new(connection, config);

    let path = RemotePath::parse("notes.txt")?;
    run(&mut device, client.write(path.clone(), b"hello from the relay".to_vec(), Precondition::Absent))?;
    let file = run(&mut device, client.read(path))?.expect("the file exists");
    println!("read {:?}", String::from_utf8_lossy(&file.data));
    Ok(())
}
