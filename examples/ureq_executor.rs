//! A real HTTP executor with `ureq`: lists a folder on a WebDAV server.
//!
//! ```text
//! CLOUDSET_URL=https://cloud.example.com/remote.php/dav/files/alice/ \
//! CLOUDSET_USER=alice CLOUDSET_PASSWORD=app-password \
//! cargo run --example ureq_executor -- Documents
//! ```
//!
//! It follows the executor contract in the README: send each request as is, never follow redirects, keep no cookies,
//! read at most `Limits::max_body_bytes + 1` bytes of a body, and report transport failures outside the crate.

#[path = "support/ureq.rs"]
mod transport;
use cloudset::{Client, ClientConfig, Connection, Endpoint, Method, RemotePath, Step, Transport};
use transport::Executor;

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name}"))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = Endpoint::parse(&env("CLOUDSET_URL"), Transport::RequireHttps)?;
    let connection = Connection::webdav(endpoint, env("CLOUDSET_USER"), env("CLOUDSET_PASSWORD"));
    let config = ClientConfig::new("cloudset-example/0.3");
    let executor = Executor::new(&config.limits);
    let client = Client::new(connection, config);

    let dir = match std::env::args().nth(1) {
        Some(path) => RemotePath::parse(&path)?,
        None => RemotePath::root(),
    };

    // The drive loop, written out instead of `cloudset::run`, because the transport can fail.
    let mut operation = client.list(dir);
    let mut response = None;
    let entries = loop {
        match operation.advance(response.take())? {
            Step::Send(request) => {
                debug_assert!(matches!(request.method, Method::Propfind));
                response = Some(executor.execute(request).map_err(|_| "HTTP transport failed")?);
            }
            Step::Done(done) => break done.value,
        }
    };
    for entry in entries {
        let kind = if entry.is_dir { "dir " } else { "file" };
        println!("{kind} {:>10} {}", entry.size.map(|size| size.to_string()).unwrap_or_default(), entry.path);
    }
    Ok(())
}
