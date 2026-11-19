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

use std::io::Read;
use std::time::Duration;

use cloudset::{Client, ClientConfig, Connection, Endpoint, HttpRequest, HttpResponse, Limits, Method, RemotePath, Step, Transport};

/// Why a request could not be sent; it never enters the crate.
#[derive(Debug)]
struct TransportError(String);

struct Executor {
    agent: ureq::Agent,
    max_body: usize,
}

impl Executor {
    fn new(limits: &Limits) -> Self {
        let tls = ureq::tls::TlsConfig::builder().root_certs(ureq::tls::RootCerts::PlatformVerifier).build();
        let config = ureq::Agent::config_builder()
            .max_redirects(0) // 3xx goes back to the crate, which only follows same-origin redirects
            .allow_non_standard_methods(true) // PROPFIND and MKCOL
            .http_status_as_error(false) // every status goes back to the crate
            .timeout_connect(Some(Duration::from_secs(10)))
            .timeout_global(Some(Duration::from_secs(60)))
            .tls_config(tls)
            .build();
        Self { agent: config.into(), max_body: limits.max_body_bytes }
    }

    fn execute(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let mut builder = ureq::http::Request::builder().method(request.method.as_str()).uri(request.url.as_str());
        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let built = builder.body(request.body).map_err(|error| TransportError(error.to_string()))?;
        let mut response = self.agent.run(built).map_err(|error| TransportError(error.to_string()))?;
        let status = response.status().as_u16();
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .filter_map(|(name, value)| value.to_str().ok().map(|value| (name.as_str().to_owned(), value.to_owned())))
            .collect();
        let mut body = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(self.max_body as u64 + 1) // anything longer is reported as `TooLarge` by the crate
            .read_to_end(&mut body)
            .map_err(|error| TransportError(error.to_string()))?;
        Ok(HttpResponse::new(status).with_headers(headers).with_body(body))
    }
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name}"))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = Endpoint::parse(&env("CLOUDSET_URL"), Transport::RequireHttps)?;
    let connection = Connection::webdav(endpoint, env("CLOUDSET_USER"), env("CLOUDSET_PASSWORD"));
    let config = ClientConfig::new("cloudset-example/0.2");
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
                response = Some(executor.execute(request).map_err(|error| format!("transport: {}", error.0))?);
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
