//! An async executor with `reqwest` and `tokio`: lists a folder on a WebDAV server.
//!
//! ```text
//! CLOUDSET_URL=https://cloud.example.com/remote.php/dav/files/alice/ \
//! CLOUDSET_USER=alice CLOUDSET_PASSWORD=app-password \
//! cargo run --example reqwest_executor -- Documents
//! ```
//!
//! Operations are plain state machines, so the async version is the same drive loop with an `.await` where the request is
//! sent. The executor follows the contract in the README: no redirects, no cookies, the body read up to
//! `Limits::max_body_bytes + 1` bytes, and transport errors kept out of the crate.

use std::time::Duration;

use cloudset::{Client, ClientConfig, Connection, Endpoint, HttpRequest, HttpResponse, Operation, RemotePath, Step, Transport};

struct Executor {
    http: reqwest::Client,
    max_body: usize,
}

impl Executor {
    fn new(max_body: usize) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none()) // 3xx goes back to the crate
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .build()?;
        Ok(Self { http, max_body })
    }

    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, Box<dyn std::error::Error>> {
        let method = reqwest::Method::from_bytes(request.method.as_str().as_bytes())?; // PROPFIND, MKCOL and MOVE too
        let mut builder = self.http.request(method, &request.url).body(request.body);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        let mut response = builder.send().await.map_err(reqwest::Error::without_url)?;
        let status = response.status().as_u16();
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .filter_map(|(name, value)| value.to_str().ok().map(|value| (name.as_str().to_owned(), value.to_owned())))
            .collect();
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(reqwest::Error::without_url)? {
            let remaining = self.max_body.saturating_add(1).saturating_sub(body.len());
            body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
            if body.len() > self.max_body {
                break; // the crate reports anything longer than the limit as `TooLarge`
            }
        }
        Ok(HttpResponse::new(status).with_headers(headers).with_body(body))
    }

    /// The drive loop, with an `.await` where the request goes out.
    async fn run<T>(&self, operation: &mut dyn Operation<Output = T>) -> Result<T, Box<dyn std::error::Error>> {
        let mut response = None;
        loop {
            match operation.advance(response.take())? {
                Step::Send(request) => response = Some(self.execute(request).await?),
                Step::Done(done) => return Ok(done.value),
            }
        }
    }
}

fn env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("set {name}"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // reqwest is built without a bundled crypto provider here; use ring, as the rest of the examples do.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let endpoint = Endpoint::parse(&env("CLOUDSET_URL")?, Transport::RequireHttps)?;
    let config = ClientConfig::new("cloudset-example/0.3");
    let executor = Executor::new(config.limits.max_body_bytes)?;
    let client = Client::new(Connection::webdav(endpoint, env("CLOUDSET_USER")?, env("CLOUDSET_PASSWORD")?), config);

    let dir = match std::env::args().nth(1) {
        Some(path) => RemotePath::parse(&path)?,
        None => RemotePath::root(),
    };
    for entry in executor.run(client.list(dir).as_mut()).await? {
        let kind = if entry.is_dir { "dir " } else { "file" };
        println!("{kind} {:>10} {}", entry.size.map(|size| size.to_string()).unwrap_or_default(), entry.path);
    }
    Ok(())
}
