use std::io::Read;
use std::time::Duration;

use cloudset::{HttpRequest, HttpResponse, Limits};

/// Why a request could not be sent; it never enters the crate.
#[derive(Debug)]
pub(crate) struct TransportError;

pub(crate) struct Executor {
    agent: ureq::Agent,
    max_body: usize,
}

impl Executor {
    pub(crate) fn new(limits: &Limits) -> Self {
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

    pub(crate) fn execute(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let mut builder = ureq::http::Request::builder().method(request.method.as_str()).uri(request.url.as_str());
        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let built = builder.body(request.body).map_err(|_| TransportError)?;
        let mut response = self.agent.run(built).map_err(|_| TransportError)?;
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
            .take((self.max_body as u64).saturating_add(1)) // anything longer is reported as `TooLarge` by the crate
            .read_to_end(&mut body)
            .map_err(|_| TransportError)?;
        Ok(HttpResponse::new(status).with_headers(headers).with_body(body))
    }
}
