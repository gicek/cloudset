//! Uploads to Google Drive: one request for small files, a resumable session for larger ones.

use serde_json::json;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{CloudError, FIELDS, HttpRequest, HttpResponse, Item, Method, Outgoing, UPLOAD, error_for, file_url, json_body, json_request};

/// Creates a file with its content in one request (`multipart/related`: JSON metadata, then the bytes). The boundary is
/// derived from a hash of the content, so it cannot occur in it.
pub(super) fn create_file(parent: &str, name: &str, data: &[u8]) -> Outgoing {
    let digest = Sha256::digest(data);
    let boundary = format!("cloudset-{}", digest[..16].iter().map(|byte| format!("{byte:02x}")).collect::<String>());
    let metadata = json!({ "name": name, "parents": [parent] });
    let mut body = format!(
        "--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{metadata}\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(data);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Outgoing::authorized(HttpRequest {
        method: Method::Post,
        url: format!("{UPLOAD}/files?uploadType=multipart&fields={FIELDS}"),
        headers: vec![
            ("Accept".into(), "application/json".into()),
            ("Content-Type".into(), format!("multipart/related; boundary={boundary}")),
        ],
        body,
    })
}

/// Replaces a file's content (a new head revision); the metadata is unchanged.
pub(super) fn upload_content(id: &str, data: Vec<u8>) -> Outgoing {
    Outgoing::authorized(HttpRequest {
        method: Method::Patch,
        url: file_url(UPLOAD, id, &format!("?uploadType=media&fields={FIELDS}")),
        headers: vec![("Accept".into(), "application/json".into()), ("Content-Type".into(), "application/octet-stream".into())],
        body: data,
    })
}

/// Single-request uploads (multipart create, media update) are meant for files up to 5 MiB; larger ones use a resumable
/// session.
pub(super) const SINGLE_REQUEST: usize = 5 * 1024 * 1024;
/// Resumable chunks must be multiples of 256 KiB.
pub(super) const CHUNK_UNIT: usize = 256 * 1024;

/// What an upload writes: a new file in a folder, or a new revision of an existing file.
pub(super) enum Target {
    New { parent: String, name: String },
    Existing { id: String },
}

pub(super) enum UploadState {
    Idle,
    /// A single request (multipart create or media update).
    Single,
    /// The resumable session is being opened.
    Opening,
    /// A chunk sent to the session URI.
    Chunk {
        session: String,
        start: usize,
    },
}

/// One upload: a single request for small files, a resumable session for larger ones (Drive's 308 "Resume Incomplete"
/// responses are progress, not redirects).
pub(super) struct Upload {
    target: Target,
    data: Zeroizing<Vec<u8>>,
    chunk: usize,
    state: UploadState,
}

pub(super) enum Uploaded {
    Send(Outgoing),
    Done(Item),
    /// The single request or the session opening failed with this response; the caller maps it.
    Failed(HttpResponse),
}

impl Upload {
    pub(super) fn new(target: Target, data: Vec<u8>, chunk: usize) -> Self {
        Self { target, data: Zeroizing::new(data), chunk, state: UploadState::Idle }
    }

    pub(super) fn start(&mut self) -> Outgoing {
        if self.data.len() <= self.chunk.min(SINGLE_REQUEST) {
            self.state = UploadState::Single;
            return match &self.target {
                Target::New { parent, name } => create_file(parent, name, &self.data),
                Target::Existing { id } => upload_content(id, self.data.to_vec()),
            };
        }
        self.state = UploadState::Opening;
        let request = match &self.target {
            Target::New { parent, name } => json_request(
                Method::Post,
                &format!("{UPLOAD}/files?uploadType=resumable&fields={FIELDS}"),
                Some(&json!({ "name": name, "parents": [parent] })),
            ),
            Target::Existing { id } => {
                json_request(Method::Patch, &file_url(UPLOAD, id, &format!("?uploadType=resumable&fields={FIELDS}")), Some(&json!({})))
            }
        };
        Outgoing::authorized(
            request
                .with_header("X-Upload-Content-Type", "application/octet-stream")
                .with_header("X-Upload-Content-Length", self.data.len().to_string()),
        )
    }

    pub(super) fn chunk(&mut self, session: String, start: usize) -> Outgoing {
        let end = start.saturating_add(self.chunk).min(self.data.len());
        let request = HttpRequest::new(Method::Put, session.clone())
            .with_header("Content-Range", format!("bytes {start}-{}/{}", end - 1, self.data.len()))
            .with_body(self.data[start..end].to_vec());
        self.state = UploadState::Chunk { session, start };
        Outgoing::authorized(request).without_redirects()
    }

    pub(super) fn receive(&mut self, response: HttpResponse) -> Result<Uploaded, CloudError> {
        match std::mem::replace(&mut self.state, UploadState::Idle) {
            UploadState::Single | UploadState::Opening if response.status != 200 => Ok(Uploaded::Failed(response)),
            UploadState::Single => {
                json_body(&response).and_then(|json| Item::parse(&json)).map(Uploaded::Done).map_err(|_| CloudError::CommitUnconfirmed)
            }
            UploadState::Opening => {
                let session = response.header("Location").ok_or(CloudError::InvalidResponse("upload session url"))?;
                if !crate::providers::is_api_url(crate::ProviderKind::GoogleDrive, session) {
                    return Err(CloudError::InvalidResponse("upload session url"));
                }
                Ok(Uploaded::Send(self.chunk(session.to_owned(), 0)))
            }
            UploadState::Chunk { session, start } => match response.status {
                200 | 201 => {
                    json_body(&response).and_then(|json| Item::parse(&json)).map(Uploaded::Done).map_err(|_| CloudError::CommitUnconfirmed)
                }
                308 => {
                    // `Range: bytes=0-N` is what the server has; continue after it. No progress means a broken session.
                    let next = response
                        .header("Range")
                        .and_then(|range| range.strip_prefix("bytes=0-"))
                        .and_then(|last| last.parse::<usize>().ok())
                        .and_then(|last| last.checked_add(1))
                        // Never past what was sent: skipping bytes would commit a file with a hole in it.
                        .filter(|next| *next > start && *next <= start.saturating_add(self.chunk).min(self.data.len() - 1))
                        .ok_or(CloudError::InvalidResponse("upload session range"))?;
                    Ok(Uploaded::Send(self.chunk(session, next)))
                }
                404 | 410 => Err(CloudError::InvalidResponse("upload session")),
                _ => Err(error_for(&response)),
            },
            UploadState::Idle => Err(CloudError::OutOfOrder),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multipart_boundary_comes_from_the_content() {
        let outgoing = create_file("parent", "data.bin", b"\x00content");
        let content_type = outgoing.request.header("Content-Type").unwrap().to_owned();
        let boundary = content_type.strip_prefix("multipart/related; boundary=").unwrap();
        assert!(boundary.starts_with("cloudset-") && boundary.len() == "cloudset-".len() + 32);
        let body = &outgoing.request.body;
        assert!(body.starts_with(format!("--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n").as_bytes()));
        assert!(body.ends_with(format!("\x00content\r\n--{boundary}--\r\n").as_bytes()));
        assert_ne!(create_file("parent", "data.bin", b"other").request.header("Content-Type"), Some(content_type.as_str()));
    }
}
