//! Large files: chunked uploads through Dropbox, OneDrive and Google Drive upload sessions, with every precondition,
//! a token refresh in the middle of a session, and a server that stops making progress.

mod common;

use cloudset::testing::oauth::{FakeProvider, MemoryCloud};
use cloudset::{AccessScope, CloudError, HttpResponse, Limits, Precondition};
use common::{PROVIDERS, SCOPES, config, path, run, sign_in};

/// Over every provider's smallest chunk (4 MiB on Dropbox) and Google Drive's 5 MiB single-request limit.
const SIZE: usize = 9 * 1024 * 1024 + 123;

fn large(seed: u8) -> Vec<u8> {
    (0..SIZE).map(|index| (index % 251) as u8 ^ seed).collect()
}

/// The smallest chunk each provider accepts, so a 9 MiB file takes several requests everywhere.
fn chunked() -> cloudset::ClientConfig {
    config().with_limits(Limits::default().with_upload_chunk_bytes(1))
}

/// The most bytes one request may carry with [`chunked`], and the endpoint that marks an upload session.
fn expectations(provider: FakeProvider) -> (usize, &'static str) {
    match provider {
        FakeProvider::Dropbox => (4 * 1024 * 1024, "upload_session"),
        FakeProvider::OneDrive => (320 * 1024, "upload.example.net"),
        FakeProvider::GoogleDrive => (256 * 1024, "uploadType=resumable"),
    }
}

#[test]
fn large_files_go_up_in_chunks_with_every_precondition() {
    for provider in PROVIDERS {
        for access in SCOPES {
            let case = format!("{provider:?}/{access:?}");
            let mut server = MemoryCloud::new(provider);
            let mut client = sign_in(&mut server, access, &chunked());
            let first = server.requests.len();
            let (max_body, marker) = expectations(provider);

            let create = if provider == FakeProvider::GoogleDrive { Precondition::None } else { Precondition::Absent };
            let created = run(&mut server, &mut client, |c| c.write(path("Big/data.bin"), large(1), create)).unwrap();
            assert_eq!(created.size, Some(SIZE as u64), "{case}");
            assert_eq!(server.data(&server.storage_path("Big/data.bin")), Some(large(1)), "{case}");
            let sent = &server.requests[first..];
            assert!(sent.iter().any(|request| request.url.contains(marker)), "{case}: used an upload session");
            assert!(sent.iter().all(|request| request.body.len() <= max_body + 1024), "{case}: no request over one chunk");

            let file = run(&mut server, &mut client, |c| c.read(path("Big/data.bin"))).unwrap().unwrap();
            assert_eq!((file.data == large(1), file.entry.revision.is_some()), (true, true), "{case}: reads back");

            if provider == FakeProvider::GoogleDrive {
                continue;
            }
            let again = run(&mut server, &mut client, |c| c.write(path("Big/data.bin"), large(2), Precondition::Absent));
            assert_eq!(again.err(), Some(CloudError::PreconditionFailed), "{case}: Absent on an existing file");

            let revision = file.entry.revision.clone().unwrap();
            if provider == FakeProvider::OneDrive {
                let before = server.requests.len();
                let refused = run(&mut server, &mut client, |c| c.write(path("Big/data.bin"), large(3), Precondition::Matches(revision)));
                assert_eq!(refused.err(), Some(CloudError::UnsupportedPrecondition));
                assert_eq!(server.requests.len(), before);
                run(&mut server, &mut client, |c| c.write(path("Big/data.bin"), large(5), Precondition::None)).unwrap();
                assert_eq!(server.data(&server.storage_path("Big/data.bin")), Some(large(5)));
                continue;
            }
            let updated =
                run(&mut server, &mut client, |c| c.write(path("Big/data.bin"), large(3), Precondition::Matches(revision.clone())))
                    .unwrap();
            assert_ne!(updated.revision, Some(revision.clone()), "{case}");
            assert_eq!(server.data(&server.storage_path("Big/data.bin")), Some(large(3)), "{case}");

            let stale = run(&mut server, &mut client, |c| c.write(path("Big/data.bin"), large(4), Precondition::Matches(revision)));
            assert_eq!(stale.err(), Some(CloudError::PreconditionFailed), "{case}: stale revision");
            assert_eq!(server.data(&server.storage_path("Big/data.bin")), Some(large(3)), "{case}: unchanged after the conflict");

            run(&mut server, &mut client, |c| c.write(path("Big/data.bin"), large(5), Precondition::None)).unwrap();
            assert_eq!(server.data(&server.storage_path("Big/data.bin")), Some(large(5)), "{case}: unconditional overwrite");
        }
    }
}

#[test]
fn small_files_stay_single_requests() {
    for provider in PROVIDERS {
        let mut server = MemoryCloud::new(provider);
        let mut client = sign_in(&mut server, AccessScope::AppFolder, &config());
        let first = server.requests.len();
        run(&mut server, &mut client, |c| c.write(path("small.bin"), vec![7; 64 * 1024], Precondition::None)).unwrap();
        let (_, marker) = expectations(provider);
        assert!(server.requests[first..].iter().all(|request| !request.url.contains(marker)), "{provider:?}");
    }
}

#[test]
fn a_token_refresh_in_the_middle_of_a_session_replays_the_chunk() {
    for provider in PROVIDERS {
        let mut server = MemoryCloud::new(provider);
        let mut client = sign_in(&mut server, AccessScope::AppFolder, &chunked());
        let mut operation = client.write(path("data.bin"), large(9), Precondition::None);
        let mut sent = 0;
        let done = cloudset::run(operation.as_mut(), |request| {
            sent += 1;
            if sent == 2 {
                server.expire_access_token();
            }
            server.handle(request)
        })
        .unwrap();
        assert_eq!(server.data(&server.storage_path("data.bin")), Some(large(9)), "{provider:?}");
        // OneDrive's chunks go to a pre-signed URL without credentials, so its token is only refreshed on the next call.
        if provider != FakeProvider::OneDrive {
            assert!(done.connection.is_some(), "{provider:?}: the refreshed connection comes back");
        }
        client = client.with_connection(done.connection.unwrap_or_else(|| client.connection().clone()));
        assert!(run(&mut server, &mut client, |c| c.stat(path("data.bin"))).unwrap().is_some());
    }
}

#[test]
fn a_session_without_progress_fails_instead_of_looping() {
    for provider in [FakeProvider::OneDrive, FakeProvider::GoogleDrive] {
        let mut server = MemoryCloud::new(provider);
        let client = sign_in(&mut server, AccessScope::AppFolder, &chunked());
        let mut operation = client.write(path("data.bin"), large(1), Precondition::None);
        // A proxy that strips the progress information from every intermediate response.
        let result = cloudset::run(operation.as_mut(), |request| {
            let response = server.handle(request);
            match response.status {
                202 => HttpResponse::new(202).with_body(b"{}".to_vec()),
                308 => HttpResponse::new(308),
                _ => response,
            }
        });
        assert!(matches!(result, Err(CloudError::InvalidResponse(_))), "{provider:?}: {result:?}");
    }
}

#[test]
fn google_large_upload_refuses_a_version_condition_before_sending_data() {
    let mut server = MemoryCloud::new(FakeProvider::GoogleDrive);
    let mut client = sign_in(&mut server, AccessScope::AppFolder, &chunked());
    let written = run(&mut server, &mut client, |c| c.write(path("data.bin"), large(1), Precondition::None)).unwrap();
    let before = server.requests.len();
    let result = run(&mut server, &mut client, |c| c.write(path("data.bin"), large(2), Precondition::Matches(written.revision.unwrap())));
    assert_eq!(result.err(), Some(CloudError::UnsupportedPrecondition));
    assert_eq!(server.requests.len(), before);
    assert_eq!(server.data(&server.storage_path("data.bin")), Some(large(1)));
}

#[test]
fn chunk_sizes_round_down_to_what_each_provider_accepts() {
    for provider in PROVIDERS {
        let mut server = MemoryCloud::new(provider);
        let config = config().with_limits(Limits::default().with_upload_chunk_bytes(5 * 1024 * 1024 + 1));
        let mut client = sign_in(&mut server, AccessScope::AppFolder, &config);
        let first = server.requests.len();
        run(&mut server, &mut client, |c| c.write(path("data.bin"), large(1), Precondition::None)).unwrap();
        let (unit, marker) = expectations(provider);
        let chunks: Vec<usize> = server.requests[first..]
            .iter()
            .filter(|request| request.url.contains(marker) && request.body.len() > 1024)
            .map(|request| request.body.len())
            .collect();
        assert!(!chunks.is_empty(), "{provider:?}");
        for size in &chunks[..chunks.len() - 1] {
            assert_eq!(size % unit, 0, "{provider:?}: {size}");
            assert!(*size <= 5 * 1024 * 1024 + 1, "{provider:?}: {size}");
        }
    }
}

#[test]
fn a_server_claiming_more_than_was_sent_is_refused() {
    for provider in [FakeProvider::OneDrive, FakeProvider::GoogleDrive] {
        let mut server = MemoryCloud::new(provider);
        let client = sign_in(&mut server, AccessScope::AppFolder, &chunked());
        let mut operation = client.write(path("data.bin"), large(1), Precondition::None);
        // A broken proxy that reports bytes it never received.
        let result = cloudset::run(operation.as_mut(), |request| {
            let response = server.handle(request);
            match response.status {
                202 => HttpResponse::new(202).with_body(br#"{"nextExpectedRanges":["8000000-"]}"#.to_vec()),
                308 => HttpResponse::new(308).with_header("Range", "bytes=0-7999999"),
                _ => response,
            }
        });
        assert!(matches!(result, Err(CloudError::InvalidResponse(_))), "{provider:?}: {result:?}");
        assert!(!server.exists(&server.storage_path("data.bin")), "{provider:?}: nothing with a hole was committed");
    }
}

#[test]
fn onedrive_clamps_chunks_strictly_below_sixty_mib() {
    let unit = 320 * 1024;
    // Force a session above the simple-upload threshold without recording a huge request in MemoryCloud.
    let mut server = MemoryCloud::new(FakeProvider::OneDrive);
    let config = config().with_limits(Limits::default().with_upload_chunk_bytes(60 * 1024 * 1024));
    let client = sign_in(&mut server, AccessScope::AppFolder, &config);
    let mut operation = client.write(path("large.bin"), vec![0; 60 * 1024 * 1024 + 1], Precondition::None);
    let cloudset::Step::Send(open) = operation.advance(None).unwrap() else { panic!("expected upload session") };
    let cloudset::Step::Send(chunk) = operation.advance(Some(server.handle(open))).unwrap() else { panic!("expected first chunk") };
    assert_eq!(chunk.body.len(), 60 * 1024 * 1024 - unit);
}

/// "Send it in one piece" must not overflow when the server acknowledges only part of that piece.
#[test]
fn google_resumes_after_a_partial_chunk_with_an_unbounded_chunk_size() {
    let mut server = MemoryCloud::new(FakeProvider::GoogleDrive);
    let unbounded = config().with_limits(Limits::default().with_upload_chunk_bytes(usize::MAX));
    let client = sign_in(&mut server, AccessScope::AppFolder, &unbounded);
    let data = large(3);
    let mut interrupted = false;
    let mut operation = client.write(path("data.bin"), data.clone(), Precondition::None);
    let result = cloudset::run(operation.as_mut(), |request| {
        if !interrupted && request.method == cloudset::Method::Put {
            interrupted = true;
            // Only the first MiB arrived; the server never saw the rest of this request.
            let mut partial = request.clone();
            partial.body.truncate(1024 * 1024);
            partial.headers.retain(|(name, _)| !name.eq_ignore_ascii_case("Content-Range"));
            partial.headers.push(("Content-Range".into(), format!("bytes 0-{}/{}", 1024 * 1024 - 1, SIZE)));
            return server.handle(partial);
        }
        server.handle(request)
    });
    assert!(interrupted);
    result.unwrap();
    assert_eq!(server.data(&server.storage_path("data.bin")), Some(data));
}

/// A pre-signed URL carries no token: its refusals say nothing about the sign-in, the permissions or the path.
#[test]
fn onedrive_presigned_url_refusals_are_server_errors() {
    for status in [400, 401, 403] {
        let mut server = MemoryCloud::new(FakeProvider::OneDrive);
        let client = sign_in(&mut server, AccessScope::AppFolder, &chunked());
        let mut write = client.write(path("data.bin"), large(1), Precondition::None);
        let result = cloudset::run(write.as_mut(), |request| {
            if request.url.contains("upload.example.net") {
                return HttpResponse::new(status).with_body(br#"{"error":{"code":"invalidRequest"}}"#.to_vec());
            }
            server.handle(request)
        });
        assert_eq!(result.err(), Some(CloudError::Server { status }));

        let mut client = client;
        run(&mut server, &mut client, |c| c.write(path("small.bin"), vec![1], Precondition::None)).unwrap();
        let mut read = client.read(path("small.bin"));
        let result = cloudset::run(read.as_mut(), |request| {
            if request.header("Authorization").is_none() { HttpResponse::new(status) } else { server.handle(request) }
        });
        assert_eq!(result.err(), Some(CloudError::Server { status }));
    }
}
