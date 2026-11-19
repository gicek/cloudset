//! Helpers shared by the integration tests: signing in to the in-memory OAuth providers and running operations.

#![allow(dead_code, unreachable_pub)]

use std::time::{Duration, UNIX_EPOCH};

use cloudset::oauth::begin;
use cloudset::testing::oauth::{DROPBOX_FULL_APP_KEY, FakeProvider, GOOGLE_APP_FOLDER, MemoryCloud};
use cloudset::{AccessScope, BoxOperation, Client, ClientConfig, CloudError, Connection, OAuthClient, ProviderKind, RemotePath};

pub const PROVIDERS: [FakeProvider; 3] = [FakeProvider::Dropbox, FakeProvider::OneDrive, FakeProvider::GoogleDrive];
pub const SCOPES: [AccessScope; 2] = [AccessScope::AppFolder, AccessScope::Full];

pub fn provider_kind(provider: FakeProvider) -> ProviderKind {
    match provider {
        FakeProvider::Dropbox => ProviderKind::Dropbox,
        FakeProvider::OneDrive => ProviderKind::OneDrive,
        FakeProvider::GoogleDrive => ProviderKind::GoogleDrive,
    }
}

pub fn config() -> ClientConfig {
    ClientConfig::new("cloudset-test/1").with_now(UNIX_EPOCH + Duration::from_secs(1_000))
}

pub fn sign_in(server: &mut MemoryCloud, access: AccessScope, config: &ClientConfig) -> Client {
    let client_id = match (server.provider, access) {
        (FakeProvider::Dropbox, AccessScope::Full) => DROPBOX_FULL_APP_KEY,
        _ => "client",
    };
    let client = OAuthClient::new(client_id, "com.example.app.oauth://callback").with_folder_name(GOOGLE_APP_FOLDER);
    let authorization = begin(provider_kind(server.provider), access, client, &[42; 64]).unwrap();
    let callback = server.authorize(authorization.url());
    let mut operation = authorization.complete(&callback, config).unwrap();
    let connection: Connection = cloudset::run(operation.as_mut(), |request| server.handle(request)).unwrap().value;
    Client::new(connection, config.clone())
}

pub fn path(text: &str) -> RemotePath {
    RemotePath::parse(text).unwrap()
}

/// Runs an operation to completion, switching to the new connection when it was refreshed.
pub fn run<T>(server: &mut MemoryCloud, client: &mut Client, make: impl FnOnce(&Client) -> BoxOperation<T>) -> Result<T, CloudError> {
    let mut operation = make(client);
    let done = cloudset::run(operation.as_mut(), |request| server.handle(request))?;
    if let Some(connection) = done.connection {
        *client = client.with_connection(connection);
    }
    Ok(done.value)
}
