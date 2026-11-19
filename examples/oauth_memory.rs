//! OAuth 2.0 + PKCE sign-in and an automatic token refresh against an in-memory Dropbox, with no network.
//!
//! Run with `cargo run --example oauth_memory --features testing`.

use std::time::{Duration, UNIX_EPOCH};

use cloudset::testing::oauth::{FakeProvider, MemoryCloud};
use cloudset::{AccessScope, Client, ClientConfig, CloudError, OAuthClient, Precondition, ProviderKind, RemotePath, oauth};

fn main() -> Result<(), CloudError> {
    let mut server = MemoryCloud::new(FakeProvider::Dropbox);
    // The crate never reads the clock: pass the current time to refresh tokens before they expire.
    let config = ClientConfig::new("example/1.0").with_now(UNIX_EPOCH + Duration::from_secs(1_000));

    // 1. Start the sign-in. In an app, take these 64 bytes from a CSPRNG.
    let random = [7u8; 64];
    let client_id = OAuthClient::new("app-key", "com.example.app.oauth://callback");
    let access = ProviderKind::Dropbox.access_scopes()[0];
    assert_eq!(access, AccessScope::AppFolder);
    let authorization = oauth::begin(ProviderKind::Dropbox, access, client_id, &random)?;

    // 2. Open `authorization.url()` in the system authentication session (ASWebAuthenticationSession, a browser with a
    //    loopback or custom scheme redirect, ...). The in-memory server plays the user and returns the callback URL.
    let callback = server.authorize(authorization.url());
    assert!(authorization.accepts(&callback));

    // 3. Complete: checks the callback and `state`, exchanges the code and looks up the account name.
    let mut exchange = authorization.complete(&callback, &config)?;
    let connection = cloudset::run(exchange.as_mut(), |request| server.handle(request))?.value;
    println!("signed in as {}", connection.account());

    let mut client = Client::new(connection, config);
    let path = RemotePath::parse("notes.txt")?;
    let mut write = client.write(path.clone(), b"hello".to_vec(), Precondition::None);
    cloudset::run(write.as_mut(), |request| server.handle(request))?;

    // 4. The access token stops working; the next operation refreshes it, replays the request once, and hands the new
    //    connection back in `Done.connection`. Replace the stored copy with it.
    server.expire_access_token();
    let mut read = client.read(path);
    let done = cloudset::run(read.as_mut(), |request| server.handle(request))?;
    if let Some(refreshed) = done.connection {
        println!("token refreshed; store the new connection");
        client = client.with_connection(refreshed);
    }
    let file = done.value.expect("the file exists");
    println!("read {:?}", String::from_utf8_lossy(&file.data));

    // 5. Signing out: revoke the token on the server, then delete the stored connection.
    let mut revoke = client.revoke();
    cloudset::run(revoke.as_mut(), |request| server.handle(request))?;
    assert!(server.revoked);
    Ok(())
}
