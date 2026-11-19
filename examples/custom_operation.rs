//! A composite operation built from the crate's own: write a file and, when its folder is missing, create the folder
//! first and try again. It shows how to implement [`Operation`] with [`Subtask`] so that sub-operation errors come back
//! to the composer and connection updates (refreshed tokens) still reach the caller.
//!
//! Run with `cargo run --example custom_operation --features testing`.

use cloudset::testing::{BASE, MemoryDav};
use cloudset::{
    BoxOperation, Client, ClientConfig, CloudError, Connection, Done, Endpoint, Entry, HttpResponse, Operation, Precondition, Progress,
    RemotePath, Step, Subtask, Transport,
};

enum Stage {
    Writing { retried: bool },
    CreatingDir,
}

struct WriteCreatingDir {
    client: Client,
    path: RemotePath,
    data: Vec<u8>,
    stage: Stage,
    current: Option<Subtask<()>>,
    write: Option<Subtask<Entry>>,
    /// The latest connection a sub-operation produced; handed to the caller in `Done.connection`.
    connection: Option<Connection>,
}

impl WriteCreatingDir {
    fn start(client: Client, path: RemotePath, data: Vec<u8>) -> BoxOperation<Entry> {
        Box::new(Self { client, path, data, stage: Stage::Writing { retried: false }, current: None, write: None, connection: None })
    }

    /// The client with the latest connection, so a refreshed token is used by the next sub-operation.
    fn client(&self) -> Client {
        match &self.connection {
            Some(connection) => self.client.with_connection(connection.clone()),
            None => self.client.clone(),
        }
    }

    fn start_write(&mut self) -> Result<Step<Entry>, CloudError> {
        let operation = self.client().write(self.path.clone(), self.data.clone(), Precondition::None);
        let (subtask, progress) = Subtask::start(operation, &mut self.connection);
        self.write = Some(subtask);
        self.on_write(progress)
    }

    fn on_write(&mut self, progress: Progress<Entry>) -> Result<Step<Entry>, CloudError> {
        match progress {
            Progress::Send(request) => Ok(Step::Send(request)),
            Progress::Finished(Ok(entry)) => Ok(Step::Done(Done::new(entry).with_connection(self.connection.take()))),
            Progress::Finished(Err(CloudError::NotFound)) if matches!(self.stage, Stage::Writing { retried: false }) => {
                let parent = self.path.parent().ok_or(CloudError::NotFound)?;
                self.stage = Stage::CreatingDir;
                let (subtask, progress) = Subtask::start(self.client().create_dir(parent), &mut self.connection);
                self.current = Some(subtask);
                self.on_create_dir(progress)
            }
            Progress::Finished(Err(error)) => Err(error),
        }
    }

    fn on_create_dir(&mut self, progress: Progress<()>) -> Result<Step<Entry>, CloudError> {
        match progress {
            Progress::Send(request) => Ok(Step::Send(request)),
            Progress::Finished(Ok(())) => {
                self.stage = Stage::Writing { retried: true };
                self.start_write()
            }
            Progress::Finished(Err(error)) => Err(error),
        }
    }
}

impl Operation for WriteCreatingDir {
    type Output = Entry;

    fn advance(&mut self, response: Option<HttpResponse>) -> Result<Step<Entry>, CloudError> {
        match (&self.stage, response) {
            (Stage::Writing { .. }, None) if self.write.is_none() => self.start_write(),
            (Stage::Writing { .. }, Some(response)) => {
                let progress = self.write.as_mut().ok_or(CloudError::OutOfOrder)?.advance(Some(response), &mut self.connection);
                self.on_write(progress)
            }
            (Stage::CreatingDir, Some(response)) => {
                let progress = self.current.as_mut().ok_or(CloudError::OutOfOrder)?.advance(Some(response), &mut self.connection);
                self.on_create_dir(progress)
            }
            _ => Err(CloudError::OutOfOrder),
        }
    }
}

fn main() -> Result<(), CloudError> {
    let mut server = MemoryDav::new("Basic YWxpY2U6c2VjcmV0");
    let endpoint = Endpoint::parse(BASE, Transport::RequireHttps)?;
    let client = Client::new(Connection::webdav(endpoint, "alice", "secret"), ClientConfig::new("example/1.0"));

    // On WebDAV a plain write into a missing folder reports `NotFound`; the composite creates the folder first.
    let mut operation = WriteCreatingDir::start(client, RemotePath::parse("New folder/data.bin")?, b"hello".to_vec());
    let done = cloudset::run(operation.as_mut(), |request| server.handle(request))?;
    println!("wrote {} after {} requests", done.value.path, server.requests.len());
    assert_eq!(server.data("New folder/data.bin").as_deref(), Some(&b"hello"[..]));
    Ok(())
}
