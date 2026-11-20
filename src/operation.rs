//! Operation state machines: the crate does no IO; every operation is a loop of "emit a request -> receive the
//! response -> emit the next request or a result".
//!
//! ```text
//! let mut response = None;
//! loop {
//!     match operation.advance(response.take())? {
//!         Step::Send(request) => response = Some(execute(request)),
//!         Step::Done(done) => break done,
//!     }
//! }
//! ```

use crate::connection::Connection;
use crate::error::CloudError;
use crate::http::{Exchange, HttpRequest, HttpResponse, Limits, Origin, Received};

/// What an operation wants next: a request to execute, or its result.
///
/// This enum is deliberately exhaustive: an operation only ever sends a request or finishes, so a drive loop can match
/// both variants without a wildcard arm.
#[derive(Debug)]
pub enum Step<T> {
    /// Execute this request and pass the response to the next [`Operation::advance`].
    Send(HttpRequest),
    /// The operation finished.
    Done(Done<T>),
}

/// The result of a finished operation.
#[derive(Debug)]
#[non_exhaustive]
pub struct Done<T> {
    /// The operation's result.
    pub value: T,
    /// A changed connection, such as one with a refreshed OAuth token. When it is set, replace the stored connection
    /// with it; the old one may no longer work.
    pub connection: Option<Connection>,
}

impl<T> Done<T> {
    /// A result without a connection change.
    #[must_use]
    pub fn new(value: T) -> Self {
        Self { value, connection: None }
    }

    /// Attaches a changed connection.
    #[must_use]
    pub fn with_connection(mut self, connection: Option<Connection>) -> Self {
        self.connection = connection;
        self
    }
}

/// A sans-IO state machine for one unit of work, such as reading a file.
///
/// Call [`advance`](Operation::advance) with `None` first, then with the response to each request it returns, until it
/// returns [`Step::Done`] or an error. Dropping an operation cancels it; nothing else needs cleaning up.
#[must_use = "an operation does nothing until it is advanced"]
pub trait Operation: Send {
    /// The result type.
    type Output;

    /// Takes a newly refreshed connection. Call after every advance, including an error, before sending the next request.
    /// Persist it immediately so cancelling an operation or losing transport cannot discard a rotated credential.
    /// For drivers that do not take updates early, a successful operation returns the update in [`Done::connection`].
    fn take_connection(&mut self) -> Option<Connection> {
        None
    }

    /// Advances the operation. Pass `None` on the first call, then the response to the previous request. Calling it
    /// again after it returned [`Step::Done`] or an error reports [`CloudError::OutOfOrder`].
    ///
    /// # Errors
    ///
    /// Any [`CloudError`] the protocol produces: an error status, an invalid response, a refused redirect, and so on.
    fn advance(&mut self, response: Option<HttpResponse>) -> Result<Step<Self::Output>, CloudError>;
}

/// A boxed operation, as returned by [`crate::Client`].
pub type BoxOperation<T> = Box<dyn Operation<Output = T>>;

/// Runs an operation to completion with a synchronous transport function that cannot fail, such as an in-memory test
/// server. For a real network, write the loop yourself so the transport can report its own errors (see the README).
///
/// A connection update only comes back in [`Done::connection`]: when the operation fails after refreshing a token,
/// the update is dropped. Use [`run_with_updates`] wherever a rotated credential must survive that.
///
/// # Errors
///
/// The first error the operation reports.
///
/// ```
/// # use cloudset::{run, Client, ClientConfig, Connection, Endpoint, HttpResponse, RemotePath, Transport};
/// let endpoint = Endpoint::parse("https://dav.example.com/", Transport::RequireHttps)?;
/// let client = Client::new(Connection::webdav(endpoint, "alice", "secret"), ClientConfig::new("example/1.0"));
/// let mut stat = client.stat(RemotePath::parse("missing.txt")?);
/// let done = run(stat.as_mut(), |_request| HttpResponse::new(404))?;
/// assert!(done.value.is_none());
/// # Ok::<(), cloudset::CloudError>(())
/// ```
pub fn run<T>(
    operation: &mut dyn Operation<Output = T>,
    mut transport: impl FnMut(HttpRequest) -> HttpResponse,
) -> Result<Done<T>, CloudError> {
    let mut response = None;
    loop {
        match operation.advance(response.take())? {
            Step::Send(request) => response = Some(transport(request)),
            Step::Done(done) => return Ok(done),
        }
    }
}

/// Like [`run`], but hands every connection update to `store` as soon as it exists and before the next request is
/// sent, so a rotated credential survives an operation that fails afterwards. The update never comes back a second
/// time in the result.
///
/// # Errors
///
/// The first error the operation reports.
///
/// ```
/// # use cloudset::{run_with_updates, Client, ClientConfig, Connection, Endpoint, HttpResponse, RemotePath, Transport};
/// # let endpoint = Endpoint::parse("https://dav.example.com/", Transport::RequireHttps)?;
/// # let client = Client::new(Connection::webdav(endpoint, "alice", "secret"), ClientConfig::new("example/1.0"));
/// let mut latest = None;
/// let mut stat = client.stat(RemotePath::parse("missing.txt")?);
/// let entry = run_with_updates(stat.as_mut(), |_request| HttpResponse::new(404), |connection| latest = Some(connection))?;
/// assert!(entry.is_none() && latest.is_none());
/// # Ok::<(), cloudset::CloudError>(())
/// ```
pub fn run_with_updates<T>(
    operation: &mut dyn Operation<Output = T>,
    mut transport: impl FnMut(HttpRequest) -> HttpResponse,
    mut store: impl FnMut(Connection),
) -> Result<T, CloudError> {
    let mut response = None;
    loop {
        let step = operation.advance(response.take());
        if let Some(connection) = operation.take_connection() {
            store(connection);
        }
        match step? {
            Step::Send(request) => response = Some(transport(request)),
            Step::Done(done) => {
                if let Some(connection) = done.connection {
                    store(connection);
                }
                return Ok(done.value);
            }
        }
    }
}

/// Send state of one request (including redirects).
pub(crate) struct Call {
    exchange: Exchange,
    origin: Origin,
    limits: Limits,
    sent: bool,
    /// The final response or an error was handed out: every further call is out of order.
    finished: bool,
}

pub(crate) enum CallStep {
    Send(HttpRequest),
    Response(HttpResponse),
}

impl Call {
    pub(crate) fn new(request: HttpRequest, origin: Origin, limits: Limits) -> Self {
        Self { exchange: Exchange::new(request), origin, limits, sent: false, finished: false }
    }

    /// Hands 3xx responses back instead of following them.
    pub(crate) fn without_redirects(mut self) -> Self {
        self.exchange = self.exchange.without_redirects();
        self
    }

    pub(crate) fn advance(&mut self, response: Option<HttpResponse>) -> Result<CallStep, CloudError> {
        let step = match (self.sent, response) {
            _ if self.finished => Err(CloudError::OutOfOrder),
            (false, None) => {
                self.sent = true;
                Ok(CallStep::Send(self.exchange.request()))
            }
            (true, Some(response)) => self.exchange.receive(response, &self.origin, &self.limits).map(|received| match received {
                Received::Resend(request) => CallStep::Send(request),
                Received::Final(response) => CallStep::Response(response),
            }),
            _ => Err(CloudError::OutOfOrder),
        };
        self.finished = !matches!(step, Ok(CallStep::Send(_)));
        step
    }
}

/// An operation with a single request: the final response goes to `interpret`.
pub(crate) struct Single<T, F> {
    call: Call,
    interpret: Option<F>,
    _output: std::marker::PhantomData<fn() -> T>,
}

impl<T, F> Single<T, F>
where
    F: FnOnce(HttpResponse) -> Result<T, CloudError> + Send,
{
    pub(crate) fn new(call: Call, interpret: F) -> Self {
        Self { call, interpret: Some(interpret), _output: std::marker::PhantomData }
    }
}

impl<T, F> Operation for Single<T, F>
where
    F: FnOnce(HttpResponse) -> Result<T, CloudError> + Send,
{
    type Output = T;

    fn advance(&mut self, response: Option<HttpResponse>) -> Result<Step<T>, CloudError> {
        match self.call.advance(response)? {
            CallStep::Send(request) => Ok(Step::Send(request)),
            CallStep::Response(response) => {
                let interpret = self.interpret.take().ok_or(CloudError::OutOfOrder)?;
                Ok(Step::Done(Done::new(interpret(response)?)))
            }
        }
    }
}

/// An operation that needs no request and yields its result directly (for providers without a revocation endpoint, for
/// example).
pub(crate) struct Ready<T>(Option<Result<T, CloudError>>);

impl<T> Ready<T> {
    pub(crate) fn ok(value: T) -> Self {
        Self(Some(Ok(value)))
    }

    pub(crate) fn err(error: CloudError) -> Self {
        Self(Some(Err(error)))
    }
}

impl<T: Send> Operation for Ready<T> {
    type Output = T;

    fn advance(&mut self, response: Option<HttpResponse>) -> Result<Step<T>, CloudError> {
        if response.is_some() {
            return Err(CloudError::OutOfOrder);
        }
        Ok(Step::Done(Done::new(self.0.take().ok_or(CloudError::OutOfOrder)??)))
    }
}

/// Maps an operation's result to another type, leaving its requests and connection changes as they are.
///
/// ```
/// # use cloudset::{map, run, Client, ClientConfig, Connection, Endpoint, HttpResponse, RemotePath, Transport};
/// # let endpoint = Endpoint::parse("https://dav.example.com/", Transport::RequireHttps)?;
/// # let client = Client::new(Connection::webdav(endpoint, "alice", "secret"), ClientConfig::new("example/1.0"));
/// let mut exists = map(client.stat(RemotePath::parse("a.txt")?), |entry| entry.is_some());
/// assert!(!run(exists.as_mut(), |_| HttpResponse::new(404))?.value);
/// # Ok::<(), cloudset::CloudError>(())
/// ```
pub fn map<T: 'static, U: 'static>(operation: BoxOperation<T>, transform: impl FnMut(T) -> U + Send + 'static) -> BoxOperation<U> {
    Box::new(Map { operation, transform })
}

struct Map<T, F> {
    operation: BoxOperation<T>,
    transform: F,
}

impl<T, U, F: FnMut(T) -> U + Send> Operation for Map<T, F> {
    type Output = U;

    fn take_connection(&mut self) -> Option<Connection> {
        self.operation.take_connection()
    }

    fn advance(&mut self, response: Option<HttpResponse>) -> Result<Step<U>, CloudError> {
        Ok(match self.operation.advance(response)? {
            Step::Send(request) => Step::Send(request),
            Step::Done(done) => Step::Done(Done { value: (self.transform)(done.value), connection: done.connection }),
        })
    }
}

/// One sub-operation inside a composite operation.
///
/// It hands the sub-operation's errors back to the composer to decide on (creating a missing directory first, for
/// example) and records connection changes so the composer can pass them on in [`Done::connection`]. See the
/// `custom_operation` example.
pub struct Subtask<T> {
    operation: BoxOperation<T>,
}

/// What a [`Subtask`] wants next.
#[derive(Debug)]
pub enum Progress<T> {
    /// Return this request from the composite operation's `advance`.
    Send(HttpRequest),
    /// The sub-operation finished, successfully or not.
    Finished(Result<T, CloudError>),
}

impl<T> std::fmt::Debug for Subtask<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subtask").finish_non_exhaustive()
    }
}

impl<T> Subtask<T> {
    /// Starts the sub-operation and returns its first step.
    pub fn start(operation: BoxOperation<T>, connection: &mut Option<Connection>) -> (Self, Progress<T>) {
        let mut subtask = Self { operation };
        let progress = subtask.advance(None, connection);
        (subtask, progress)
    }

    /// Advances the sub-operation; if it finishes with a new connection, writes it to `connection`.
    pub fn advance(&mut self, response: Option<HttpResponse>, connection: &mut Option<Connection>) -> Progress<T> {
        let result = self.operation.advance(response);
        if let Some(update) = self.operation.take_connection() {
            *connection = Some(update);
        }
        match result {
            Ok(Step::Send(request)) => Progress::Send(request),
            Ok(Step::Done(done)) => {
                if done.connection.is_some() {
                    *connection = done.connection;
                }
                Progress::Finished(Ok(done.value))
            }
            Err(error) => Progress::Finished(Err(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::{Endpoint, Transport};

    /// An operation that sends one request, then finishes with a new connection after the response (simulates a token
    /// refresh).
    struct Refreshing(bool);

    impl Operation for Refreshing {
        type Output = u8;

        fn advance(&mut self, response: Option<HttpResponse>) -> Result<Step<u8>, CloudError> {
            match (self.0, response) {
                (false, None) => {
                    self.0 = true;
                    Ok(Step::Send(HttpRequest {
                        method: crate::Method::Get,
                        url: "https://x/".into(),
                        headers: Vec::new(),
                        body: Vec::new(),
                    }))
                }
                (true, Some(_)) => Ok(Step::Done(Done { value: 7, connection: Some(refreshed()) })),
                _ => Err(CloudError::OutOfOrder),
            }
        }
    }

    fn refreshed() -> Connection {
        Connection::webdav(Endpoint::parse("https://x/", Transport::RequireHttps).unwrap(), "u", "new")
    }

    #[test]
    fn map_and_subtask_carry_connection_updates() {
        let mut mapped = map(Box::new(Refreshing(false)), |value| value * 2);
        let done = run(mapped.as_mut(), |_| HttpResponse::new(200)).unwrap();
        assert_eq!((done.value, done.connection), (14, Some(refreshed())));

        let mut latest = None;
        let (mut subtask, progress) = Subtask::start(Box::new(Refreshing(false)), &mut latest);
        assert!(matches!(progress, Progress::Send(_)));
        assert!(latest.is_none());
        assert!(matches!(subtask.advance(Some(HttpResponse::new(200)), &mut latest), Progress::Finished(Ok(7))));
        assert_eq!(latest, Some(refreshed()));
        assert!(matches!(subtask.advance(None, &mut latest), Progress::Finished(Err(CloudError::OutOfOrder))));
        assert_eq!(latest, Some(refreshed()), "a failing sub-operation must not clear the recorded connection");
    }

    #[test]
    fn ready_operations() {
        let mut ok = Ready::ok(1u8);
        assert!(matches!(ok.advance(None), Ok(Step::Done(Done { value: 1, connection: None }))));
        assert_eq!(ok.advance(None).err(), Some(CloudError::OutOfOrder));
        assert_eq!(Ready::<u8>::err(CloudError::InvalidPath).advance(None).err(), Some(CloudError::InvalidPath));
    }
}
