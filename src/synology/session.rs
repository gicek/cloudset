//! Driver for Synology operations: the counterpart of [`crate::authorized`] for DSM sessions. Each operation is written
//! as [`Steps`]; this driver signs in when there is no session, adds the session ID to every request, signs in again and
//! replays (once) when DSM reports the session expired or replaced, and hands the renewed connection back.
//!
//! Requests with the session only go to the origin of the connection's DSM address.

use zeroize::Zeroizing;

use crate::authorized::{Next, Outgoing, Steps};
use crate::client::ClientConfig;
use crate::connection::{Connection, SynologyCredential};
use crate::error::CloudError;
use crate::http::HttpResponse;
use crate::operation::{BoxOperation, Call, CallStep, Done, Operation, Ready, Step};
use crate::synology::api;

enum Phase {
    Start,
    SigningIn { call: Call, pending: Outgoing, retried: bool },
    Sending { call: Call, outgoing: Outgoing, retried: bool },
    Finished,
}

pub(crate) struct Session<S> {
    steps: S,
    credential: SynologyCredential,
    config: ClientConfig,
    /// A one-time code for the first sign-in, which only the interactive sign-in has.
    otp_code: Option<Zeroizing<String>>,
    /// Sign-in errors reach the caller as they are; otherwise they mean the stored connection needs a new sign-in.
    interactive: bool,
    renewed: bool,
    phase: Phase,
}

impl<S: Steps> Session<S> {
    pub(crate) fn new(steps: S, connection: &Connection, config: &ClientConfig) -> Result<Self, CloudError> {
        let credential = connection.synology_credential().cloned().ok_or(CloudError::InvalidConnection)?;
        Ok(Self::with_credential(steps, credential, config))
    }

    /// A driver that signs in first, with a one-time code when there is one, and reports sign-in errors as they are.
    pub(crate) fn signing_in(
        steps: S,
        mut credential: SynologyCredential,
        otp_code: Option<Zeroizing<String>>,
        config: &ClientConfig,
    ) -> Self {
        credential.session = None;
        Self { otp_code, interactive: true, ..Self::with_credential(steps, credential, config) }
    }

    fn with_credential(steps: S, credential: SynologyCredential, config: &ClientConfig) -> Self {
        Self { steps, credential, config: config.clone(), otp_code: None, interactive: false, renewed: false, phase: Phase::Start }
    }

    fn send(&mut self, outgoing: Outgoing, retried: bool) -> Result<Step<S::Output>, CloudError> {
        if outgoing.authorize && self.credential.session.is_none() {
            return self.sign_in(outgoing, retried);
        }
        let mut request = outgoing.request.clone();
        let origin = self.credential.endpoint.origin();
        let url = url::Url::parse(&request.url).map_err(|_| CloudError::InvalidEndpoint("url"))?;
        if !origin.admits(&url) {
            return Err(CloudError::InsecureRedirect);
        }
        if outgoing.authorize
            && let Some(session) = &self.credential.session
        {
            api::with_session(&mut request, session)?;
        }
        request.headers.push(("User-Agent".into(), self.config.user_agent.clone()));
        let mut call = Call::new(request, origin, self.config.limits);
        if !outgoing.follow_redirects {
            call = call.without_redirects();
        }
        let step = call.advance(None)?;
        self.phase = Phase::Sending { call, outgoing, retried };
        sent(step)
    }

    fn sign_in(&mut self, pending: Outgoing, retried: bool) -> Result<Step<S::Output>, CloudError> {
        let otp_code = self.otp_code.take();
        let mut request = api::login_request(&self.credential, otp_code.as_deref().map(String::as_str), &self.config)?;
        request.headers.push(("User-Agent".into(), self.config.user_agent.clone()));
        let mut call = Call::new(request, self.credential.endpoint.origin(), self.config.limits);
        let step = call.advance(None)?;
        self.phase = Phase::SigningIn { call, pending, retried };
        sent(step)
    }

    fn signed_in(&mut self, response: &HttpResponse) -> Result<(), CloudError> {
        match api::apply_login(&mut self.credential, response) {
            Ok(()) => {
                self.renewed = true;
                Ok(())
            }
            // Without the user there is no one-time code to give: the stored connection needs a new sign-in.
            Err(CloudError::OtpRequired) if !self.interactive => Err(CloudError::ReauthRequired),
            Err(error) => Err(error),
        }
    }
}

fn sent<T>(step: CallStep) -> Result<Step<T>, CloudError> {
    match step {
        CallStep::Send(request) => Ok(Step::Send(request)),
        CallStep::Response(_) => Err(CloudError::OutOfOrder),
    }
}

impl<S: Steps> Operation for Session<S> {
    type Output = S::Output;

    fn take_connection(&mut self) -> Option<Connection> {
        std::mem::take(&mut self.renewed).then(|| Connection::synology(self.credential.clone()))
    }

    fn advance(&mut self, response: Option<HttpResponse>) -> Result<Step<S::Output>, CloudError> {
        match std::mem::replace(&mut self.phase, Phase::Finished) {
            Phase::Start if response.is_none() => {
                let outgoing = self.steps.first()?;
                self.send(outgoing, false)
            }
            Phase::SigningIn { mut call, pending, retried } => match call.advance(response)? {
                CallStep::Send(request) => {
                    self.phase = Phase::SigningIn { call, pending, retried };
                    Ok(Step::Send(request))
                }
                CallStep::Response(response) => {
                    self.signed_in(&response)?;
                    self.send(pending, retried)
                }
            },
            Phase::Sending { mut call, outgoing, retried } => match call.advance(response)? {
                CallStep::Send(request) => {
                    self.phase = Phase::Sending { call, outgoing, retried };
                    Ok(Step::Send(request))
                }
                CallStep::Response(response) => {
                    let refused = api::session_error(&response).filter(|_| outgoing.authorize && outgoing.refresh);
                    match refused {
                        // A session refused right after a successful sign-in is not the password's fault (another
                        // client signing in at the same moment, or a proxy changing the client IP): report it as it is.
                        Some(code) if retried => Err(CloudError::Provider { code }),
                        Some(_) => {
                            self.credential.session = None;
                            self.sign_in(outgoing, true)
                        }
                        None => match self.steps.next(response)? {
                            Next::Request(next) => self.send(next, false),
                            Next::Done(value) => Ok(Step::Done(Done::new(value).with_connection(self.take_connection()))),
                        },
                    }
                }
            },
            Phase::Start | Phase::Finished => Err(CloudError::OutOfOrder),
        }
    }
}

/// Wraps `steps` in a driver for `connection`.
pub(crate) fn op<S: Steps + 'static>(steps: S, connection: &Connection, config: &ClientConfig) -> BoxOperation<S::Output> {
    match Session::new(steps, connection, config) {
        Ok(operation) => Box::new(operation),
        Err(error) => Box::new(Ready::err(error)),
    }
}
