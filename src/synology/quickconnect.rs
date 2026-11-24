//! QuickConnect: finds a Synology device by its QuickConnect ID, on the local network, over the internet or through
//! Synology's relay.
//!
//! 1. [`resolve`] asks a QuickConnect control host (`Serv.php`, `get_server_info`) for the device's addresses. Control
//!    hosts are regional: a device registered in another region is answered with a list of `sites` to ask instead, which
//!    the operation follows (only control hosts: one name directly under `quickconnect.to` or `quickconnect.cn`).
//! 2. [`Resolution::candidates`] lists the HTTPS addresses to try, the local network first. Probe them concurrently with
//!    [`Resolution::probe`] and short timeouts (2 to 5 seconds), then use the first candidate in list order that
//!    answered. A probe only succeeds when DSM's `pingpong.cgi` names this device (`ezid`, the MD5 of its server ID),
//!    which rules out a stale address that now leads to another Synology device.
//! 3. When no candidate answers, [`Resolution::request_relay`] (`request_tunnel`) opens a tunnel through Synology's relay
//!    and returns its addresses (`https://<id>.<relay region>.quickconnect.to/` or `.cn`); probe them the same way.
//!
//! A probe is not authentication: the server ID is public, so anyone can answer with the right `ezid`. What protects
//! the password is TLS with a certificate the system trusts. Never pin a certificate because a probe succeeded; a pin
//! ([`Connection::with_pinned_certificate`](crate::Connection::with_pinned_certificate)) needs the user to confirm the
//! fingerprint, as for any self-hosted server.
//!
//! # Regions and mainland China
//!
//! Synology runs separate infrastructure for mainland China: control hosts under `quickconnect.cn` (such as
//! `global.quickconnect.cn`) and relays under `<relay region>.quickconnect.cn`. From mainland China,
//! `global.quickconnect.to` is often slow or unreachable, and the reverse can be true elsewhere. Pass
//! [`Region::ChinaMainland`] when the device or the user is there (an address typed with `quickconnect.cn` says so; see
//! [`Region::from_address`]). The operation asks the other region's global host when the first one answers with an
//! error, and the relay keeps to the domain of the control host that knew the device. A transport failure (timeout,
//! DNS) is yours to see: resolve again with [`Region::other`].
//!
//! Only HTTPS candidates are produced. Addresses that are bare IPs rarely carry a certificate the system trusts; DSM's
//! own names (`*.direct.quickconnect.to`, DDNS) and the relay do.

use std::collections::VecDeque;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use md5::{Digest, Md5};
use serde_json::{Value, json};
use url::Url;

use crate::client::ClientConfig;
use crate::connection::{Endpoint, Transport};
use crate::error::CloudError;
use crate::http::{HttpRequest, HttpResponse, Method, Origin};
use crate::operation::{BoxOperation, Call, CallStep, Done, Operation, Ready, Single, Step};

/// The DSM 7 web portal service. One entry per request: `Serv.php` refuses larger bodies with 413.
const SERVICE: &str = "mainapp_https";
/// How many control hosts one resolution asks at most (the two global hosts plus regional redirects).
const MAX_CONTROL_HOSTS: usize = 6;
const PINGPONG: &str = "webman/pingpong.cgi?action=cors&quickconnect=true";
/// `suberrno` of an ID no control host knows.
const UNKNOWN_ID: i64 = 2;

/// Where QuickConnect's control and relay servers are: everywhere else, or mainland China.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Region {
    /// `quickconnect.to`.
    Global,
    /// `quickconnect.cn`, Synology's separate infrastructure for mainland China.
    ChinaMainland,
}

impl Region {
    /// The control host a resolution starts with.
    #[must_use]
    pub fn control_host(self) -> &'static str {
        match self {
            Self::Global => "global.quickconnect.to",
            Self::ChinaMainland => "global.quickconnect.cn",
        }
    }

    /// The other region, to resolve again after the first region's control host could not be reached.
    #[must_use]
    pub fn other(self) -> Self {
        match self {
            Self::Global => Self::ChinaMainland,
            Self::ChinaMainland => Self::Global,
        }
    }

    /// The region an address typed by the user names, such as `quickconnect.cn/my-nas` or `https://my-nas.quickconnect.to`;
    /// `None` for a bare ID.
    ///
    /// ```
    /// # use cloudset::synology::quickconnect::Region;
    /// assert_eq!(Region::from_address("QuickConnect.cn/my-nas"), Some(Region::ChinaMainland));
    /// assert_eq!(Region::from_address("my-nas"), None);
    /// ```
    #[must_use]
    pub fn from_address(input: &str) -> Option<Self> {
        let url = address_url(input.trim())?;
        Self::of_host(url.host_str()?)
    }

    fn domain(self) -> &'static str {
        match self {
            Self::Global => "quickconnect.to",
            Self::ChinaMainland => "quickconnect.cn",
        }
    }

    fn of_host(host: &str) -> Option<Self> {
        let host = host.to_ascii_lowercase();
        [Self::Global, Self::ChinaMainland]
            .into_iter()
            .find(|region| host == region.domain() || host.strip_suffix(region.domain()).is_some_and(|rest| rest.ends_with('.')))
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::ChinaMainland => "chinaMainland",
        }
    }

    pub(crate) fn from_name(name: &str) -> Option<Self> {
        [Self::Global, Self::ChinaMainland].into_iter().find(|region| region.as_str() == name)
    }
}

/// A validated QuickConnect ID: letters, digits and hyphens, starting with a letter, at most 63 characters (it becomes
/// a DNS label). Stored in lowercase.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct QuickConnectId(String);

impl QuickConnectId {
    /// Reads an ID typed by the user: `my-nas`, `quickconnect.to/my-nas`, `https://my-nas.quickconnect.cn` or a relay
    /// address such as `https://my-nas.de3.quickconnect.to/`.
    ///
    /// ```
    /// # use cloudset::synology::quickconnect::QuickConnectId;
    /// assert_eq!(QuickConnectId::parse("https://QuickConnect.to/My-NAS")?.as_str(), "my-nas");
    /// assert_eq!(QuickConnectId::parse("my-nas.cn4.quickconnect.cn")?.as_str(), "my-nas");
    /// assert!(QuickConnectId::parse("192.168.1.2").is_err());
    /// # Ok::<(), cloudset::CloudError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`CloudError::InvalidEndpoint`] for anything that does not contain a valid ID.
    pub fn parse(input: &str) -> Result<Self, CloudError> {
        let invalid = CloudError::InvalidEndpoint("quickconnect id");
        let text = input.trim();
        let id = if is_label(text) {
            text.to_owned()
        } else {
            let url = address_url(text).ok_or(invalid.clone())?;
            let host = url.host_str().ok_or(invalid.clone())?;
            let region = Region::of_host(host).ok_or(invalid.clone())?;
            let id = if host.eq_ignore_ascii_case(region.domain()) {
                url.path_segments().and_then(|mut segments| segments.next())
            } else {
                host.split('.').next()
            };
            id.unwrap_or_default().to_owned()
        };
        let starts_with_letter = id.bytes().next().is_some_and(|byte| byte.is_ascii_alphabetic());
        if !is_label(&id) || !starts_with_letter {
            return Err(invalid);
        }
        Ok(Self(id.to_ascii_lowercase()))
    }

    /// The ID.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for QuickConnectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "QuickConnectId({})", self.0)
    }
}

impl fmt::Display for QuickConnectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An address typed with or without a scheme, as a URL.
fn address_url(text: &str) -> Option<Url> {
    if text.contains("://") { Url::parse(text).ok() } else { Url::parse(&format!("https://{text}")).ok() }
}

/// A DNS label: 1 to 63 ASCII letters, digits and hyphens, not starting or ending with a hyphen.
fn is_label(text: &str) -> bool {
    (1..=63).contains(&text.len())
        && text.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && !text.starts_with('-')
        && !text.ends_with('-')
}

/// A host name made of DNS labels, or `None` for anything else (a port, a path, an IP, an empty label).
fn host_name(text: &str) -> Option<String> {
    let host = text.trim().trim_end_matches('.').to_ascii_lowercase();
    let valid = host.len() <= 253 && host.contains('.') && host.split('.').all(is_label) && host.parse::<IpAddr>().is_err();
    valid.then_some(host)
}

/// A control host the resolution may ask, and the region it is in: one name directly under `quickconnect.to` or
/// `quickconnect.cn` (`global.`, `usc.`, `cnc.`). Deeper names are devices (`*.direct.quickconnect.to`) or relays.
fn control_host(text: &str) -> Option<(String, Region)> {
    let host = host_name(text)?;
    let region = Region::of_host(&host)?;
    let name = host.strip_suffix(region.domain())?.strip_suffix('.')?;
    (!name.contains('.')).then_some((host, region))
}

/// How a candidate reaches the device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Route {
    /// An address on the device's local network; only reachable from inside it.
    LocalNetwork,
    /// A public address: DDNS, Synology's SmartDNS name, or the router's public IP with a forwarded port.
    Internet,
    /// Synology's relay. Always reachable while the device is online, but slower; use it last.
    Relay,
}

/// A DSM address to probe, and how it reaches the device.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Candidate {
    /// The DSM address; pass it to [`crate::synology::SignIn::new`] or [`crate::Connection::with_endpoint`] once a
    /// probe confirmed it.
    pub endpoint: Endpoint,
    /// How it reaches the device.
    pub route: Route,
}

/// What a control host knows about a device.
#[derive(Clone, Debug)]
pub struct Resolution {
    id: QuickConnectId,
    region: Region,
    control_host: String,
    server_id: String,
    candidates: Vec<Candidate>,
}

impl Resolution {
    /// The QuickConnect ID.
    #[must_use]
    pub fn id(&self) -> &QuickConnectId {
        &self.id
    }

    /// The region of the control host that knew the device. Store it with the connection, so the next resolution starts
    /// there.
    #[must_use]
    pub fn region(&self) -> Region {
        self.region
    }

    /// Direct addresses, most preferred first: local network names and IPs, then public names and IPs.
    #[must_use]
    pub fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }

    /// Checks that `endpoint` answers as this device. Resolves to `false` for any other answer: another device, an error
    /// status, something that is not DSM. Transport failures stay with your executor; treat them as `false`. This tells
    /// reachable addresses apart; it does not authenticate the device (see the [module documentation](self)).
    pub fn probe(&self, endpoint: &Endpoint, config: &ClientConfig) -> BoxOperation<bool> {
        let url = match endpoint.join(PINGPONG) {
            Ok(url) => url,
            Err(error) => return Box::new(Ready::err(error)),
        };
        let request = HttpRequest::new(Method::Get, url.as_str())
            .with_header("Accept", "application/json")
            .with_header("User-Agent", config.user_agent.clone());
        let expected = ezid(&self.server_id);
        // A redirect would leave the address being checked: it counts as no answer.
        let call = Call::new(request, endpoint.origin(), config.limits).without_redirects();
        Box::new(Single::new(call, move |response| Ok(response.status == 200 && pong_matches(&response, &expected))))
    }

    /// Asks the control host to open a relay tunnel and returns the relay's addresses, the control host's own domain
    /// first. Probe them like any other candidate: the tunnel can take a moment to come up.
    pub fn request_relay(&self, config: &ClientConfig) -> BoxOperation<Vec<Candidate>> {
        let call = match control_call(&self.control_host, "request_tunnel", &self.id, config) {
            Ok(call) => call,
            Err(error) => return Box::new(Ready::err(error)),
        };
        let (id, region) = (self.id.clone(), self.region);
        Box::new(Single::new(call, move |response| {
            if !response.is_success() {
                return Err(CloudError::Server { status: response.status });
            }
            let items = items(&response)?;
            let relay_region = items
                .iter()
                .filter(|item| item.get("errno").and_then(Value::as_i64) == Some(0))
                .find_map(|item| item.pointer("/env/relay_region").and_then(Value::as_str).filter(|name| is_label(name)))
                .ok_or_else(|| error_of(&items, "quickconnect relay"))?;
            relay_candidates(&id, region, &relay_region.to_ascii_lowercase())
        }))
    }
}

/// The relay addresses `https://<id>.<relay region>.<domain>/`, the domain of `region` first.
fn relay_candidates(id: &QuickConnectId, region: Region, relay_region: &str) -> Result<Vec<Candidate>, CloudError> {
    [region, region.other()]
        .into_iter()
        .map(|region| {
            let endpoint = Endpoint::parse(&format!("https://{id}.{relay_region}.{}/", region.domain()), Transport::RequireHttps)?;
            Ok(Candidate { endpoint, route: Route::Relay })
        })
        .collect()
}

/// `ezid` of a device: the MD5 of its server ID, in lowercase hex.
fn ezid(server_id: &str) -> String {
    Md5::digest(server_id.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn pong_matches(response: &HttpResponse, expected: &str) -> bool {
    let Ok(pong) = serde_json::from_slice::<Value>(&response.body) else { return false };
    pong.get("success").and_then(Value::as_bool) == Some(true)
        && pong.get("ezid").and_then(Value::as_str).is_some_and(|ezid| ezid.eq_ignore_ascii_case(expected))
}

/// A request to a control host's `Serv.php`, which only accepts requests to its own origin.
fn control_call(host: &str, command: &str, id: &QuickConnectId, config: &ClientConfig) -> Result<Call, CloudError> {
    let request = control_request(host, command, id, config)?;
    let url = Url::parse(&request.url).map_err(|_| CloudError::InvalidResponse("control host"))?;
    Ok(Call::new(request, Origin::of(&url), config.limits))
}

fn control_request(host: &str, command: &str, id: &QuickConnectId, config: &ClientConfig) -> Result<HttpRequest, CloudError> {
    let url = Url::parse(&format!("https://{host}/Serv.php")).map_err(|_| CloudError::InvalidResponse("control host"))?;
    let body = json!([{
        "version": 1,
        "command": command,
        "stop_when_error": false,
        "stop_when_success": command == "request_tunnel",
        "id": SERVICE,
        "serverID": id.as_str(),
        "is_gofile": false,
        "path": "",
    }]);
    Ok(HttpRequest::new(Method::Post, url.as_str())
        // The content type the QuickConnect web portal sends with this JSON body.
        .with_header("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
        .with_header("Accept", "application/json")
        .with_header("User-Agent", config.user_agent.clone())
        .with_body(body.to_string()))
}

/// The response entries: `Serv.php` answers a JSON array with one entry per request, or a single object.
fn items(response: &HttpResponse) -> Result<Vec<Value>, CloudError> {
    match serde_json::from_slice::<Value>(&response.body).map_err(|_| CloudError::InvalidResponse("json"))? {
        Value::Array(items) => Ok(items),
        item @ Value::Object(_) => Ok(vec![item]),
        _ => Err(CloudError::InvalidResponse("quickconnect")),
    }
}

/// The error for entries that carry no answer: an ID no control host knows is `NotFound`.
fn error_of(items: &[Value], reason: &'static str) -> CloudError {
    if items.iter().any(|item| item.get("suberrno").and_then(Value::as_i64) == Some(UNKNOWN_ID)) {
        CloudError::NotFound
    } else {
        CloudError::InvalidResponse(reason)
    }
}

/// Looks the device up, following regional redirects; see the [module documentation](self).
///
/// # Errors
///
/// The operation reports [`CloudError::NotFound`] when no control host knows the ID, and
/// [`CloudError::InvalidResponse`] when none could answer.
pub fn resolve(id: &QuickConnectId, region: Region, config: &ClientConfig) -> BoxOperation<Resolution> {
    let queue = [region, region.other()].into_iter().map(|region| (region.control_host().to_owned(), region)).collect();
    Box::new(Resolve { id: id.clone(), config: config.clone(), queue, asked: Vec::new(), unknown: false, call: None, finished: false })
}

struct Resolve {
    id: QuickConnectId,
    config: ClientConfig,
    /// Control hosts still to ask, next first.
    queue: VecDeque<(String, Region)>,
    asked: Vec<String>,
    /// A control host said it does not know the ID.
    unknown: bool,
    /// The request in flight, and the host and region it went to.
    call: Option<(Call, String, Region)>,
    /// A result or an error was handed out.
    finished: bool,
}

impl Resolve {
    /// Asks the next control host, or gives up.
    fn ask_next(&mut self) -> Result<Step<Resolution>, CloudError> {
        let Some((host, region)) = self.queue.pop_front().filter(|_| self.asked.len() < MAX_CONTROL_HOSTS) else {
            return Err(if self.unknown { CloudError::NotFound } else { CloudError::InvalidResponse("quickconnect unavailable") });
        };
        self.asked.push(host.clone());
        let mut call = control_call(&host, "get_server_info", &self.id, &self.config)?;
        let step = call.advance(None)?;
        self.call = Some((call, host, region));
        match step {
            CallStep::Send(request) => Ok(Step::Send(request)),
            CallStep::Response(_) => Err(CloudError::OutOfOrder),
        }
    }

    /// Reads one control host's answer: a resolution, or redirects to queue.
    fn read(&mut self, response: &HttpResponse, host: String, region: Region) -> Option<Resolution> {
        let items = items(response).ok().filter(|_| response.is_success())?;
        let mut redirects = Vec::new();
        for item in &items {
            if item.get("suberrno").and_then(Value::as_i64) == Some(UNKNOWN_ID) {
                self.unknown = true;
            }
            for site in item.get("sites").and_then(Value::as_array).into_iter().flatten() {
                if let Some((site, region)) = site.as_str().and_then(control_host)
                    && !self.asked.contains(&site)
                    && !self.queue.iter().chain(&redirects).any(|(queued, _)| *queued == site)
                {
                    redirects.push((site, region));
                }
            }
        }
        // A region that redirects knows best: its sites go before the other global host.
        for redirect in redirects.into_iter().rev() {
            self.queue.push_front(redirect);
        }
        let item = items.iter().find(|item| item.get("errno").and_then(Value::as_i64) == Some(0))?;
        let server_id = item.pointer("/server/serverID").and_then(Value::as_str).filter(|id| !id.is_empty())?;
        let control_host = item.pointer("/env/control_host").and_then(Value::as_str).and_then(control_host).map_or(host, |(host, _)| host);
        Some(Resolution { id: self.id.clone(), region, control_host, server_id: server_id.to_owned(), candidates: direct_candidates(item) })
    }
}

impl Operation for Resolve {
    type Output = Resolution;

    fn advance(&mut self, response: Option<HttpResponse>) -> Result<Step<Resolution>, CloudError> {
        let step = match (self.call.take(), response) {
            _ if self.finished => Err(CloudError::OutOfOrder),
            (None, None) if self.asked.is_empty() => self.ask_next(),
            (Some((mut call, host, region)), Some(response)) => match call.advance(Some(response)) {
                Ok(CallStep::Send(request)) => {
                    self.call = Some((call, host, region));
                    Ok(Step::Send(request))
                }
                Ok(CallStep::Response(response)) => match self.read(&response, host, region) {
                    Some(resolution) => Ok(Step::Done(Done::new(resolution))),
                    None => self.ask_next(),
                },
                // A control host that answers off protocol (too large, a foreign redirect) is skipped like one that errs.
                Err(_) => self.ask_next(),
            },
            _ => Err(CloudError::OutOfOrder),
        };
        self.finished = !matches!(step, Ok(Step::Send(_)));
        step
    }
}

/// A port from `service`, which may come as a number or a string; `None` for 0 or anything unreadable.
fn port(value: Option<&Value>) -> Option<u16> {
    let value = value?;
    let port = value.as_u64().or_else(|| value.as_str().and_then(|text| text.parse().ok()))?;
    u16::try_from(port).ok().filter(|port| *port != 0)
}

/// A non-empty string field that is not DSM's `"NULL"`.
fn text<'a>(item: &'a Value, pointer: &str) -> Option<&'a str> {
    item.pointer(pointer).and_then(Value::as_str).map(str::trim).filter(|text| !text.is_empty() && *text != "NULL")
}

fn strings<'a>(item: &'a Value, pointer: &str) -> impl Iterator<Item = &'a str> {
    item.pointer(pointer).and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str)
}

/// Private and shared address space: only reachable on the device's own network.
fn is_local(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_link_local() || (ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1]))
}

/// Candidate addresses from a `get_server_info` entry, in the order the QuickConnect web portal prefers them.
fn direct_candidates(item: &Value) -> Vec<Candidate> {
    let Some(local_port) = port(item.pointer("/service/port")) else { return Vec::new() };
    // The router's forwarded port first, then the device's own port (forwarded unchanged, or no NAT at all).
    let mut public_ports = Vec::new();
    public_ports.extend(port(item.pointer("/service/ext_port")).filter(|port| *port != local_port));
    public_ports.push(local_port);

    let mut candidates = Vec::new();
    let mut add = |host: &str, ports: &[u16], route: Route| {
        for port in ports {
            let address = match host.parse::<IpAddr>() {
                Ok(IpAddr::V6(ip)) if ip.is_unspecified() || ip.is_loopback() => return,
                Ok(IpAddr::V4(ip)) if ip.is_unspecified() || ip.is_loopback() => return,
                Ok(IpAddr::V6(ip)) => format!("https://[{ip}]:{port}/"),
                Ok(IpAddr::V4(ip)) => format!("https://{ip}:{port}/"),
                Err(_) => match host_name(host) {
                    Some(name) => format!("https://{name}:{port}/"),
                    None => return,
                },
            };
            if let Ok(endpoint) = Endpoint::parse(&address, Transport::RequireHttps)
                && !candidates.iter().any(|candidate: &Candidate| candidate.endpoint == endpoint)
            {
                candidates.push(Candidate { endpoint, route });
            }
        }
    };

    // SmartDNS names: `syn4-` / `syn6-` names point at the public address, the others at a local one.
    let smart_names: Vec<&str> = strings(item, "/smartdns/lan").chain(strings(item, "/smartdns/lanv6")).collect();
    let is_public_name = |name: &str| name.starts_with("syn4-") || name.starts_with("syn6-");
    for name in smart_names.iter().filter(|name| !is_public_name(name)) {
        add(name, &[local_port], Route::LocalNetwork);
    }
    let interface_ips: Vec<Ipv4Addr> = item
        .pointer("/server/interface")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|interface| interface.get("ip").and_then(Value::as_str)?.parse().ok())
        .collect();
    for ip in interface_ips.iter().filter(|ip| is_local(**ip)) {
        add(&ip.to_string(), &[local_port], Route::LocalNetwork);
    }
    for name in [text(item, "/server/fqdn"), text(item, "/server/ddns"), text(item, "/smartdns/host")].into_iter().flatten() {
        add(name, &public_ports, Route::Internet);
    }
    for name in smart_names.iter().filter(|name| is_public_name(name)) {
        add(name, &public_ports, Route::Internet);
    }
    // Only a global unicast address (2000::/3) is reachable from elsewhere.
    let global_ipv6 = text(item, "/server/external/ipv6")
        .and_then(|ip| ip.parse::<std::net::Ipv6Addr>().ok())
        .filter(|ip| (ip.segments()[0] & 0xe000) == 0x2000);
    if let Some(ipv6) = global_ipv6 {
        add(&ipv6.to_string(), &public_ports, Route::Internet);
    }
    let external = text(item, "/server/external/ip").and_then(|ip| ip.parse::<Ipv4Addr>().ok()).filter(|ip| !is_local(*ip));
    for ip in external.into_iter().chain(interface_ips.into_iter().filter(|ip| !is_local(*ip))) {
        add(&ip.to_string(), &public_ports, Route::Internet);
    }
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ids_from_typed_addresses() {
        for (input, id) in [
            ("my-nas", "my-nas"),
            ("  My-NAS ", "my-nas"),
            ("quickconnect.to/my-nas", "my-nas"),
            ("http://QuickConnect.cn/my-nas/", "my-nas"),
            ("https://my-nas.quickconnect.to", "my-nas"),
            ("my-nas.cn4.quickconnect.cn", "my-nas"),
            ("https://my-nas.de3.quickconnect.to/webman/index.cgi", "my-nas"),
        ] {
            assert_eq!(QuickConnectId::parse(input).map(|id| id.0), Ok(id.to_owned()), "{input}");
        }
        for bad in
            ["", "-nas", "nas-", "1nas", "my_nas", "nas.example.com", "192.168.1.2", "quickconnect.to/", "quickconnect.to", &"a".repeat(64)]
        {
            assert!(QuickConnectId::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn regions_from_addresses_and_hosts() {
        assert_eq!(Region::from_address("my-nas.quickconnect.cn"), Some(Region::ChinaMainland));
        assert_eq!(Region::from_address("https://quickconnect.to/my-nas"), Some(Region::Global));
        assert_eq!(Region::from_address("evilquickconnect.cn/x"), None, "only the domain itself and its subdomains");
        assert_eq!(control_host("CNC.quickconnect.cn"), Some(("cnc.quickconnect.cn".into(), Region::ChinaMainland)));
        for bad in [
            "quickconnect.to",
            "usc.quickconnect.to:8443",
            "usc.quickconnect.to/x",
            "evil.com",
            "a.quickconnect.to.evil.com",
            "1.2.3.4",
            "my-nas.direct.quickconnect.to",
            "my-nas.cn4.quickconnect.cn",
        ] {
            assert_eq!(control_host(bad), None, "{bad}");
        }
        for region in [Region::Global, Region::ChinaMainland] {
            assert_eq!(Region::from_name(region.as_str()), Some(region));
            assert_eq!(region.other().other(), region);
        }
    }

    #[test]
    fn ezid_is_the_md5_of_the_server_id() {
        assert_eq!(ezid(""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(ezid("abc"), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn orders_candidates_local_first_and_drops_unusable_addresses() {
        let item = json!({
            "errno": 0,
            "server": {
                "serverID": "1234",
                "ddns": "nas.synology.me",
                "fqdn": "NULL",
                "external": { "ip": "203.0.113.7", "ipv6": "::" },
                "interface": [{ "ip": "192.168.1.20" }, { "ip": "127.0.0.1" }, { "ip": "not an ip" }],
            },
            "service": { "port": 5001, "ext_port": "15001" },
            "smartdns": {
                "host": "my-nas.direct.quickconnect.to",
                "lan": ["192-168-1-20.my-nas.direct.quickconnect.to", "syn4-203-0-113-7.my-nas.direct.quickconnect.to", "bad/name"],
            },
        });
        let candidates: Vec<(String, Route)> =
            direct_candidates(&item).into_iter().map(|candidate| (candidate.endpoint.as_str().to_owned(), candidate.route)).collect();
        let expected = [
            ("https://192-168-1-20.my-nas.direct.quickconnect.to:5001/", Route::LocalNetwork),
            ("https://192.168.1.20:5001/", Route::LocalNetwork),
            ("https://nas.synology.me:15001/", Route::Internet),
            ("https://nas.synology.me:5001/", Route::Internet),
            ("https://my-nas.direct.quickconnect.to:15001/", Route::Internet),
            ("https://my-nas.direct.quickconnect.to:5001/", Route::Internet),
            ("https://syn4-203-0-113-7.my-nas.direct.quickconnect.to:15001/", Route::Internet),
            ("https://syn4-203-0-113-7.my-nas.direct.quickconnect.to:5001/", Route::Internet),
            ("https://203.0.113.7:15001/", Route::Internet),
            ("https://203.0.113.7:5001/", Route::Internet),
        ];
        assert_eq!(candidates, expected.map(|(url, route)| (url.to_owned(), route)));
        assert!(direct_candidates(&json!({ "service": { "port": 0 } })).is_empty(), "no port, no candidates");
    }

    #[test]
    fn public_ipv6_must_be_global_unicast() {
        let with_ipv6 = |ip: &str| {
            let item = json!({ "server": { "external": { "ipv6": ip } }, "service": { "port": 5001 } });
            direct_candidates(&item).into_iter().map(|candidate| candidate.endpoint.as_str().to_owned()).collect::<Vec<_>>()
        };
        assert_eq!(with_ipv6("2001:db8::7"), ["https://[2001:db8::7]:5001/"]);
        for local in ["fe80::1", "fd00::1", "::", "::1", "ff02::1", "::ffff:192.168.1.2"] {
            assert!(with_ipv6(local).is_empty(), "{local}");
        }
    }

    #[test]
    fn redirects_are_bounded_and_kept_to_control_hosts() {
        let id = QuickConnectId::parse("my-nas").unwrap();
        let mut asked = Vec::new();
        let mut next = 0;
        let mut resolve = resolve(&id, Region::Global, &ClientConfig::new("x"));
        let result = crate::run(resolve.as_mut(), |request| {
            asked.push(Url::parse(&request.url).unwrap().host_str().unwrap().to_owned());
            next += 1;
            // Every host redirects to a new one, plus hosts that are not control hosts.
            let sites = json!([format!("r{next}.quickconnect.to"), "my-nas.direct.quickconnect.to", "evil.example.com"]);
            HttpResponse::new(200).with_body(json!([{ "errno": 4, "suberrno": 1, "sites": sites }]).to_string())
        });
        assert_eq!(result.err(), Some(CloudError::InvalidResponse("quickconnect unavailable")));
        assert_eq!(asked.len(), MAX_CONTROL_HOSTS);
        assert_eq!(asked[..2], ["global.quickconnect.to", "r1.quickconnect.to"], "redirects go first");
        assert!(asked.iter().all(|host| control_host(host).is_some()), "{asked:?}");
    }

    #[test]
    fn relays_follow_the_control_hosts_domain() {
        let id = QuickConnectId::parse("my-nas").unwrap();
        let relays = relay_candidates(&id, Region::ChinaMainland, "cn4").unwrap();
        let urls: Vec<&str> = relays.iter().map(|candidate| candidate.endpoint.as_str()).collect();
        assert_eq!(urls, ["https://my-nas.cn4.quickconnect.cn/", "https://my-nas.cn4.quickconnect.to/"]);
        assert!(relays.iter().all(|candidate| candidate.route == Route::Relay));
    }

    #[test]
    fn control_requests_stay_small() {
        let id = QuickConnectId::parse(&format!("a{}", "b".repeat(62))).unwrap();
        let request = control_request("global.quickconnect.cn", "get_server_info", &id, &ClientConfig::new("x")).unwrap();
        assert!(request.body.len() < 300, "Serv.php answers 413 to larger bodies: {}", request.body.len());
        assert_eq!(request.url, "https://global.quickconnect.cn/Serv.php");
    }
}
