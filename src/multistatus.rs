//! WebDAV `207 Multi-Status` response parsing (RFC 4918 §13). Only `href` and four properties from 2xx `propstat` are read.
//!
//! Remote XML is always treated as untrusted: `DOCTYPE` is rejected (no custom entities are ever expanded), nesting depth
//! and entry count are capped, and only predefined entities and character references are decoded.

use std::time::SystemTime;

use quick_xml::NsReader;
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::Event;
use quick_xml::name::{Namespace, ResolveResult};

use crate::error::CloudError;

const DAV: Namespace<'static> = Namespace("DAV:");
const MAX_DEPTH: usize = 32;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DavEntry {
    pub href: String,
    pub is_dir: bool,
    pub size: Option<u64>,
    pub modified_at: Option<SystemTime>,
    pub etag: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tag {
    Multistatus,
    Response,
    Href,
    Propstat,
    Status,
    Prop,
    ResourceType,
    Collection,
    ContentLength,
    LastModified,
    Etag,
    Other,
}

impl Tag {
    fn of(name: &str) -> Self {
        match name {
            "multistatus" => Self::Multistatus,
            "response" => Self::Response,
            "href" => Self::Href,
            "propstat" => Self::Propstat,
            "status" => Self::Status,
            "prop" => Self::Prop,
            "resourcetype" => Self::ResourceType,
            "collection" => Self::Collection,
            "getcontentlength" => Self::ContentLength,
            "getlastmodified" => Self::LastModified,
            "getetag" => Self::Etag,
            _ => Self::Other,
        }
    }

    /// Elements whose text content is collected.
    fn has_text(self) -> bool {
        matches!(self, Self::Href | Self::Status | Self::ContentLength | Self::LastModified | Self::Etag)
    }
}

#[derive(Default)]
struct Propstat {
    status: Option<u16>,
    props: DavEntry,
}

fn succeeded(status: Option<u16>) -> bool {
    status.is_none_or(|status| (200..300).contains(&status))
}

#[derive(Default)]
struct ResponseBuilder {
    href: Option<String>,
    /// The status of the response as a whole (the `href` + `status` form of RFC 4918 §14.24).
    status: Option<u16>,
    props: DavEntry,
}

impl ResponseBuilder {
    /// Merges a 2xx (or status-less) propstat; properties that only appear in failed propstats (404 etc.) count as absent.
    fn merge(&mut self, propstat: Propstat) {
        if succeeded(propstat.status) {
            let props = propstat.props;
            self.props.is_dir |= props.is_dir;
            self.props.size = self.props.size.or(props.size);
            self.props.modified_at = self.props.modified_at.or(props.modified_at);
            self.props.etag = self.props.etag.take().or(props.etag);
        }
    }
}

/// A parsed multistatus body.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Multistatus {
    pub entries: Vec<DavEntry>,
    /// The `href`s the server reports as missing (a 404 status for the whole response).
    pub missing: Vec<String>,
}

pub(crate) fn parse(body: &[u8], max_entries: usize) -> Result<Multistatus, CloudError> {
    let mut reader = NsReader::from_reader(body);
    reader.config_mut().expand_empty_elements = true;
    let mut buf = Vec::new();
    let mut stack: Vec<Tag> = Vec::new();
    let mut text = String::new();
    let mut parsed = Multistatus::default();
    let mut response: Option<ResponseBuilder> = None;
    let mut propstat: Option<Propstat> = None;
    let mut saw_root = false;

    loop {
        let (namespace, event) = reader.read_resolved_event_into(&mut buf).map_err(|_| CloudError::InvalidResponse("malformed xml"))?;
        let in_dav = matches!(namespace, ResolveResult::Bound(ns) if ns == DAV);
        match event {
            Event::Start(start) => {
                let tag = if in_dav { Tag::of(start.local_name().as_ref()) } else { Tag::Other };
                if stack.is_empty() {
                    if tag != Tag::Multistatus {
                        return Err(CloudError::InvalidResponse("not a multistatus"));
                    }
                    saw_root = true;
                }
                if stack.len() >= MAX_DEPTH {
                    return Err(CloudError::InvalidResponse("xml too deep"));
                }
                // Elements only count at their place in the document: a property value may itself contain DAV elements.
                match (stack.last(), tag, stack.len()) {
                    (Some(Tag::Multistatus), Tag::Response, 1) => response = Some(ResponseBuilder::default()),
                    (Some(Tag::Response), Tag::Propstat, 2) => propstat = Some(Propstat::default()),
                    (Some(Tag::ResourceType), Tag::Collection, 5) => {
                        if let Some(propstat) = propstat.as_mut() {
                            propstat.props.is_dir = true;
                        }
                    }
                    _ => {}
                }
                text.clear();
                stack.push(tag);
            }
            Event::End(_) => {
                let tag = stack.pop().ok_or(CloudError::InvalidResponse("malformed xml"))?;
                let parent = stack.last().copied();
                let value = text.trim();
                match (parent, tag, stack.len()) {
                    (Some(Tag::Response), Tag::Href, 2) => {
                        if let Some(response) = response.as_mut() {
                            response.href = Some(value.to_owned());
                        }
                    }
                    (Some(Tag::Response), Tag::Status, 2) => {
                        if let Some(response) = response.as_mut() {
                            response.status = parse_status(value);
                        }
                    }
                    (Some(Tag::Propstat), Tag::Status, 3) => {
                        if let Some(propstat) = propstat.as_mut() {
                            propstat.status = parse_status(value);
                        }
                    }
                    (Some(Tag::Prop), Tag::ContentLength | Tag::LastModified | Tag::Etag, 4) => {
                        if let Some(propstat) = propstat.as_mut() {
                            set_prop(&mut propstat.props, tag, value);
                        }
                    }
                    (Some(Tag::Response), Tag::Propstat, 2) => {
                        if let (Some(response), Some(propstat)) = (response.as_mut(), propstat.take()) {
                            response.merge(propstat);
                        }
                    }
                    (Some(Tag::Multistatus), Tag::Response, 1) => {
                        // A response without an `href`, or one that failed for another reason (403 and the like), names
                        // nothing usable.
                        if let Some(ResponseBuilder { href: Some(href), status, props }) = response.take() {
                            if parsed.entries.len() + parsed.missing.len() >= max_entries {
                                return Err(CloudError::TooLarge);
                            }
                            if succeeded(status) {
                                parsed.entries.push(DavEntry { href, ..props });
                            } else if status == Some(404) {
                                parsed.missing.push(href);
                            }
                        }
                    }
                    _ => {}
                }
                text.clear();
            }
            Event::Text(content) => {
                if stack.last().is_some_and(|tag| tag.has_text()) {
                    text.push_str(&content.xml10_content());
                }
            }
            Event::CData(content) => {
                if stack.last().is_some_and(|tag| tag.has_text()) {
                    text.push_str(&content.xml10_content());
                }
            }
            Event::GeneralRef(reference) => {
                let resolved =
                    if let Some(c) = reference.resolve_char_ref().map_err(|_| CloudError::InvalidResponse("bad character reference"))? {
                        c.to_string()
                    } else {
                        resolve_predefined_entity(&reference).ok_or(CloudError::InvalidResponse("unknown entity"))?.to_owned()
                    };
                if stack.last().is_some_and(|tag| tag.has_text()) {
                    text.push_str(&resolved);
                }
            }
            Event::DocType(_) => return Err(CloudError::InvalidResponse("doctype not allowed")),
            Event::Eof => break,
            Event::Empty(_) | Event::Comment(_) | Event::Decl(_) | Event::PI(_) => {}
        }
        buf.clear();
    }
    if !saw_root || !stack.is_empty() {
        return Err(CloudError::InvalidResponse("not a multistatus"));
    }
    Ok(parsed)
}

fn parse_status(line: &str) -> Option<u16> {
    line.split_whitespace().nth(1)?.parse().ok()
}

fn set_prop(props: &mut DavEntry, tag: Tag, value: &str) {
    if value.is_empty() {
        return;
    }
    match tag {
        Tag::ContentLength => props.size = value.parse().ok(),
        Tag::LastModified => props.modified_at = httpdate::parse_http_date(value).ok(),
        Tag::Etag => props.etag = Some(value.to_owned()),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    #[test]
    fn parses_prefixed_and_default_namespaces() {
        let body = br#"<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
  <d:response><d:href>/dav/Backups/</d:href>
    <d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>"dir1"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
    <d:propstat><d:prop><d:getcontentlength/></d:prop><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>
  </d:response>
  <d:response><d:href>/dav/Backups/a%20b&amp;c.txt</d:href>
    <d:propstat><d:prop><d:resourcetype/><d:getcontentlength>42</d:getcontentlength>
      <d:getlastmodified>Sun, 06 Nov 1994 08:49:37 GMT</d:getlastmodified><d:getetag>&quot;e1&quot;</d:getetag><oc:size>9</oc:size></d:prop>
      <d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  </d:response>
</d:multistatus>"#;
        let entries = parse(body, 10).unwrap().entries;
        assert_eq!(
            entries[0],
            DavEntry { href: "/dav/Backups/".into(), is_dir: true, etag: Some("\"dir1\"".into()), ..DavEntry::default() }
        );
        assert_eq!(
            entries[1],
            DavEntry {
                href: "/dav/Backups/a%20b&c.txt".into(),
                is_dir: false,
                size: Some(42),
                modified_at: Some(UNIX_EPOCH + Duration::from_secs(784_111_777)),
                etag: Some("\"e1\"".into()),
            }
        );

        let default_ns = br#"<multistatus xmlns="DAV:"><response><href>https://x/a</href><propstat><prop><getetag>W/"1"</getetag></prop></propstat></response></multistatus>"#;
        assert_eq!(parse(default_ns, 10).unwrap().entries[0].etag.as_deref(), Some("W/\"1\""));
    }

    #[test]
    fn ignores_foreign_namespaces_with_dav_names() {
        let body = br#"<d:multistatus xmlns:d="DAV:" xmlns:x="urn:x"><d:response><d:href>/a</d:href><d:propstat><d:prop>
            <d:resourcetype><x:collection/></d:resourcetype><x:getetag>"no"</x:getetag></d:prop></d:propstat></d:response></d:multistatus>"#;
        assert_eq!(parse(body, 10).unwrap().entries[0], DavEntry { href: "/a".into(), ..DavEntry::default() });
    }

    #[test]
    fn reads_the_status_of_a_whole_response() {
        let body = br#"<d:multistatus xmlns:d="DAV:">
            <d:response><d:href>/dav/gone.txt</d:href><d:status>HTTP/1.1 404 Not Found</d:status></d:response>
            <d:response><d:href>/dav/secret.txt</d:href><d:status>HTTP/1.1 403 Forbidden</d:status></d:response>
            <d:response><d:href>/dav/a.txt</d:href><d:status>HTTP/1.1 200 OK</d:status></d:response>
        </d:multistatus>"#;
        let parsed = parse(body, 10).unwrap();
        assert_eq!(parsed.entries, [DavEntry { href: "/dav/a.txt".into(), ..DavEntry::default() }]);
        assert_eq!(parsed.missing, ["/dav/gone.txt"]);
    }

    #[test]
    fn dav_elements_inside_a_property_value_are_not_structure() {
        let body = br#"<d:multistatus xmlns:d="DAV:" xmlns:x="urn:x"><d:response><d:href>/real</d:href><d:propstat><d:prop>
            <d:getetag>"1"</d:getetag>
            <x:p><d:multistatus><d:response><d:href>/fake</d:href><d:propstat><d:prop><d:getetag>"2"</d:getetag>
                <d:resourcetype><d:collection/></d:resourcetype></d:prop></d:propstat></d:response></d:multistatus>
                <d:href>/also-fake</d:href><d:status>HTTP/1.1 404 Not Found</d:status></x:p>
            </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#;
        let parsed = parse(body, 10).unwrap();
        assert_eq!(parsed.entries, [DavEntry { href: "/real".into(), etag: Some("\"1\"".into()), ..DavEntry::default() }]);
        assert!(parsed.missing.is_empty());
    }

    #[test]
    fn propstats_are_merged_as_they_arrive() {
        let propstats = r#"<d:propstat><d:prop><d:getetag>"e"</d:getetag></d:prop></d:propstat>"#.repeat(5_000);
        let body = format!(r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/a</d:href>{propstats}</d:response></d:multistatus>"#);
        assert_eq!(parse(body.as_bytes(), 1).unwrap().entries[0].etag.as_deref(), Some("\"e\""));
    }

    #[test]
    fn rejects_hostile_or_malformed_input() {
        let doctype = br#"<?xml version="1.0"?><!DOCTYPE d [<!ENTITY x "xxxxxxxx">]><d:multistatus xmlns:d="DAV:"><d:response><d:href>&x;</d:href></d:response></d:multistatus>"#;
        assert_eq!(parse(doctype, 10), Err(CloudError::InvalidResponse("doctype not allowed")));
        let entity = br#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>&x;</d:href></d:response></d:multistatus>"#;
        assert_eq!(parse(entity, 10), Err(CloudError::InvalidResponse("unknown entity")));
        let deep = format!(r#"<d:multistatus xmlns:d="DAV:">{}{}</d:multistatus>"#, "<a>".repeat(40), "</a>".repeat(40));
        assert_eq!(parse(deep.as_bytes(), 10), Err(CloudError::InvalidResponse("xml too deep")));
        let many = format!(r#"<d:multistatus xmlns:d="DAV:">{}</d:multistatus>"#, "<d:response><d:href>/a</d:href></d:response>".repeat(3));
        assert_eq!(parse(many.as_bytes(), 2), Err(CloudError::TooLarge));
        assert!(parse(b"<html><body>login</body></html>", 10).is_err());
        assert!(parse(b"", 10).is_err());
        assert!(parse(br#"<d:multistatus xmlns:d="DAV:"><d:response>"#, 10).is_err());
    }
}
