use std::time::SystemTime;

use crate::path::RemotePath;

/// A version identifier from the remote (ETag / rev), stored and sent back verbatim and only compared for equality.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Revision(String);

impl Revision {
    /// Wraps a version string, such as one stored after an earlier read.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The version string, for storing it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// RFC 9110 entity-tag syntax. In particular, the wildcard and validator lists must never
    /// turn a version-specific If-Match into a broader condition.
    pub(crate) fn is_strong_etag(&self) -> bool {
        let tag = self.as_str().as_bytes();
        tag.len() >= 2
            && tag.first() == Some(&b'"')
            && tag.last() == Some(&b'"')
            && tag[1..tag.len() - 1].iter().all(|&b| b == 0x21 || (0x23..=0x7e).contains(&b) || b >= 0x80)
    }

    /// A tag that names exactly one version in `If-Match`: a strong entity-tag, or a bare token as Microsoft Graph
    /// returns for personal accounts (`aRDQ2…`). The wildcard, weak tags and lists are refused.
    pub(crate) fn is_single_match_tag(&self) -> bool {
        let tag = self.as_str().as_bytes();
        self.is_strong_etag()
            || (!tag.is_empty()
                && tag != b"*"
                && !tag.starts_with(b"W/")
                && tag.iter().all(|&b| b == 0x21 || ((0x23..=0x7e).contains(&b) && b != b',') || b >= 0x80))
    }
}

/// Metadata of a file or directory.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Entry {
    /// The path relative to the connection's root.
    pub path: RemotePath,
    /// Whether it is a directory.
    pub is_dir: bool,
    /// Size in bytes, for files whose provider reports one.
    pub size: Option<u64>,
    /// Last modification time reported by the server.
    pub modified_at: Option<SystemTime>,
    /// The file's version, for [`Precondition::Matches`]. Directories usually have none.
    pub revision: Option<Revision>,
}

/// File contents together with the metadata of the same version.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct File {
    /// The contents.
    pub data: Vec<u8>,
    /// Metadata of the version that was read.
    pub entry: Entry,
}

impl std::fmt::Debug for File {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("File").field("len", &self.data.len()).field("entry", &self.entry).finish()
    }
}

/// Precondition for a write; if it does not hold, the write fails with [`crate::CloudError::PreconditionFailed`] and the
/// remote is unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Precondition {
    /// Overwrite unconditionally.
    None,
    /// Create only if the file does not exist.
    Absent,
    /// Overwrite only if the remote version is still this one.
    Matches(Revision),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_tags_name_exactly_one_version() {
        for strong in ["\"abc\"", "\"{F2B9A0AE-0AB8},4\"", "\"\""] {
            assert!(Revision::new(strong).is_strong_etag() && Revision::new(strong).is_single_match_tag(), "{strong}");
        }
        for bare in ["aRDQ2NDhGMDZDOTFEOUQzRCE1NDkyNy4w", "0B4dataRevAAA"] {
            assert!(!Revision::new(bare).is_strong_etag() && Revision::new(bare).is_single_match_tag(), "{bare}");
        }
        for refused in ["", "*", "W/\"abc\"", "\"a\", \"b\"", "a,b", "a b", "a\"b", "a\r\nX-Injected: 1"] {
            assert!(!Revision::new(refused).is_strong_etag() && !Revision::new(refused).is_single_match_tag(), "{refused:?}");
        }
    }
}
