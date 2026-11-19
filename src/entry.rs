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

    /// A weak ETag (`W/"…"`) cannot be used for the strong comparison of conditional requests.
    pub(crate) fn is_weak(&self) -> bool {
        self.0.starts_with("W/")
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
