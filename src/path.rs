use std::fmt;

use crate::error::CloudError;

/// A path relative to the storage root, stored as segments. The root is the empty path.
///
/// Segments may not be empty, `.`, or `..`, and may not contain `/`, `\`, or control characters: paths come from the UI
/// or from remote listings, so traversal must be ruled out before they are joined into a URL.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RemotePath {
    segments: Vec<String>,
}

impl RemotePath {
    /// The root of the connection.
    #[must_use]
    pub fn root() -> Self {
        Self::default()
    }

    /// Parses `a/b/c`. Leading and trailing `/` are ignored; empty inner segments (`a//b`) are rejected.
    ///
    /// # Errors
    ///
    /// [`CloudError::InvalidPath`] for an empty segment, `.`, `..`, a backslash or a control character.
    pub fn parse(text: &str) -> Result<Self, CloudError> {
        let trimmed = text.trim_matches('/');
        if trimmed.is_empty() {
            return Ok(Self::root());
        }
        Self::from_segments(trimmed.split('/').map(str::to_owned))
    }

    /// A path from already split segments, such as names from a listing.
    ///
    /// # Errors
    ///
    /// [`CloudError::InvalidPath`] if any segment is invalid (see [`RemotePath::parse`]) or contains `/`.
    pub fn from_segments(segments: impl IntoIterator<Item = String>) -> Result<Self, CloudError> {
        let segments: Vec<String> = segments.into_iter().collect();
        if segments.iter().all(|segment| valid_segment(segment)) { Ok(Self { segments }) } else { Err(CloudError::InvalidPath) }
    }

    /// This path with one more segment.
    ///
    /// # Errors
    ///
    /// [`CloudError::InvalidPath`] if `name` is not a valid single segment.
    pub fn join(&self, name: &str) -> Result<Self, CloudError> {
        if !valid_segment(name) {
            return Err(CloudError::InvalidPath);
        }
        let mut segments = self.segments.clone();
        segments.push(name.to_owned());
        Ok(Self { segments })
    }

    /// The path without its last segment; `None` for the root.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        let (_, parent) = self.segments.split_last()?;
        Some(Self { segments: parent.to_vec() })
    }

    /// The last segment; `None` for the root.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.segments.last().map(String::as_str)
    }

    /// The segments, from the root down.
    #[must_use]
    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    /// Whether this is the root.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.segments.is_empty()
    }

    /// Whether `ancestor` is this path or one of its parents.
    #[must_use]
    pub fn starts_with(&self, ancestor: &RemotePath) -> bool {
        self.segments.starts_with(&ancestor.segments)
    }
}

fn valid_segment(segment: &str) -> bool {
    !segment.is_empty() && segment != "." && segment != ".." && !segment.chars().any(|c| c == '/' || c == '\\' || c.is_control())
}

impl fmt::Display for RemotePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.segments.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_rejects_traversal() {
        assert_eq!(RemotePath::parse("/").unwrap(), RemotePath::root());
        let path = RemotePath::parse("/Backups/data.bin").unwrap();
        assert_eq!(path.segments(), ["Backups", "data.bin"]);
        assert_eq!(path.to_string(), "Backups/data.bin");
        assert_eq!(path.parent().unwrap().to_string(), "Backups");
        assert_eq!(path.name(), Some("data.bin"));
        assert_eq!(RemotePath::parse("备份/文件 1").unwrap().segments(), ["备份", "文件 1"]);
        for bad in ["a//b", "a/../b", "./a", "a\\b", "a/\u{0}b", "a/\nb"] {
            assert_eq!(RemotePath::parse(bad), Err(CloudError::InvalidPath), "{bad:?}");
        }
        assert_eq!(RemotePath::root().join(".."), Err(CloudError::InvalidPath));
        assert_eq!(RemotePath::root().parent(), None);
        assert!(path.starts_with(&RemotePath::parse("Backups").unwrap()) && path.starts_with(&RemotePath::root()));
        assert!(!RemotePath::parse("Backup").unwrap().starts_with(&RemotePath::parse("Backups").unwrap()));
    }
}
