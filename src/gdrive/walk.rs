//! Path resolution on Google Drive: name lookups across pages, and the walk from the drive root that creates missing
//! folders along the way.

use super::{CloudError, HttpResponse, Item, Outgoing, children_query, create_folder, error_for, files, get, json_body, search_url};
use super::{EMPTY_PAGES, LOOKUP_PAGE};
use crate::client::ClientConfig;
use crate::connection::{AccessScope, Connection};
use crate::path::RemotePath;

/// Tracks a complete name lookup across pages, including empty intermediate pages.
pub(super) struct Lookup {
    query: String,
    name: String,
    oldest: Option<Item>,
    matches: usize,
    remaining: usize,
    empty_pages: usize,
}

pub(super) enum LookupResult {
    More(Outgoing),
    Found(Option<Item>, usize),
}

impl Lookup {
    pub(super) fn new(parent: &str, name: &str, folders_only: bool, limit: usize) -> Self {
        Self {
            query: children_query(parent, Some(name), folders_only),
            name: name.to_owned(),
            oldest: None,
            matches: 0,
            remaining: limit,
            empty_pages: EMPTY_PAGES,
        }
    }

    pub(super) fn page(&self, token: Option<&str>) -> Outgoing {
        get(search_url(&self.query, LOOKUP_PAGE, token))
    }

    pub(super) fn receive(&mut self, response: &HttpResponse) -> Result<LookupResult, CloudError> {
        if response.status != 200 {
            return Err(error_for(response));
        }
        let (items, next) = files(response)?;
        self.remaining = self.remaining.checked_sub(items.len()).ok_or(CloudError::TooLarge)?;
        if items.is_empty() && next.is_some() {
            self.empty_pages = self.empty_pages.checked_sub(1).ok_or(CloudError::TooLarge)?;
        }
        for item in items.into_iter().filter(|item| item.name == self.name) {
            self.matches += 1;
            if self.oldest.as_ref().is_none_or(|oldest| (item.created_at, &item.id) < (oldest.created_at, &oldest.id)) {
                self.oldest = Some(item);
            }
        }
        Ok(match next {
            Some(token) => LookupResult::More(self.page(Some(&token))),
            None => LookupResult::Found(self.oldest.take(), self.matches),
        })
    }
}

#[derive(Clone)]
pub(super) struct Drive {
    limit: usize,
    /// Name of the app folder in My Drive; `None` with the `drive` scope.
    app_folder: Option<String>,
}

impl Drive {
    pub(super) fn of(connection: &Connection, config: &ClientConfig) -> Result<Self, CloudError> {
        let credential = connection.oauth_credential().ok_or(CloudError::InvalidConnection)?;
        let app_folder = match credential.access {
            AccessScope::AppFolder => Some(credential.folder_name.clone().ok_or(CloudError::InvalidConnection)?),
            AccessScope::Full => None,
        };
        Ok(Self { app_folder, limit: config.limits.max_entries })
    }

    /// Resolves `path`; with `create_parents`, missing directories above the last segment are created. The app folder
    /// itself is always created when missing, so that it exists (and shows up in My Drive) right after sign-in.
    pub(super) fn walk(&self, path: &RemotePath, create_parents: bool) -> Walk {
        let mut segments: Vec<String> = self.app_folder.iter().cloned().collect();
        let base = segments.len();
        segments.extend(path.segments().iter().cloned());
        let create = if create_parents { base.max(segments.len().saturating_sub(1)) } else { base };
        Walk { limit: self.limit, segments, create, depth: 0, current: Item::drive_root(), parent: None, state: WalkState::Idle }
    }

    /// Whether the operation on `path` needs no request to find it (the root of My Drive).
    pub(super) fn is_drive_root(&self, path: &RemotePath) -> bool {
        self.app_folder.is_none() && path.is_root()
    }
}

pub(super) enum WalkState {
    Idle,
    Lookup(Lookup),
    Create,
    /// Created a folder (`None` when the response did not describe it); looking the name up again.
    Recheck(Lookup, Option<Item>),
}

/// Resolves a path segment by segment from the drive root.
pub(super) struct Walk {
    pub(super) limit: usize,
    /// From the drive root, including the app folder.
    segments: Vec<String>,
    /// Directories are created when missing at depths below this.
    create: usize,
    /// Segments resolved so far; `current` is the item at this depth.
    depth: usize,
    current: Item,
    parent: Option<Item>,
    state: WalkState,
}

pub(super) enum Walked {
    Send(Outgoing),
    /// `item` is the whole path, `parent` the item one level above it (also when the last segment is missing).
    Found {
        item: Option<Item>,
        parent: Option<Item>,
    },
}

impl Walk {
    pub(super) fn step(&mut self) -> Walked {
        if self.depth == self.segments.len() {
            return Walked::Found { item: Some(self.current.clone()), parent: self.parent.clone() };
        }
        let lookup = Lookup::new(&self.current.id, &self.segments[self.depth], self.depth + 1 < self.segments.len(), self.limit);
        let request = lookup.page(None);
        self.state = WalkState::Lookup(lookup);
        Walked::Send(request)
    }

    pub(super) fn descend(&mut self, item: Item) -> Walked {
        self.parent = Some(std::mem::replace(&mut self.current, item));
        self.depth += 1;
        self.step()
    }

    pub(super) fn receive(&mut self, response: HttpResponse) -> Result<Walked, CloudError> {
        match std::mem::replace(&mut self.state, WalkState::Idle) {
            WalkState::Lookup(mut lookup) => match lookup.receive(&response)? {
                LookupResult::More(request) => {
                    self.state = WalkState::Lookup(lookup);
                    Ok(Walked::Send(request))
                }
                LookupResult::Found(Some(item), _) => Ok(self.descend(item)),
                LookupResult::Found(None, _) if self.depth < self.create => {
                    self.state = WalkState::Create;
                    Ok(Walked::Send(create_folder(&self.current.id, &self.segments[self.depth])))
                }
                LookupResult::Found(None, _) => {
                    let parent = (self.depth + 1 == self.segments.len()).then(|| self.current.clone());
                    Ok(Walked::Found { item: None, parent })
                }
            },
            WalkState::Create => {
                if response.status != 200 {
                    return Err(error_for(&response));
                }
                let created = json_body(&response).and_then(|json| Item::parse(&json)).ok();
                let lookup = Lookup::new(&self.current.id, &self.segments[self.depth], true, self.limit);
                let request = lookup.page(None);
                self.state = WalkState::Recheck(lookup, created);
                Ok(Walked::Send(request))
            }
            WalkState::Recheck(mut lookup, created) => match lookup.receive(&response).map_err(|_| CloudError::CommitUnconfirmed)? {
                LookupResult::More(request) => {
                    self.state = WalkState::Recheck(lookup, created);
                    Ok(Walked::Send(request))
                }
                // The oldest folder with the name, so every device settles on the same one.
                LookupResult::Found(Some(item), _) => Ok(self.descend(item)),
                // The listing lags behind the create: the response already named the folder.
                LookupResult::Found(None, _) => created.map(|item| self.descend(item)).ok_or(CloudError::CommitUnconfirmed),
            },
            WalkState::Idle => Err(CloudError::OutOfOrder),
        }
    }
}
