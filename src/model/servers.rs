//! Server profiles (GUI state: %APPDATA%\broccoli\state\servers.json).

use super::outbound::OutboundModel;
use super::settings::Settings;
use super::{StateLoadError, load_state, save_state, skip_empty_vec, skip_false};
use crate::model::inbound::{BLOCK_OUTBOUND_TAG, DIRECT_OUTBOUND_TAG};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// The reserved id and title of the group hand-added servers live in. The
/// group always exists, sorts first, and can be neither renamed nor deleted.
pub const MANUAL_GROUP_ID: &str = "manual";
pub const MANUAL_GROUP_TITLE: &str = "Manual";

/// The selector every server tag starts with: Xray matches outbound tags by
/// prefix, so `[` reaches every server and no built-in outbound.
pub const ALL_SERVERS_SELECTOR: &str = "[";

/// The prefix a pre-grouping build wrote in front of a profile's id: those
/// tags are rewritten on load (`srv-01234567` → `[Manual] Name`).
const LEGACY_TAG_PREFIX: &str = "srv-";

/// A server group: the `Manual` group, or a subscription's group.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Group {
    pub id: String,
    pub title: String,
    /// The group's tab is pinned beside the three default tabs. Presentation
    /// only: the stored group order, and with it the generated block order,
    /// keeps its place either way.
    #[serde(default, skip_serializing_if = "skip_false")]
    pub pinned: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription: Option<Subscription>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Group {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().simple().to_string(),
            title: title.into(),
            pinned: false,
            subscription: None,
            extra: Map::new(),
        }
    }
    /// The reserved `Manual` group record.
    pub fn manual() -> Self {
        Self {
            id: MANUAL_GROUP_ID.into(),
            title: MANUAL_GROUP_TITLE.into(),
            pinned: false,
            subscription: None,
            extra: Map::new(),
        }
    }
    pub fn is_manual(&self) -> bool {
        self.id == MANUAL_GROUP_ID
    }
    /// Whether the group's tab sits in the pinned or the unpinned band: its
    /// pin state, and never the reserved `Manual` group, whose tab is one of
    /// the three defaults. The tab bar and
    /// [`ServersFile::reorder_group_in_band`] both read this one definition.
    pub fn in_band(&self, pinned: bool) -> bool {
        !self.is_manual() && self.pinned == pinned
    }
    /// The group's kind, derived from whether it carries feed state. A kind is
    /// fixed at creation: nothing converts a manual group into a subscription
    /// group or the reverse.
    pub fn kind(&self) -> GroupKind {
        if self.subscription.is_some() {
            GroupKind::Subscription
        } else {
            GroupKind::Manual
        }
    }
}

/// What a group is: hand-managed rows, or a provider's feed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GroupKind {
    #[default]
    Manual,
    Subscription,
}

/// The provider-bound state of a subscription group. Body fetching fills the
/// remaining fields; a group record without this object is a plain group.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Subscription {
    pub url: String,
    /// Whether the subscription uses a custom User-Agent instead of the
    /// global one. A custom value is sent verbatim; empty omits the header.
    #[serde(default, skip_serializing_if = "skip_false")]
    pub user_agent_custom: bool,
    /// The custom User-Agent, meaningful only when `user_agent_custom` is set.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub user_agent: String,
    /// True while the title came from the add dialog's default rather than
    /// the user; a provider title may name the group only then.
    #[serde(default, skip_serializing_if = "skip_false")]
    pub title_auto: bool,
    /// The last fetch's outcome: the time, whether it succeeded, and the
    /// error text when it did not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_fetch: Option<FetchResult>,
    /// The provider's traffic and expiry snapshot, when it sent one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<SubscriptionMetadata>,
    /// The last refresh's report.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<RefreshReport>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Subscription {
    /// The User-Agent this fetch sends: the custom value verbatim when the
    /// group chose one, the global value verbatim otherwise. Empty means the
    /// header is omitted.
    pub fn effective_user_agent(&self, global: &str) -> String {
        if self.user_agent_custom {
            self.user_agent.clone()
        } else {
            global.to_owned()
        }
    }
}

/// One fetch's outcome.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FetchResult {
    /// Unix seconds of the attempt.
    pub at: u64,
    pub ok: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `Subscription-Userinfo` plus the `Profile-*` headers and their body-comment
/// fallback. Zero fields mean the provider did not send them.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SubscriptionMetadata {
    pub upload: u64,
    pub download: u64,
    /// Zero means unlimited.
    pub total: u64,
    /// Unix seconds; zero means no expiry.
    pub expire: u64,
    /// `profile-update-interval`, in hours; zero means absent.
    pub update_interval: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub title: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub web_page_url: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub support_url: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub announce: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl SubscriptionMetadata {
    /// The provider's headers in one snapshot. All-empty input means the
    /// provider sent no metadata and yields `None`.
    pub fn from_provider(
        userinfo: &str,
        update_interval: &str,
        title: &str,
        web_page_url: &str,
        support_url: &str,
        announce: &str,
    ) -> Option<Self> {
        let mut metadata = Self::default();
        for pair in userinfo.split(';') {
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            let value = value.trim();
            match key.trim().to_ascii_lowercase().as_str() {
                "upload" => metadata.upload = value.parse().unwrap_or_default(),
                "download" => metadata.download = value.parse().unwrap_or_default(),
                "total" => metadata.total = value.parse().unwrap_or_default(),
                "expire" => {
                    let expire: u64 = value.parse().unwrap_or_default();
                    metadata.expire = if expire > 1_000_000_000_000 {
                        expire / 1000
                    } else {
                        expire
                    };
                }
                _ => {}
            }
        }
        metadata.update_interval = parse_update_interval(update_interval);
        metadata.title = decode_profile_title(title);
        metadata.web_page_url = web_page_url.trim().to_owned();
        metadata.support_url = support_url.trim().to_owned();
        metadata.announce = announce.trim().to_owned();
        let empty = metadata.upload == 0
            && metadata.download == 0
            && metadata.total == 0
            && metadata.expire == 0
            && metadata.update_interval == 0
            && metadata.title.is_empty()
            && metadata.web_page_url.is_empty()
            && metadata.support_url.is_empty()
            && metadata.announce.is_empty();
        (!empty).then_some(metadata)
    }
}

/// `profile-update-interval`: hours; `h`/`d`/`s` tolerated, clamped to
/// 1..=8784 (one year).
pub fn parse_update_interval(text: &str) -> u64 {
    let text = text.trim().to_ascii_lowercase();
    if text.is_empty() {
        return 0;
    }
    let (number, multiplier) = if let Some(value) = text.strip_suffix('h') {
        (value, 1)
    } else if let Some(value) = text.strip_suffix('d') {
        (value, 24)
    } else if let Some(value) = text.strip_suffix('s') {
        (value, 0)
    } else {
        (text.as_str(), 1)
    };
    let Ok(number) = number.trim().parse::<u64>() else {
        return 0;
    };
    if number == 0 {
        return 0;
    }
    let hours = if multiplier == 0 {
        number.div_ceil(3600).max(1)
    } else {
        number.saturating_mul(multiplier)
    };
    hours.clamp(1, 8784)
}

/// A `base64:` `Profile-Title` is unwrapped; anything else is the title.
pub fn decode_profile_title(text: &str) -> String {
    let text = text.trim();
    let Some(encoded) = text.strip_prefix("base64:") else {
        return text.to_owned();
    };
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_else(|| text.to_owned())
}

/// One refresh's outcome, persisted with the subscription so the report window
/// can reopen it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RefreshReport {
    /// Unix seconds of the refresh.
    pub at: u64,
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
    pub refused: usize,
    pub ignored: usize,
    /// Whether the refresh removed the active server and moved the route to
    /// Block.
    pub route_to_block: bool,
    /// Bounded rows; the counts above stay exact when rows are dropped.
    pub rows: Vec<ReportRow>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One report row.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportRow {
    pub kind: ReportKind,
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub raw: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReportKind {
    Added,
    Updated,
    Removed,
    Refused,
    Ignored,
}

/// The opaque refresh keys stored at import and never recomputed: the content
/// key matches the same provider entry, the identity key matches the same
/// server after the user edited it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ProfileOrigin {
    pub content_key: String,
    pub identity_key: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ServersFile {
    pub version: u32,
    /// id of the active profile
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<String>,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub profiles: Vec<ServerProfile>,
    /// The groups server rows are organised in; [`Group::manual`] always
    /// exists and sorts first. A file written before groups carries none, so
    /// the load migration can tell the legacy shape apart.
    #[serde(default, skip_serializing_if = "skip_empty_vec")]
    pub groups: Vec<Group>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
    /// The load repaired an active id that named no profile. Runtime-only;
    /// the servers screen surfaces it once.
    #[serde(skip)]
    pub active_route_repaired: bool,
}

impl Default for ServersFile {
    fn default() -> Self {
        Self {
            version: 1,
            active: None,
            profiles: Vec::new(),
            groups: vec![Group::manual()],
            extra: Map::new(),
            active_route_repaired: false,
        }
    }
}

/// The profiles one generated document carries, in wire order: the active
/// route's server first, then the rest in grouped display order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EmittedSet {
    /// Profile indices in wire order.
    pub order: Vec<usize>,
    /// Indices emitted only because an emitted profile dials through them:
    /// their switch stays off and locked.
    pub chain_only: std::collections::BTreeSet<usize>,
}

/// One fetched entry, ready to reconcile: the profile and the two keys the
/// refresh matches by.
#[derive(Clone, Debug)]
pub struct SubscriptionEntry {
    pub profile: ServerProfile,
    pub content_key: String,
    pub identity_key: String,
}

/// How many report rows are kept; the counts stay exact.
pub const REPORT_ROW_LIMIT: usize = 500;

/// Append one report row while the row list has room.
pub fn push_report_row(rows: &mut Vec<ReportRow>, row: ReportRow) {
    if rows.len() < REPORT_ROW_LIMIT {
        rows.push(row);
    }
}

/// A name unique among `taken` too: the freshly built group rows are not in
/// the server list yet while a refresh resolves names.
fn unique_against<'a>(base: &str, taken: impl Iterator<Item = &'a str>) -> String {
    let taken: Vec<&str> = taken.collect();
    if !taken.contains(&base) {
        return base.to_owned();
    }
    let mut suffix = 1;
    loop {
        let candidate = format!("{base} ({suffix})");
        if !taken.contains(&candidate.as_str()) {
            return candidate;
        }
        suffix += 1;
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

impl ServersFile {
    /// Load servers.json. Missing or structurally corrupt files fall back to
    /// `Default` (the corrupt file is quarantined); a
    /// semantically invalid file (valid JSON, bad content — e.g. an unknown
    /// `security`/`network` value) returns an error naming the field and is
    /// left intact for the user to fix.
    pub fn load() -> Result<Self, StateLoadError> {
        Self::load_with_tag_renames().map(|(servers, _)| servers)
    }
    /// [`Self::load`] plus the legacy tag rewrites the migration found (old
    /// tag → new tag, and `srv-` → `[`), so the loader can apply them to the
    /// routing document. [`Self::load`] drops them: a caller that judges a
    /// profile list has no routing document to rewrite.
    pub fn load_with_tag_renames() -> Result<(Self, BTreeMap<String, String>), StateLoadError> {
        let mut servers: Self = load_state("servers.json")?;
        let renames = servers.migrate();
        // The stored route is the route: a profile id names that server, the
        // reserved `direct`/`block` values name the built-ins, and no value
        // means Direct. The load never promotes a profile into a missing id —
        // a hand-edited or stale id becomes Block, so a broken file cannot
        // silently route traffic through a server the user did not choose.
        match servers.active.clone() {
            Some(id)
                if id != DIRECT_OUTBOUND_TAG
                    && id != BLOCK_OUTBOUND_TAG
                    && !servers.profiles.iter().any(|profile| profile.id == id) =>
            {
                tracing::warn!(
                    "servers.active {id:?} names no profile; the active route is now block"
                );
                servers.active = Some(BLOCK_OUTBOUND_TAG.to_owned());
                servers.active_route_repaired = true;
            }
            Some(_) => {}
            None => {}
        }
        Ok((servers, renames))
    }
    /// A server file built from its active choice and profile list, with the
    /// reserved group and every profile's cached group title filled in.
    pub fn with_profiles(active: Option<String>, profiles: Vec<ServerProfile>) -> Self {
        let mut servers = Self {
            version: 1,
            active,
            profiles,
            ..Self::default()
        };
        servers.hydrate_group_titles();
        servers
    }
    /// Replace one group's profiles with a fetched entry list.
    ///
    /// Provider fields and names win; each entry keeps the matched profile's
    /// switch and id (so the active route and every reference survive), matched
    /// by the stored content key first and the identity key second. A profile
    /// with no matching entry is removed — and when it was the active server
    /// the route becomes Block. Returns the report for the caller to extend
    /// with its refused/ignored rows.
    pub fn refresh_subscription_group(
        &mut self,
        settings: &mut Settings,
        group_id: &str,
        entries: Vec<SubscriptionEntry>,
    ) -> RefreshReport {
        let title = self
            .group_title_of(group_id)
            .unwrap_or(MANUAL_GROUP_TITLE)
            .to_owned();
        let active = self.active.clone();
        let existing: Vec<ServerProfile> = self
            .profiles
            .iter()
            .filter(|profile| profile.group_id() == group_id)
            .cloned()
            .collect();
        let mut by_content = BTreeMap::new();
        let mut by_identity = BTreeMap::new();
        for (index, profile) in existing.iter().enumerate() {
            if let Some(origin) = &profile.origin {
                by_content.insert(origin.content_key.clone(), index);
                by_identity.insert(origin.identity_key.clone(), index);
            }
        }
        self.profiles
            .retain(|profile| profile.group_id() != group_id);

        let mut report = RefreshReport {
            at: unix_now(),
            ..RefreshReport::default()
        };
        let mut used = std::collections::BTreeSet::new();
        let mut renames = Vec::new();
        let mut fresh = Vec::with_capacity(entries.len());
        for entry in entries {
            let matched = by_content
                .get(&entry.content_key)
                .copied()
                .filter(|index| !used.contains(index))
                .or_else(|| {
                    by_identity
                        .get(&entry.identity_key)
                        .copied()
                        .filter(|index| !used.contains(index))
                });
            let old = matched.map(|index| {
                used.insert(index);
                &existing[index]
            });
            let mut profile = entry.profile;
            profile.group = group_id.to_owned();
            profile.group_title = title.clone();
            profile.origin = Some(ProfileOrigin {
                content_key: entry.content_key,
                identity_key: entry.identity_key,
                ..ProfileOrigin::default()
            });
            if let Some(old) = old {
                profile.id = old.id.clone();
                profile.enabled = old.enabled;
                let old_tag = old.tag();
                profile.name = self.unique_profile_name(group_id, &profile.name, Some(&old.id));
                profile.name = unique_against(
                    &profile.name,
                    fresh
                        .iter()
                        .map(|profile: &ServerProfile| profile.name.as_str()),
                );
                let new_tag = profile.tag();
                if old_tag != new_tag {
                    renames.push((old_tag, new_tag));
                }
                report.updated += 1;
                push_report_row(
                    &mut report.rows,
                    ReportRow {
                        kind: ReportKind::Updated,
                        name: profile.name.clone(),
                        raw: String::new(),
                    },
                );
            } else {
                profile.name = self.unique_profile_name(group_id, &profile.name, None);
                profile.name = unique_against(
                    &profile.name,
                    fresh
                        .iter()
                        .map(|profile: &ServerProfile| profile.name.as_str()),
                );
                report.added += 1;
                push_report_row(
                    &mut report.rows,
                    ReportRow {
                        kind: ReportKind::Added,
                        name: profile.name.clone(),
                        raw: String::new(),
                    },
                );
            }
            fresh.push(profile);
        }
        for (index, profile) in existing.iter().enumerate() {
            if used.contains(&index) {
                continue;
            }
            report.removed += 1;
            push_report_row(
                &mut report.rows,
                ReportRow {
                    kind: ReportKind::Removed,
                    name: profile.name.clone(),
                    raw: String::new(),
                },
            );
        }
        self.profiles.extend(fresh);
        if let Some(active) = active
            && !self.profiles.iter().any(|profile| profile.id == active)
            && active != DIRECT_OUTBOUND_TAG
            && active != BLOCK_OUTBOUND_TAG
        {
            self.active = Some(BLOCK_OUTBOUND_TAG.to_owned());
            report.route_to_block = true;
        }
        if !renames.is_empty() {
            self.rewrite_chain_targets(&renames);
            settings.rewrite_outbound_tags(&renames);
        }
        report
    }
    /// Replace the stored profile that carries `profile.id`, keeping its name
    /// unique inside its group and rewriting every reference to the old tag —
    /// chain hops inside the server list, and routing rules, balancers and
    /// observatory selectors in `settings`. Returns false when no profile
    /// carries that id.
    pub fn replace_profile(&mut self, settings: &mut Settings, mut profile: ServerProfile) -> bool {
        let Some(index) = self
            .profiles
            .iter()
            .position(|existing| existing.id == profile.id)
        else {
            return false;
        };
        let group_id = profile.group_id().to_owned();
        let group_title = self
            .group_title_of(&group_id)
            .unwrap_or(MANUAL_GROUP_TITLE)
            .to_owned();
        profile.group = group_id.clone();
        profile.name = self.unique_profile_name(&group_id, &profile.name, Some(&profile.id));
        profile.group_title = group_title;
        let old_tag = self.profiles[index].tag();
        self.profiles[index] = profile;
        let new_tag = self.profiles[index].tag();
        if old_tag != new_tag {
            let renames = vec![(old_tag, new_tag)];
            self.rewrite_chain_targets(&renames);
            settings.rewrite_outbound_tags(&renames);
        }
        true
    }
    /// Append a switched-off snapshot of the subscription row `id` into the
    /// manual group `group_id`; a missing or subscription group falls back to
    /// `Manual`, which is the reserved manual group. The subscription row
    /// stays untouched, the copy never takes the active route, and a refresh
    /// cannot reach it. Returns the copy's id; a manual row has no
    /// subscription snapshot to copy.
    pub fn copy_to_manual(&mut self, id: &str, group_id: &str) -> Option<String> {
        let source = self
            .profiles
            .iter()
            .find(|profile| profile.id == id && profile.origin.is_some())?
            .clone();
        let target = self
            .groups
            .iter()
            .find(|group| group.id == group_id && group.kind() == GroupKind::Manual)
            .map(|group| group.id.clone())
            .unwrap_or_else(|| MANUAL_GROUP_ID.to_owned());
        let title = self
            .group_title_of(&target)
            .unwrap_or(MANUAL_GROUP_TITLE)
            .to_owned();
        let mut copy = source;
        copy.id = uuid::Uuid::new_v4().simple().to_string();
        copy.group = target.clone();
        copy.group_title = title;
        copy.enabled = false;
        copy.origin = None;
        copy.name = self.unique_profile_name(&target, &copy.name, None);
        let id = copy.id.clone();
        self.profiles.push(copy);
        Some(id)
    }
    /// Append a profile from an import or a copy: an unknown group falls back
    /// to `Manual`, and the name is made unique inside its group.
    pub fn adopt_profile(&mut self, profile: ServerProfile) {
        let group_id = profile.group_id().to_owned();
        self.adopt_profile_in(profile, &group_id);
    }
    /// Append a profile into `group_id` — the group the tab that launched the
    /// add, paste or conversion owns. An unknown or missing group falls back
    /// to `Manual`, and the name is made unique inside the target group.
    pub fn adopt_profile_in(&mut self, mut profile: ServerProfile, group_id: &str) {
        let group_id = if self.group_title_of(group_id).is_some() {
            group_id
        } else {
            MANUAL_GROUP_ID
        };
        profile.name = self.unique_profile_name(group_id, &profile.name, None);
        profile.group_title = self
            .group_title_of(group_id)
            .unwrap_or(MANUAL_GROUP_TITLE)
            .to_owned();
        profile.group = group_id.to_owned();
        self.profiles.push(profile);
    }
    /// Delete a group and its servers. The reserved `Manual` group cannot be
    /// deleted, and neither can a group that does not exist, so this returns
    /// `false` for both without touching the file. When one of the deleted
    /// servers was the active route — or the group held the last servers — the
    /// route moves to Block.
    pub fn delete_group(&mut self, id: &str) -> bool {
        if id == MANUAL_GROUP_ID || self.group_title_of(id).is_none() {
            return false;
        }
        self.groups.retain(|group| group.id != id);
        self.profiles.retain(|profile| profile.group_id() != id);
        let active_lost = self.active.as_deref().is_some_and(|active| {
            active != DIRECT_OUTBOUND_TAG
                && active != BLOCK_OUTBOUND_TAG
                && !self.profiles.iter().any(|profile| profile.id == active)
        });
        if active_lost || self.profiles.is_empty() {
            self.active = Some(BLOCK_OUTBOUND_TAG.to_owned());
        }
        true
    }
    /// Atomic save (tmp + rename).
    pub fn save(&self) -> anyhow::Result<()> {
        save_state("servers.json", self)
    }
    pub fn active_profile(&self) -> Option<&ServerProfile> {
        let id = self.active.as_deref()?;
        self.profiles.iter().find(|p| p.id == id)
    }
    /// Make `id` the active route: a profile id, or the reserved `direct` /
    /// `block` value. Row order is independent of the route now — the
    /// emitter puts the active server first — so no row moves.
    pub fn activate(&mut self, id: &str) {
        self.active = Some(id.to_owned());
    }
    /// The built-in outbound the active route names, if it is Direct or
    /// Block rather than a profile.
    pub fn active_route_builtin(&self) -> Option<&'static str> {
        match self.active.as_deref() {
            None | Some(DIRECT_OUTBOUND_TAG) => Some(DIRECT_OUTBOUND_TAG),
            Some(BLOCK_OUTBOUND_TAG) => Some(BLOCK_OUTBOUND_TAG),
            _ => None,
        }
    }
    /// Profile indices in grouped display order: the reserved `Manual` group
    /// first, then groups in stored order, rows in list order within each
    /// group. A profile whose group record is missing counts as `Manual`.
    pub fn grouped_order(&self) -> Vec<usize> {
        let mut order = Vec::with_capacity(self.profiles.len());
        let grouped = |group_id: &str, order: &mut Vec<usize>| {
            for (index, profile) in self.profiles.iter().enumerate() {
                if profile.group_id() == group_id && !order.contains(&index) {
                    order.push(index);
                }
            }
        };
        grouped(MANUAL_GROUP_ID, &mut order);
        for group in &self.groups {
            if !group.is_manual() {
                grouped(&group.id, &mut order);
            }
        }
        for index in 0..self.profiles.len() {
            if !order.contains(&index) {
                order.push(index);
            }
        }
        order
    }
    /// Move the profile at `from` inside its own group: ahead of the sibling
    /// at `before`, or to the group's tail when that is `None`. Row order is
    /// per group, so a destination naming another group's profile is refused
    /// and the stored list stays untouched. Returns whether the order changed.
    pub fn move_profile_in_group(&mut self, from: usize, before: Option<usize>) -> bool {
        let Some(profile) = self.profiles.get(from) else {
            return false;
        };
        let group = profile.group_id().to_owned();
        if let Some(target) = before
            && (target == from
                || self
                    .profiles
                    .get(target)
                    .is_none_or(|profile| profile.group_id() != group))
        {
            return false;
        }
        let moved = self.profiles.remove(from);
        let insert = match before {
            Some(target) if target > from => target - 1,
            Some(target) => target,
            // The group's tail in the stored list; other groups' rows move
            // past in neither direction, since only relative order counts.
            None => self
                .profiles
                .iter()
                .rposition(|profile| profile.group_id() == group)
                .map_or(self.profiles.len(), |last| last + 1),
        };
        let changed = insert != from;
        self.profiles.insert(insert, moved);
        changed
    }
    /// The profiles the generated document carries: the active profile,
    /// every enabled profile, and every profile reachable transitively
    /// through a chain hop from those. The active profile leads; the rest
    /// follow grouped display order. A hop reached only through a chain is
    /// reported in `chain_only`, whatever its switch says.
    pub fn emitted_set(&self) -> EmittedSet {
        let tags: BTreeMap<String, usize> = self
            .profiles
            .iter()
            .enumerate()
            .map(|(index, profile)| (profile.tag(), index))
            .collect();
        let active = self
            .active
            .as_deref()
            .and_then(|id| self.profiles.iter().position(|profile| profile.id == id));
        let mut seeds = Vec::with_capacity(self.profiles.len());
        if let Some(index) = active {
            seeds.push(index);
        }
        for (index, profile) in self.profiles.iter().enumerate() {
            if profile.enabled && Some(index) != active {
                seeds.push(index);
            }
        }
        let mut included = std::collections::BTreeSet::new();
        let mut queue = seeds.clone();
        while let Some(index) = queue.pop() {
            if !included.insert(index) {
                continue;
            }
            let Some(target) = self.profiles[index].chain_target() else {
                continue;
            };
            if let Some(&hop) = tags.get(target)
                && !included.contains(&hop)
            {
                queue.push(hop);
            }
        }
        let chain_only = included
            .iter()
            .copied()
            .filter(|index| !seeds.contains(index))
            .collect();
        let mut order = Vec::with_capacity(included.len());
        if let Some(index) = active
            && included.contains(&index)
        {
            order.push(index);
        }
        for index in self.grouped_order() {
            if included.contains(&index) && Some(index) != active {
                order.push(index);
            }
        }
        EmittedSet { order, chain_only }
    }
    /// Ensure the reserved `Manual` group exists, carries its reserved title,
    /// and sorts first.
    pub fn ensure_manual_group(&mut self) {
        match self
            .groups
            .iter()
            .position(|group| group.id == MANUAL_GROUP_ID)
        {
            Some(index) => {
                self.groups[index].title = MANUAL_GROUP_TITLE.into();
                if index > 0 {
                    let manual = self.groups.remove(index);
                    self.groups.insert(0, manual);
                }
            }
            None => self.groups.insert(0, Group::manual()),
        }
    }
    /// Move group `id` to position `to` inside its pinned or unpinned tab
    /// band. Only the dragged band's slots in the stored group order move;
    /// each other band keeps its members and their places, so a drag never
    /// changes the other band's blocks and pinning alone never moves a block.
    /// The reserved `Manual` group does not move.
    pub fn reorder_group_in_band(&mut self, id: &str, to: usize) {
        if id == MANUAL_GROUP_ID {
            return;
        }
        let Some(pinned) = self
            .groups
            .iter()
            .find(|group| group.id == id)
            .map(|group| group.pinned)
        else {
            return;
        };
        let slots: Vec<usize> = self
            .groups
            .iter()
            .enumerate()
            .filter(|(_, group)| group.in_band(pinned))
            .map(|(index, _)| index)
            .collect();
        let mut band: Vec<Group> = slots
            .iter()
            .map(|&index| self.groups[index].clone())
            .collect();
        let Some(from) = band.iter().position(|group| group.id == id) else {
            return;
        };
        let moved = band.remove(from);
        let to = to.min(band.len());
        band.insert(to, moved);
        for (&slot, group) in slots.iter().zip(band) {
            self.groups[slot] = group;
        }
    }
    /// Refresh each profile's cached group title from its group record and
    /// move a profile whose group disappeared into `Manual`.
    pub fn hydrate_group_titles(&mut self) {
        let titles: BTreeMap<String, String> = self
            .groups
            .iter()
            .map(|group| (group.id.clone(), group.title.clone()))
            .collect();
        for profile in &mut self.profiles {
            let group_id = profile.group_id().to_owned();
            match titles.get(&group_id) {
                Some(title) => {
                    profile.group = group_id;
                    profile.group_title.clone_from(title);
                }
                None => {
                    profile.group = MANUAL_GROUP_ID.into();
                    profile.group_title = MANUAL_GROUP_TITLE.into();
                }
            }
        }
    }
    /// The title of the group `group_id` names, if it exists.
    pub fn group_title_of(&self, group_id: &str) -> Option<&str> {
        self.groups
            .iter()
            .find(|group| group.id == group_id)
            .map(|group| group.title.as_str())
    }
    /// The outbound tag `profile` carries, resolved against this list's
    /// groups. Falls back to `[Manual] Name` when the profile's group is
    /// missing, the same title [`Self::hydrate_group_titles`] would assign.
    pub fn tag_of(&self, profile: &ServerProfile) -> String {
        let title = self
            .group_title_of(profile.group_id())
            .unwrap_or(MANUAL_GROUP_TITLE);
        format!("[{title}] {}", profile.name)
    }
    /// A title not already used by another group: `base`, then `base (1)`,
    /// `base (2)`, in that order.
    pub fn unique_group_title(&self, base: &str, except: Option<&str>) -> String {
        let base = match base.trim() {
            "" => "Group",
            trimmed => trimmed,
        };
        let mut title = base.to_owned();
        let mut suffix = 1;
        while self
            .groups
            .iter()
            .any(|group| group.title == title && Some(group.id.as_str()) != except)
        {
            title = format!("{base} ({suffix})");
            suffix += 1;
        }
        title
    }
    /// A name not already used inside `group_id`: `base`, then `base (1)`,
    /// `base (2)`, in that order.
    pub fn unique_profile_name(&self, group_id: &str, base: &str, except: Option<&str>) -> String {
        let base = base.trim();
        let mut name = base.to_owned();
        let mut suffix = 1;
        while self.profiles.iter().any(|profile| {
            profile.name == name
                && profile.group_id() == group_id
                && Some(profile.id.as_str()) != except
        }) {
            name = format!("{base} ({suffix})");
            suffix += 1;
        }
        name
    }
    /// Rename a profile, keeping its name unique inside its group and
    /// rewriting every chain hop that named the old tag. Returns the tag
    /// rewrites the caller must apply to the routing document
    /// ([`Settings::rewrite_outbound_tags`]).
    pub fn rename_profile(&mut self, id: &str, name: &str) -> Vec<(String, String)> {
        let Some(index) = self.profiles.iter().position(|profile| profile.id == id) else {
            return Vec::new();
        };
        let group_id = self.profiles[index].group_id().to_owned();
        let old_tag = self.profiles[index].tag();
        let name = self.unique_profile_name(&group_id, name, Some(id));
        self.profiles[index].name = name;
        let new_tag = self.profiles[index].tag();
        if old_tag == new_tag {
            return Vec::new();
        }
        self.rewrite_chain_targets(&[(old_tag.clone(), new_tag.clone())]);
        vec![(old_tag, new_tag)]
    }
    /// Rename a group, keeping its title unique and rewriting every tag it
    /// prefixes together with every chain hop that named one. The reserved
    /// `Manual` group cannot be renamed. Returns the tag rewrites the caller
    /// must apply to the routing document
    /// ([`Settings::rewrite_outbound_tags`]).
    pub fn rename_group(&mut self, id: &str, title: &str) -> Vec<(String, String)> {
        if id == MANUAL_GROUP_ID {
            return Vec::new();
        }
        let Some(index) = self.groups.iter().position(|group| group.id == id) else {
            return Vec::new();
        };
        let title = self.unique_group_title(title, Some(id));
        self.groups[index].title = title;
        let mut renames = Vec::new();
        for profile in &mut self.profiles {
            if profile.group_id() != id {
                continue;
            }
            let old_tag = profile.tag();
            profile.group_title = self
                .groups
                .iter()
                .find(|group| group.id == id)
                .map(|group| group.title.clone())
                .unwrap_or_else(|| MANUAL_GROUP_TITLE.into());
            let new_tag = profile.tag();
            if old_tag != new_tag {
                renames.push((old_tag, new_tag));
            }
        }
        self.rewrite_chain_targets(&renames);
        renames
    }
    /// Rewrite `dialerProxy` targets inside the profile set according to
    /// `renames` (old tag → new tag).
    fn rewrite_chain_targets(&mut self, renames: &[(String, String)]) {
        if renames.is_empty() {
            return;
        }
        for profile in &mut self.profiles {
            let Some(target) = profile.chain_target().map(str::to_owned) else {
                continue;
            };
            if let Some((_, new_tag)) = renames.iter().find(|(old, _)| *old == target) {
                profile.set_chain_target(new_tag.clone());
            }
        }
    }
    /// One-time upgrade from the `srv-<id8>` scheme: create `Manual`, put
    /// every profile in it, give each a name (its address when it has none),
    /// mark it enabled so the configuration does not change, and record the
    /// tag rewrites for the loader. A file that already has groups is
    /// already migrated; only the `Manual` group is repaired there.
    fn migrate(&mut self) -> BTreeMap<String, String> {
        let legacy = self.groups.is_empty();
        self.ensure_manual_group();
        let mut renames = BTreeMap::new();
        if legacy {
            let mut names = std::collections::BTreeSet::new();
            for profile in &mut self.profiles {
                profile.group = MANUAL_GROUP_ID.into();
                profile.enabled = true;
                let mut base = profile.name.trim().to_owned();
                if base.is_empty() {
                    base = profile
                        .server_address()
                        .unwrap_or_else(|| legacy_tag_id(&profile.id).to_owned());
                }
                let mut name = base.clone();
                let mut suffix = 1;
                while !names.insert(name.clone()) {
                    name = format!("{base} ({suffix})");
                    suffix += 1;
                }
                profile.name = name;
            }
            for profile in &self.profiles {
                let old = format!("{LEGACY_TAG_PREFIX}{}", legacy_tag_id(&profile.id));
                renames.insert(old, profile.tag());
            }
            renames.insert(LEGACY_TAG_PREFIX.into(), ALL_SERVERS_SELECTOR.into());
            let pairs: Vec<(String, String)> = renames
                .iter()
                .map(|(old, new)| (old.clone(), new.clone()))
                .collect();
            self.rewrite_chain_targets(&pairs);
        }
        self.hydrate_group_titles();
        renames
    }
}

/// The id prefix a pre-grouping build put after `srv-`: the id's first 8
/// characters, or the whole id when it is shorter.
fn legacy_tag_id(id: &str) -> &str {
    let end = id
        .char_indices()
        .nth(8)
        .map_or(id.len(), |(index, _)| index);
    &id[..end]
}

/// Rename a profile and its tag references in the routing document in one
/// step: rules, chain hops, balancer and observatory selectors.
pub fn rename_profile(servers: &mut ServersFile, settings: &mut Settings, id: &str, name: &str) {
    let renames = servers.rename_profile(id, name);
    settings.rewrite_outbound_tags(&renames);
}

/// Rename a group and every tag it prefixes, in the profile set and in the
/// routing document, in one step.
pub fn rename_group(servers: &mut ServersFile, settings: &mut Settings, id: &str, title: &str) {
    let renames = servers.rename_group(id, title);
    settings.rewrite_outbound_tags(&renames);
}

/// What one latency measurement observed: a delay, or a dead outbound, with
/// the mechanism that produced it and when. Runtime-only: the profile lets a
/// latency test's verdict outrank background monitoring, and the settings
/// file never carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeVerdict {
    pub outcome: ProbeOutcome,
    pub source: ProbeSource,
    pub measured_at: std::time::SystemTime,
    /// The captured core error for a dead verdict; absent for a delay.
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeOutcome {
    Delay(i64),
    Dead,
}

/// Which mechanism measured a verdict: the user's latency test or the
/// background health engine's monitoring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeSource {
    LatencyTest,
    Monitoring,
}

impl ProbeVerdict {
    /// A delay measured now by `source`.
    pub fn delay(ms: i64, source: ProbeSource) -> Self {
        Self {
            outcome: ProbeOutcome::Delay(ms),
            source,
            measured_at: std::time::SystemTime::now(),
            error: None,
        }
    }

    /// A dead outbound measured now by `source`, with the core's error when
    /// one was captured.
    pub fn dead(source: ProbeSource, error: Option<String>) -> Self {
        Self {
            outcome: ProbeOutcome::Dead,
            source,
            measured_at: std::time::SystemTime::now(),
            error,
        }
    }

    /// The measured delay, when the verdict is a delay.
    pub fn delay_ms(&self) -> Option<i64> {
        match self.outcome {
            ProbeOutcome::Delay(ms) => Some(ms),
            ProbeOutcome::Dead => None,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ServerProfile {
    pub id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// The id of the group this profile belongs to; empty means `manual` for
    /// a file written before grouping.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub group: String,
    /// Whether the profile enters the generated configuration besides the
    /// active route. Every new profile starts switched off.
    #[serde(skip_serializing_if = "skip_false")]
    pub enabled: bool,
    pub outbound: OutboundModel,
    /// The last probe verdict — runtime cache, never persisted.
    #[serde(skip)]
    pub verdict: Option<ProbeVerdict>,
    /// The refresh keys of a subscription import. Absent on a hand-added
    /// profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<ProfileOrigin>,
    /// The title of [`Self::group`], cached so [`Self::tag`] can be built
    /// without the server list. Runtime only; refreshed by
    /// [`ServersFile::hydrate_group_titles`].
    #[serde(skip)]
    pub(crate) group_title: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl ServerProfile {
    pub fn new(name: impl Into<String>, outbound: OutboundModel) -> Self {
        Self {
            id: uuid::Uuid::new_v4().simple().to_string(),
            name: name.into(),
            group: MANUAL_GROUP_ID.into(),
            enabled: false,
            outbound,
            verdict: None,
            origin: None,
            group_title: MANUAL_GROUP_TITLE.into(),
            extra: Map::new(),
        }
    }
    /// The group id this profile belongs to, with the legacy empty value
    /// resolved to `manual`.
    pub fn group_id(&self) -> &str {
        if self.group.is_empty() {
            MANUAL_GROUP_ID
        } else {
            &self.group
        }
    }
    /// `[Group] Name` — outbound tag used in generated configs, routing and
    /// stats. The group title comes from the owning server list; a profile
    /// built outside one falls back to `Manual`.
    pub fn tag(&self) -> String {
        let title = if self.group_title.is_empty() {
            MANUAL_GROUP_TITLE
        } else {
            self.group_title.as_str()
        };
        format!("[{title}] {}", self.name)
    }
    /// The tag's four literal parts, without formatting the whole tag.
    fn tag_parts(&self) -> [&str; 4] {
        let title = if self.group_title.is_empty() {
            MANUAL_GROUP_TITLE
        } else {
            self.group_title.as_str()
        };
        ["[", title, "] ", self.name.as_str()]
    }
    /// Whether [`Self::tag`] equals `other`.
    pub fn tag_eq(&self, other: &str) -> bool {
        let [open, title, close, name] = self.tag_parts();
        let Some(rest) = other.strip_prefix(open) else {
            return false;
        };
        let Some(rest) = rest.strip_prefix(title) else {
            return false;
        };
        let Some(rest) = rest.strip_prefix(close) else {
            return false;
        };
        rest == name
    }
    /// Whether [`Self::tag`] starts with `pattern` — the balancer and
    /// observatory selectors match outbound tags by prefix
    /// (`app/proxyman/outbound.Manager.Select`). The empty pattern matches
    /// every tag, exactly as the core's prefix match does.
    pub fn tag_starts_with(&self, pattern: &str) -> bool {
        let mut remaining = pattern;
        for part in self.tag_parts() {
            if remaining.is_empty() {
                return true;
            }
            let compared = remaining.len().min(part.len());
            if part.as_bytes()[..compared] != remaining.as_bytes()[..compared] {
                return false;
            }
            if remaining.len() <= part.len() {
                return true;
            }
            remaining = &remaining[part.len()..];
        }
        remaining.is_empty()
    }
    /// The outbound tag this profile dials through, if any —
    /// `streamSettings.sockopt.dialerProxy`, the one spelling the pinned core
    /// still reads. Validation rejects a chain target naming no outbound.
    pub fn chain_target(&self) -> Option<&str> {
        self.outbound
            .stream
            .sockopt
            .as_ref()
            .map(|sockopt| sockopt.dialer_proxy.as_str())
            .filter(|tag| !tag.is_empty())
    }
    /// Set (or with an empty value, clear) the chain target.
    fn set_chain_target(&mut self, tag: String) {
        let mut sockopt = self.outbound.stream.sockopt.take().unwrap_or_default();
        sockopt.dialer_proxy = tag;
        self.outbound.stream.sockopt = Some(sockopt);
    }
    /// The remote server endpoint in display form, or `None` when the
    /// protocol carries no usable address. The protocol table owns both the
    /// shape and the spelling
    /// ([`crate::model::outbound::ProtocolSettings::server_address`]).
    pub fn server_address(&self) -> Option<String> {
        self.outbound.settings.server_address()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::outbound::{OutboundModel, Protocol, ProtocolSettings};

    fn profile_with_address(address: &str, port: u16) -> ServerProfile {
        let mut profile = ServerProfile::new("srv", OutboundModel::new(Protocol::Vless));
        let ProtocolSettings::Vless(settings) = &mut profile.outbound.settings else {
            unreachable!("Vless is the default protocol");
        };
        settings.address = address.into();
        settings.port = port;
        profile
    }

    #[test]
    fn server_address_formats_host_port_and_brackets_ipv6() {
        assert_eq!(
            profile_with_address("1.2.3.4", 443)
                .server_address()
                .as_deref(),
            Some("1.2.3.4:443")
        );
        assert_eq!(
            profile_with_address("2001:db8::1", 443)
                .server_address()
                .as_deref(),
            Some("[2001:db8::1]:443")
        );
    }

    #[test]
    fn server_address_omitted_when_host_or_port_unusable() {
        assert_eq!(profile_with_address("", 443).server_address(), None);
        assert_eq!(profile_with_address("1.2.3.4", 0).server_address(), None);
        let freedom = ServerProfile::new("direct", OutboundModel::new(Protocol::Freedom));
        assert_eq!(freedom.server_address(), None);
    }

    #[test]
    fn chain_target_reads_the_dialer_proxy_spelling_only() {
        let mut profile = ServerProfile::new("hop", OutboundModel::new(Protocol::Freedom));
        assert_eq!(profile.chain_target(), None);
        profile.outbound.chain_via("srv-exit");
        assert_eq!(profile.chain_target(), Some("srv-exit"));
        // An empty value is no chain.
        if let Some(sockopt) = profile.outbound.stream.sockopt.as_mut() {
            sockopt.dialer_proxy.clear();
        }
        assert_eq!(profile.chain_target(), None);
    }

    #[test]
    fn tag_comparisons_agree_with_the_formatted_tag() {
        let profile = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        let tag = profile.tag();
        assert_eq!(tag, "[Manual] Tokyo");
        // Every pattern shape: empty, a bracket prefix, a partial group, the
        // full tag, beyond it, and outside the namespace.
        for pattern in [
            "",
            "[",
            "[M",
            "[Manual",
            "[Manual]",
            "[Manual] ",
            "[Manual] T",
            "[Manual] Tokyo",
            "[Manual] Tokyo2",
            "srv-",
            "direct",
        ] {
            assert_eq!(
                profile.tag_starts_with(pattern),
                tag.starts_with(pattern),
                "pattern {pattern:?}"
            );
        }
        for candidate in [
            tag.as_str(),
            "[Manual] Toky",
            "[Manual] Tokyo2",
            "",
            "srv-abc",
            "direct",
        ] {
            assert_eq!(
                profile.tag_eq(candidate),
                tag == candidate,
                "candidate {candidate:?}"
            );
        }
        // The empty pattern matches every tag, as the core's prefix match
        // does; the bracket selector reaches every server.
        assert!(profile.tag_starts_with(ALL_SERVERS_SELECTOR));
    }

    #[test]
    fn stored_retired_proxy_settings_key_survives_an_unrelated_save_and_the_gate() {
        use crate::model::validation::{Severity, ValidationCode, validate_profiles};
        use crate::sys::appdata::with_appdata;

        with_appdata(|| {
            // A stored profile from a build that still used the retired key:
            // Xray refuses to build it now, and the model must not fail the
            // load over it.
            let stored = serde_json::json!({
                "version": 1,
                "active": "aaaaaaaa11111111",
                "profiles": [{
                    "id": "aaaaaaaa11111111",
                    "name": "hop",
                    "outbound": {"protocol": "freedom", "proxySettings": {"tag": "srv-exit"}}
                }]
            });
            save_state("servers.json", &stored).expect("write the stored file");

            let mut servers = ServersFile::load().expect("a retired key must not fail the load");
            assert_eq!(
                servers.profiles[0].outbound.retired_proxy_settings,
                Some(serde_json::json!({"tag": "srv-exit"}))
            );
            assert_eq!(
                servers.profiles[0].chain_target(),
                None,
                "the retired key is never converted into a chain"
            );
            let gated = |servers: &ServersFile| {
                validate_profiles(&servers.profiles, servers.active.as_deref(), false)
                    .iter()
                    .any(|issue| {
                        issue.code == ValidationCode::OutboundProxySettingsRemoved
                            && issue.severity == Severity::Error
                    })
            };
            assert!(gated(&servers), "the profile must gate until resolved");

            // An unrelated edit (the display name) saves the file and the
            // gate survives the reload: the key stays on disk until the user
            // resolves the profile.
            servers.profiles[0].name = "hop-renamed".into();
            servers.save().expect("save servers.json");
            let saved: Value = load_state("servers.json").expect("reload the saved file");
            assert_eq!(
                saved["profiles"][0]["outbound"]["proxySettings"],
                serde_json::json!({"tag": "srv-exit"}),
                "an unrelated save must keep the retired key: {saved}"
            );
            let reloaded = ServersFile::load().expect("reload the saved file");
            assert_eq!(reloaded.profiles[0].name, "hop-renamed");
            assert!(gated(&reloaded), "the gate must survive the reload");

            // A duplicated profile inherits the raw key (the list's Duplicate
            // action clones the stored profile): the copy stays gated and its
            // saved file carries the key until the user resolves it.
            let mut duplicated = reloaded.clone();
            let mut copy = duplicated.profiles[0].clone();
            copy.id = "cccccccc33333333".into();
            copy.name = "hop copy".into();
            duplicated.profiles.push(copy);
            assert!(gated(&duplicated), "the copy must stay gated");
            duplicated.save().expect("save the duplicated profile set");
            let saved: Value = load_state("servers.json").expect("reload the saved file");
            assert_eq!(
                saved["profiles"][1]["outbound"]["proxySettings"],
                serde_json::json!({"tag": "srv-exit"}),
                "the copy's file must keep the retired key: {saved}"
            );

            // The user resolves the chain — the editor clears the key — and
            // the next save drops it.
            let mut resolved = reloaded;
            resolved.profiles[0].outbound.chain_via("srv-exit");
            resolved.profiles[0].outbound.retired_proxy_settings = None;
            resolved.save().expect("save servers.json");
            let saved: Value = load_state("servers.json").expect("reload the saved file");
            assert_eq!(
                saved["profiles"][0]["outbound"]["streamSettings"]["sockopt"]["dialerProxy"],
                serde_json::json!("srv-exit")
            );
            let key_present =
                saved["profiles"][0]["outbound"]
                    .as_object()
                    .is_some_and(|outbound| {
                        outbound
                            .keys()
                            .any(|key| key.eq_ignore_ascii_case("proxySettings"))
                    });
            assert!(
                !key_present,
                "the resolved profile must drop the key: {saved}"
            );
            let reloaded = ServersFile::load().expect("reload the saved file");
            assert_eq!(reloaded.profiles[0].chain_target(), Some("srv-exit"));
            assert!(
                reloaded.profiles[0]
                    .outbound
                    .retired_proxy_settings
                    .is_none()
            );
        });
    }

    #[test]
    fn stored_xdns_old_shape_loads_warns_once_and_saves_the_current_shape() {
        use crate::model::stream::FinalmaskUdpMask;
        use crate::model::validation::{Severity, ValidationCode, validate_profiles};
        use crate::sys::appdata::with_appdata;

        with_appdata(|| {
            // A stored profile from a build that wrote the old object fields,
            // the bare-string arrays, and the removed `domain` key: the
            // rewritten core refuses each at unmarshal, and the model must not
            // fail the load over them.
            let stored = serde_json::json!({
                "version": 1,
                "active": "aaaaaaaa11111111",
                "profiles": [{
                    "id": "aaaaaaaa11111111",
                    "name": "xdns",
                    "outbound": {
                        "protocol": "freedom",
                        "streamSettings": {"finalmask": {"udp": [{"type": "xdns", "settings": {
                            "domain": "old.example.com",
                            "domains": ["dns.example", {"name": "kept.example", "types": [1]}],
                            "resolvers": [
                                "dns.example+udp://1.1.1.1:53",
                                {"type": "udp", "settings": {"addr": "1.1.1.1:53"}}
                            ]
                        }}]}}
                    }
                }]
            });
            save_state("servers.json", &stored).expect("write the stored file");

            let mut servers =
                ServersFile::load().expect("retired xdns spellings must not fail the load");
            let mask = &servers.profiles[0]
                .outbound
                .stream
                .finalmask
                .as_ref()
                .unwrap()
                .udp[0];
            let FinalmaskUdpMask::Xdns { settings, .. } = mask else {
                panic!("the stored profile holds an xdns mask");
            };
            assert!(settings.retired_shape, "the load migrated the entry");
            assert_eq!(settings.domains.len(), 3);
            assert_eq!(settings.resolvers.len(), 2);

            let retired_warnings = |servers: &ServersFile| {
                validate_profiles(&servers.profiles, servers.active.as_deref(), false)
                    .into_issues()
                    .into_iter()
                    .filter(|issue| issue.code == ValidationCode::FinalmaskXdnsShapeRetired)
                    .collect::<Vec<_>>()
            };
            let warnings = retired_warnings(&servers);
            assert_eq!(warnings.len(), 1, "one warning for the whole mask");
            assert_eq!(warnings[0].severity, Severity::Warning);

            // An unrelated edit saves the file, and the migration reaches
            // disk: nothing but the current shape is written back.
            servers.profiles[0].name = "xdns-renamed".into();
            servers.save().expect("save servers.json");
            let saved: Value = load_state("servers.json").expect("reload the saved file");
            let settings = &saved["profiles"][0]["outbound"]["streamSettings"]["finalmask"]["udp"]
                [0]["settings"];
            assert_eq!(
                *settings,
                serde_json::json!({
                    "domains": [
                        {"names": ["dns.example"], "types": [1, 28]},
                        {"names": ["kept.example"], "types": [1]},
                        {"names": ["old.example.com"], "types": [1, 28]}
                    ],
                    "resolvers": [
                        {"addrs": ["udp://1.1.1.1:53"]},
                        {"addrs": ["udp://1.1.1.1:53"]}
                    ]
                })
            );
            let reloaded = ServersFile::load().expect("reload the saved file");
            assert_eq!(reloaded.profiles[0].name, "xdns-renamed");
            assert!(retired_warnings(&reloaded).is_empty());
        });
    }

    #[test]
    fn server_address_wireguard_takes_first_peer_endpoint() {
        let mut profile = ServerProfile::new("wg", OutboundModel::new(Protocol::Wireguard));
        {
            let ProtocolSettings::Wireguard(settings) = &mut profile.outbound.settings else {
                unreachable!();
            };
            settings.peers.push(crate::model::outbound::WireguardPeer {
                endpoint: "10.9.0.1:51820".into(),
                ..Default::default()
            });
        }
        assert_eq!(profile.server_address().as_deref(), Some("10.9.0.1:51820"));
        {
            let ProtocolSettings::Wireguard(settings) = &mut profile.outbound.settings else {
                unreachable!();
            };
            settings.peers[0].endpoint.clear();
        }
        assert_eq!(profile.server_address(), None);
    }

    #[test]
    fn legacy_file_migrates_tags_groups_and_enabled_flags() {
        use crate::sys::appdata::with_appdata;

        with_appdata(|| {
            let stored = serde_json::json!({
                "version": 1,
                "active": "aaaaaaaa11111111",
                "profiles": [
                    {
                        "id": "aaaaaaaa11111111",
                        "name": "Tokyo",
                        "outbound": {
                            "protocol": "freedom",
                            "streamSettings": {"sockopt": {"dialerProxy": "srv-bbbbbbbb"}}
                        }
                    },
                    {
                        "id": "bbbbbbbb22222222",
                        "outbound": {"protocol": "freedom"}
                    }
                ]
            });
            save_state("servers.json", &stored).expect("write the legacy file");

            let (servers, renames) =
                ServersFile::load_with_tag_renames().expect("load the legacy file");
            assert_eq!(servers.groups.len(), 1);
            assert_eq!(servers.groups[0].id, MANUAL_GROUP_ID);
            assert_eq!(servers.groups[0].title, MANUAL_GROUP_TITLE);
            assert!(
                servers.profiles.iter().all(|profile| profile.enabled),
                "every migrated profile must stay emitted"
            );
            assert_eq!(servers.profiles[0].tag(), "[Manual] Tokyo");
            assert_eq!(
                servers.profiles[1].name, "bbbbbbbb",
                "an unnamed profile falls back to its old id prefix"
            );
            assert_eq!(
                servers.profiles[0].chain_target(),
                Some("[Manual] bbbbbbbb"),
                "the chain hop follows the renamed tag"
            );
            assert_eq!(
                renames.get("srv-aaaaaaaa"),
                Some(&"[Manual] Tokyo".to_owned())
            );
            assert_eq!(
                renames.get(LEGACY_TAG_PREFIX),
                Some(&ALL_SERVERS_SELECTOR.to_owned())
            );

            servers.save().expect("save the migrated file");
            let (reloaded, renames) =
                ServersFile::load_with_tag_renames().expect("reload the migrated file");
            assert!(renames.is_empty(), "migration must be idempotent");
            assert_eq!(reloaded.profiles[0].name, "Tokyo");
            assert!(reloaded.profiles[0].enabled);
        });
    }

    #[test]
    fn renaming_a_profile_rewrites_chains_rules_and_selectors() {
        use crate::model::routing::Rule;

        let tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        let mut osaka = ServerProfile::new("Osaka", OutboundModel::new(Protocol::Freedom));
        osaka.outbound.chain_via(tokyo.tag());
        let mut servers = ServersFile::with_profiles(Some(tokyo.id.clone()), vec![tokyo, osaka]);
        let mut settings = Settings::default();
        settings.routing.rules.push(Rule {
            outbound_tag: servers.profiles[0].tag(),
            ..Default::default()
        });
        settings.routing.balancers.push(crate::model::Balancer {
            tag: "bal".into(),
            selector: vec![servers.profiles[0].tag()],
            ..Default::default()
        });

        let id = servers.profiles[0].id.clone();
        rename_profile(&mut servers, &mut settings, &id, "Tokyo 2");

        assert_eq!(servers.profiles[0].tag(), "[Manual] Tokyo 2");
        assert_eq!(servers.profiles[1].chain_target(), Some("[Manual] Tokyo 2"));
        assert_eq!(settings.routing.rules[0].outbound_tag, "[Manual] Tokyo 2");
        assert_eq!(
            settings.routing.balancers[0].selector,
            vec!["[Manual] Tokyo 2".to_owned()]
        );
    }

    #[test]
    fn names_are_unique_inside_their_group() {
        let mut servers = ServersFile::with_profiles(
            None,
            vec![
                ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom)),
                ServerProfile::new("Osaka", OutboundModel::new(Protocol::Freedom)),
            ],
        );
        let id = servers.profiles[1].id.clone();
        servers.rename_profile(&id, "Tokyo");
        assert_eq!(servers.profiles[1].name, "Tokyo (1)");
        servers.rename_profile(&id, "Tokyo");
        assert_eq!(
            servers.profiles[1].name, "Tokyo (1)",
            "an unchanged unique name keeps its suffix"
        );
    }

    #[test]
    fn emitted_set_is_the_active_enabled_and_chain_hops() {
        let freedom = || OutboundModel::new(Protocol::Freedom);
        let a = ServerProfile::new("A", freedom());
        let b = ServerProfile::new("B", freedom());
        let mut c = ServerProfile::new("C", freedom());
        c.enabled = true;
        let mut d = ServerProfile::new("D", freedom());
        d.enabled = true;
        let mut e = ServerProfile::new("E", freedom());
        let feed = Group::new("Feed");
        let feed_id = feed.id.clone();
        d.group = feed_id.clone();
        e.group = feed_id;
        let mut servers = ServersFile {
            active: Some(a.id.clone()),
            profiles: vec![a, b, c, d, e],
            ..ServersFile::default()
        };
        servers.groups.push(feed);
        servers.hydrate_group_titles();
        let e_tag = servers.profiles[4].tag();
        let b_tag = servers.profiles[1].tag();
        servers.profiles[0].outbound.chain_via(e_tag);
        servers.profiles[3].outbound.chain_via(b_tag);

        let emitted = servers.emitted_set();
        let names: Vec<&str> = emitted
            .order
            .iter()
            .map(|&index| servers.profiles[index].name.as_str())
            .collect();
        assert_eq!(
            names,
            ["A", "B", "C", "D", "E"],
            "the active server leads, then grouped order, chain hops included"
        );
        let chain_only: Vec<&str> = emitted
            .chain_only
            .iter()
            .map(|&index| servers.profiles[index].name.as_str())
            .collect();
        assert_eq!(
            chain_only,
            ["B", "E"],
            "a hop reached only through a chain is chain-only"
        );
    }

    #[test]
    fn switched_off_servers_stay_off_the_wire() {
        let freedom = || OutboundModel::new(Protocol::Freedom);
        let a = ServerProfile::new("A", freedom());
        let b = ServerProfile::new("B", freedom());
        let mut c = ServerProfile::new("C", freedom());
        c.enabled = true;
        let servers = ServersFile::with_profiles(Some(a.id.clone()), vec![a, b, c]);
        let config = crate::r#gen::generate_with_api_port(
            &servers,
            &crate::model::Settings::default(),
            10853,
        )
        .expect("generate config");
        let tags: Vec<&str> = config["outbounds"]
            .as_array()
            .expect("outbounds")
            .iter()
            .filter_map(|outbound| outbound["tag"].as_str())
            .collect();
        assert_eq!(
            &tags[..2],
            ["[Manual] A", "[Manual] C"],
            "the active server leads, then the enabled one; the switched-off B is absent"
        );
        assert!(!tags.contains(&"[Manual] B"));
    }

    #[test]
    fn provider_metadata_parses_units_and_clamps_the_interval() {
        let metadata = SubscriptionMetadata::from_provider(
            "upload=10; download=20; total=100; expire=1700000000000",
            "30d",
            "base64:RmVlZA==",
            "https://example.com",
            "https://support.example.com",
            "notice",
        )
        .expect("metadata");
        assert_eq!(
            (metadata.upload, metadata.download, metadata.total),
            (10, 20, 100)
        );
        assert_eq!(metadata.expire, 1_700_000_000);
        assert_eq!(metadata.update_interval, 720);
        assert_eq!(metadata.title, "Feed");
        assert!(SubscriptionMetadata::from_provider("", "0h", "", "", "", "").is_none());
        assert_eq!(parse_update_interval("99999d"), 8784);
        assert_eq!(parse_update_interval("junk"), 0);
        assert_eq!(parse_update_interval("90s"), 1);
    }

    #[test]
    fn report_rows_stay_bounded_while_counts_stay_exact() {
        let mut report = RefreshReport::default();
        for index in 0..(REPORT_ROW_LIMIT + 5) {
            report.added += 1;
            push_report_row(
                &mut report.rows,
                ReportRow {
                    kind: ReportKind::Added,
                    name: format!("server-{index}"),
                    raw: String::new(),
                },
            );
        }
        assert_eq!(report.rows.len(), REPORT_ROW_LIMIT);
        assert_eq!(report.added, REPORT_ROW_LIMIT + 5);
    }

    #[test]
    fn subscription_refresh_replaces_one_group_and_carries_switches() {
        use crate::model::Balancer;
        use crate::model::routing::Rule;

        let feed = Group::new("Feed");
        let feed_id = feed.id.clone();
        let mut group = ServersFile::default();
        let mut kept = ServerProfile::new("Old name", OutboundModel::new(Protocol::Freedom));
        kept.group = feed_id.clone();
        kept.enabled = true;
        kept.origin = Some(ProfileOrigin {
            content_key: "content-1".into(),
            identity_key: "identity-1".into(),
            ..Default::default()
        });
        let mut stale = ServerProfile::new("Stale", OutboundModel::new(Protocol::Freedom));
        stale.group = feed_id.clone();
        stale.origin = Some(ProfileOrigin {
            content_key: "content-2".into(),
            identity_key: "identity-2".into(),
            ..Default::default()
        });
        let manual = ServerProfile::new("Manual", OutboundModel::new(Protocol::Freedom));
        group.active = Some(kept.id.clone());
        group.profiles = vec![kept.clone(), stale, manual];
        group.groups.push(feed);
        group.hydrate_group_titles();
        let kept_tag = group.profiles[0].tag();
        let mut settings = Settings::default();
        settings.routing.rules.push(Rule {
            outbound_tag: kept_tag.clone(),
            ..Default::default()
        });
        settings.routing.balancers.push(Balancer {
            tag: "bal".into(),
            selector: vec![kept_tag],
            ..Default::default()
        });

        let renamed = ServerProfile::new("New name", OutboundModel::new(Protocol::Freedom));
        let fresh = ServerProfile::new("Fresh", OutboundModel::new(Protocol::Freedom));
        let report = group.refresh_subscription_group(
            &mut settings,
            &feed_id,
            vec![
                SubscriptionEntry {
                    profile: renamed,
                    content_key: "content-1".into(),
                    identity_key: "identity-1".into(),
                },
                SubscriptionEntry {
                    profile: fresh,
                    content_key: "content-3".into(),
                    identity_key: "identity-3".into(),
                },
            ],
        );

        assert_eq!((report.updated, report.added, report.removed), (1, 1, 1));
        let names: Vec<&str> = group
            .profiles
            .iter()
            .filter(|profile| profile.group_id() == feed_id)
            .map(|profile| profile.name.as_str())
            .collect();
        assert_eq!(names, ["New name", "Fresh"]);
        assert!(
            group
                .profiles
                .iter()
                .find(|profile| profile.name == "New name")
                .is_some_and(|profile| profile.enabled),
            "the user's switch follows the matched entry"
        );
        assert_eq!(
            group.active.as_deref(),
            Some(kept.id.as_str()),
            "the matched entry keeps its id and the route"
        );
        assert_eq!(
            settings.routing.rules[0].outbound_tag, "[Feed] New name",
            "the provider's name wins and references follow"
        );
        assert_eq!(
            settings.routing.balancers[0].selector,
            vec!["[Feed] New name".to_owned()]
        );
        assert!(
            group
                .profiles
                .iter()
                .any(|profile| profile.name == "Manual" && profile.group_id() == MANUAL_GROUP_ID),
            "another group is untouched"
        );
    }

    #[test]
    fn subscription_user_agent_mode_chooses_the_source() {
        let mut subscription = Subscription::default();
        assert_eq!(subscription.effective_user_agent("global/1"), "global/1");
        subscription.user_agent_custom = true;
        subscription.user_agent = "custom/2".into();
        assert_eq!(subscription.effective_user_agent("global/1"), "custom/2");
        subscription.user_agent.clear();
        assert_eq!(
            subscription.effective_user_agent("global/1"),
            "",
            "a custom empty value omits the header"
        );
        subscription.user_agent_custom = false;
        assert_eq!(subscription.effective_user_agent(""), "");
    }

    #[test]
    fn refresh_deduplicates_names_across_the_same_fetch() {
        let feed = Group::new("Feed");
        let feed_id = feed.id.clone();
        let mut servers = ServersFile::default();
        servers.groups.push(feed);
        let mut settings = Settings::default();
        let entry = |name: &str, key: &str| SubscriptionEntry {
            profile: ServerProfile::new(name, OutboundModel::new(Protocol::Freedom)),
            content_key: key.into(),
            identity_key: key.into(),
        };
        let report = servers.refresh_subscription_group(
            &mut settings,
            &feed_id,
            vec![entry("Same", "a"), entry("Same", "b")],
        );
        assert_eq!(report.added, 2);
        let names: Vec<&str> = servers
            .profiles
            .iter()
            .filter(|profile| profile.group_id() == feed_id)
            .map(|profile| profile.name.as_str())
            .collect();
        assert_eq!(names, ["Same", "Same (1)"]);
    }

    #[test]
    fn removing_the_active_subscription_server_lands_on_block() {
        let feed = Group::new("Feed");
        let feed_id = feed.id.clone();
        let mut profile = ServerProfile::new("Only", OutboundModel::new(Protocol::Freedom));
        profile.group = feed_id.clone();
        profile.origin = Some(ProfileOrigin {
            content_key: "content".into(),
            identity_key: "identity".into(),
            ..Default::default()
        });
        let mut servers = ServersFile {
            active: Some(profile.id.clone()),
            profiles: vec![profile],
            ..ServersFile::default()
        };
        servers.groups.push(feed);
        servers.hydrate_group_titles();
        let mut settings = Settings::default();

        let report = servers.refresh_subscription_group(&mut settings, &feed_id, Vec::new());
        assert_eq!(report.removed, 1);
        assert_eq!(
            servers.active.as_deref(),
            Some(crate::model::inbound::BLOCK_OUTBOUND_TAG)
        );
    }

    /// A subscription row and the file around it: `Feed` holds `Tokyo`, which
    /// is the active route, and `Backup` already holds a `Tokyo` of its own so
    /// a copy's name has to be suffixed.
    fn copy_fixture() -> (ServersFile, ServerProfile, String, String) {
        let mut feed = Group::new("Feed");
        feed.subscription = Some(Subscription::default());
        let feed_id = feed.id.clone();
        let backup = Group::new("Backup");
        let backup_id = backup.id.clone();
        let mut sub = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        sub.group = feed_id.clone();
        sub.enabled = true;
        sub.origin = Some(ProfileOrigin {
            content_key: "content".into(),
            identity_key: "identity".into(),
            ..Default::default()
        });
        let mut taken = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        taken.group = backup_id.clone();
        let mut servers = ServersFile {
            active: Some(sub.id.clone()),
            profiles: vec![sub.clone(), taken],
            groups: vec![Group::manual(), backup, feed],
            ..ServersFile::default()
        };
        servers.hydrate_group_titles();
        (servers, sub, feed_id, backup_id)
    }

    /// Every outbound tag the generated configuration carries.
    fn generated_tags(servers: &ServersFile) -> Vec<String> {
        let config = crate::r#gen::generate_with_api_port(
            servers,
            &crate::model::Settings::default(),
            10853,
        )
        .expect("generate config");
        config["outbounds"]
            .as_array()
            .expect("outbounds")
            .iter()
            .filter_map(|outbound| outbound["tag"].as_str().map(str::to_owned))
            .collect()
    }

    #[test]
    fn copy_to_group_places_a_switched_off_snapshot_in_the_chosen_group() {
        let (mut servers, sub, feed_id, backup_id) = copy_fixture();
        let source_index = servers
            .profiles
            .iter()
            .position(|profile| profile.id == sub.id)
            .expect("the source row");

        let copy_id = servers
            .copy_to_manual(&sub.id, &backup_id)
            .expect("a subscription row is copied");
        let copy = servers
            .profiles
            .iter()
            .find(|profile| profile.id == copy_id)
            .expect("the copy exists");
        assert_eq!(copy.group_id(), backup_id);
        assert_eq!(copy.group_title, "Backup");
        assert_eq!(copy.name, "Tokyo (1)", "a used name takes the next suffix");
        assert_eq!(copy.tag(), "[Backup] Tokyo (1)");
        assert!(!copy.enabled, "the copy starts switched off");
        assert!(copy.origin.is_none(), "a copy is not a subscription row");
        assert_eq!(
            servers.active.as_deref(),
            Some(sub.id.as_str()),
            "the copy never takes the route"
        );

        // The subscription row stays exactly where it was.
        assert_eq!(
            servers
                .profiles
                .iter()
                .position(|profile| profile.id == sub.id),
            Some(source_index),
            "copying appends the copy and never moves the source"
        );
        let original = &servers.profiles[source_index];
        assert_eq!(original.group_id(), feed_id);
        assert_eq!(original.name, "Tokyo");
        assert!(original.enabled);
        assert!(original.origin.is_some());
        assert!(
            servers.copy_to_manual(&copy_id, &backup_id).is_none(),
            "a manual row has no subscription snapshot to copy"
        );

        // A refresh of the subscription neither touches nor removes the
        // copy: the feed still owns the original, and only the original.
        let mut settings = Settings::default();
        let entry = SubscriptionEntry {
            profile: sub.clone(),
            content_key: "content".into(),
            identity_key: "identity".into(),
        };
        servers.refresh_subscription_group(&mut settings, &feed_id, vec![entry]);
        let copy = servers
            .profiles
            .iter()
            .find(|profile| profile.id == copy_id)
            .expect("the copy survives a refresh");
        assert_eq!(copy.tag(), "[Backup] Tokyo (1)");
        assert!(!copy.enabled);

        // The copy enters the configuration only when switched on.
        assert!(
            !generated_tags(&servers).contains(&"[Backup] Tokyo (1)".to_owned()),
            "a switched-off copy stays out of the configuration"
        );
        servers
            .profiles
            .iter_mut()
            .find(|profile| profile.id == copy_id)
            .expect("the copy exists")
            .enabled = true;
        assert!(
            generated_tags(&servers).contains(&"[Backup] Tokyo (1)".to_owned()),
            "switching the copy on emits it in its group's block"
        );
    }

    #[test]
    fn copy_to_group_defaults_to_the_manual_group() {
        let (mut servers, sub, _, _) = copy_fixture();
        let copy_id = servers
            .copy_to_manual(&sub.id, MANUAL_GROUP_ID)
            .expect("copied");
        let copy = servers
            .profiles
            .iter()
            .find(|profile| profile.id == copy_id)
            .expect("the copy exists");
        assert_eq!(copy.group_id(), MANUAL_GROUP_ID);
        assert_eq!(copy.tag(), "[Manual] Tokyo");
    }

    #[test]
    fn group_order_drives_the_emitted_order() {
        let freedom = || OutboundModel::new(Protocol::Freedom);
        let mut a = ServerProfile::new("A", freedom());
        a.enabled = true;
        let mut b = ServerProfile::new("B", freedom());
        b.enabled = true;
        let first = Group::new("First");
        let first_id = first.id.clone();
        a.group = first_id;
        let second = Group::new("Second");
        let second_id = second.id.clone();
        b.group = second_id;
        let mut servers = ServersFile::default();
        servers.profiles = vec![a, b];
        servers.groups = vec![crate::model::servers::Group::manual(), first, second];
        servers.hydrate_group_titles();
        let tags = |servers: &ServersFile| -> Vec<String> {
            let config = crate::r#gen::generate_with_api_port(
                servers,
                &crate::model::Settings::default(),
                10853,
            )
            .expect("generate config");
            config["outbounds"]
                .as_array()
                .expect("outbounds")
                .iter()
                .take(3)
                .filter_map(|outbound| outbound["tag"].as_str().map(str::to_owned))
                .collect()
        };
        assert_eq!(tags(&servers), ["direct", "[First] A", "[Second] B"]);
        servers.groups.swap(1, 2);
        assert_eq!(tags(&servers), ["direct", "[Second] B", "[First] A"]);
    }

    #[test]
    fn a_group_pin_round_trips_and_defaults_to_absent() {
        let mut group = Group::new("Feed");
        group.pinned = true;
        let stored = serde_json::to_value(&group).expect("the group serializes");
        assert_eq!(stored["pinned"], serde_json::json!(true));
        let reloaded: Group = serde_json::from_value(stored).expect("a pinned group deserializes");
        assert!(reloaded.pinned, "the pin survives a restart");

        // A file written before the flag existed has no key: the group
        // reloads unpinned, and a fresh group starts that way.
        let legacy: Group = serde_json::from_value(serde_json::json!({"id": "g", "title": "Feed"}))
            .expect("a legacy group deserializes");
        assert!(!legacy.pinned);
        assert!(!Group::new("Other").pinned);
        let stored = serde_json::to_value(Group::new("Other")).expect("the group serializes");
        assert!(
            stored.get("pinned").is_none(),
            "an unpinned flag stays out of the stored file"
        );
    }

    #[test]
    fn a_band_drag_reorders_only_its_own_band() {
        let mut servers = ServersFile::default();
        let mut groups = vec![Group::manual()];
        for (title, pinned) in [
            ("First", false),
            ("Second", true),
            ("Third", false),
            ("Fourth", true),
        ] {
            let mut group = Group::new(title);
            group.pinned = pinned;
            groups.push(group);
        }
        servers.groups = groups;
        let ids = |servers: &ServersFile| -> Vec<String> {
            servers
                .groups
                .iter()
                .map(|group| group.title.clone())
                .collect()
        };
        assert_eq!(
            ids(&servers),
            ["Manual", "First", "Second", "Third", "Fourth"]
        );

        // The pinned band is [Second, Fourth]: moving Fourth to its start
        // swaps only those two slots; the unpinned group keeps its place.
        let fourth = servers.groups[4].id.clone();
        servers.reorder_group_in_band(&fourth, 0);
        assert_eq!(
            ids(&servers),
            ["Manual", "First", "Fourth", "Third", "Second"]
        );

        // A drag in the unpinned band leaves the pinned band's slots alone.
        let third = servers.groups[3].id.clone();
        servers.reorder_group_in_band(&third, 0);
        assert_eq!(
            ids(&servers),
            ["Manual", "Third", "Fourth", "First", "Second"]
        );

        // The reserved group never moves.
        servers.reorder_group_in_band(MANUAL_GROUP_ID, 4);
        assert_eq!(
            ids(&servers),
            ["Manual", "Third", "Fourth", "First", "Second"]
        );
    }

    #[test]
    fn pinning_a_group_changes_presentation_not_the_block_order() {
        let freedom = || OutboundModel::new(Protocol::Freedom);
        let mut a = ServerProfile::new("A", freedom());
        a.enabled = true;
        let mut b = ServerProfile::new("B", freedom());
        b.enabled = true;
        let first = Group::new("First");
        let second = Group::new("Second");
        a.group = first.id.clone();
        b.group = second.id.clone();
        let mut servers = ServersFile {
            profiles: vec![a, b],
            groups: vec![Group::manual(), first, second],
            ..ServersFile::default()
        };
        servers.hydrate_group_titles();
        let tags = |servers: &ServersFile| -> Vec<String> {
            let config = crate::r#gen::generate_with_api_port(
                servers,
                &crate::model::Settings::default(),
                10853,
            )
            .expect("generate config");
            config["outbounds"]
                .as_array()
                .expect("outbounds")
                .iter()
                .take(3)
                .filter_map(|outbound| outbound["tag"].as_str().map(str::to_owned))
                .collect()
        };
        let before = tags(&servers);
        servers.groups[2].pinned = true;
        assert_eq!(tags(&servers), before, "a pin never rewrites the document");
    }

    #[test]
    fn a_row_moves_only_inside_its_own_group() {
        let freedom = || OutboundModel::new(Protocol::Freedom);
        let feed = Group::new("Feed");
        let feed_id = feed.id.clone();
        let mut alpha = ServerProfile::new("Alpha", freedom());
        alpha.enabled = true;
        let mut bravo = ServerProfile::new("Bravo", freedom());
        bravo.enabled = true;
        let mut charlie = ServerProfile::new("Charlie", freedom());
        charlie.enabled = true;
        charlie.group = feed_id.clone();
        let mut delta = ServerProfile::new("Delta", freedom());
        delta.enabled = true;
        delta.group = feed_id;
        let mut servers = ServersFile {
            profiles: vec![alpha, bravo, charlie, delta],
            groups: vec![Group::manual(), feed],
            ..ServersFile::default()
        };
        servers.hydrate_group_titles();
        let names = |servers: &ServersFile| -> Vec<String> {
            servers
                .profiles
                .iter()
                .map(|profile| profile.name.clone())
                .collect()
        };

        // Delta lands ahead of Charlie inside Feed.
        assert!(servers.move_profile_in_group(3, Some(2)));
        assert_eq!(names(&servers), ["Alpha", "Bravo", "Delta", "Charlie"]);
        // Already in place: the move reports no change.
        assert!(!servers.move_profile_in_group(2, Some(3)));
        assert_eq!(names(&servers), ["Alpha", "Bravo", "Delta", "Charlie"]);
        // A destination in another group is refused and moves nothing.
        assert!(!servers.move_profile_in_group(2, Some(1)));
        assert_eq!(names(&servers), ["Alpha", "Bravo", "Delta", "Charlie"]);
        // `None` is the row's own group's tail, not the list's.
        assert!(servers.move_profile_in_group(0, None));
        assert_eq!(names(&servers), ["Bravo", "Alpha", "Delta", "Charlie"]);
        assert!(servers.move_profile_in_group(2, None));
        assert_eq!(names(&servers), ["Bravo", "Alpha", "Charlie", "Delta"]);
    }

    #[test]
    fn direct_and_block_routes_lead_the_document() {
        let mut enabled = ServerProfile::new("A", OutboundModel::new(Protocol::Freedom));
        enabled.enabled = true;
        let mut servers = ServersFile::with_profiles(
            Some(crate::model::inbound::DIRECT_OUTBOUND_TAG.into()),
            vec![enabled],
        );
        let tags = |servers: &ServersFile| -> Vec<String> {
            let config = crate::r#gen::generate_with_api_port(
                servers,
                &crate::model::Settings::default(),
                10853,
            )
            .expect("generate config");
            config["outbounds"]
                .as_array()
                .expect("outbounds")
                .iter()
                .filter_map(|outbound| outbound["tag"].as_str().map(str::to_owned))
                .collect()
        };
        assert_eq!(
            &tags(&servers)[..3],
            ["direct", "[Manual] A", "block"],
            "a Direct route leads; enabled servers follow"
        );

        servers.activate(crate::model::inbound::BLOCK_OUTBOUND_TAG);
        assert_eq!(
            &tags(&servers)[..3],
            ["block", "[Manual] A", "direct"],
            "a Block route leads; enabled servers follow"
        );

        // A built-in route is a legal active value, not a missing profile.
        let issues = crate::model::validation::validate_settings(
            &crate::model::Settings::default(),
            &servers,
            10853,
        );
        assert!(
            !issues.iter().any(|issue| matches!(
                issue.code,
                crate::model::ValidationCode::ActiveProfileMissing(_)
            )),
            "the reserved route must not be reported as a missing profile"
        );
    }

    #[test]
    fn renaming_a_group_rewrites_every_tag_it_prefixes() {
        let group = Group::new("Feed");
        let group_id = group.id.clone();
        let mut feed = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        feed.group = group_id.clone();
        let manual = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        let mut servers = ServersFile::default();
        servers.profiles.push(feed);
        servers.profiles.push(manual);
        servers.groups.push(group);
        servers.hydrate_group_titles();
        let mut settings = Settings::default();
        settings.routing.observatory.subject_selector = vec![servers.profiles[0].tag()];

        rename_group(&mut servers, &mut settings, &group_id, "Feed 2");

        assert_eq!(servers.profiles[0].tag(), "[Feed 2] Tokyo");
        assert_eq!(
            servers.profiles[1].tag(),
            "[Manual] Tokyo",
            "the other group's tag is untouched"
        );
        assert_eq!(
            settings.routing.observatory.subject_selector,
            vec!["[Feed 2] Tokyo".to_owned()]
        );
        assert!(
            servers.rename_group(MANUAL_GROUP_ID, "Renamed").is_empty(),
            "the reserved group cannot be renamed"
        );
    }

    #[test]
    fn adopting_a_profile_into_a_group_targets_that_group() {
        let feed = Group::new("Feed");
        let feed_id = feed.id.clone();
        let mut taken = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        taken.group = feed_id.clone();
        let mut servers = ServersFile {
            groups: vec![Group::manual(), feed],
            profiles: vec![taken],
            ..ServersFile::default()
        };
        servers.hydrate_group_titles();

        let imported = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        servers.adopt_profile_in(imported, &feed_id);
        let added = servers
            .profiles
            .iter()
            .find(|profile| profile.group_id() == feed_id && profile.name == "Tokyo (1)")
            .expect("the name is made unique inside the target group");
        assert_eq!("[Feed] Tokyo (1)", added.tag());

        let elsewhere = ServerProfile::new("Osaka", OutboundModel::new(Protocol::Freedom));
        servers.adopt_profile_in(elsewhere, "missing-group");
        assert!(
            servers
                .profiles
                .iter()
                .any(|profile| profile.name == "Osaka" && profile.group_id() == MANUAL_GROUP_ID),
            "an unknown target group falls back to Manual"
        );
    }

    #[test]
    fn a_group_kind_comes_from_its_subscription_state() {
        assert_eq!(GroupKind::Manual, Group::new("Mine").kind());
        assert_eq!(GroupKind::Manual, Group::manual().kind());
        let mut feed = Group::new("Feed");
        feed.subscription = Some(Subscription::default());
        assert_eq!(GroupKind::Subscription, feed.kind());
        feed.subscription = None;
        assert_eq!(
            GroupKind::Manual,
            feed.kind(),
            "a group without feed state is a manual group"
        );
    }

    #[test]
    fn group_titles_stay_unique_with_the_existing_suffix() {
        let mut servers = ServersFile::default();
        let feed = Group::new("Feed");
        let feed_id = feed.id.clone();
        servers.groups.push(feed);
        assert_eq!(servers.unique_group_title("Feed", None), "Feed (1)");
        assert_eq!(
            servers.unique_group_title("Feed", Some(&feed_id)),
            "Feed",
            "the renamed group keeps its own title"
        );
        assert_eq!(
            servers.unique_group_title("Manual", None),
            "Manual (1)",
            "the reserved group's title is taken too"
        );
        assert_eq!(servers.unique_group_title("", None), "Group");
        assert_eq!(servers.unique_group_title("  Trimmed  ", None), "Trimmed");
    }

    #[test]
    fn deleting_a_group_removes_its_servers_and_moves_a_lost_route_to_block() {
        let feed = Group::new("Feed");
        let feed_id = feed.id.clone();
        let mut own = ServerProfile::new("Own", OutboundModel::new(Protocol::Freedom));
        own.enabled = true;
        let mut fed = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        fed.group = feed_id.clone();
        fed.enabled = true;
        let fed_id = fed.id.clone();
        let mut servers = ServersFile {
            profiles: vec![own, fed],
            groups: vec![Group::manual(), feed],
            active: Some(fed_id.clone()),
            ..ServersFile::default()
        };
        servers.hydrate_group_titles();

        assert!(servers.delete_group(&feed_id));
        assert!(
            !servers.groups.iter().any(|group| group.id == feed_id),
            "the group record is gone"
        );
        assert!(
            !servers.profiles.iter().any(|profile| profile.id == fed_id),
            "the group's servers are gone"
        );
        assert!(servers.profiles.iter().any(|profile| profile.name == "Own"));
        assert_eq!(
            servers.active.as_deref(),
            Some(crate::model::inbound::BLOCK_OUTBOUND_TAG),
            "deleting the active server moves the route to Block"
        );

        assert!(
            !servers.delete_group(MANUAL_GROUP_ID),
            "the reserved group cannot be deleted"
        );
        assert!(servers.groups.iter().any(Group::is_manual));
        assert!(
            !servers.delete_group("missing"),
            "an unknown group changes nothing"
        );
    }

    #[test]
    fn deleting_a_group_leaves_a_route_to_another_group_alone() {
        let feed = Group::new("Feed");
        let feed_id = feed.id.clone();
        let mut own = ServerProfile::new("Own", OutboundModel::new(Protocol::Freedom));
        own.enabled = true;
        let own_id = own.id.clone();
        let mut fed = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        fed.group = feed_id.clone();
        let servers = ServersFile {
            profiles: vec![own, fed],
            groups: vec![Group::manual(), feed],
            active: Some(own_id.clone()),
            ..ServersFile::default()
        };
        let mut servers = servers;
        servers.hydrate_group_titles();
        assert!(servers.delete_group(&feed_id));
        assert_eq!(servers.active.as_deref(), Some(own_id.as_str()));
    }
}
