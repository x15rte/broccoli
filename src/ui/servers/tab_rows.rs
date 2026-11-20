//! The rows of one tab, and what each row is: the display order the table
//! paints, the display facts every row command reads, and the mapping a drag
//! uses to reach the stored profile order.
//!
//! The rows are a view of the model: search filters them, the view sort
//! reorders them, and the tab chooses them. They are rebuilt only when the
//! model generation, the tab, the search or the sort moves; the drag's seed
//! lists and the per-row facts are derived with them, so a drag frame and a
//! painted row read a computed fact instead of re-deriving it.
//!
//! The facts are display facts only (ADR-0078): whether the row is the active
//! route, is emitted only for the chain, is locked or can move. A command
//! that changes the model still changes the model, and the next generation
//! rebuilds these rows from it.

use std::collections::HashMap;
use std::rc::Rc;

use crate::model::servers::{EmittedSet, MANUAL_GROUP_ID};
use crate::model::settings::{SortColumn, ViewSort};
use crate::model::{ProbeVerdict, ServerProfile, ServersFile};

use super::ServerTab;

/// What one displayed row is, in display terms. A row is the profile it
/// renders plus the facts the paint and the row commands read; `checked`
/// is not one of them, because the switch state belongs to the selection
/// and the profile, not to the display.
#[derive(Clone, Copy)]
pub(super) struct RowFacts<'a> {
    /// The profile this display position renders.
    pub(super) profile: usize,
    /// The row's 1-based number in the order column, when the tab shows one.
    pub(super) order: Option<usize>,
    /// Whether the tab paints the group column on its rows.
    pub(super) group: bool,
    /// The row renders the active route, which the generated order pins
    /// first.
    pub(super) active: bool,
    /// The row is emitted only because another outbound dials through it.
    pub(super) hop: bool,
    /// The row's switch is locked: the active route and a chain-only hop are
    /// in the generated document whatever their own switch says.
    pub(super) locked: bool,
    /// Whether the row can move inside its own group block: only the
    /// `Emitted` tab reorders rows, and only a row with a movable sibling of
    /// its group has somewhere to go.
    pub(super) movable: bool,
    /// The labels of the emitted servers that dial through this row, in
    /// emitted order. Empty for a row nothing dials through.
    pub(super) dialers: &'a [String],
}

/// One tab's rows: the display order as profile indices, and the facts every
/// painted row and row command reads.
pub(super) struct TabRows {
    /// The model generation the rows were derived from. The model's order,
    /// names, chains and verdicts are all facts of this generation.
    generation: u64,
    tab: ServerTab,
    search: String,
    sort: Option<ViewSort>,
    /// Profile indices in display order.
    rows: Rc<[usize]>,
    /// Whether display index `i` can move inside its group block.
    movable: Rc<[bool]>,
    /// The display rows a drag may lift or land on: the rows without the
    /// chain hops, which are a consequence of the chain and not a place in
    /// their group.
    seeds: Rc<[usize]>,
    /// `seeds_before[i]`: how many seed rows precede display index `i`.
    /// `seeds_before[rows.len()]` is the seed row count.
    seeds_before: Rc<[usize]>,
    /// The group each seed row belongs to, as a symbol assigned at rebuild:
    /// a drop compares group membership, never group names.
    seed_group: Rc<[u32]>,
    /// Whether display index `i` is emitted only for the chain.
    hop: Rc<[bool]>,
    /// `dialers[i]`: the labels the latency hover names for display index
    /// `i`, empty when the row is not a hop.
    dialers: Rc<[Vec<String>]>,
    /// The profile index the generated order pins first.
    active: Option<usize>,
    /// Whether the tab numbers its rows in outbound order.
    show_order: bool,
    /// Whether the tab paints the group column.
    show_group: bool,
}

impl TabRows {
    /// Build one tab's rows from the model, the emitted set and the view
    /// inputs. The caller decides when this runs; [`Self::is_current`] says
    /// whether the rows it holds still match the current inputs.
    pub(super) fn rebuild(
        generation: u64,
        tab: ServerTab,
        search: &str,
        sort: Option<ViewSort>,
        servers: &ServersFile,
        emitted: &EmittedSet,
    ) -> Self {
        let mut rows = match &tab {
            ServerTab::Emitted => emitted.order.clone(),
            ServerTab::All => servers.grouped_order(),
            ServerTab::Manual => group_members(servers, MANUAL_GROUP_ID),
            ServerTab::Group(id) => group_members(servers, id),
        };
        let needle = search.trim().to_lowercase();
        if !needle.is_empty() {
            rows.retain(|&index| {
                let profile = &servers.profiles[index];
                profile.name.to_lowercase().contains(&needle)
                    || profile
                        .server_address()
                        .is_some_and(|address| address.to_lowercase().contains(&needle))
            });
        }
        // The emitted order is the outbound order; every other tab draws a
        // view, which the sort may reorder.
        if tab != ServerTab::Emitted
            && let Some(sort) = sort
        {
            sort_rows(&mut rows, &servers.profiles, sort);
        }

        let active = servers
            .active
            .as_deref()
            .and_then(|id| servers.profiles.iter().position(|profile| profile.id == id));
        // One pass derives the seed list, the seed index, the per-row chain
        // facts and the group each seed belongs to. A group is assigned a
        // symbol on first sight, so a drop never compares group names.
        let mut seeds = Vec::with_capacity(rows.len());
        let mut seeds_before = Vec::with_capacity(rows.len() + 1);
        let mut seed_group = Vec::with_capacity(rows.len());
        let mut group_ids: Vec<String> = Vec::new();
        let mut group_symbols: HashMap<&str, u32> = HashMap::new();
        let mut hop = Vec::with_capacity(rows.len());
        let mut dialers = Vec::with_capacity(rows.len());
        for &index in &rows {
            seeds_before.push(seeds.len());
            let is_hop = emitted.chain_only.contains(&index);
            hop.push(is_hop);
            dialers.push(if is_hop {
                emitted.dialers.get(&index).cloned().unwrap_or_default()
            } else {
                Vec::new()
            });
            if is_hop {
                continue;
            }
            seeds.push(index);
            let group = servers.profiles[index].group_id();
            let symbol = match group_symbols.get(group) {
                Some(&symbol) => symbol,
                None => {
                    let symbol = group_ids.len() as u32;
                    group_ids.push(group.to_owned());
                    group_symbols.insert(group, symbol);
                    symbol
                }
            };
            seed_group.push(symbol);
        }
        seeds_before.push(seeds.len());

        // A row can move only inside its own block, and only when that block
        // holds another movable sibling. The active route is its own block
        // (the generated order pins it first) and a chain hop is not a place
        // in its group, so neither counts as a sibling.
        let mut group_counts = vec![0usize; group_ids.len()];
        for (position, &index) in seeds.iter().enumerate() {
            if Some(index) == active {
                continue;
            }
            group_counts[seed_group[position] as usize] += 1;
        }
        let mut movable = vec![false; rows.len()];
        if tab == ServerTab::Emitted {
            for (display, &index) in rows.iter().enumerate() {
                if hop[display] || Some(index) == active {
                    continue;
                }
                let symbol = seed_group[seeds_before[display]] as usize;
                movable[display] = group_counts[symbol] > 1;
            }
        }

        let show_order = tab == ServerTab::Emitted;
        let show_group = matches!(tab, ServerTab::All | ServerTab::Emitted);
        Self {
            generation,
            tab,
            search: search.to_owned(),
            sort,
            rows: Rc::from(rows.into_boxed_slice()),
            movable: Rc::from(movable.into_boxed_slice()),
            seeds: Rc::from(seeds.into_boxed_slice()),
            seeds_before: Rc::from(seeds_before.into_boxed_slice()),
            seed_group: Rc::from(seed_group.into_boxed_slice()),
            hop: Rc::from(hop.into_boxed_slice()),
            dialers: Rc::from(dialers.into_boxed_slice()),
            active,
            show_order,
            show_group,
        }
    }

    /// Whether these rows were derived from the current view inputs.
    pub(super) fn is_current(
        &self,
        generation: u64,
        tab: &ServerTab,
        search: &str,
        sort: Option<ViewSort>,
    ) -> bool {
        self.generation == generation
            && &self.tab == tab
            && self.search == search
            && self.sort == sort
    }

    /// The profile indices the tab paints, in display order.
    pub(super) fn rows(&self) -> &[usize] {
        &self.rows
    }

    /// What display position `display` is: the profile it renders and the
    /// display facts its paint and its commands read.
    pub(super) fn facts(&self, display: usize) -> RowFacts<'_> {
        let profile = self.rows[display];
        let active = self.active == Some(profile);
        let hop = self.hop[display];
        RowFacts {
            profile,
            order: self.show_order.then_some(display + 1),
            group: self.show_group,
            active,
            hop,
            locked: active || hop,
            movable: self.movable[display],
            dialers: self.dialers[display].as_slice(),
        }
    }

    /// The stored move a drop on display row `from_display` at `gap` asks
    /// for: the dragged profile and the sibling it lands ahead of, `None`
    /// ahead meaning its block's tail.
    ///
    /// `gap` indexes the display list: above a row's midline inserts before
    /// it, below inserts after it. A hop row never lifts, the active route is
    /// a block of its own, and a gap whose neighbours both belong to another
    /// group names no move, so a cross-block drop neither paints an insertion
    /// line nor changes the stored order. The gaps beside the dragged row's
    /// own slot are no-ops.
    pub(super) fn drop_target(
        &self,
        from_display: usize,
        gap: usize,
    ) -> Option<(usize, Option<usize>)> {
        let &from_profile = self.rows.get(from_display)?;
        if self.hop.get(from_display).copied().unwrap_or(false) || self.active == Some(from_profile)
        {
            return None;
        }
        let from = *self.seeds_before.get(from_display)?;
        let gap = *self.seeds_before.get(gap)?;
        if gap == from || gap == from + 1 {
            return None;
        }
        let group = *self.seed_group.get(from)?;
        // The lifted row is not a place to land, and neither is the active
        // route the generated order pins outside every block.
        let in_block = |position: usize| {
            self.seeds.get(position).is_some_and(|&index| {
                index != from_profile
                    && Some(index) != self.active
                    && self.seed_group[position] == group
            })
        };
        let previous = gap.checked_sub(1);
        let next = (gap < self.seeds.len()).then_some(gap);
        if !previous.is_some_and(in_block) && !next.is_some_and(in_block) {
            return None;
        }
        let before = next
            .filter(|&position| in_block(position))
            .map(|position| self.seeds[position]);
        Some((from_profile, before))
    }
}

/// The profile indices of one group, in stored order.
fn group_members(servers: &ServersFile, group_id: &str) -> Vec<usize> {
    servers
        .profiles
        .iter()
        .enumerate()
        .filter(|(_, profile)| profile.group_id() == group_id)
        .map(|(index, _)| index)
        .collect()
}

/// Sort a tab's row indices by one column, ascending or descending. The
/// stored order is untouched; only the view's row list moves.
fn sort_rows(rows: &mut [usize], profiles: &[ServerProfile], sort: ViewSort) {
    match sort.column {
        SortColumn::Name => rows.sort_by_cached_key(|&index| profiles[index].name.to_lowercase()),
        SortColumn::Protocol => {
            rows.sort_by_cached_key(|&index| profiles[index].outbound.protocol.as_str().to_owned());
        }
        SortColumn::Latency => {
            rows.sort_by_cached_key(|&index| {
                match profiles[index]
                    .verdict
                    .as_ref()
                    .and_then(ProbeVerdict::delay_ms)
                {
                    Some(value) => (0u8, value),
                    None => (1u8, i64::MAX),
                }
            });
        }
    }
    if !sort.ascending {
        rows.reverse();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::servers::Group;
    use crate::model::settings::{SortColumn, ViewSort};
    use crate::model::{OutboundModel, Protocol, ProtocolSettings};
    use crate::ui::servers::selection::{Selection, VisibleRows};

    /// A profile named `name`, in `group`, switched on, with the address the
    /// search reads.
    fn profile(name: &str, group: &str, address: &str) -> ServerProfile {
        let mut profile = ServerProfile::new(name, OutboundModel::new(Protocol::Vless));
        profile.group = group.to_owned();
        profile.enabled = true;
        let ProtocolSettings::Vless(settings) = &mut profile.outbound.settings else {
            unreachable!("Vless is the fresh protocol");
        };
        settings.address = address.to_owned();
        settings.port = 443;
        profile
    }

    /// Manual [ManualOne, ManualTwo] then Feed [FeedOne, FeedTwo], stored as
    /// FeedOne, ManualOne, FeedTwo, ManualTwo so the grouped order is a
    /// reordering of the stored list. FeedOne is the route, so the emitted
    /// order leads with it.
    fn servers() -> ServersFile {
        let feed = Group::new("Feed");
        let feed_id = feed.id.clone();
        let mut servers = ServersFile {
            profiles: vec![
                profile("FeedOne", &feed_id, "10.0.0.1"),
                profile("ManualOne", MANUAL_GROUP_ID, "10.0.0.2"),
                profile("FeedTwo", &feed_id, "10.0.0.3"),
                profile("ManualTwo", MANUAL_GROUP_ID, "10.0.0.4"),
            ],
            groups: vec![Group::manual(), feed],
            ..ServersFile::default()
        };
        servers.active = Some(servers.profiles[0].id.clone());
        servers
    }

    fn index_of(servers: &ServersFile, name: &str) -> usize {
        servers
            .profiles
            .iter()
            .position(|profile| profile.name == name)
            .unwrap_or_else(|| panic!("the fixture lists {name:?}"))
    }

    fn ids_at<'a>(servers: &'a ServersFile, rows: &TabRows) -> Vec<&'a str> {
        rows.rows()
            .iter()
            .map(|&index| servers.profiles[index].name.as_str())
            .collect()
    }

    #[test]
    fn each_tab_lists_its_own_rows_in_its_own_order() {
        let servers = servers();
        let emitted = servers.emitted_set();
        // Obtained by hand from the model's contract: see `emitted_set()`.
        assert_eq!(
            emitted.order,
            vec![
                index_of(&servers, "FeedOne"),
                index_of(&servers, "ManualOne"),
                index_of(&servers, "ManualTwo"),
                index_of(&servers, "FeedTwo"),
            ]
        );

        let all = TabRows::rebuild(1, ServerTab::All, "", None, &servers, &emitted);
        assert_eq!(
            ids_at(&servers, &all),
            ["ManualOne", "ManualTwo", "FeedOne", "FeedTwo"],
            "All groups rows by the group order, not the stored list"
        );

        let manual = TabRows::rebuild(1, ServerTab::Manual, "", None, &servers, &emitted);
        assert_eq!(ids_at(&servers, &manual), ["ManualOne", "ManualTwo"]);

        let feed = TabRows::rebuild(
            1,
            ServerTab::Group(servers.groups[1].id.clone()),
            "",
            None,
            &servers,
            &emitted,
        );
        assert_eq!(ids_at(&servers, &feed), ["FeedOne", "FeedTwo"]);

        let emitted_tab = TabRows::rebuild(1, ServerTab::Emitted, "", None, &servers, &emitted);
        assert_eq!(
            ids_at(&servers, &emitted_tab),
            ["FeedOne", "ManualOne", "ManualTwo", "FeedTwo"],
            "Emitted keeps the generated outbound order"
        );
    }

    #[test]
    fn the_search_filters_by_name_or_address_inside_the_tab_only() {
        let servers = servers();
        let emitted = servers.emitted_set();
        let rows = TabRows::rebuild(1, ServerTab::All, "  feed  ", None, &servers, &emitted);
        assert_eq!(ids_at(&servers, &rows), ["FeedOne", "FeedTwo"]);

        let rows = TabRows::rebuild(1, ServerTab::All, "10.0.0.4", None, &servers, &emitted);
        assert_eq!(ids_at(&servers, &rows), ["ManualTwo"]);

        // The same needle inside a tab that does not hold the row finds
        // nothing: the filter never reaches across tabs.
        let rows = TabRows::rebuild(1, ServerTab::Manual, "feed", None, &servers, &emitted);
        assert!(rows.rows().is_empty());
    }

    #[test]
    fn the_view_sort_reorders_every_tab_but_emitted() {
        let servers = servers();
        let emitted = servers.emitted_set();
        let descending = ViewSort {
            column: SortColumn::Name,
            ascending: false,
        };

        let all = TabRows::rebuild(1, ServerTab::All, "", Some(descending), &servers, &emitted);
        assert_eq!(
            ids_at(&servers, &all),
            ["ManualTwo", "ManualOne", "FeedTwo", "FeedOne"]
        );

        let manual = TabRows::rebuild(
            1,
            ServerTab::Manual,
            "",
            Some(descending),
            &servers,
            &emitted,
        );
        assert_eq!(ids_at(&servers, &manual), ["ManualTwo", "ManualOne"]);

        // Emitted draws the outbound order whatever the sort says.
        let emitted_tab = TabRows::rebuild(
            1,
            ServerTab::Emitted,
            "",
            Some(descending),
            &servers,
            &emitted,
        );
        assert_eq!(
            ids_at(&servers, &emitted_tab),
            ["FeedOne", "ManualOne", "ManualTwo", "FeedTwo"]
        );
    }

    #[test]
    fn the_latency_sort_puts_measured_rows_first_in_their_direction() {
        use crate::model::{ProbeOutcome, ProbeSource};
        use std::time::SystemTime;

        let mut servers = servers();
        let feed_one = index_of(&servers, "FeedOne");
        servers.profiles[feed_one].verdict = Some(ProbeVerdict {
            outcome: ProbeOutcome::Delay(10),
            source: ProbeSource::LatencyTest,
            measured_at: SystemTime::now(),
            error: None,
        });
        let emitted = servers.emitted_set();
        let ascending = ViewSort {
            column: SortColumn::Latency,
            ascending: true,
        };
        let rows = TabRows::rebuild(1, ServerTab::All, "", Some(ascending), &servers, &emitted);
        assert_eq!(
            ids_at(&servers, &rows),
            ["FeedOne", "ManualOne", "ManualTwo", "FeedTwo"],
            "unmeasured rows follow the measured ones, in their stored order"
        );
    }

    #[test]
    fn a_row_is_locked_exactly_when_it_is_the_route_or_a_chain_only_hop() {
        let freedom = || OutboundModel::new(Protocol::Freedom);
        let mut alpha = ServerProfile::new("Alpha", freedom());
        alpha.enabled = true;
        let hop = ServerProfile::new("Hop", freedom());
        let mut bravo = ServerProfile::new("Bravo", freedom());
        bravo.enabled = true;
        let mut servers = ServersFile {
            profiles: vec![alpha, hop, bravo],
            ..ServersFile::default()
        };
        servers.active = Some(servers.profiles[0].id.clone());

        let mut emitted = servers.emitted_set();
        // The fixture wires the chain by hand: Alpha dials through Hop.
        emitted.order = vec![0, 1, 2];
        emitted.chain_only = [1].into_iter().collect();
        emitted.dialers.insert(1, vec!["Alpha".to_owned()]);
        let rows = TabRows::rebuild(1, ServerTab::Emitted, "", None, &servers, &emitted);

        let active = rows.facts(0);
        assert!(active.active && active.locked && !active.hop);
        let hop = rows.facts(1);
        assert!(hop.hop && hop.locked && !hop.active);
        assert_eq!(hop.dialers, ["Alpha"]);
        let bravo = rows.facts(2);
        assert!(!bravo.active && !bravo.hop && !bravo.locked);
        assert!(bravo.dialers.is_empty());
    }

    #[test]
    fn a_row_moves_only_inside_a_block_with_another_movable_sibling() {
        let freedom = || OutboundModel::new(Protocol::Freedom);
        let mut alpha = ServerProfile::new("Alpha", freedom());
        alpha.enabled = true;
        let hop = ServerProfile::new("Hop", freedom());
        let mut bravo = ServerProfile::new("Bravo", freedom());
        bravo.enabled = true;
        let mut charlie = ServerProfile::new("Charlie", freedom());
        charlie.enabled = true;
        let mut servers = ServersFile {
            profiles: vec![alpha, hop, bravo, charlie],
            ..ServersFile::default()
        };
        servers.active = Some(servers.profiles[0].id.clone());
        let mut emitted = servers.emitted_set();
        emitted.order = vec![0, 1, 2, 3];
        emitted.chain_only = [1].into_iter().collect();
        let rows = TabRows::rebuild(1, ServerTab::Emitted, "", None, &servers, &emitted);
        assert!(!rows.facts(0).movable, "the active route is its own block");
        assert!(!rows.facts(1).movable, "a hop is not a place in its group");
        assert!(rows.facts(2).movable, "Bravo has a movable sibling");
        assert!(rows.facts(3).movable, "Charlie has a movable sibling");

        // The other tabs never advertise a move.
        let all = TabRows::rebuild(1, ServerTab::All, "", None, &servers, &emitted);
        assert!(
            all.rows()
                .iter()
                .enumerate()
                .all(|(display, _)| !all.facts(display).movable)
        );
    }

    #[test]
    fn facts_map_a_display_position_to_its_profile_and_tab_columns() {
        let servers = servers();
        let emitted = servers.emitted_set();
        let rows = TabRows::rebuild(1, ServerTab::All, "", None, &servers, &emitted);
        for display in 0..rows.rows().len() {
            let facts = rows.facts(display);
            assert_eq!(facts.profile, rows.rows()[display]);
            assert_eq!(facts.order, None, "only Emitted numbers its rows");
            assert!(facts.group, "All paints the group column");
        }
        let emitted_tab = TabRows::rebuild(1, ServerTab::Emitted, "", None, &servers, &emitted);
        assert_eq!(emitted_tab.facts(0).order, Some(1));
        assert_eq!(emitted_tab.facts(3).order, Some(4));
        assert!(emitted_tab.facts(0).group);
        let manual = TabRows::rebuild(1, ServerTab::Manual, "", None, &servers, &emitted);
        assert_eq!(manual.facts(0).order, None);
        assert!(!manual.facts(0).group);
    }

    #[test]
    fn drop_target_maps_a_gap_to_its_group_sibling_or_the_tail() {
        // Manual [Alpha, Bravo] then Feed [Charlie, Delta], Alpha the route:
        // Emitted draws Alpha → Bravo → Charlie → Delta.
        let mut servers = servers();
        let feed_id = servers.groups[1].id.clone();
        servers.profiles = vec![
            profile("Alpha", MANUAL_GROUP_ID, "10.0.0.1"),
            profile("Bravo", MANUAL_GROUP_ID, "10.0.0.2"),
            profile("Charlie", &feed_id, "10.0.0.3"),
            profile("Delta", &feed_id, "10.0.0.4"),
        ];
        servers.active = Some(servers.profiles[0].id.clone());
        let emitted = servers.emitted_set();
        let rows = TabRows::rebuild(1, ServerTab::Emitted, "", None, &servers, &emitted);
        assert_eq!(
            ids_at(&servers, &rows),
            ["Alpha", "Bravo", "Charlie", "Delta"]
        );

        // The first gap sits above the pinned route, which is no block a row
        // can enter.
        assert_eq!(rows.drop_target(1, 0), None);
        // A cross-block gap names no move.
        assert_eq!(rows.drop_target(3, 1), None);
        // Delta above Charlie lands ahead of it inside the Feed block.
        assert_eq!(rows.drop_target(3, 2), Some((3, Some(2))));
        // Charlie below Delta lands at the Feed block's tail.
        assert_eq!(rows.drop_target(2, 4), Some((2, None)));
        // The gaps beside the dragged row's own slot are no-ops.
        assert_eq!(rows.drop_target(3, 4), None);
        assert_eq!(rows.drop_target(2, 3), None);
        // The route never lifts.
        assert_eq!(rows.drop_target(0, 4), None);
    }

    #[test]
    fn drop_target_skips_a_hop_between_the_seed_rows() {
        let freedom = || OutboundModel::new(Protocol::Freedom);
        let mut alpha = ServerProfile::new("Alpha", freedom());
        alpha.enabled = true;
        let hop = ServerProfile::new("Hop", freedom());
        let mut bravo = ServerProfile::new("Bravo", freedom());
        bravo.enabled = true;
        let mut charlie = ServerProfile::new("Charlie", freedom());
        charlie.enabled = true;
        let mut servers = ServersFile {
            profiles: vec![alpha, hop, bravo, charlie],
            ..ServersFile::default()
        };
        servers.active = Some(servers.profiles[0].id.clone());
        let mut emitted = servers.emitted_set();
        emitted.order = vec![0, 1, 2, 3];
        emitted.chain_only = [1].into_iter().collect();
        let rows = TabRows::rebuild(1, ServerTab::Emitted, "", None, &servers, &emitted);
        assert_eq!(
            ids_at(&servers, &rows),
            ["Alpha", "Hop", "Bravo", "Charlie"]
        );

        // Charlie above Bravo: the hop between them is skipped, so the move
        // names Bravo, never the hop.
        assert_eq!(rows.drop_target(3, 2), Some((3, Some(2))));
        assert_eq!(rows.drop_target(1, 3), None, "a hop never lifts");
    }

    #[test]
    fn a_filter_or_sort_that_hides_a_selected_row_prunes_the_selection() {
        let servers = servers();
        let emitted = servers.emitted_set();
        let mut selection = Selection::default();
        selection.select(&servers.profiles[1].id);
        selection.toggle(&servers.profiles[3].id);
        assert_eq!(selection.len(), 2);

        // A search that keeps only ManualOne drops the other selected row.
        let filtered =
            TabRows::rebuild(1, ServerTab::Manual, "ManualOne", None, &servers, &emitted);
        selection.retain_visible(VisibleRows::new(filtered.rows(), &servers.profiles));
        assert_eq!(selection.len(), 1);
        assert!(selection.contains(&servers.profiles[1].id));

        // A sort keeps every row, so nothing is pruned: the visible order
        // moves and the batch commands follow it.
        selection.toggle(&servers.profiles[3].id);
        let descending = ViewSort {
            column: SortColumn::Name,
            ascending: false,
        };
        let sorted = TabRows::rebuild(
            1,
            ServerTab::Manual,
            "",
            Some(descending),
            &servers,
            &emitted,
        );
        selection.retain_visible(VisibleRows::new(sorted.rows(), &servers.profiles));
        assert_eq!(selection.len(), 2);
        assert_eq!(
            selection.ids_in_order(VisibleRows::new(sorted.rows(), &servers.profiles)),
            vec![
                servers.profiles[3].id.clone(),
                servers.profiles[1].id.clone()
            ]
        );
    }

    #[test]
    fn is_current_tracks_the_four_view_inputs() {
        let servers = servers();
        let emitted = servers.emitted_set();
        let rows = TabRows::rebuild(7, ServerTab::All, "feed", None, &servers, &emitted);
        assert!(rows.is_current(7, &ServerTab::All, "feed", None));
        assert!(!rows.is_current(8, &ServerTab::All, "feed", None));
        assert!(!rows.is_current(7, &ServerTab::Manual, "feed", None));
        assert!(!rows.is_current(7, &ServerTab::All, "manual", None));
        assert!(!rows.is_current(
            7,
            &ServerTab::Manual,
            "feed",
            Some(ViewSort {
                column: SortColumn::Name,
                ascending: true
            })
        ));
    }
}
