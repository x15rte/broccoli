//! The servers table's selection: the rows a table command acts on.

use std::collections::BTreeSet;

use crate::model::ServerProfile;

/// The rows a table command acts on — the clicked row, a Ctrl/Shift range, or
/// every visible row — plus the focused row the editor follows, the anchor a
/// Shift-click extends from, and whether the opening focus was filled in.
///
/// The selection never crosses a tab: every rule that computes from rows
/// takes the tab's visible row order, so an id outside it is never selected.
#[derive(Default)]
pub(super) struct Selection {
    /// The row the editor follows. A plain click and a Ctrl-add move it; a
    /// row menu opened outside the selection does not.
    focus: Option<String>,
    /// The selected rows by profile id. Scoped to the tab and to what the
    /// search shows.
    ids: BTreeSet<String>,
    /// The row a Shift-click extends from. `None` until a plain or Ctrl
    /// click names one.
    anchor: Option<String>,
    /// Whether the opening focus was filled in. The screen focuses the active
    /// server (or the first row) once; switching tabs clears the focus and
    /// does not bring it back.
    initialized: bool,
}

/// One tab's visible rows in display order: the profile indices the table
/// renders and the profiles they index.
///
/// Every selection rule that computes from "what this tab shows" takes this
/// one value instead of a row slice beside a profile slice, so a display
/// position and the profile it names cannot drift apart or be swapped at a
/// call site.
#[derive(Clone, Copy)]
pub(super) struct VisibleRows<'a> {
    rows: &'a [usize],
    profiles: &'a [ServerProfile],
}

impl<'a> VisibleRows<'a> {
    /// The rows a tab renders, as indices into `profiles`.
    pub(super) fn new(rows: &'a [usize], profiles: &'a [ServerProfile]) -> Self {
        Self { rows, profiles }
    }

    /// The display position of `id`, when this tab shows that row.
    fn position_of(&self, id: &str) -> Option<usize> {
        self.rows
            .iter()
            .position(|&index| self.profiles[index].id == id)
    }

    /// The id at one display position.
    fn id_at(&self, position: usize) -> &'a str {
        self.profiles[self.rows[position]].id.as_str()
    }

    /// The ids this tab shows, in display order.
    fn ids(&self) -> impl Iterator<Item = &'a str> {
        let rows = self.rows;
        let profiles = self.profiles;
        rows.iter().map(move |&index| profiles[index].id.as_str())
    }
}

impl Selection {
    /// The focused row.
    pub(super) fn focus(&self) -> Option<&str> {
        self.focus.as_deref()
    }

    /// The row a Shift-click extends from.
    #[cfg(test)]
    pub(super) fn anchor(&self) -> Option<&str> {
        self.anchor.as_deref()
    }

    /// Whether `id` is selected.
    pub(super) fn contains(&self, id: &str) -> bool {
        self.ids.contains(id)
    }

    /// The number of selected rows.
    pub(super) fn len(&self) -> usize {
        self.ids.len()
    }

    /// Whether no row is selected.
    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// The selected ids, in id order — the form the row menu reads when it
    /// asks whether any selected row is copyable or locked.
    pub(super) fn iter(&self) -> impl Iterator<Item = &String> {
        self.ids.iter()
    }

    /// The only selected row, when exactly one is selected.
    pub(super) fn only(&self) -> Option<&str> {
        if self.ids.len() == 1 {
            self.ids.iter().next().map(String::as_str)
        } else {
            None
        }
    }

    /// Whether this id is the only selected row.
    pub(super) fn is_single(&self, id: &str) -> bool {
        self.ids.len() == 1 && self.ids.contains(id)
    }

    /// Focus `id` without touching the selection: the tests that drive a
    /// focused row alone.
    #[cfg(test)]
    pub(super) fn set_focus(&mut self, id: impl Into<String>) {
        self.focus = Some(id.into());
    }

    /// Fill the opening focus once: the active server or the first row, when
    /// nothing is focused yet. A later tab switch clears the focus and does
    /// not bring it back, because the fill's flag is already set.
    pub(super) fn initialize_focus(&mut self, fallback: impl FnOnce() -> Option<String>) {
        if self.initialized {
            return;
        }
        self.initialized = true;
        if self.focus.is_none() {
            self.focus = fallback();
        }
    }

    /// Drop a focus the model no longer backs, so a deleted profile cannot
    /// stay the editor's target.
    pub(super) fn retain_focus(&mut self, profiles: &[ServerProfile]) {
        if self
            .focus
            .as_ref()
            .is_some_and(|id| !profiles.iter().any(|profile| &profile.id == id))
        {
            self.focus = None;
        }
    }

    /// A plain click: make `id` the sole selected row, the focus, and the
    /// anchor.
    pub(super) fn select(&mut self, id: &str) {
        self.ids.clear();
        self.ids.insert(id.to_owned());
        self.anchor = Some(id.to_owned());
        self.focus = Some(id.to_owned());
    }

    /// A row menu opened on a row outside the selection replaces the
    /// selection with that row without moving the focus: the command acts on
    /// its own row while the editor stays on the focused one.
    pub(super) fn isolate(&mut self, id: &str) {
        self.ids.clear();
        self.ids.insert(id.to_owned());
        self.anchor = Some(id.to_owned());
    }

    /// Ctrl-click: add the row to the selection, or remove it. Removing the
    /// anchor clears it; removing the focus moves the focus to a remaining
    /// row, if any.
    pub(super) fn toggle(&mut self, id: &str) {
        if self.ids.remove(id) {
            if self.anchor.as_deref() == Some(id) {
                self.anchor = None;
            }
            if self.focus.as_deref() == Some(id) {
                self.focus = self.ids.iter().next().cloned();
            }
        } else {
            self.ids.insert(id.to_owned());
            self.focus = Some(id.to_owned());
            self.anchor = Some(id.to_owned());
        }
    }

    /// Shift-click: select every visible row between the anchor and `id`, in
    /// `rows`' display order. The anchor stays where it was; without a usable
    /// anchor the row becomes the whole selection.
    pub(super) fn extend(&mut self, id: &str, rows: VisibleRows<'_>) {
        let Some(target) = rows.position_of(id) else {
            return;
        };
        let anchor = self
            .anchor
            .as_deref()
            .and_then(|anchor| rows.position_of(anchor))
            .unwrap_or(target);
        let (start, end) = if anchor <= target {
            (anchor, target)
        } else {
            (target, anchor)
        };
        self.ids.clear();
        for position in start..=end {
            self.ids.insert(rows.id_at(position).to_owned());
        }
        self.anchor = Some(rows.id_at(anchor).to_owned());
        self.focus = Some(id.to_owned());
    }

    /// Ctrl+A: select every row the current tab shows, anchored at the first.
    pub(super) fn select_all(&mut self, rows: VisibleRows<'_>) {
        self.ids.clear();
        let mut first = None;
        for id in rows.ids() {
            self.ids.insert(id.to_owned());
            first.get_or_insert_with(|| id.to_owned());
        }
        self.anchor = first.clone();
        if first.is_some() {
            self.focus = first;
        }
    }

    /// Drop the selection and its anchor together, leaving nothing selected.
    pub(super) fn clear(&mut self) {
        self.ids.clear();
        self.anchor = None;
        self.focus = None;
    }

    /// Drop every selected id no profile backs any more, so a deleted profile
    /// cannot be acted on through a stale selection.
    pub(super) fn retain_profiles(&mut self, profiles: &[ServerProfile]) {
        self.ids
            .retain(|id| profiles.iter().any(|profile| &profile.id == id));
        self.retain_anchored_id();
    }

    /// Keep the selection inside the rows the current tab shows: a search
    /// that filters a row out also removes it from the selection.
    pub(super) fn retain_visible(&mut self, rows: VisibleRows<'_>) {
        self.ids.retain(|id| rows.position_of(id).is_some());
        self.retain_anchored_id();
    }

    /// Drop the rows `removed` names after a delete, and a focus that went
    /// with them.
    pub(super) fn retain_not(&mut self, removed: &[String]) {
        if self
            .focus
            .as_deref()
            .is_some_and(|id| removed.iter().any(|removed| removed == id))
        {
            self.focus = None;
        }
        self.ids.retain(|id| !removed.contains(id));
        self.retain_anchored_id();
    }

    /// The selected ids in `rows`' display order — the order every batch
    /// command applies — and only the rows this tab shows.
    pub(super) fn ids_in_order(&self, rows: VisibleRows<'_>) -> Vec<String> {
        rows.ids()
            .filter(|id| self.ids.contains(*id))
            .map(str::to_owned)
            .collect()
    }

    /// Clear an anchor whose row left the selection: the anchor is always one
    /// of the selected rows.
    fn retain_anchored_id(&mut self) {
        if self
            .anchor
            .as_deref()
            .is_some_and(|anchor| !self.ids.contains(anchor))
        {
            self.anchor = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Selection, VisibleRows};
    use crate::model::{OutboundModel, Protocol, ServerProfile};

    fn profiles(names: &[&str]) -> Vec<ServerProfile> {
        names
            .iter()
            .map(|name| ServerProfile::new(*name, OutboundModel::new(Protocol::Freedom)))
            .collect()
    }

    fn all(profiles: &[ServerProfile]) -> Vec<usize> {
        (0..profiles.len()).collect()
    }

    /// One tab's visible rows, as the screen hands them to the selection.
    fn visible<'a>(rows: &'a [usize], profiles: &'a [ServerProfile]) -> VisibleRows<'a> {
        VisibleRows::new(rows, profiles)
    }

    /// A plain select makes a sole selection and anchors it.
    #[test]
    fn a_plain_select_makes_one_row_the_selection_and_the_anchor() {
        let profiles = profiles(&["a", "b", "c"]);
        let mut selection = Selection::default();
        selection.select(&profiles[1].id);

        assert_eq!(
            selection.ids_in_order(visible(&all(&profiles), &profiles)),
            [profiles[1].id.clone()]
        );
        assert_eq!(selection.anchor(), Some(profiles[1].id.as_str()));
        assert_eq!(selection.focus(), Some(profiles[1].id.as_str()));
        assert!(selection.is_single(&profiles[1].id));
    }

    /// Ctrl toggles a row: adding moves the anchor and the focus to it,
    /// removing clears the anchor it held.
    #[test]
    fn ctrl_toggles_a_row_and_moves_the_anchor_with_it() {
        let profiles = profiles(&["a", "b", "c"]);
        let mut selection = Selection::default();
        selection.select(&profiles[0].id);
        selection.toggle(&profiles[2].id);
        assert_eq!(
            selection.ids_in_order(visible(&all(&profiles), &profiles)),
            [profiles[0].id.clone(), profiles[2].id.clone()]
        );
        assert_eq!(selection.anchor(), Some(profiles[2].id.as_str()));
        assert_eq!(selection.focus(), Some(profiles[2].id.as_str()));

        selection.toggle(&profiles[2].id);
        assert_eq!(
            selection.ids_in_order(visible(&all(&profiles), &profiles)),
            [profiles[0].id.clone()]
        );
        assert_eq!(selection.anchor(), None);
        assert_eq!(selection.focus(), Some(profiles[0].id.as_str()));
    }

    /// Shift extends from the anchor over the display order while the anchor
    /// stays put; without an anchor the clicked row becomes the selection.
    #[test]
    fn shift_extends_from_the_anchor_which_stays_put() {
        let profiles = profiles(&["a", "b", "c", "d"]);
        let rows = all(&profiles);
        let mut selection = Selection::default();
        selection.select(&profiles[0].id);
        selection.extend(&profiles[2].id, visible(&rows, &profiles));
        assert_eq!(
            selection.ids_in_order(visible(&rows, &profiles)),
            [
                profiles[0].id.clone(),
                profiles[1].id.clone(),
                profiles[2].id.clone()
            ]
        );
        assert_eq!(selection.anchor(), Some(profiles[0].id.as_str()));
        assert_eq!(selection.focus(), Some(profiles[2].id.as_str()));

        // Extending again measures from the same anchor, not from the last
        // Shift click.
        selection.extend(&profiles[1].id, visible(&rows, &profiles));
        assert_eq!(
            selection.ids_in_order(visible(&rows, &profiles)),
            [profiles[0].id.clone(), profiles[1].id.clone()]
        );
        assert_eq!(selection.anchor(), Some(profiles[0].id.as_str()));

        let mut fresh = Selection::default();
        fresh.extend(&profiles[3].id, visible(&rows, &profiles));
        assert_eq!(
            fresh.ids_in_order(visible(&rows, &profiles)),
            [profiles[3].id.clone()]
        );
        assert_eq!(fresh.anchor(), Some(profiles[3].id.as_str()));
    }

    /// Select-all covers every visible row and anchors the first.
    #[test]
    fn select_all_covers_the_visible_rows_and_anchors_the_first() {
        // A tab's row order need not be the model's: this one is reversed.
        let profiles = profiles(&["a", "b", "c"]);
        let rows = vec![2, 1, 0];
        let mut selection = Selection::default();
        selection.select_all(visible(&rows, &profiles));

        assert_eq!(
            selection.ids_in_order(visible(&rows, &profiles)),
            [
                profiles[2].id.clone(),
                profiles[1].id.clone(),
                profiles[0].id.clone()
            ]
        );
        assert_eq!(selection.anchor(), Some(profiles[2].id.as_str()));
        assert_eq!(selection.focus(), Some(profiles[2].id.as_str()));
    }

    /// Pruning drops the rows that left the model or the visible set, and
    /// clears an anchor that went with them.
    #[test]
    fn pruning_drops_rows_that_left_the_model_or_the_visible_set() {
        let profiles = profiles(&["a", "b", "c"]);
        let mut selection = Selection::default();
        selection.select_all(visible(&all(&profiles), &profiles));

        // A search filters "b" out of the tab.
        let rows = vec![0, 2];
        selection.retain_visible(visible(&rows, &profiles));
        assert_eq!(
            selection.ids_in_order(visible(&rows, &profiles)),
            [profiles[0].id.clone(), profiles[2].id.clone()]
        );
        assert_eq!(selection.anchor(), Some(profiles[0].id.as_str()));

        // The model no longer holds "a", the anchor: both go.
        let remaining = vec![profiles[2].clone()];
        selection.retain_profiles(&remaining);
        assert_eq!(
            selection.ids_in_order(visible(&all(&remaining), &remaining)),
            [remaining[0].id.clone()]
        );
        assert_eq!(selection.anchor(), None);
    }

    /// A delete drops the deleted rows and a focus that went with them.
    #[test]
    fn deleting_rows_drops_them_and_their_focus() {
        let profiles = profiles(&["a", "b"]);
        let mut selection = Selection::default();
        selection.select(&profiles[1].id);
        selection.retain_not(&[profiles[1].id.clone()]);
        assert!(selection.is_empty());
        assert_eq!(selection.focus(), None);
        assert_eq!(selection.anchor(), None);
    }

    /// Clearing leaves nothing selected or anchored.
    #[test]
    fn clearing_leaves_nothing() {
        let profiles = profiles(&["a", "b"]);
        let mut selection = Selection::default();
        selection.select_all(visible(&all(&profiles), &profiles));
        selection.clear();
        assert!(selection.is_empty());
        assert_eq!(selection.focus(), None);
        assert_eq!(selection.anchor(), None);
    }

    /// Ids come back in display order and only for the rows the tab passes:
    /// a selected row outside the visible order is never acted on.
    #[test]
    fn ids_come_back_in_display_order_and_never_across_tabs() {
        let profiles = profiles(&["a", "b", "c"]);
        let mut selection = Selection::default();
        selection.select_all(visible(&all(&profiles), &profiles));

        let tab_rows = vec![2, 0];
        assert_eq!(
            selection.ids_in_order(visible(&tab_rows, &profiles)),
            [profiles[2].id.clone(), profiles[0].id.clone()]
        );
    }

    /// The opening focus is filled once; a later clear is not undone by the
    /// next frame's fallback.
    #[test]
    fn the_opening_focus_is_filled_once() {
        let profiles = profiles(&["a", "b"]);
        let mut selection = Selection::default();
        selection.initialize_focus(|| Some(profiles[1].id.clone()));
        assert_eq!(selection.focus(), Some(profiles[1].id.as_str()));

        selection.clear();
        selection.initialize_focus(|| Some(profiles[0].id.clone()));
        assert_eq!(selection.focus(), None);
    }
}
