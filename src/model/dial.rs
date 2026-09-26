//! The server-profile reference and dial graph.
//!
//! How profiles point at each other is one graph, but every question over it
//! used to be a private walk: the validation pass rebuilt the chain map to
//! report a dangling hop or a cycle, the generator rebuilt the tag set to
//! decide which profiles dial out directly (the bootstrap DNS scope), the
//! latency probe walked the chain transitively to stage the probes a profile
//! needs, the delete dialog scanned rules, balancers and every other profile
//! for references, and the chain-target picker listed the hops a profile may
//! name. Five walks, three resolutions of "does this target name a profile",
//! two of them able to disagree about a builtin or a cycle.
//!
//! This module answers all of them from one graph built over the profile set
//! and the outbound tags the generated document carries — so "is this hop a
//! profile", "which outbound is direct-dial" and "who references this tag"
//! have one definition each.

use super::ServerProfile;
use super::inbound::{BLOCK_OUTBOUND_TAG, DIRECT_OUTBOUND_TAG};
use super::settings::Settings;
use super::validation::{ValidationCode, ValidationIssue};
use crate::links::excerpt;
use std::collections::BTreeSet;

/// The profile-set dial graph, resolved against the tags the generated
/// document carries.
///
/// A chain target outside that universe is a dangling reference (the
/// validation pass reports it and generation refuses); a target inside it
/// that names no profile is a built-in outbound the child resolves itself.
pub struct DialGraph<'a> {
    profiles: &'a [ServerProfile],
    outbound_tags: &'a BTreeSet<String>,
}

impl<'a> DialGraph<'a> {
    /// The graph of `profiles`, resolved against `outbound_tags` — the set
    /// `emit::outbound_tags` (settings scope) or
    /// `emit::profile_outbound_tags` (profile scope) answers.
    pub fn new(profiles: &'a [ServerProfile], outbound_tags: &'a BTreeSet<String>) -> Self {
        Self {
            profiles,
            outbound_tags,
        }
    }

    fn profile(&self, tag: &str) -> Option<&'a ServerProfile> {
        self.profiles.iter().find(|profile| profile.tag() == tag)
    }

    /// Whether this profile dials its server itself: no chain hop, or a hop
    /// that names a built-in outbound rather than another profile (that hop's
    /// server is reached on the far side of the built-in, not through a
    /// profile the document carries).
    pub fn dials_directly(&self, profile: &ServerProfile) -> bool {
        match profile.chain_target() {
            None => true,
            Some(target) => self.profile(target).is_none(),
        }
    }

    /// The outbound tags of every profile that dials out directly.
    pub fn direct_dial_tags(&self) -> BTreeSet<String> {
        self.profiles
            .iter()
            .filter(|profile| self.dials_directly(profile))
            .map(ServerProfile::tag)
            .collect()
    }

    /// The profiles `tag` reaches through its chain, transitively and
    /// cycle-safe, in breadth-first walk order: the profiles a staged child
    /// needs besides `tag` itself. An unresolvable target is left out — a
    /// built-in resolves inside the child, and a dangling one is refused at
    /// generation instead.
    pub fn dependencies(&self, tag: &str) -> Vec<&'a ServerProfile> {
        let mut visited = BTreeSet::from([tag.to_string()]);
        let mut queue = vec![tag.to_string()];
        let mut dependencies = Vec::new();
        while let Some(current) = queue.first().cloned() {
            queue.remove(0);
            let Some(profile) = self.profile(&current) else {
                continue;
            };
            let Some(target) = profile.chain_target() else {
                continue;
            };
            if !visited.insert(target.to_string()) {
                continue;
            }
            if let Some(dependency) = self.profile(target) {
                dependencies.push(dependency);
                queue.push(target.to_string());
            }
        }
        dependencies
    }

    /// The tags a profile's chain hop may name: every other profile, then the
    /// built-in outbounds. A profile's own tag is excluded — a hop to itself
    /// could only produce a cycle.
    pub fn chain_target_options(&self, own_id: &str) -> Vec<String> {
        self.profiles
            .iter()
            .filter(|profile| profile.id != own_id)
            .map(ServerProfile::tag)
            .chain([
                DIRECT_OUTBOUND_TAG.to_string(),
                BLOCK_OUTBOUND_TAG.to_string(),
            ])
            .collect()
    }

    /// Every model site that references `profile_id`'s outbound tag, as wire
    /// paths: routing rules, balancer fallbacks, and other profiles' chain
    /// hops. The delete confirmation renders these verbatim — which is why the
    /// profile being deleted is excluded by *identity*: two profiles can carry
    /// one tag (a hand-edited state file), and a tag comparison would drop the
    /// other one's real reference to the same outbound.
    pub fn references(&self, settings: &Settings, profile_id: &str) -> Vec<String> {
        let Some(tag) = self
            .profiles
            .iter()
            .find(|profile| profile.id == profile_id)
            .map(ServerProfile::tag)
        else {
            return Vec::new();
        };
        let mut references = Vec::new();
        for (index, rule) in settings.routing.rules.iter().enumerate() {
            if rule.outbound_tag == tag {
                references.push(format!("routing.rules[{}].outboundTag", index + 1));
            }
        }
        for (index, balancer) in settings.routing.balancers.iter().enumerate() {
            if balancer.fallback_tag == tag {
                references.push(format!("routing.balancers[{}].fallbackTag", index + 1));
            }
        }
        for (index, profile) in self.profiles.iter().enumerate() {
            if profile.id == profile_id {
                continue;
            }
            if profile.chain_target() == Some(tag.as_str()) {
                let label = if profile.name.is_empty() {
                    profile.tag()
                } else {
                    profile.name.clone()
                };
                references.push(format!(
                    "servers[{}] ({label}).streamSettings.sockopt.dialerProxy",
                    index + 1
                ));
            }
        }
        references
    }

    /// The chain rules of this graph, in the order the profile list reads: a
    /// hop naming no emitted outbound, then (at most) one cycle report
    /// naming the loop it walked.
    pub fn chain_findings(&self) -> Vec<ValidationIssue> {
        let mut findings = Vec::new();
        let mut chains = Vec::<(String, String)>::new();
        for profile in self.profiles {
            let Some(target) = profile.chain_target() else {
                continue;
            };
            let source = profile.tag();
            if !self.outbound_tags.contains(target) {
                findings.push(ValidationIssue::error(
                    ValidationCode::OutboundChainMissing(excerpt(&source), excerpt(target)),
                ));
            } else {
                chains.push((source, target.to_string()));
            }
        }
        let target_of = |tag: &str| {
            chains
                .iter()
                .find(|(source, _)| source == tag)
                .map(|(_, target)| target.as_str())
        };
        for (start, _) in &chains {
            let mut path = Vec::<String>::new();
            let mut current = start.as_str();
            loop {
                if let Some(index) = path.iter().position(|tag| tag == current) {
                    let mut cycle = path[index..].to_vec();
                    cycle.push(current.to_string());
                    findings.push(ValidationIssue::error(ValidationCode::OutboundChainCycle(
                        excerpt(&cycle.join(" -> ")),
                    )));
                    return findings;
                }
                path.push(current.to_string());
                let Some(next) = target_of(current) else {
                    break;
                };
                current = next;
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{OutboundModel, Protocol};

    fn profile(name: &str) -> ServerProfile {
        ServerProfile::new(name, OutboundModel::new(Protocol::Freedom))
    }

    /// Give `profile` a chain hop to `target`, the way the editor writes one.
    fn chain(profile: &mut ServerProfile, target: &str) {
        let sockopt = profile
            .outbound
            .stream
            .sockopt
            .get_or_insert_with(Default::default);
        sockopt.dialer_proxy = target.to_string();
    }

    /// The outbound universe of `profiles`, as the graph resolves against it:
    /// the caller keeps it alive beside the graph.
    fn tags_of(profiles: &[ServerProfile]) -> BTreeSet<String> {
        crate::model::emit::profile_outbound_tags(profiles)
    }

    /// A profile with no hop, one with a hop to a profile, and one whose hop
    /// names the built-in `direct` are the three dial shapes: only the middle
    /// one reaches its server through the chain.
    #[test]
    fn direct_dial_follows_the_profile_set_not_the_target_shape() {
        let mut direct = profile("direct");
        chain(&mut direct, DIRECT_OUTBOUND_TAG);
        let mut chained = profile("chained");
        let hop = profile("hop");
        chain(&mut chained, &hop.tag());
        let plain = profile("plain");
        let profiles = vec![direct.clone(), chained.clone(), hop.clone(), plain.clone()];
        let tags = tags_of(&profiles);
        let graph = DialGraph::new(&profiles, &tags);

        assert!(graph.dials_directly(&direct), "a builtin hop is direct");
        assert!(!graph.dials_directly(&chained), "a profile hop is not");
        assert!(graph.dials_directly(&plain));
        assert_eq!(
            graph.direct_dial_tags(),
            BTreeSet::from([direct.tag(), hop.tag(), plain.tag()])
        );
    }

    /// The dependency walk reaches through hops transitively, never repeats a
    /// profile, and terminates on a cycle (which validation refuses, but the
    /// probe stages its child before the verdict exists).
    #[test]
    fn dependencies_walk_transitively_and_terminate_on_cycles() {
        let first = profile("first");
        let second = profile("second");
        let third = profile("third");
        let mut profiles = vec![first.clone(), second.clone(), third.clone()];
        chain(&mut profiles[0], &second.tag());
        chain(&mut profiles[1], &third.tag());
        chain(&mut profiles[2], &first.tag());
        let tags = tags_of(&profiles);
        let graph = DialGraph::new(&profiles, &tags);

        let dependencies = graph.dependencies(&first.tag());
        assert_eq!(
            dependencies
                .iter()
                .map(|profile| profile.id.as_str())
                .collect::<Vec<_>>(),
            [second.id.as_str(), third.id.as_str()],
            "the walk is breadth-first and cycle-safe"
        );
    }

    /// The chain rules: a hop outside the emitted universe is reported, and a
    /// cycle is reported once, naming the loop.
    #[test]
    fn chain_findings_report_dangling_hops_and_one_cycle() {
        let mut dangling = profile("dangling");
        chain(&mut dangling, "srv-not-emitted");
        let mut profiles = vec![dangling];
        let tags = tags_of(&profiles);
        let graph = DialGraph::new(&profiles, &tags);
        let findings = graph.chain_findings();
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(matches!(
            findings[0].code,
            ValidationCode::OutboundChainMissing(_, _)
        ));

        let a = profile("a");
        let b = profile("b");
        profiles = vec![a.clone(), b.clone()];
        chain(&mut profiles[0], &b.tag());
        chain(&mut profiles[1], &a.tag());
        let tags = tags_of(&profiles);
        let graph = DialGraph::new(&profiles, &tags);
        let findings = graph.chain_findings();
        assert_eq!(findings.len(), 1, "one report per graph: {findings:?}");
        let ValidationCode::OutboundChainCycle(path) = &findings[0].code else {
            panic!("expected a cycle report, got {:?}", findings[0].code);
        };
        assert!(
            path.contains(" -> ") && path.contains(&a.tag()) && path.contains(&b.tag()),
            "the report names the loop it walked: {path}"
        );
    }

    /// The option list offers every other profile and the built-ins, never
    /// the profile's own tag.
    #[test]
    fn chain_target_options_exclude_the_profile_itself() {
        let first = profile("first");
        let second = profile("second");
        let profiles = vec![first.clone(), second.clone()];
        let tags = tags_of(&profiles);
        let graph = DialGraph::new(&profiles, &tags);
        assert_eq!(
            graph.chain_target_options(&first.id),
            [
                second.tag(),
                DIRECT_OUTBOUND_TAG.to_string(),
                BLOCK_OUTBOUND_TAG.to_string()
            ]
        );
    }

    /// References cover the settings half (rules, balancer fallbacks) and the
    /// profile half (other profiles' hops), each as its wire path.
    #[test]
    fn references_name_every_site() {
        let target = profile("target");
        let mut chained = profile("chained");
        chain(&mut chained, &target.tag());
        let profiles = vec![target.clone(), chained.clone()];
        let tags = tags_of(&profiles);
        let graph = DialGraph::new(&profiles, &tags);
        let mut settings = Settings::default();
        settings.routing.rules.push(crate::model::Rule {
            outbound_tag: target.tag(),
            ..Default::default()
        });
        settings.routing.balancers.push(crate::model::Balancer {
            fallback_tag: target.tag(),
            ..Default::default()
        });

        let references = graph.references(&settings, &target.id);
        assert!(
            references
                .iter()
                .any(|path| path == "routing.rules[1].outboundTag"),
            "{references:?}"
        );
        assert!(
            references
                .iter()
                .any(|path| path == "routing.balancers[1].fallbackTag"),
            "{references:?}"
        );
        assert!(
            references
                .iter()
                .any(|path| path.contains("dialerProxy") && path.contains("chained")),
            "{references:?}"
        );
    }
}
