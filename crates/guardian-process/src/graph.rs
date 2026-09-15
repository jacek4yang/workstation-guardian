//! The process graph: parent/child structure over a process inventory.
//!
//! Detection needs ancestry, not just a flat list. "Is this `cargo` owned by a Claude Code
//! session?" and "is this `python.exe` an MCP helper spawned by an agent, rather than an
//! agent itself?" are both questions about the tree.
//!
//! # Cycles
//!
//! A process tree on Windows is not guaranteed to be a tree. Parent pids can be reused, a
//! process can outlive its parent, and a snapshot taken while processes start and exit can
//! contain an edge that closes a loop. Every traversal here is therefore bounded by a depth
//! limit, so a malformed graph degrades to a truncated ancestor list rather than an infinite
//! loop.

use std::collections::{HashMap, HashSet};

use guardian_proto::model::ProcessSnapshot;

/// Maximum depth walked when collecting ancestors.
///
/// Real process trees are a handful of levels deep. 64 is far beyond anything legitimate
/// while still bounding the work on a corrupted graph.
pub const MAX_ANCESTRY_DEPTH: usize = 64;

/// A parent/child view over a snapshot.
#[derive(Debug, Clone)]
pub struct ProcessGraph {
    nodes: HashMap<u32, ProcessSnapshot>,
    children: HashMap<u32, Vec<u32>>,
    /// pid -> depth from a root, computed lazily for tie-breaking.
    roots: Vec<u32>,
}

impl ProcessGraph {
    /// Build a graph from a snapshot list.
    ///
    /// If two snapshots share a pid (possible when a pid is reused between the moment the
    /// snapshot started and finished), the later entry wins, which matches what a reader
    /// would see by re-querying.
    pub fn new(processes: Vec<ProcessSnapshot>) -> Self {
        let mut nodes = HashMap::with_capacity(processes.len());
        for p in processes {
            nodes.insert(p.pid, p);
        }

        let mut children: HashMap<u32, Vec<u32>> = HashMap::with_capacity(nodes.len());
        for p in nodes.values() {
            // An edge to a pid that is not in the snapshot is not usable, and a self-edge
            // would create a trivial cycle.
            if p.parent_pid == 0 || p.parent_pid == p.pid {
                continue;
            }
            if !nodes.contains_key(&p.parent_pid) {
                continue;
            }
            children.entry(p.parent_pid).or_default().push(p.pid);
        }

        let mut roots: Vec<u32> = nodes
            .values()
            .filter(|p| p.parent_pid == 0 || !nodes.contains_key(&p.parent_pid))
            .map(|p| p.pid)
            .collect();
        roots.sort_unstable();

        ProcessGraph {
            nodes,
            children,
            roots,
        }
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn get(&self, pid: u32) -> Option<&ProcessSnapshot> {
        self.nodes.get(&pid)
    }

    pub fn iter(&self) -> impl Iterator<Item = &ProcessSnapshot> {
        self.nodes.values()
    }

    pub fn roots(&self) -> &[u32] {
        &self.roots
    }

    /// Immediate children of a pid.
    pub fn children_of(&self, pid: u32) -> &[u32] {
        self.children.get(&pid).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Walk from `pid` toward the root, returning tips in parent-first order.
    ///
    /// Bounded by [`MAX_ANCESTRY_DEPTH`] and by a visited set, so a cycle terminates.
    pub fn ancestors(&self, pid: u32) -> Vec<&ProcessSnapshot> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut current = pid;

        for _ in 0..MAX_ANCESTRY_DEPTH {
            let Some(node) = self.nodes.get(&current) else {
                break;
            };
            let parent = node.parent_pid;
            if parent == 0 || parent == current || !seen.insert(parent) {
                break;
            }
            let Some(parent_node) = self.nodes.get(&parent) else {
                break;
            };
            out.push(parent_node);
            current = parent;
        }

        out
    }

    /// The immediate parent, if present in the snapshot.
    pub fn parent_of(&self, pid: u32) -> Option<&ProcessSnapshot> {
        let node = self.nodes.get(&pid)?;
        self.nodes.get(&node.parent_pid)
    }

    /// Collect `pid` and every descendant, breadth-first, bounded by `limit`.
    ///
    /// The bound matters: a process that spawns children in a loop could otherwise make this
    /// walk the entire process table for every candidate, every sweep.
    pub fn subtree(&self, pid: u32, limit: usize) -> Vec<u32> {
        let mut out = Vec::new();
        let mut queue = std::collections::VecDeque::new();
        let mut seen = HashSet::new();

        queue.push_back(pid);
        seen.insert(pid);

        while let Some(current) = queue.pop_front() {
            out.push(current);
            if out.len() >= limit {
                break;
            }
            for &child in self.children_of(current) {
                if seen.insert(child) {
                    queue.push_back(child);
                }
            }
        }

        out
    }

    /// The outermost ancestor of `pid` that is still within the snapshot.
    ///
    /// This is the agent-session root: many agents re-exec themselves or tunnel through a
    /// launcher, and the meaningful identity is the top of that chain.
    pub fn root_ancestor(&self, pid: u32) -> u32 {
        let mut current = pid;
        let mut seen = HashSet::new();
        seen.insert(pid);

        for _ in 0..MAX_ANCESTRY_DEPTH {
            let Some(node) = self.nodes.get(&current) else {
                break;
            };
            let parent = node.parent_pid;
            if parent == 0 || !self.nodes.contains_key(&parent) {
                break;
            }
            if !seen.insert(parent) {
                // A cycle: stop rather than spin.
                break;
            }
            current = parent;
        }

        current
    }

    /// Names of the immediate children of `pid`, for signature matching.
    pub fn child_names(&self, pid: u32) -> Vec<&str> {
        self.children_of(pid)
            .iter()
            .filter_map(|c| self.nodes.get(c))
            .map(|p| p.name.as_str())
            .collect()
    }

    /// Whether any descendant matches a predicate. Bounded by `limit`.
    pub fn any_descendant(
        &self,
        pid: u32,
        limit: usize,
        pred: impl Fn(&ProcessSnapshot) -> bool,
    ) -> bool {
        self.subtree(pid, limit)
            .into_iter()
            .filter(|&p| p != pid)
            .filter_map(|p| self.nodes.get(&p))
            .any(pred)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardian_proto::model::ProcessIdentity;

    fn p(pid: u32, parent: u32, name: &str) -> ProcessSnapshot {
        ProcessSnapshot {
            pid,
            parent_pid: parent,
            name: name.into(),
            image_path: None,
            cmdline: None,
            created_filetime: pid as u64,
            session_id: 1,
            user_sid: None,
            cmdline_denied: false,
        }
    }

    /// The shape from the real machine: a terminal hosting a shell hosting an agent hosting
    /// a build tool.
    fn realistic_tree() -> ProcessGraph {
        ProcessGraph::new(vec![
            p(100, 0, "WindowsTerminal.exe"),
            p(200, 100, "pwsh.exe"),
            p(300, 200, "node.exe"),
            p(400, 300, "claude.exe"),
            p(500, 400, "git.exe"),
            p(600, 400, "cargo.exe"),
            p(700, 600, "rustc.exe"),
        ])
    }

    #[test]
    fn children_are_indexed_correctly() {
        let g = realistic_tree();
        assert_eq!(g.children_of(400).len(), 2);
        assert!(g.children_of(400).contains(&500));
        assert!(g.children_of(400).contains(&600));
        assert!(g.children_of(700).is_empty());
        assert!(
            g.children_of(99_999).is_empty(),
            "an unknown pid has no children"
        );
    }

    #[test]
    fn ancestry_walks_upward_parent_first() {
        let g = realistic_tree();
        let names: Vec<&str> = g.ancestors(400).iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["node.exe", "pwsh.exe", "WindowsTerminal.exe"]);
    }

    #[test]
    fn ancestry_of_a_root_is_empty() {
        let g = realistic_tree();
        assert!(g.ancestors(100).is_empty());
    }

    #[test]
    fn ancestry_of_an_unknown_pid_is_empty() {
        let g = realistic_tree();
        assert!(g.ancestors(12_345).is_empty());
    }

    #[test]
    fn root_ancestor_finds_the_top_of_the_chain() {
        let g = realistic_tree();
        assert_eq!(g.root_ancestor(700), 100);
        assert_eq!(g.root_ancestor(400), 100);
        assert_eq!(g.root_ancestor(100), 100, "a root is its own root");
    }

    #[test]
    fn a_cycle_terminates_instead_of_hanging() {
        // Parent pid reuse can produce a loop in a snapshot. Traversal must not spin.
        let g = ProcessGraph::new(vec![p(1, 2, "a.exe"), p(2, 1, "b.exe")]);
        let ancestors = g.ancestors(1);
        assert!(
            ancestors.len() <= 2,
            "a cycle must terminate: {ancestors:?}"
        );
        let _ = g.root_ancestor(1);
    }

    #[test]
    fn a_self_parent_edge_is_ignored() {
        let g = ProcessGraph::new(vec![p(1, 1, "self.exe")]);
        assert!(g.ancestors(1).is_empty());
        assert_eq!(g.root_ancestor(1), 1);
        assert!(g.children_of(1).is_empty());
    }

    #[test]
    fn a_dangling_parent_produces_a_root() {
        // The parent exited before the snapshot; the child is effectively a root.
        let g = ProcessGraph::new(vec![p(5, 4, "orphan.exe")]);
        assert_eq!(g.roots(), &[5]);
        assert!(g.ancestors(5).is_empty());
    }

    #[test]
    fn subtree_collects_descendants_breadth_first_and_bounded() {
        let g = realistic_tree();
        let sub = g.subtree(400, 100);
        assert!(sub.contains(&400));
        assert!(sub.contains(&500));
        assert!(sub.contains(&600));
        assert!(sub.contains(&700));
        assert!(!sub.contains(&300), "the parent is not a descendant");

        // The limit is respected even when more nodes exist.
        let bounded = g.subtree(100, 3);
        assert_eq!(bounded.len(), 3);
    }

    #[test]
    fn subtree_of_a_leaf_is_itself() {
        let g = realistic_tree();
        assert_eq!(g.subtree(700, 100), vec![700]);
    }

    #[test]
    fn descendant_predicate_sees_grandchildren() {
        let g = realistic_tree();
        assert!(g.any_descendant(300, 100, |p| p.name == "rustc.exe"));
        assert!(!g.any_descendant(500, 100, |p| p.name == "rustc.exe"));
    }

    #[test]
    fn descendant_search_does_not_match_the_node_itself() {
        let g = realistic_tree();
        assert!(
            !g.any_descendant(400, 100, |p| p.name == "claude.exe"),
            "the starting node is not its own descendant"
        );
    }

    #[test]
    fn child_names_are_available_for_matching() {
        let g = realistic_tree();
        let mut names = g.child_names(400);
        names.sort_unstable();
        assert_eq!(names, vec!["cargo.exe", "git.exe"]);
    }

    #[test]
    fn duplicate_pids_keep_the_last_entry() {
        // A pid reused mid-snapshot; the later entry is the one a fresh query would see.
        let g = ProcessGraph::new(vec![p(10, 0, "old.exe"), p(10, 0, "new.exe")]);
        assert_eq!(g.get(10).unwrap().name, "new.exe");
        assert_eq!(g.len(), 1);
    }

    #[test]
    fn empty_graph_is_usable() {
        let g = ProcessGraph::new(vec![]);
        assert!(g.is_empty());
        assert!(g.ancestors(1).is_empty());
        assert!(g.children_of(1).is_empty());
        assert!(g.roots().is_empty());
    }

    #[test]
    fn depth_limit_bounds_a_very_deep_chain() {
        // A chain deeper than the limit must be truncated, not walked forever.
        let mut v = vec![p(0, 0, "root.exe")];
        for i in 1..200u32 {
            v.push(p(i, i - 1, "n.exe"));
        }
        let g = ProcessGraph::new(v);
        let ancestors = g.ancestors(199);
        assert!(
            ancestors.len() <= MAX_ANCESTRY_DEPTH,
            "ancestry must be bounded, got {}",
            ancestors.len()
        );
    }

    #[test]
    fn process_identity_is_available_from_graph_nodes() {
        let g = realistic_tree();
        let node = g.get(400).unwrap();
        let id: ProcessIdentity = node.identity();
        assert_eq!(id.pid, 400);
        assert_eq!(id.created_filetime, 400);
    }
}
