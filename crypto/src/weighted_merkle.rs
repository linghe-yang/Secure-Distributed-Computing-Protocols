//! Indexed SHA-256 Merkle commitments for weighted protocols.
//! Reuses the repository's hash primitive and proof representation. The legacy
//! accelerated tree is intentionally unchanged; its hash_two implementation
//! encrypts temporary arrays and cannot be used for these binding commitments.
use crate::{
    aes_hash::Proof,
    hash::{do_hash, Hash},
};
use sha2::{Digest, Sha256};

/// Cached domain/context prefix. Encoding is byte-for-byte identical to bincode v1.
struct Hasher {
    leaf: Sha256,
    branch: Sha256,
}
fn prefix(tag: &str, context: Hash, count: usize) -> Sha256 {
    let mut h = Sha256::new();
    h.update((tag.len() as u64).to_le_bytes());
    h.update(tag.as_bytes());
    h.update(context);
    h.update((count as u64).to_le_bytes());
    h
}
impl Hasher {
    fn new(context: Hash, count: usize) -> Self {
        Self {
            leaf: prefix("weighted/merkle/leaf/v1", context, count),
            branch: prefix("weighted/merkle/branch/v1", context, count),
        }
    }
    fn leaf(&self, index: usize, value: &[u8]) -> Hash {
        let mut h = self.leaf.clone();
        h.update((index as u64).to_le_bytes());
        h.update((value.len() as u64).to_le_bytes());
        h.update(value);
        h.finalize().into()
    }
    fn branch(&self, index: usize, left: Hash, right: Hash) -> Hash {
        let mut h = self.branch.clone();
        h.update((index as u64).to_le_bytes());
        h.update(left);
        h.update(right);
        h.finalize().into()
    }
}
pub fn leaf(context: Hash, count: usize, index: usize, value: &[u8]) -> Hash {
    Hasher::new(context, count).leaf(index, value)
}
pub struct IndexedTree {
    nodes: Vec<Hash>,
    pub count: usize,
    width: usize,
    context: Hash,
}
impl IndexedTree {
    pub fn new<V: AsRef<[u8]>>(context: Hash, values: &[V]) -> Self {
        assert!(!values.is_empty());
        let count = values.len();
        let width = count.next_power_of_two().max(2);
        let mut nodes = vec![[0; 32]; 2 * width];
        let hasher = Hasher::new(context, count);
        for i in 0..width {
            nodes[width + i] = if i < count {
                hasher.leaf(i, values[i].as_ref())
            } else {
                do_hash(
                    &bincode::serialize(&(
                        "weighted/merkle/padding/v1",
                        context,
                        count as u64,
                        i as u64,
                    ))
                    .unwrap(),
                )
            };
        }
        for i in (1..width).rev() {
            nodes[i] = hasher.branch(i, nodes[2 * i], nodes[2 * i + 1]);
        }
        Self {
            nodes,
            count,
            width,
            context,
        }
    }
    pub fn root(&self) -> Hash {
        self.nodes[1]
    }
    pub fn proof(&self, index: usize) -> Proof {
        assert!(index < self.count);
        let mut pos = self.width + index;
        let mut lemma = vec![self.nodes[pos]];
        let mut path = vec![];
        while pos > 1 {
            lemma.push(self.nodes[pos ^ 1]);
            path.push(pos & 1 == 0);
            pos /= 2;
        }
        lemma.push(self.root());
        Proof::new(lemma, path)
    }
    pub fn range_proof(&self, start: usize, len: usize) -> Option<Vec<Hash>> {
        Some(
            range_frontier(self.count, start, len)?
                .into_iter()
                .map(|p| self.nodes[p])
                .collect(),
        )
    }
    pub fn context(&self) -> Hash {
        self.context
    }
}
pub fn verify(
    context: Hash,
    root: Hash,
    count: usize,
    index: usize,
    value: &[u8],
    proof: &Proof,
) -> bool {
    if count == 0 || index >= count || count > 1 << 24 {
        return false;
    }
    let width = count.next_power_of_two().max(2);
    let depth = width.trailing_zeros() as usize;
    if proof.path().len() != depth || proof.lemma().len() != depth + 2 {
        return false;
    }
    if proof.item() != leaf(context, count, index, value) || proof.root() != root {
        return false;
    }
    let hasher = Hasher::new(context, count);
    let mut pos = width + index;
    let mut hash = proof.item();
    for (level, sibling) in proof.lemma()[1..depth + 1].iter().enumerate() {
        let left = pos & 1 == 0;
        if proof.path()[level] != left {
            return false;
        }
        hash = if left {
            hasher.branch(pos / 2, hash, *sibling)
        } else {
            hasher.branch(pos / 2, *sibling, hash)
        };
        pos /= 2;
    }
    hash == root
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn one_leaf_and_malformed_proofs() {
        let data = vec![vec![7; 32]];
        let t = IndexedTree::new([1; 32], &data);
        let p = t.proof(0);
        assert!(verify([1; 32], t.root(), 1, 0, &data[0], &p));
        assert!(!verify([2; 32], t.root(), 1, 0, &data[0], &p));
        assert!(!verify(
            [1; 32],
            t.root(),
            1,
            0,
            &data[0],
            &Proof::new(vec![], vec![])
        ));
        assert!(!verify([1; 32], t.root(), 1, 1, &data[0], &p));
    }
    #[test]
    fn every_leaf_is_binding() {
        let data = vec![vec![7; 32]; 16];
        let t = IndexedTree::new([1; 32], &data);
        for i in 0..data.len() {
            let mut changed = data.clone();
            changed[i][0] ^= 1;
            let other = IndexedTree::new([1; 32], &changed);
            assert_ne!(t.root(), other.root());
            assert!(!verify([1; 32], t.root(), 16, i, &changed[i], &t.proof(i)));
            assert!(verify([1; 32], t.root(), 16, i, &data[i], &t.proof(i)));
        }
    }
}

/// Canonical minimal frontier for a nonempty contiguous leaf range, in node order.
pub fn range_frontier(count: usize, start: usize, len: usize) -> Option<Vec<usize>> {
    if count == 0 || count > 1 << 24 || len == 0 || start.checked_add(len)? > count {
        return None;
    }
    let width = count.next_power_of_two().max(2);
    let mut active: std::collections::BTreeSet<_> = (width + start..width + start + len).collect();
    let mut frontier = std::collections::BTreeSet::new();
    while !active.contains(&1) {
        for &pos in &active {
            if !active.contains(&(pos ^ 1)) {
                frontier.insert(pos ^ 1);
            }
        }
        active = active.into_iter().map(|p| p / 2).collect();
    }
    Some(frontier.into_iter().collect())
}
/// Verify a multiproof once, then materialize legacy openings for public fault certificates.
pub fn open_range<V: AsRef<[u8]>>(
    context: Hash,
    root: Hash,
    count: usize,
    start: usize,
    values: &[V],
    siblings: &[Hash],
) -> Option<Vec<Proof>> {
    let frontier = range_frontier(count, start, values.len())?;
    if frontier.len() != siblings.len() {
        return None;
    }
    let width = count.next_power_of_two().max(2);
    let h = Hasher::new(context, count);
    let mut nodes: std::collections::BTreeMap<usize, Hash> =
        frontier.into_iter().zip(siblings.iter().copied()).collect();
    let mut active = std::collections::BTreeSet::new();
    for (i, value) in values.iter().enumerate() {
        nodes.insert(width + start + i, h.leaf(start + i, value.as_ref()));
        active.insert(width + start + i);
    }
    while !active.contains(&1) {
        let parents: std::collections::BTreeSet<_> = active.iter().map(|p| p / 2).collect();
        for &p in &parents {
            nodes.insert(
                p,
                h.branch(p, *nodes.get(&(2 * p))?, *nodes.get(&(2 * p + 1))?),
            );
        }
        active = parents;
    }
    if nodes.get(&1)? != &root {
        return None;
    }
    (start..start + values.len())
        .map(|i| {
            let mut pos = width + i;
            let mut lemma = vec![*nodes.get(&pos)?];
            let mut path = vec![];
            while pos > 1 {
                lemma.push(*nodes.get(&(pos ^ 1))?);
                path.push(pos & 1 == 0);
                pos /= 2;
            }
            lemma.push(root);
            Some(Proof::new(lemma, path))
        })
        .collect()
}
/// Extract a canonical frontier from individual openings without changing the tree.
pub fn pack_range(count: usize, start: usize, proofs: &[Proof]) -> Option<Vec<Hash>> {
    let frontier = range_frontier(count, start, proofs.len())?;
    let width = count.next_power_of_two().max(2);
    let depth = width.trailing_zeros() as usize;
    let mut nodes = std::collections::BTreeMap::new();
    for (i, proof) in proofs.iter().enumerate() {
        if proof.lemma().len() != depth + 2 || proof.path().len() != depth {
            return None;
        }
        let mut pos = width + start + i;
        for sibling in &proof.lemma()[1..depth + 1] {
            nodes.insert(pos ^ 1, *sibling);
            pos /= 2;
        }
    }
    frontier
        .into_iter()
        .map(|p| nodes.get(&p).copied())
        .collect()
}

#[cfg(test)]
mod optimized_tests {
    use super::*;
    #[test]
    fn hashes_preserve_bincode_commitments() {
        let context = [13; 32];
        let h = Hasher::new(context, 192);
        for i in 0..192 {
            let a = [i as u8; 32];
            let b = [7; 32];
            assert_eq!(
                h.leaf(i, &a),
                do_hash(
                    &bincode::serialize(&(
                        "weighted/merkle/leaf/v1",
                        context,
                        192u64,
                        i as u64,
                        a.as_slice()
                    ))
                    .unwrap()
                )
            );
            assert_eq!(
                h.branch(i, a, b),
                do_hash(
                    &bincode::serialize(&(
                        "weighted/merkle/branch/v1",
                        context,
                        192u64,
                        i as u64,
                        a,
                        b
                    ))
                    .unwrap()
                )
            );
        }
    }
    #[test]
    fn multiproofs_bind_every_range_and_reject_malformed_frontiers() {
        for n in [1, 2, 3, 7, 12, 25] {
            let values: Vec<_> = (0..n).map(|i| [i as u8; 32]).collect();
            let t = IndexedTree::new([1; 32], &values);
            for start in 0..n {
                for len in 1..=n - start {
                    let proofs: Vec<_> = (start..start + len).map(|i| t.proof(i)).collect();
                    let p = pack_range(n, start, &proofs).unwrap();
                    let opened =
                        open_range([1; 32], t.root(), n, start, &values[start..start + len], &p)
                            .unwrap();
                    for (j, proof) in opened.iter().enumerate() {
                        assert!(verify(
                            [1; 32],
                            t.root(),
                            n,
                            start + j,
                            &values[start + j],
                            proof
                        ));
                    }
                    let mut bad = values[start..start + len].to_vec();
                    bad[0][0] ^= 1;
                    assert!(open_range([1; 32], t.root(), n, start, &bad, &p).is_none());
                    let mut extra = p.clone();
                    extra.push([0; 32]);
                    assert!(open_range(
                        [1; 32],
                        t.root(),
                        n,
                        start,
                        &values[start..start + len],
                        &extra
                    )
                    .is_none());
                }
            }
        }
    }
}
