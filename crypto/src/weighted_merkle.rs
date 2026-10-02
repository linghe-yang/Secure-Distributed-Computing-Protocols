//! Indexed SHA-256 Merkle commitments for weighted protocols.
//! Reuses the repository's hash primitive and proof representation. The legacy
//! accelerated tree is intentionally unchanged; its hash_two implementation
//! encrypts temporary arrays and cannot be used for these binding commitments.
use crate::{
    aes_hash::Proof,
    hash::{do_hash, Hash},
};
pub fn leaf(context: Hash, count: usize, index: usize, value: &[u8]) -> Hash {
    do_hash(
        &bincode::serialize(&(
            "weighted/merkle/leaf/v1",
            context,
            count as u64,
            index as u64,
            value,
        ))
        .expect("leaf encoding"),
    )
}
fn branch(context: Hash, count: usize, index: usize, left: Hash, right: Hash) -> Hash {
    do_hash(
        &bincode::serialize(&(
            "weighted/merkle/branch/v1",
            context,
            count as u64,
            index as u64,
            left,
            right,
        ))
        .expect("branch encoding"),
    )
}
pub struct IndexedTree {
    nodes: Vec<Hash>,
    pub count: usize,
    width: usize,
    context: Hash,
}
impl IndexedTree {
    pub fn new(context: Hash, values: &[Vec<u8>]) -> Self {
        assert!(!values.is_empty());
        let count = values.len();
        let width = count.next_power_of_two().max(2);
        let mut nodes = vec![[0; 32]; 2 * width];
        for i in 0..width {
            nodes[width + i] = if i < count {
                leaf(context, count, i, &values[i])
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
            nodes[i] = branch(context, count, i, nodes[2 * i], nodes[2 * i + 1]);
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
    let mut pos = width + index;
    let mut hash = proof.item();
    for (level, sibling) in proof.lemma()[1..depth + 1].iter().enumerate() {
        let left = pos & 1 == 0;
        if proof.path()[level] != left {
            return false;
        }
        hash = if left {
            branch(context, count, pos / 2, hash, *sibling)
        } else {
            branch(context, count, pos / 2, *sibling, hash)
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
