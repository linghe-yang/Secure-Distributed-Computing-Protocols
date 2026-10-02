use crate::{Bundle, Fragment, Retrieval, SourceOpening, StorageFault, StripeWitness};
use anyhow::{ensure, Result};
use bincode::Options;
use crypto::{
    hash::{do_hash, Hash},
    weighted_merkle::{verify, IndexedTree},
};
use reed_solomon_erasure::galois_16::ReedSolomon;
use std::collections::BTreeMap;
use types::{InstanceId, Replica, WeightedMembership};

pub const BLOCK_BYTES: usize = 32;
pub const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;
pub const CHUNK_BYTES: usize = 32 * 1024;
/// One shared directory and completion instance; stripes never run separate quorums.
pub struct Codec {
    pub k: usize,
    pub m: usize,
    pub q: usize,
    pub file_bytes: usize,
    pub counts: Vec<usize>,
    pub positions: Vec<std::ops::Range<usize>>,
    pub context: Hash,
    pub directory_context: Hash,
    code: ReedSolomon,
}
pub struct Prepared {
    pub root: Hash,
    pub bundles: Vec<Bundle>,
    pub stripes: Vec<IndexedTree>,
    pub directory: IndexedTree,
    pub rows: Vec<Vec<[u8; 32]>>,
}
impl Codec {
    pub fn new(
        membership: &WeightedMembership,
        instance: InstanceId,
        public_id: Hash,
        file_bytes: usize,
    ) -> Result<Self> {
        let k = membership.n();
        ensure!(
            k <= 4096 && instance.valid(k) && instance.dealer.is_some(),
            "WAVID requires a registered dealer and at most 4096 physical parties"
        );
        ensure!(
            file_bytes <= MAX_FILE_BYTES,
            "file length exceeds resource limit"
        );
        let counts = membership.storage_counts();
        let m: usize = counts.iter().sum();
        let q = file_bytes.max(1).div_ceil(k * BLOCK_BYTES);
        let code = ReedSolomon::new(k, m - k)?;
        let mut offset = 0;
        let positions = counts
            .iter()
            .map(|count| {
                let r = offset..offset + count;
                offset += count;
                r
            })
            .collect();
        let context = do_hash(&bincode::serialize(&(
            "wavid/systematic-gf16/v1",
            public_id,
            instance,
            file_bytes as u64,
            k as u64,
            m as u64,
            &counts,
        ))?);
        let directory_context = do_hash(&bincode::serialize(&("wavid/directory/v1", context))?);
        Ok(Self {
            k,
            m,
            q,
            file_bytes,
            counts,
            positions,
            context,
            directory_context,
            code,
        })
    }
    pub fn stripe_context(&self, z: usize) -> Hash {
        do_hash(&bincode::serialize(&("wavid/stripe/v1", self.context, z as u64)).unwrap())
    }
    fn encode_stripe(&self, data: &[[u8; 32]]) -> Result<Vec<[u8; 32]>> {
        ensure!(data.len() == self.k, "source stripe size");
        let mut shards: Vec<Vec<[u8; 2]>> = data
            .iter()
            .map(|b| b.chunks_exact(2).map(|c| [c[0], c[1]]).collect())
            .collect();
        shards.extend((self.k..self.m).map(|_| vec![[0; 2]; 16]));
        self.code.encode(&mut shards)?;
        Ok(shards
            .into_iter()
            .map(|s| {
                let mut b = [0; 32];
                for (i, c) in s.into_iter().enumerate() {
                    b[2 * i] = c[0];
                    b[2 * i + 1] = c[1];
                }
                b
            })
            .collect())
    }
    pub fn prepare(&self, data: &[u8]) -> Result<Prepared> {
        ensure!(
            data.len() == self.file_bytes,
            "fixed file length differs from descriptor"
        );
        let mut padded = data.to_vec();
        padded.resize(self.q * self.k * 32, 0);
        let mut rows = Vec::with_capacity(self.q);
        for stripe in padded.chunks_exact(self.k * 32) {
            let source: Vec<[u8; 32]> = stripe
                .chunks_exact(32)
                .map(|c| c.try_into().unwrap())
                .collect();
            rows.push(self.encode_stripe(&source)?);
        }
        self.commit_rows(rows)
    }
    /// Low-level commitment; callers may use this to exercise malformed-dealer certificates.
    pub fn commit_rows(&self, rows: Vec<Vec<[u8; 32]>>) -> Result<Prepared> {
        ensure!(
            rows.len() == self.q && rows.iter().all(|s| s.len() == self.m),
            "invalid coordinate geometry"
        );
        let stripes: Vec<_> = rows
            .iter()
            .enumerate()
            .map(|(z, r)| {
                IndexedTree::new(
                    self.stripe_context(z),
                    &r.iter().map(|b| b.to_vec()).collect::<Vec<_>>(),
                )
            })
            .collect();
        let roots: Vec<_> = stripes.iter().map(|t| t.root().to_vec()).collect();
        let directory = IndexedTree::new(self.directory_context, &roots);
        let root = directory.root();
        let bundles = (0..self.k)
            .map(|owner| Bundle {
                directory: stripes.iter().map(|t| t.root()).collect(),
                stripes: rows
                    .iter()
                    .enumerate()
                    .map(|(z, r)| {
                        self.positions[owner]
                            .clone()
                            .map(|index| Fragment {
                                index,
                                data: r[index],
                                proof: stripes[z].proof(index),
                            })
                            .collect()
                    })
                    .collect(),
            })
            .collect();
        Ok(Prepared {
            root,
            bundles,
            stripes,
            directory,
            rows,
        })
    }
    pub fn bundle_bytes(&self, owner: Replica) -> usize {
        // bincode fixed-width lengths, two vectors inside Proof, hashes and booleans.
        let depth = self.m.next_power_of_two().max(2).trailing_zeros() as usize;
        let fragment = 8 + 32 + 8 + 32 * (depth + 2) + 8 + depth;
        8 + 32 * self.q + 8 + self.q * (8 + self.counts[owner] * fragment)
    }
    pub fn decode_bundle(&self, owner: Replica, raw: &[u8]) -> Option<Bundle> {
        if owner >= self.k || raw.len() != self.bundle_bytes(owner) {
            return None;
        }
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(raw.len() as u64)
            .reject_trailing_bytes()
            .deserialize(raw)
            .ok()
    }
    pub fn verify_bundle(
        &self,
        owner: Replica,
        bundle: &Bundle,
        expected: Option<Hash>,
    ) -> Option<Hash> {
        if owner >= self.k || bundle.directory.len() != self.q || bundle.stripes.len() != self.q {
            return None;
        }
        let root = IndexedTree::new(
            self.directory_context,
            &bundle
                .directory
                .iter()
                .map(|h| h.to_vec())
                .collect::<Vec<_>>(),
        )
        .root();
        if expected.is_some_and(|r| r != root) {
            return None;
        }
        for (z, stripe) in bundle.stripes.iter().enumerate() {
            if stripe.len() != self.counts[owner] {
                return None;
            }
            for (index, fragment) in self.positions[owner].clone().zip(stripe) {
                if fragment.index != index
                    || !verify(
                        self.stripe_context(z),
                        bundle.directory[z],
                        self.m,
                        index,
                        &fragment.data,
                        &fragment.proof,
                    )
                {
                    return None;
                }
            }
        }
        Some(root)
    }
    fn decode_stripe(&self, fragments: &[Fragment]) -> Result<Vec<[u8; 32]>> {
        ensure!(fragments.len() == self.k, "exactly k fragments needed");
        let mut shards: Vec<Option<Vec<[u8; 2]>>> = vec![None; self.m];
        for f in fragments {
            ensure!(
                f.index < self.m && shards[f.index].is_none(),
                "duplicate or unknown coordinate"
            );
            shards[f.index] = Some(f.data.chunks_exact(2).map(|c| [c[0], c[1]]).collect());
        }
        self.code.reconstruct(&mut shards)?;
        // Re-encode from the recovered systematic data, including originally supplied parity.
        let source: Vec<_> = shards[..self.k]
            .iter()
            .map(|s| {
                let mut b = [0; 32];
                for (i, c) in s.as_ref().unwrap().iter().enumerate() {
                    b[2 * i] = c[0];
                    b[2 * i + 1] = c[1];
                }
                b
            })
            .collect();
        self.encode_stripe(&source)
    }
    pub fn source_opening(&self, prepared: &Prepared, block: usize) -> Result<SourceOpening> {
        ensure!(block < self.q * self.k, "source block index");
        let z = block / self.k;
        let index = block % self.k;
        Ok(SourceOpening {
            stripe: z,
            root: prepared.stripes[z].root(),
            directory_proof: prepared.directory.proof(z),
            fragment: Fragment {
                index,
                data: prepared.rows[z][index],
                proof: prepared.stripes[z].proof(index),
            },
        })
    }
    pub fn verify_source(&self, root: Hash, p: &SourceOpening) -> bool {
        p.stripe < self.q
            && p.fragment.index < self.k
            && verify(
                self.directory_context,
                root,
                self.q,
                p.stripe,
                &p.root,
                &p.directory_proof,
            )
            && verify(
                self.stripe_context(p.stripe),
                p.root,
                self.m,
                p.fragment.index,
                &p.fragment.data,
                &p.fragment.proof,
            )
    }
    pub fn verify_fault(&self, root: Hash, fault: &StorageFault) -> bool {
        match fault {
            StorageFault::Coding(w) => {
                if w.stripe >= self.q
                    || w.fragments.len() != self.k
                    || !verify(
                        self.directory_context,
                        root,
                        self.q,
                        w.stripe,
                        &w.root,
                        &w.directory_proof,
                    )
                {
                    return false;
                }
                if w.fragments.iter().any(|f| {
                    !verify(
                        self.stripe_context(w.stripe),
                        w.root,
                        self.m,
                        f.index,
                        &f.data,
                        &f.proof,
                    )
                }) {
                    return false;
                }
                match self.decode_stripe(&w.fragments) {
                    Ok(rows) => {
                        IndexedTree::new(
                            self.stripe_context(w.stripe),
                            &rows.iter().map(|b| b.to_vec()).collect::<Vec<_>>(),
                        )
                        .root()
                            != w.root
                    }
                    Err(_) => false,
                }
            }
            StorageFault::Padding(p) => {
                self.verify_source(root, p)
                    && p.fragment.data.iter().enumerate().any(|(offset, b)| {
                        (p.stripe * self.k + p.fragment.index) * 32 + offset >= self.file_bytes
                            && *b != 0
                    })
            }
        }
    }
    pub fn recover(
        &self,
        root: Hash,
        directory: &[Hash],
        rows: &[BTreeMap<usize, Fragment>],
    ) -> Result<Option<Retrieval>> {
        if rows.len() != self.q || rows.iter().any(|r| r.len() < self.k) {
            return Ok(None);
        }
        ensure!(directory.len() == self.q, "directory size");
        let tree = IndexedTree::new(
            self.directory_context,
            &directory.iter().map(|h| h.to_vec()).collect::<Vec<_>>(),
        );
        ensure!(tree.root() == root, "directory commitment");
        let mut data = Vec::with_capacity(self.q * self.k * 32);
        for z in 0..self.q {
            let fragments: Vec<_> = rows[z].values().take(self.k).cloned().collect();
            ensure!(
                fragments.iter().all(|f| verify(
                    self.stripe_context(z),
                    directory[z],
                    self.m,
                    f.index,
                    &f.data,
                    &f.proof
                )),
                "unauthenticated recovery coordinate"
            );
            let decoded = self.decode_stripe(&fragments)?;
            let encoded_tree = IndexedTree::new(
                self.stripe_context(z),
                &decoded.iter().map(|b| b.to_vec()).collect::<Vec<_>>(),
            );
            if encoded_tree.root() != directory[z] {
                return Ok(Some(Retrieval::Invalid(StorageFault::Coding(
                    StripeWitness {
                        stripe: z,
                        root: directory[z],
                        directory_proof: tree.proof(z),
                        fragments,
                    },
                ))));
            }
            for (index, block) in decoded[..self.k].iter().enumerate() {
                if block.iter().enumerate().any(|(offset, b)| {
                    (z * self.k + index) * 32 + offset >= self.file_bytes && *b != 0
                }) {
                    return Ok(Some(Retrieval::Invalid(StorageFault::Padding(
                        SourceOpening {
                            stripe: z,
                            root: directory[z],
                            directory_proof: tree.proof(z),
                            fragment: Fragment {
                                index,
                                data: *block,
                                proof: encoded_tree.proof(index),
                            },
                        },
                    ))));
                }
                data.extend_from_slice(block);
            }
        }
        data.truncate(self.file_bytes);
        Ok(Some(Retrieval::File(data)))
    }
}
