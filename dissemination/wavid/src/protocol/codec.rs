use crate::{Bundle, Fragment, Retrieval, SourceOpening, StorageFault, StripeWitness};
use anyhow::{ensure, Result};
use bincode::Options;
use crypto::{
    hash::{do_hash, Hash},
    weighted_merkle::{open_range, pack_range, range_frontier, verify, IndexedTree},
};
use reed_solomon_erasure::galois_16::ReedSolomon;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex, OnceLock, Weak},
};
use types::{InstanceId, Replica, WeightedMembership};

pub const BLOCK_BYTES: usize = 32;
// For n <= 64 and W <= n^n, the reference 256-bit certified AX bulk
// is bounded by 126.90 MiB (odd-even) or 157.99 MiB (bitonic).
// Keep more than 3x headroom; this caps raw file bytes, not encoded storage.
pub const MAX_FILE_BYTES: usize = 512 * 1024 * 1024;
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
    code: Arc<Coding>,
}
enum Coding {
    Gf8(reed_solomon_erasure::galois_8::ReedSolomon),
    Gf16(ReedSolomon),
}
fn coding(k: usize, m: usize) -> Result<Arc<Coding>> {
    type Cache = Mutex<HashMap<(usize, usize), Weak<Coding>>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();
    let mut cache = CACHE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap();
    if let Some(c) = cache.get(&(k, m)).and_then(Weak::upgrade) {
        return Ok(c);
    }
    cache.retain(|_, v| v.strong_count() > 0);
    let c = Arc::new(if m <= 256 {
        Coding::Gf8(reed_solomon_erasure::galois_8::ReedSolomon::new(k, m - k)?)
    } else {
        Coding::Gf16(ReedSolomon::new(k, m - k)?)
    });
    cache.insert((k, m), Arc::downgrade(&c));
    Ok(c)
}
#[derive(Serialize, Deserialize)]
struct PackedStripe {
    data: Vec<[u8; 32]>,
    siblings: Vec<Hash>,
}
#[derive(Serialize, Deserialize)]
struct PackedBundle {
    version: u8,
    directory: Vec<Hash>,
    stripes: Vec<PackedStripe>,
}
/// Only the verified decoder constructs this wrapper; caller mutation cannot bypass checks.
pub(crate) struct VerifiedBundle {
    pub(crate) bundle: Bundle,
    pub(crate) root: Hash,
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
        let code = coding(k, m)?;
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
            "wavid/systematic-adaptive/multiproof/v2",
            BLOCK_BYTES as u64,
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
        if let Coding::Gf8(code) = self.code.as_ref() {
            let mut shards: Vec<[u8; 32]> = data.to_vec();
            shards.resize(self.m, [0; 32]);
            code.encode(&mut shards)?;
            return Ok(shards);
        }
        let mut shards: Vec<Vec<[u8; 2]>> = data
            .iter()
            .map(|b| b.chunks_exact(2).map(|c| [c[0], c[1]]).collect())
            .collect();
        shards.extend((self.k..self.m).map(|_| vec![[0; 2]; 16]));
        match self.code.as_ref() {
            Coding::Gf16(code) => code.encode(&mut shards)?,
            Coding::Gf8(_) => unreachable!(),
        };
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
    /// Normal network path: build each stripe once and avoid materializing individual paths.
    pub(crate) fn prepare_packets(&self, data: &[u8]) -> Result<(Hash, Vec<Vec<u8>>)> {
        ensure!(
            data.len() == self.file_bytes,
            "fixed file length differs from descriptor"
        );
        let mut bundles: Vec<PackedBundle> = (0..self.k)
            .map(|_| PackedBundle {
                version: 2,
                directory: Vec::new(),
                stripes: Vec::with_capacity(self.q),
            })
            .collect();
        let mut roots = Vec::with_capacity(self.q);
        for z in 0..self.q {
            let mut source = vec![[0u8; 32]; self.k];
            for (j, block) in source.iter_mut().enumerate() {
                let start = (z * self.k + j) * BLOCK_BYTES;
                if start < data.len() {
                    let end = (start + BLOCK_BYTES).min(data.len());
                    block[..end - start].copy_from_slice(&data[start..end]);
                }
            }
            let row = self.encode_stripe(&source)?;
            let tree = IndexedTree::new(self.stripe_context(z), &row);
            roots.push(tree.root());
            for (owner, bundle) in bundles.iter_mut().enumerate() {
                let positions = self.positions[owner].clone();
                bundle.stripes.push(PackedStripe {
                    data: row[positions.clone()].to_vec(),
                    siblings: tree.range_proof(positions.start, positions.len()).unwrap(),
                });
            }
        }
        let root = IndexedTree::new(self.directory_context, &roots).root();
        let mut packets = Vec::with_capacity(self.k);
        for (owner, mut bundle) in bundles.into_iter().enumerate() {
            bundle.directory = roots.clone();
            let mut raw = Vec::with_capacity(self.bundle_bytes(owner));
            bincode::serialize_into(&mut raw, &bundle)?;
            packets.push(raw);
        }
        Ok((root, packets))
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
            .map(|(z, r)| IndexedTree::new(self.stripe_context(z), r))
            .collect();
        let roots: Vec<_> = stripes.iter().map(|t| t.root()).collect();
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
        let frontier = range_frontier(self.m, self.positions[owner].start, self.counts[owner])
            .unwrap()
            .len();
        1 + 8 + 32 * self.q + 8 + self.q * (8 + 32 * self.counts[owner] + 8 + 32 * frontier)
    }
    /// Versioned compact wire representation; public single-block openings remain available.
    pub fn encode_bundle(&self, owner: Replica, bundle: &Bundle) -> Result<Vec<u8>> {
        ensure!(
            owner < self.k && bundle.directory.len() == self.q && bundle.stripes.len() == self.q,
            "bundle geometry"
        );
        let mut stripes = Vec::with_capacity(self.q);
        for stripe in &bundle.stripes {
            ensure!(
                stripe.len() == self.counts[owner]
                    && stripe
                        .iter()
                        .zip(self.positions[owner].clone())
                        .all(|(f, i)| f.index == i),
                "coordinate geometry"
            );
            let proofs: Vec<_> = stripe.iter().map(|f| f.proof.clone()).collect();
            let siblings = pack_range(self.m, self.positions[owner].start, &proofs)
                .ok_or_else(|| anyhow::anyhow!("malformed proof"))?;
            stripes.push(PackedStripe {
                data: stripe.iter().map(|f| f.data).collect(),
                siblings,
            });
        }
        let mut raw = Vec::with_capacity(self.bundle_bytes(owner));
        bincode::serialize_into(
            &mut raw,
            &PackedBundle {
                version: 2,
                directory: bundle.directory.clone(),
                stripes,
            },
        )?;
        Ok(raw)
    }
    pub fn decode_bundle(&self, owner: Replica, raw: &[u8]) -> Option<Bundle> {
        self.decode_verified_bundle(owner, raw, None, None)
            .map(|v| v.bundle)
    }
    pub(crate) fn decode_verified_bundle(
        &self,
        owner: Replica,
        raw: &[u8],
        expected: Option<Hash>,
        cached_directory: Option<&[Hash]>,
    ) -> Option<VerifiedBundle> {
        if owner >= self.k || raw.len() != self.bundle_bytes(owner) {
            return None;
        }
        let packed: PackedBundle = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(raw.len() as u64)
            .reject_trailing_bytes()
            .deserialize(raw)
            .ok()?;
        if packed.version != 2 || packed.directory.len() != self.q || packed.stripes.len() != self.q
        {
            return None;
        }
        let root = if let (Some(root), Some(directory)) = (expected, cached_directory) {
            if directory != packed.directory.as_slice() {
                return None;
            }
            root
        } else {
            IndexedTree::new(self.directory_context, &packed.directory).root()
        };
        if expected.is_some_and(|r| r != root) {
            return None;
        }
        let mut stripes = Vec::with_capacity(self.q);
        for (z, stripe) in packed.stripes.into_iter().enumerate() {
            if stripe.data.len() != self.counts[owner] {
                return None;
            }
            let proofs = open_range(
                self.stripe_context(z),
                packed.directory[z],
                self.m,
                self.positions[owner].start,
                &stripe.data,
                &stripe.siblings,
            )?;
            stripes.push(
                self.positions[owner]
                    .clone()
                    .zip(stripe.data.into_iter().zip(proofs))
                    .map(|(index, (data, proof))| Fragment { index, data, proof })
                    .collect(),
            );
        }
        Some(VerifiedBundle {
            root,
            bundle: Bundle {
                directory: packed.directory,
                stripes,
            },
        })
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
        if let Coding::Gf8(code) = self.code.as_ref() {
            let mut shards: Vec<Option<Vec<u8>>> = vec![None; self.m];
            for f in fragments {
                ensure!(
                    f.index < self.m && shards[f.index].is_none(),
                    "duplicate or unknown coordinate"
                );
                shards[f.index] = Some(f.data.to_vec());
            }
            code.reconstruct_data(&mut shards)?;
            let source: Vec<[u8; 32]> = shards[..self.k]
                .iter()
                .map(|s| s.as_ref().unwrap().as_slice().try_into().unwrap())
                .collect();
            return self.encode_stripe(&source);
        }
        let mut shards: Vec<Option<Vec<[u8; 2]>>> = vec![None; self.m];
        for f in fragments {
            ensure!(
                f.index < self.m && shards[f.index].is_none(),
                "duplicate or unknown coordinate"
            );
            shards[f.index] = Some(f.data.chunks_exact(2).map(|c| [c[0], c[1]]).collect());
        }
        match self.code.as_ref() {
            Coding::Gf16(code) => code.reconstruct_data(&mut shards)?,
            Coding::Gf8(_) => unreachable!(),
        };
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
                        IndexedTree::new(self.stripe_context(w.stripe), &rows).root() != w.root
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
        self.recover_inner(root, directory, rows, false)
    }
    pub(crate) fn recover_verified(
        &self,
        root: Hash,
        directory: &[Hash],
        rows: &[BTreeMap<usize, Fragment>],
    ) -> Result<Option<Retrieval>> {
        self.recover_inner(root, directory, rows, true)
    }
    fn recover_inner(
        &self,
        root: Hash,
        directory: &[Hash],
        rows: &[BTreeMap<usize, Fragment>],
        verified: bool,
    ) -> Result<Option<Retrieval>> {
        if rows.len() != self.q || rows.iter().any(|r| r.len() < self.k) {
            return Ok(None);
        }
        ensure!(directory.len() == self.q, "directory size");
        let tree = IndexedTree::new(self.directory_context, directory);
        ensure!(tree.root() == root, "directory commitment");
        let mut data = Vec::with_capacity(self.q * self.k * 32);
        for z in 0..self.q {
            let fragments: Vec<_> = rows[z].values().take(self.k).cloned().collect();
            ensure!(
                verified
                    || fragments.iter().all(|f| verify(
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
            let encoded_tree = IndexedTree::new(self.stripe_context(z), &decoded);
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
