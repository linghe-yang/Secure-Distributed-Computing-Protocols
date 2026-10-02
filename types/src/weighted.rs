//! Shared weighted membership and invocation types. Numerical weights never expand identities.
use crate::Replica;
use num_bigint::BigUint;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{collections::BTreeSet, fmt, str::FromStr};

#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct Weight(pub BigUint);
impl From<u64> for Weight {
    fn from(x: u64) -> Self {
        Self(x.into())
    }
}
impl FromStr for Weight {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (digits, radix) = s.strip_prefix("0x").map_or((s, 10), |s| (s, 16));
        BigUint::parse_bytes(digits.as_bytes(), radix)
            .map(Self)
            .ok_or_else(|| "expected a nonnegative decimal or hexadecimal integer".into())
    }
}
impl fmt::Display for Weight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl Serialize for Weight {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{}", self.0.to_str_radix(16)))
    }
}
impl<'de> Deserialize<'de> for Weight {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Paper convention: actual corrupt weight B < threshold T, with 3T <= W.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WeightedMembership {
    pub weights: Vec<Weight>,
    pub threshold: BigUint,
    pub total: BigUint,
    pub quorum: BigUint,
}
impl WeightedMembership {
    pub fn new(weights: Vec<Weight>, threshold: Weight) -> Result<Self, String> {
        if weights.is_empty() || weights.iter().any(|w| w.0 == BigUint::from(0u8)) {
            return Err("weights must be nonempty and strictly positive".into());
        }
        let total: BigUint = weights.iter().map(|w| w.0.clone()).sum();
        if threshold.0 == BigUint::from(0u8) || &threshold.0 * 3u8 > total {
            return Err("weighted protocols require 0 < T and 3T <= W; corrupt weight must be strictly less than T".into());
        }
        let quorum = &total - &threshold.0;
        Ok(Self {
            weights,
            threshold: threshold.0,
            total,
            quorum,
        })
    }
    pub fn n(&self) -> usize {
        self.weights.len()
    }
    pub fn weight(&self, ids: impl IntoIterator<Item = Replica>) -> Result<BigUint, String> {
        let mut seen = BTreeSet::new();
        let mut result = BigUint::from(0u8);
        for id in ids {
            if id >= self.n() || !seen.insert(id) {
                return Err("unknown or duplicate participant".into());
            }
            result += &self.weights[id].0;
        }
        Ok(result)
    }
    pub fn storage_counts(&self) -> Vec<usize> {
        self.weights
            .iter()
            .map(|w| {
                let value = (&w.0 * BigUint::from(3 * self.n()) + &self.total - BigUint::from(1u8))
                    / &self.total;
                // Each count is bounded by 3n, independently of weight bit length.
                value
                    .to_str_radix(10)
                    .parse()
                    .expect("storage count bounded by 3n")
            })
            .collect()
    }
}

/// IDs are application-registered before peer traffic. A service supplies its own component domain.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct InstanceId {
    pub epoch: u64,
    pub dealer: Option<Replica>,
    pub slot: u64,
}
impl InstanceId {
    pub fn new(epoch: u64, dealer: Option<Replica>, slot: u64) -> Self {
        Self {
            epoch,
            dealer,
            slot,
        }
    }
    pub fn valid(&self, n: usize) -> bool {
        self.dealer.map_or(true, |d| d < n)
    }
}

/// Explicit exact dyadic output: numerator / 2^exponent, never floating point.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Dyadic {
    pub numerator: Weight,
    pub exponent: u32,
}

#[derive(Clone, Debug)]
pub struct SendAction<T> {
    pub recipient: Replica,
    pub message: T,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn huge_weights_and_deduplication() {
        let w: Weight = format!("0x1{}", "0".repeat(512)).parse().unwrap();
        let m = WeightedMembership::new(vec![w.clone(); 4], Weight(&w.0 * 4u8 / 3u8)).unwrap();
        assert_eq!(m.storage_counts(), vec![3; 4]);
        assert!(m.weight([0, 0]).is_err());
        assert!(m.weight([4]).is_err());
        let encoded = bincode::serialize(&w).unwrap();
        assert_eq!(bincode::deserialize::<Weight>(&encoded).unwrap(), w);
    }
}
