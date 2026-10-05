use hmac::{Hmac, Mac, NewMac};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const HASH_SIZE: usize = 32;

pub type Hash = [u8; HASH_SIZE];

pub const EMPTY_HASH: Hash = [0 as u8; 32];

type HmacSha256 = Hmac<Sha256>;

pub fn do_hash(bytes: &[u8]) -> Hash {
    let hash = Sha256::digest(bytes);
    return hash.into();
}

pub fn do_hash_merkle(bytes: &[u8]) -> Hash {
    let mut sha256 = Sha256::new();
    sha256.update(&[0x00]);
    sha256.update(bytes);
    sha256.clone().finalize().into()
}

pub fn ser_and_hash(obj: &impl Serialize) -> Hash {
    let serialized_bytes = bincode::serialize(obj).unwrap();
    return do_hash(&serialized_bytes);
}

pub fn do_mac(bytes: &[u8], secret_key: &[u8]) -> Hash {
    let mut mac = HmacSha256::new_varkey(secret_key).expect("HMAC can take secret key of any size");
    mac.update(bytes);
    let result = mac.finalize();
    // is an array copy necessary?
    result.into_bytes().into()
}

pub fn verf_mac(bytes: &[u8], secret_key: &[u8], mac_v: &[u8]) -> bool {
    let mut mac = HmacSha256::new_varkey(secret_key).expect("HMAC can take secret key of any size");

    mac.update(bytes);

    let err_c = mac.verify(mac_v);
    match err_c {
        Ok(_) => true,
        Err(_) => false,
    }
}
/// Stream bincode's canonical encoding into HMAC, without a message-sized temporary.
struct MacWriter(HmacSha256);
impl std::io::Write for MacWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub fn serialized_mac(value: &impl Serialize, key: &[u8]) -> bincode::Result<Hash> {
    let mut w = MacWriter(HmacSha256::new_varkey(key).expect("HMAC key"));
    bincode::serialize_into(&mut w, value)?;
    Ok(w.0.finalize().into_bytes().into())
}
pub fn verify_serialized_mac(value: &impl Serialize, key: &[u8], expected: &[u8]) -> bool {
    let mut w = MacWriter(HmacSha256::new_varkey(key).expect("HMAC key"));
    bincode::serialize_into(&mut w, value).is_ok() && w.0.verify(expected).is_ok()
}
#[cfg(test)]
mod streaming_tests {
    use super::*;
    #[test]
    fn canonical_mac_compatibility() {
        let value = (
            "weighted/frame/v1",
            [9u8; 32],
            0usize,
            1usize,
            17u64,
            vec![42u8; 32768],
        );
        let key = [3u8; 32];
        let old = do_mac(&bincode::serialize(&value).unwrap(), &key);
        assert_eq!(old, serialized_mac(&value, &key).unwrap());
        assert!(verify_serialized_mac(&value, &key, &old));
        let mut bad = old;
        bad[0] ^= 1;
        assert!(!verify_serialized_mac(&value, &key, &bad));
    }
}

/// Authenticate existing buffers without concatenating a large payload.
pub fn mac_parts(parts: &[&[u8]], key: &[u8]) -> Hash {
    let mut mac = HmacSha256::new_varkey(key).expect("HMAC key");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}
pub fn verify_mac_parts(parts: &[&[u8]], key: &[u8], expected: &[u8]) -> bool {
    let mut mac = HmacSha256::new_varkey(key).expect("HMAC key");
    for part in parts {
        mac.update(part);
    }
    mac.verify(expected).is_ok()
}
