#![deny(warnings)]
use crate::utils::poseidon_hash::internal;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Digest(pub [u8; 32]);

impl core::fmt::Debug for Digest {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        fmt.write_str("poseidon:")?;
        for b in self.0.iter() {
            fmt.write_fmt(format_args!("{b:02x}"))?;
        }
        Ok(())
    }
}

pub fn zero_digest() -> Digest {
    Digest([0u8; 32])
}

impl From<[u8; 32]> for Digest {
    fn from(d: [u8; 32]) -> Self {
        Self(d)
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Digest {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::invalid_length(bytes.len(), &"32 bytes"));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Digest(array))
    }
}

pub fn hash_one_thing<T1>(_label1: &str, v1: T1) -> Digest
where
    T1: AsRef<[u8]>,
{
    // Use the consolidated Poseidon hashing
    let hash = internal::hash_slice(v1.as_ref());
    Digest(hash)
}

pub fn hash_two_things<T1, T2>(_label1: &str, _label2: &str, v1: T1, v2: T2) -> Digest
where
    T1: AsRef<[u8]>,
    T2: AsRef<[u8]>,
{
    // Use the consolidated Poseidon hashing for two slices
    let hash = internal::hash_two_slices(v1.as_ref(), v2.as_ref());
    Digest(hash)
}
