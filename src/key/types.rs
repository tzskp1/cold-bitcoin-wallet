use k256::elliptic_curve::rand_core::CryptoRngCore;
use k256::schnorr::{SigningKey, VerifyingKey};
use std::ops::Deref;

#[derive(Clone)]
pub struct PublicKey {
    inner: VerifyingKey,
}

impl PublicKey {
    pub fn new(inner: VerifyingKey) -> Self {
        Self { inner }
    }

    pub fn from_hex(value: &str) -> Option<Self> {
        let inner = hex::decode(value).ok()?;
        let inner = VerifyingKey::from_bytes(&inner).ok()?;
        Some(Self { inner })
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes().into()
    }
}

impl Deref for PublicKey {
    type Target = VerifyingKey;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub struct SecretKey {
    inner: SigningKey,
}

impl SecretKey {
    pub fn new(inner: SigningKey) -> Self {
        Self { inner }
    }

    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self {
            inner: SigningKey::random(rng),
        }
    }

    pub fn to_public(&self) -> PublicKey {
        PublicKey {
            inner: self.inner.verifying_key().clone(),
        }
    }
}
