use k256::elliptic_curve::bigint::ArrayEncoding;
use k256::elliptic_curve::{Curve, ops::Reduce, point::AffineCoordinates};
use k256::schnorr::signature::hazmat::PrehashSigner;
use k256::schnorr::{SigningKey, VerifyingKey};
use k256::{AffinePoint, NonZeroScalar, ProjectivePoint, Scalar, Secp256k1, U256};
use sha2::{Digest, Sha256};
use std::ops::Deref;

pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(data);
    hasher.finalize().into()
}

#[derive(Clone, Copy, Debug)]
pub enum Network {
    Mainnet,
    Testnet,
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct PublicKey {
    inner: VerifyingKey,
    negated: bool,
}

impl PublicKey {
    pub fn new(inner: VerifyingKey) -> Self {
        Self {
            inner,
            negated: false,
        }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes().into()
    }

    #[allow(dead_code)]
    pub fn is_negated(&self) -> bool {
        self.negated
    }

    pub fn tweak(&self) -> Option<Self> {
        let generator = AffinePoint::GENERATOR;
        let public_point = self.inner.as_affine();
        let public_x = self.inner.to_bytes();
        let tweak = tagged_hash("TapTweak", &public_x);
        let tweak = U256::from_be_slice(&tweak);
        if tweak.ge(&Secp256k1::ORDER) {
            return None;
        }
        let tweak: Scalar = Reduce::<U256>::reduce(tweak);
        let tweaked_point = ProjectivePoint::from(public_point) + (generator * tweak);
        let negated = tweaked_point.to_affine().y_is_odd().into();
        let tweaked_point = if negated {
            -tweaked_point
        } else {
            tweaked_point
        };
        let tweaked_public = k256::PublicKey::from_affine(tweaked_point.to_affine()).ok()?;
        let tweaked_public = VerifyingKey::try_from(tweaked_public).ok()?;
        Some(Self {
            inner: tweaked_public,
            negated,
        })
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

    pub fn to_public(&self) -> PublicKey {
        PublicKey::new(*self.inner.verifying_key())
    }

    pub fn sign(&self, msg: &[u8; 32]) -> Option<[u8; 64]> {
        let sig = self.inner.sign_prehash(msg).ok()?;
        Some(sig.to_bytes())
    }

    pub fn tweak(&self) -> Option<Self> {
        let generator = AffinePoint::GENERATOR;
        let public_point = generator * self.inner.as_nonzero_scalar().as_ref();
        let secret_key = if public_point.to_affine().y_is_odd().into() {
            &self.inner.as_nonzero_scalar().negate()
        } else {
            self.inner.as_nonzero_scalar()
        };
        let public_x = public_point.to_affine().x();
        let tweak = tagged_hash("TapTweak", &public_x);
        let tweak = U256::from_be_byte_array(tweak.into());
        if tweak.ge(&Secp256k1::ORDER) {
            return None;
        }
        let tweak: Scalar = Reduce::<U256>::reduce(tweak);
        let secret_key = NonZeroScalar::new(secret_key + tweak);
        secret_key
            .into_option()
            .map(|secret_key| Self::new(SigningKey::from(secret_key)))
    }
}
