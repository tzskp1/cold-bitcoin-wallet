// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
use super::bech32m::{self, Bech32m};
use crate::key::PublicKey;
use k256::elliptic_curve::{ops::Reduce, sec1::ToEncodedPoint};
use k256::{AffinePoint, ProjectivePoint, Scalar, U256, schnorr::VerifyingKey};
use sha2::{Digest, Sha256};
use std::ops::Deref;

fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(data);
    hasher.finalize().into()
}

fn tweak_pubkey(value: &VerifyingKey) -> ProjectivePoint {
    let generator = AffinePoint::GENERATOR;
    let public_point = value.as_affine();
    let public_x = value.to_bytes();
    let tweak = tagged_hash("TapTweak", &public_x);
    let tweak: Scalar = Reduce::<U256>::reduce(U256::from_be_slice(&tweak));
    ProjectivePoint::from(public_point) + (generator * tweak)
}

#[derive(Clone)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    pub fn hrp(&self) -> &str {
        match self {
            Self::Mainnet => "bc",
            Self::Testnet => "tb",
        }
    }
}

pub struct Address {
    inner: Bech32m,
}

impl Deref for Address {
    type Target = Bech32m;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[derive(thiserror::Error, Debug)]
pub enum AddressError {
    #[error("point of public key is invalid")]
    InvalidPoint,
    #[error("failed to create bech32m address")]
    Bech32m,
}

impl PublicKey {
    pub fn to_address(&self, network: &Network) -> Result<Address, AddressError> {
        let tweak_point = tweak_pubkey(&self).to_encoded_point(false);
        let tweak_point_x = tweak_point.x().ok_or(AddressError::InvalidPoint)?;
        let address = bech32m::Bech32m::new_witver1(network.hrp(), tweak_point_x)
            .ok_or(AddressError::Bech32m)?;
        Ok(Address { inner: address })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[rstest::rstest]
    fn test_tweak_pubkey() {
        let public_key =
            hex::decode("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d")
                .unwrap();
        let public_key = VerifyingKey::from_bytes(&public_key).unwrap();
        let public_key = PublicKey::new(public_key);
        let tweak_key =
            hex::decode("53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343")
                .unwrap();

        let result = tweak_pubkey(&public_key).to_encoded_point(false);
        assert_eq!(**result.x().unwrap(), tweak_key);
        assert_eq!(
            public_key
                .to_address(&Network::Mainnet)
                .unwrap()
                .to_string(),
            "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5"
        );
    }
}
