// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
use super::bech32m::{self, Bech32m};
use crate::key::{Network, PublicKey};
use k256::elliptic_curve::{
    Curve, ops::Reduce, ops::ReduceNonZero, point::AffineCoordinates, sec1::ToEncodedPoint,
};
use k256::schnorr::{SigningKey, VerifyingKey};
use k256::{AffinePoint, NonZeroScalar, ProjectivePoint, Scalar, Secp256k1, U256};
use sha2::{Digest, Sha256};
use std::fmt::Display;
use std::ops::Deref;

pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(data);
    hasher.finalize().into()
}

pub fn tweak_pubkey(value: &VerifyingKey) -> ProjectivePoint {
    let generator = AffinePoint::GENERATOR;
    let public_point = value.as_affine();
    let public_x = value.to_bytes();
    let tweak = tagged_hash("TapTweak", &public_x);
    let tweak = U256::from_be_slice(&tweak);
    // TODO: make error
    let tweak: Scalar = Reduce::<U256>::reduce(tweak);
    ProjectivePoint::from(public_point) + (generator * tweak)
}

pub fn tweak_seckey(value: &SigningKey) -> SigningKey {
    let generator = AffinePoint::GENERATOR;
    let public_point = generator * value.as_nonzero_scalar().as_ref();
    let secret_key = if public_point.to_affine().y_is_odd().into() {
        &value.as_nonzero_scalar().negate()
    } else {
        value.as_nonzero_scalar()
    };
    let public_x = public_point.to_affine().x();
    let tweak = tagged_hash("TapTweak", &public_x);
    let tweak = U256::from_be_slice(&tweak);
    // if U256::new(tweak).ge(&Secp256k1::ORDER) {
    // }
    // TODO: make error
    let tweak: Scalar = Reduce::<U256>::reduce(tweak);
    let secret_key = NonZeroScalar::new(secret_key + tweak);
    match secret_key.into_option() {
        Some(secret_key) => SigningKey::from(secret_key),
        None => unimplemented!(),
    }
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

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
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
    pub fn to_address(&self, network: Network) -> Result<Address, AddressError> {
        let tweak_point = tweak_pubkey(self).to_encoded_point(false);
        let tweak_point_x = tweak_point.x().ok_or(AddressError::InvalidPoint)?;
        let address = bech32m::Bech32m::new_witver1(network.hrp(), tweak_point_x)
            .ok_or(AddressError::Bech32m)?;
        Ok(Address { inner: address })
    }
}

impl std::str::FromStr for Address {
    type Err = bech32m::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let inner = Bech32m::from_str(s)?;
        Ok(Self { inner })
    }
}

impl Address {
    pub fn script_pubkey(&self) -> Vec<u8> {
        let data = self.inner.data();
        let program = &data[1..];
        let mut script = Vec::with_capacity(34);
        script.push(0x51); // OP_1
        script.push(0x20); // push 32 bytes
        script.extend_from_slice(program);
        script
    }

    pub fn network(&self) -> Option<Network> {
        match self.inner.hrp() {
            "tb" => Some(Network::Testnet),
            "bc" => Some(Network::Mainnet),
            _ => None,
        }
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
            public_key.to_address(Network::Mainnet).unwrap().to_string(),
            "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5"
        );
    }
}
