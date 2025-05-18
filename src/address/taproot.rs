// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
use super::bech32m::{self, Bech32m};
use k256::elliptic_curve::{FieldBytes, ops::Reduce, sec1::ToEncodedPoint};
use k256::{AffinePoint, ProjectivePoint, Scalar, U256, schnorr::VerifyingKey};
use sha2::{Digest, Sha256};
use std::convert::TryFrom;
use std::ops::Deref;

fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(&tag_hash);
    hasher.update(&tag_hash);
    hasher.update(data);
    hasher.finalize().into()
}

fn tweak_pubkey(value: &VerifyingKey) -> ProjectivePoint {
    let generator = AffinePoint::GENERATOR;
    let public_point = value.as_affine();
    let public_x = value.to_bytes();
    let tweak = tagged_hash("TapTweak", &public_x);
    let tweak: Scalar = Reduce::<U256>::reduce_bytes(&FieldBytes::<k256::Secp256k1>::from(tweak));
    ProjectivePoint::from(public_point) + (generator * tweak)
}

#[derive(Clone)]
pub struct PublicKey {
    inner: VerifyingKey,
}

impl Deref for PublicKey {
    type Target = VerifyingKey;

    fn deref(&self) -> &Self::Target {
        &self.inner
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

impl TryFrom<PublicKey> for Address {
    type Error = ();

    fn try_from(value: PublicKey) -> Result<Self, Self::Error> {
        // TODO: remove unwrap
        let tweak_point = tweak_pubkey(&value.inner).to_encoded_point(false);
        let tweak_point_x = tweak_point.x().unwrap();
        // TODO: generalize bc & remove unwrap
        let address = bech32m::Bech32m::new_witver1("bc", tweak_point_x).unwrap();
        Ok(Address { inner: address })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_str_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[rstest::rstest]
    fn test_tweak_pubkey() {
        let public_key = "d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d";
        let public_key = hex_str_to_bytes(public_key);
        let public_key = VerifyingKey::from_bytes(&public_key).unwrap();
        let public_key = PublicKey { inner: public_key };
        let tweak_key = "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343";
        let tweak_key = hex_str_to_bytes(tweak_key);

        let result = tweak_pubkey(&public_key.inner).to_encoded_point(false);
        assert_eq!(**result.x().unwrap(), tweak_key);
        assert_eq!(
            Address::try_from(public_key).unwrap().to_string(),
            "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5"
        );
    }
}
