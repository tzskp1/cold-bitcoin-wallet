// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
use super::types;
use super::types::Network;
use hmac::{Hmac, Mac};
use k256::elliptic_curve::Curve;
use k256::elliptic_curve::ops::Reduce;
use k256::{PublicKey, Scalar, Secp256k1, SecretKey, U256};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

// In view of implementation costs, base58 will not be implemented.

type HmacSha512 = Hmac<Sha512>;

const BITCOIN_SEED: &[u8] = b"Bitcoin seed";

#[derive(Clone, Copy)]
pub enum Index {
    Hardened(u32),
    NonHardened(u32),
}

impl Index {
    pub fn incr(&self) -> Self {
        match self {
            Index::Hardened(index) => Index::Hardened(index + 1),
            Index::NonHardened(index) => Index::NonHardened(index + 1),
        }
    }

    pub fn to_u32(self) -> u32 {
        match self {
            Index::Hardened(index) => index + 0x80000000,
            Index::NonHardened(index) => index,
        }
    }

    pub fn from_u32(index: u32) -> Self {
        if index >= 0x80000000 {
            Index::Hardened(index)
        } else {
            Index::NonHardened(index)
        }
    }
}

pub enum KeyType {
    Secret(SecretKey),
    Public(PublicKey),
}

pub struct Key {
    network: Network,
    parent_fingerprint: [u8; 4],
    child_number: Option<Index>,
    depth: u8,
    key: KeyType,
    chain_code: [u8; 32],
}

impl Drop for Key {
    fn drop(&mut self) {
        self.chain_code.zeroize();
    }
}

#[derive(thiserror::Error, Debug)]
pub enum GenerateMasterKeyError {
    #[error("failed to create secret key")]
    SecretKey(k256::elliptic_curve::Error),
}

impl Key {
    pub fn generate_master(seed: &[u8], network: Network) -> Result<Self, GenerateMasterKeyError> {
        // SAFETY: No error because of fixed length
        let mut mac = HmacSha512::new_from_slice(BITCOIN_SEED).unwrap();
        mac.update(seed);
        let mac = mac.finalize().into_bytes();
        let secret_key =
            SecretKey::from_slice(&mac[..32]).map_err(GenerateMasterKeyError::SecretKey)?;
        Ok(Self {
            network,
            parent_fingerprint: [0; 4],
            child_number: None,
            depth: 0,
            key: KeyType::Secret(secret_key),
            chain_code: mac[32..].try_into().unwrap(),
        })
    }

    pub fn to_public(&self) -> Option<Self> {
        let public_key = match &self.key {
            KeyType::Secret(secret_key) => secret_key.public_key(),
            KeyType::Public(_) => return None,
        };
        Some(Self {
            parent_fingerprint: self.parent_fingerprint,
            network: self.network,
            child_number: self.child_number,
            depth: self.depth,
            key: KeyType::Public(public_key),
            chain_code: self.chain_code,
        })
    }

    pub fn fingerprint(&self) -> [u8; 4] {
        let public_key = match &self.key {
            KeyType::Secret(secret_key) => secret_key.public_key().to_sec1_bytes(),
            KeyType::Public(public_key) => public_key.to_sec1_bytes(),
        };
        let sha256 = Sha256::digest(&public_key);
        let ripemd160 = Ripemd160::digest(sha256);
        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&ripemd160[..4]);
        fingerprint
    }

    pub fn derive(&self, index: Index) -> Option<Key> {
        let mut mac = HmacSha512::new_from_slice(&self.chain_code).unwrap();
        let secret_key = match &self.key {
            KeyType::Secret(secret_key) => secret_key,
            KeyType::Public(_) => return None,
        };
        let _index = match index {
            Index::Hardened(index) => {
                mac.update(&[0]);
                mac.update(&secret_key.to_bytes());
                mac.update(&(index + 0x80000000).to_be_bytes());
                index
            }
            Index::NonHardened(index) => {
                mac.update(&secret_key.public_key().to_sec1_bytes());
                mac.update(&index.to_be_bytes());
                index
            }
        };
        let mac = mac.finalize().into_bytes();
        let s = U256::from_be_slice(&mac[..32]);
        if s.ge(&Secp256k1::ORDER) {
            return self.derive(index.incr());
        }
        let s: Scalar = Reduce::<U256>::reduce(s);
        let secret_key = secret_key.to_nonzero_scalar().add(&s);
        let secret_key = SecretKey::from_bytes(&secret_key.to_bytes());
        match secret_key {
            Ok(secret_key) => Some(Self {
                parent_fingerprint: self.fingerprint(),
                network: self.network,
                child_number: Some(index),
                depth: self.depth + 1,
                key: KeyType::Secret(secret_key),
                chain_code: mac[32..].try_into().unwrap(),
            }),
            Err(_) => self.derive(index.incr()),
        }
    }

    pub fn derive_path(
        seed: &[u8],
        network: Network,
        path: &[Index],
    ) -> Result<Self, GenerateMasterKeyError> {
        let key = Self::generate_master(seed, network)?;
        // SAFETY: It will always be a private key, so no error will occur.
        Ok(path
            .iter()
            .fold(key, |key, index| key.derive(*index).unwrap()))
    }

    pub fn to_bytes(&self) -> [u8; 78] {
        let mut result = [0; 78];
        let version = match (self.network, &self.key) {
            (Network::Mainnet, KeyType::Public(_)) => [0x04, 0x88, 0xB2, 0x1E],
            (Network::Mainnet, KeyType::Secret(_)) => [0x04, 0x88, 0xAD, 0xE4],
            (Network::Testnet, KeyType::Public(_)) => [0x04, 0x35, 0x87, 0xCF],
            (Network::Testnet, KeyType::Secret(_)) => [0x04, 0x35, 0x83, 0x94],
        };
        result[0..4].copy_from_slice(&version);
        result[4] = self.depth;
        if self.depth != 0 {
            result[5..9].copy_from_slice(&self.parent_fingerprint);
        }
        result[9..13].copy_from_slice(
            &self
                .child_number
                .map(|i| i.to_u32())
                .unwrap_or(0)
                .to_be_bytes(),
        );
        result[13..45].copy_from_slice(&self.chain_code);
        match &self.key {
            KeyType::Public(public_key) => {
                result[45..78].copy_from_slice(&public_key.to_sec1_bytes())
            }
            KeyType::Secret(secret_key) => result[46..78].copy_from_slice(&secret_key.to_bytes()),
        }
        result
    }

    // TODO: use Result
    pub fn from_bytes(array: [u8; 78]) -> Option<Self> {
        let (network, key) = match array[0..4] {
            [0x04, 0x88, 0xB2, 0x1E] => (
                Network::Mainnet,
                KeyType::Public(PublicKey::from_sec1_bytes(&array[45..78]).ok()?),
            ),
            [0x04, 0x88, 0xAD, 0xE4] => (
                Network::Mainnet,
                KeyType::Secret(SecretKey::from_slice(&array[46..78]).ok()?),
            ),
            [0x04, 0x35, 0x87, 0xCF] => (
                Network::Testnet,
                KeyType::Public(PublicKey::from_sec1_bytes(&array[45..78]).ok()?),
            ),
            [0x04, 0x35, 0x83, 0x94] => (
                Network::Testnet,
                KeyType::Secret(SecretKey::from_slice(&array[46..78]).ok()?),
            ),
            _ => return None,
        };
        let depth = array[4];
        Some(Self {
            parent_fingerprint: array[5..9].try_into().ok()?,
            key,
            network,
            depth,
            child_number: if depth == 0 {
                None
            } else {
                Some(Index::from_u32(u32::from_be_bytes(
                    array[9..13].try_into().ok()?,
                )))
            },
            chain_code: array[13..45].try_into().ok()?,
        })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ParsePathError {
    #[error("invalid characters at {positions:?}")]
    InvalidChar { positions: Vec<usize> },
    #[error("path must begin with m")]
    InvalidPrefix,
}

pub fn parse_path(s: &str) -> Result<Vec<Index>, ParsePathError> {
    let mut errs = Vec::new();
    let path = s
        .strip_prefix("m")
        .ok_or(ParsePathError::InvalidPrefix)?
        .split('/')
        .filter(|c| !c.is_empty())
        .map(|code| {
            if let Some(code) = code.strip_suffix('\'') {
                code.parse().ok().map(Index::Hardened)
            } else {
                code.parse().ok().map(Index::NonHardened)
            }
        })
        .enumerate()
        .scan(&mut errs, |errs, (pos, index)| {
            if index.is_none() {
                errs.push(pos);
            }
            Some(index)
        })
        .flatten()
        .collect();
    if errs.is_empty() {
        Ok(path)
    } else {
        Err(ParsePathError::InvalidChar { positions: errs })
    }
}

pub fn derive_path(
    seed: &[u8],
    network: Network,
    path: &[Index],
) -> Result<types::SecretKey, GenerateMasterKeyError> {
    let key = Key::derive_path(seed, network, path)?;
    // SAFETY: It will always be a private key, so no error will occur.
    match &key.key {
        KeyType::Secret(key) => Ok(types::SecretKey::new(key.into())),
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[rstest::rstest]
    #[case(
        "000102030405060708090a0b0c0d0e0f",
        "m",
        Network::Mainnet,
        "0488b21e000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d5080339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
        "0488ade4000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d50800e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
    )]
    #[case(
        "000102030405060708090a0b0c0d0e0f",
        "m/0'",
        Network::Mainnet,
        "0488b21e013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56",
        "0488ade4013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae623614100edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
    )]
    #[case(
        "000102030405060708090a0b0c0d0e0f",
        "m/0'/1/2'/2/1000000000",
        Network::Mainnet,
        "0488b21e05d880d7d83b9aca00c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011",
        "0488ade405d880d7d83b9aca00c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e00471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8"
    )]
    fn test_derive(
        #[case] seed: &str,
        #[case] path: &str,
        #[case] network: Network,
        #[case] public_key: &str,
        #[case] secret_key: &str,
    ) {
        let path = parse_path(path).unwrap();
        let seed = hex::decode(seed).unwrap();
        let expected_public_key = hex::decode(public_key).unwrap();
        let expected_secret_key = hex::decode(secret_key).unwrap();
        let secret_key = Key::derive_path(&seed, network, &path).unwrap();

        assert_eq!(secret_key.to_bytes().to_vec(), expected_secret_key);
        assert_eq!(
            secret_key.to_public().unwrap().to_bytes().to_vec(),
            expected_public_key
        );
    }

    #[rstest::rstest]
    fn test_encode_decode_roundtrip() {
        let seed = [0, 1];
        let secret_key = Key::generate_master(&seed, Network::Testnet)
            .unwrap()
            .to_bytes();
        assert_eq!(secret_key, Key::from_bytes(secret_key).unwrap().to_bytes());
    }
}
