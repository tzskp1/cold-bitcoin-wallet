use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;
use zeroize::Zeroize;

#[derive(Serialize, Deserialize)]
pub struct SeedFormat {
    salt: String,
    nonce: String,
    seed: String,
}

pub struct Vault {
    file_path: PathBuf,
    nonce: [u8; 12],
    salt: SaltString,
}

#[derive(thiserror::Error, Debug)]
pub enum CreateVaultError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("nonce decoding error")]
    Nonce,
    #[error("argon2 error")]
    Argon2(argon2::password_hash::errors::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum SaveSeedError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error("derive key error")]
    DeriveKey,
    #[error("aes error")]
    Aes(aes_gcm::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum LoadSeedError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error("derive key error")]
    DeriveKey,
    #[error("aes error")]
    Aes(aes_gcm::Error),
}

impl Vault {
    pub fn new(
        file_path: impl Into<PathBuf>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self, CreateVaultError> {
        let file_path = file_path.into();
        match File::open(&file_path) {
            Ok(file) => {
                let reader = BufReader::new(file);
                let key: SeedFormat = serde_json::from_reader(reader)?;
                let nonce = hex::decode(&key.nonce)
                    .ok()
                    .and_then(|x| x.try_into().ok())
                    .ok_or(CreateVaultError::Nonce)?;
                let salt = SaltString::from_b64(&key.salt).map_err(CreateVaultError::Argon2)?;
                Ok(Self {
                    nonce,
                    file_path,
                    salt,
                })
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut nonce = [0; 12];
                rng.fill_bytes(&mut nonce);
                Ok(Self {
                    nonce,
                    file_path,
                    salt: SaltString::generate(rng),
                })
            }
            Err(e) => Err(e)?,
        }
    }

    fn derive_key(&self, mut passphrase: String) -> Option<[u8; 32]> {
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(passphrase.as_bytes(), &self.salt)
            .ok()?;
        let key = password_hash.hash?;
        let mut derived_key = [0u8; 32];
        derived_key.copy_from_slice(key.as_bytes());
        passphrase.zeroize();
        Some(derived_key)
    }

    pub fn save_seed(&self, passphrase: String, seed: &[u8]) -> Result<(), SaveSeedError> {
        let mut key = self
            .derive_key(passphrase)
            .ok_or(SaveSeedError::DeriveKey)?;
        let cipher = Aes256Gcm::new(&key.into());
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&self.nonce), seed)
            .map_err(SaveSeedError::Aes)?;
        let ciphertext = hex::encode(&ciphertext);
        let file = File::create(&self.file_path)?;
        let writer = BufWriter::new(file);
        let key_format = SeedFormat {
            salt: self.salt.as_str().to_string(),
            nonce: hex::encode(self.nonce),
            seed: ciphertext,
        };
        key.zeroize();
        serde_json::to_writer_pretty(writer, &key_format)?;
        Ok(())
    }

    pub fn load_seed(&self, passphrase: String) -> Result<Vec<u8>, LoadSeedError> {
        let mut key = self
            .derive_key(passphrase)
            .ok_or(LoadSeedError::DeriveKey)?;
        let cipher = Aes256Gcm::new(&key.into());
        let file = File::open(&self.file_path)?;
        let reader = BufReader::new(file);
        let key_format: SeedFormat = serde_json::from_reader(reader)?;
        let ciphertext = hex::decode(&key_format.seed)?;
        let seed = cipher
            .decrypt(Nonce::from_slice(&self.nonce), ciphertext.as_slice())
            .map_err(LoadSeedError::Aes)?;
        key.zeroize();
        Ok(seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use rand::rngs::OsRng;

    #[cfg(unix)]
    #[rstest::rstest]
    fn test_save_load() {
        let seed = [0, 1];
        let mut rng = OsRng;
        let mut path = std::env::temp_dir();
        path.push(format!("test-vector-seed-{}", rng.next_u64()));
        let vault = Vault::new(&path, &mut rng).unwrap();
        let pass = "this is a pen";
        vault.save_seed(pass.to_string(), &seed).unwrap();
        let loaded = vault.load_seed(pass.to_string()).unwrap();

        assert_eq!(loaded, seed);

        std::fs::remove_file(path).unwrap();
    }
}
