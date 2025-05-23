use rand_core::CryptoRngCore;
use std::path::PathBuf;

use crate::address::{self, taproot};
use crate::key::{Network, vault, wallet};

#[derive(thiserror::Error, Debug)]
pub enum GenerateSeedError {
    #[error(transparent)]
    CreateVault(#[from] vault::CreateVaultError),
    #[error(transparent)]
    SaveSeed(#[from] vault::SaveSeedError),
    #[error("path:{0} already exists")]
    FileExist(PathBuf),
    #[error(transparent)]
    CreateDirectory(#[from] std::io::Error),
    #[error("cannot use root directory")]
    Root,
}

pub fn generate_seed(
    rng: &mut impl CryptoRngCore,
    path: impl Into<PathBuf>,
    passphrase: String,
) -> Result<(), GenerateSeedError> {
    let path: PathBuf = path.into();
    if path.exists() {
        return Err(GenerateSeedError::FileExist(path));
    }
    std::fs::create_dir_all(path.parent().ok_or(GenerateSeedError::Root)?)?;
    let mut seed = [0; 32];
    rng.fill_bytes(&mut seed);
    let vault = vault::Vault::new(path, rng)?;
    vault.save_seed(passphrase, &seed)?;
    Ok(())
}

#[derive(thiserror::Error, Debug)]
pub enum GenerateAddressError {
    #[error(transparent)]
    CreateVault(#[from] vault::CreateVaultError),
    #[error(transparent)]
    LoadSeed(#[from] vault::LoadSeedError),
    #[error("path:{0} does not exists")]
    FileNotExist(PathBuf),
    #[error(transparent)]
    CreateDirectory(#[from] std::io::Error),
    #[error(transparent)]
    ParsePath(#[from] wallet::ParsePathError),
    #[error(transparent)]
    GenerateMasterKey(#[from] wallet::GenerateMasterKeyError),
    #[error(transparent)]
    Address(#[from] address::taproot::AddressError),
}

pub fn generate_address(
    rng: &mut impl CryptoRngCore,
    seed_path: impl Into<PathBuf>,
    wallet_path: String,
    network: Network,
    passphrase: String,
) -> Result<taproot::Address, GenerateAddressError> {
    let seed_path: PathBuf = seed_path.into();
    if !seed_path.exists() {
        return Err(GenerateAddressError::FileNotExist(seed_path));
    }
    let vault = vault::Vault::new(seed_path, rng)?;
    let wallet_path = wallet::parse_path(&wallet_path)?;
    let seed = vault.load_seed(passphrase)?;
    let secret_key = wallet::derive_path(&seed, network, &wallet_path)?;
    let address = secret_key.to_public().to_address(network)?;
    Ok(address)
}
