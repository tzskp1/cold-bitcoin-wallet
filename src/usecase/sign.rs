use crate::address::{bech32m, taproot};
use crate::key::{Network, vault, wallet};
use crate::transaction::{self, Transaction};
use hex::FromHexError;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
pub struct TransactionInput {
    pub txid: String,
    pub vout: u32,
    pub address: String,
    pub amount: u64,
}

#[derive(Serialize, Deserialize)]
pub struct TransactionOutput {
    pub address: String,
    pub amount: u64,
}

#[derive(Serialize, Deserialize)]
pub struct TransactionParam {
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
    pub private_key_paths: Vec<String>,
}

#[derive(thiserror::Error, Debug)]
pub enum TransactionInputConvertError {
    #[error(transparent)]
    Hex(#[from] FromHexError),
    #[error("mismatched length of array: {0}")]
    Size(usize),
}

impl TryFrom<TransactionInput> for transaction::TxIn {
    type Error = TransactionInputConvertError;

    fn try_from(value: TransactionInput) -> Result<Self, Self::Error> {
        let mut txid: [u8; 32] = hex::decode(value.txid)?
            .try_into()
            .map_err(|x: Vec<_>| TransactionInputConvertError::Size(x.len()))?;
        txid.reverse();
        Ok(Self {
            sequence: 0xFFFFFFFF,
            script_sig: Vec::new(),
            previous_output: transaction::OutPoint {
                txid,
                vout: value.vout,
            },
            witness: Vec::new(),
        })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum TransactionOutputConvertError {
    #[error(transparent)]
    Bech32m(#[from] bech32m::ParseError),
    #[error(transparent)]
    Address(#[from] taproot::AddressError),
}

impl TryFrom<TransactionOutput> for transaction::TxOut {
    type Error = TransactionOutputConvertError;

    fn try_from(value: TransactionOutput) -> Result<Self, Self::Error> {
        let addr: taproot::Address = value.address.parse()?;
        Ok(Self {
            value: value.amount,
            script_pubkey: addr.script_pubkey().ok_or(taproot::AddressError::Bech32m)?,
        })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum TransactionConvertError {
    #[error(transparent)]
    TransactionInputConvert(#[from] TransactionInputConvertError),
    #[error(transparent)]
    TransactionOutputConvert(#[from] TransactionOutputConvertError),
}

impl TryFrom<TransactionParam> for transaction::Transaction {
    type Error = TransactionConvertError;

    fn try_from(value: TransactionParam) -> Result<Self, Self::Error> {
        let inputs = value
            .inputs
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<_, _>>()?;
        let outputs = value
            .outputs
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<_, _>>()?;
        Ok(Self {
            version: 2,
            inputs,
            outputs,
            lock_time: 0,
        })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum SignTransactionError {
    #[error(transparent)]
    CreateVault(#[from] vault::CreateVaultError),
    #[error(transparent)]
    LoadSeed(#[from] vault::LoadSeedError),
    #[error("path:{0} does not exist")]
    FileNotExist(PathBuf),
    #[error(transparent)]
    OpenDirectory(#[from] std::io::Error),
    #[error(transparent)]
    ParsePath(#[from] wallet::ParsePathError),
    #[error(transparent)]
    GenerateMasterKey(#[from] wallet::GenerateMasterKeyError),
    #[error(transparent)]
    Address(#[from] taproot::AddressError),
    #[error("transaction has no txin")]
    EmptyInput,
    #[error(transparent)]
    AddressParse(#[from] bech32m::ParseError),
    #[error("only mainnet and testnet are supported")]
    InvalidNetwork,
    #[error(transparent)]
    TransactionConvert(#[from] TransactionConvertError),
    #[error(transparent)]
    Sign(#[from] transaction::SignError),
}

pub fn sign_transaction(
    rng: &mut impl CryptoRngCore,
    seed_path: impl Into<PathBuf>,
    parameter: TransactionParam,
    passphrase: String,
) -> Result<String, SignTransactionError> {
    let seed_path: PathBuf = seed_path.into();
    if !seed_path.exists() {
        return Err(SignTransactionError::FileNotExist(seed_path));
    }
    let private_key_paths = &parameter.private_key_paths;
    if parameter.inputs.is_empty() {
        return Err(SignTransactionError::EmptyInput);
    }
    let mut prevouts = Vec::with_capacity(parameter.inputs.len());
    let mut network = None;
    for input in &parameter.inputs {
        let addr: taproot::Address = input.address.parse()?;
        let addr_network = addr.network().ok_or(SignTransactionError::InvalidNetwork)?;
        if let Some(net) = network {
            match (net, addr_network) {
                (Network::Mainnet, Network::Mainnet) => {}
                (Network::Testnet, Network::Testnet) => {}
                _ => return Err(SignTransactionError::InvalidNetwork),
            }
        } else {
            network = Some(addr_network);
        }
        prevouts.push(transaction::TxOut {
            script_pubkey: addr.script_pubkey().ok_or(taproot::AddressError::Bech32m)?,
            value: input.amount,
        });
    }
    let network = network.unwrap();
    let vault = vault::Vault::new(seed_path, rng)?;
    let seed = vault.load_seed(passphrase)?;
    let secret_keys = private_key_paths
        .iter()
        .map(|path| {
            let path = wallet::parse_path(path)?;
            let secret_key = wallet::derive_path(&seed, network, &path)?;
            Ok(secret_key)
        })
        .collect::<Result<Vec<_>, SignTransactionError>>()?;
    let mut transaction: Transaction = parameter.try_into()?;
    transaction.sign_all_inputs(&prevouts, &secret_keys)?;
    Ok(hex::encode(transaction.encode()))
}
