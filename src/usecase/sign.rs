use crate::address::{self, bech32m, taproot};
use crate::key::{vault, wallet};
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
    #[error("miss match length of array: {0}")]
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

impl TryFrom<TransactionOutput> for transaction::TxOut {
    type Error = bech32m::ParseError;

    fn try_from(value: TransactionOutput) -> Result<Self, Self::Error> {
        let addr: taproot::Address = value.address.parse()?;
        Ok(Self {
            value: value.amount,
            script_pubkey: addr.script_pubkey(),
        })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum TransactionConvertError {
    #[error(transparent)]
    TransactionInputConvert(#[from] TransactionInputConvertError),
    #[error(transparent)]
    TransactionOutputConvert(#[from] bech32m::ParseError),
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
    #[error("path:{0} does not exists")]
    FileNotExist(PathBuf),
    #[error(transparent)]
    OpenDirectory(#[from] std::io::Error),
    #[error(transparent)]
    ParsePath(#[from] wallet::ParsePathError),
    #[error(transparent)]
    GenerateMasterKey(#[from] wallet::GenerateMasterKeyError),
    #[error(transparent)]
    Address(#[from] taproot::AddressError),
    #[error("transaction have no txin")]
    EmptyInput,
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
    // TODO: remove unwrap
    let prevouts: Vec<_> = parameter
        .inputs
        .iter()
        .map(|input| {
            let addr: taproot::Address = input.address.parse().unwrap();
            transaction::TxOut {
                script_pubkey: addr.script_pubkey(),
                value: input.amount,
            }
        })
        .collect();
    let vault = vault::Vault::new(seed_path, rng)?;
    let seed = vault.load_seed(passphrase)?;
    let first_addr: taproot::Address = parameter
        .inputs
        .first()
        .ok_or(SignTransactionError::EmptyInput)?
        .address
        .parse()
        .unwrap();
    let network = first_addr.network().unwrap();
    let secret_keys = private_key_paths
        .into_iter()
        .map(|path| {
            let path = wallet::parse_path(&path)?;
            let secret_key = wallet::derive_path(&seed, network, &path)?;
            Ok(secret_key)
        })
        .collect::<Result<Vec<_>, SignTransactionError>>()?;
    let mut transaction: Transaction = parameter.try_into().unwrap();
    transaction
        .sign_all_inputs(&prevouts, &secret_keys)
        .unwrap();
    Ok(hex::encode(&transaction.encode()))
}
