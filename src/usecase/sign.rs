use crate::address::{bech32m, taproot};
use crate::key::vault::Passphrase;
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

fn validate_parameter_network(
    parameter: &TransactionParam,
) -> Result<Network, SignTransactionError> {
    let mut addrs = parameter
        .inputs
        .iter()
        .map(|input| &input.address)
        .chain(parameter.outputs.iter().map(|output| &output.address));
    let network = addrs
        .try_fold(None, |network, addr| {
            let addr: taproot::Address = addr.parse()?;
            let addr_network = addr.network().ok_or(SignTransactionError::InvalidNetwork)?;
            match network {
                None => Ok(Some(addr_network)),
                Some(network) if network == addr_network => Ok(Some(addr_network)),
                Some(_) => Err(SignTransactionError::InvalidNetwork),
            }
        })?
        .ok_or(SignTransactionError::EmptyInput)?;
    Ok(network)
}

pub fn sign_transaction(
    rng: &mut impl CryptoRngCore,
    seed_path: impl Into<PathBuf>,
    parameter: TransactionParam,
    passphrase: Passphrase,
) -> Result<String, SignTransactionError> {
    let seed_path: PathBuf = seed_path.into();
    if !seed_path.exists() {
        return Err(SignTransactionError::FileNotExist(seed_path));
    }
    let private_key_paths = &parameter.private_key_paths;
    if parameter.inputs.is_empty() {
        return Err(SignTransactionError::EmptyInput);
    }
    let prevouts = parameter
        .inputs
        .iter()
        .map(|input| {
            let addr: taproot::Address = input.address.parse()?;
            Ok(transaction::TxOut {
                script_pubkey: addr.script_pubkey().ok_or(taproot::AddressError::Bech32m)?,
                value: input.amount,
            })
        })
        .collect::<Result<Vec<_>, SignTransactionError>>()?;
    let network = validate_parameter_network(&parameter)?;
    let vault = vault::Vault::new(seed_path, rng)?;
    let seed = vault.load_seed(passphrase)?;
    let secret_keys = private_key_paths
        .iter()
        .map(|path| {
            let path = wallet::parse_path(path)?;
            let secret_key = wallet::derive_path(&*seed, network, &path)?;
            Ok(secret_key)
        })
        .collect::<Result<Vec<_>, SignTransactionError>>()?;
    let mut transaction: Transaction = parameter.try_into()?;
    transaction.sign_all_inputs(&prevouts, &secret_keys)?;
    Ok(hex::encode(transaction.encode()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[rstest::rstest]
    fn test_validate_parameter_network_same() {
        let parameter = TransactionParam {
            inputs: vec![TransactionInput {
                txid: String::new(),
                vout: 0,
                address: "tb1pqqj0xeagwy5fdcwg45tfamfx9nrcaz2d8h33qp03nksrudzrqm6syq3vzj"
                    .to_string(),
                amount: 0,
            }],
            outputs: vec![TransactionOutput {
                address: "tb1p5v6e4u94y3jp50h0mky78zxu3af49x98qr9cmrzqktyytjdn0x5qhw96f9"
                    .to_string(),
                amount: 0,
            }],
            private_key_paths: vec![],
        };
        assert_eq!(
            validate_parameter_network(&parameter).unwrap(),
            Network::Testnet
        );
    }

    #[rstest::rstest]
    fn test_validate_parameter_network_mismatch() {
        let parameter = TransactionParam {
            inputs: vec![TransactionInput {
                txid: String::new(),
                vout: 0,
                address: "tb1pqqj0xeagwy5fdcwg45tfamfx9nrcaz2d8h33qp03nksrudzrqm6syq3vzj"
                    .to_string(),
                amount: 0,
            }],
            outputs: vec![TransactionOutput {
                address: "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5"
                    .to_string(),
                amount: 0,
            }],
            private_key_paths: vec![],
        };
        assert!(matches!(
            validate_parameter_network(&parameter),
            Err(SignTransactionError::InvalidNetwork)
        ));
    }

    #[rstest::rstest]
    fn test_validate_parameter_network_empty() {
        let parameter = TransactionParam {
            inputs: vec![],
            outputs: vec![],
            private_key_paths: vec![],
        };
        assert!(matches!(
            validate_parameter_network(&parameter),
            Err(SignTransactionError::EmptyInput)
        ));
    }
}
