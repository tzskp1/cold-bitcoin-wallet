// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
use super::bech32m::{self, Bech32m};
use crate::key::{Network, PublicKey};
use std::fmt::Display;
use std::ops::Deref;

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
    #[error("invalid bech32m address format")]
    Bech32m,
}

impl PublicKey {
    pub fn to_address(&self, network: Network) -> Result<Address, AddressError> {
        let tweaked_point = self.tweak().ok_or(AddressError::InvalidPoint)?;
        let address = bech32m::Bech32m::new_witver1(network.hrp(), &tweaked_point.to_bytes())
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
    pub fn script_pubkey(&self) -> Option<Vec<u8>> {
        let data = self.inner.data(true)?;
        let mut script = Vec::with_capacity(34);
        script.push(0x51); // OP_1
        script.push(0x20); // push 32 bytes
        script.extend_from_slice(&data);
        Some(script)
    }

    pub fn network(&self) -> Option<Network> {
        match self.inner.hrp() {
            "tb" => Some(Network::Testnet),
            "bc" => Some(Network::Mainnet),
            _ => None,
        }
    }
}
