use crate::key;
use clap::{Parser, Subcommand, ValueEnum};
use std::convert::From;
use std::path::PathBuf;

fn get_default_seed_path() -> String {
    let mut path = std::env::home_dir().unwrap();
    path.push(".config/cold-bitcoin-wallet/seed");
    path.into_os_string().into_string().unwrap()
}

#[derive(Debug, Clone, ValueEnum)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl From<Network> for key::Network {
    fn from(value: Network) -> Self {
        match value {
            Network::Mainnet => Self::Mainnet,
            Network::Testnet => Self::Testnet,
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum Target {
    /// Generate a Taproot address
    Address {
        /// derivation path of hd wallet
        #[arg(short, long, required = true, ignore_case = true)]
        wallet_path: String,
        /// Path of the file where the wallet seed is stored
        #[arg(short, long, ignore_case = true, default_value = get_default_seed_path())]
        seed_path: PathBuf,
        /// Select network (mainnet/testnet)
        #[arg(value_enum, short, long, ignore_case = true, default_value_t = Network::Mainnet)]
        network: Network,
        /// Print address only
        #[arg(short, long)]
        quiet: bool,
    },
    /// Generate the wallet seed
    Seed {
        /// Path of the file where the wallet seed is stored
        #[arg(short, long, ignore_case = true, default_value = get_default_seed_path())]
        seed_path: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum SubCommands {
    /// Assemble and sign the transaction
    #[command(arg_required_else_help = true)]
    Sign {
        /// Path to the JSON file describing the transaction parameters
        ///
        /// The JSON file specifies the destination address, remittance amount, etc.
        #[arg(short, long, required = true, ignore_case = true)]
        parameter_path: PathBuf,
        /// Path of the file where the wallet seed is stored
        #[arg(short, long, ignore_case = true, default_value = get_default_seed_path())]
        seed_path: PathBuf,
        /// Print transaction only
        #[arg(short, long)]
        quiet: bool,
    },
    #[command(subcommand, arg_required_else_help = true)]
    Generate(Target),
}

/// Bitcoin Transaction Generation CLI Tool
///
/// Allows you to create transactions and generate signed transactions.
#[derive(Debug, Parser)]
#[clap(
    name = env!("CARGO_PKG_NAME"),
    version = env!("CARGO_PKG_VERSION"),
    author = env!("CARGO_PKG_AUTHORS"),
    about = env!("CARGO_PKG_DESCRIPTION"),
    arg_required_else_help = true,
)]
pub struct Cli {
    #[command(subcommand)]
    pub subcommand: SubCommands,
}
