use clap::{Parser, Subcommand, ValueEnum};
use std::convert::From;
use std::path::PathBuf;

use crate::key;

#[allow(deprecated)]
fn get_default_seed_path() -> String {
    // Will no longer be deprecated in the near future
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
    Address {
        #[arg(short = 'w', long = "wallet_path", required = true, ignore_case = true)]
        wallet_path: String,
        #[arg(short = 's', long = "seed_path", ignore_case = true, default_value = get_default_seed_path())]
        seed_path: PathBuf,
        #[arg(value_enum, short = 'n', long = "network", ignore_case = true, default_value_t = Network::Mainnet)]
        network: Network,
    },
    Seed {
        #[arg(short = 'p', long = "path", ignore_case = true, default_value = get_default_seed_path())]
        path: PathBuf,
    },
    Key {
        #[arg(short = 'w', long = "wallet_path", required = true, ignore_case = true)]
        wallet_path: String,
        #[arg(short = 's', long = "seed_path", ignore_case = true, default_value = get_default_seed_path())]
        seed_path: PathBuf,
    },
    Transaction {
        #[arg(short = 'p', long = "parameter", required = true, ignore_case = true)]
        parameter: (),
    },
}

#[derive(Debug, Subcommand)]
pub enum SubCommands {
    #[command(arg_required_else_help = true)]
    Sign {
        #[arg(short = 'p', long = "parameter", required = true, ignore_case = true)]
        parameter: (),
    },
    #[command(subcommand, arg_required_else_help = true)]
    Generate(Target),
}

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
