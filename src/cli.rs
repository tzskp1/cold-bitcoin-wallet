use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub enum Target {
    Address,
    Key {
        #[clap(short = 'p', long = "path", required = true, ignore_case = true)]
        path: PathBuf,
    },
    Transaction {
        #[clap(short = 'p', long = "parameter", required = true, ignore_case = true)]
        parameter: (),
    },
}

#[derive(Debug, Subcommand)]
pub enum SubCommands {
    #[clap(arg_required_else_help = true)]
    Sign {
        #[clap(short = 'p', long = "parameter", required = true, ignore_case = true)]
        parameter: (),
    },
    #[clap(subcommand, arg_required_else_help = true)]
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
    #[clap(subcommand)]
    pub subcommand: SubCommands,
}
