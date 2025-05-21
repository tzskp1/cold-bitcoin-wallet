mod address;
mod cli;
mod key;

use clap::Parser;
use cli::{SubCommands, Target};

fn main() {
    let cli = cli::Cli::parse();
    match cli.subcommand {
        SubCommands::Sign { parameter } => {
            dbg!("sign");
        }
        SubCommands::Generate(Target::Address) => {
            // address::taproot::Address
        }
        SubCommands::Generate(Target::Key { path }) => {
            dbg!("gen key");
        }
        SubCommands::Generate(_) => {
            dbg!("gen key");
        }
    }
}
