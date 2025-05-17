mod cli;

use clap::Parser;
use cli::{SubCommands, Target};

fn main() {
    let cli = cli::Cli::parse();
    match cli.subcommand {
        SubCommands::Sign { parameter } => {
            dbg!("sign");
        }
        SubCommands::Generate(Target::Address) => {
            dbg!("gen add");
        }
        SubCommands::Generate(Target::Key) => {
            dbg!("gen key");
        }
    }
}
