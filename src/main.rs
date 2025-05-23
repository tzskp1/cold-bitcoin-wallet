mod address;
mod cli;
mod key;
mod usecase;

use clap::Parser;
use cli::{SubCommands, Target};
use rand_core::OsRng;
use std::io::{Write, stdin, stdout};

fn read_passphrase() -> std::io::Result<String> {
    let mut out = stdout();
    print!("Enter Passphrase: ");
    out.flush()?;
    let mut input = String::new();
    stdin().read_line(&mut input)?;
    Ok(input)
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = cli::Cli::parse();

    match cli.subcommand {
        SubCommands::Sign { parameter } => {
            dbg!("sign");
        }
        SubCommands::Generate(Target::Address {
            wallet_path,
            seed_path,
            network,
        }) => {
            let pass = read_passphrase()?;
            let address = usecase::generate::generate_address(
                &mut OsRng,
                seed_path,
                wallet_path,
                network.into(),
                pass,
            )?;
            println!("Address: {}", address);
        }
        SubCommands::Generate(Target::Seed { path }) => {
            let pass = read_passphrase()?;
            usecase::generate::generate_seed(&mut OsRng, path, pass)?;
        }
        SubCommands::Generate(Target::Key {
            wallet_path,
            seed_path,
        }) => {
            let path = key::wallet::parse_path(&wallet_path)?;
        }
        SubCommands::Generate(_) => {
            dbg!("gen key");
        }
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
    }
}
