mod address;
mod cli;
mod key;
mod transaction;
mod usecase;

use clap::Parser;
use cli::{SubCommands, Target};
use rand_core::OsRng;
use std::fs::File;
use std::io::{BufReader, Write, stdin, stdout};

fn read_passphrase(quiet: bool) -> std::io::Result<key::vault::Passphrase> {
    let mut out = stdout();
    if !quiet {
        print!("Enter Passphrase: ");
    }
    out.flush()?;
    let mut input = String::new();
    stdin().read_line(&mut input)?;
    let input = input.trim_end().to_string();
    Ok(key::vault::Passphrase::new(input))
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = cli::Cli::parse();

    match cli.subcommand {
        SubCommands::Sign {
            parameter_path,
            seed_path,
            quiet,
        } => {
            let pass = read_passphrase(quiet)?;
            let file = File::open(&parameter_path)?;
            let reader = BufReader::new(file);
            let parameter = serde_json::from_reader(reader)?;
            let transaction =
                usecase::sign::sign_transaction(&mut OsRng, seed_path, parameter, pass)?;
            if quiet {
                println!("{}", transaction);
            } else {
                println!("Transaction: {}", transaction);
            }
        }
        SubCommands::Generate(Target::Address {
            wallet_path,
            seed_path,
            network,
            quiet,
        }) => {
            let pass = read_passphrase(quiet)?;
            let address = usecase::generate::generate_address(
                &mut OsRng,
                seed_path,
                wallet_path,
                network.into(),
                pass,
            )?;
            if quiet {
                println!("{}", address);
            } else {
                println!("Address: {}", address);
            }
        }
        SubCommands::Generate(Target::Seed { seed_path }) => {
            let pass = read_passphrase(false)?;
            usecase::generate::generate_seed(&mut OsRng, seed_path, pass)?;
        }
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
    }
}
