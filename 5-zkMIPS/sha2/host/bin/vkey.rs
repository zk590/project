use clap::Parser;
use zkm_sdk::{include_elf, ProverClient};

/// The ELF (executable and linkable format) file for the zkMIPS zkVM.
pub const SHA2_ELF: &[u8] = include_elf!("sha2");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    output: String,
}

fn main() {
    // Setup the logger.
    zkm_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    // Parse the command line arguments.
    let args = Args::parse();

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the program to get the verification key.
    let (_, vk) = client.setup(SHA2_ELF);

    // Write the verification key to the specified output file.
    let vk_json = serde_json::to_string(&vk).unwrap();
    std::fs::write(&args.output, vk_json).unwrap();

    println!("Verification key saved to {}", args.output);
}