#![allow(non_snake_case)]

/*
Tool to write public keys from raw blocks
for curve tree construction.
 */

use blocks_iterator::PeriodCounter;
use env_logger::Env;
use blocks_iterator::log::info;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use itertools::Itertools;
use std::time::Duration;
//use structopt::StructOpt;

fn main() -> Result<(), Box<dyn Error>> {
    // TODO this tool is derived from
    // https://github.com/RCasatta/blocks_iterator/blob/b421617cba76a6a5c119fa5733c6c8181b2c7483/examples/outputs_versions.rs
    // as a starting point.
    // The command line handling has been ignored for now,
    // we will add this (and possibly options in the config file)
    // for filenames, blocks file source, and probably output encodings.
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    info!("start");
    let mut period = PeriodCounter::new(Duration::from_secs(10));

    //let mut config = Config::from_args();
    let mut config = blocks_iterator::Config::new(
        "/home/username/.bitcoin/blocks", bitcoin::Network::Bitcoin);
    config.skip_prevout = true;
    let iter = blocks_iterator::iter(config);
    let mut output_file = File::create("keysfound.txt").unwrap();
    let mut v: Vec<String> = Vec::new();
    for block_extra in iter {
        if period.period_elapsed().is_some() {
            info!(
                "# {:7} {}",
                block_extra.height, block_extra.block_hash
            );
        }

        if block_extra.height == 481824 {
            info!("segwit locked in");
        }
        if block_extra.height == 687456 {
            info!("taproot locked in");
        }
        for (_txid, tx) in block_extra.iter_tx() {
            for (_i, output) in tx.output.iter().enumerate() {
                if output.script_pubkey.is_witness_program() && output.value > 500000u64 {
                    //println!("Found an output with value: {}", output.value);
                    let version = output.script_pubkey.as_bytes()[0] as usize;
                    if version == 0x51 {
                        // lose version byte and also leading 0x20 (length)
                        let buf1 = &output.script_pubkey.as_bytes()[2..];
                        let towrite = hex::encode(buf1);
                        v.push(towrite);
                    }
                }
            }
        }
    }
    let fullstr = v.into_iter().unique().join(" ");
    write!(output_file, "{}", fullstr).expect("Failed to write keys to file.");
    Ok(())
}
