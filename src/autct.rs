#![allow(non_snake_case)]

extern crate rand;
extern crate alloc;
extern crate ark_secp256k1;
use autct::rpcclient;
use autct::rpcserver;
use autct::config::AutctConfig;
use bitcoin::{Address, PrivateKey, XOnlyPublicKey};
use bitcoin::key::Secp256k1;


use std::error::Error;


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>>{
    let autctcfg = AutctConfig::build()?;
    match autctcfg.clone().mode.unwrap().as_str() {
        "prove" => {return request_prove(autctcfg).await
                    },
        "verify" => {return request_verify(autctcfg).await},
        "serve" => {return rpcserver::do_serve(autctcfg).await
                    },
        "newkeys" => {return create_keys(autctcfg).await},
        _ => {return Err("Invalid mode, must be 'prove', 'serve', 'newkeys' or 'verify'".into())},

    }
}

async fn create_keys(autctcfg: AutctConfig) ->Result<(), Box<dyn Error>> {

    let nw = match autctcfg.bc_network.unwrap().as_str() {
        "mainnet" => bitcoin::Network::Bitcoin,
        "signet" => bitcoin::Network::Signet,
        "regtest" => bitcoin::Network::Regtest,
       _ => return Err("Invalid bitcoin network string in config.".into()),
    };

    // This uses the `rand-std` feature in the rust-bitcoin crate to generate
    // the random number via libsecp256k1 in the recommended secure way:
    let privkey = PrivateKey::generate(nw);
    let secp = Secp256k1::new();
    // this is the standard way to generate plain-vanilla taproot addresses:
    // it is not "raw" (rawtr in descriptors) but it applies a merkle root of
    // null as the tweak to the internal pubkey. This is what e.g. Sparrow is
    // looking for as "p2tr" type.
    let addr = Address::p2tr(&secp,
         XOnlyPublicKey::from(privkey.public_key(&secp).inner),
          None, privkey.network);
    println!("This is the address to pay into: {}", addr);
    // print this to the file configured in --privkey file, but error/warn if already exists
    println!("This is the private key in WIF format: {}", privkey);
    println!("The WIF string above can be imported into e.g. Sparrow, Core to sweep or access the funds in it.");
    Ok(())
}
async fn request_verify(autctcfg: AutctConfig) -> Result<(), Box<dyn Error>> {
    let res = rpcclient::verify(autctcfg).await;
    match res {
        Ok(rest) => {
        // codes defined in lib.rs
        // TODO: create some callback structure to receive the resource
            match rest.accepted {
                // deliberately verbose message here to help testers understand:
                1 => println!("Request was accepted by the Autct verifier! The proof is valid and the (unknown) pubkey is unused."),
                -1 => println!("Request rejected, PedDLEQ proof does not match the tree."),
                -2 => println!("Request rejected, PedDLEQ proof is invalid."),
                -3 => println!("Request rejected, proofs are valid but key image is reused."),
                -4 => println!("Request rejected, keyset chosen does not match the server's."),
                _ => println!("Unrecognized error code from server?"),
            }
        },
        Err(_) => return Err("Verificatoin request processing failed.".into()),
    };
    Ok(())
}

async fn request_prove(autctcfg: AutctConfig) -> Result<(), Box<dyn Error>>{
    let res = rpcclient::prove(autctcfg).await;
    match res {
        Ok(rest) => {
        // codes defined in lib.rs
        // TODO: create some callback structure to receive the resource
            match rest.accepted {
                // deliberately verbose message here to help testers understand:
                0 => println!("Proof generated successfully."),
                -1 => println!("Undefined failure in proving."),
                -2 => println!("Proving request rejected, must be only one context:keyset provided."),
                -3 => println!("Proving request rejected, provided context label is not served."),
                -4 => println!("Proving request rejected, provided keyset is not served."),
                -5 => println!("Proving request rejected, wrong bitcoin network."),
                -6 => println!("Proving request rejected, could not read private key from file."),
                -7 => println!("Proving request rejected, invalid private key format (must be WIF or hex)."),
                -8 => println!("Proving request rejected, provided key is not in the keyset"),
                _ => println!("Unrecognized error code from server?"),
            }
        },
        Err(_) => return Err("Proving request processing failed.".into()),
    };
    Ok(())
}

