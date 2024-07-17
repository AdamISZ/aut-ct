#![allow(non_snake_case)]

extern crate rand;
extern crate alloc;
extern crate ark_secp256k1;
use autct::rpcclient;
use autct::rpcserver;
use autct::config::AutctConfig;


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
        "newkeys" => {return request_create_keys(autctcfg).await},
        _ => {return Err("Invalid mode, must be 'prove', 'serve', 'newkeys' or 'verify'".into())},

    }
}

async fn request_create_keys(autctcfg: AutctConfig) ->Result<(), Box<dyn Error>> {
    let res = rpcclient::createkeys(autctcfg).await;
    match res {
        Ok(rest) => {
        // codes defined in lib.rs
            match rest.accepted {
                0 => {println!("New key and address generated successfully");
                println!("This is the address to pay into: {}", rest.address.unwrap());
                println!("The corresponding private key is written in WIF format to: {}", rest.privkey_file_loc.unwrap());
                println!("The WIF string can be imported into e.g. Sparrow, Core to sweep or access the funds in it.");
            },
                -1 => println!("Undefined failure in key generation."),
                -2 => println!("New key request rejected, mismatch in bitcoin network."),
                -3 => println!("New key request rejected, could not write private key to specified file location."),
                _ => println!("Unrecognized error code from server?"),
            }
        },
        Err(_) => return Err("Proving request processing failed.".into()),
    };
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

