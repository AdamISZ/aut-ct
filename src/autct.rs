#![allow(non_snake_case)]

extern crate rand;
extern crate alloc;
extern crate ark_secp256k1;
use autct::rpcclient;
use autct::rpcserver;
use autct::config::AutctConfig;
use autct::utils::write_file_string;
use std::io::Write;
use std::error::Error;
use base64::prelude::*;
use autct::encryption::{encrypt, decrypt};

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
        // this extra tool is really just for testing:
        "encryptkey" => {return request_encrypt_key(autctcfg).await},
        // extra tool for exporting the key:
        "decryptkey" => {return request_decrypted_key(autctcfg).await},
        _ => {return Err("Invalid mode, must be 'prove', 'serve', 'newkeys', 'encryptkey', 'decryptkey' or 'verify'".into())},

    }
}

/// This is a tool for manual testing; users will always
/// have privkeys stored in encrypted files. Hence
/// there is no attempt to handle errors properly.
async fn request_encrypt_key(autctcfg: AutctConfig) -> Result<(), Box<dyn Error>>  {
    let password = rpassword::prompt_password("Enter a password to encrypt the private key: ").unwrap();
    let privkey_file_str = autctcfg.privkey_file_str.clone().unwrap();
    let plaintext_priv_wif = autct::utils::read_file_string(&privkey_file_str)?;
    let mut buf: Vec<u8> = Vec::new();
    write!(&mut buf, "{}", plaintext_priv_wif)?;
    let encrypted_data = encrypt(&buf, &password.as_bytes())?;
    // TODO write_file_str does not pay attention to errors (but low priority)
    write_file_string(&(autctcfg.privkey_file_str.clone().unwrap() + ".enc"), encrypted_data);
    Ok(())
}

// This tool is helpful to allow importing the key to a Bitcoin wallet
async fn request_decrypted_key(autctcfg: AutctConfig) -> Result<(), Box<dyn Error>> {
    let password = rpassword::prompt_password("Enter password to decrypt private key: ")?;
    let privkey_file_str = autctcfg.privkey_file_str.clone().unwrap();
    let encrypted_priv_wif = std::fs::read(&privkey_file_str)?;
    let bytes_priv_wif = decrypt(&encrypted_priv_wif, &password.as_bytes())?;
    let plaintext_priv_wif = std::str::from_utf8(&bytes_priv_wif)?;
    println!("Private key: {}", plaintext_priv_wif);
    Ok(())
}

async fn request_create_keys(autctcfg: AutctConfig) ->Result<(), Box<dyn Error>> {
    // This requires interaction from user: give a password on the command line:
    let password = rpassword::prompt_password("Enter a password to encrypt the new private key: ").unwrap();
    let res = rpcclient::createkeys(autctcfg, password).await;
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
        // TODO: create some callback structure to receive the resource
            match rest.accepted {
                // deliberately verbose message here to help testers understand:
                1 => println!("Request was accepted by the Autct verifier! The proof is valid and the (unknown) pubkey is unused."),
                -1 => println!("Request rejected, PedDLEQ proof does not match the tree."),
                -2 => println!("Request rejected, PedDLEQ proof is invalid."),
                -3 => println!("Request rejected, proofs are valid but key image is reused."),
                -4 => println!("Request rejected, keyset chosen does not match the server's."),
                -5 => println!("Invalid encoding of proof, should be base64."),
                -6 => println!("Curve point deserialization failure in proof."),
                -7 => println!("PedDLEQ proof deserialization failed."),
                _ => println!("Unrecognized error code from server?"),
            }
        },
        Err(_) => return Err("Verificatoin request processing failed.".into()),
    };
    Ok(())
}

async fn request_prove(autctcfg: AutctConfig) -> Result<(), Box<dyn Error>>{
    // This requires interaction from user: give a password on the command line:
    let password = rpassword::prompt_password("Enter a password to decrypt the private key: ").unwrap();
    let required_proof_destination = autctcfg.clone().proof_file_str.unwrap();
    let b64chosen: bool = autctcfg.clone().base64_proof.unwrap();
    let res = rpcclient::prove(autctcfg, password).await;
    match res {
        Ok(rest) => {
        // codes defined in lib.rs
        // TODO: create some callback structure to receive the resource
            match rest.accepted {
                0 => {println!("Proof generated successfully.");
                // receive the base64 proof and convert it to a binary file.
                let b64proof = rest.proof.unwrap();
                if b64chosen {
                    println!("Here is the proof in base64 format: {}", b64proof);
                }
                else {
                let decoded_proof = BASE64_STANDARD.decode(b64proof)
                .expect("Unexpected format of proof, should be base64");
                write_file_string(&required_proof_destination, decoded_proof);
                }
            },
                -1 => println!("Undefined failure in proving."),
                -2 => println!("Proving request rejected, must be only one context:keyset provided."),
                -3 => println!("Proving request rejected, provided context label is not served."),
                -4 => println!("Proving request rejected, provided keyset is not served."),
                -5 => println!("Proving request rejected, wrong bitcoin network."),
                -6 => println!("Proving request rejected, could not read private key from file."),
                -7 => println!("Proving request rejected, invalid private key format (must be WIF or hex)."),
                -8 => println!("Proving request rejected, provided key is not in the keyset"),
                -9 => println!("Keyset string has incorrect syntax."),
                -10 => println!("Ped-DLEQ proof serialization error."),
                -11 => println!("Curve point serialization failure."),
                -12 => println!("Bulletproof serialization error."),
                -13 => println!("Curve tree merkle path serialiazation error"),
                -14 => println!("Private key file decryption error."),
                _ => println!("Unrecognized error code from server?"),
            }
        },
        Err(_) => return Err("Proving request processing failed.".into()),
    };
    Ok(())
}

