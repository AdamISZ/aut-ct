#![allow(non_snake_case)]

extern crate rand;
extern crate alloc;
extern crate ark_secp256k1;
use crate::key_processing::create_fake_privkeys_values_files;
use crate::rpcclient;
//use crate::rpcserver;
use crate::config::{AutctConfig, get_params_from_config_string};
use crate::utils::write_file_string;
use std::io::Write;
use std::error::Error;
use base64::prelude::*;
use crate::encryption::{encrypt, decrypt};

/// An undocumented tool for creating test files.
/// Note that this misuses config vars as follows:
/// filenameprefix is -k/keysets
/// numprivs is depth/-d
/// long parsed values/indices string is -p/rpchost
/// Specify the total number of keys to be created in the keyset,
/// then specify the indices for which you're going to generate
/// the proof, along with the value for each index, using colon
/// separated pairs. For example:
/// ./autct -M audittestgen -W 100 -l 2:5000,14:90000 -k mytestdata
pub async fn create_test_data(autctcfg: AutctConfig) -> Result<(), Box<dyn Error>> {
    let filenameprefix = autctcfg.keysets.clone().unwrap();
    let numprivs = autctcfg.depth.clone().unwrap() as u64;
    let values_indices_str = autctcfg.rpc_host.clone().unwrap();
    // extract a vector of indices and values as index:value,index:value,..
    let (iv, vv) = get_params_from_config_string(
        values_indices_str)?;
    let values_vec: Vec<u64> = vv.iter().map(|x| x.parse::<u64>().unwrap()).collect();
    let indices_vec: Vec<i32> = iv.iter().map(|x| x.parse::<i32>().unwrap()).collect();
    create_fake_privkeys_values_files(numprivs,
        indices_vec, values_vec, &filenameprefix)?;
    Ok(())
}
/// This is a tool for manual testing; users will always
/// have privkeys stored in encrypted files. Hence
/// there is no attempt to handle errors properly.
pub async fn request_encrypt_key(autctcfg: AutctConfig) -> Result<(), Box<dyn Error>>  {
    let password = rpassword::prompt_password("Enter a password to encrypt the private key: ").unwrap();
    let privkey_file_str = autctcfg.privkey_file_str.clone().unwrap();
    let plaintext_priv_wif = crate::utils::read_file_string(&privkey_file_str)?;
    let mut buf: Vec<u8> = Vec::new();
    write!(&mut buf, "{}", plaintext_priv_wif)?;
    let encrypted_data = encrypt(&buf, &password.as_bytes())?;
    // TODO write_file_str does not pay attention to errors (but low priority)
    write_file_string(&(autctcfg.privkey_file_str.clone().unwrap() + ".enc"), encrypted_data);
    Ok(())
}

// This tool is helpful to allow importing the key to a Bitcoin wallet
pub async fn request_decrypted_key(autctcfg: AutctConfig) -> Result<(), Box<dyn Error>> {
    let password = rpassword::prompt_password("Enter password to decrypt private key: ")?;
    let privkey_file_str = autctcfg.privkey_file_str.clone().unwrap();
    let encrypted_priv_wif = std::fs::read(&privkey_file_str)?;
    let bytes_priv_wif = decrypt(&encrypted_priv_wif, &password.as_bytes())?;
    let plaintext_priv_wif = std::str::from_utf8(&bytes_priv_wif)?;
    println!("Private key: {}", plaintext_priv_wif);
    Ok(())
}

pub async fn request_create_keys(autctcfg: AutctConfig) ->Result<(), Box<dyn Error>> {
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

pub async fn request_verify(autctcfg: AutctConfig) -> Result<(), Box<dyn Error>> {
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

fn print_and_return(s: &str) -> Result<String, Box<dyn Error>>{
    println!("{}", s);
    Ok(s.to_string())
}

pub async fn request_echo(autctcfg: &AutctConfig) -> Result<String, Box<dyn Error>> {
    let res = rpcclient::echo(autctcfg).await;
    match res {
        Ok(x) => Ok(x.response_msg),
        Err(_) => Err("Failed echo call".into())
    }
}

pub async fn request_audit_verify(autctcfg: AutctConfig) -> Result<String, Box<dyn Error>>{
    let res = rpcclient::auditverify(autctcfg.clone()).await;
    match res {
        Ok(rest) => {
            // Note that we are guaranteed non-nonsense values
            // for these fields because this is a non-Err response:
            let satmin = rest.audit_range_min;
            let satmax = satmin + 2u64.pow(rest.audit_range_exponent as u32);
            match rest.accepted {
                1 => {let s = format!("Audit is valid! The utxos' total value is between {} and {} satoshis.",
                 satmin, satmax);
                 println!("{}", s);
                 return Ok(s)},
                -1 => {let s = "Invalid encoding of proof, should be base64.";
                return print_and_return(s);},
                -2 => {let s = "Invalid proof serialization";
                return print_and_return(s);},
                -3 => {let s = "Proof of assets in range is rejected, proof invalid.";
                return print_and_return(s);},
                _ => {let s = "Unrecognized error code from server?";
                return print_and_return(s);},
            }
        },
        Err(e) => return Err(
            format!("{}", e).into()),
    };
}

pub async fn request_audit(autctcfg: AutctConfig) -> Result<(), Box<dyn Error>>{
    let res = rpcclient::auditprove(
        autctcfg.clone()).await;
    let required_proof_destination = autctcfg.clone()
    .proof_file_str.unwrap();
    let b64chosen: bool = autctcfg.base64_proof.unwrap();
    match res {
        Ok(rest) => {
            match rest.accepted {
                0 => {println!("Proof generated successfully.");
                // receive the base64 proof and convert it to a binary file.
                let b64proof = rest.audit_proof.unwrap();
                if b64chosen {
                    println!("Here is the proof in base64 format: {}", b64proof);
                }
                else {
                let decoded_proof = BASE64_STANDARD
                .decode(b64proof)
                .expect("Unexpected format of proof, should be base64");
                write_file_string(&required_proof_destination, decoded_proof);
                }
                },
                -1 => {println!("Error getting privkeys and values from file")},
                -2 => {println!("Proof created does not verify.")},
                -3 => {println!("Error encoding the serialized proof.")},
                _ => println!("Unrecognized error code from server?"),
            }
        },
        Err(_) => return Err("Audit proving request processing failed.".into()),
    }
    Ok(())
}

pub async fn request_prove(autctcfg: AutctConfig) -> Result<(), Box<dyn Error>>{
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

