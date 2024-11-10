#![allow(non_snake_case)]

/// Processing bitcoin private key files

extern crate bulletproofs;
extern crate merlin;
extern crate rand;

use ark_ec::AffineRepr;
use ark_serialize::CanonicalSerialize;
use bitcoin::secp256k1::All;
use rand::Rng;
use std::iter::zip;

use std::error::Error;
use std::io::Write;
use ark_ec::short_weierstrass::Affine;
use ark_secp256k1::Config as SecpConfig;
use bitcoin::key::Secp256k1;
use bitcoin::PrivateKey;
use crate::auditor::get_audit_generators;
use crate::serialization::{self, *};


type F = <ark_secp256k1::Affine as AffineRepr>::ScalarField;
/// Given a list of values for a defined range of
/// private keys from integers 1..n,
/// create a private keys and values file, comma separated,
/// with private keys as WIF, and also a file of public commitments
/// for the serving of the keyset (and curve tree creation)
pub fn create_fake_privkeys_values_files(num_privs: u64,
    values_indices: Vec<i32>, // the indices in the full set of keys which we want to use as prover
    values_vec: Vec<u64>, // the sats value at each of those indices (the privkey is just the index)
    filelabel: & str) -> Result<(), Box<dyn Error>> {
    let secp = Secp256k1::new();
    // first form the vector of all private keys as WIF strings
    let mut privkey_wifs: Vec<String> = Vec::new();
    for i in 1..num_privs+1u64 {
        let privk: F = i.into();
        let mut buf: Vec<u8> = Vec::new();
        privk.serialize_compressed(&mut buf)?;
        buf.reverse();
        let privk2: PrivateKey = PrivateKey::from_slice(
            &buf, bitcoin::Network::Signet).unwrap();
        let privhex = hex::encode(&privk2.to_bytes());
    
        let x = decode_hex_le_to_F::<F>(&privhex)?;
        privkey_wifs.push(get_wif_from_field_elem(x)?);
    }

    // then assign the specified values to the specified indices
    // then assign random values to the other indices, forming a complete
    // vector of values.
    let mut vec_all_values: Vec<u64> = vec![0u64; num_privs as usize];
    let mut rng = rand::thread_rng();
    for ind  in 0..num_privs {
        if values_indices.contains(&(ind as i32)) {
            // get the index in the list for which the index is ind:
            let k = values_indices.iter()
            .position(|&r| r == ind as i32).unwrap();
            vec_all_values[ind as usize] = values_vec[k];
        }
        else {
            vec_all_values[ind as usize] = rng.gen::<u64>();
        }
    };
    // Then call `get_commitments_from_wif_and_sats` to form a complete
    // set of commitments.
    let commitments = get_commitments_from_wif_and_sats(
        privkey_wifs.clone(), vec_all_values, &secp)?;
    
    // Then write those to a *pks file with the given label.
    let commsfilename = filelabel.to_owned() + ".pks";
    write_keyset_file_from_commitments(commitments, &commsfilename)?;

    // Then form the list of (wif privkeys, values) for the assigned values.
    // Then write those into a .txt file with the given label.
    let mut filtered_privkey_wifs: Vec<String> = Vec::new();
    for i in values_indices {
        filtered_privkey_wifs.push(privkey_wifs[i as usize].clone());
    }
    let privsfilename = filelabel.to_owned() + "-privkeys.txt";
    write_privkeys_file(filtered_privkey_wifs, values_vec, &privsfilename)?;
    Ok(())
}

/// The format of the private key file used
/// to create audit proofs is:
/// privkey-as-WIF,value-in-sats
/// with one line per key/utxo you want to prove for.
pub fn write_privkeys_file(privkeys_wif: Vec<String>,
    values_vec: Vec<u64>,
    filename: &str) -> Result<(), Box<dyn Error>> {
    let mut buf: Vec<u8> = Vec::new();
    for (p, v) in zip(privkeys_wif, values_vec) {
        writeln!(&mut buf, "{},{}", p, v.to_string())?;
    }
    write_file_string(filename, buf);
    Ok(())
}

pub fn write_keyset_file_from_commitments(comms: Vec<Affine<SecpConfig>>,
output_filename: &str) -> Result<(), Box<dyn Error>> {
    let mut buf: Vec<u8> = Vec::new();
    let mut commslist: Vec<String> = Vec::new();
    for comm in comms {
        let mut buf2: Vec<u8> = Vec::new();
        comm.serialize_with_mode(&mut buf2,
            ark_serialize::Compress::Yes)?;
        commslist.push(hex::encode(buf2));
        }
    write!(&mut buf, "{}", commslist.join(" "))?;
    write_file_string(output_filename, buf);
    Ok(())  
}

pub fn get_commitments_from_wif_and_sats_file(privkeys_values_file_loc: &str,
secp: &Secp256k1::<All>) -> Result<
    Vec<Affine<SecpConfig>>, Box<dyn Error>>{
    let (privkeys_wif, values) = get_privkeys_and_values(
        privkeys_values_file_loc)?;
    get_commitments_from_wif_and_sats(privkeys_wif, values, &secp)
}
/// Return a list of commitments to xG + vJ for
/// a set of privkeys read as WIF, each tweaked as p2tr
pub fn get_commitments_from_wif_and_sats(privkeys_wif: Vec<String>,
    values: Vec<u64>, secp: &Secp256k1<All>)
-> Result<Vec<Affine<SecpConfig>>, Box<dyn Error>> {
    let (_, J) = get_audit_generators();
    let mut comms: Vec<Affine<SecpConfig>> = Vec::new();
    for i in 0..privkeys_wif.len() {
        let (_, comm) = serialization::privkey_val_to_taproot_ark_ec(
            &privkeys_wif[i], values[i], J, secp)?;
        comms.push(comm);
    }
    Ok(comms)
}

pub fn get_privkeys_and_values(fileloc: &str) -> Result<(Vec<String>, Vec<u64>), Box<dyn Error>>{
    let ptext = read_file_string(&fileloc)?;
    let lines = ptext.lines();
    let mut privkeys_wif: Vec<String> = vec![];
    let mut values: Vec<u64> = vec![];
    for line in lines {
        let v: Vec<&str> = line.split(",").collect::<Vec<_>>();
        privkeys_wif.push(v[0].to_string());
        let value_int = (v[1]).parse::<u64>()?;
        values.push(value_int);
    }
    Ok((privkeys_wif, values))
}
