#![allow(non_snake_case)]

extern crate rand;
extern crate alloc;
extern crate ark_secp256k1;
use base64::prelude::*;
use autct::utils::*;
use autct::config::AutctConfig;
use autct::peddleq::PedDleqProof;
mod rpcclient;
mod rpcserver;
use bitcoin::{Address, PrivateKey, XOnlyPublicKey};
use bitcoin::key::{Secp256k1, TapTweak, UntweakedKeypair};

use bulletproofs::r1cs::R1CSProof;
use bulletproofs::r1cs::Prover;
use alloc::vec::Vec;
use ark_ec::{AffineRepr, short_weierstrass::SWCurveConfig, CurveGroup};
use ark_ff::{PrimeField, Zero, One};
use ark_serialize::{
    CanonicalSerialize, Compress};
use relations::curve_tree::{SelRerandParameters, SelectAndRerandomizePath};
use std::ops::{Mul, Add};
use merlin::Transcript;

use ark_ec::short_weierstrass::Affine;
use ark_secp256k1::{Config as SecpConfig, Fq as SecpBase};
use ark_secq256k1::Config as SecqConfig;

use std::time::Instant;

// this function returns the curve tree for the set of points
// read from disk (currently pubkey file location is passed as an argument), and
// then returns a tree, along with two bulletproofs for secp and secq,
// and the "merkle proof" of (blinded) commitments to the root.
// For the details on this proof, see "Select-and-Rerandomize" in the paper.
pub fn get_curve_tree_with_proof<
    F: PrimeField,
    P0: SWCurveConfig<BaseField = F> + Copy,
    P1: SWCurveConfig<BaseField = P0::ScalarField, ScalarField = P0::BaseField> + Copy,
>(
    depth: usize,
    generators_length_log_2: usize,
    pubkey_file_path: &str,
    our_pubkey: Affine<P0>,
) -> (R1CSProof<Affine<P0>>, R1CSProof<Affine<P1>>,
    SelectAndRerandomizePath<P0, P1>,
    P0::ScalarField,
    Affine<P0>, Affine<P0>, bool) {
    let mut rng = rand::thread_rng();
    let generators_length = 1 << generators_length_log_2;

    let sr_params =
        SelRerandParameters::<P0, P1>::new(generators_length, generators_length, &mut rng);

    let p0_transcript = Transcript::new(b"select_and_rerandomize");
    let mut p0_prover: Prover<_, Affine<P0>> =
        Prover::new(&sr_params.even_parameters.pc_gens, p0_transcript);

    let p1_transcript = Transcript::new(b"select_and_rerandomize");
    let mut p1_prover: Prover<_, Affine<P1>> =
        Prover::new(&sr_params.odd_parameters.pc_gens, p1_transcript);

    // these are called 'leaf commitments' and not 'leaves', but it's just
    // to emphasize that we are not committing to scalars, but using points (i.e. pubkeys)
    // as the commitments (i.e. pedersen commitments with zero randomness) at
    // the leaf level.
    let mut privkey_parity_flip: bool = false;
    let leaf_commitments = get_leaf_commitments::<F, P0>(
        &(pubkey_file_path.to_string() + ".p"));
    // derive the index where our pubkey is in the list.
    // but: since it will have been permissible-ized, we need to rederive the permissible
    // version here, purely for searching:

    // as well as the randomness in the blinded commitment, we also need to use the same
    // blinding base:
    let b_blinding = sr_params.even_parameters.pc_gens.B_blinding;
    let mut our_pubkey_permiss1: Affine<P0> = our_pubkey;
    while !sr_params.even_parameters.uh.is_permissible(our_pubkey_permiss1) {
        our_pubkey_permiss1 = (our_pubkey_permiss1 + b_blinding).into();
    }
    let mut our_pubkey_permiss2: Affine<P0> = -our_pubkey;
    while !sr_params.even_parameters.uh.is_permissible(our_pubkey_permiss2) {
        our_pubkey_permiss2 = (our_pubkey_permiss2 + b_blinding).into();
    }
    let mut key_index: i32; // we're guaranteed to overwrite or panic but the compiler insists.
    // the reason for 2 rounds of search is that BIP340 can output a different parity
    // compared to ark-ec 's compression algo.
    key_index = match leaf_commitments.iter().position(|&x| x  == our_pubkey_permiss1) {
        None => -1,
        Some(ks) => ks.try_into().unwrap()
    };
    if key_index == -1 {
        key_index = match leaf_commitments.iter().position(|&x| x == our_pubkey_permiss2) {
            None => panic!("provided pubkey not found in the set"),
            Some(ks) => {
                privkey_parity_flip = true;
                ks.try_into().unwrap()
            }
        }
    };

    // Now we know we have a key that's in the set, we can construct the curve
    // tree from the set, and then the proof using its private key:
    let beforect = Instant::now();
    let (curve_tree, _) = get_curve_tree::<F, P0, P1>(
        leaf_commitments.clone(), depth, &sr_params);
    println!("Elapsed time for curve tree construction: {:.2?}", beforect.elapsed());
    assert_eq!(curve_tree.height(), depth);

    let (path_commitments, rand_scalar) =
    curve_tree.select_and_rerandomize_prover_gadget(
        key_index.try_into().unwrap(),
        &mut p0_prover,
        &mut p1_prover,
        &sr_params,
        &mut rng,
    );
    // The randomness for the PedDLEQ proof will have to be the randomness
    // used in the curve tree randomization, *plus* the randomness that was used
    // to convert P to a permissible point, upon initial insertion into the tree.
    let mut r_offset: P0::ScalarField = P0::ScalarField::zero();
    let lcindex: usize = key_index.try_into().unwrap();
    let mut p_prime: Affine<P0> = leaf_commitments[lcindex];
    // TODO: this is basically repeating what's already done in
    // sr_params creation, but I don't know how else to extract the number
    // of H bumps that were done (and we need to, see previous comment).
    while !sr_params.even_parameters.uh.is_permissible(p_prime) {
        p_prime = (p_prime + b_blinding).into();
        r_offset += P0::ScalarField::one();
    }
    // print the root of the curve tree.
    // TODO: how to allow the return value to be either
    // Affine<P0> or Affine<P1>? And as a consequence,
    // to let the code be correct for any depth.
    // And/or, is there not
    // a simpler way to extract the root of the tree
    // (which should be just .parent_commitment, but all methods
    // to extract this value seem to be private)
    let newpath = curve_tree.select_and_rerandomize_verification_commitments(
    path_commitments.clone());
    let root_is_odd = newpath.even_commitments.len() == newpath.odd_commitments.len();
    println!("Root is odd? {}", root_is_odd);
    let root: Affine<P0>;
    if !root_is_odd {
        root = *newpath.even_commitments.first().unwrap();
    }
    else {
        // derp, see above TODO
        panic!("Wrong root parity, should be even");
    }
    let p0_proof = p0_prover
        .prove(&sr_params.even_parameters.bp_gens)
        .unwrap();
    let p1_proof = p1_prover
        .prove(&sr_params.odd_parameters.bp_gens)
        .unwrap();
    let returned_rand = rand_scalar + r_offset;
    (p0_proof, p1_proof, path_commitments,
     returned_rand, b_blinding, root, privkey_parity_flip)
}

#[tokio::main]
async fn main() -> Result<(), CustomError>{

    if let Ok(autctcfg) = AutctConfig::build(){
    // TODO maybe remove this code duplication?
    // The problem is that `L`, the branching factor of tree,
    // *must* be a const generic, as I understand it,
    // and we must return a tree with a specific value of that
    // const usize integer. I'm not sure if we can do that
    // with a macro, or if it's worth it to remove this
    // minor duplication.
    match autctcfg.clone().mode.unwrap().as_str() {
        "prove" => {return run_prover(autctcfg)
                    },
        "request" => {return run_request(autctcfg).await},
        "serve" => {return rpcserver::do_serve(autctcfg).await
                    },
        "newkeys" => {return run_create_keys(autctcfg).await},
        "convertkeys" => {return run_convert_keys::<SecpBase, SecpConfig, SecqConfig>(autctcfg)},
        _ => {println!("Invalid mode, must be 'prove', 'serve', 'newkeys', 'convertkeys' or 'request'")},

    }}
    else {
        return Err(CustomError{});
    }
    Ok(())
}

// Takes as input a hex list of actual BIP340 pubkeys
// that should come from the utxo set;
// converts each point into a permissible point
// and then writes these points in binary format into
// a new file with same name as keyset with .p appended.
pub fn run_convert_keys<F: PrimeField,
P0: SWCurveConfig<BaseField = F> + Copy,
P1: SWCurveConfig<BaseField = P0::ScalarField,
ScalarField = P0::BaseField> + Copy,>(autctcfg: AutctConfig) -> Result<(), CustomError>{
    let (cls, mut kss) = autctcfg.clone()
    .get_context_labels_and_keysets().unwrap();
    if kss.len() != 1 || cls.len() != 1 {
        return Err(CustomError{});
    }
    let keyset = kss.pop().unwrap();
    let raw_pubkeys = get_pubkey_leaves_hex::<F, P0>(&keyset);
    let mut rng = rand::thread_rng();
    let generators_length = 1 << autctcfg.generators_length_log_2.unwrap();

    let sr_params =
        SelRerandParameters::<P0, P1>::new(generators_length,
            generators_length, &mut rng);
    let (permissible_points, _pr)
     = create_permissible_points_and_randomnesses(
        &raw_pubkeys, &sr_params);
    // take vec permissible points and write it in binary as n*33 bytes
    let mut buf: Vec<u8> = Vec::with_capacity(permissible_points.len()*33);
    let _: Vec<_> = permissible_points
        .iter()
        .map(|pt: &Affine<P0>| {
            pt.serialize_compressed(&mut buf).expect("Failed to serialize point")
        }).collect();
    let output_file = keyset.clone() + ".p";
    write_file_string(&output_file, buf);
    Ok(())
}

async fn run_create_keys(autctcfg: AutctConfig) ->Result<(), CustomError> {

    let nw = match autctcfg.bc_network.unwrap().as_str() {
        "mainnet" => bitcoin::Network::Bitcoin,
        "signet" => bitcoin::Network::Signet,
        "regtest" => bitcoin::Network::Regtest,
       _ => panic!("Invalid bitcoin network string in config."),
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
async fn run_request(autctcfg: AutctConfig) -> Result<(), CustomError> {
    let res = rpcclient::do_request(autctcfg).await;
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
        Err(_) => return Err(CustomError{}),
    };
    Ok(())
}

pub fn run_prover(autctcfg: AutctConfig) -> Result<(), CustomError>{
    type F = <ark_secp256k1::Affine as AffineRepr>::ScalarField;
    let nw = match autctcfg.bc_network.clone().unwrap().as_str() {
        "mainnet" => bitcoin::Network::Bitcoin,
        "signet" => bitcoin::Network::Signet,
        "regtest" => bitcoin::Network::Regtest,
       _ => panic!("Invalid bitcoin network string in config."),
    };
    let secp = Secp256k1::new(); // is the context global? need to check
    // read privkey from file; we prioritize WIF format for compatibility
    // with external wallets, but if that fails, we attempt to read it
    // as raw hex:
    let privkey_file_str = autctcfg.privkey_file_str.clone().unwrap();
    let privwif:String = read_file_string(&privkey_file_str)
    .expect("Failed to read the private key from the file");

    // Because sparrow (and, kinda, Core) expect usage of non-raw p2tr,
    // it means we're forced to use the default tweaking algo here, even
    // though it majorly screws up the flow (as we want to use ark's Affine<>
    // objects for the curve points here).
    // 1. First convert the hex equivalent of the WIF into a byte slice (
    // note that this is a big endian encoding still).
    // 2. Then call PrivateKey.from_slice to deserialize into a PrivateKey.
    // 3. use the privkey.public_key(&secp).inner.tap_tweak function
    //    to get a tweaked pubkey.
    // 3. Then serialize that as a string, deserialize it back out to Affine<Config>

    let privkeyres1 = PrivateKey::from_wif(privwif.as_str());
    let privkey: PrivateKey;
    if privkeyres1.is_err(){
        let privkeyres2 = PrivateKey::from_slice(
            &hex::decode(privwif).unwrap(),
         nw);
        if privkeyres2.is_err(){
            panic!("Failed to read the private key as either WIF or hex format!");
        }
        privkey = privkeyres2.unwrap();
    }
    else {
        privkey = privkeyres1.unwrap();
    }
    let untweaked_key_pair: UntweakedKeypair = UntweakedKeypair::from_secret_key(
        &secp, &privkey.inner);
    let tweaked_key_pair = untweaked_key_pair.tap_tweak(&secp, None);
    let privkey_bytes = tweaked_key_pair.to_inner().secret_bytes();
    let privhex = hex::encode(&privkey_bytes);

    let mut x = decode_hex_le_to_F::<F>(&privhex);
    let G = SecpConfig::GENERATOR;
    let mut P = G.mul(x).into_affine();
    print_affine_compressed(P, "our pubkey");
    let (mut cls, mut kss) = autctcfg.clone()
    .get_context_labels_and_keysets().unwrap();
    if kss.len() != 1 || cls.len() != 1 {
        //return Err("You may only specify one context_label:keyset in the proof request".into())
        return Err(CustomError{});
    }
    let keyset = kss.pop().unwrap();
    let context_label = cls.pop().unwrap();
    let gctwptime = Instant::now();
    let (p0proof,
        p1proof,
        path,
    r,
    H,
    root,
    privkey_parity_flip) = get_curve_tree_with_proof::<
    SecpBase,
    SecpConfig,
    SecqConfig>(
            autctcfg.depth.unwrap().try_into().unwrap(),
            autctcfg.generators_length_log_2.unwrap().try_into().unwrap(),
            &keyset, P);
    println!("Elapsed time for get curve tree with proof: {:.2?}", gctwptime.elapsed());
    // if we could only find our pubkey in the list by flipping
    // the sign of our private key (this is because the BIP340 compression
    // logic is different from that in ark-ec; a TODO is to remove this
    // confusion by having the BIP340 logic in this code):
    if privkey_parity_flip {
        x = -x;
        P = -P;
    }
    print_affine_compressed(P, "P after flipping");
    // next steps create the Pedersen DLEQ proof for this key:
    //
    let J = get_generators::<SecpBase, SecpConfig>(context_label.as_bytes());
    print_affine_compressed(J, "J");
    // blinding factor for Pedersen
    // the Pedersen commitment D is xG + rH
    let rH = H.mul(r).into_affine();
    let D = P.add(rH).into_affine();
    // the key image (E) is xJ
    let E = J.mul(x).into_affine();
    let mut transcript = Transcript::new(APP_DOMAIN_LABEL);
    let proof = PedDleqProof::create(
            &mut transcript,
            &D,
            &E,
            &x,
            &r,
            &G,
            &H,
            &J,
            None,
            None,
            context_label.as_bytes(),
            autctcfg.user_string.as_ref().unwrap().as_bytes()
    );
    let mut buf = Vec::with_capacity(proof.serialized_size(Compress::Yes));
    proof.serialize_compressed(&mut buf).unwrap();

        let mut verifier = Transcript::new(APP_DOMAIN_LABEL);
        assert!(proof
            .verify(
                &mut verifier,
                &D,
                &E,
                &G,
                &H,
                &J,
                context_label.as_bytes(),
                autctcfg.user_string.unwrap().as_bytes()
            )
            .is_ok());
        print_affine_compressed(D, "D");
        print_affine_compressed(E, "E");
    let total_size =
    33 + 33 + // D and E points (compressed)
    proof.serialized_size(Compress::Yes) + 
    p0proof.serialized_size(Compress::Yes) + 
    p1proof.serialized_size(Compress::Yes) +
    path.serialized_size(Compress::Yes);
    let mut buf2 = Vec::with_capacity(total_size);
    D.serialize_compressed(&mut buf2).unwrap();
    E.serialize_compressed(&mut buf2).unwrap();
    proof.serialize_with_mode(&mut buf2, Compress::Yes).unwrap();
    p0proof.serialize_compressed(&mut buf2).unwrap();
    p1proof.serialize_compressed(&mut buf2).unwrap();
    path.serialize_compressed(&mut buf2).unwrap();
    root.serialize_compressed(&mut buf2).unwrap();
    if autctcfg.base64_proof.unwrap() {
        let encoded = BASE64_STANDARD.encode(buf2);
        println!("Proof generated successfully:\n{}", encoded);
        return Ok(());
    }
    write_file_string(&autctcfg.proof_file_str.clone().unwrap(), buf2);
    println!("Proof generated successfully and written to {}. Size was {}",
    &autctcfg.proof_file_str.unwrap(), total_size);
    print_affine_compressed(root, "root");
    Ok(())
}

