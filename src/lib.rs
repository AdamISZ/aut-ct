#![allow(non_snake_case)]

pub mod peddleq;
pub mod utils;
pub mod autctverifier;
pub mod autctactions;
pub mod config;
pub mod keyimagestore;
pub mod rpcclient;
pub mod rpcserver;
pub mod encryption;
pub mod generalschnorr;
pub mod key_processing;
pub mod sumrangeproof;
pub mod auditor;
extern crate rand;
extern crate alloc;
extern crate ark_secp256k1;

use utils::*;

use peddleq::PedDleqProof;
use autctverifier::verify_curve_tree_proof;
use bulletproofs::r1cs::R1CSProof;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use serde_derive::{Deserialize, Serialize};
use relations::curve_tree::SelectAndRerandomizePath;

use merlin::Transcript;

use ark_ec::short_weierstrass::Affine;
use ark_secp256k1::Config as SecpConfig;
use ark_secq256k1::Config as SecqConfig;
use std::io::Cursor;
use std::time::Instant;
use toy_rpc::macros::export_impl;
use std::io::Write;

use base64::prelude::*;

use bitcoin::key::{Secp256k1, TapTweak, UntweakedKeypair};

use alloc::vec::Vec;
use ark_ec::{AffineRepr, short_weierstrass::SWCurveConfig, CurveGroup};
use ark_secp256k1::Fq as SecpBase;
use std::ops::{Mul, Add};
use bitcoin::{Address, PrivateKey, XOnlyPublicKey};
use encryption::{encrypt, decrypt};
use auditor::{get_audit_generators, AuditProof};
use key_processing::get_privkeys_and_values;

pub mod rpc {

    use crate::config::get_params_from_config_string;

    use super::*;
    use std::{sync::{Arc, Mutex}, u64};
    use ark_ff::BigInteger256;
    use relations::curve_tree::{CurveTree, SelRerandParameters};

    #[derive(Clone)]
    pub struct RPCProverVerifierArgs {
                pub keyset_file_locs: Vec<String>,
                pub context_labels: Vec<String>,
                pub sr_params: SelRerandParameters<SecpConfig, SecqConfig>,
                pub curve_trees: Vec<CurveTree<SecpConfig, SecqConfig>>,
                pub G: Affine<SecpConfig>,
                pub H: Affine<SecpConfig>,
                pub Js: Vec<Affine<SecpConfig>>,
                pub ks: Vec<Arc<Mutex<keyimagestore::KeyImageStore<Affine<SecpConfig>>>>>,
            }

            #[derive(Serialize, Deserialize)]
            pub struct RPCCreateKeysRequest {
                pub bc_network: String,
                pub privkey_file_loc: String,
                pub encryption_password: String,
            }

            #[derive(Serialize, Deserialize)]
            pub struct RPCCreateKeysResponse {
                pub address: Option<String>, // note that for taproot, the pubkey is implicit
                pub privkey_file_loc: Option<String>,
                pub accepted: i32,
            }

            pub struct RPCCreateKeys {
            }

            #[export_impl]
            impl RPCCreateKeys {
                #[export_method]
                pub async fn createkeys(&self, args: RPCCreateKeysRequest)
                -> Result<RPCCreateKeysResponse, String> {
                    let mut resp: RPCCreateKeysResponse = RPCCreateKeysResponse{
                        address: None,
                        privkey_file_loc: Some(args.privkey_file_loc),
                        accepted: -1
                    };
                    let nw = match args.bc_network.as_str() {
                        "mainnet" => bitcoin::Network::Bitcoin,
                        "signet" => bitcoin::Network::Signet,
                        "regtest" => bitcoin::Network::Regtest,
                       _ => {resp.accepted = -2;
                             return Ok(resp)},
                    };
                
                    // This uses the `rand-std` feature in the rust-bitcoin crate to generate
                    // the random number via libsecp256k1 in the recommended secure way:
                    let privkey = PrivateKey::generate(nw);
                    // persist the newly created key in WIF format to the location
                    // requested:
                    let mut buf = Vec::new();
                    let res = write!(&mut buf, "{}", privkey);
                    if !res.is_ok(){
                        resp.accepted = -3;
                        return Ok(resp);
                    }
                    // encrypt the data using password `encryption_password`:
                    // (note use of 'expect' OK because the encryption operation
                    // failing is a logic error):
                    let encrypted_data = encrypt(&buf, &args.encryption_password.as_bytes())
                    .expect("Failed to encrypt");
                    write_file_string(&resp.privkey_file_loc.clone().unwrap(), encrypted_data);
                    let secp = Secp256k1::new();
                    // this is the standard way to generate plain-vanilla taproot addresses:
                    // it is not "raw" (rawtr in descriptors) but it applies a merkle root of
                    // null as the tweak to the internal pubkey. This is what e.g. Sparrow is
                    // looking for as "p2tr" type.
                    let addr = Address::p2tr(&secp,
                         XOnlyPublicKey::from(privkey.public_key(&secp).inner),
                          None, privkey.network);
                    resp.address = Some(addr.to_string());
                    resp.accepted = 0;
                    Ok(resp)
                }
            }

            #[derive(Serialize, Deserialize)]
            pub struct RPCAuditProofRequest {
                pub keyset: String,
                pub depth: i32,
                pub generators_length_log_2: u8,
                pub user_label: String,
                pub privkeys_values_file_loc: String,
                pub bc_network: String,
                pub audit_range_min: u64, //k
                pub audit_range_exponent: usize, //n
            }

            #[derive(Serialize, Deserialize)]
            pub struct RPCAuditProofResponse {
                pub keyset: Option<String>,
                    pub user_label: Option<String>,
                    pub context_label: Option<String>,
                    pub audit_proof: Option<String>,
                    pub accepted: i32,
            }

            pub struct RPCAuditProver{
                pub prover_verifier_args:  RPCProverVerifierArgs,
            }

            #[export_impl]
            impl RPCAuditProver {
                #[export_method]
                pub async fn audit_prove(&self, args: RPCAuditProofRequest)
                -> Result<RPCAuditProofResponse, String>{
                    let mut resp: RPCAuditProofResponse = RPCAuditProofResponse{
                        keyset: None, // note that this needs to be parsed out
                        user_label: Some(args.user_label.clone()),
                        context_label: None, // as above for keyset
                        audit_proof: None,
                        accepted: 0,
                    };
                    let pva = &self.prover_verifier_args;

                    // tasks:
                    // 0. get_generators for xG + vJ + rH representations.
                    // However "H" will be the default blinding basepoint from
                    // "pc_gens " from curve trees, and will be the same between
                    // the curve tree proofs and the sum range proof; it will then
                    // be applied to the custom representation proof.
                    let (G, J) = get_audit_generators();
                    print_affine_compressed(J, "J");
                    // 1. read in a a set of privkeys from the file,
                    // and associated values of utxos, as two vectors.
                    let res = get_privkeys_and_values(
                        &args.privkeys_values_file_loc);
                    if res.is_err(){
                        resp.accepted = -1;
                        return Ok(resp);
                    }
                    let (privkeys_wif, values) = res.unwrap();
                    // 1a Form list of commitments as xG + vJ
                    let mut comms: Vec<Affine<SecpConfig>> = Vec::new();
                    let secp = Secp256k1::new();
                    type F = <ark_secp256k1::Affine as AffineRepr>::ScalarField;
                    let mut privkeys: Vec<F> = Vec::new();
                    for i in 0..privkeys_wif.len() {
                        let privkeyres1 =
                        PrivateKey::from_wif(
                            &privkeys_wif[i]);
                        let privkey: PrivateKey = privkeyres1.unwrap();
                        let untweaked_key_pair: UntweakedKeypair =
                        UntweakedKeypair::from_secret_key(
                            &secp, &privkey.inner);
                        let tweaked_key_pair =
                        untweaked_key_pair.tap_tweak(&secp, None);
                        let privkey_bytes = tweaked_key_pair.
                        to_inner().secret_bytes();
                        let privhex = hex::encode(&privkey_bytes);
    
                        let mut x =
                        decode_hex_le_to_F::<F>(&privhex);
                        let mut P = G.mul(x).into_affine();
                        // Since we are using BIP340 pubkeys on chain, we must use the correct
                        // sign of x, such that the parity of x*G is even.
                        // This is because, the public servers/verifiers have no choice
                        // but to assume that the public representation (a BIP340 key)
                        // corresponds to that parity, when they do the P +vG arithmetic.
                        // TODO refactor this, it is reused in key_processing.rs:
                        let yval: SecpBase = *P.y().unwrap();
                        let yvalint: BigInteger256 = BigInteger256::from(yval);
                        if yvalint.0[0] % 2 == 1 {
                            x = -x;
                            P = -P;}
                        privkeys.push(x);
                        let v = F::from(values[i]);
                        // C = xG + vJ (note *un*blinded)
                        comms.push(P.add(J.mul(v)).into_affine());
                    }
                

                    // 2. Call auditproof.create with:
                    //pub fn create(k: u64,n: usize, G: &Affine<P0>, H: &Affine<P0>, J: &Affine<P0>, commitment_list: Vec<Affine<P0>>,
                    //witness section: privkeys: Vec<P0::ScalarField>, values: Vec<u64>,
                    // proof parameters: depth: usize, generators_length_log_2: usize, keyset: &str)
                    //
                    // for this, we take k, n, depth, genlog, keyset from args.
                    // we take privkeys and values from step 1
                    // we take G, H, J from step 0
                    // and we take commitments by step 1a
                    let prf: AuditProof<SecpBase, SecpConfig, SecqConfig> = 
                    AuditProof::<SecpBase, SecpConfig, SecqConfig>::create(
                        args.audit_range_min,
                        args.audit_range_exponent,
                        &G,
                        &J,
                        comms,
                        privkeys,
                        values,
                        &pva.keyset_file_locs[0],
                        &pva.curve_trees[0],
                        &pva.sr_params,
                        &args.user_label
                    ).unwrap(); // todo Result not working?
                    //if prfres.is_err(){
                    //    resp.accepted = -2;
                    //    return Ok(resp);
                    //}
                    //let auditproof = prfres.unwrap();
                    //
                    // 4. Do a sanity check veriy call.
                    //
                    let verifresult = prf.verify(&G, &J,
                        &pva.curve_trees[0], // assuming one is that OK? TODO
                        &pva.sr_params,
                        &args.user_label);
                    if verifresult.is_err() {
                        resp.accepted = -2;
                        return Ok(resp);
                    }
                    //let verifres = auditproof
                    // 5. Update the response object and return the serialization of the proof.
                    let mut buf = Vec::with_capacity(prf.serialized_size(Compress::Yes));
                    if prf.serialize_compressed(&mut buf).is_err(){
                        resp.accepted = -3;
                        return Ok(resp);
                    };
                    let encoded = BASE64_STANDARD.encode(buf);
                    resp.audit_proof = Some(encoded);
                    //
                    // NB This call may take some non trivial time so pay attention to timeout.
                    Ok(resp)
                }
            }
            #[derive(Serialize, Deserialize)]
            pub struct RPCProverRequest {
                pub keyset: String,
                pub depth: i32,
                pub generators_length_log_2: u8,
                pub user_label: String,
                pub privkey_file_loc: String,
                pub bc_network: String, // this is needed for parsing private keys
                pub encryption_password: String,
            }
        
            #[derive(Debug, Serialize, Deserialize)]
            pub struct RPCProverResponse {
                    pub keyset: Option<String>,
                    pub user_label: Option<String>,
                    pub context_label: Option<String>,
                    pub proof: Option<String>,
                    pub key_image: Option<String>,
                    pub accepted: i32,
            }
        
            pub struct RPCProver{
                pub prover_verifier_args:  RPCProverVerifierArgs,
            }

            #[export_impl]
            impl RPCProver {
                #[export_method]
                pub async fn prove(&self, args: RPCProverRequest) -> Result<RPCProverResponse, String>{
                    let pva = &self.prover_verifier_args;
                    let mut resp: RPCProverResponse = RPCProverResponse{
                        keyset: None, // note that this needs to be parsed out
                        user_label: Some(args.user_label.clone()),
                        context_label: None, // as above for keyset
                        proof: None,
                        key_image: None,
                        accepted: -1
                    };
                    // parse out the single (context label, keyset pair) provided
                    // by the caller's request, and then check that they are included
                    // in the list supported by this server.
                    let (mut cls, mut kss) = match get_params_from_config_string(args.keyset){
                        Ok(x) => x,
                        Err(_) => {resp.accepted = -9;
                                   return Ok(resp)
                                  }
                    };
                    if kss.len() != 1 || cls.len() != 1 {
                        resp.accepted = -2;
                        return Ok(resp);
                    }
                    let keyset = match kss.pop(){
                        Some(x) => x,
                        None => {resp.accepted = -9;
                                 return Ok(resp)}
                    };
                    let context_label = match cls.pop(){
                        Some(x) => x,
                        None => {resp.accepted = -9;
                                 return Ok(resp)}
                    };
                    if !(pva.context_labels.contains(&context_label)) {
                        resp.accepted = -3;
                        return Ok(resp);
                    }
                    if !(pva.keyset_file_locs.contains(&keyset)){
                        resp.accepted = -4;
                        return Ok(resp);
                    }
                    type F = <ark_secp256k1::Affine as AffineRepr>::ScalarField;
                    let nw = match args.bc_network.clone().as_str() {
                        "mainnet" => bitcoin::Network::Bitcoin,
                        "signet" => bitcoin::Network::Signet,
                        "regtest" => bitcoin::Network::Regtest,
                    _ => {resp.accepted = -5;
                          return Ok(resp);},
                    };
                    let secp = Secp256k1::new();
                    // read privkey from encrypted file;
                    // we prioritize WIF format for compatibility
                    // with external wallets, but if that fails, we attempt to read it
                    // as raw hex:
                    let privkey_file_str = args.privkey_file_loc.clone();
                    let encrypted_privwif = match std::fs::read(&privkey_file_str) {
                        Ok(data) => data,
                        Err(e) => {resp.accepted = -6;
                            println!("Got error: {:?}", e);
                            return Ok(resp);}
                    };
                    let privwifres = decrypt(&encrypted_privwif,
                    &args.encryption_password.as_bytes());
                    if privwifres.is_err(){
                        resp.accepted = -14;
                        return Ok(resp);
                    }
                    let privwif = privwifres.unwrap();
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

                    let privkeyres1 = PrivateKey::from_wif(
                        std::str::from_utf8(&privwif).unwrap());
                    let privkey: PrivateKey;
                    if privkeyres1.is_err(){
                        let privkeyres2 = PrivateKey::from_slice(
                            &hex::decode(privwif).unwrap(),
                        nw);
                        if privkeyres2.is_err(){
                            resp.accepted = -7;
                            return Ok(resp);
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
                    print_affine_compressed(P, "request pubkey");
                    let gctwptime = Instant::now();
                    let (p0proof,
                        p1proof,
                        path,
                        r,
                        H,
                        root,
                        privkey_parity_flip) = match get_curve_tree_with_proof::<
                    SecpBase,
                    SecpConfig,
                    SecqConfig>(
                            args.depth.try_into().unwrap(),
                            args.generators_length_log_2.try_into().unwrap(),
                            &keyset, P) {
                                Err(_) => {resp.accepted = -8;
                                    return Ok(resp);}
                                Ok((p0proof,
                                    p1proof,
                                    path,
                                r,
                                H,
                                root,
                                privkey_parity_flip)) => (p0proof,
                                    p1proof,
                                    path,
                                r,
                                H,
                                root,
                                privkey_parity_flip),
                            };

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
                            args.user_label.as_bytes()
                    );
                    let mut buf = Vec::with_capacity(proof.serialized_size(Compress::Yes));
                    if proof.serialize_compressed(&mut buf).is_err(){
                        resp.accepted = -10;
                        return Ok(resp);
                    };

                        let mut verifier = Transcript::new(APP_DOMAIN_LABEL);
                        // here following the principle that internal logic errors
                        // should crash:
                        assert!(proof
                            .verify(
                                &mut verifier,
                                &D,
                                &E,
                                &G,
                                &H,
                                &J,
                                context_label.as_bytes(),
                                args.user_label.as_bytes()
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
                    if D.serialize_compressed(&mut buf2).is_err() {
                        resp.accepted = -11;
                        return Ok(resp)
                    };
                    if E.serialize_compressed(&mut buf2).is_err() {
                        resp.accepted = -11;
                        return Ok(resp)
                    };
                    if proof.serialize_with_mode(&mut buf2, Compress::Yes).is_err() {
                        resp.accepted = -10;
                        return Ok(resp)
                    };
                    if p0proof.serialize_compressed(&mut buf2).is_err() {
                        resp.accepted = -12;
                        return Ok(resp)
                    };
                    if p1proof.serialize_compressed(&mut buf2).is_err() {
                        resp.accepted = -12;
                        return Ok(resp)
                    };
                    if path.serialize_compressed(&mut buf2).is_err() {
                        resp.accepted = -13;
                        return Ok(resp)
                    };
                    if root.serialize_compressed(&mut buf2).is_err() {
                        resp.accepted = -11;
                        return Ok(resp)
                    };

                    let encoded = BASE64_STANDARD.encode(buf2);
                    print_affine_compressed(root, "root");
                    let mut e = Vec::new();
                    if E.serialize_compressed(&mut e).is_err(){
                        resp.accepted = -11;
                        return Ok(resp)
                    };
                    let resp: RPCProverResponse = RPCProverResponse{
                        keyset: Some(keyset),
                        user_label: Some(args.user_label),
                        context_label: Some(context_label),
                        proof: Some(encoded),
                        key_image: Some(hex::encode(&e)),
                        accepted: 0,
                    };
                    Ok(resp)
                }
            }

    // The request is just a message that
    // a caller can use to distinguish different calls
    #[derive(Serialize, Deserialize)]
    pub struct RPCEchoRequest {
        pub msg: String,
    }
    // The response just adds the "autct-ok"
    // response to the unique message
    #[derive(Serialize, Deserialize, Debug)]
    pub struct RPCEchoResponse {
        pub response_msg: String,
    }
    pub struct RPCEcho {}

    #[export_impl]
    impl RPCEcho {
    #[export_method]
    pub async fn echo(&self, args: RPCEchoRequest) ->
    Result<RPCEchoResponse, String>{
        Ok(RPCEchoResponse{
            response_msg: "aut-ct".to_string() + &args.msg,
        })
        }
    }

    #[derive(Serialize, Deserialize)]
    pub struct RPCAuditProofVerifyRequest {
        pub keyset: String,
        pub context_label: String,
        pub proof: String,
        pub depth: i32,
        pub generators_length_log_2: u8,
        pub user_label: String,
    }
    #[derive(Serialize, Deserialize, Debug)]
    pub struct RPCAuditProofVerifyResponse {
        pub keyset: String,
        pub context_label: String,
        pub accepted: i32,
        pub audit_range_min: u64, //k
        pub audit_range_exponent: usize, //n 
    }

    pub struct RPCAuditProofVerifier {
        pub prover_verifier_args: RPCProverVerifierArgs,
    }

    #[export_impl]
    impl RPCAuditProofVerifier {
        #[export_method]
        pub async fn auditverify(&self,
            args: RPCAuditProofVerifyRequest) ->
            Result<RPCAuditProofVerifyResponse, String>{
                let verif_request = args;
                let pva = &self.prover_verifier_args;
                let (G, J) = get_audit_generators();
                let mut resp: RPCAuditProofVerifyResponse =
                RPCAuditProofVerifyResponse{
                    keyset: verif_request.keyset.clone(),
                    context_label: verif_request.context_label.clone(),
                    accepted: -100,
                    audit_range_min: u64::MAX,
                    audit_range_exponent: 0usize,
                };
                let decoded_proof = match BASE64_STANDARD
                .decode(verif_request.proof) {
                    Ok(x) => x,
                    Err(_) => {resp.accepted = -1;
                        return Ok(resp);},
                };
    
                let mut cursor = Cursor::new(decoded_proof);
                let prf = match AuditProof::<SecpBase, SecpConfig, SecqConfig>
                ::deserialize_with_mode(&mut cursor, Compress::Yes, Validate::Yes ){
                        Ok(x) => x,
                        Err(e) => {
                            println!("Got error in deserialize: {}", e);
                            resp.accepted = -2;
                            return Ok(resp)
                        }
                };
                // we fill in the audit range values that were
                // serialized into the proof here,
                // as they are part of the claim, whether proven or not:
                resp.audit_range_min = prf.k;
                resp.audit_range_exponent = prf.n;
                // we assume that audit mode only ever
                // uses one keyset in the definition, hence [0].
                // Notice that here we aren't even bothering
                // to check that the keyset the client asked for
                // matches the one the server is serving, so that's
                // a TODO as the client might not have any idea why
                // their proofs aren't verifying!
                let verifresult = prf.verify(&G, &J,
                        &pva.curve_trees[0],
                        &pva.sr_params,
                        &verif_request.user_label);
                if verifresult.is_err() {
                        resp.accepted = -3;
                        return Ok(resp);
                }
                else {
                    // All checks successful, return resource
                    println!("Verifying audit proof passed");
                    resp.accepted = 1;
                    Ok(resp)
                }   
        }
    }

    #[derive(Serialize, Deserialize)]
    pub struct RPCProofVerifyRequest {
        pub keyset: String,
        pub user_label: String,
        pub context_label: String,
        pub application_label: String,
        pub proof: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct RPCProofVerifyResponse {
            pub keyset: String,
            pub user_label: String,
            pub context_label: String,
            pub application_label: String,
            pub accepted: i32,
            // TODO possibly remove this;
            // the resource string will be the
            // responsibility of the caller,
            // for now we just leave a default string
            // that could be used somehow in future versions:
            pub resource_string: Option<String>,
            pub key_image: Option<String>,
    }
    // This struct encapsulates the state maintained by the verifying
    // server (mostly to make the actual rea-time verification fast)
    // Note that this does NOT currently include the context label,
    // allowing the verifier to 'blindly' serve requests for any context;
    // the callback code that ends up assiging resource strings to users,
    // should be able to decide the business logic of that based on the
    // context label given in the Request object.
    pub struct RPCProofVerifier{
        pub prover_verifier_args: RPCProverVerifierArgs,
    }
    #[export_impl]
    impl RPCProofVerifier {

        // the two arguments are:
        // a String containing the name of the file containing the pubkeys
        // a bytestring (Vec<u8>) containing the serialized proof of ownership
        // of a key in the set, corresponding to a given key image.
        // The first argument is currently (TODO) only used as a sanity check:
        // if it is not the same filename as the server has pre-loaded, we return
        // an error.
        // The return values are defined (as strings) in autct.rs
        #[export_method]
        pub async fn verify(&self, args: RPCProofVerifyRequest) -> Result<RPCProofVerifyResponse, String>{
            let verif_request = args;

            let mut resp: RPCProofVerifyResponse = RPCProofVerifyResponse{
                keyset: verif_request.keyset.clone(),
                // note that this must be set by the *caller*:
                user_label: verif_request.user_label.clone(),
                application_label: String::from_utf8(APP_DOMAIN_LABEL.to_vec()).unwrap(),
                context_label: verif_request.context_label.clone(),
                accepted: -100,
                resource_string: None,
                key_image: None,
            };

            // get the appropriate J value, and Curve Tree,
            // by finding the index of the keyset, since
            // we set the contexts in the same order as the keysets
            // (and therefore Trees):
            let idx = match self.prover_verifier_args.context_labels.iter().position(
                |x| x == &verif_request.context_label){
                    Some(i) => i,
                    None => {resp.accepted = -4;
                             return Ok(resp)}
                };
            let decoded_proof = match BASE64_STANDARD.decode(verif_request.proof) {
                Ok(x) => x,
                Err(_) => {resp.accepted = -5;
                    return Ok(resp);},
            };

            let mut cursor = Cursor::new(decoded_proof);
            // deserialize the components of the PedDLEQ proof first and verify it:
            let D = match Affine::<SecpConfig>::deserialize_compressed(
                &mut cursor){
                    Ok(x) => x,
                    Err(_) => {
                        resp.accepted = -6;
                        return Ok(resp)
                    }
                };
            let E = match Affine::<SecpConfig>::deserialize_compressed(
                    &mut cursor){
                    Ok(x) => x,
                    Err(_) => {
                        resp.accepted = -6;
                        return Ok(resp)
                    }
                };
            let proof = match PedDleqProof::<Affine<SecpConfig>>::deserialize_with_mode(
                &mut cursor, Compress::Yes, Validate::Yes){
                    Ok(x) => x,
                    Err(_) => {
                        resp.accepted = -7;
                        return Ok(resp)
                    }
                };
            let mut transcript = Transcript::new(APP_DOMAIN_LABEL);
            let verif_result = proof
            .verify(
                &mut transcript,
                &D,
                &E,
                &self.prover_verifier_args.G,
                &self.prover_verifier_args.H,
                &self.prover_verifier_args.Js[idx],
                verif_request.context_label.as_bytes(),
                verif_request.user_label.as_bytes()
            );
            let mut b_E = Vec::new();
            // failure is an internal code logic error,
            // since it does not depend on external input,
            // hence we leave the potential panic:
            E.serialize_compressed(&mut b_E).expect("Failed to serialize point E");
            let str_E = hex::encode(&b_E).to_string();
            if !verif_result
                    .is_ok(){
                        println!("PedDLEQ proof is invalid");
                        resp.accepted = -2;
                        resp.key_image = Some(str_E);
                        return Ok(resp);
                    }
            // check early if the now-verified key image (E) is a reuse-attempt:
            if self.prover_verifier_args.ks[idx].lock().unwrap().is_key_in_store(E) {
                println!("Reuse of key image disallowed: ");
                print_affine_compressed(E, "Key image value");
                resp.accepted = -3;
                resp.key_image = Some(str_E);
                return Ok(resp);
            }
            // if it isn't, then it counts as used now:
            self.prover_verifier_args.ks[idx].lock().unwrap().add_key(E).expect("Failed to add keyimage to store.");
            // Next, we deserialize and validate the curve tree proof.
            // TODO replace these `expect()` calls; we need to return
            // an 'invalid proof format' error if they send us junk, not crash!
            let p0proof = 
            R1CSProof::<Affine<SecpConfig>>::deserialize_with_mode(
                &mut cursor, Compress::Yes, Validate::Yes).expect("Failed p0proof deserialize");
            let p1proof = 
            R1CSProof::<Affine<SecqConfig>>::deserialize_with_mode(
                &mut cursor, Compress::Yes, Validate::Yes).expect("Failed p1proof deserialize");
            let path = 
            SelectAndRerandomizePath::<SecpConfig, SecqConfig>::deserialize_with_mode(
                &mut cursor, Compress::Yes, Validate::Yes).expect("failed path deserialize");

            // TODO this is part of the 'can we handle different root parity' problem:
            let prover_root = Affine::<SecpConfig>::deserialize_compressed(
                    &mut cursor).expect("Failed to deserialize root");
            let timer1 = Instant::now();
            let claimed_D = verify_curve_tree_proof(
                path.clone(), &self.prover_verifier_args.sr_params, 
                &self.prover_verifier_args.curve_trees[idx],
                &p0proof, &p1proof, prover_root);
            let claimed_D_result = match claimed_D {
                Ok(x) => x,
                Err(_x) => {
                    resp.accepted = -1;
                    resp.key_image = Some(str_E);
                    return Ok(resp)},
            };
            println!("Elapsed time for verify_curve_tree_proof: {:.2?}", timer1.elapsed());
            // TODO check if any reuse is possible with sign flip:
            if claimed_D_result != D && claimed_D_result != -D {
                println!("Curve tree proof did not match PedDLEQ proof");
                resp.accepted = -1;
                resp.key_image = Some(str_E);
                Ok(resp)
            }
            else {
                // All checks successful, return resource
                println!("Verifying curve tree passed and it matched the key image. Here is the key image: {}",
                str_E);
                resp.accepted = 1;
                // as per comment in Response struct:
                resp.resource_string = Some("soup-for-you".to_string());
                resp.key_image = Some(str_E);
                Ok(resp)
            }
        }
    }
}

