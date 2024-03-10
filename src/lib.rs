#![allow(non_snake_case)]

pub mod peddleq;
pub mod utils;
pub mod autctverifier;
pub mod config;

extern crate rand;
extern crate alloc;
extern crate ark_secp256k1;

use utils::*;

use peddleq::PedDleqProof;
use autctverifier::verify_curve_tree_proof;
use bulletproofs::r1cs::R1CSProof;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};

use relations::curve_tree::SelectAndRerandomizePath;

use merlin::Transcript;

use ark_ec::short_weierstrass::Affine;
use ark_secp256k1::Config as SecpConfig;
use ark_secq256k1::Config as SecqConfig;

use std::io::Cursor;
use std::time::Instant;

pub mod rpc {
    use super::*;
    use relations::curve_tree::{CurveTree, SelRerandParameters};
    use toy_rpc::macros::export_impl;

    pub struct RPCProofVerifier{
        pub pubkey_filepath: String,
        pub sr_params: SelRerandParameters<SecpConfig, SecqConfig>,
        pub curve_tree: CurveTree<{BRANCHING_FACTOR}, SecpConfig, SecqConfig>,
        pub H: Affine<SecpConfig>
    }
    #[export_impl]
    impl RPCProofVerifier {

        // currently the only request in the API:
        // the two arguments are:
        // a String containing the name of the file containing the pubkeys
        // a bytestring (Vec<u8>) containing the serialized proof of ownership
        // of a key in the set, corresponding to a given key image.
        // The first argument is currently (TODO) only used as a sanity check:
        // if it is not the same filename as the server has pre-loaded, we return
        // an error.
        // The return values:
        // 1 means proof fully valid and key image accepted
        // -1 means the PedDLEQ proof for the rerandomized key is itself valid,
        // but that same rerandomized key does not verify against the Curve Tree.
        // -2 means that the PedDLEQ proof for the rerandomized key does not validate.
        // -3 (TODO) would mean that the proofs are valid but the key image is rejected
        //    as a double spend.
        // -4 The filename does not match the keyset which the RPC server is using (TODO,
        //    this will be removed, see other comments below about this.)
        #[export_method]
        pub async fn verify(&self, args: (String, Vec<u8>)) -> Result<i32, String>{
            let (pubkey_filepath, buf) = args;
            // TODO:
            // For now, we just check that the pubkey file requested
            // by the client corresponds to the pubkey set and curve tree
            // that we pre-loaded on startup.
            // In future we should have the server pre-load a whole set of
            // different curve trees and, more practically, create a client
            // call that loads a specific keyset and curve tree for future
            // verification calls.
            // Also we want to be able to return sensible errors like
            // "that pubkey set's curve tree does not exist/is not yet loaded".
            assert_eq!(pubkey_filepath, self.pubkey_filepath);
            let mut cursor = Cursor::new(buf);
            // deserialize the components of the PedDLEQ proof first and verify it:
            let D = Affine::<SecpConfig>::deserialize_compressed(
                &mut cursor).expect("Failed to deserialize D");
            let E = Affine::<SecpConfig>::deserialize_compressed(
                    &mut cursor).expect("Failed to deserialize E");
            let proof = PedDleqProof::<Affine<SecpConfig>>::deserialize_with_mode(
                &mut cursor, Compress::Yes, Validate::Yes).unwrap();
            let mut transcript = Transcript::new(APP_DOMAIN_LABEL);
            // TODO obv generators should be initialized on startup, but trivial cost:
            let (G, J) = get_generators();
            if !(proof
                    .verify(
                        &mut transcript,
                        &D,
                        &E,
                        &G,
                        &self.H,
                        &J
                    )
                    .is_ok()){
                        println!("PedDLEQ proof is invalid");
                        return Ok(-2);
                    }
            // Next, we deserialize and validate the curve tree proof.
            let p0proof = 
            R1CSProof::<Affine<SecpConfig>>::deserialize_with_mode(
                &mut cursor, Compress::Yes, Validate::Yes).expect("Failed p0proof deserialize");
            let p1proof = 
            R1CSProof::<Affine<SecqConfig>>::deserialize_with_mode(
                &mut cursor, Compress::Yes, Validate::Yes).expect("Failed p1proof deserialize");
            let path = 
            SelectAndRerandomizePath::<{BRANCHING_FACTOR}, SecpConfig, SecqConfig>::deserialize_with_mode(
                &mut cursor, Compress::Yes, Validate::Yes).expect("failed path deserialize");

            // TODO this is part of the 'can we handle different root parity' problem:
            let prover_root = Affine::<SecpConfig>::deserialize_compressed(
                    &mut cursor).expect("Failed to deserialize root");
            let timer1 = Instant::now();
            let claimed_D = verify_curve_tree_proof(
                path.clone(), &self.sr_params, &self.curve_tree, p0proof, p1proof, prover_root);
            let claimed_D_result = match claimed_D {
                Ok(x) => x,
                Err(_x) => return Ok(-1),
            };
            println!("Elapsed time for verify_curve_tree_proof: {:.2?}", timer1.elapsed());
            if claimed_D_result != D && claimed_D_result != -D {
                println!("Curve tree proof did not match PedDLEQ proof");
                Ok(-1)
            }
            else {
                // 4: If not assertion error, print out that it passed.
                let mut bufEfinal: Vec<u8> = Vec::new();
                E.serialize_compressed(&mut bufEfinal).expect("failed to serialize E");
                println!("Verifying curve tree passed and it matched the key image. Here is the key image: {:?}",
                hex::encode(&bufEfinal));
                // TODO here will be a check whether the token (=key image) passes, i.e. was it already used and stored.
                Ok(1)
            }
        }
    }
}

