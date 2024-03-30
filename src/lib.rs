#![allow(non_snake_case)]

pub mod peddleq;
pub mod utils;
pub mod autctverifier;
pub mod config;
pub mod keyimagestore;

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

pub mod rpc {

    use super::*;
    use std::sync::{Arc, Mutex};
    use relations::curve_tree::{CurveTree, SelRerandParameters};

    #[derive(Serialize, Deserialize)]
    pub struct RPCProofVerifyRequest {
        pub keyset: String,
        pub user_label: String,
        pub context_label: String,
        pub application_label: String,
        pub proof: Vec<u8>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct RPCProofVerifyResponse {
            pub keyset: String,
            pub user_label: String,
            pub context_label: String,
            pub application_label: String,
            pub accepted: i32,
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
    pub struct RPCProofVerifier<const L: usize>{
        pub pubkey_filepath: String,
        pub sr_params: SelRerandParameters<SecpConfig, SecqConfig>,
        pub curve_tree: CurveTree<L, SecpConfig, SecqConfig>,
        pub G: Affine<SecpConfig>,
        pub H: Affine<SecpConfig>,
        pub J: Affine<SecpConfig>,
        pub ks: Arc<Mutex<keyimagestore::KeyImageStore<Affine<SecpConfig>>>>,
    }

    impl<const L: usize> RPCProofVerifier<{L}> {

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
        // -3 Means that the proofs are valid but the key image is rejected
        //    as a double spend.
        pub async fn verify(&self, args: RPCProofVerifyRequest) -> Result<RPCProofVerifyResponse, String>{
            let verif_request = args;

            let mut resp: RPCProofVerifyResponse = RPCProofVerifyResponse{
                keyset: self.pubkey_filepath.clone(),
                // note that this must be set by the *caller*:
                user_label: verif_request.user_label.clone(),
                application_label: String::from_utf8(APP_DOMAIN_LABEL.to_vec()).unwrap(),
                context_label: verif_request.context_label.clone(),
                accepted: -100,
                resource_string: None,
                key_image: None,
            };

            // TODO:
            // For now, we just check that the pubkey file requested
            // by the client corresponds to the keyset chosen by this process
            // on startup.
            // In future we should have the server pre-load a whole set of
            // different keysets and curve trees and, more practically, create a client
            // call that loads a specific keyset and curve tree for future
            // verification calls.
            // Also we want to be able to return sensible errors like
            // "that pubkey set's curve tree does not exist/is not yet loaded".
            if !(verif_request.keyset == self.pubkey_filepath) {
                resp.accepted = -4;
                return Ok(resp);
            }

            let mut cursor = Cursor::new(verif_request.proof);
            // deserialize the components of the PedDLEQ proof first and verify it:
            let D = Affine::<SecpConfig>::deserialize_compressed(
                &mut cursor).expect("Failed to deserialize D");
            let E = Affine::<SecpConfig>::deserialize_compressed(
                    &mut cursor).expect("Failed to deserialize E");
            let proof = PedDleqProof::<Affine<SecpConfig>>::deserialize_with_mode(
                &mut cursor, Compress::Yes, Validate::Yes).unwrap();
            let mut transcript = Transcript::new(APP_DOMAIN_LABEL);
            let verif_result = proof
            .verify(
                &mut transcript,
                &D,
                &E,
                &self.G,
                &self.H,
                &self.J,
                verif_request.context_label.as_bytes(),
                verif_request.user_label.as_bytes()
            );
            let mut b_E = Vec::new();
            E.serialize_compressed(&mut b_E).expect("Failed to serialize point");
            let str_E = hex::encode(&b_E).to_string();
            if !verif_result
                    .is_ok(){
                        println!("PedDLEQ proof is invalid");
                        resp.accepted = -2;
                        resp.key_image = Some(str_E);
                        return Ok(resp);
                    }
            // check early if the now-verified key image (E) is a reuse-attempt:
            if self.ks.lock().unwrap().is_key_in_store(E) {
                println!("Reuse of key image disallowed: ");
                print_affine_compressed(E, "Key image value");
                resp.accepted = -3;
                resp.key_image = Some(str_E);
                return Ok(resp);
            }
            // if it isn't, then it counts as used now:
            self.ks.lock().unwrap().add_key(E).expect("Failed to add keyimage to store.");
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
            SelectAndRerandomizePath::<L, SecpConfig, SecqConfig>::deserialize_with_mode(
                &mut cursor, Compress::Yes, Validate::Yes).expect("failed path deserialize");

            // TODO this is part of the 'can we handle different root parity' problem:
            let prover_root = Affine::<SecpConfig>::deserialize_compressed(
                    &mut cursor).expect("Failed to deserialize root");
            let timer1 = Instant::now();
            let claimed_D = verify_curve_tree_proof(
                path.clone(), &self.sr_params, &self.curve_tree, p0proof, p1proof, prover_root);
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
                resp.resource_string = Some("soup-for-you".to_string());
                resp.key_image = Some(str_E);
                Ok(resp)
            }
        }
    }

    // NOTE: The remaining code here is the expanded-out
    // code from using the macros `export_impl` and `export_method`
    // which previously were used for the above RPCProofVerifier
    // and verify() code (use `cargo expand --lib rpc > toafile.txt`).
    // The reason for this ugly/janky choice is that these macros do
    // not (as far as I can tell) support const generics, and throw
    // compilation error if you try to use them on a struct with such
    // a const generic, so I expanded out the macros and re-added L by hand.
    impl<const L: usize> RPCProofVerifier<{L}> {
        pub fn verify_handler(
            self: std::sync::Arc<Self>,
            mut deserializer: Box<
                dyn toy_rpc::erased_serde::Deserializer<'static> + Send,
            >,
        ) -> toy_rpc::service::HandlerResultFut {
            Box::pin(async move {
                let req: RPCProofVerifyRequest = toy_rpc::erased_serde::deserialize(
                        &mut deserializer,
                    )
                    .map_err(|e| toy_rpc::error::Error::ParseError(Box::new(e)))?;
                self.verify(req)
                    .await
                    .map(|r| {
                        Box::new(r)
                            as Box<
                                dyn toy_rpc::erased_serde::Serialize + Send + Sync + 'static,
                            >
                    })
                    .map_err(|err| err.into())
            })
        }
    }
    impl<const L: usize> toy_rpc::util::RegisterService for RPCProofVerifier<{L}> {
        fn handlers() -> std::collections::HashMap<
            &'static str,
            toy_rpc::service::AsyncHandler<Self>,
        > {
            let mut map = std::collections::HashMap::<
                &'static str,
                toy_rpc::service::AsyncHandler<RPCProofVerifier<L>>,
            >::new();
            map.insert("verify", RPCProofVerifier::verify_handler);
            map
        }
        fn default_name() -> &'static str {
            "RPCProofVerifier"
        }
    }
    pub struct RPCProofVerifierClient<'c, AckMode> {
        client: &'c toy_rpc::client::Client<AckMode>,
        service_name: &'c str,
    }
    impl<'c, AckMode> RPCProofVerifierClient<'c, AckMode> {
        pub fn verify<A>(&'c self, args: A) -> toy_rpc::client::Call<RPCProofVerifyResponse>
        where
            A: std::borrow::Borrow<RPCProofVerifyRequest> + Send + Sync
                + toy_rpc::serde::Serialize + 'static,
        {
            self.client.call("RPCProofVerifier.verify", args)
        }
    }
    pub trait RPCProofVerifierClientStub<AckMode> {
        fn r_p_c_proof_verifier<'c>(&'c self) -> RPCProofVerifierClient<AckMode>;
    }
    impl<AckMode> RPCProofVerifierClientStub<AckMode>
    for toy_rpc::client::Client<AckMode> {
        fn r_p_c_proof_verifier<'c>(&'c self) -> RPCProofVerifierClient<AckMode> {
            RPCProofVerifierClient {
                client: self,
                service_name: "RPCProofVerifier",
            }
        }
    }
}

