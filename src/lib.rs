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
use toy_rpc::macros::export_impl;

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
        pub keyset_file_locs: Vec<String>,
        pub context_labels: Vec<String>,
        pub sr_params: SelRerandParameters<SecpConfig, SecqConfig>,
        pub curve_trees: Vec<CurveTree<SecpConfig, SecqConfig>>,
        pub G: Affine<SecpConfig>,
        pub H: Affine<SecpConfig>,
        pub Js: Vec<Affine<SecpConfig>>,
        pub ks: Vec<Arc<Mutex<keyimagestore::KeyImageStore<Affine<SecpConfig>>>>>,
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
        // -3 Means that the proofs are valid but the key image is rejected
        //    as a double spend.
        // -4 means that the keyset chosen does not match (see below)
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

            if !(self.context_labels.contains(&verif_request.context_label)) {
                resp.accepted = -4;
                return Ok(resp);
            }
            // get the appropriate J value, and Curve Tree,
            // by finding the index of the keyset, since
            // we set the contexts in the same order as the keysets
            // (and therefore Trees):
            // (TODO can fold in above existence check to this call;
            // but for now, this is guaranteed to succeed because of
            // that check.)
            let idx = self.context_labels.iter().position(
                |x| x == &verif_request.context_label).unwrap();
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
                &self.Js[idx],
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
            if self.ks[idx].lock().unwrap().is_key_in_store(E) {
                println!("Reuse of key image disallowed: ");
                print_affine_compressed(E, "Key image value");
                resp.accepted = -3;
                resp.key_image = Some(str_E);
                return Ok(resp);
            }
            // if it isn't, then it counts as used now:
            self.ks[idx].lock().unwrap().add_key(E).expect("Failed to add keyimage to store.");
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
                path.clone(), &self.sr_params, 
                &self.curve_trees[idx],
                p0proof, p1proof, prover_root);
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

