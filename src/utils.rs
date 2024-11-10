#![allow(non_snake_case)]
extern crate rand;
extern crate alloc;
extern crate ark_secp256k1;

use ark_ff::{Field, PrimeField};
use ark_ec::AffineRepr;
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::short_weierstrass::Affine;
use relations::curve_tree::CurveTree;
use std::error::Error;
use ark_serialize::CanonicalSerialize;
use relations::curve_tree::{SelRerandParameters, SelectAndRerandomizePath};
use bulletproofs::r1cs::R1CSProof;
use bulletproofs::r1cs::Prover;
use merlin::Transcript;

// all transcripts created in this project should be
// initialized with this name:
pub const APP_DOMAIN_LABEL: &[u8] = b"autct-v1.0";
pub const BRANCHING_FACTOR: usize = 1024;
pub const BATCH_SIZE: usize = 1;
// specific to an application; this default is only for tests.
// Should be set in the config file, in the field `context_label`.
pub const CONTEXT_LABEL: &[u8] = b"default-app-context-label";
// specific to a protocol-instance run; typically it should be
// an ephemeral user id. Like the above, the default exists
// primarily for testing
pub const USER_STRING: &[u8] = b"name-goes-here";

pub fn print_field_elem_hex<F: PrimeField>(x: &F, name: &str) {
    let mut b = Vec::new();
    x.serialize_compressed(&mut b).expect("Failed to serialize field element");
    println!("This is the value of {}: {:#?}", name, hex::encode(&b));
}

pub fn print_affine_compressed<F: PrimeField,
P0: SWCurveConfig<BaseField = F> + Copy>(pt: Affine<P0>, name: &str) {
    let mut b = Vec::new();
        pt.serialize_compressed(&mut b).expect("Failed to serialize point");
    println!("This is the value of {}: {:#?}", name, hex::encode(&b));
}

// protocol requires three generators G, H, J (ignoring
// bulletproofs itself):
// G is a known constant generator.
// H is currently gotten from the CurveTree rerandomization,
// because we have to use the same blinding element in both
// sub protocols. (but note, we are currently using a default
// value, and the verifier must ensure that it is NUMS, so
// TODO: add this back here.)
// J must be defined globally for the given context, so we give
// two bits of context: an application specific label, and a tree
// root (which ensures both sides are working on the same Curve
// Tree).
pub fn get_generators<F: PrimeField,
P0: SWCurveConfig<BaseField = F> + Copy>(
    label: &[u8]) -> Affine<P0>{
    // in line with above comments, probably peel out the
    // algorithm for J into a separate sub-function, because
    // we will probably want to add an optional counter.
    // for now:
    // format "J"||app-label, then pass through string-to-point algo.
    // see issue #7, #8 for discussion.
    let mut b = Vec::new();
    b.extend(b"J"); //TODO <- not correct, make it an arg.
    b.extend(label);
    affine_from_bytes_tai::<Affine<P0>>(&b)
}

pub fn field_as_bytes<F: Field>(field: &F) -> Vec<u8> {
    let mut bytes = Vec::new();
    if let Err(e) = field.serialize_compressed(&mut bytes) {
        panic!("{}", e)
    }
    bytes
}

// an effective generation of NUMS deterministically:
pub fn affine_from_bytes_tai<C: AffineRepr>(bytes: &[u8]) -> C {
    extern crate crypto;
    use crypto::digest::Digest;
    use crypto::sha2::Sha256;

    for i in 0..=u8::max_value() {
        let mut sha = Sha256::new();
        sha.input(bytes);
        sha.input(&[i]);
        let mut buf = [0u8; 32];
        sha.result(&mut buf);
        let res = C::from_random_bytes(&buf);
        if let Some(point) = res {
            return point;
        }
    }
    panic!()
}

pub fn get_curve_tree<
F: PrimeField,
P0: SWCurveConfig<BaseField = F> + Copy,
P1: SWCurveConfig<BaseField = P0::ScalarField, ScalarField = P0::BaseField> + Copy,>(
    leaf_commitments: &Vec<Affine<P0>>,
    depth: usize,
    sr_params: &SelRerandParameters<P0, P1>) -> (CurveTree<BRANCHING_FACTOR, BATCH_SIZE, P0, P1>, Affine<P0>){
    //let leaf_commitments = get_leaf_commitments(file_loc);
    let curve_tree = CurveTree::<BRANCHING_FACTOR, BATCH_SIZE, P0, P1>::from_set(
        leaf_commitments, sr_params, Some(depth));
    (curve_tree, sr_params.even_parameters.pc_gens.B_blinding)
}

pub fn get_key_index_from_hex_leaves(leaf_commitments: &Vec<&str>,
    our_pubkey_hex: String) -> Result<i32, Box<dyn Error>> {
        let key_index = match leaf_commitments.iter().position(|x| *x  == our_pubkey_hex) {
            None => {return Err("provided pubkey not found in the set".into());},
            Some(ks) => {ks.try_into().unwrap()}
        };
        Ok(key_index)
}

/// Derive the index where our pubkey is in the list.
pub fn get_key_index_from_leaves<F: PrimeField,
P0: SWCurveConfig<BaseField = F> + Copy,
P1: SWCurveConfig<BaseField = P0::ScalarField, ScalarField = P0::BaseField> + Copy,>(
    leaf_commitments: &Vec<Affine<P0>>,
    our_pubkey: Affine<P0>) -> Result<i32, Box<dyn Error>> {
    let key_index = match leaf_commitments.iter().position(|&x| x  == our_pubkey) {
        None => {return Err("provided pubkey not found in the set".into());},
        Some(ks) => {ks.try_into().unwrap()}
    };
    Ok(key_index)
}

pub fn get_curve_tree_proof_from_curve_tree<
F: PrimeField,
P0: SWCurveConfig<BaseField = F> + Copy,
P1: SWCurveConfig<BaseField = P0::ScalarField, ScalarField = P0::BaseField> + Copy,
>(
    key_index: i32,
    curve_tree: &CurveTree<BRANCHING_FACTOR, BATCH_SIZE, P0, P1>,
    sr_params: &SelRerandParameters<P0, P1>,
) -> Result<(R1CSProof<Affine<P0>>, R1CSProof<Affine<P1>>,
SelectAndRerandomizePath<BRANCHING_FACTOR, P0, P1>,
P0::ScalarField,
Affine<P0>, Affine<P0>), Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();

    let p0_transcript = Transcript::new(b"select_and_rerandomize");
    let mut p0_prover: Prover<_, Affine<P0>> =
        Prover::new(&sr_params.even_parameters.pc_gens, p0_transcript);

    let p1_transcript = Transcript::new(b"select_and_rerandomize");
    let mut p1_prover: Prover<_, Affine<P1>> =
        Prover::new(&sr_params.odd_parameters.pc_gens, p1_transcript);

    let b_blinding = sr_params.even_parameters.pc_gens.B_blinding;
    let (path_commitments, rand_scalar) =
    curve_tree.select_and_rerandomize_prover_gadget(
        key_index.try_into().unwrap(),
        0,
        &mut p0_prover,
        &mut p1_prover,
        &sr_params,
        &mut rng,
    );
    let mut newpath = path_commitments.clone();
    curve_tree.select_and_rerandomize_verification_commitments(
        &mut newpath);
    let root: Affine<P0> = *newpath.even_commitments.first().unwrap();
    let p0_proof = p0_prover
        .prove(&sr_params.even_parameters.bp_gens)
        .unwrap();
    let p1_proof = p1_prover
        .prove(&sr_params.odd_parameters.bp_gens)
        .unwrap();
    //let returned_rand = rand_scalar + r_offset;
    Ok((p0_proof, p1_proof, path_commitments,
     rand_scalar, b_blinding, root))
}

