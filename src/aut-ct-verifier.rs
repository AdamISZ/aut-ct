#![allow(non_snake_case)]

extern crate rand;
extern crate alloc;
extern crate ark_secp256k1;

use autct::utils::*;

use autct::peddleq::PedDleqProof;
use bulletproofs::r1cs::R1CSProof;
use bulletproofs::r1cs::Verifier;
use alloc::vec::Vec;
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};

use relations::curve_tree::{SelRerandParameters, CurveTree, SelectAndRerandomizePath};

use merlin::Transcript;

use ark_ec::short_weierstrass::Affine;
use ark_secp256k1::{Config as SecpConfig, Fq as SecpBase};
use ark_secq256k1::Config as SecqConfig;

use std::fs;
use std::env;
use std::io::Cursor;

// This function thows assertion errors if the given
// set (curve_tree, p0proof, p1proof, path_commitments, root)
// do not validate ('curve_tree' is generated locally by the
// verifier from the keyset, and that is compared against the other
// items, which are all deserialized from the proof string given
// by the Prover)
pub fn verify_curve_tree_proof<
    const L: usize,
    F: PrimeField,
    P0: SWCurveConfig<BaseField = F> + Copy,
    P1: SWCurveConfig<BaseField = P0::ScalarField, ScalarField = P0::BaseField> + Copy,
>(
    generators_length_log_2: usize,
    path_commitments: SelectAndRerandomizePath<L, P0, P1>,
    curve_tree: &CurveTree<L, P0, P1>,
    p0proof: R1CSProof<Affine<P0>>,
    p1proof: R1CSProof<Affine<P1>>,
    root: Affine<P0>,
) -> Affine<P0> {
    // TODO we do *not* want to use randomness as input to the
    // universal hash function for permissible points, since that precludes
    // people independently creating the same tree of permissible points.
    let mut rng = rand::thread_rng();
    let generators_length = 1 << generators_length_log_2;

    let sr_params =
        SelRerandParameters::<P0, P1>::new(
            generators_length, generators_length, &mut rng);
    let secp_transcript = Transcript::new(b"select_and_rerandomize");
    let mut secp_verifier = Verifier::new(secp_transcript);
    let secq_transcript = Transcript::new(b"select_and_rerandomize");
    let mut secq_verifier = Verifier::new(secq_transcript);

    let _rerandomized_leaf = curve_tree.select_and_rerandomize_verifier_gadget(
        &mut secp_verifier,
        &mut secq_verifier,
        path_commitments.clone(),
        &sr_params,
    );
    let secq_res = secq_verifier.verify(
        &p1proof,
        &sr_params.odd_parameters.pc_gens,
        &sr_params.odd_parameters.bp_gens,
    );
    let secp_res = secp_verifier.verify(
        &p0proof,
        &sr_params.even_parameters.pc_gens,
        &sr_params.even_parameters.bp_gens,
    );
    assert_eq!(secq_res, secp_res);
    assert_eq!(secq_res, Ok(()));

    // check also that the path's first node matches the root of the tree that we
    // constructed from the keyset
    // TODO see comments on autct.rs construction of root also.
    let newpath = curve_tree.select_and_rerandomize_verification_commitments(
        path_commitments.clone());
    let root_is_odd = newpath.even_commitments.len() == newpath.odd_commitments.len();
    println!("Root is odd? {}", root_is_odd);
    let verifier_root: Affine<P0>;
    if !root_is_odd {
        verifier_root = *newpath.even_commitments.first().unwrap();
    }
    else {
        // derp, see above TODO
        panic!("Wrong root parity, should be even");
    }
    assert_eq!(root, verifier_root);

    // return the last commitment so that it can be checked
    // that it matches the D value from the Ped-DLEQ:
    path_commitments.get_rerandomized_leaf()
}

fn get_curve_tree<
const L: usize,
F: PrimeField,
P0: SWCurveConfig<BaseField = F> + Copy,
P1: SWCurveConfig<BaseField = P0::ScalarField, ScalarField = P0::BaseField> + Copy,>(
    file_loc: &str,
    depth: usize,
    generators_length_log_2: usize) -> (CurveTree<L, P0, P1>, Affine<P0>){
    let leaf_commitments = get_leaf_commitments(file_loc);
    let mut rng = rand::thread_rng();
    let generators_length = 1 << generators_length_log_2;
    let sr_params =
        SelRerandParameters::<P0, P1>::new(
            generators_length,
            generators_length, &mut rng);
    let (permissible_points,
        _permissible_randomnesses) =
        create_permissible_points_and_randomnesses(&leaf_commitments, &sr_params);
    let curve_tree = CurveTree::<L, P0, P1>::from_set(
        &permissible_points, &sr_params, Some(depth));
    assert_eq!(curve_tree.height(), depth);
    (curve_tree, sr_params.even_parameters.pc_gens.B_blinding)
}
pub fn main(){
    // User gives location of pubkey file as argument,
    // to reconstruct the tree.
    // TODO: we really want to only pass the root in *this*
    // tool, to save time; but, the verifier needs to have constructed
    // the (transparent, unblinded) tree at some point, right?
    // Needs investigation.
    let args: Vec<String> = env::args().collect();
    let pubkeys_filepath = &args[1];
    //
    // read from file into buf:
    let buf = fs::read("proof.txt").unwrap();
    // 1: Re-create the curve tree from pubkeys.txt
    let (curve_tree, H) = get_curve_tree::
    <256, SecpBase, SecpConfig, SecqConfig>(
        pubkeys_filepath,
        2, 11);
    let mut cursor = Cursor::new(buf);
    let D = Affine::<SecpConfig>::deserialize_compressed(
        &mut cursor).expect("Failed to deserialize D");
    let E = Affine::<SecpConfig>::deserialize_compressed(
            &mut cursor).expect("Failed to deserialize E");
    let proof = PedDleqProof::<Affine<SecpConfig>>::deserialize_with_mode(
        &mut cursor, Compress::Yes, Validate::Yes).unwrap();
    let mut transcript = Transcript::new(b"ped-dleq-test");
    let (G, J) = get_generators();
    assert!(proof
            .verify(
                &mut transcript,
                &D,
                &E,
                &G,
                &H,
                &J
            )
            .is_ok());
    // Next, we validate the curve tree proof.
    // Steps:
    // 2: Read p0proof, p1proof, path from the pre-existing buffer of proof.txt
    let p0proof = 
    R1CSProof::<Affine<SecpConfig>>::deserialize_with_mode(
        &mut cursor, Compress::Yes, Validate::Yes).expect("Failed p0proof deserialize");
    let p1proof = 
    R1CSProof::<Affine<SecqConfig>>::deserialize_with_mode(
        &mut cursor, Compress::Yes, Validate::Yes).expect("Failed p1proof deserialize");
    let path = 
    SelectAndRerandomizePath::<256, SecpConfig, SecqConfig>::deserialize_with_mode(
        &mut cursor, Compress::Yes, Validate::Yes).expect("failed path deserialize");

    // TODO this is part of the 'can we handle different root parity' problem:
    let prover_root = Affine::<SecpConfig>::deserialize_compressed(
            &mut cursor).expect("Failed to deserialize root");
    // 3: Call verify_curve_tree with (curve tree, p0proof, p1proof, path)
    use std::time::Instant;
    let before = Instant::now();
    let claimed_D = verify_curve_tree_proof(
        11, path.clone(), &curve_tree, p0proof, p1proof, prover_root);
    println!("Elapsed time: {:.2?}", before.elapsed());
    assert_eq!(claimed_D, D);

    // 4: If not assertion error, print out that it passed.
    let mut bufEfinal: Vec<u8> = Vec::new();
    E.serialize_compressed(&mut bufEfinal).expect("failed to serialize E");
    println!("Verifying curve tree passed and it matched the key image. Here is the key image: {:?}", hex::encode(&bufEfinal));

}


