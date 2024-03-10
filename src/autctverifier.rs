#![allow(non_snake_case)]

extern crate rand;
extern crate alloc;
extern crate ark_secp256k1;

use crate::utils;

use bulletproofs::r1cs::R1CSError;
use bulletproofs::r1cs::R1CSProof;
use bulletproofs::r1cs::Verifier;

use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::PrimeField;


use relations::curve_tree::{SelRerandParameters, CurveTree, SelectAndRerandomizePath};

use merlin::Transcript;

use ark_ec::short_weierstrass::Affine;

use std::time::Instant;

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
    path_commitments: SelectAndRerandomizePath<L, P0, P1>,
    sr_params: &SelRerandParameters<P0, P1>,
    curve_tree: &CurveTree<L, P0, P1>,
    p0proof: R1CSProof<Affine<P0>>,
    p1proof: R1CSProof<Affine<P1>>,
    root: Affine<P0>,
) -> Result<Affine<P0>, R1CSError> {
    let timer2 = Instant::now();
    println!("Elapsed time for selrerand paramater generation: {:.2?}", timer2.elapsed());
    let secp_transcript = Transcript::new(b"select_and_rerandomize");
    let mut secp_verifier = Verifier::new(secp_transcript);
    let secq_transcript = Transcript::new(b"select_and_rerandomize");
    let mut secq_verifier = Verifier::new(secq_transcript);

    let beforeleaf = Instant::now();
    let _rerandomized_leaf = curve_tree.select_and_rerandomize_verifier_gadget(
        &mut secp_verifier,
        &mut secq_verifier,
        path_commitments.clone(),
        sr_params,
    );
    println!("Elapsed time for verifier gadget call: {:.2?}", beforeleaf.elapsed());
    let before = Instant::now();
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
    match secp_res {
        Ok(rest) => rest,
        Err(rest) => return Err(rest),
    };
    match secq_res {
        Ok(rest) => rest,
        Err(rest) => return Err(rest),
    };
    println!("Elapsed time for verifier calls: {:.2?}", before.elapsed());

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
    Ok(path_commitments.get_rerandomized_leaf())
}

pub fn get_curve_tree<
const L: usize,
F: PrimeField,
P0: SWCurveConfig<BaseField = F> + Copy,
P1: SWCurveConfig<BaseField = P0::ScalarField, ScalarField = P0::BaseField> + Copy,>(
    file_loc: &str,
    depth: usize,
    sr_params: &SelRerandParameters<P0, P1>) -> (CurveTree<L, P0, P1>, Affine<P0>){
    let leaf_commitments = utils::get_leaf_commitments(file_loc);
    let (permissible_points,
        _permissible_randomnesses) =
        utils::create_permissible_points_and_randomnesses(&leaf_commitments, sr_params);
    let curve_tree = CurveTree::<L, P0, P1>::from_set(
        &permissible_points, sr_params, Some(depth));
    assert_eq!(curve_tree.height(), depth);
    (curve_tree, sr_params.even_parameters.pc_gens.B_blinding)
}

