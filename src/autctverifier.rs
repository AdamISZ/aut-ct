#![allow(non_snake_case)]

extern crate rand;
extern crate alloc;
extern crate ark_secp256k1;

use bulletproofs::r1cs::R1CSError;
use bulletproofs::r1cs::R1CSProof;
use bulletproofs::r1cs::Verifier;

use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::PrimeField;


use relations::curve_tree::{SelRerandParameters, CurveTree, SelectAndRerandomizePath};

use merlin::Transcript;

use ark_ec::short_weierstrass::Affine;

use std::time::Instant;

/// Given a Curve Tree select-and-rerandomize proof,
/// verifies it and returns an error if fails, or Ok() if not.
/// 
/// # Arguments
///
/// * `path_commitments` - a SelectandRerandomize path provide by the prover
///    (like a merkle path)
/// * `sr_params` - SelectandRerandomize parameters
/// * `curve_tree` - a Curve Tree object held by the verifier against which
///    the proof will be checked.
/// * `p0_proof` - a bulletproof over secp256k1
/// *  `p1_proof` - a bulletproof over secq256k1
/// *  `root` - the curve tree root claimed by the prover
///
/// # Returns:
/// 
///  * `Affine<P0>` - a single curve point which is the rerandomized leaf used in the proof
/// 
/// # Errors:
/// 
///  * R1CSError - if either of the two bulletproofs fails to verify
///  * AssertionError - if the root claimed by the prover does not match the verifier's Tree
/// 
/// # Panics:
///   * if the tree reconstructed from the prover does not have even parity
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
        panic!("Wrong root parity, should be even");
    }
    assert_eq!(root, verifier_root);

    // return the last commitment so that it can be checked
    // that it matches the D value from the Ped-DLEQ:
    Ok(path_commitments.get_rerandomized_leaf())
}



