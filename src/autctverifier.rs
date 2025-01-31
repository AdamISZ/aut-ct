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

// This function thows assertion errors if the given
// set (curve_tree, p0proof, p1proof, path_commitments, root)
// do not validate ('curve_tree' is generated locally by the
// verifier from the keyset, and that is compared against the other
// items, which are all deserialized from the proof string given
// by the Prover)
pub fn verify_curve_tree_proof<
const BRANCHING_FACTOR: usize,
const BATCH_SIZE: usize,
    F: PrimeField,
    P0: SWCurveConfig<BaseField = F> + Copy,
    P1: SWCurveConfig<BaseField = P0::ScalarField, ScalarField = P0::BaseField> + Copy,
>(
    path_commitments: SelectAndRerandomizePath<BRANCHING_FACTOR, P0, P1>,
    sr_params: &SelRerandParameters<P0, P1>,
    curve_tree: &CurveTree<BRANCHING_FACTOR, BATCH_SIZE, P0, P1>,
    p0proof: &R1CSProof<Affine<P0>>,
    p1proof: &R1CSProof<Affine<P1>>,
    root: Affine<P0>,
) -> Result<Affine<P0>, R1CSError> {
    let path_commitments2:
    &mut SelectAndRerandomizePath<BRANCHING_FACTOR, P0, P1>
    = &mut path_commitments.clone();
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

    curve_tree.select_and_rerandomize_verification_commitments(
        path_commitments2);

    let verifier_root: Affine<P0> = *path_commitments2.even_commitments.first().unwrap();

    // check also that the path's first node matches the root of the tree that we
    // constructed from the keyset
    assert_eq!(root, verifier_root);

    // return the last commitment so that it can be checked
    // that it matches the D value from the Ped-DLEQ:
    Ok(path_commitments.get_rerandomized_leaf())
}



