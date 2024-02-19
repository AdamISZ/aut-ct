#![allow(non_snake_case)]

extern crate rand;
extern crate alloc;
extern crate ark_secp256k1;

use autct::utils::*;

use autct::peddleq::PedDleqProof;
use bulletproofs::r1cs::R1CSProof;
use bulletproofs::r1cs::Prover;
use alloc::vec::Vec;
use ark_ec::{AffineRepr, short_weierstrass::SWCurveConfig, CurveGroup, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_serialize::{
    CanonicalSerialize, CanonicalDeserialize, Compress};
use relations::curve_tree::{SelRerandParameters, CurveTree, SelectAndRerandomizePath};
use std::env;
use std::ops::{Mul, Add};
use merlin::Transcript;

use ark_ec::short_weierstrass::Affine;
use ark_secp256k1::{Config as SecpConfig, Fq as SecpBase};
use ark_secq256k1::Config as SecqConfig;


pub fn commit<C: AffineRepr>(value: C::ScalarField, blinding: C::ScalarField, basepoint1: &C, basepoint2: &C) -> C {
    C::Group::msm_unchecked(&[*basepoint1, *basepoint2], &[value, blinding]).into()
}

fn create_permissible_points_and_randomnesses<
   F: PrimeField,
   P0: SWCurveConfig<BaseField = F> + Copy,
   P1: SWCurveConfig<BaseField = P0::ScalarField, ScalarField = P0::BaseField> + Copy,>(
    leaf_commitments: &[Affine<P0>],
    sr_params: &SelRerandParameters<P0, P1>,
) -> (Vec<Affine<P0>>, Vec<P1::BaseField>) {
    leaf_commitments
        .iter()
        .map(|commitment| {
            sr_params
                .even_parameters
                .uh
                .permissible_commitment(commitment, &sr_params.even_parameters.pc_gens.B_blinding)
        })
        .unzip()
}

// this function returns the curve tree for the set of points
// read from disk (currently pubkey file location is passed as an argument), and
// then returns a tree, along with two bulletproofs for secp and secq,
// and the "merkle proof" of (blinded) commitments to the root.
// For the details on this proof, see "Select-and-Rerandomize" in the paper.
pub fn get_curve_tree_with_proof<
    const L: usize,
    F: PrimeField,
    P0: SWCurveConfig<BaseField = F> + Copy,
    P1: SWCurveConfig<BaseField = P0::ScalarField, ScalarField = P0::BaseField> + Copy,
>(
    depth: usize,
    generators_length_log_2: usize,
    pubkey_file_path: &str,
    key_index: usize,
) -> (R1CSProof<Affine<P0>>, R1CSProof<Affine<P1>>,
    SelectAndRerandomizePath<L, P0, P1>,
    P0::ScalarField,
    Affine<P0>) {
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
    let leaf_commitments = get_leaf_commitments::<F, P0>(pubkey_file_path);
    // the conversion to permissible needs to be deterministic.
    // TODO: figure out how to do the Universal Hash step without random values
    // (for now, we have edited the underlying universal hash code to accommodate this)
    let (permissible_points, _permissible_randomnesses) =
        create_permissible_points_and_randomnesses::<F, P0, P1>(&leaf_commitments, &sr_params);

    println!("Printing out leaf commitments:");
    for l in leaf_commitments {
        let mut bufl = Vec::new();
        l.serialize_compressed(&mut bufl).expect("Failed to deserialize leaf commitmnet");
        println!("Here is lcomm: {:#?}", hex::encode(&bufl));
    }
    let curve_tree = CurveTree::<L, P0, P1>::from_set(
        &permissible_points, &sr_params, Some(depth));
    assert_eq!(curve_tree.height(), depth);

    let (path_commitments, rand_scalar) =
    curve_tree.select_and_rerandomize_prover_gadget(
        key_index,
        &mut p0_prover,
        &mut p1_prover,
        &sr_params,
        &mut rng,
    );
    // as well as the randomness in the blinded commitment, we also need to use the same
    // blinding base:
    let b_blinding = sr_params.even_parameters.pc_gens.B_blinding;
    let p0_proof = p0_prover
        .prove(&sr_params.even_parameters.bp_gens)
        .unwrap();
    let p1_proof = p1_prover
        .prove(&sr_params.odd_parameters.bp_gens)
        .unwrap();
    (p0_proof, p1_proof, path_commitments, rand_scalar, b_blinding)
}

pub fn main(){

    type F = <ark_secp256k1::Affine as AffineRepr>::ScalarField;
    let args: Vec<String> = env::args().collect();
    println!("Here is args: {}, {}", args[0], args[1]);
    // read privkey from command line (TODO, use a file)
    let privhex = &args[1];
    // position of our key in the list;
    // TODO needs a tool to make it easy for usage.
    let keyindex: usize = args[3].parse().unwrap();
    println!("Got key index: {}", keyindex);

    // all the encodings in the ark-ff stuff is LE, so we
    // must convert. TODO relegate to utils for dedup.
    let mut privle = hex::decode(privhex).expect("hex decode failed");
    privle.reverse();


    let x = F::deserialize_compressed(&privle[..]).unwrap();
    let filepath = &args[2];
    let (p0proof,
        p1proof,
        path,
    r,
    H) = get_curve_tree_with_proof::<
    256,
    SecpBase,
    SecpConfig,
    SecqConfig>(
            2, 11, filepath, keyindex);
    // next steps create the Pedersen DLEQ proof for this key:
    //
    // blinding factor for Pedersen
    let (G, J) = get_generators::<SecpBase, SecpConfig>();
    let P = G.mul(x).into_affine();
    let mut bufP = Vec::new();
    P.serialize_compressed(&mut bufP).expect("Failed to serialize P");
    println!("Here is our pubkey: {:#?}", hex::encode(&bufP));
    // the Pedersen commitment D is xG + rH
    let rH = H.mul(r).into_affine();
    let D = P.add(rH).into_affine();
    // the key image (E) is xJ
    let E = J.mul(x).into_affine();
    let mut transcript = Transcript::new(b"ped-dleq-test");
    let proof = PedDleqProof::create(
            &mut transcript,
            &D,
            &E,
            &x,
            &r,
            &G,
            &H,
            &J,
    );
    let mut buf = Vec::with_capacity(proof.serialized_size(Compress::Yes));
    proof.serialize_compressed(&mut buf).unwrap();

        let mut verifier = Transcript::new(b"ped-dleq-test");
        assert!(proof
            .verify(
                &mut verifier,
                &D,
                &E,
                &G,
                &H,
                &J,
            )
            .is_ok());
        let mut bufD: Vec<u8> = Vec::new();

        D.serialize_compressed(&mut bufD).expect("Failed to serialize D");
        let mut bufE = Vec::new();
        E.serialize_compressed(&mut bufE).expect("Failed to serialize E");
        println!("This is the value of D: {:#?}", hex::encode(&bufD));
        println!("This is the value of E: {:#?}", hex::encode(&bufE));
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
    // TODO:
    // here sanity check that the final path entry we output is identical to D,
    // otherwise the two proofs do not tie together and therefore the key
    // image is not valid (so far only checked it manually!)
    path.serialize_compressed(&mut buf2).unwrap();
    write_file_string("proof.txt", buf2);
    println!("Proof generated successfully and wrote to proof.txt. Size was {}", total_size);
}
