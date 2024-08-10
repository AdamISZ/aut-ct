#![allow(non_snake_case)]

extern crate merlin;
extern crate rand;

use ark_ec::AffineRepr;
use ark_ff::Field;
use ark_std::UniformRand;

use ark_secp256k1::Affine;

use bulletproofs::r1cs::*;
use bulletproofs::{BulletproofGens, PedersenGens};
use merlin::Transcript;

// Example of range proof gadget copied from the
// bulletproofs repo example.
// A further test example is created for proof in
// range not starting with 0.

// Offset Range Proof gadget
// Enforces that the quantity of v is in the range [k, k+2^n).

pub fn offset_range_proof<F: Field, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    mut v: LinearCombination<F>,
    v_assignment: Option<u64>,
    n: usize,
    k: u64,
) -> Result<(), R1CSError> {
    let mut exp_2 = F::one();

    let voffset: LinearCombination<F> = constant(k);
    for i in 0..n {
        // Create low-level variables and add them to constraints
        let (a, b, o) = cs.allocate_multiplier(
            v_assignment.map(|q| {
            let bit: u64 = ((q - k) >> i) & 1;
            ((1 - bit).into(), bit.into())
        }))?;

        // Enforce a * b = 0, so one of (a,b) is zero
        cs.constrain(o.into());
        // Enforce that a = 1 - b, so they both are 1 or 0.
        // cs.constrain(a + (b - 1u64));
        cs.constrain(a + (b - constant(1u64)));
        // Add `-b_i*2^i` to the linear combination
        // in order to form the following constraint by the end of the loop:
        // v = Sum(b_i * 2^i, i = 0..n-1)
        v = v - b * exp_2;
        exp_2 = exp_2 + exp_2;
    }

    // Enforce that v = Sum(b_i * 2^i, i = 0..n-1) + k
    cs.constrain(v - voffset);

    Ok(())
}
// Range Proof gadget

/// Enforces that the quantity of v is in the range [0, 2^n).
pub fn range_proof<F: Field, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    mut v: LinearCombination<F>,
    v_assignment: Option<u64>,
    n: usize,
) -> Result<(), R1CSError> {
    let mut exp_2 = F::one();
    for i in 0..n {
        // Create low-level variables and add them to constraints
        
        let (a, b, o) = cs.allocate_multiplier(
            v_assignment.map(|q| {
            let bit: u64 = (q >> i) & 1;
            ((1 - bit).into(), bit.into())
        }))?;

        // Enforce a * b = 0, so one of (a,b) is zero
        cs.constrain(o.into());

        // Enforce that a = 1 - b, so they both are 1 or 0.
        // cs.constrain(a + (b - 1u64));
        cs.constrain(a + (b - constant(1u64)));

        // Add `-b_i*2^i` to the linear combination
        // in order to form the following constraint by the end of the loop:
        // v = Sum(b_i * 2^i, i = 0..n-1)
        v = v - b * exp_2;

        exp_2 = exp_2 + exp_2;
  
    }

    // Enforce that v = Sum(b_i * 2^i, i = 0..n-1)
    cs.constrain(v);

    Ok(())
}

#[test]
fn offset_range_proof_gadget() {
    // This tests proving that a value is in range
    // k -> k+2^n instead of 0 -> 2^n
    use rand::thread_rng;
    use rand::Rng;
    let mut rng = thread_rng();
    //offset
    let k = 4000u64;
    let m = 5; // number of values to test per `n`

    for n in [10, 32, 63].iter() {
        let (min, max) = (0u64 + k, ((1u128 << n) - 1) as u64 + k);
        let values: Vec<u64> = (0..m).map(|_| rng.gen_range(min..max)).collect();
        for v in values {
           assert!(offset_range_proof_helper::<Affine>(k, v.into(), *n).is_ok());
        }
        assert!(offset_range_proof_helper::<Affine>(k, (max + 1).into(), *n).is_err());
    }
}

fn offset_range_proof_helper<C: AffineRepr>(k: u64, v_val: u64, n: usize) -> Result<(), R1CSError> {
   // Common
   let pc_gens = PedersenGens::<C>::default();
   let bp_gens = BulletproofGens::<C>::new(128, 1);

   // Prover's scope
   let (proof, commitment) = {
       // Prover makes a `ConstraintSystem` instance representing a range proof gadget
       let mut prover_transcript = Transcript::new(b"RangeProofTest");
       let mut rng = rand::thread_rng();

       let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

       let (com, var) = prover.commit(v_val.into(), C::ScalarField::rand(&mut rng));
       assert!(offset_range_proof(&mut prover, var.into(), Some(v_val), n, k).is_ok());

       let proof = prover.prove(&bp_gens)?;

       (proof, com)
   };

   // Verifier makes a `ConstraintSystem` instance representing a merge gadget
   let mut verifier_transcript = Transcript::new(b"RangeProofTest");
   let mut verifier = Verifier::new(&mut verifier_transcript);

   let var = verifier.commit(commitment);

   // Verifier adds constraints to the constraint system
   assert!(offset_range_proof(&mut verifier, var.into(), None, n, k).is_ok());

   // Verifier verifies proof
   verifier.verify(&proof, &pc_gens, &bp_gens) 
}

#[test]
fn range_proof_gadget() {
    use rand::thread_rng;
    use rand::Rng;

    let mut rng = thread_rng();
    let m = 3; // number of values to test per `n`

    for n in [2, 10, 32, 63].iter() {
        let (min, max) = (0u64, ((1u128 << n) - 1) as u64);
        let values: Vec<u64> = (0..m).map(|_| rng.gen_range(min..max)).collect();
        for v in values {
            assert!(range_proof_helper::<Affine>(v.into(), *n).is_ok());
        }
        assert!(range_proof_helper::<Affine>((max + 1).into(), *n).is_err());
    }
}

fn range_proof_helper<C: AffineRepr>(v_val: u64, n: usize) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::<C>::default();
    let bp_gens = BulletproofGens::<C>::new(128, 1);

    // Prover's scope
    let (proof, commitment) = {
        // Prover makes a `ConstraintSystem` instance representing a range proof gadget
        let mut prover_transcript = Transcript::new(b"RangeProofTest");
        let mut rng = rand::thread_rng();

        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        let (com, var) = prover.commit(v_val.into(), C::ScalarField::rand(&mut rng));
        assert!(range_proof(&mut prover, var.into(), Some(v_val), n).is_ok());

        let proof = prover.prove(&bp_gens)?;

        (proof, com)
    };

    // Verifier makes a `ConstraintSystem` instance representing a merge gadget
    let mut verifier_transcript = Transcript::new(b"RangeProofTest");
    let mut verifier = Verifier::new(&mut verifier_transcript);

    let var = verifier.commit(commitment);

    // Verifier adds constraints to the constraint system
    assert!(range_proof(&mut verifier, var.into(), None, n).is_ok());

    // Verifier verifies proof
    verifier.verify(&proof, &pc_gens, &bp_gens)
}
