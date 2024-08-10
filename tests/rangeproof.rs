#![allow(non_snake_case)]
extern crate bulletproofs;
extern crate merlin;
extern crate rand;

use ark_ec::AffineRepr;
use ark_ff::Field;
use ark_std::UniformRand;

use ark_secp256k1::Affine;

use bulletproofs::r1cs::*;
use bulletproofs::{BulletproofGens, PedersenGens};
use merlin::Transcript;

// test of primitive addition checks
mod low_sum_range_proof {
    use super::*;
    fn gadget_add_two<F: Field, CS:ConstraintSystem<F>>(
        cs: &mut CS,
        a: LinearCombination<F>,
        b: LinearCombination<F>,
        sum: LinearCombination<F>
    ) {
        cs.constrain(sum - (a + b));
    }

    #[test]
    fn test_add_two_values_wrapper(){
        let pc_gens = PedersenGens::<Affine>::default();
        let bp_gens = BulletproofGens::<Affine>::new(128, 1);
        test_add_two_values::<Affine>(&pc_gens, &bp_gens)
    }
    fn test_add_two_values<C: AffineRepr>(pc_gens: &PedersenGens<C>,
    bp_gens: &BulletproofGens<C>){
    // start with a vector of 4 values
    let a = 9u64;
    let b = 12u64;
    let mut transcript = Transcript::new(b"LowRangeProofSum");
    let mut prover = Prover::new(&pc_gens, &mut transcript);

    let mut rng = rand::thread_rng();
    let (comma, vara) = prover.commit(a.into(), C::ScalarField::rand(&mut rng));
    let (commb, varb) = prover.commit(b.into(), C::ScalarField::rand(&mut rng));
    let (commsum, varsum) = prover.commit((a+b).into(), C::ScalarField::rand(&mut rng));
    gadget_add_two(&mut prover, vara.into(), varb.into(), varsum.into());
    let proof = prover.prove(bp_gens).unwrap();
    let mut transcript2 = Transcript::new(b"LowRangeProofSum");
    let mut verifier = Verifier::new(&mut transcript2);
    let vara_verif = verifier.commit(comma);
    let varb_verif = verifier.commit(commb);
    let varsum_verif = verifier.commit(commsum);
    gadget_add_two(
        &mut verifier,
        vara_verif.into(),
        varb_verif.into(),
        varsum_verif.into()
    );
    let res = verifier
            .verify(&proof, &pc_gens, &bp_gens);
    if res.is_err(){
        println!("Got verif error: {:?}", res);
    }
    
    }
}

// tests of:
// a proof that the sum of a vector agrees with a given commitment,
// and,
// a proof of a *set* of values adding up to
// a sum that is within  a specified range
mod sum_range_proof {
    use super::*;
    /// Constrains v0 + v1 + .. v_m-1 = sum
    fn gadget_vector_sum<F: Field, CS: ConstraintSystem<F>>(
        cs: &mut CS,
        vec_v: Vec<Variable<F>>, // committed-to vector
        sum: LinearCombination<F>, // committed-to sum
    )  {
        let mut expected_sum = LinearCombination::<F>::from(F::zero());
        for i in 0..vec_v.len() {
            expected_sum = expected_sum + vec_v[i];
        }
        cs.constrain(sum - expected_sum)
    }

    #[test]
    fn wrapped_test_vector_sum(){
        let pc_gens = PedersenGens::<Affine>::default();
        let bp_gens = BulletproofGens::<Affine>::new(128, 1);
        test_vector_sum::<Affine>(&pc_gens, &bp_gens)
    }
    fn test_vector_sum<C: AffineRepr>(pc_gens: &PedersenGens<C>,
    bp_gens: &BulletproofGens<C>){

    // start with a vector of 4 values
    let vec_v = vec!(5000u64,
    400u64,
    900u64,
    100u64);
    let mut transcript = Transcript::new(b"RangeProofSum");
    let mut prover = Prover::new(&pc_gens, &mut transcript);

    let mut rng = rand::thread_rng();
    let vec_v_scalars = vec_v.into_iter().map(|q| q.into()).collect::<Vec<_>>();
    let (comm, var) = prover.commit_vec(&vec_v_scalars, C::ScalarField::rand(&mut rng), &bp_gens);
    let realsum = vec_v_scalars.iter().sum();
    let (sumcomm, sumvar) = prover.commit(realsum, C::ScalarField::rand(&mut rng));
    gadget_vector_sum(&mut prover, var, sumvar.into());
    let proof = prover.prove(bp_gens).unwrap();
    let mut transcript2 = Transcript::new(b"RangeProofSum");
    let mut verifier = Verifier::new(&mut transcript2);
    let var_verif_vec = verifier.commit_vec(4, comm);
    let var_verif_sum = verifier.commit(sumcomm);
    gadget_vector_sum(
        &mut verifier,
        var_verif_vec,
        var_verif_sum.into(),
    );
    verifier
            .verify(&proof, &pc_gens, &bp_gens).unwrap();
    
    }

    // Constrains v_sum between k and k+2^n
    fn gadget_offset_range_proof<F: Field, CS: ConstraintSystem<F>>(
        cs: &mut CS,
        k: u64,
        n: usize,
        mut v_sum: LinearCombination<F>,
        v_sum_assignment: Option<u64>,
    ) -> Result<(), R1CSError> {
        // we can only prove for values > k;
        // but `None` indicates verify operation.
        match v_sum_assignment {
            Some(x) => {if x < k {
                return Err(R1CSError::GadgetError{description: "Sum is too small, no valid proof possible.".into()});
                }}
            None => ()
        }
        let mut exp_2 = F::one();
        let voffset: LinearCombination<F> = constant(k);
        for i in 0..n {
            // Create low-level variables and add them to constraints
            let (a, b, o) = cs.allocate_multiplier(
                v_sum_assignment.map(|q| {
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
            // v = Sum(b_i * 2^i, i = 0..n-1) + k
            v_sum = v_sum - b * exp_2;
            exp_2 = exp_2 + exp_2;
        }

        // Enforce that v = Sum(b_i * 2^i, i = 0..n-1) + k
        cs.constrain(v_sum - voffset);
        Ok(())
    }

    // Prover's scope
    fn range_proof_sum_gadgets_prover<C: AffineRepr>(
        pc_gens: &PedersenGens<C>,
        bp_gens: &BulletproofGens<C>,
        vec_v: Vec<u64>,
        k: u64,
        n: usize,
        vec_x: Vec<C::ScalarField>,
    ) -> Result<(R1CSProof<C>, C, Vec<C>), R1CSError> {
        assert!(vec_v.len() == vec_x.len());
        let m = vec_v.len();
        // Create a prover
        let mut transcript = Transcript::new(b"RangeProofSum");
        let mut prover = Prover::new(pc_gens, &mut transcript);

        let mut rng = rand::thread_rng();

        // for each of the m indices, we want to commit to:
        // Q_i = x_i G_1 + v_i G_2 (+rH)
        // so using commit_vec, we get back a list of m commitments
        // Q_i, i=0..m
        // and a vector of vector of Variables. Each inner vector has 2 components:
        // (x_i, v_i)
        // we take the second components, m of them, and use that set of values
        // as input to our (sum) offset range proof.
        let mut vars_repr: Vec<Vec<Variable<C::ScalarField>>> = Vec::new();
        let mut Q_comms: Vec<C> = Vec::new();
        for i in 0..m {
            let vec_temp = vec!(vec_x[i],
            vec_v[i].into());
            let (comm, var) = prover.commit_vec(
                &vec_temp.clone(),
                C::ScalarField::rand(&mut rng),
                bp_gens,);
            vars_repr.push(var);
            Q_comms.push(comm);
        }
        // Next we use the created Variables referencing the secret values
        let mut vars_v: Vec<Variable<C::ScalarField>> = Vec::new();
        for i in 0..m {
            vars_v.push(vars_repr[i][1]);
        }
        let mut vars_x: Vec<Variable<C::ScalarField>> = Vec::new();
        for i in 0..m {
            vars_x.push(vars_repr[i][0]);
        }
        // Commit to the witness component: sum of individual input values
        let sum: u64 = vec_v.iter().sum();
        let h = C::ScalarField::rand(&mut rng);
        let (comm1, vars1) = 
        prover.commit(C::ScalarField::from(sum), h);

        // Constrain to the committed sum
        gadget_vector_sum(
            &mut prover,
            vars_v,
            vars1.into(),
        );

        // Constrain that the sum is in the claimed range:
        if gadget_offset_range_proof(
            &mut prover,
            k,
            n,
            vars1.into(),
            Some(sum)).is_err(){
                // hmm? what is the right way to
                // raise a R1CS proving error?
                // It can't be this nonsense.
                return Err(R1CSError::GadgetError{
                    description: "offset range proof gadget creation failed.".to_string()});
            };

        // 4. Make a proof
        let proof = prover.prove(bp_gens)?;

        Ok((proof, comm1, Q_comms))
    }

    fn range_proof_sum_gadgets_verifier<C: AffineRepr>(
        pc_gens: &PedersenGens<C>,
        bp_gens: &BulletproofGens<C>,
        proof: R1CSProof<C>,
        comm: C,
        k: u64,
        n: usize,
        Qcomms: Vec<C>,
    ) -> Result<(), R1CSError> {
        let mut transcript = Transcript::new(b"RangeProofSum");

        let mut verifier = Verifier::new(&mut transcript);
        let m = Qcomms.len();

        let mut vars_repr: Vec<Vec<Variable<C::ScalarField>>> = Vec::new();
        for i in 0..m {
            let var = verifier.commit_vec(2, Qcomms[i]);
            vars_repr.push(var);
        }
        let mut vars_v: Vec<Variable<C::ScalarField>> = Vec::new();
        for i in 0..m {
            vars_v.push(vars_repr[i][1]);
        }
        let mut vars_x: Vec<Variable<C::ScalarField>> = Vec::new();
        for i in 0..m {
            vars_x.push(vars_repr[i][0]);
        }
        let var_c: Variable<C::ScalarField> = verifier.commit(comm);
        gadget_vector_sum(
            &mut verifier,
            vars_v.into_iter().map(|v| v.into()).collect::<Vec<_>>(),
            var_c.into(),
        );
        if gadget_offset_range_proof(
            &mut verifier,
            k,
            n,
            var_c.into(),
            None).is_err(){
                // hmm? what is the right way to
                // raise a R1CS proving error?
                // It can't be this nonsense.
                return Err(R1CSError::GadgetError{
                    description: "verify offset range proof failed.".to_string()});
            };
        // 4. Verify the proof
        verifier
            .verify(&proof, &pc_gens, &bp_gens)
            .map_err(|_| R1CSError::VerificationError)
    }


fn sum_range_proof_test_helper(
    m: u64,
    params: Vec<Vec<u64>>,
    k: u64, // start of range ('offset')
    n: usize // power of 2 for width of range
    ) -> Result<(), R1CSError> {
    let pc_gens = PedersenGens::<Affine>::default();
    let bp_gens = BulletproofGens::<Affine>::new(128, 1);

    // strategy: set variables for x and v values as vectors.
    // use commit_vec for each i in 0..m to create a Ci = xiG1 + viG2 + riH
    // create new internal var q = sum of vi
    // apply range proof gadget to q
    for vinner in params {
        // make m private keys
        let mut privkey_vec: Vec<<ark_secp256k1::Affine as AffineRepr>::ScalarField> = Vec::new();
        for i in 0..m {
            privkey_vec.push((i + 5u64).into());
        }
        let (proof, comm, Qcomms) = range_proof_sum_gadgets_prover::<Affine>(
            &pc_gens,
            &bp_gens,
            vinner,
            k,
            n,
            privkey_vec)?;
        range_proof_sum_gadgets_verifier::<Affine>(
            &pc_gens, &bp_gens, proof, comm, k, n, Qcomms)?;
    }
    Ok(())
}

#[test]
fn sum_range_proof_test(){
    assert!(sum_range_proof_test_helper(4,
        [[5000u64, 400u64, 900u64, 100u64].to_vec()].to_vec(), 6000u64, 10).is_ok());
    assert!(sum_range_proof_test_helper(4,
        [[5000u64, 400u64, 900u64, 100u64].to_vec()].to_vec(), 100u64, 10).is_err());
    assert!(sum_range_proof_test_helper(4,
        [[50000u64, 23u64, 900u64, 100u64].to_vec()].to_vec(), 50000u64, 10).is_ok()); // should be inside range by 1
    assert!(sum_range_proof_test_helper(4,
        [[500u64, 400u64, 900u64, 100u64].to_vec()].to_vec(), 1917u64, 4).is_err()); // below lower limit of range
    
}
}



// Example of range proof gadget copied from the
// bulletproofs repo example but modified to allow
// range not starting with 0:

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
