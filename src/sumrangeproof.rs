
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
    vec_r: Option<Vec<C::ScalarField>>,
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
        // take blinding from arg if provided, else random:
        let blinding: C::ScalarField = match vec_r {
            Some(ref x) => x[i],
            None => C::ScalarField::rand(&mut rng),
        };
        let (comm, var) = prover.commit_vec(
            &vec_temp.clone(),
            blinding,
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
    // 5. before returning to the caller, sanity check verification
    // (this is always cheap):
    range_proof_sum_gadgets_verifier(pc_gens, bp_gens,
        &proof, comm1, k, n, &Q_comms)?;

    Ok((proof, comm1, Q_comms))
}

pub fn range_proof_sum_gadgets_verifier<C: AffineRepr>(
    pc_gens: &PedersenGens<C>,
    bp_gens: &BulletproofGens<C>,
    proof: &R1CSProof<C>,
    comm: C,
    k: u64,
    n: usize,
    Qcomms: &Vec<C>,
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

/// Returns a ZKP for the statement:
/// "The secret tuples (privkey, value)
/// have a sum of values in range between
/// k and k + 2^n, and those secret tuples
/// are the openings of the commitments
/// vector Qcomms"
/// TODO: randomness should be an input.
pub fn sum_range_proof<C: AffineRepr>(
    values: Vec<u64>,
    privkeys: Option<Vec<C::ScalarField>>, // optional to allow tests
    blindings: Option<Vec<C::ScalarField>>, // as above
    k: u64, // start of range ('offset')
    n: usize, // power of 2 for width of range,
    pc_gens: &PedersenGens<C>,
    bp_gens: &BulletproofGens<C>
    ) -> Result<(R1CSProof<C>, C, Vec<C>, C), R1CSError> {
    let m = values.len();
    // make m private keys if not provided as argument:
    let privkey_vec: Vec<C::ScalarField> = 
    match privkeys {
        Some(tmp) => {
            let privtemp: Vec<C::ScalarField> = tmp.iter().map(|x| (*x).into()).collect();
            privtemp
            },
        None => {
            let mut privtemp: Vec<C::ScalarField> = Vec::new();
            for i in 0..m as u64 {
                privtemp.push((5u64 + i).into());
            }
            privtemp
        } 
    };
        
    let (proof, comm, Qcomms) =
    range_proof_sum_gadgets_prover::<C>(
        &pc_gens,
        &bp_gens,
        values,
        k,
        n,
        privkey_vec,
        blindings)?;

    Ok((proof, comm, Qcomms, pc_gens.B_blinding))
}

#[test]
fn sum_range_proof_test(){
    let pc_gens = PedersenGens::<Affine>::default();
    let bp_gens = BulletproofGens::<Affine>::new(128, 1);
    assert!(sum_range_proof::<Affine>(
        [5000u64, 400u64, 900u64, 100u64].to_vec(), None, None,
        6000u64, 10, &pc_gens, &bp_gens).is_ok());
    assert!(sum_range_proof::<Affine>(
        [5000u64, 400u64, 900u64, 100u64].to_vec(), None, None,
        100u64, 10, &pc_gens, &bp_gens).is_err());
    assert!(sum_range_proof::<Affine>(
        [50000u64, 23u64, 900u64, 100u64].to_vec(), None, None,
        50000u64, 10, &pc_gens, &bp_gens).is_ok()); // should be inside range by 1
    assert!(sum_range_proof::<Affine>(
        [500u64, 400u64, 900u64, 100u64].to_vec(), None, None,
        1917u64, 4, &pc_gens, &bp_gens).is_err()); // below lower limit of range
    
}

