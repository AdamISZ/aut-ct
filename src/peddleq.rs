#![allow(non_snake_case)]
extern crate rand;
extern crate alloc;
extern crate ark_secp256k1;

use crate::utils;

use alloc::vec::Vec;
use ark_ec::{AffineRepr, VariableBaseMSM};
use ark_ff::Field;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Write,
};
use ark_std::Zero;
use ark_std::UniformRand;
use std::ops::Add;
use merlin::Transcript;


pub trait TranscriptProtocol {
    fn ped_dleq_proof_domain_sep(&mut self, n: u64);

    /// Append a `scalar` with the given `label`.
    fn append_scalar<C: AffineRepr>(&mut self, label: &'static [u8], scalar: &C::ScalarField);

    /// Append a `point` with the given `label`.
    fn append_point<C: AffineRepr>(&mut self, label: &'static [u8], point: &C);

    /// Check that a point is not the identity, then append it to the
    /// transcript.  Otherwise, return an error.
    fn validate_and_append_point<C: AffineRepr>(
        &mut self,
        label: &'static [u8],
        point: &C,
    ) -> Result<(), &str>;

    /// Compute a `label`ed challenge variable.
    fn challenge_scalar<C: AffineRepr>(&mut self, label: &'static [u8]) -> C::ScalarField;
}

impl TranscriptProtocol for Transcript {

    fn ped_dleq_proof_domain_sep(&mut self, n: u64) {
        self.append_message(b"dom-sep", b"peddleqproof");
        self.append_u64(b"n", n);
    }

    fn append_scalar<C: AffineRepr>(&mut self, label: &'static [u8], scalar: &C::ScalarField) {
        self.append_message(label, &utils::field_as_bytes(scalar));
    }

    fn append_point<C: AffineRepr>(&mut self, label: &'static [u8], point: &C) {
        let mut bytes = Vec::new();
        if let Err(e) = point.serialize_compressed(&mut bytes) {
            panic!("{}", e)
        }
        self.append_message(label, &bytes);
    }

    fn validate_and_append_point<C: AffineRepr>(
        &mut self,
        label: &'static [u8],
        point: &C,
    ) -> Result<(), &str> {
        if point.is_zero() {
            Err("point is zero")
        } else {
            let mut bytes = Vec::new();
            if let Err(e) = point.serialize_compressed(&mut bytes) {
                panic!("{}", e)
            }
            self.append_message(label, &bytes);
            Ok(())
        }
    }

    fn challenge_scalar<C: AffineRepr>(&mut self, label: &'static [u8]) -> C::ScalarField {
        extern crate crypto;
        use crypto::digest::Digest;
        // TODO: switch to SHA2
        //use crypto::sha3::Sha3;
        use crypto::sha2::Sha256;

        let mut bytes = [0u8; 64];
        self.challenge_bytes(label, &mut bytes);

        for i in 0..=u8::max_value() {
            let mut sha = Sha256::new();
            sha.input(&bytes);
            sha.input(&[i]);
            let mut buf = [0u8; 32];

            sha.result(&mut buf);
            let res = <C::ScalarField as Field>::from_random_bytes(&buf);

            if let Some(scalar) = res {
                return scalar;
            }
        }
        panic!()
    }
}

pub fn commit<C: AffineRepr>(value: C::ScalarField, blinding: C::ScalarField, basepoint1: &C, basepoint2: &C) -> C {
    C::Group::msm_unchecked(&[*basepoint1, *basepoint2], &[value, blinding]).into()
}

#[derive(Clone, Debug)]
pub struct PedDleqProof<C: AffineRepr> {
    pub R1: C,
    pub R2: C,
    pub sigma1: C::ScalarField,
    pub sigma2: C::ScalarField,
}

impl<C: AffineRepr> PedDleqProof<C> {
    /// Create an proof that D, E have the same x s.t.:
    /// D = xG + rH and E = xJ (orthogonal bases G, H, J)
    pub fn create(
        transcript: &mut Transcript,
        D: &C,
        E: &C,
        x: &C::ScalarField,
        r: &C::ScalarField,
        G: &C,
        H: &C,
        J: &C,
    ) -> PedDleqProof<C> {
        // TODO, fix up transcript fields
        transcript.ped_dleq_proof_domain_sep(1);
        // Step 1: create random scalars s, t
        // Step 2: create "commitment" = sG + tH
        // Step 2b: create "commitment" = sJ
        // Step 3: create challenge hash from transcript, call it e
        // Step 4: calculate sigma1 = s + ex
        // Step 5: calculate sigma2 = t + er
        // return (P=sG + tH, Q=sJ, sigma1, sigma2) as proof
        // If it's the first iteration, unroll the Hprime = H*y_inv scalar mults
        // into multiscalar muls, for performance.

        //Step 1
        // Construct blinding factors using an RNG.
        let mut rng = rand::thread_rng();
        let s = C::ScalarField::rand(&mut rng);
        let t = C::ScalarField::rand(&mut rng);
        //Step 2
        let P = commit(s, t, G, H);
        transcript.append_point(b"1", &P);
        //Step 2b
        let Q = commit(s, C::ScalarField::zero(), J, H);
        transcript.append_point(b"2", &Q);
        transcript.append_point(b"3", D);
        transcript.append_point(b"4", E);

        // Step 3
        let e = 
        transcript.challenge_scalar::<C>(b"e");
        // Step 4
        let sigma1 = s + (*x)*e;
        // Step 5
        let sigma2 = t + (*r)*e;
        //println!("Here is R1,R2 in the proof creator: {},\t {}", P, Q);
        PedDleqProof {
            R1: P.clone(),
            R2: Q.clone(),
            sigma1,
            sigma2,
        }
    }
    pub fn verify(
        &self,
        transcript: &mut Transcript,
        D: &C,
        E: &C,
        //sigma1: &C::ScalarField,
        //sigma2: &C::ScalarField,
        //R1: &C,
        //R2: &C,
        G: &C,
        H: &C,
        J: &C,
    ) -> Result<(), &str>
    {
        //println!("Here is R1,R2 in the proof verifier: {},\t {}", self.R1, self.R2);
        //form correct hash challenge
        transcript.ped_dleq_proof_domain_sep(1);
        transcript.append_point(b"1", &self.R1);
        transcript.append_point(b"2", &self.R2);
        transcript.append_point(b"3", D);
        transcript.append_point(b"4", E);
        let e =
        transcript.challenge_scalar::<C>(b"e");

        // checks:
        // sigma1 G + sigma_2 H = R1 + e*D
        // sigma2 J = R2 + e*E
        //
        if !(G.mul(&self.sigma1).add(H.mul(&self.sigma2)) == self.R1.add(D.mul(e))){
            println!("Verify check1 failed");
            return Err("verify check 1 failed")
        }
        if !(J.mul(&self.sigma1) == self.R2.add(E.mul(e))){
            println!("Verify check2 failed");
            return Err("verify check 2 failed")
        }
        Ok(())
    }
    /// Returns the size in bytes required to serialize the ped-dleq proof
    pub fn serialized_size(&self, compress: Compress) -> usize {
        // prof consists of 4 objects, two scalars sigma1, sigma2 and two points R1, R2.
        // Note that both prover and verifier own P and C1 (blinded claimed tree entry)
        // as well as G, H, J generators.
        let scalars_size = self.sigma1.serialized_size(compress) * 2;
        // size of the 2 points
        let points_size = self.R1.serialized_size(compress) * 2;
        scalars_size + points_size
    }
}

impl<C: AffineRepr> Valid for PedDleqProof<C> {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}
impl<C: AffineRepr> CanonicalSerialize for PedDleqProof<C> {
    /// Returns the size in bytes required to serialize the ped-dleq proof
    /// TODO: Why is this copy-pasted from the struct function?
    fn serialized_size(&self, mode: Compress) -> usize {
        // prof consists of 4 objects, two scalars sigma1, sigma2 and two points R1, R2.
        // Note that both prover and verifier own P and C1 (blinded claimed tree entry)
        // as well as G, H, J generators.
        let scalars_size = self.sigma1.serialized_size(mode) * 2;
        // size of the 3 points
        let points_size = self.R1.serialized_size(mode) * 2;
        scalars_size + points_size
    }

    /// Serializes the proof into a byte array of 4 32-byte elements.
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.R1.serialize_with_mode(&mut writer, compress)?;
        self.R2.serialize_with_mode(&mut writer, compress)?;
        self.sigma1.serialize_with_mode(&mut writer, compress)?;
        self.sigma2.serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }
}

impl<C: AffineRepr> CanonicalDeserialize for PedDleqProof<C> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        Ok(Self {
            R1: C::deserialize_with_mode(&mut reader, compress, validate)?,
            R2: C::deserialize_with_mode(&mut reader, compress, validate)?,
            sigma1: C::ScalarField::deserialize_with_mode(&mut reader, compress, validate)?,
            sigma2: C::ScalarField::deserialize_with_mode(&mut reader, compress, validate)?,
        })
    }
}

