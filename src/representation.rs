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
use ark_std::UniformRand;
use std::ops::Add;
use merlin::Transcript;

const REPR3_PROTOCOL_LABEL: &[u8] = b"3-representation-proof";
const REPR3_PROTOCOL_VERSION: u64 = 1;
pub trait TranscriptProtocol {
    fn repr3_proof_domain_sep(&mut self, app_context_label: &[u8], user_string: &[u8]);

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

    fn repr3_proof_domain_sep(&mut self, app_context_label: &[u8], user_string: &[u8]) {
        self.append_message(b"dom-sep", REPR3_PROTOCOL_LABEL);
        // This is the version number for this sub-protocol (3-proof)
        // separate from version of higher level proto that uses it:
        self.append_u64(b"n", REPR3_PROTOCOL_VERSION);
        // This label is for the top level application using the protocol:
        self.append_message(b"dom-sep", app_context_label);
        // This label is specific to this instance of the protocol;
        // typically it is an ephemeral user ID, though it can be anything:
        self.append_message(b"dom-sep", user_string);
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
        use crypto::sha2::Sha256;

        let mut bytes = [0u8; 64];
        self.challenge_bytes(label, &mut bytes);
        // this is just a boilerplate conversion from
        // a hash output to a valid scalar in the field
        for i in 0..=u8::max_value() {
            let mut sha = Sha256::new();
            sha.input(&bytes);
            sha.input(&[i]);
            let mut buf = [0u8; 32];

            sha.result(&mut buf);
            // hash output is BE but field element conversion is LE:
            buf.reverse();
            let res = <C::ScalarField as Field>::from_random_bytes(&buf);

            if let Some(scalar) = res {
                return scalar;
            }
        }
        panic!()
    }
}

pub fn commit<C: AffineRepr>(privkey: C::ScalarField, value: C::ScalarField, blinding: C::ScalarField,
    basepoint1: &C, basepoint2: &C, basepoint3: &C) -> C {
    C::Group::msm_unchecked(&[*basepoint1, *basepoint2, *basepoint3], &[privkey, value, blinding]).into()
}

#[derive(Clone, Debug)]
pub struct Repr3Proof<C: AffineRepr> {
    pub R: C,
    pub sigma1: C::ScalarField,
    pub sigma2: C::ScalarField,
    pub sigma3: C::ScalarField,
}

impl<C: AffineRepr> Repr3Proof<C> {
    /// Create a proof of knowledge of the opening
    /// triplet (x, v, r) for D = xG + vJ + rH
    pub fn create(
        transcript: &mut Transcript,
        D: &C,
        x: &C::ScalarField,
        v: &C::ScalarField,
        r: &C::ScalarField,
        G: &C,
        H: &C,
        J: &C,
        sarg: Option<C::ScalarField>,
        targ: Option<C::ScalarField>,
        uarg: Option<C::ScalarField>,
        app_context_label: &[u8],
        user_string: &[u8]
    ) -> Repr3Proof<C> {

        transcript.repr3_proof_domain_sep(app_context_label, user_string);
        // Step 1: create random scalars s, t, u
        // Step 2: create "commitment" = sG + tJ + uH
        // Step 3: create challenge hash from transcript, call it e
        // Step 4: calculate sigma1 = s + ex
        // Step 5: calculate sigma2 = t + ev
        // Step 6: Calculate sigma3 = u + er
        // return (P=sG + tJ + uH, sigma1, sigma2, sigma3) as proof

        //Step 1
        // Construct blinding factors using an RNG.
        let mut rng = rand::thread_rng();
        let s = sarg.unwrap_or(C::ScalarField::rand(&mut rng));
        let t = targ.unwrap_or(C::ScalarField::rand(&mut rng));
        let u = uarg.unwrap_or(C::ScalarField::rand(&mut rng));
        //Step 2
        let P = commit(s, t, u, G, J, H);
        transcript.append_point(b"1", &P);
        transcript.append_point(b"2", D);
        // Step 3
        let e = 
        transcript.challenge_scalar::<C>(b"e");
        // Step 4
        let sigma1 = s + (*x)*e;
        // Step 5
        let sigma2 = t + (*v)*e;
        // Step 6
        let sigma3 = u + (*r)*e;

        Repr3Proof {
            R: P.clone(),
            sigma1,
            sigma2,
            sigma3,
        }
    }
    pub fn verify(
        &self,
        transcript: &mut Transcript,
        D: &C,
        G: &C,
        H: &C,
        J: &C,
        app_context_label: &[u8],
        user_string: &[u8]
    ) -> Result<(), &str>
    {

        //form correct hash challenge
        transcript.repr3_proof_domain_sep(app_context_label, user_string);
        transcript.append_point(b"1", &self.R);
        transcript.append_point(b"2", D);
        let e =
        transcript.challenge_scalar::<C>(b"e");
        // checks:
        // sigma1 G + sigma_2 J  + sigma3 H = R + e*D
        //
        if !(G.mul(&self.sigma1).add(J.mul(&self.sigma2))
        .add(H.mul(&self.sigma3)) == self.R.add(D.mul(e))){
            println!("Verify check failed");
            return Err("verify check 1 failed")
        }
        Ok(())
    }
    /// Returns the size in bytes required to serialize the ped-dleq proof
    pub fn serialized_size(&self, compress: Compress) -> usize {
        // proof consists of 4 objects, 3 scalars sigma1, sigma2, sigma3 and one point R.
        // Note that both prover and verifier own P and D (blinded claimed tree entry)
        // as well as G, H, J generators.
        let scalars_size = self.sigma1.serialized_size(compress) * 3;
        // size of the 2 points
        let points_size = self.R.serialized_size(compress);
        scalars_size + points_size
    }
}

impl<C: AffineRepr> Valid for Repr3Proof<C> {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}
impl<C: AffineRepr> CanonicalSerialize for Repr3Proof<C> {
    /// Returns the size in bytes required to serialize the ped-dleq proof
    /// TODO: Why is this copy-pasted from the struct function?
    fn serialized_size(&self, mode: Compress) -> usize {
        let scalars_size = self.sigma1.serialized_size(mode) * 3;
        let points_size = self.R.serialized_size(mode);
        scalars_size + points_size
    }

    /// Serializes the proof into a byte array of 4 32/33-byte elements.
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.R.serialize_with_mode(&mut writer, compress)?;
        self.sigma1.serialize_with_mode(&mut writer, compress)?;
        self.sigma2.serialize_with_mode(&mut writer, compress)?;
        self.sigma3.serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }
}

impl<C: AffineRepr> CanonicalDeserialize for Repr3Proof<C> {
    fn deserialize_with_mode<Re: Read>(
        mut reader: Re,
        compress: Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        Ok(Self {
            R: C::deserialize_with_mode(&mut reader, compress, validate)?,
            sigma1: C::ScalarField::deserialize_with_mode(&mut reader, compress, validate)?,
            sigma2: C::ScalarField::deserialize_with_mode(&mut reader, compress, validate)?,
            sigma3: C::ScalarField::deserialize_with_mode(&mut reader, compress, validate)?,
        })
    }
}
