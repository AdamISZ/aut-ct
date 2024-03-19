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

const PEDDLEQ_PROTOCOL_LABEL: &[u8] = b"peddleqproof";
const PEDDLEQ_PROTOCOL_VERSION: u64 = 1;
pub trait TranscriptProtocol {
    fn ped_dleq_proof_domain_sep(&mut self, app_context_label: &[u8]);

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

    fn ped_dleq_proof_domain_sep(&mut self, app_context_label: &[u8]) {
        self.append_message(b"dom-sep", PEDDLEQ_PROTOCOL_LABEL);
        // This is the version number for this sub-protocol (ped-dleq)
        // separate from version of higher level proto that uses it:
        self.append_u64(b"n", PEDDLEQ_PROTOCOL_VERSION);
        // This label is for the top level application using the protocol:
        self.append_message(b"dom-sep", app_context_label);
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
        sarg: Option<C::ScalarField>,
        targ: Option<C::ScalarField>,
        app_context_label: &[u8]
    ) -> PedDleqProof<C> {

        transcript.ped_dleq_proof_domain_sep(app_context_label);
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
        let s = sarg.unwrap_or(C::ScalarField::rand(&mut rng));
        let t = targ.unwrap_or(C::ScalarField::rand(&mut rng));
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
        G: &C,
        H: &C,
        J: &C,
        app_context_label: &[u8]
    ) -> Result<(), &str>
    {

        //form correct hash challenge
        transcript.ped_dleq_proof_domain_sep(app_context_label);
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
        // proof consists of 4 objects, two scalars sigma1, sigma2 and two points R1, R2.
        // Note that both prover and verifier own P and D (blinded claimed tree entry)
        // as well as G, H, J generators and E(the key image).
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
        let scalars_size = self.sigma1.serialized_size(mode) * 2;
        let points_size = self.R1.serialized_size(mode) * 2;
        scalars_size + points_size
    }

    /// Serializes the proof into a byte array of 4 32/33-byte elements.
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

#[cfg(test)]
mod tests {
    use crate::utils::*;
    use super::*;
    extern crate hex;
    extern crate ark_secp256k1;
    use serde_json::from_str;
    use std::{fs::File, io::Cursor};
    use std::io::Read;
    use std::ops::{Mul, Add};
    use serde::{Deserialize, Serialize};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_secp256k1::{Config as SecpConfig, Fq as SecpBase};
    use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
    // recipe from:
    // https://stackoverflow.com/questions/70615096/deserialize-json-list-of-hex-strings-as-bytes
    #[derive(Serialize, Deserialize, Debug)]
    #[serde(transparent)]
    struct MyHex {
        #[serde(with = "hex::serde")]
        hex: Vec<u8>,
    }
    /* Structure of test vectors is:
    (see https://github.com/AdamISZ/aut-ct-test-cases/blob/master/src/peddleq.py )
    "case" : str(i),
                    "privkey": hexer(priv),
                    "r": get_rev_bytes(hexer(r), "hex"),
                    "s": get_rev_bytes(hexer(s), "hex"),
                    "t": hexer(get_rev_bytes(hexer(t))),
                    "pc": hexer(convert_to_ark_compressed(pc)),
                    "ki": hexer(convert_to_ark_compressed(ki)),
                    "R1": hexer(convert_to_ark_compressed(R1)),
                    "R2": hexer(convert_to_ark_compressed(R2)),
                    "sigma1": get_rev_bytes(hexer(sigma1), "hex"),
                    "sigma2": get_rev_bytes(hexer(sigma2), "hex"),
                    "e": hexer(get_challenge(R1, R2, pc, ki).to_bytes())}
     */
    #[derive(Serialize, Deserialize)]
    pub struct PedDLEQTestCase {
        case: String, // name/identifier for test case
        privkey: MyHex,
        r: MyHex, // pedersen commitment randomness, "imported" from curve tree proof
        s: MyHex, // "value" portion of commitment for ZkPoK
        t: MyHex, // "blinding" portion of commitment for ZkPoK
        pc: MyHex, // pedersen commitment (point)
        ki: MyHex, // key image
        R1: MyHex, // commitment for ZkPoK (over G)
        R2: MyHex, // commitment for ZkPoK (over J)
        sigma1: MyHex, // sigma protocol response element 1
        sigma2: MyHex, // sigmal protocol response element 2
        e: MyHex, // challenge hash of sigma protocol (sha2 of PRF from STROBE)
    }

    #[derive(Serialize, Deserialize)]
    pub struct PedDLEQTestCaseList {
        cases: Vec<PedDLEQTestCase>,
    }

    #[test]
    fn run_test_cases() {
        type F = <ark_secp256k1::Affine as AffineRepr>::ScalarField;
        let mut file = File::open("testdata/testcases.json").unwrap();
        let mut data = String::new();
        file.read_to_string(&mut data).unwrap();
        let value: Vec<PedDLEQTestCase> = from_str::<Vec<PedDLEQTestCase>>(&data).unwrap();
        // calculate generators G, H, J for all the cases, first.
        let G = SecpConfig::GENERATOR;
        // This is the default H value in curve_trees; could re-derive but pulls in unnecessary deps:
        let Hhex = "87163d621f520cca22c42466af3b046475db26a1177166ba51eac76fc31dc35680".to_string();
        let Hbin = hex::decode(&Hhex).unwrap();
        let mut cursor = Cursor::new(Hbin);
        let H = Affine::<SecpConfig>::deserialize_compressed(
            &mut cursor).expect("Failed to deserialize H");
        // To calculate J, we should provide the root of the tree as a point,
        // but here we're not doing that, so we arbitrarily use H instead.
        let J = get_generators::<SecpBase, SecpConfig>(H, utils::CONTEXT_LABEL);
        for case in value {
            // TODO; why does the compiler try to force the return values
            // into a scalar field of a (projective) config, so I have to force
            // it to switch back to the field element?
            let r = F::from(F::deserialize_compressed(&case.r.hex[..]).unwrap());
            let x = F::from(F::deserialize_compressed(&case.privkey.hex[..]).unwrap());
            let P = G.mul(x).into_affine();
            let s = F::from(F::deserialize_compressed(&case.s.hex[..]).unwrap());
            let t = F::from(F::deserialize_compressed(&case.t.hex[..]).unwrap());
            // first, reconstruct D and E from the given inputs and check it corresponds
            // to the data given in the test vector(fields "pc" and "ki").
            // Then, construct the proof, giving values to the optional arguments,
            // s and t (instead of them being chosen at random, here).
            // Finally compare the proof outputs R1, R2, sigma1, sigma2 and e, with
            // those in the test vector.
            let D = P.add(H.mul(r)).into_affine();
            let E = J.mul(x).into_affine();
            let mut bD = Vec::new();
            D.serialize_compressed(&mut bD).expect("Failed to serialize point");
            assert_eq!(bD, case.pc.hex[..]);
            let mut bE = Vec::new();
            E.serialize_compressed(&mut bE).expect("Failed to serialize point");
            assert_eq!(bE, case.ki.hex[..]);
            let mut transcript = Transcript::new(APP_DOMAIN_LABEL);
            let proof = PedDleqProof::create(
            &mut transcript,
            &D,
            &E,
            &x,
            &r,
            &G,
            &H,
            &J,
            Some(s),
            Some(t),
            utils::CONTEXT_LABEL
            );
            // TODO wrap these up to remove the repetition:
            let mut b = Vec::new();
            proof.R1.serialize_compressed(&mut b).expect("Failed to serialize point");
            assert_eq!(b, case.R1.hex[..]);
            let mut bR2 = Vec::new();
            proof.R2.serialize_compressed(&mut bR2).expect("Failed to serialize point");
            assert_eq!(bR2, case.R2.hex[..]);
            let mut bs1 = Vec::new();
            proof.sigma1.serialize_compressed(&mut bs1).expect("Failed to serialize sigma1");
            assert_eq!(bs1, case.sigma1.hex[..]);
            let mut bs2 = Vec::new();
            proof.sigma2.serialize_compressed(&mut bs2).expect("Failed to serialize sigma2");
            assert_eq!(bs2, case.sigma2.hex[..]);


        }

    }
}


