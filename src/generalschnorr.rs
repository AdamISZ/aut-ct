#![allow(non_snake_case)]
extern crate rand;
extern crate alloc;
extern crate ark_secp256k1;

use std::{collections::HashSet, error::Error};

use crate::utils;

use alloc::vec::Vec;
use ark_ec::{AffineRepr, VariableBaseMSM};
use ark_ff::Field;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Write,
};
use ark_std::UniformRand;
use merlin::Transcript;

pub const GENSCHNORR_PROTOCOL_LABEL: &[u8] = b"autct-generalised-schnorr";
pub const GENSCHNORR_PROTOCOL_VERSION: u64 = 1;
pub trait TranscriptProtocol {
    fn gs_proof_domain_sep(&mut self, app_context_label: &[u8], user_string: &[u8]);

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

    fn gs_proof_domain_sep(&mut self,
        app_context_label: &[u8], user_string: &[u8]) {
        self.append_message(b"dom-sep",
        GENSCHNORR_PROTOCOL_LABEL);
        // This is the version number for this sub-protocol (3-proof)
        // separate from version of higher level proto that uses it:
        self.append_u64(b"n",
        GENSCHNORR_PROTOCOL_VERSION);
        // This label is for the top level application using the protocol:
        self.append_message(b"dom-sep",
        app_context_label);
        // This label is specific to this instance of the protocol;
        // typically it is an ephemeral user ID, though it can be anything:
        self.append_message(b"dom-sep",
        user_string);
    }

    fn append_scalar<C: AffineRepr>(&mut self,
        label: &'static [u8], scalar: &C::ScalarField) {
        self.append_message(label,
            &utils::field_as_bytes(scalar));
    }

    fn append_point<C: AffineRepr>(&mut self,
        label: &'static [u8], point: &C) {
        let mut bytes = Vec::new();
        if let Err(e) =
        point.serialize_compressed(&mut bytes) {
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
            if let Err(e) =
            point.serialize_compressed(&mut bytes) {
                panic!("{}", e)
            }
            self.append_message(label, &bytes);
            Ok(())
        }
    }

    fn challenge_scalar<C: AffineRepr>(&mut self,
        label: &'static [u8]) -> C::ScalarField {
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


#[derive(Clone, Debug)]
pub struct GenSchnorrProof<C: AffineRepr> {
    pub Rvec: Vec<C>,
    pub sigmavec: Vec<C::ScalarField>,
    pub RI: C,
    pub I: C,
    pub keyimagebase: C,
}

impl<C: AffineRepr> GenSchnorrProof<C> {
    /// Create a proof of knowledge of the opening
    /// tuple (x1, x2, ...) for C_i = Sum (x_i * Base_(i,j))
    /// for a matrix of bases i x j in size.
    /// Additionally, return I = x_1 Q as an
    /// "adjunct" key-image that allows verification
    /// that the same x value is not reused.
    /// Note that there is only *one* vector of x values here,
    /// i.e. we are doing proof of *same* representation, across
    /// multiple base sets.
    pub fn create(
        transcript: &mut Transcript,
        Ci: &Vec::<C>, // publicised commitments against which we are proving
        x: &Vec<C::ScalarField>, // secret commitment openings
        basesvec: &Vec<Vec::<C>>, // a matrix of bases
        keyimagebase: C, // a single extra base for key images
        app_context_label: &[u8],
        user_string: &[u8]
    ) -> GenSchnorrProof<C> {
        transcript.gs_proof_domain_sep(app_context_label, user_string);
        // for every "claim" (commitment provided),
        // there'll be an "R" (ephemeral commitment).
        // Then after the challenge:
        // for every base, there'll be a response sigma.
        let mut Rvec: Vec<C> = Vec::new();
        let mut noncesvec: Vec<C::ScalarField> = Vec::new();
        let mut rng = rand::thread_rng();
        for _ in 0..x.len() {
            noncesvec.push(C::ScalarField::rand(&mut rng));
        }
        for j in 0..Ci.len(){
            transcript.append_point(b"C", &Ci[j]);
            let tempR = C::Group::msm_unchecked(
                basesvec[j].as_slice(), &noncesvec).into();
            // TODO change label per index
            transcript.append_point(b"R", &tempR);
            Rvec.push(tempR);
        }
        // the nonce for the key image
        let RI = keyimagebase.mul(noncesvec[0]).into();
        transcript.append_point(b"RI", &RI);
        // the key image I = x_1Q
        let I = keyimagebase.mul(x[0]).into();
        transcript.append_point(b"I", &I);
        let e = 
        transcript.challenge_scalar::<C>(b"e");
        let mut sigmavec: Vec<C::ScalarField> = Vec::new();
        for i in 0..x.len() {
            sigmavec.push(noncesvec[i] + (e)*(x[i]));
        }

        GenSchnorrProof {
            Rvec,
            sigmavec,
            RI,
            I,
            keyimagebase,
        }
    }
    pub fn verify(
        &self,
        transcript: &mut Transcript,
        Ci: &Vec::<C>, // publicised commitments against which we are verifying
        basesvec: &Vec<Vec<C>>, // a matrix of bases
        app_context_label: &[u8],
        user_string: &[u8]
    ) -> Result<(), &str>
    {
        //form correct hash challenge
        transcript.gs_proof_domain_sep(app_context_label, user_string);
        for i in 0..Ci.len(){
            transcript.append_point(b"C", &Ci[i]);
            transcript.append_point(b"R", &self.Rvec[i]);
        }
        transcript.append_point(b"RI", &self.RI);
        transcript.append_point(b"I", &self.I);
        let e =
        transcript.challenge_scalar::<C>(b"e");
        for i in 0..Ci.len() {
            // R_i + eC_i = sum (sigma_j * base_j)
            let lhs: C = (self.Rvec[i] + Ci[i].mul(e)).into();
            let rhs: C = C::Group::msm_unchecked(
                &basesvec[i], &self.sigmavec).into();
            if ! (rhs == lhs) {
                return Err("Generalized schnorr proof failed to verify".into());
            }
            // R_I + eI = sigma_0 * keyimage_base
            let lhs: C = self.RI.add(self.I.mul(e)).into();
            let rhs: C = self.keyimagebase.mul(self.sigmavec[0]).into();
            if ! (rhs == lhs) {
                return Err(
                    "Generalized schnorr proof failed to verify (keyimage)"
                    .into());
            }
        }
        Ok(())
    }
    /// Returns the size in bytes required to serialize the proof
    pub fn serialized_size(&self, compress: Compress) -> usize {
        let scalars_size = self.sigmavec.serialized_size(compress);
        let points_size = self.Rvec.serialized_size(compress);
        let RIsize = self.RI.serialized_size(compress);
        let Isize = self.I.serialized_size(compress);
        let keyimagebasesize = self.keyimagebase.serialized_size(compress);
        scalars_size + points_size + RIsize + Isize + keyimagebasesize
    }
}

impl<C: AffineRepr> Valid for GenSchnorrProof<C> {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}
impl<C: AffineRepr> CanonicalSerialize for GenSchnorrProof<C> {
    /// Returns the size in bytes required to serialize the proof
    /// TODO: Why is this copy-pasted from the struct function?
    fn serialized_size(&self, compress: Compress) -> usize {
        let scalars_size = self.sigmavec.serialized_size(compress);
        let points_size = self.Rvec.serialized_size(compress);
        let RIsize = self.RI.serialized_size(compress);
        let Isize = self.I.serialized_size(compress);
        let keyimagebasesize = self.keyimagebase.serialized_size(compress);
        scalars_size + points_size + RIsize + Isize + keyimagebasesize
    }

    /// Serializes the proof into a byte array of 32/33-byte elements.
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.Rvec.serialize_with_mode(&mut writer, compress)?;
        self.sigmavec.serialize_with_mode(&mut writer, compress)?;
        self.RI.serialize_with_mode(&mut writer, compress)?;
        self.I.serialize_with_mode(&mut writer, compress)?;
        self.keyimagebase.serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }
}

impl<C: AffineRepr> CanonicalDeserialize for GenSchnorrProof<C> {
    fn deserialize_with_mode<Re: Read>(
        mut reader: Re,
        compress: Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        Ok(Self {
            Rvec: Vec::<C>::deserialize_with_mode(&mut reader, compress, validate)?,
            sigmavec: Vec::<C::ScalarField>::deserialize_with_mode(&mut reader, compress, validate)?,
            RI: C::deserialize_with_mode(&mut reader, compress, validate)?,
            I: C::deserialize_with_mode(&mut reader, compress, validate)?,
            keyimagebase: C::deserialize_with_mode(&mut reader, compress, validate)?,
        })
    }
}

pub fn check_no_duplicate_keyimages_in_repr_proofs<C: AffineRepr>(
    repr_proofs: &Vec<GenSchnorrProof<C>>)
    -> Result<(), Box<dyn Error>>{
    let keyimages: Vec<C> = repr_proofs
        .iter().map(|x| x.I).collect::<Vec<_>>();
        let uniques_len = keyimages.iter()
        .collect::<HashSet<&C>>()
        .len();
        if uniques_len != keyimages.len() {
                return Err("Duplicate key images in representation proofs".into());
        }
        Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::ThreadRng;
    use rand::thread_rng;
    extern crate hex;
    extern crate ark_secp256k1;
    use ark_ec::AffineRepr;
    use ark_secp256k1::Config as SecpConfig;
    use ark_ec::short_weierstrass::Affine;
    use crate::affine_from_bytes_tai;
    use crate::utils::get_generators;
    type F = <ark_secp256k1::Affine as AffineRepr>::ScalarField;
    use ark_ec::CurveGroup;

    /// Useful to be able to create a whole batch of repr
    /// proofs so that we can check cross-proof properties,
    /// specifically key image:
    fn generate_rand_repr_proofs(
        n: usize, ncomms: usize, nbases: usize, rng: &mut ThreadRng)
        -> (Vec<GenSchnorrProof<Affine<SecpConfig>>>,
            Vec<Vec<Vec<Affine<SecpConfig>>>>,
            Vec<Vec<Affine<SecpConfig>>>,
            Vec<Vec<F>>){
        let mut proofsres: Vec<GenSchnorrProof<Affine<SecpConfig>>> = Vec::new();
        let mut basesres: Vec<Vec<Vec<Affine<SecpConfig>>>> = Vec::new();
        let mut commsres: Vec<Vec<Affine<SecpConfig>>> = Vec::new();
        let mut secretsres: Vec<Vec<F>> = Vec::new(); 
        for _ in 0..n {
            let mut bases: Vec<Vec::<Affine<SecpConfig>>> = Vec::new();
            let mut comms: Vec::<Affine<SecpConfig>> = Vec::new();
            let mut secrets: Vec<F> = Vec::new();
            // note there are ixj bases:
            for j in 0..ncomms {
                let mut vectemp = Vec::new();
                for i in 0..nbases {
                    vectemp.push(
                        affine_from_bytes_tai(&(j*nbases + i).to_be_bytes()));
                }
                bases.push(vectemp);
            }
            for _ in 0..nbases {
                // (TODO make secrets determ. rand. as well?)
                secrets.push(F::rand(rng));
            }

            for i in 0..ncomms {
                comms.push(<ark_secp256k1::Affine as AffineRepr>::Group::msm_unchecked(
                    &bases[i as usize], &secrets
                ).into());
            }
            let keyimagebase = get_generators(b"test-keyimage");
            let mut transcript = Transcript::new(&GENSCHNORR_PROTOCOL_LABEL);
            proofsres.push(GenSchnorrProof::<Affine<SecpConfig>>::create(
                &mut transcript,
                &comms,
                &secrets,
                &bases,
                keyimagebase,
                b"test context label",
                    b"test user string"
            ));
            basesres.push(bases);
            commsres.push(comms);
            secretsres.push(secrets);
        }
        (proofsres, basesres, commsres, secretsres)
    }
    #[test]
    fn test_no_reuse(){
        let mut rng = rand::thread_rng();
        let (prfs, _, _, _) =
        generate_rand_repr_proofs(10, 5, 4, &mut rng);
        assert!(check_no_duplicate_keyimages_in_repr_proofs(&prfs).is_ok());

    }

    #[test]
    fn gs_cases_basic() {
        let mut rng = rand::thread_rng();
        //let mut rng = thread_rng();
        let (prfs, bases, comms, _) =
        generate_rand_repr_proofs(1, 5, 4, &mut rng);

        let mut transcript = Transcript::new(&GENSCHNORR_PROTOCOL_LABEL);
        assert!(prfs[0].verify(&mut transcript,
            &comms[0],
            &bases[0],
            b"test context label",
                b"test user string").is_ok());
        // it should not pass verification with invalid R values
        let mut prf_invalid_R: GenSchnorrProof<Affine<SecpConfig>>=
        prfs[0].clone();
        prf_invalid_R.Rvec[0] =
        <ark_secp256k1::Affine as AffineRepr>::Group::rand(
            &mut rng).into_affine();
        transcript = Transcript::new(&GENSCHNORR_PROTOCOL_LABEL);
        assert!(prf_invalid_R.verify(&mut transcript,
            &comms[0],
            &bases[0],
            b"test context label",
                b"test user string").is_err());
        // It should not pass validation with invalid sigma values
        let mut prf_invalid_sigma:
        GenSchnorrProof<Affine<SecpConfig>> =
        prfs[0].clone();
        prf_invalid_sigma.sigmavec[0] =
        F::rand(&mut rng);
        transcript = Transcript::new(&GENSCHNORR_PROTOCOL_LABEL);
        assert!(prf_invalid_sigma.verify(&mut transcript,
            &comms[0],
            &bases[0],
            b"test context label",
                b"test user string").is_err());

    }
}

