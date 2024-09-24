// This module generates proofs that the prover holds a certain
// number of taproot utxos whose total value is in a given range,
// without revealing which utxos.

// Component 1: Curve Tree select-and-rerandomize:
// This generates a set of N blinded commitments to leaves of the
// curve tree, which will have been generated using all available
// taproot utxos (the structure and format being extensively explained
// in the other "autct" tool in this repo.)
//
// Note that the leaves of the tree are calculable (by anyone)
// as C_i = P_i + v_i J + 0 *H, where v_i is the sats value of the given
// utxo and P_i is the corresponding (taproot) pubkey.

// Component 2: a bulletproof that the sum of the values v_i in the
// list of blinded commitments C*_i = x_i G + v_i J + r_i H is in a range
// between a declared minimum k and a maximum k + 2^n for some prover-
// declared value of n.
// Note that the "proof in range" part of this is a trivial modification
// of the standard proof that a secret value is in range 0..2^n.

// Component 3: a proof of knowledge of "multi-representation",
// i.e. proving not only that:
// the prover knows x_i, v_i and r_i s.t. C*_i = x_i G + v_i J + r_i H.
// but also:
// the prover knows that C*_i,2 = x_i G_2 + v_i J_2 + r_i H_2.
// this is achieved with a generalisation of Schnorr proofs.
// 
// TODO: note that the multiple bulletproofs here can and should be batched
// for better proof size and verification time, though it is not expected
// for now that any use case would really have a problem with performance.
//
#![allow(non_snake_case)]
extern crate rand;
extern crate alloc;
extern crate ark_secp256k1;

use std::error::Error;
use std::iter::zip;
use std::ops::{Mul, Add};
use ark_ff::PrimeField;
use ark_ec::{short_weierstrass::Affine, short_weierstrass::SWCurveConfig, CurveGroup};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Write,
};
use ark_secp256k1::{Config as SecpConfig, Fq as SecpBase};
use bulletproofs::r1cs::*;
use merlin::Transcript;
use relations::curve_tree::{CurveTree, SelRerandParameters, SelectAndRerandomizePath};
use crate::generalschnorr::{GenSchnorrProof, GENSCHNORR_PROTOCOL_LABEL,
    check_no_duplicate_keyimages_in_repr_proofs};
use crate::sumrangeproof::{sum_range_proof, range_proof_sum_gadgets_verifier};
use crate::autctverifier::verify_curve_tree_proof;
use crate::utils::{get_generators, get_curve_tree_proof_from_curve_tree,
    get_leaf_commitments};

pub const J_GENERATOR_LABEL: &[u8] = b"auditor-J";
pub const H_GENERATOR_LABEL: &[u8] = b"auditor-H";

pub fn get_audit_generators() -> (Affine<SecpConfig>, Affine<SecpConfig>){
    let G = SecpConfig::GENERATOR;
    let J = get_generators::<SecpBase, SecpConfig>(J_GENERATOR_LABEL);
    (G, J)
}


#[derive(Clone)]
pub struct AuditProof<F: PrimeField,
P0: SWCurveConfig<BaseField = F> + Copy,
P1: SWCurveConfig<BaseField = P0::ScalarField, ScalarField = P0::BaseField> + Copy,> {
    pub blinded_commitment_list: Vec<Affine<P0>>,
    pub blinding_base: Affine<P0>,
    pub representation_proofs: Vec<GenSchnorrProof<Affine<P0>>>,
    pub sum_range_proof: R1CSProof<Affine<P0>>,
    pub sum_commitment: Affine<P0>,
     // commitments used in sum range proof
    // same secrets, but different bases, to `blinded_commitment_list`:
    pub Q_comms: Vec<Affine<P0>>,
    pub k: u64,
    pub n: usize,
    pub curvetree_p0_proofs: Vec<R1CSProof<Affine<P0>>>,
    pub curvetree_p1_proofs: Vec<R1CSProof<Affine<P1>>>,
    pub curvetree_paths: Vec<SelectAndRerandomizePath<P0, P1>>,
    // note that we can only use one tree, hence only one root
    // note also that we are restricted to even depth trees,
    // so the root is always in secp.
    pub root: Affine<P0>,
}

impl<F: PrimeField,
P0: SWCurveConfig<BaseField = F> + Copy,
P1: SWCurveConfig<BaseField = P0::ScalarField,
ScalarField = P0::BaseField> + Copy,> AuditProof<F, P0, P1> {
    /// Create a proof of knowledge of the opening
    /// triplet (x, v, r) for D = xG + vJ + rH
    /// for each of a set of utxos, along with proof
    /// of the statement that their total value is in
    /// a range defined by (k, n)
    pub fn create(
        k: u64,
        n: usize,
        G: &Affine<P0>,
        J: &Affine<P0>,
        commitment_list: Vec<Affine<P0>>,
        //witness section:
        privkeys: Vec<P0::ScalarField>,
        values: Vec<u64>,
        // proof parameters:
        keyset: &str,
        curve_tree: &CurveTree<P0, P1>,
        sr_params: &SelRerandParameters<P0, P1>,
        user_string: &str
    ) -> Result<AuditProof<F, P0, P1>, Box<dyn Error>> {
        // 3: curve tree proof for each of the m commitments
        let mut curvetree_p0_proofs: Vec<R1CSProof<Affine<P0>>> = Vec::new();
        let mut curvetree_p1_proofs: Vec<R1CSProof<Affine<P1>>> = Vec::new();
        let mut  curvetree_paths: Vec<SelectAndRerandomizePath<P0, P1>> = Vec::new();
        let mut blindings: Vec<P0::ScalarField> = Vec::new();

        let leaf_commitments = get_leaf_commitments::<F, P0>(
            &(keyset.to_string() + ".p"));
        let mut root: Option<Affine<P0>> = None;
        for i in 0..commitment_list.len() {
            let (p0proof,
                p1proof,
                path,
                r,
                _, // we don't need H because it is static
                rt,
                _) = match // parity flip
                get_curve_tree_proof_from_curve_tree::<
                    F,
                    P0,
                    P1>(
                    curve_tree,
                    &leaf_commitments, commitment_list[i],
                sr_params) {
                    Err(e) => {return Err(e.into());},
                        Ok((p0proof,
                            p1proof,
                            path,
                        r,
                        H,
                        root,
                        privkey_parity_flip)) => (p0proof,
                            p1proof,
                            path,
                        r,
                        H,
                        root,
                        privkey_parity_flip),
                    };
            // TODO sanity check all same maybe?
            root = Some(rt);

            curvetree_p0_proofs.push(p0proof);
            curvetree_p1_proofs.push(p1proof);
            curvetree_paths.push(path);
            blindings.push(r);
        };
        // TODO
        assert!(root.is_some());

        // 2: proof of sum-in-range
        let (proof2, comm_sum,
            Q_comms, H) =
         match sum_range_proof::<Affine<P0>>(
            values.clone(),
            Some(privkeys.clone()),
            Some(blindings.clone()),
            k,
            n,
            &sr_params.even_parameters.pc_gens,
            &sr_params.even_parameters.bp_gens
        ){
            Ok((a, b, c, H))
            => (a, b, c, H),
            // TODO error handling
            Err(_) => panic!("Error in sum range proof."),
        };
        // get the vector of blinded commitments.
        let blinded_commitment_list = zip(
            blindings.clone(), commitment_list)
            .into_iter().map(|(x, y)| y.add(
            H.mul(x)).into_affine()).collect::<Vec<_>>();
        // 1: proof of knowledge of representation:
        let mut repr_proofs: Vec<GenSchnorrProof<Affine<P0>>> = Vec::new();
        for i in 0..Q_comms.len() {
            let mut transcript = Transcript::new(
                GENSCHNORR_PROTOCOL_LABEL);
            // the secrets will be: (x, v, r).
            // the two bases sets will be:
            // 1. G, J, H
            // 2. G1, G2, H where G1, G2 come from the bp_gens.
            // TODO is the fact that the H is the same a problem? It can be changed.
            let bpgensshare =
            sr_params.even_parameters.bp_gens.share(0);
            let g1g2: Vec<&Affine<P0>> = bpgensshare.G(2).collect();
            let firstrow = vec![*G, *J, H];
            let secondrow = vec![*g1g2[0], *g1g2[1], H];
            let keyimagebase: Affine<P0> = get_generators(b"auditproof-keyimage");
            let secrets = vec![privkeys[i],
            values[i].into(), blindings[i]];
            let basesvec = vec![firstrow, secondrow];
            let comms = vec![blinded_commitment_list[i], Q_comms[i]];
            repr_proofs.push(GenSchnorrProof::create(
                &mut transcript,
                &comms,
                &secrets,
                &basesvec,
                keyimagebase,
                // TODO labelling:
                b"bloo", user_string.as_bytes()));
        }
        // We now have a full set of AuditProof elements:
        Ok(AuditProof{
            blinded_commitment_list,
            blinding_base: H,
            representation_proofs: repr_proofs,
            sum_range_proof: proof2,
            sum_commitment: comm_sum,
            Q_comms,
            k,
            n,
            curvetree_p0_proofs,
            curvetree_p1_proofs,
            curvetree_paths,
            root: root.unwrap(),
        })
    }

    pub fn verify(
        &self, G: &Affine<P0>, J: &Affine<P0>,
        curve_tree: &CurveTree<P0, P1>,
        sr_params: &SelRerandParameters<P0, P1>,
        user_string: &str
    ) -> Result<(), Box<dyn Error>>
    {
        // Before verifying the ZK proofs,
        // we can check whether the published
        // key images are unique, which is a requirement
        // to prove that the same utxo is not reused:
        check_no_duplicate_keyimages_in_repr_proofs(
            &self.representation_proofs)?;

        let m = self.blinded_commitment_list.len();
        for i in 0..m {
            // verify representation proof
            let mut transcript = Transcript::new(
                GENSCHNORR_PROTOCOL_LABEL);
            // calculate the bases:
            let bpgensshare =
            sr_params.even_parameters.bp_gens.share(0);
            let g1g2: Vec<&Affine<P0>> = bpgensshare.G(2).collect();
            let firstrow = vec![*G, *J, self.blinding_base];
            let secondrow =
            vec![*g1g2[0], *g1g2[1], self.blinding_base];
            let basesvec = vec![firstrow, secondrow];
            self.representation_proofs[i].verify(
                &mut transcript,
                &vec![self.blinded_commitment_list[i], self.Q_comms[i]],
                &basesvec,
                b"bloo", // TODO labels
                user_string.as_bytes()
            )?;
        }
        for i in 0..m {
            // verify curve tree proof
            // TODO obviously this should be an aggregated proof!
            let claimed_D = verify_curve_tree_proof(
                self.curvetree_paths[i].clone(),
                &sr_params, 
                &curve_tree,
                &self.curvetree_p0_proofs[i],
                &self.curvetree_p1_proofs[i],
                self.root)?;
            if claimed_D != self.blinded_commitment_list[i] && claimed_D != -self.blinded_commitment_list[i] {
                return Err("Commitment did not match the curve tree proof".into());
            }
        }
        // verify sum-range proof:
        range_proof_sum_gadgets_verifier(&sr_params.even_parameters.pc_gens,
        &sr_params.even_parameters.bp_gens, &self.sum_range_proof,
        self.sum_commitment,self.k, self.n,
    &self.Q_comms)?;
        println!("Audit proof verification successful");
        Ok(())
    }
    /// Returns the size in bytes required to serialize the entire audit proof
    pub fn serialized_size(&self, compress: Compress) -> usize {
        // Three main components are:
        // 1 list of all curve tree membership proofs
        // 2 list of representation proofs
        // 3 list of sum-range proofs.
        // Note that there is overlap: in particular, the blinded
        // commitment used as public input to the curve tree proof,
        // is the same blinded commitment used in the representation
        // proof (and there are m of them for m utxos), see "Qcomms"
        // and "blinded_commitments"
        let blinded_commitment_size =
        self.blinded_commitment_list.serialized_size(compress);
        let p0proofs_size =
        self.curvetree_p0_proofs.serialized_size(compress);
        let p1proofs_size =
        self.curvetree_p1_proofs.serialized_size(compress);
        let paths_size =
        self.curvetree_paths.serialized_size(compress);
        let repr_proofs_size =
        self.representation_proofs.serialized_size(compress);
        // The sum-range proof is an R1CS Proof, a single commitment
        // (for the sum) and the re-blinded "Q-comms" commitments
        let sum_range_proof_size =
        self.sum_range_proof.serialized_size(compress) + 33;
        let Q_comms_size = self.Q_comms.serialized_size(compress);
        let k_size = self.k.serialized_size(compress);
        let n_size = self.n.serialized_size(compress);
        // add one more 33 for root and one for blinding base
        blinded_commitment_size + p0proofs_size + p1proofs_size
        + paths_size + 33*2 + sum_range_proof_size + Q_comms_size
        + repr_proofs_size + k_size + n_size
    }
}

impl<F: PrimeField,
P0: SWCurveConfig<BaseField = F> + Copy,
P1: SWCurveConfig<BaseField = P0::ScalarField,
ScalarField = P0::BaseField> + Copy,> Valid for AuditProof<F, P0, P1> {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}
impl<F: PrimeField,
P0: SWCurveConfig<BaseField = F> + Copy,
P1: SWCurveConfig<BaseField = P0::ScalarField,
ScalarField = P0::BaseField> + Copy,> CanonicalSerialize for AuditProof<F, P0, P1> {
    /// Returns the size in bytes required to serialize the ped-dleq proof
    /// TODO: Why is this copy-pasted from the struct function?
    fn serialized_size(&self, compress: Compress) -> usize {
        let blinded_commitment_size =
        self.blinded_commitment_list.serialized_size(compress);
        let p0proofs_size =
        self.curvetree_p0_proofs.serialized_size(compress);
        let p1proofs_size =
        self.curvetree_p1_proofs.serialized_size(compress);
        let paths_size =
        self.curvetree_paths.serialized_size(compress);
        let repr_proofs_size =
        self.representation_proofs.serialized_size(compress);
        // The sum-range proof is an R1CS Proof, a single commitment
        // (for the sum) and the re-blinded "Q-comms" commitments
        let sum_range_proof_size =
        self.sum_range_proof.serialized_size(compress) + 33;
        let Q_comms_size = self.Q_comms.serialized_size(compress);
        let k_size = self.k.serialized_size(compress);
        let n_size = self.n.serialized_size(compress);
        // add one more 33 for root and one for blinding base
        blinded_commitment_size + p0proofs_size + p1proofs_size
        + paths_size + 33*2 + sum_range_proof_size + Q_comms_size
        + repr_proofs_size + k_size + n_size
    }

    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.blinded_commitment_list.serialize_with_mode(&mut writer, compress)?;
        self.blinding_base.serialize_with_mode(&mut writer, compress)?;
        self.curvetree_p0_proofs.serialize_with_mode(&mut writer, compress)?;
        self.curvetree_p1_proofs.serialize_with_mode(&mut writer, compress)?;
        self.curvetree_paths.serialize_with_mode(&mut writer, compress)?;
        self.root.serialize_with_mode(&mut writer, compress)?;
        self.representation_proofs.serialize_with_mode(&mut writer, compress)?;
        self.sum_range_proof.serialize_with_mode(&mut writer, compress)?;
        self.sum_commitment.serialize_with_mode(&mut writer, compress)?;
        self.Q_comms.serialize_with_mode(&mut writer, compress)?;
        self.k.serialize_with_mode(&mut writer, compress)?;
        self.n.serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }
}

impl<F: PrimeField,
P0: SWCurveConfig<BaseField = F> + Copy,
P1: SWCurveConfig<BaseField = P0::ScalarField,
ScalarField = P0::BaseField> + Copy,> CanonicalDeserialize for AuditProof<F, P0, P1> {
    fn deserialize_with_mode<Re: Read>(
        mut reader: Re,
        compress: Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> { 
        Ok(Self {
            blinded_commitment_list: Vec::<Affine<P0>>::deserialize_with_mode(
                &mut reader, compress, validate)?,
            blinding_base: Affine::<P0>::deserialize_with_mode(
                &mut reader, compress, validate)?,
            curvetree_p0_proofs: Vec::<R1CSProof<Affine<P0>>>::deserialize_with_mode(
                &mut reader, compress, validate)?,
            curvetree_p1_proofs: Vec::<R1CSProof<Affine<P1>>>::deserialize_with_mode(
                &mut reader, compress, validate)?,
            curvetree_paths: Vec::<SelectAndRerandomizePath<P0, P1>>::deserialize_with_mode(
                &mut reader, compress, validate)?,
            root: Affine::<P0>::deserialize_with_mode(&mut reader, compress, validate)?,
            representation_proofs: Vec::<GenSchnorrProof<Affine<P0>>>::deserialize_with_mode(
                &mut reader, compress, validate)?,
            sum_range_proof: R1CSProof::<Affine<P0>>::deserialize_with_mode(
                &mut reader, compress, validate)?,
            sum_commitment: Affine::<P0>::deserialize_with_mode(&mut reader, compress, validate)?,
            Q_comms: Vec::<Affine<P0>>::deserialize_with_mode(&mut reader, compress, validate)?,
            k: u64::deserialize_with_mode(&mut reader, compress, validate)?,
            n: usize::deserialize_with_mode(&mut reader, compress, validate)?
        })
    }
}