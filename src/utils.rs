#![allow(non_snake_case)]
extern crate rand;
extern crate alloc;
extern crate ark_secp256k1;

use ark_ff::{BigInteger, Field};
use ark_ff::{PrimeField, Zero, One};
use ark_ec::AffineRepr;
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::short_weierstrass::Affine;
use relations::curve_tree::CurveTree;
use std::error::Error;
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;
use std::time::Instant;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use relations::curve_tree::{SelRerandParameters, SelectAndRerandomizePath};
use bulletproofs::r1cs::R1CSProof;
use bulletproofs::r1cs::Prover;
use merlin::Transcript;

// all transcripts created in this project should be
// initialized with this name:
pub const APP_DOMAIN_LABEL: &[u8] = b"autct-v1.0";
pub const BRANCHING_FACTOR: usize = 256;
// specific to an application; this default is only for tests.
// Should be set in the config file, in the field `context_label`.
pub const CONTEXT_LABEL: &[u8] = b"default-app-context-label";
// specific to a protocol-instance run; typically it should be
// an ephemeral user id. Like the above, the default exists
// primarily for testing
pub const USER_STRING: &[u8] = b"name-goes-here";



// Given a hex string of big-endian encoding,
// first change to little endian bytes and then deserialize
// it as a field element
pub fn decode_hex_le_to_F<F: PrimeField>(s: &String) -> F{
    let mut x = hex::decode(s).expect("Invalid hex encoding");
    x.reverse();
    F::deserialize_compressed(&x[..]).unwrap()
}

pub fn print_field_elem_hex<F: PrimeField>(x: &F, name: &str) {
    let mut b = Vec::new();
    x.serialize_compressed(&mut b).expect("Failed to serialize field element");
    println!("This is the value of {}: {:#?}", name, hex::encode(&b));
}

pub fn print_affine_compressed<F: PrimeField,
P0: SWCurveConfig<BaseField = F> + Copy>(pt: Affine<P0>, name: &str) {
    let mut b = Vec::new();
        pt.serialize_compressed(&mut b).expect("Failed to serialize point");
    println!("This is the value of {}: {:#?}", name, hex::encode(&b));
}

// protocol requires three generators G, H, J (ignoring
// bulletproofs itself):
// G is a known constant generator.
// H is currently gotten from the CurveTree rerandomization,
// because we have to use the same blinding element in both
// sub protocols. (but note, we are currently using a default
// value, and the verifier must ensure that it is NUMS, so
// TODO: add this back here.)
// J must be defined globally for the given context, so we give
// two bits of context: an application specific label, and a tree
// root (which ensures both sides are working on the same Curve
// Tree).
pub fn get_generators<F: PrimeField,
P0: SWCurveConfig<BaseField = F> + Copy>(
    label: &[u8]) -> Affine<P0>{
    // in line with above comments, probably peel out the
    // algorithm for J into a separate sub-function, because
    // we will probably want to add an optional counter.
    // for now:
    // format "J"||app-label, then pass through string-to-point algo.
    // see issue #7, #8 for discussion.
    let mut b = Vec::new();
    b.extend(b"J"); //TODO <- not correct, make it an arg.
    b.extend(label);
    affine_from_bytes_tai::<Affine<P0>>(&b)
}

pub fn field_as_bytes<F: Field>(field: &F) -> Vec<u8> {
    let mut bytes = Vec::new();
    if let Err(e) = field.serialize_compressed(&mut bytes) {
        panic!("{}", e)
    }
    bytes
}

pub fn read_file_string(filepath: &str) -> Result<String, Box<dyn Error>> {
    let resp = match fs::read_to_string(filepath) {
        Ok(data) => data,
        Err(e) => {return Err(e.into());}
    };
    Ok(resp.trim_end().to_string())
}

pub fn write_file_string(filepath: &str, mut buf: Vec<u8>) -> () {
    fs::write(filepath, &mut buf).expect("Failed to write to file");
}

pub fn write_file_string2(loc: PathBuf, mut buf: Vec<u8>) ->Result<(), std::io::Error> {
    fs::write(loc, &mut buf)
}

// an effective generation of NUMS deterministically:
pub fn affine_from_bytes_tai<C: AffineRepr>(bytes: &[u8]) -> C {
    extern crate crypto;
    use crypto::digest::Digest;
    use crypto::sha2::Sha256;

    for i in 0..=u8::max_value() {
        let mut sha = Sha256::new();
        sha.input(bytes);
        sha.input(&[i]);
        let mut buf = [0u8; 32];
        sha.result(&mut buf);
        let res = C::from_random_bytes(&buf);
        if let Some(point) = res {
            return point;
        }
    }
    panic!()
}

// This function takes pubkeys in binary
// as serialized from ark and written to a file,
// and stores them in a Vec of curve points.
pub fn get_leaf_commitments<F: PrimeField,
P0: SWCurveConfig<BaseField = F> + Copy>(pubkey_file_path: &str) -> Vec<Affine<P0>>{
    let buf = fs::read(pubkey_file_path).unwrap();
    let pts_bin: Vec<&[u8]> = buf.chunks(33).into_iter().map(|x: &[u8]| {
        x
    })
    .collect();
    let mut leaf_commitments = Vec::new();
    let desertime = Instant::now();
    for a in pts_bin.into_iter(){
        let x = <Affine<P0>>::deserialize_compressed_unchecked(
            &a[..]).expect("Failed to deserialize point");
        leaf_commitments.push(x);
    }
    println!("Elapsed time for deser: {:.2?}", desertime.elapsed());
    leaf_commitments
}


pub fn get_correct_pubkeys_from_ark_hex_list<F: PrimeField,
P0: SWCurveConfig<BaseField = F> + std::marker::Copy>(
    ark_ser_list: Vec<&str>) ->
    Result<Vec<Affine<P0>>, Box<dyn Error>>
    {
        let mut b: Vec<Vec<u8>> = Vec::new();
        for s in ark_ser_list {
            // TODO, also why doesn't the below map work?
            b.push(hex::decode(s).unwrap());
        }

        //ark_ser_list.iter().map(|x|
        //    match hex::decode(x){
        //        Ok(y) => y,
        //        Err(e) => return Err(e)
        //    })
        //   .collect();
    let mut pubkeys = Vec::new();
    for a in b{
        let mut cursor = Cursor::new(a);
        match Affine::<P0>::deserialize_with_mode(&mut cursor,
            ark_serialize::Compress::Yes,
            ark_serialize::Validate::Yes){
            Ok(Q) => {
                pubkeys.push(Q);
            },
            Err(_) => {println!("Invalid hex pubkey detected, ignoring.")}
        };
    }
    Ok(pubkeys)
}

/// Given a list of BIP340 encoded keys as hex string
/// serializations, convert each one into a curve point
/// Affine<SecpConfig>, but ensure that the point returned
/// has even parity.
pub fn get_correct_pubkeys_from_bip340_hex_list<F: PrimeField,
P0: SWCurveConfig<BaseField = F> + std::marker::Copy>(
    bip340_ser_list: Vec<&str>) ->
    Result<Vec<Affine<P0>>, Box<dyn Error>>
    {
    let mut b = Vec::new();
    for s in bip340_ser_list {
        let o_sbin = hex::decode(s);
        match o_sbin {
            Ok(x) => {let mut sbin = x;
                sbin.reverse();
                // we don't attempt to calculate a sign,
                // because we only care about parity,
                // which is handled in the second loop below.
                sbin.push(0u8);
                b.push(sbin.clone())},
            Err(e) => {println!("Error {}", e)}
        }
    }
    let mut pubkeys = Vec::new();
    for a in b{
        let mut cursor = Cursor::new(a);
        match Affine::<P0>::deserialize_with_mode(&mut cursor,
            ark_serialize::Compress::Yes,
            ark_serialize::Validate::Yes){
            Ok(Q) => {
                let mut P = Q.clone();
                let yval: F = *P.y().unwrap();
                let yvalint = yval.into_bigint();
                if yvalint.is_odd() {
                    P = -P;}
                pubkeys.push(P);
            },
            Err(_) => {println!("Invalid hex pubkey detected, ignoring.")}
        };
    }
    Ok(pubkeys)
}

/// This function wraps get_correct_pubkeys_from_bip340hex,
/// handling the file input
pub fn get_pubkey_leaves_hex<F: PrimeField,
                P0: SWCurveConfig<BaseField = F>
                + std::marker::Copy>(pubkey_file_path: &str)
                -> Vec<Affine<P0>>{
    // this whole section is clunky TODO
    // (need to reverse each binary string, but reverse() is 'in place', hence loop,
    // so the "TODO" is how to do that more elegantly)
    let filestr:String = read_file_string(pubkey_file_path)
    .expect("my failure message");
    let hex_keys_vec = filestr.split_whitespace().collect::<Vec<_>>();
    get_correct_pubkeys_from_ark_hex_list::<F, P0>(hex_keys_vec).unwrap()
}

pub fn create_permissible_points_and_randomnesses<
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

pub fn get_curve_tree<
F: PrimeField,
P0: SWCurveConfig<BaseField = F> + Copy,
P1: SWCurveConfig<BaseField = P0::ScalarField, ScalarField = P0::BaseField> + Copy,>(
    leaf_commitments: &Vec<Affine<P0>>,
    depth: usize,
    sr_params: &SelRerandParameters<P0, P1>) -> (CurveTree<P0, P1>, Affine<P0>){
    //let leaf_commitments = get_leaf_commitments(file_loc);
    let curve_tree = CurveTree::<P0, P1>::from_set(
        leaf_commitments, sr_params, Some(depth));
    (curve_tree, sr_params.even_parameters.pc_gens.B_blinding)
}

/// Derive the index where our pubkey is in the list.
/// but: since it will have been permissible-ized, we need to rederive the permissible
/// version here, purely for searching. This is a little involved!
/// First, as well as the randomness in the blinded commitment, we also need to use the same
/// blinding base.
/// Second, the randomness for the additional proofs will have to be the randomness
/// used in the curve tree randomization, *plus* the randomness that was used
/// to convert P to a permissible point, upon initial insertion into the tree.
/// We need to keep track of what this tweak is, in both possibilities of positive
/// and negative of initial key.
pub fn get_key_index_from_leaves<F: PrimeField,
P0: SWCurveConfig<BaseField = F> + Copy,
P1: SWCurveConfig<BaseField = P0::ScalarField, ScalarField = P0::BaseField> + Copy,>(
    leaf_commitments: &Vec<Affine<P0>>,
    b_blinding: Affine<P0>,
    sr_params: &SelRerandParameters<P0, P1>,
    our_pubkey: Affine<P0>) -> Result<(i32, P0::ScalarField, bool), Box<dyn Error>> {
    let mut privkey_parity_flip: bool = false;
    let mut r_offset1: P0::ScalarField = P0::ScalarField::zero();
    let mut r_offset2: P0::ScalarField = P0::ScalarField::zero();
    let mut r_offset: P0::ScalarField = P0::ScalarField::zero();
    let mut our_pubkey_permiss1: Affine<P0> = our_pubkey;
    while !sr_params.even_parameters.uh.is_permissible(our_pubkey_permiss1) {
        our_pubkey_permiss1 = (our_pubkey_permiss1 + b_blinding).into();
        r_offset1 += P0::ScalarField::one();
    }
    let mut our_pubkey_permiss2: Affine<P0> = -our_pubkey;
    while !sr_params.even_parameters.uh.is_permissible(our_pubkey_permiss2) {
        our_pubkey_permiss2 = (our_pubkey_permiss2 + b_blinding).into();
        r_offset2 += P0::ScalarField::one();
    }
    let mut key_index: i32; // we're guaranteed to overwrite or panic but the compiler insists.
    // the reason for 2 rounds of search is that BIP340 can output a different parity
    // compared to ark-ec 's compression algo.
    key_index = match leaf_commitments.iter().position(|&x| x  == our_pubkey_permiss1) {
        None => -1,
        Some(ks) => {r_offset = r_offset1;
            ks.try_into().unwrap()}
    };
    if key_index == -1 {
        key_index = match leaf_commitments.iter().position(|&x| x == our_pubkey_permiss2) {
            None => {return Err("provided pubkey not found in the set".into());},
            Some(ks) => {
                privkey_parity_flip = true;
                r_offset = r_offset2;
                ks.try_into().unwrap()
            }
        }
    };
    Ok((key_index, r_offset, privkey_parity_flip))
}


// this function returns the curve tree for the set of points
// read from disk (currently pubkey file location is passed as an argument), and
// then returns a tree, along with two bulletproofs for secp and secq,
// and the "merkle proof" of (blinded) commitments to the root.
// For the details on this proof, see "Select-and-Rerandomize" in the paper.
pub fn get_curve_tree_with_proof<
    F: PrimeField,
    P0: SWCurveConfig<BaseField = F> + Copy,
    P1: SWCurveConfig<BaseField = P0::ScalarField, ScalarField = P0::BaseField> + Copy,
>(
    depth: usize,
    generators_length_log_2: usize,
    pubkey_file_path: &str,
    our_pubkey: Affine<P0>,
) -> Result<(R1CSProof<Affine<P0>>, R1CSProof<Affine<P1>>,
    SelectAndRerandomizePath<P0, P1>,
    P0::ScalarField,
    Affine<P0>, Affine<P0>, bool), Box<dyn std::error::Error>> {
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
    // the leaf level. (though they *can* themselves be commitments, e.g. see auditor code)
    let leaf_commitments = get_leaf_commitments::<F, P0>(
        &(pubkey_file_path.to_string() + ".p"));

    let b_blinding = sr_params.even_parameters.pc_gens.B_blinding;
    let (key_index, r_offset, privkey_parity_flip) =
    get_key_index_from_leaves(
        &leaf_commitments, b_blinding, &sr_params, our_pubkey)?;
    // Now we know we have a key that's in the set, we can construct the curve
    // tree from the set, and then the proof using its private key:
    let beforect = Instant::now();
    let (curve_tree, _) = get_curve_tree::<F, P0, P1>(
        &leaf_commitments, depth, &sr_params);
    println!("Elapsed time for curve tree construction: {:.2?}", beforect.elapsed());
    assert_eq!(curve_tree.height(), depth);

    let (path_commitments, rand_scalar) =
    curve_tree.select_and_rerandomize_prover_gadget(
        key_index.try_into().unwrap(),
        &mut p0_prover,
        &mut p1_prover,
        &sr_params,
        &mut rng,
    );
    // print the root of the curve tree.
    // TODO: how to allow the return value to be either
    // Affine<P0> or Affine<P1>? And as a consequence,
    // to let the code be correct for any depth.
    // And/or, is there not
    // a simpler way to extract the root of the tree
    // (which should be just .parent_commitment, but all methods
    // to extract this value seem to be private)
    let newpath = curve_tree.select_and_rerandomize_verification_commitments(
    path_commitments.clone());
    let root_is_odd = newpath.even_commitments.len() == newpath.odd_commitments.len();
    println!("Root is odd? {}", root_is_odd);
    let root: Affine<P0>;
    if !root_is_odd {
        root = *newpath.even_commitments.first().unwrap();
    }
    else {
        // derp, see above TODO
        panic!("Wrong root parity, should be even");
    }
    let p0_proof = p0_prover
        .prove(&sr_params.even_parameters.bp_gens)
        .unwrap();
    let p1_proof = p1_prover
        .prove(&sr_params.odd_parameters.bp_gens)
        .unwrap();
    let returned_rand = rand_scalar + r_offset;
    Ok((p0_proof, p1_proof, path_commitments,
     returned_rand, b_blinding, root, privkey_parity_flip))
}


pub fn get_curve_tree_proof_from_curve_tree<
F: PrimeField,
P0: SWCurveConfig<BaseField = F> + Copy,
P1: SWCurveConfig<BaseField = P0::ScalarField, ScalarField = P0::BaseField> + Copy,
>(
    curve_tree: &CurveTree<P0, P1>,
    leaf_commitments: &Vec<Affine<P0>>,
    our_pubkey: Affine<P0>,
    sr_params: &SelRerandParameters<P0, P1>,
) -> Result<(R1CSProof<Affine<P0>>, R1CSProof<Affine<P1>>,
SelectAndRerandomizePath<P0, P1>,
P0::ScalarField,
Affine<P0>, Affine<P0>, bool), Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();

    let p0_transcript = Transcript::new(b"select_and_rerandomize");
    let mut p0_prover: Prover<_, Affine<P0>> =
        Prover::new(&sr_params.even_parameters.pc_gens, p0_transcript);

    let p1_transcript = Transcript::new(b"select_and_rerandomize");
    let mut p1_prover: Prover<_, Affine<P1>> =
        Prover::new(&sr_params.odd_parameters.pc_gens, p1_transcript);

    let b_blinding = sr_params.even_parameters.pc_gens.B_blinding;
    let (key_index, r_offset, privkey_parity_flip) =
    get_key_index_from_leaves(
        &leaf_commitments, b_blinding, &sr_params, our_pubkey)?;
    let (path_commitments, rand_scalar) =
    curve_tree.select_and_rerandomize_prover_gadget(
        key_index.try_into().unwrap(),
        &mut p0_prover,
        &mut p1_prover,
        &sr_params,
        &mut rng,
    );
    // print the root of the curve tree.
    // TODO: how to allow the return value to be either
    // Affine<P0> or Affine<P1>? And as a consequence,
    // to let the code be correct for any depth.
    // And/or, is there not
    // a simpler way to extract the root of the tree
    // (which should be just .parent_commitment, but all methods
    // to extract this value seem to be private)
    let newpath = curve_tree.select_and_rerandomize_verification_commitments(
    path_commitments.clone());
    let root_is_odd = newpath.even_commitments.len() == newpath.odd_commitments.len();
    println!("Root is odd? {}", root_is_odd);
    let root: Affine<P0>;
    if !root_is_odd {
        root = *newpath.even_commitments.first().unwrap();
    }
    else {
        // derp, see above TODO
        panic!("Wrong root parity, should be even");
    }
    let p0_proof = p0_prover
        .prove(&sr_params.even_parameters.bp_gens)
        .unwrap();
    let p1_proof = p1_prover
        .prove(&sr_params.odd_parameters.bp_gens)
        .unwrap();
    let returned_rand = rand_scalar + r_offset;
    Ok((p0_proof, p1_proof, path_commitments,
     returned_rand, b_blinding, root, privkey_parity_flip))
}

// Takes as input a hex list of actual BIP340 pubkeys
// that should come from the utxo set;
// converts each point into a permissible point
// and then writes these points in binary format into
// a new file with same name as keyset with .p appended.
// TODO return an error if this can't be done.
pub fn convert_keys<F: PrimeField,
P0: SWCurveConfig<BaseField = F> + Copy,
P1: SWCurveConfig<BaseField = P0::ScalarField,
ScalarField = P0::BaseField> + Copy,>(
    keyset: String, generators_length_log_2: u8) -> Result<(), Box<dyn Error>>{
    let raw_pubkeys =
    get_pubkey_leaves_hex::<F, P0>(&keyset);
    let mut rng = rand::thread_rng();
    let generators_length = 1 << generators_length_log_2;

    let sr_params =
        SelRerandParameters::<P0, P1>::new(generators_length,
            generators_length, &mut rng);
    let (permissible_points, _pr)
     = create_permissible_points_and_randomnesses(
        &raw_pubkeys, &sr_params);
    // take vec permissible points and write it in binary as n*33 bytes
    let mut buf: Vec<u8> = Vec::with_capacity(permissible_points.len()*33);
    let _: Vec<_> = permissible_points
        .iter()
        .map(|pt: &Affine<P0>| {
            pt.serialize_compressed(&mut buf).expect(
                "Failed to serialize point")
        }).collect();
    let output_file = keyset.clone() + ".p";
    write_file_string(&output_file, buf);
    Ok(())
}
