#![allow(non_snake_case)]
extern crate rand;
extern crate alloc;
extern crate ark_secp256k1;

use ark_ff::Field;
use ark_ff::PrimeField;
use ark_ec::AffineRepr;
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::short_weierstrass::Affine;
use std::fs;
use ark_serialize::CanonicalSerialize;
use relations::curve_tree::SelRerandParameters;

// all transcripts created in this project should be
// initialized with this name:
pub const APP_DOMAIN_LABEL: &[u8] = b"autct v1.0";
pub const BRANCHING_FACTOR: usize = 256;
// specific to an application; this default is only for tests.
// Should be set in the config file, in the field `context_label`.
pub const CONTEXT_LABEL: &[u8] = b"default-app-context-label";

// Given a hex string of big-endian encoding,
// first change to little endian bytes and then deserialize
// it as a field element
pub fn decode_hex_le_to_F<F: PrimeField>(s: &String) -> F{
    let mut x = hex::decode(s).expect("hex decode failed");
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
    b.extend(b"J");
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

pub fn read_file_string(filepath: &str) -> Result<String, Box<dyn std::error::Error>> {
    let data = fs::read_to_string(filepath)?;
    Ok(data)
}

pub fn write_file_string(filepath: &str, mut buf: Vec<u8>) -> () {
    fs::write(filepath, &mut buf).expect("Failed to write to file");
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

pub fn get_leaf_commitments<F: PrimeField,
                            P0: SWCurveConfig<BaseField = F>>(pubkey_file_path: &str)
                            -> Vec<Affine<P0>>{
    // this whole section is clunky TODO
    // (need to reverse each binary string, but reverse() is 'in place', hence loop,
    // so the "TODO" is how to do that more elegantly)
    let filestr:String = read_file_string(pubkey_file_path)
    .expect("my failure message");
    let hex_keys_vec = filestr.split_whitespace().collect::<Vec<_>>();
    let hex_keys_vec_count = hex_keys_vec.len();
    println!("Pubkey count: {}", hex_keys_vec_count);
    let hex_keys = hex_keys_vec.into_iter();
    let mut b = Vec::new();
    for s in hex_keys {
        let o_sbin = hex::decode(s);
        match o_sbin {
            Ok(x) => {let mut sbin = x;
                sbin.reverse();
                b.push(sbin.clone())},
            Err(e) => {println!("Error {}", e)}
        }
        //let mut sbin = hex::decode(s).expect("hex decode failed");
        //sbin.reverse();
        //b.push(sbin.clone());
    }
    let mut leaf_commitments = Vec::new();
    for a in b.into_iter(){
        let x = <Affine<P0> as AffineRepr>::from_random_bytes(&a[..]);
        match x {
            Some(y) => {leaf_commitments.push(y)},
            None => {println!("Error {:#?}", a);}, // not hex decoding in case invalid? TODO
        };
    }
    //let leaf_commitments: Vec<Affine<P0>> = b
    //        .into_iter()
    //        .map(|x| <Affine<P0> as AffineRepr>::from_random_bytes(&x[..]).unwrap()).collect();
    leaf_commitments
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
