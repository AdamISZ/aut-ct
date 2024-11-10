// serialization.rs
use std::fs;
use std::path::PathBuf;
use std::io::Cursor;
use std::error::Error;
use ark_ec::short_weierstrass::Affine;
use ark_secp256k1::Config as SecpConfig;
use std::ops::{Mul, Add};

use bitcoin::{key::{Secp256k1, TapTweak, UntweakedKeypair}, secp256k1::All};

use alloc::vec::Vec;
use ark_ec::{AffineRepr, short_weierstrass::SWCurveConfig, CurveGroup};
use ark_secp256k1::Fq as SecpBase;
use bitcoin::PrivateKey;
use ark_ff::{BigInteger, BigInteger256, PrimeField};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
type F = <ark_secp256k1::Affine as AffineRepr>::ScalarField;

//Reading and writing files:
pub fn read_file_string(filepath: &str) -> Result<String, Box<dyn Error>> {
    let resp = match fs::read_to_string(filepath) {
        Ok(data) => data,
        Err(e) => {return Err(e.into());}
    };
    Ok(resp.trim_end().to_string())
}

pub fn write_file_string(filepath: &str, buf: Vec<u8>) -> () {
    fs::write(filepath, buf).expect("Failed to write to file");
}

pub fn write_file_string2(loc: PathBuf, mut buf: Vec<u8>) ->Result<(), std::io::Error> {
    fs::write(loc, &mut buf)
}

/// Given a hex string of big-endian encoding,
/// first change to little endian bytes and then deserialize
/// it as a field element
pub fn decode_hex_le_to_F<F: PrimeField>(s: &String)
-> Result<F, Box<dyn Error>>{
    let mut x = hex::decode(s).expect("Invalid hex encoding");
    x.reverse();
    Ok(F::deserialize_compressed(&x[..])?)
}

pub fn get_wif_from_field_elem(x: F) -> Result<String, Box<dyn Error>>{
    let mut buf: Vec<u8> = Vec::new();
    x.serialize_compressed(&mut buf)?;
    buf.reverse();
    let privk2: PrivateKey = PrivateKey::from_slice(&buf, bitcoin::Network::Signet).unwrap();
    return Ok(privk2.to_wif());
}

pub fn get_field_elem_from_wif(wif: &String) -> Result<F, Box<dyn Error>> {
    let privk = PrivateKey::from_wif(wif)?;
    let privkey_bytes = privk.to_bytes();
    let privhex = hex::encode(&privkey_bytes);
    decode_hex_le_to_F::<F>(&privhex)
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
        let mut pubkeys = Vec::new();
        for a in b{
            let mut cursor = Cursor::new(a);
            match Affine::<P0>::deserialize_compressed_unchecked(&mut cursor){
            Ok(Q) => {
                pubkeys.push(Q);
            },
            Err(_) => {println!("Invalid hex pubkey detected, ignoring")}
        };
            //match Affine::<P0>::deserialize_with_mode(&mut cursor,
            //    ark_serialize::Compress::Yes,
            //    ark_serialize::Validate::Yes){
            //    Ok(Q) => {
            //        pubkeys.push(Q);
            //    },
            //    Err(_) => {println!("Invalid hex pubkey detected, ignoring.")}
            //};
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
    // TODO return errors for failed reading
    let filestr:String = read_file_string(pubkey_file_path)
    .expect("Failed to read pubkey file");

    let hex_keys_vec = filestr.split_whitespace().collect::<Vec<_>>();
    if pubkey_file_path.ends_with(".aks"){
        get_correct_pubkeys_from_bip340_hex_list(hex_keys_vec).unwrap()
    }
    else { // current convention is ".pks", but not enforced for now
        get_correct_pubkeys_from_ark_hex_list::<F, P0>(hex_keys_vec).unwrap()
    }
}

// No longer needed without permissibility;
// currently present as a near pass through
pub fn convert_keys<F: PrimeField,
P0: SWCurveConfig<BaseField = F> + Copy,
P1: SWCurveConfig<BaseField = P0::ScalarField,
ScalarField = P0::BaseField> + Copy,>(
    keyset: String) -> Result<Vec<Affine<P0>>, Box<dyn Error>>{
    Ok(get_pubkey_leaves_hex::<F, P0>(&keyset))
}

pub fn convert_pt_to_hex_bip340<F: PrimeField,
P0: SWCurveConfig<BaseField = F>+Copy>(
    pt: Affine<P0>) -> Result<String, Box<dyn Error>> {
    let mut buf2: Vec<u8> = Vec::new();
    pt.serialize_with_mode(&mut buf2, ark_serialize::Compress::Yes)?; 
    // ignore the final byte which is the sign byte in ark:
    let buf3  = &mut buf2[0..32];
    // ark uses LE, so stop that nonsense:
    buf3.reverse();
    let bin_bip340_pubkey = bitcoin::XOnlyPublicKey::from_slice(&buf3)?.serialize();
    Ok(hex::encode(bin_bip340_pubkey))
}

/// Given a BIP340 serialized public key hex string,
/// return a secp256k1 public key object for ark-ec
pub fn bip340_to_ark_ec(
    bip340_key: &str) -> Result<Affine<SecpConfig>, Box<dyn Error>> {
    // Deserialize BIP340 x-coordinate hex string, create ark-ec point
    let mut o_sbin = hex::decode(bip340_key)?;
    o_sbin.reverse();
    // choose a sign arbitrarily:
    o_sbin.push(0u8);
    let mut cursor = Cursor::new(o_sbin);
    let mut Q = Affine::<SecpConfig>::deserialize_with_mode(
        &mut cursor,
        ark_serialize::Compress::Yes,
        ark_serialize::Validate::Yes)?;
    // flip the sign if necessary to ensure
    // the y coord is even as per BIP340:
    let yval: SecpBase = *Q.y().unwrap();
    let yvalint = yval.into_bigint();
    if yvalint.is_odd() {
        Q = -Q;
    }
    Ok(Q)
}

/// Extract x-coordinate and apply BIP340 evenness rule
/// to serialize to hex string
pub fn ark_ec_to_bip340<P: AffineRepr>(ark_point: P)
    -> Result<String, Box<dyn Error>> {
    let mut buf2: Vec<u8> = Vec::new();
    ark_point.serialize_with_mode(&mut buf2, ark_serialize::Compress::Yes)?; 
    // ignore the final byte which is the sign byte in ark:
    let buf3  = &mut buf2[0..32];
    // ark uses LE, so stop that nonsense:
    buf3.reverse();
    let bin_bip340_pubkey = bitcoin::XOnlyPublicKey::from_slice(&buf3)?.serialize();
    Ok(hex::encode(bin_bip340_pubkey))

}

/// Use rust-bitcoin to derive Taproot pubkey P from private key
/// Convert to ark-ec point.
/// Additionally return the *tweaked* version of the private key,
/// such that P = xG.
/// Note that we MUST switch the sign of x, and therefore P,
/// if the derived P value has odd y, so that the key we get
/// corresponds to what would appear on chain as BIP340.
/// Note that this uses the automatic tweaking with a null script
/// method, which is currently standard in taproot supporting wallets.
pub fn private_key_to_taproot_ark_ec(
    wif_key: &str, secp: &Secp256k1<All>) ->
    Result<(F, Affine<SecpConfig>), Box<dyn Error>> {
    let privkey =
    PrivateKey::from_wif(wif_key)?;
    let untweaked_key_pair: UntweakedKeypair =
    UntweakedKeypair::from_secret_key(
        &secp, &privkey.inner);
    let tweaked_key_pair =
    untweaked_key_pair.tap_tweak(&secp, None);
    let privkey_bytes = tweaked_key_pair.
    to_inner().secret_bytes();
    let privhex = hex::encode(&privkey_bytes);

    let mut x =
    decode_hex_le_to_F::<F>(&privhex)?;
    let G = SecpConfig::GENERATOR;
    let mut P = G.mul(x).into_affine();
    let yval: SecpBase = *P.y().unwrap();
    let yvalint: BigInteger256 = BigInteger256::from(yval);
    if yvalint.0[0] % 2 == 1 {
        P = -P;
        x = -x;}
    Ok((x, P))
}

/// Take a tuple (privkey, value) and construct a commitment
/// to P + vJ where J is a given NUMS alternate generator,
/// and P is the taproot-tweaked public key for x.
/// Return both P and the tweaked equivalent of x.
pub fn privkey_val_to_taproot_ark_ec(wif_key: &str,
    val: u64, J: Affine<SecpConfig>, secp: &Secp256k1<All>)
-> Result<(F, Affine<SecpConfig>), Box<dyn Error>> {
    let (x, P) =
    private_key_to_taproot_ark_ec(wif_key, secp)?;
    let v = F::from(val);
    Ok((x, P.add(J.mul(v)).into_affine()))
}

