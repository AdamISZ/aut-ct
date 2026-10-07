#![allow(non_snake_case)]

use std::io::Cursor;
use std::sync::{Arc, Mutex};

use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_secp256k1::{Config as SecpConfig, Fq as SecpBase};
use ark_secq256k1::Config as SecqConfig;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use autct::encryption::encrypt;
use autct::keyimagestore::KeyImageStore;
use autct::peddleq::PedDleqProof;
use autct::rpc::{RPCProofVerifier, RPCProofVerifyRequest, RPCProver,
    RPCProverRequest, RPCProverVerifierArgs};
use autct::serialization::convert_keys;
use autct::utils::{get_curve_tree, get_generators, APP_DOMAIN_LABEL, BRANCHING_FACTOR};
use base64::prelude::*;
use bitcoin::key::{Keypair, Parity, Secp256k1, TapTweak};
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Network, PrivateKey};
use bulletproofs::r1cs::R1CSProof;
use relations::curve_tree::{SelRerandParameters, SelectAndRerandomizePath};

const CONTEXT: &str = "malformed-test";
const PASSWORD: &str = "pw";

type Path = SelectAndRerandomizePath<BRANCHING_FACTOR, SecpConfig, SecqConfig>;

// Decodes every part of a proof and encodes it again, so that two
// encodings of the same proof give the same bytes. Arkworks ignores the
// x bytes of a point at infinity, so a proof has more than one encoding.
fn reencode(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut cursor = Cursor::new(bytes);
    let mut out = Vec::new();
    Affine::<SecpConfig>::deserialize_compressed(&mut cursor).ok()?
        .serialize_compressed(&mut out).ok()?;
    Affine::<SecpConfig>::deserialize_compressed(&mut cursor).ok()?
        .serialize_compressed(&mut out).ok()?;
    PedDleqProof::<Affine<SecpConfig>>::deserialize_compressed(&mut cursor).ok()?
        .serialize_compressed(&mut out).ok()?;
    R1CSProof::<Affine<SecpConfig>>::deserialize_compressed(&mut cursor).ok()?
        .serialize_compressed(&mut out).ok()?;
    R1CSProof::<Affine<SecqConfig>>::deserialize_compressed(&mut cursor).ok()?
        .serialize_compressed(&mut out).ok()?;
    let path = Path::deserialize_with_mode(
        &mut cursor, Compress::Yes, Validate::Yes).ok()?;
    path.selected_commitment.serialize_compressed(&mut out).ok()?;
    path.odd_commitments.serialize_compressed(&mut out).ok()?;
    path.even_commitments.serialize_compressed(&mut out).ok()?;
    Affine::<SecpConfig>::deserialize_compressed(&mut cursor).ok()?
        .serialize_compressed(&mut out).ok()?;
    Some(out)
}

// Splits a proof into the bytes before the curve tree path, the path,
// and the root, so that tests can change the path.
fn split_at_path(bytes: &[u8]) -> (Vec<u8>, Path, Vec<u8>) {
    let mut cursor = Cursor::new(bytes);
    let _ = Affine::<SecpConfig>::deserialize_compressed(&mut cursor).unwrap();
    let _ = Affine::<SecpConfig>::deserialize_compressed(&mut cursor).unwrap();
    let _ = PedDleqProof::<Affine<SecpConfig>>::deserialize_compressed(&mut cursor).unwrap();
    let _ = R1CSProof::<Affine<SecpConfig>>::deserialize_compressed(&mut cursor).unwrap();
    let _ = R1CSProof::<Affine<SecqConfig>>::deserialize_compressed(&mut cursor).unwrap();
    let start = cursor.position() as usize;
    let path = Path::deserialize_with_mode(
        &mut cursor, Compress::Yes, Validate::Yes).unwrap();
    let end = cursor.position() as usize;
    (bytes[..start].to_vec(), path, bytes[end..].to_vec())
}

#[tokio::test]
async fn malformed_proofs_get_error_codes() {
    let dir = std::env::temp_dir().join(
        format!("autct-malformed-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let secp = Secp256k1::new();

    // even y keys only, so the prover's parity handling is not involved
    let mut keys = vec![];
    for i in 1..=16u8 {
        let sk = SecretKey::from_slice(&[i; 32]).unwrap();
        let (xonly, parity) = Keypair::from_secret_key(&secp, &sk)
            .tap_tweak(&secp, None).to_inner().x_only_public_key();
        if parity == Parity::Even {
            keys.push((sk, xonly.to_string()));
        }
    }
    assert!(keys.len() >= 3);
    let keyset = dir.join("keys.aks").to_str().unwrap().to_string();
    let hex: Vec<String> = keys.iter().map(|k| k.1.clone()).collect();
    std::fs::write(&keyset, hex[..3].join(" ")).unwrap();

    let sr_params = SelRerandParameters::<SecpConfig, SecqConfig>::new(
        1 << 11, 1 << 11);
    let leaves = convert_keys::<SecpBase, SecpConfig, SecqConfig>(
        keyset.clone()).unwrap();
    let (tree, _) = get_curve_tree::<SecpBase, SecpConfig, SecqConfig>(
        &leaves, 2, &sr_params);
    let J: Affine<SecpConfig> = get_generators(CONTEXT.as_bytes());
    let ks = KeyImageStore::<Affine<SecpConfig>>::new(
        Some("test".to_string()),
        format!("{}/{}", dir.to_str().unwrap(),
            String::from_utf8(APP_DOMAIN_LABEL.to_vec()).unwrap()),
        CONTEXT.to_string(), Some(J));
    let H = sr_params.even_parameters.pc_gens.B_blinding;
    let args = RPCProverVerifierArgs {
        keyset_file_locs: vec![keyset.clone()],
        context_labels: vec![CONTEXT.to_string()],
        sr_params,
        curve_trees: vec![Arc::new(tree)],
        G: SecpConfig::GENERATOR,
        H,
        Js: vec![J],
        ks: vec![Arc::new(Mutex::new(ks))],
    };
    let prover = RPCProver { prover_verifier_args: args.clone() };
    let verifier = RPCProofVerifier { prover_verifier_args: args };

    let privkey_file = dir.join("key.enc");
    let wif = PrivateKey::new(keys[0].0, Network::Regtest).to_wif();
    std::fs::write(&privkey_file,
        encrypt(wif.as_bytes(), PASSWORD.as_bytes()).unwrap()).unwrap();
    let presp = prover.prove(RPCProverRequest {
        keyset: format!("{}:{}", CONTEXT, keyset),
        depth: 2,
        generators_length_log_2: 11,
        user_label: "user".to_string(),
        privkey_file_loc: privkey_file.to_str().unwrap().to_string(),
        bc_network: "regtest".to_string(),
        encryption_password: PASSWORD.to_string(),
    }).await.unwrap();
    let honest = BASE64_STANDARD.decode(presp.proof.unwrap()).unwrap();
    let verify = |bytes: &[u8]| verifier.verify(RPCProofVerifyRequest {
        keyset: keyset.clone(),
        user_label: "user".to_string(),
        context_label: CONTEXT.to_string(),
        application_label: String::new(),
        proof: BASE64_STANDARD.encode(bytes),
    });

    // a valid proof with a different root
    let mut bytes = honest.clone();
    let n = bytes.len();
    let mut g = Vec::new();
    SecpConfig::GENERATOR.serialize_compressed(&mut g).unwrap();
    bytes[n - 33..].copy_from_slice(&g);
    assert_eq!(verify(&bytes).await.unwrap().accepted, -1);

    // junk after the PedDLEQ proof
    let mut bytes = honest[..33 + 33 + 130].to_vec();
    bytes.extend_from_slice(&[0u8; 10]);
    assert_eq!(verify(&bytes).await.unwrap().accepted, -8);

    // a path with one level missing, or one level too many
    let (head, path, root) = split_at_path(&honest);
    for change in [-1i32, 1] {
        let mut bad_path = path.clone();
        if change < 0 {
            bad_path.odd_commitments.pop();
        } else {
            bad_path.even_commitments.push(SecpConfig::GENERATOR);
        }
        let mut bytes = head.clone();
        bad_path.selected_commitment.serialize_compressed(&mut bytes).unwrap();
        bad_path.odd_commitments.serialize_compressed(&mut bytes).unwrap();
        bad_path.even_commitments.serialize_compressed(&mut bytes).unwrap();
        bytes.extend_from_slice(&root);
        assert_eq!(verify(&bytes).await.unwrap().accepted, -1);
    }

    // every truncation and a spread of single byte changes must be
    // rejected without panicking; a change that decodes to the same
    // proof is skipped, as it would be accepted and use up the key image
    for len in 0..honest.len() {
        assert!(verify(&honest[..len]).await.unwrap().accepted < 0,
            "truncation to {} bytes was accepted", len);
    }
    let canonical = reencode(&honest).unwrap();
    let mut skipped = 0;
    for i in (0..honest.len()).step_by(17) {
        let mut bytes = honest.clone();
        bytes[i] ^= 0x01;
        if reencode(&bytes).as_ref() == Some(&canonical) {
            skipped += 1;
            continue;
        }
        assert!(verify(&bytes).await.unwrap().accepted < 0,
            "change at byte {} was accepted", i);
    }
    assert!(skipped < 10);

    // none of the above consumed the key image
    assert_eq!(verify(&honest).await.unwrap().accepted, 1);
    std::fs::remove_dir_all(&dir).unwrap();
}
