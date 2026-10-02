#![allow(non_snake_case)]

use std::sync::{Arc, Mutex};

use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_secp256k1::{Config as SecpConfig, Fq as SecpBase};
use ark_secq256k1::Config as SecqConfig;
use autct::encryption::encrypt;
use autct::keyimagestore::KeyImageStore;
use autct::rpc::{RPCProofVerifier, RPCProofVerifyRequest, RPCProver,
    RPCProverRequest, RPCProverVerifierArgs};
use autct::serialization::convert_keys;
use autct::utils::{get_curve_tree, get_generators, APP_DOMAIN_LABEL};
use bitcoin::key::{Keypair, Parity, Secp256k1, TapTweak};
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Network, PrivateKey};
use relations::curve_tree::SelRerandParameters;

const CONTEXT: &str = "keyimage-test";
const PASSWORD: &str = "pw";

fn make_args(keyset: &str, sr_params: SelRerandParameters<SecpConfig, SecqConfig>,
    ks: Arc<Mutex<KeyImageStore<Affine<SecpConfig>>>>) -> RPCProverVerifierArgs {
    let leaves = convert_keys::<SecpBase, SecpConfig, SecqConfig>(
        keyset.to_string()).unwrap();
    let (tree, _) = get_curve_tree::<SecpBase, SecpConfig, SecqConfig>(
        &leaves, 2, &sr_params);
    let H = sr_params.even_parameters.pc_gens.B_blinding;
    RPCProverVerifierArgs {
        keyset_file_locs: vec![keyset.to_string()],
        context_labels: vec![CONTEXT.to_string()],
        sr_params,
        curve_trees: vec![Arc::new(tree)],
        G: SecpConfig::GENERATOR,
        H,
        Js: vec![get_generators(CONTEXT.as_bytes())],
        ks: vec![ks],
    }
}

#[tokio::test]
async fn failed_curve_tree_proof_does_not_consume_key_image() {
    let dir = std::env::temp_dir().join(
        format!("autct-keyimage-{}", std::process::id()));
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
    assert!(keys.len() >= 4);

    // keyset B is keyset A plus one key, so the trees differ
    let keyset_a = dir.join("a.aks").to_str().unwrap().to_string();
    let keyset_b = dir.join("b.aks").to_str().unwrap().to_string();
    let hex: Vec<String> = keys.iter().map(|k| k.1.clone()).collect();
    std::fs::write(&keyset_a, hex[..3].join(" ")).unwrap();
    std::fs::write(&keyset_b, hex[..4].join(" ")).unwrap();

    let new_params = || SelRerandParameters::<SecpConfig, SecqConfig>::new(
        1 << 11, 1 << 11);
    let J: Affine<SecpConfig> = get_generators(CONTEXT.as_bytes());
    let ks = Arc::new(Mutex::new(KeyImageStore::<Affine<SecpConfig>>::new(
        Some("test".to_string()),
        format!("{}/{}", dir.to_str().unwrap(),
            String::from_utf8(APP_DOMAIN_LABEL.to_vec()).unwrap()),
        CONTEXT.to_string(), Some(J))));
    let prover = RPCProver {
        prover_verifier_args: make_args(&keyset_a, new_params(), ks.clone()) };
    let verifier_a = RPCProofVerifier {
        prover_verifier_args: make_args(&keyset_a, new_params(), ks.clone()) };
    let verifier_b = RPCProofVerifier {
        prover_verifier_args: make_args(&keyset_b, new_params(), ks.clone()) };

    let privkey_file = dir.join("key.enc");
    let wif = PrivateKey::new(keys[0].0, Network::Regtest).to_wif();
    std::fs::write(&privkey_file,
        encrypt(wif.as_bytes(), PASSWORD.as_bytes()).unwrap()).unwrap();
    let prove = || prover.prove(RPCProverRequest {
        keyset: format!("{}:{}", CONTEXT, keyset_a),
        depth: 2,
        generators_length_log_2: 11,
        user_label: "user".to_string(),
        privkey_file_loc: privkey_file.to_str().unwrap().to_string(),
        bc_network: "regtest".to_string(),
        encryption_password: PASSWORD.to_string(),
    });
    let request = |proof: String| RPCProofVerifyRequest {
        keyset: keyset_a.clone(),
        user_label: "user".to_string(),
        context_label: CONTEXT.to_string(),
        application_label: String::new(),
        proof,
    };

    let proof = prove().await.unwrap().proof.unwrap();
    let resp = verifier_b.verify(request(proof)).await.unwrap();
    assert_eq!(resp.accepted, -1);

    let proof = prove().await.unwrap().proof.unwrap();
    let resp = verifier_a.verify(request(proof)).await.unwrap();
    assert_eq!(resp.accepted, 1);

    let proof = prove().await.unwrap().proof.unwrap();
    let resp = verifier_a.verify(request(proof)).await.unwrap();
    assert_eq!(resp.accepted, -3);
    std::fs::remove_dir_all(&dir).unwrap();
}
