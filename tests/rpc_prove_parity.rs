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

const CONTEXT: &str = "parity-test";
const PASSWORD: &str = "pw";

#[tokio::test]
async fn rpc_proofs_verify_for_both_output_key_parities() {
    let dir = std::env::temp_dir().join(
        format!("autct-parity-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let secp = Secp256k1::new();

    let mut keys = vec![];
    for i in 1..=8u8 {
        let sk = SecretKey::from_slice(&[i; 32]).unwrap();
        let (xonly, parity) = Keypair::from_secret_key(&secp, &sk)
            .tap_tweak(&secp, None).to_inner().x_only_public_key();
        keys.push((sk, xonly, parity));
    }
    let odd = keys.iter().position(|k| k.2 == Parity::Odd).unwrap();
    let even = keys.iter().position(|k| k.2 == Parity::Even).unwrap();

    let keyset = dir.join("keys.aks").to_str().unwrap().to_string();
    let hexkeys: Vec<String> = keys.iter().map(|k| k.1.to_string()).collect();
    std::fs::write(&keyset, hexkeys.join(" ")).unwrap();

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

    for i in [odd, even] {
        let (sk, _, parity) = keys[i];
        let wif = PrivateKey::new(sk, Network::Regtest).to_wif();
        let privkey_file = dir.join(format!("key{}.enc", i));
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
        assert_eq!(presp.accepted, 0);
        let vresp = verifier.verify(RPCProofVerifyRequest {
            keyset: keyset.clone(),
            user_label: "user".to_string(),
            context_label: CONTEXT.to_string(),
            application_label: String::new(),
            proof: presp.proof.unwrap(),
        }).await.unwrap();
        assert_eq!(vresp.accepted, 1, "key {} with {:?} y failed", i, parity);
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
