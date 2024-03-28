#![allow(non_snake_case)]

use ark_serialize::{ CanonicalDeserialize, 
    Compress, Validate};
use autct::utils::APP_DOMAIN_LABEL;
use tokio::{task, net::TcpListener};
use std::fs;
use std::io::Cursor;
use std::sync::{Arc, Mutex};
use std::error::Error;
use toy_rpc::Server;


use autct::{rpc::RPCProofVerifier, utils};
use autct::autctverifier::get_curve_tree;
use autct::config::AutctConfig;
use autct::keyimagestore::{KeyImageStore, create_new_store};
use relations::curve_tree::SelRerandParameters;
use ark_secp256k1::{Config as SecpConfig, Fq as SecpBase};
use ark_secq256k1::Config as SecqConfig;
use ark_ec::short_weierstrass::{Affine, SWCurveConfig};


pub async fn do_serve(autctcfg: AutctConfig) -> Result<(), Box<dyn Error>>{
    let pubkey_filepath2 = autctcfg.keyset.clone().unwrap();
    let rpc_port = autctcfg.rpc_port.unwrap();
    let host: &str= &autctcfg.rpc_host.clone().unwrap();
    let port_str: &str = &rpc_port.to_string();
    let addr: String = format!("{}:{}", host, port_str);
    let mut rng = rand::thread_rng();
    let generators_length = 1 << autctcfg.generators_length_log_2.unwrap();
    let sr_params2 = SelRerandParameters::<SecpConfig, SecqConfig>::new(
                generators_length,
                generators_length, &mut rng);
    let (curve_tree2, H2) = get_curve_tree::
        <{autct::utils::BRANCHING_FACTOR}, SecpBase, SecpConfig, SecqConfig>(
        &pubkey_filepath2,
        autctcfg.depth.unwrap().try_into().unwrap(), &sr_params2);
    let G2 = SecpConfig::GENERATOR;
    let J2 = utils::get_generators(autctcfg.context_label.as_ref().unwrap().as_bytes());
    // load the appropriate key image database:
    let ksr = create_new_store::<SecpBase, SecpConfig>(autctcfg.clone());
    let mut ks: KeyImageStore<Affine<SecpConfig>>;
    if ksr.is_err() {
        ks = KeyImageStore::<Affine<SecpConfig>>::new(
            autctcfg.keyimage_filename_suffix, String::from_utf8(APP_DOMAIN_LABEL.to_vec()).unwrap(), Some(J2));
        let file_contents = fs::read(ks.full_file_loc.clone().unwrap()).unwrap();
        let cursor = Cursor::new(file_contents);
        // note that this overwrites the pre-existing 'ks' object (but not the file!)
        ks = KeyImageStore::<Affine<SecpConfig>>::deserialize_with_mode(cursor,
            Compress::Yes, Validate::No).unwrap();
    }
    else {
        ks = ksr.unwrap();
    }
    let ksm = Arc::new(Mutex::new(ks));
    let verifier_service = Arc::new(
        RPCProofVerifier{ sr_params: sr_params2,
            pubkey_filepath: pubkey_filepath2,
            curve_tree: curve_tree2,
            G: G2,
            H: H2,
            J: J2,
            context_label: autctcfg.context_label.unwrap(),
            user_string: autctcfg.user_string.unwrap(),
            ks: ksm}
    );
    let server = Server::builder()
        .register(verifier_service) // register service
        .build();
    let listener = TcpListener::bind(&addr).await.unwrap();

    // Run the server in a separate task
    let handle = task::spawn(async move {
        println!("Starting server at {}", &addr);
        server.accept(listener).await.unwrap();
    });
    handle.await.expect("Error running the RPC server");
    Ok(())
}

