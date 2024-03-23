#![allow(non_snake_case)]

use tokio::{task, net::TcpListener};
use std::sync::Arc;
use std::error::Error;
use toy_rpc::Server;


use autct::{rpc::RPCProofVerifier, utils};
use autct::autctverifier::get_curve_tree;
use autct::config::AutctConfig;
use relations::curve_tree::SelRerandParameters;
use ark_secp256k1::{Config as SecpConfig, Fq as SecpBase};
use ark_secq256k1::Config as SecqConfig;
use ark_ec::short_weierstrass::SWCurveConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>>{
    //let autctcfg: AutctConfig = confy::load("autct", None).expect("Config failed to load");
    let autctcfg = AutctConfig::build()?;
    let pubkey_filepath2 = autctcfg.keyset.unwrap();
    let rpc_port = autctcfg.rpc_port.unwrap();
    let host: &str= &autctcfg.rpc_host.unwrap();
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
    let verifier_service = Arc::new(
        RPCProofVerifier{ sr_params: sr_params2,
            pubkey_filepath: pubkey_filepath2,
            curve_tree: curve_tree2,
            G: G2,
            H: H2,
            J: J2,
            context_label: autctcfg.context_label.unwrap(),
            user_string: autctcfg.user_string.unwrap()}
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

