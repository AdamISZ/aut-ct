#![allow(non_snake_case)]

use tokio::{task, net::TcpListener};
use std::sync::Arc;
use std::env;
use toy_rpc::Server;


use autct::rpc::RPCProofVerifier;
use autct::autctverifier::get_curve_tree;
use autct::config::AutctConfig;
use relations::curve_tree::SelRerandParameters;
use ark_secp256k1::{Config as SecpConfig, Fq as SecpBase};
use ark_secq256k1::Config as SecqConfig;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let autctcfg: AutctConfig = confy::load("autct", None).expect("Config failed to load");
    let pubkey_filepath2 = args[1].clone();
    let rpc_port = autctcfg.rpc_port;
    let host: &str= &autctcfg.rpc_host;
    let port_str: &str = &rpc_port.to_string();
    let addr: String = format!("{}:{}", host, port_str);
    let mut rng = rand::thread_rng();
    let generators_length = 1 << autctcfg.generators_length_log_2;
    let sr_params2 = SelRerandParameters::<SecpConfig, SecqConfig>::new(
                generators_length,
                generators_length, &mut rng);
    let (curve_tree2, H2) = get_curve_tree::
        <{autct::utils::BRANCHING_FACTOR}, SecpBase, SecpConfig, SecqConfig>(
        &pubkey_filepath2,
        autctcfg.depth.try_into().unwrap(), &sr_params2);
    let verifier_service = Arc::new(
        RPCProofVerifier{ sr_params: sr_params2,
            pubkey_filepath: pubkey_filepath2,
            curve_tree: curve_tree2,
            H: H2,
            context_label: autctcfg.context_label}
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
}

