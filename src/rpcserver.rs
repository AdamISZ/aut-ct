#![allow(non_snake_case)]

use tokio::{task, net::TcpListener};
use std::sync::Arc;
use std::env;
use toy_rpc::Server;

use autct::rpc::RPCProofVerifier;
use autct::autctverifier::get_curve_tree;
use relations::curve_tree::SelRerandParameters;
use ark_secp256k1::{Config as SecpConfig, Fq as SecpBase};
use ark_secq256k1::Config as SecqConfig;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let pubkey_filepath2 = args[1].clone();
    let addr = "127.0.0.1:23333";
    let mut rng = rand::thread_rng();
    let generators_length_log_2 = 11;
    let generators_length = 1 << generators_length_log_2;
    let sr_params2 = SelRerandParameters::<SecpConfig, SecqConfig>::new(
                generators_length,
                generators_length, &mut rng);
    let (curve_tree2, H2) = get_curve_tree::
        <256, SecpBase, SecpConfig, SecqConfig>(
        &pubkey_filepath2,
        2, &sr_params2);
    let verifier_service = Arc::new(
        RPCProofVerifier{ sr_params: sr_params2,
            pubkey_filepath: pubkey_filepath2,
            curve_tree: curve_tree2,
            H: H2,}
    );
    let server = Server::builder()
        .register(verifier_service) // register service
        .build();
    let listener = TcpListener::bind(addr).await.unwrap();

    // Run the server in a separate task
    let handle = task::spawn(async move {
        println!("Starting server at {}", &addr);
        server.accept(listener).await.unwrap();
    });
    handle.await.expect("Error running the RPC server");
}

