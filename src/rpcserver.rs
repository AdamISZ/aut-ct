#![allow(non_snake_case)]

use ark_serialize::{ CanonicalDeserialize, 
    Compress, Validate};
use crate::rpc::{RPCAuditProver, RPCCreateKeys, RPCProverVerifierArgs};
use crate::utils::{get_curve_tree, get_leaf_commitments, convert_keys, APP_DOMAIN_LABEL};
use tokio::{task, net::TcpListener};
use std::fs;
use std::error::Error;
use std::io::Cursor;
use std::sync::{Arc, Mutex};
use toy_rpc::Server;
use std::iter::zip;

use crate::{rpc::RPCProofVerifier, rpc::RPCProver, utils};
use crate::config::AutctConfig;
use crate::keyimagestore::{KeyImageStore, create_new_store};
use relations::curve_tree::{SelRerandParameters, CurveTree};
use ark_secp256k1::{Config as SecpConfig, Fq as SecpBase};
use ark_secq256k1::Config as SecqConfig;
use ark_ec::short_weierstrass::{Affine, SWCurveConfig};

pub async fn do_serve(autctcfg: AutctConfig) -> Result<(), Box<dyn Error>>{
    let (context_labels, keyset_file_locs) = match autctcfg
    .clone().get_context_labels_and_keysets(){
        Ok(x) => x,
        Err(err) => return Err(err),
    };
    let rpc_port = autctcfg.rpc_port.unwrap();
    let host: &str= &autctcfg.rpc_host.clone().unwrap();
    let port_str: &str = &rpc_port.to_string();
    let addr: String = format!("{}:{}", host, port_str);
    let mut rng = rand::thread_rng();
    let generators_length = 1 << autctcfg.generators_length_log_2.unwrap();
    let sr_params = SelRerandParameters::<SecpConfig, SecqConfig>::new(
                generators_length,
                generators_length, &mut rng);
    let mut curve_trees: Vec<CurveTree<SecpConfig, SecqConfig>> = vec![];
    let mut Js: Vec<Affine<SecpConfig>> = vec![];
    let mut kss: Vec<Arc<Mutex<KeyImageStore<Affine<SecpConfig>>>>> = vec![];
    for (fl, cl) in zip(keyset_file_locs.iter(), context_labels.iter()) {
        // this part is what consumes time, so we do it upfront on startup of the rpc server,
        // for every keyset that we are serving.
        // also note that for now there are no errors returned by convert_keys hence unwrap()
        // TODO add info to interface so user knows why the startup is hanging
        convert_keys::<SecpBase,
        SecpConfig,
        SecqConfig>(fl.to_string(),
         autctcfg.generators_length_log_2.unwrap()).unwrap();
        let leaf_commitments = get_leaf_commitments(
            &(fl.to_string() + ".p"));

        // Actually creating the curve tree is much less time consuming (a few seconds for most trees)
        let (curve_tree2, _) = get_curve_tree::
        <SecpBase, SecpConfig, SecqConfig>(
        &leaf_commitments,
        autctcfg.depth.unwrap().try_into().unwrap(), &sr_params);
        curve_trees.push(curve_tree2);
        let J = utils::get_generators(cl.as_bytes());
        // load the appropriate key image database.
        // There is a finesse here: given that we may have many (keyset, context_label)
        // pairs, and that the key image store *only* depends on the latter, then, we only
        // need one key image store per *unique* context_label
        let ksr = create_new_store::<SecpBase, SecpConfig>(autctcfg.clone(), cl);
        let mut ks: KeyImageStore<Affine<SecpConfig>>;
        if ksr.is_err() {
            ks = KeyImageStore::<Affine<SecpConfig>>::new(
                autctcfg.keyimage_filename_suffix.clone(), String::from_utf8(APP_DOMAIN_LABEL.to_vec()).unwrap(),
                cl.clone(), Some(J));
            let file_contents = fs::read(ks.full_file_loc.clone().unwrap()).unwrap();
            let cursor = Cursor::new(file_contents);
            // note that this overwrites the pre-existing 'ks' object (but not the file!)
            ks = KeyImageStore::<Affine<SecpConfig>>::deserialize_with_mode(cursor,
                Compress::Yes, Validate::No).unwrap();
            // because not initialized with `new`, this KeyImageStore needs to have
            // its full file location set manually:
            ks.set_full_file_loc(autctcfg.keyimage_filename_suffix.clone().unwrap());
        }
        else {
            ks = ksr.unwrap();
        }
        kss.push(Arc::new(Mutex::new(ks)));
        Js.push(J);
    }
    let G = SecpConfig::GENERATOR;
    //let J = utils::get_generators(autctcfg.context_label.as_ref().unwrap().as_bytes());
    let H = sr_params.even_parameters.pc_gens.B_blinding.clone();
    let prover_verifier_args = RPCProverVerifierArgs {
        sr_params,
        keyset_file_locs,
        context_labels,
        curve_trees,
        G,
        H,
        Js,
        ks: kss
    };
    let verifier_service = Arc::new(
        RPCProofVerifier{
            prover_verifier_args: prover_verifier_args.clone()}
    );
    let prover_service = Arc::new(
        RPCProver{
            prover_verifier_args: prover_verifier_args.clone()}
    );
    let auditor_service = Arc::new(RPCAuditProver{
        prover_verifier_args});
    let createkeys_service = Arc::new(RPCCreateKeys{});
    let server = Server::builder()
        .register(verifier_service) // register service
        .register(prover_service)
        .register(createkeys_service)
        .register(auditor_service)
        .build();
    let listener = TcpListener::bind(&addr).await.unwrap();

    // Run the server in a separate task
    let handle = task::spawn(async move {
        println!("Starting server at {}", &addr);
        server.accept_websocket(listener).await.unwrap();
    });
    handle.await.expect("Error running the RPC server");
    Ok(())
}

