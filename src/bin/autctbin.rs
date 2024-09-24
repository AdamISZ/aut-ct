#![allow(non_snake_case)]

extern crate rand;
extern crate alloc;
extern crate ark_secp256k1;
use autct::rpcserver;
use std::error::Error;
use autct::autctactions::*;
use autct::config::AutctConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>>{
    let autctcfg = AutctConfig::build()?;
    match autctcfg.clone().mode.unwrap().as_str() {
        "prove" => {return request_prove(autctcfg).await
                    },
        "verify" => {return request_verify(autctcfg).await},
        "serve" => {return rpcserver::do_serve(autctcfg).await
                    },
        "newkeys" => {return request_create_keys(autctcfg).await},
        "auditprove" => {return request_audit(autctcfg).await},
        "auditverify" => {let _ = request_audit_verify(autctcfg).await;
        return Ok(())},
        // this extra tool is really just for testing:
        "encryptkey" => {return request_encrypt_key(autctcfg).await},
        // extra tool for exporting the key:
        "decryptkey" => {return request_decrypted_key(autctcfg).await},
        // extra (undocumented) tool for creating test files:
        "audittestgen" => {return create_test_data(autctcfg).await},
        _ => {return Err("Invalid mode, must be 'prove', 'auditprove', 'serve', 'newkeys', 'encryptkey', 'decryptkey' or 'verify'".into())},

    }
}
