use std::sync::Arc;
use std::time::Duration;

use autct::config::AutctConfig;
use autct::rpc::RPCEcho;
use autct::rpcclient;
use tokio::net::{TcpListener, TcpStream};
use toy_rpc::Server;

#[tokio::test]
async fn bad_connections_do_not_stop_the_server() {
    let server = Server::builder().register(Arc::new(RPCEcho {})).build();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { server.accept_websocket(listener).await });

    let mut cfg = AutctConfig::default();
    cfg.rpc_host = Some(addr.ip().to_string());
    cfg.rpc_port = Some(addr.port() as i32);
    let echo = || async {
        match tokio::time::timeout(Duration::from_secs(5),
            rpcclient::echo(&cfg)).await {
            Ok(Ok(resp)) => resp.response_msg,
            Ok(Err(e)) => format!("error: {}", e),
            Err(_) => "timed out".to_string(),
        }
    };
    assert_eq!(echo().await, "aut-cttest");

    // a connection that closes without a WebSocket handshake
    drop(TcpStream::connect(addr).await.unwrap());
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(echo().await, "aut-cttest");

    // a connection that stays open and never sends a handshake
    let idle = TcpStream::connect(addr).await.unwrap();
    assert_eq!(echo().await, "aut-cttest");
    drop(idle);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(echo().await, "aut-cttest");
}
