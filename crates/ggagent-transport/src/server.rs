use crate::a2a_rpc::{A2aRpcHandler, JsonRpcRequest};
use crate::ard_service::ArdService;
use crate::sse::SseFormatter;
use ggagent_kernel::a2a::AgentCard;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::info;

pub struct TransportServer {
    port: u16,
    a2a_handler: Arc<A2aRpcHandler>,
    ard_service: Arc<ArdService>,
    agent_card: AgentCard,
}

impl TransportServer {
    pub fn new(port: u16, agent_card: AgentCard, ard_service: ArdService) -> Self {
        let a2a_handler = Arc::new(A2aRpcHandler::new(agent_card.clone()));
        Self {
            port,
            a2a_handler,
            ard_service: Arc::new(ard_service),
            agent_card,
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let addr = format!("127.0.0.1:{}", self.port);
        let listener = TcpListener::bind(&addr).await?;
        info!(
            "CKODEX ggagent transport server listening on http://{}",
            addr
        );

        loop {
            let (mut socket, _peer_addr) = listener.accept().await?;
            let a2a = Arc::clone(&self.a2a_handler);
            let ard = Arc::clone(&self.ard_service);
            let card = self.agent_card.clone();

            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                let n = match socket.read(&mut buf).await {
                    Ok(n) if n > 0 => n,
                    _ => return,
                };

                let request = String::from_utf8_lossy(&buf[..n]);
                let first_line = request.lines().next().unwrap_or_default();
                let parts: Vec<&str> = first_line.split_whitespace().collect();

                if parts.len() < 2 {
                    return;
                }

                let method = parts[0];
                let path = parts[1];

                // Route requests
                if method == "GET" && path == "/.well-known/ard.json" {
                    let doc = ard.get_document();
                    let body = serde_json::to_string_pretty(&doc).unwrap_or_default();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                } else if method == "GET" && path == "/.well-known/agent-card.json" {
                    let body = serde_json::to_string_pretty(&card).unwrap_or_default();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                } else if method == "GET" && path == "/healthz" {
                    let body = "{\"status\":\"healthy\",\"engine\":\"ckodex-ggagent-cli\",\"version\":\"2.0.0\"}";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                } else if method == "POST" && path == "/api/v1/a2a" {
                    // Find JSON body after \r\n\r\n
                    if let Some(pos) = request.find("\r\n\r\n") {
                        let json_str = &request[pos + 4..];
                        if let Ok(rpc_req) = serde_json::from_str::<JsonRpcRequest>(json_str) {
                            let rpc_res = a2a.handle_request(rpc_req);
                            let body = serde_json::to_string_pretty(&rpc_res).unwrap_or_default();
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = socket.write_all(response.as_bytes()).await;
                            return;
                        }
                    }
                    let err_body = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32700,\"message\":\"Parse error\"},\"id\":null}";
                    let response = format!(
                        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        err_body.len(),
                        err_body
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                } else if method == "GET" && path.starts_with("/api/v1/a2a/events") {
                    let headers = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\nAccess-Control-Allow-Origin: *\r\n\r\n";
                    let _ = socket.write_all(headers.as_bytes()).await;

                    // Send initial handshake SSE
                    let handshake = SseFormatter::format_event(
                        "a2a.handshake",
                        Some("0"),
                        &serde_json::json!({
                            "agent": "ckodex-ggagent-cli",
                            "protocol": "A2A v1.0",
                            "status": "connected"
                        }),
                    )
                    .unwrap_or_default();
                    let _ = socket.write_all(handshake.as_bytes()).await;
                } else if method == "GET" && (path == "/" || path == "/playground") {
                    let html = include_str!("../templates/playground.html");
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
                        html.len(),
                        html
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                } else {
                    let not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                    let _ = socket.write_all(not_found.as_bytes()).await;
                }
            });
        }
    }
}
