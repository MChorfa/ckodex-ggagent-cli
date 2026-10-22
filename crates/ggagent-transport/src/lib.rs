//! # ggagent-transport
//!
//! Explicit Transport Layer for `ckodex-ggagent-cli`.
//!
//! Handles:
//! - Google A2A JSON-RPC 2.0 and Server-Sent Events (SSE) streaming
//! - Agentic Resource Discovery (ARD) /.well-known/ard.json server and resolver
//! - Model Context Protocol (MCP) tool bridge
//! - Agnostic cross-harness adapters (Antigravity, Claude Code, Codex, OpenCode, SAM Mesh)
//! - Native async HTTP/SSE/JSON-RPC server

pub mod a2a_rpc;
pub mod ard_service;
pub mod cross_harness;
pub mod error;
pub mod server;
pub mod sse;

pub use a2a_rpc::{A2aRpcHandler, JsonRpcRequest, JsonRpcResponse};
pub use ard_service::ArdService;
pub use cross_harness::{CrossHarnessBridge, HarnessFamily, HarnessProfile};
pub use error::TransportError;
pub use server::TransportServer;
pub use sse::SseFormatter;
