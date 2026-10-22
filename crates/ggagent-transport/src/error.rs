use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum TransportError {
    #[error("JSON-RPC error: code={code}, message={message}")]
    JsonRpc { code: i32, message: String },

    #[error("SSE streaming error: {0}")]
    SseError(String),

    #[error("Network I/O error: {0}")]
    IoError(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Task not found: {0}")]
    TaskNotFound(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Harness bridge error: {0}")]
    HarnessError(String),
}
