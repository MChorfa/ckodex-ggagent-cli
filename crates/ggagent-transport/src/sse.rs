use serde::Serialize;

/// SSE Event Formatter
pub struct SseFormatter;

impl SseFormatter {
    /// Formats an event into text/event-stream representation
    pub fn format_event<T: Serialize>(
        event_type: &str,
        id: Option<&str>,
        data: &T,
    ) -> Result<String, serde_json::Error> {
        let json_payload = serde_json::to_string(data)?;
        let mut out = String::new();

        if let Some(id_str) = id {
            out.push_str(&format!("id: {}\n", id_str));
        }

        out.push_str(&format!("event: {}\n", event_type));

        for line in json_payload.lines() {
            out.push_str(&format!("data: {}\n", line));
        }

        out.push('\n'); // Event boundary
        Ok(out)
    }

    /// Formats a comment heartbeat ping
    pub fn heartbeat() -> &'static str {
        ": ping\n\n"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_sse() {
        let payload = serde_json::json!({"status": "RUNNING", "progress": 50});
        let formatted = SseFormatter::format_event("task.status", Some("evt-1"), &payload).unwrap();
        assert!(formatted.contains("id: evt-1\n"));
        assert!(formatted.contains("event: task.status\n"));
        assert!(formatted.contains("data: {\"progress\":50,\"status\":\"RUNNING\"}\n\n"));
    }
}
