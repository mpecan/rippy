//! Sending one System One request. A trait so tests can inject answers without
//! a network; [`HttpTransport`] is the only implementation that makes a call.

use std::time::Duration;

use serde_json::Value;

/// Posts a request body and returns the parsed response body.
pub trait Transport {
    /// # Errors
    ///
    /// Returns a short, user-facing description of the failure. Any error
    /// leaves the ask unchanged.
    fn post(
        &self,
        endpoint: &str,
        api_key: &str,
        body: &Value,
        timeout: Duration,
    ) -> Result<Value, String>;
}

/// Blocking HTTPS through `ureq`, with one overall deadline and no retries:
/// hook latency matters more than a retried answer.
pub struct HttpTransport;

impl Transport for HttpTransport {
    fn post(
        &self,
        endpoint: &str,
        api_key: &str,
        body: &Value,
        timeout: Duration,
    ) -> Result<Value, String> {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .build()
            .into();
        let mut response = agent
            .post(endpoint)
            .header("Authorization", &format!("Bearer {api_key}"))
            .send_json(body)
            .map_err(|e| describe(&e, timeout))?;
        response
            .body_mut()
            .read_json::<Value>()
            .map_err(|e| format!("unreadable response: {e}"))
    }
}

fn describe(error: &ureq::Error, timeout: Duration) -> String {
    match error {
        ureq::Error::StatusCode(401) => "HTTP 401 (check the API key)".to_owned(),
        ureq::Error::StatusCode(402) => "HTTP 402 (no credit left on the account)".to_owned(),
        ureq::Error::StatusCode(422) => "HTTP 422 (request rejected)".to_owned(),
        ureq::Error::StatusCode(429) => "HTTP 429 (rate limited)".to_owned(),
        ureq::Error::StatusCode(529) => "HTTP 529 (overloaded)".to_owned(),
        ureq::Error::StatusCode(code) => format!("HTTP {code}"),
        ureq::Error::Timeout(_) => format!("timed out after {} ms", timeout.as_millis()),
        other => other.to_string(),
    }
}
