use serde::Serialize;
use std::io::{self, Write};

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Payload {
    State(StatePayload),
    Data(DataPayload),
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StatePayload {
    Alive { version: String },
    Degraded { reason: String },
    Fatal { reason: String },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DataPayload {
    Signal(SignalPayload),
    Gauge(GaugePayload),
}

#[derive(Debug, Clone, Serialize)]
pub struct SignalPayload {
    pub signal_type: &'static str,
    pub fields: SignalFields,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignalFields {
    pub domain: String,
    pub action: RedirectAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub enum RedirectAction {
    Tunnel,
}

#[derive(Debug, Clone, Serialize)]
pub struct GaugePayload {
    pub total: u64,
    pub tunneled: u64,
    pub whitelisted: u64,
    pub passed: u64,
}

pub fn state_alive(version: &str) -> Payload {
    Payload::State(StatePayload::Alive {
        version: version.to_string(),
    })
}

pub fn state_fatal(reason: &str) -> Payload {
    Payload::State(StatePayload::Fatal {
        reason: reason.to_string(),
    })
}

pub fn state_degraded(reason: &str) -> Payload {
    Payload::State(StatePayload::Degraded {
        reason: reason.to_string(),
    })
}

pub fn data_gauge(total: u64, tunneled: u64, whitelisted: u64, passed: u64) -> Payload {
    Payload::Data(DataPayload::Gauge(GaugePayload {
        total,
        tunneled,
        whitelisted,
        passed,
    }))
}

pub fn data_signal_redirect(domain: &str, action: RedirectAction) -> Payload {
    Payload::Data(DataPayload::Signal(SignalPayload {
        signal_type: "DOMAIN_REDIRECTED",
        fields: SignalFields {
            domain: domain.to_string(),
            action,
        },
    }))
}

pub fn emit(payload: &Payload) {
    if let Ok(json) = serde_json::to_string(payload) {
        let stdout = io::stdout();
        let mut lock = stdout.lock();
        let _ = writeln!(lock, "{json}");
        let _ = lock.flush();
    }
}
