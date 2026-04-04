use serde::Serialize;
use std::io::{self, Write};

#[derive(Serialize)]
struct StateAlive<'a> {
    state: &'static str,
    version: &'a str,
}

#[derive(Serialize)]
struct StateFatal<'a> {
    state: &'static str,
    reason: &'a str,
}

#[derive(Serialize)]
struct StateDegraded<'a> {
    state: &'static str,
    reason: &'a str,
}

#[derive(Serialize)]
struct DataGauge {
    data: &'static str,
    total: usize,
    redirected: usize,
    bypassed: usize,
    passed: usize,
}

#[derive(Serialize)]
struct DataSignalRedirect<'a> {
    data: &'static str,
    name: &'static str,
    domain: &'a str,
    redirect_ip: &'a str,
}

pub fn state_alive(version: &str) -> String {
    serde_json::to_string(&StateAlive {
        state: "alive",
        version,
    })
    .unwrap()
}

pub fn state_fatal(reason: &str) -> String {
    serde_json::to_string(&StateFatal {
        state: "fatal",
        reason,
    })
    .unwrap()
}

pub fn state_degraded(reason: &str) -> String {
    serde_json::to_string(&StateDegraded {
        state: "degraded",
        reason,
    })
    .unwrap()
}

pub fn data_gauge(total: usize, redirected: usize, bypassed: usize, passed: usize) -> String {
    serde_json::to_string(&DataGauge {
        data: "gauge",
        total,
        redirected,
        bypassed,
        passed,
    })
    .unwrap()
}

pub fn data_signal_redirect(domain: &str, redirect_ip: &str) -> String {
    serde_json::to_string(&DataSignalRedirect {
        data: "signal",
        name: "DOMAIN_REDIRECTED",
        domain,
        redirect_ip,
    })
    .unwrap()
}

pub fn emit(message: &str) {
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    let _ = writeln!(lock, "{}", message);
    let _ = lock.flush();
}
