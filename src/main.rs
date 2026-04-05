mod config;
mod dns;
mod domain_list;
mod error;
mod packet;
mod protocol;

use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use clap::Parser;
use nfq::{Queue, Verdict};

use config::{Args, Config};
use domain_list::DomainList;
use protocol::RedirectAction;

static STATS_TOTAL: AtomicUsize = AtomicUsize::new(0);
static STATS_REDIRECT: AtomicUsize = AtomicUsize::new(0);
static STATS_TUNNEL: AtomicUsize = AtomicUsize::new(0);
static STATS_BYPASS: AtomicUsize = AtomicUsize::new(0);
static STATS_PASS: AtomicUsize = AtomicUsize::new(0);

const STATS_INTERVAL_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficCategory {
    Redirect,
    Tunnel,
    Bypass,
    Pass,
}

pub struct DomainLists {
    pub redirect: DomainList,
    pub tunnel: DomainList,
    pub bypass: DomainList,
}

fn classify_domain(domain: &str, lists: &DomainLists) -> TrafficCategory {
    if lists.bypass.contains(domain) {
        TrafficCategory::Bypass
    } else if lists.tunnel.contains(domain) {
        TrafficCategory::Tunnel
    } else if lists.redirect.contains(domain) {
        TrafficCategory::Redirect
    } else {
        TrafficCategory::Pass
    }
}

enum PacketVerdict {
    Accept,
    SpoofedResponse(Vec<u8>),
}

fn spoof_dns_response(
    dns_payload: &[u8],
    raw_packet: &[u8],
    target_ip: Ipv4Addr,
) -> Option<Vec<u8>> {
    let dns_response = dns::craft_response(dns_payload, target_ip)?;
    packet::build_spoofed_packet(raw_packet, &dns_response)
}

fn process_packet(raw_packet: &[u8], lists: &DomainLists, config: &Config) -> PacketVerdict {
    let headers = match etherparse::PacketHeaders::from_ip_slice(raw_packet) {
        Ok(h) => h,
        Err(_) => {
            STATS_PASS.fetch_add(1, Ordering::Relaxed);
            return PacketVerdict::Accept;
        }
    };

    let dns_payload = headers.payload.slice();

    let domain = match dns::extract_domain(dns_payload) {
        Some(d) => d,
        None => {
            STATS_PASS.fetch_add(1, Ordering::Relaxed);
            return PacketVerdict::Accept;
        }
    };

    let category = classify_domain(&domain, lists);

    match category {
        TrafficCategory::Redirect => {
            STATS_REDIRECT.fetch_add(1, Ordering::Relaxed);
            match spoof_dns_response(dns_payload, raw_packet, config.redirect_ip) {
                Some(spoofed) => {
                    protocol::emit(&protocol::data_signal_redirect(
                        &domain,
                        RedirectAction::Redirect,
                    ));
                    PacketVerdict::SpoofedResponse(spoofed)
                }
                None => {
                    STATS_PASS.fetch_add(1, Ordering::Relaxed);
                    PacketVerdict::Accept
                }
            }
        }
        TrafficCategory::Tunnel => {
            STATS_TUNNEL.fetch_add(1, Ordering::Relaxed);
            match config.tunnel_ip {
                Some(tunnel_ip) => match spoof_dns_response(dns_payload, raw_packet, tunnel_ip) {
                    Some(spoofed) => {
                        protocol::emit(&protocol::data_signal_redirect(
                            &domain,
                            RedirectAction::Tunnel,
                        ));
                        PacketVerdict::SpoofedResponse(spoofed)
                    }
                    None => {
                        STATS_PASS.fetch_add(1, Ordering::Relaxed);
                        PacketVerdict::Accept
                    }
                },
                None => {
                    // tunnel_ip not configured — pass through
                    STATS_PASS.fetch_add(1, Ordering::Relaxed);
                    PacketVerdict::Accept
                }
            }
        }
        TrafficCategory::Bypass => {
            STATS_BYPASS.fetch_add(1, Ordering::Relaxed);
            PacketVerdict::Accept
        }
        TrafficCategory::Pass => {
            STATS_PASS.fetch_add(1, Ordering::Relaxed);
            PacketVerdict::Accept
        }
    }
}

fn load_list(path: &Path, name: &str) -> DomainList {
    match DomainList::load(path) {
        Ok(list) => list,
        Err(e) => {
            protocol::emit(&protocol::state_fatal(&format!(
                "cannot load {} list: {}",
                name, e
            )));
            std::process::exit(1);
        }
    }
}

fn main() {
    let args = Args::parse();
    let config = Config::from(args);

    let redirect_list = load_list(&config.redirect_list_path, "redirect");
    if redirect_list.len() == 0 {
        protocol::emit(&protocol::state_degraded(
            "redirect list empty, working as passthrough",
        ));
    }

    let tunnel_list = match &config.tunnel_list_path {
        Some(path) => load_list(path, "tunnel"),
        None => DomainList::empty(),
    };

    let bypass_list = match &config.bypass_list_path {
        Some(path) => load_list(path, "bypass"),
        None => DomainList::empty(),
    };

    let lists = DomainLists {
        redirect: redirect_list,
        tunnel: tunnel_list,
        bypass: bypass_list,
    };

    let mut queue = match Queue::open() {
        Ok(q) => q,
        Err(e) => {
            protocol::emit(&protocol::state_fatal(&format!(
                "cannot open NFQUEUE: {:?}",
                e
            )));
            std::process::exit(1);
        }
    };

    if let Err(e) = queue.bind(config.queue_num) {
        protocol::emit(&protocol::state_fatal(&format!(
            "cannot bind NFQUEUE {}: {:?}",
            config.queue_num, e
        )));
        std::process::exit(1);
    }

    protocol::emit(&protocol::state_alive(env!("CARGO_PKG_VERSION")));

    let mut last_stats = Instant::now();

    loop {
        let mut msg = match queue.recv() {
            Ok(msg) => msg,
            Err(e) => {
                eprintln!("recv error: {:?}", e);
                continue;
            }
        };

        STATS_TOTAL.fetch_add(1, Ordering::Relaxed);

        let payload = msg.get_payload();
        let verdict = process_packet(payload, &lists, &config);

        match verdict {
            PacketVerdict::Accept => {
                msg.set_verdict(Verdict::Accept);
            }
            PacketVerdict::SpoofedResponse(spoofed_packet) => {
                msg.set_payload(spoofed_packet);
                msg.set_verdict(Verdict::Accept);
            }
        }

        queue.verdict(msg).ok();

        if last_stats.elapsed().as_secs() >= STATS_INTERVAL_SECS {
            let total = STATS_TOTAL.load(Ordering::Relaxed);
            let redirected = STATS_REDIRECT.load(Ordering::Relaxed);
            let tunneled = STATS_TUNNEL.load(Ordering::Relaxed);
            let bypassed = STATS_BYPASS.load(Ordering::Relaxed);
            let passed = STATS_PASS.load(Ordering::Relaxed);
            protocol::emit(&protocol::data_gauge(
                total as u64,
                redirected as u64,
                tunneled as u64,
                bypassed as u64,
                passed as u64,
            ));
            last_stats = Instant::now();
        }
    }
}
