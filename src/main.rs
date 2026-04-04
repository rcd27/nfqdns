mod config;
mod dns;
mod domain_list;
mod packet;
mod protocol;

use config::Config;
use domain_list::DomainList;
use nfq::{Queue, Verdict};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

static STATS_TOTAL: AtomicUsize = AtomicUsize::new(0);
static STATS_REDIRECT: AtomicUsize = AtomicUsize::new(0);
static STATS_BYPASS: AtomicUsize = AtomicUsize::new(0);
static STATS_PASS: AtomicUsize = AtomicUsize::new(0);

const STATS_INTERVAL_SECS: u64 = 60;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config = match Config::from_args(&args) {
        Ok(c) => c,
        Err(e) => {
            protocol::emit(&protocol::state_fatal(&format!("invalid args: {}", e)));
            std::process::exit(1);
        }
    };

    let redirect_list = match DomainList::load(&config.redirect_list_path) {
        Ok(list) => {
            if list.len() == 0 {
                protocol::emit(&protocol::state_degraded(
                    "redirect list empty, working as passthrough",
                ));
            }
            list
        }
        Err(e) => {
            protocol::emit(&protocol::state_fatal(&format!(
                "cannot load redirect list: {}",
                e
            )));
            std::process::exit(1);
        }
    };

    let bypass_list = match &config.bypass_list_path {
        Some(path) => match DomainList::load(path) {
            Ok(list) => list,
            Err(e) => {
                protocol::emit(&protocol::state_fatal(&format!(
                    "cannot load bypass list: {}",
                    e
                )));
                std::process::exit(1);
            }
        },
        None => DomainList::empty(),
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
        let verdict = process_packet(payload, &redirect_list, &bypass_list, &config);

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
            let bypassed = STATS_BYPASS.load(Ordering::Relaxed);
            let passed = STATS_PASS.load(Ordering::Relaxed);
            protocol::emit(&protocol::data_gauge(total, redirected, bypassed, passed));
            last_stats = Instant::now();
        }
    }
}

enum PacketVerdict {
    Accept,
    SpoofedResponse(Vec<u8>),
}

fn process_packet(
    raw_packet: &[u8],
    redirect_list: &DomainList,
    bypass_list: &DomainList,
    config: &Config,
) -> PacketVerdict {
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

    if bypass_list.contains(&domain) {
        STATS_BYPASS.fetch_add(1, Ordering::Relaxed);
        return PacketVerdict::Accept;
    }

    if redirect_list.contains(&domain) {
        STATS_REDIRECT.fetch_add(1, Ordering::Relaxed);

        let dns_response = match dns::craft_response(dns_payload, config.redirect_ip) {
            Some(r) => r,
            None => {
                STATS_PASS.fetch_add(1, Ordering::Relaxed);
                return PacketVerdict::Accept;
            }
        };

        let spoofed = match packet::build_spoofed_packet(raw_packet, &dns_response) {
            Some(s) => s,
            None => {
                STATS_PASS.fetch_add(1, Ordering::Relaxed);
                return PacketVerdict::Accept;
            }
        };

        protocol::emit(&protocol::data_signal_redirect(
            &domain,
            &config.redirect_ip.to_string(),
        ));
        return PacketVerdict::SpoofedResponse(spoofed);
    }

    STATS_PASS.fetch_add(1, Ordering::Relaxed);
    PacketVerdict::Accept
}
