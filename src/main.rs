mod config;
mod dns;
mod domain_list;
mod packet;

use config::Config;
use domain_list::DomainList;
use nfq::{Queue, Verdict};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

static STATS_TOTAL: AtomicU64 = AtomicU64::new(0);
static STATS_REDIRECT: AtomicU64 = AtomicU64::new(0);
static STATS_BYPASS: AtomicU64 = AtomicU64::new(0);
static STATS_PASS: AtomicU64 = AtomicU64::new(0);

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config = match Config::from_args(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            eprintln!("Usage: nfqdns --redirect-ip IP --redirect-list PATH [--bypass-list PATH] [--queue-num N] [--stats-interval SEC]");
            std::process::exit(1);
        }
    };

    let redirect_list = match DomainList::load(&config.redirect_list_path) {
        Ok(list) => {
            eprintln!("[nfqdns] redirect list: {} domains from {}", list.len(), config.redirect_list_path);
            list
        }
        Err(e) => {
            eprintln!("[nfqdns] FATAL: {}", e);
            std::process::exit(1);
        }
    };

    let bypass_list = match &config.bypass_list_path {
        Some(path) => match DomainList::load(path) {
            Ok(list) => {
                eprintln!("[nfqdns] bypass list: {} domains from {}", list.len(), path);
                list
            }
            Err(e) => {
                eprintln!("[nfqdns] FATAL: {}", e);
                std::process::exit(1);
            }
        }
        None => DomainList::empty(),
    };

    eprintln!("[nfqdns] redirect-ip: {}", config.redirect_ip);
    eprintln!("[nfqdns] queue-num: {}", config.queue_num);
    eprintln!("[nfqdns] binding to NFQUEUE {}...", config.queue_num);

    let mut queue = match Queue::open() {
        Ok(q) => q,
        Err(e) => {
            eprintln!("[nfqdns] FATAL: cannot open NFQUEUE: {:?}", e);
            eprintln!("[nfqdns] hint: run as root, ensure kmod-nfnetlink-queue is loaded");
            std::process::exit(1);
        }
    };

    if let Err(e) = queue.bind(config.queue_num) {
        eprintln!("[nfqdns] FATAL: cannot bind to queue {}: {:?}", config.queue_num, e);
        std::process::exit(1);
    }

    eprintln!("[nfqdns] listening on NFQUEUE {}", config.queue_num);

    let mut last_stats = Instant::now();

    loop {
        let mut msg = match queue.recv() {
            Ok(msg) => msg,
            Err(e) => {
                eprintln!("[nfqdns] recv error: {:?}", e);
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

        if config.stats_interval > 0 && last_stats.elapsed().as_secs() >= config.stats_interval {
            let total = STATS_TOTAL.load(Ordering::Relaxed);
            let tunnel = STATS_REDIRECT.load(Ordering::Relaxed);
            let bypass = STATS_BYPASS.load(Ordering::Relaxed);
            let pass = STATS_PASS.load(Ordering::Relaxed);
            eprintln!("[nfqdns] stats: total={} redirect={} bypass={} pass={}", total, tunnel, bypass, pass);
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

    // Bypass list first (always pass through)
    if bypass_list.contains(&domain) {
        STATS_BYPASS.fetch_add(1, Ordering::Relaxed);
        return PacketVerdict::Accept;
    }

    // Redirect list
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

        eprintln!("[nfqdns] REDIRECT: {} -> {}", domain, config.redirect_ip);
        return PacketVerdict::SpoofedResponse(spoofed);
    }

    // Unknown — pass through
    STATS_PASS.fetch_add(1, Ordering::Relaxed);
    PacketVerdict::Accept
}
