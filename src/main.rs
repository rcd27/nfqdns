mod config;
mod dns;
mod domain_list;
mod error;
mod packet;
mod protocol;
mod rawsock;

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use clap::Parser;

use config::{Args, Config};
use domain_list::DomainList;
use protocol::RedirectAction;

static STATS_TOTAL: AtomicUsize = AtomicUsize::new(0);
static STATS_TUNNEL: AtomicUsize = AtomicUsize::new(0);
static STATS_WHITELIST: AtomicUsize = AtomicUsize::new(0);
static STATS_PASS: AtomicUsize = AtomicUsize::new(0);

const STATS_INTERVAL_SECS: u64 = 60;
const BUF_SIZE: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficCategory {
    Tunnel,
    Whitelist,
    Pass,
}

pub struct DomainLists {
    pub tunnel: DomainList,
    pub whitelist: DomainList,
}

fn classify_domain(domain: &str, lists: &DomainLists) -> TrafficCategory {
    if lists.whitelist.contains(domain) {
        TrafficCategory::Whitelist
    } else if lists.tunnel.contains(domain) {
        TrafficCategory::Tunnel
    } else {
        TrafficCategory::Pass
    }
}

/// Обрабатывает пойманный IP пакет. Возвращает spoofed response если домен в списке.
fn process_packet(raw_ip: &[u8], lists: &DomainLists, config: &Config) -> Option<Vec<u8>> {
    let info = packet::parse_dns_query(raw_ip)?;
    let domain = dns::extract_domain(&info.dns_payload)?;
    let category = classify_domain(&domain, lists);

    STATS_TOTAL.fetch_add(1, Ordering::Relaxed);

    match category {
        TrafficCategory::Tunnel => {
            STATS_TUNNEL.fetch_add(1, Ordering::Relaxed);
            let dns_response = dns::craft_response(&info.dns_payload, config.spoof_ip)?;
            protocol::emit(&protocol::data_signal_redirect(
                &domain,
                RedirectAction::Tunnel,
            ));
            Some(packet::build_spoofed_response(&info, &dns_response))
        }
        TrafficCategory::Whitelist => {
            STATS_WHITELIST.fetch_add(1, Ordering::Relaxed);
            None
        }
        TrafficCategory::Pass => {
            STATS_PASS.fetch_add(1, Ordering::Relaxed);
            None
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
    let config = match Config::from_args(args) {
        Ok(c) => c,
        Err(e) => {
            protocol::emit(&protocol::state_fatal(&e));
            std::process::exit(1);
        }
    };

    if config.ifaces.is_empty() {
        protocol::emit(&protocol::state_fatal(
            "no interfaces specified (--ifaces eth0,eth1)",
        ));
        std::process::exit(1);
    }

    let tunnel_list = load_list(&config.tunnel_list_path, "tunnel");
    if tunnel_list.len() == 0 {
        protocol::emit(&protocol::state_degraded(
            "tunnel list empty, working as passthrough",
        ));
    }

    let whitelist = match &config.whitelist_path {
        Some(path) => load_list(path, "whitelist"),
        None => DomainList::empty(),
    };

    let lists = DomainLists {
        tunnel: tunnel_list,
        whitelist,
    };

    // AF_PACKET на первом bridge порту.
    // На L2 bridge оба порта видят один и тот же трафик — достаточно слушать один.
    let iface = &config.ifaces[0];
    let sock = match rawsock::RawSocket::bind(iface) {
        Ok(s) => s,
        Err(e) => {
            protocol::emit(&protocol::state_fatal(&format!(
                "cannot bind AF_PACKET on {}: {}",
                iface, e
            )));
            std::process::exit(1);
        }
    };

    protocol::emit(&protocol::state_alive(env!("CARGO_PKG_VERSION")));

    let mut buf = [0u8; BUF_SIZE];
    let mut last_stats = Instant::now();

    loop {
        let (len, addr) = match sock.recv(&mut buf) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("recv error: {}", e);
                continue;
            }
        };

        // PACKET_OUTGOING (4) — наши собственные пакеты, пропускаем
        if addr.sll_pkttype == 4 {
            continue;
        }

        // ETH_P_ALL: Ethernet frame. Фильтруем IPv4 (0x0800).
        if len < 14 {
            continue;
        }
        let ethertype = u16::from_be_bytes([buf[12], buf[13]]);
        if ethertype != 0x0800 {
            continue;
        }

        // Пропускаем Ethernet header (14 байт)
        let raw_ip = &buf[14..len];

        if let Some(spoofed_ip) = process_packet(raw_ip, &lists, &config) {
            // Ethernet frame: dst=client MAC, src=original dst MAC, ethertype=IPv4
            let client_mac = &buf[6..12];
            let dns_server_mac = &buf[0..6];

            let mut frame = Vec::with_capacity(14 + spoofed_ip.len());
            frame.extend_from_slice(client_mac);
            frame.extend_from_slice(dns_server_mac);
            frame.extend_from_slice(&[0x08, 0x00]);
            frame.extend_from_slice(&spoofed_ip);

            let mut dst_mac = [0u8; 6];
            dst_mac.copy_from_slice(client_mac);

            if let Err(e) = sock.send(&frame, &dst_mac) {
                eprintln!("send error: {}", e);
            }
        }

        if last_stats.elapsed().as_secs() >= STATS_INTERVAL_SECS {
            let total = STATS_TOTAL.load(Ordering::Relaxed);
            let tunneled = STATS_TUNNEL.load(Ordering::Relaxed);
            let whitelisted = STATS_WHITELIST.load(Ordering::Relaxed);
            let passed = STATS_PASS.load(Ordering::Relaxed);
            protocol::emit(&protocol::data_gauge(
                total as u64,
                tunneled as u64,
                whitelisted as u64,
                passed as u64,
            ));
            last_stats = Instant::now();
        }
    }
}
