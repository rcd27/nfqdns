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
static STATS_REDIRECT: AtomicUsize = AtomicUsize::new(0);
static STATS_TUNNEL: AtomicUsize = AtomicUsize::new(0);
static STATS_BYPASS: AtomicUsize = AtomicUsize::new(0);
static STATS_PASS: AtomicUsize = AtomicUsize::new(0);

const STATS_INTERVAL_SECS: u64 = 60;
const BUF_SIZE: usize = 4096;

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

/// Обрабатывает пойманный IP пакет. Возвращает spoofed response если домен в списке.
fn process_packet(
    raw_ip: &[u8],
    lists: &DomainLists,
    config: &Config,
) -> Option<Vec<u8>> {
    let info = packet::parse_dns_query(raw_ip)?;
    let domain = dns::extract_domain(&info.dns_payload)?;
    let category = classify_domain(&domain, lists);

    STATS_TOTAL.fetch_add(1, Ordering::Relaxed);

    match category {
        TrafficCategory::Redirect => {
            STATS_REDIRECT.fetch_add(1, Ordering::Relaxed);
            let dns_response = dns::craft_response(&info.dns_payload, config.redirect_ip)?;
            protocol::emit(&protocol::data_signal_redirect(&domain, RedirectAction::Redirect));
            Some(packet::build_spoofed_response(&info, &dns_response))
        }
        TrafficCategory::Tunnel => {
            STATS_TUNNEL.fetch_add(1, Ordering::Relaxed);
            let tunnel_ip = config.tunnel_ip?;
            let dns_response = dns::craft_response(&info.dns_payload, tunnel_ip)?;
            protocol::emit(&protocol::data_signal_redirect(&domain, RedirectAction::Tunnel));
            Some(packet::build_spoofed_response(&info, &dns_response))
        }
        TrafficCategory::Bypass => {
            STATS_BYPASS.fetch_add(1, Ordering::Relaxed);
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
    let config = Config::from(args);

    if config.ifaces.is_empty() {
        protocol::emit(&protocol::state_fatal("no interfaces specified (--ifaces eth0,eth1)"));
        std::process::exit(1);
    }

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

    // Открываем raw socket на первом интерфейсе.
    // На L2 bridge оба порта видят один и тот же трафик — достаточно слушать один.
    // Ответ инжектим на тот же порт (обратно к клиенту).
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

        // Debug: логируем первые 20 пакетов
        {
            static DEBUG_COUNT: AtomicUsize = AtomicUsize::new(0);
            let count = DEBUG_COUNT.fetch_add(1, Ordering::Relaxed);
            if count < 20 {
                let ethertype = if len >= 14 { u16::from_be_bytes([buf[12], buf[13]]) } else { 0 };
                let mut extra = String::new();
                if ethertype == 0x0800 && len > 14 + 23 {
                    let ip_proto = buf[14 + 9];
                    if ip_proto == 17 { // UDP
                        let dst_port = u16::from_be_bytes([buf[14 + 22], buf[14 + 23]]);
                        extra = format!(" UDP dst_port={}", dst_port);
                    }
                }
                eprintln!("DEBUG[{}]: len={} pkttype={} etype=0x{:04x}{}", count, len, addr.sll_pkttype, ethertype, extra);
            }
        }

        // sll_pkttype: PACKET_OUTGOING (4) — наши собственные пакеты, пропускаем
        if addr.sll_pkttype == 4 {
            continue;
        }

        // ETH_P_ALL: Ethernet frame. EtherType = IPv4 (0x0800).
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
            // Собираем Ethernet frame: dst=client MAC, src=original dst MAC, ethertype=IPv4
            let client_mac = &buf[6..12]; // src MAC из оригинального frame
            let our_mac = &buf[0..6]; // dst MAC из оригинального frame (MAC "роутера"/DNS)

            let mut frame = Vec::with_capacity(14 + spoofed_ip.len());
            frame.extend_from_slice(client_mac); // dst = клиент
            frame.extend_from_slice(our_mac); // src = "DNS сервер"
            frame.extend_from_slice(&[0x08, 0x00]); // EtherType = IPv4
            frame.extend_from_slice(&spoofed_ip);

            let mut dst_mac = [0u8; 6];
            dst_mac.copy_from_slice(client_mac);

            if let Err(e) = sock.send(&frame, &dst_mac) {
                eprintln!("send error: {}", e);
            }
        }

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
