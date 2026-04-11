use std::net::Ipv4Addr;
use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(name = "nfqdns", about = "DNS traffic classifier for L2 bridge via AF_PACKET")]
pub struct Args {
    /// Bridge порты для перехвата DNS (через запятую: eth0,eth1)
    #[arg(long, value_delimiter = ',')]
    pub ifaces: Vec<String>,
    /// Интерфейс для spoofed IP (берёт IPv4 автоматически, например wlan0)
    #[arg(long)]
    pub spoof_iface: Option<String>,
    /// Явный IP для spoofed ответов (вместо --spoof-iface)
    #[arg(long)]
    pub spoof_ip: Option<Ipv4Addr>,
    /// Список доменов для redirect (desync/zapret)
    #[arg(long)]
    pub redirect_list: PathBuf,
    /// Список доменов для tunnel (sing-box)
    #[arg(long)]
    pub tunnel_list: Option<PathBuf>,
    /// Список доменов для bypass (без модификации)
    #[arg(long)]
    pub bypass_list: Option<PathBuf>,
}

pub struct Config {
    pub ifaces: Vec<String>,
    pub spoof_ip: Ipv4Addr,
    pub redirect_list_path: PathBuf,
    pub tunnel_list_path: Option<PathBuf>,
    pub bypass_list_path: Option<PathBuf>,
}

/// Получает IPv4 адрес интерфейса из /sys/class/net + ip addr
pub fn get_iface_ipv4(iface: &str) -> Option<Ipv4Addr> {
    let output = std::process::Command::new("ip")
        .args(["-4", "addr", "show", iface])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("inet ") {
            // "inet 192.168.1.93/24 ..."
            let addr_str = trimmed
                .split_whitespace()
                .nth(1)?
                .split('/')
                .next()?;
            return addr_str.parse().ok();
        }
    }
    None
}

impl Config {
    pub fn from_args(args: Args) -> Result<Self, String> {
        let spoof_ip = if let Some(ip) = args.spoof_ip {
            ip
        } else if let Some(ref iface) = args.spoof_iface {
            get_iface_ipv4(iface).ok_or_else(|| {
                format!("cannot get IPv4 from interface {}", iface)
            })?
        } else {
            return Err("either --spoof-ip or --spoof-iface required".into());
        };

        Ok(Config {
            ifaces: args.ifaces,
            spoof_ip,
            redirect_list_path: args.redirect_list,
            tunnel_list_path: args.tunnel_list,
            bypass_list_path: args.bypass_list,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_with_explicit_ip() {
        let args = Args::try_parse_from([
            "nfqdns",
            "--ifaces", "eth0,eth1",
            "--spoof-ip", "192.168.1.93",
            "--redirect-list", "/tmp/redirect.txt",
        ])
        .unwrap();
        let config = Config::from_args(args).unwrap();
        assert_eq!(config.ifaces, vec!["eth0", "eth1"]);
        assert_eq!(config.spoof_ip, Ipv4Addr::new(192, 168, 1, 93));
    }

    #[test]
    fn config_without_ip_or_iface_fails() {
        let args = Args::try_parse_from([
            "nfqdns",
            "--ifaces", "eth0",
            "--redirect-list", "/tmp/redirect.txt",
        ])
        .unwrap();
        assert!(Config::from_args(args).is_err());
    }
}
