use std::net::Ipv4Addr;
use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(name = "nfqdns", about = "DNS traffic classifier for L2 bridge via AF_PACKET")]
pub struct Args {
    /// Bridge порты для перехвата DNS (через запятую: eth0,eth1)
    #[arg(long, value_delimiter = ',')]
    pub ifaces: Vec<String>,
    /// IP для redirect (desync/zapret) доменов
    #[arg(long)]
    pub redirect_ip: Ipv4Addr,
    /// Список доменов для redirect
    #[arg(long)]
    pub redirect_list: PathBuf,
    /// IP для tunnel (sing-box) доменов
    #[arg(long)]
    pub tunnel_ip: Option<Ipv4Addr>,
    /// Список доменов для tunnel
    #[arg(long)]
    pub tunnel_list: Option<PathBuf>,
    /// Список доменов для bypass (без модификации)
    #[arg(long)]
    pub bypass_list: Option<PathBuf>,
}

pub struct Config {
    pub ifaces: Vec<String>,
    pub redirect_ip: Ipv4Addr,
    pub tunnel_ip: Option<Ipv4Addr>,
    pub redirect_list_path: PathBuf,
    pub tunnel_list_path: Option<PathBuf>,
    pub bypass_list_path: Option<PathBuf>,
}

impl From<Args> for Config {
    fn from(args: Args) -> Self {
        Config {
            ifaces: args.ifaces,
            redirect_ip: args.redirect_ip,
            tunnel_ip: args.tunnel_ip,
            redirect_list_path: args.redirect_list,
            tunnel_list_path: args.tunnel_list,
            bypass_list_path: args.bypass_list,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_args() {
        let args = Args::try_parse_from([
            "nfqdns",
            "--ifaces",
            "eth0,eth1",
            "--redirect-ip",
            "10.99.1.50",
            "--redirect-list",
            "/tmp/redirect.txt",
        ])
        .unwrap();
        let config = Config::from(args);
        assert_eq!(config.ifaces, vec!["eth0", "eth1"]);
        assert_eq!(config.redirect_ip, Ipv4Addr::new(10, 99, 1, 50));
        assert!(config.tunnel_ip.is_none());
    }
}
