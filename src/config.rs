use std::net::Ipv4Addr;
use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(name = "nfqdns", about = "DNS traffic classifier for L2 bridge")]
pub struct Args {
    #[arg(long)]
    pub redirect_ip: Ipv4Addr,
    #[arg(long)]
    pub redirect_list: PathBuf,
    #[arg(long)]
    pub tunnel_ip: Option<Ipv4Addr>,
    #[arg(long)]
    pub tunnel_list: Option<PathBuf>,
    #[arg(long)]
    pub bypass_list: Option<PathBuf>,
    #[arg(long, default_value = "100")]
    pub queue_num: u16,
}

pub struct Config {
    pub queue_num: u16,
    pub redirect_ip: Ipv4Addr,
    pub tunnel_ip: Option<Ipv4Addr>,
    pub redirect_list_path: PathBuf,
    pub tunnel_list_path: Option<PathBuf>,
    pub bypass_list_path: Option<PathBuf>,
}

impl From<Args> for Config {
    fn from(args: Args) -> Self {
        Config {
            queue_num: args.queue_num,
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
            "--redirect-ip",
            "192.168.1.50",
            "--redirect-list",
            "/tmp/redirect.txt",
        ])
        .unwrap();
        let config = Config::from(args);
        assert_eq!(config.redirect_ip, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(config.queue_num, 100);
        assert!(config.tunnel_ip.is_none());
    }
}
