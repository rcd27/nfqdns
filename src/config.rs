use std::net::Ipv4Addr;

pub struct Config {
    pub queue_num: u16,
    pub redirect_ip: Ipv4Addr,
    pub redirect_list_path: String,
    pub bypass_list_path: Option<String>,
    pub stats_interval: u64,
}

impl Config {
    pub fn from_args(args: &[String]) -> Result<Config, String> {
        let mut queue_num: u16 = 100;
        let mut redirect_ip: Option<Ipv4Addr> = None;
        let mut redirect_list_path: Option<String> = None;
        let mut bypass_list_path: Option<String> = None;
        let mut stats_interval: u64 = 60;

        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--queue-num" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--queue-num requires a value".to_string());
                    }
                    queue_num = args[i].parse().map_err(|_| "invalid queue-num".to_string())?;
                }
                "--redirect-ip" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--redirect-ip requires a value".to_string());
                    }
                    redirect_ip = Some(args[i].parse().map_err(|_| "invalid redirect-ip".to_string())?);
                }
                "--redirect-list" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--redirect-list requires a value".to_string());
                    }
                    redirect_list_path = Some(args[i].clone());
                }
                "--bypass-list" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--bypass-list requires a value".to_string());
                    }
                    bypass_list_path = Some(args[i].clone());
                }
                "--stats-interval" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--stats-interval requires a value".to_string());
                    }
                    stats_interval = args[i].parse().map_err(|_| "invalid stats-interval".to_string())?;
                }
                other => {
                    return Err(format!("unknown argument: {}", other));
                }
            }
            i += 1;
        }

        let redirect_ip = redirect_ip.ok_or("--redirect-ip is required".to_string())?;
        let redirect_list_path = redirect_list_path.ok_or("--redirect-list is required".to_string())?;

        Ok(Config {
            queue_num,
            redirect_ip,
            redirect_list_path,
            bypass_list_path,
            stats_interval,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_args() {
        let args: Vec<String> = vec![
            "--redirect-ip", "192.168.1.50",
            "--redirect-list", "/etc/nfqdns/tunnel.txt",
        ].into_iter().map(String::from).collect();

        let config = Config::from_args(&args).unwrap();
        assert_eq!(config.redirect_ip, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(config.redirect_list_path, "/etc/nfqdns/tunnel.txt");
        assert_eq!(config.queue_num, 100);
        assert!(config.bypass_list_path.is_none());
    }

    #[test]
    fn parse_all_args() {
        let args: Vec<String> = vec![
            "--queue-num", "200",
            "--redirect-ip", "10.0.0.1",
            "--redirect-list", "/tmp/tunnel.txt",
            "--bypass-list", "/tmp/bypass.txt",
            "--stats-interval", "30",
        ].into_iter().map(String::from).collect();

        let config = Config::from_args(&args).unwrap();
        assert_eq!(config.queue_num, 200);
        assert_eq!(config.redirect_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(config.bypass_list_path.unwrap(), "/tmp/bypass.txt");
        assert_eq!(config.stats_interval, 30);
    }

    #[test]
    fn missing_required_redirect_ip() {
        let args: Vec<String> = vec![
            "--redirect-list", "/tmp/tunnel.txt",
        ].into_iter().map(String::from).collect();

        let result = Config::from_args(&args);
        assert!(result.is_err());
    }

    #[test]
    fn missing_required_tunnel_list() {
        let args: Vec<String> = vec![
            "--redirect-ip", "1.2.3.4",
        ].into_iter().map(String::from).collect();

        let result = Config::from_args(&args);
        assert!(result.is_err());
    }
}
