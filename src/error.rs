#[derive(Debug, thiserror::Error)]
pub enum NfqdnsError {
    #[error("config: {0}")]
    Config(String),
    #[error("domain list {path}: {source}")]
    DomainList {
        path: String,
        source: std::io::Error,
    },
    #[error("raw socket {iface}: {source}")]
    RawSocket {
        iface: String,
        source: std::io::Error,
    },
}
