# nfqdns

DNS interceptor for Linux L2 bridge via NFQUEUE.

Intercepts DNS queries passing through a transparent bridge, checks domain names against configurable lists, and
responds with a specified redirect IP for matched domains. Unmatched queries pass through the bridge unmodified.

## Use Cases

- Traffic steering on transparent bridge (redirect specific domains to a specified IP)
- DNS-based ad blocking on L2 bridge
- Parental control without router access
- IoT device DNS filtering

## How It Works

```
Client → DNS query → bridge (br0) → NFQUEUE → nfqdns
                                                  │
                              ┌───────────────────┼──────────────┐
                              │                   │              │
                         In redirect list?   In bypass list?  Unknown
                              │                   │              │
                         Spoof response      NF_ACCEPT        NF_ACCEPT
                         (redirect IP)       (pass through)   (pass through)
                              │
                         Client receives
                         redirect IP
```

nfqdns intercepts DNS query packets from NFQUEUE, parses the queried domain name, and makes a decision:

- **Redirect list match**: craft a spoofed DNS response with the redirect IP, swap src/dst in the IP/UDP headers,
  recalculate checksums, and inject the response back through the bridge. The original query is dropped.
- **Exclude list match**: accept the packet unchanged (pass through the bridge).
- **No match**: accept the packet unchanged (pass through the bridge).

Suffix matching is used: `example.com` in the list will match `cdn.example.com`, `sub.example.com`, etc.

## Requirements

- Linux kernel with `kmod-nfnetlink-queue` and `kmod-nft-queue`
- `kmod-br-netfilter` (for bridge NFQUEUE support)
- `sysctl net.bridge.bridge-nf-call-iptables=1`
- nftables rule to send DNS to NFQUEUE:

```
table inet nfqdns {
    chain forward {
        type filter hook forward priority -10;
        udp dport 53 queue num 100
    }
}
```

## Usage

```bash
nfqdns \
  --redirect-ip 192.168.1.50 \
  --redirect-list /etc/nfqdns/redirect.txt \
  [--bypass-list /etc/nfqdns/bypass.txt] \
  [--queue-num 100] \
  [--stats-interval 60]
```

### Arguments

| Argument           | Required | Default | Description                                      |
|--------------------|----------|---------|--------------------------------------------------|
| `--redirect-ip`    | yes      | -       | IPv4 address to use in spoofed DNS responses     |
| `--redirect-list`  | yes      | -       | Path to file with domains to redirect            |
| `--bypass-list`   | no       | -       | Path to file with domains to always pass through |
| `--queue-num`      | no       | 100     | NFQUEUE number to bind to                        |
| `--stats-interval` | no       | 60      | Seconds between stats output (0 to disable)      |

## List Format

One domain per line. Comments (`#`) and empty lines are ignored. Suffix matching is applied automatically.

```
# Domains to redirect
example.com
another-domain.org
```

## Building

```bash
# Native build
cargo build --release

# Cross-compile for aarch64 (OpenWrt)
cargo build --target aarch64-unknown-linux-musl --release
```

## License

MIT
