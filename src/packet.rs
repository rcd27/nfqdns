use etherparse::PacketBuilder;

/// Минимальные заголовки из raw IPv4/UDP пакета (без Ethernet).
/// AF_PACKET SOCK_RAW с ETH_P_IP отдаёт пакет начиная с IP заголовка.
pub struct DnsPacketInfo {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub dns_payload: Vec<u8>,
}

/// Парсит IPv4/UDP пакет и извлекает DNS payload.
/// Возвращает None если пакет не IPv4/UDP или dst_port != 53.
pub fn parse_dns_query(raw: &[u8]) -> Option<DnsPacketInfo> {
    let headers = etherparse::PacketHeaders::from_ip_slice(raw).ok()?;

    let ip = match &headers.net {
        Some(etherparse::NetHeaders::Ipv4(h, _)) => h,
        _ => return None,
    };

    let udp = match &headers.transport {
        Some(etherparse::TransportHeader::Udp(h)) => h,
        _ => return None,
    };

    if udp.destination_port != 53 {
        return None;
    }

    Some(DnsPacketInfo {
        src_ip: ip.source,
        dst_ip: ip.destination,
        src_port: udp.source_port,
        dst_port: udp.destination_port,
        dns_payload: headers.payload.slice().to_vec(),
    })
}

/// Собирает spoofed DNS response пакет (IP/UDP, без Ethernet).
/// src/dst IP и порты перевёрнуты относительно оригинала.
pub fn build_spoofed_response(
    original: &DnsPacketInfo,
    dns_response: &[u8],
) -> Vec<u8> {
    let builder = PacketBuilder::ipv4(original.dst_ip, original.src_ip, 64)
        .udp(original.dst_port, original.src_port);

    let mut buf = Vec::with_capacity(builder.size(dns_response.len()));
    builder.write(&mut buf, dns_response).expect("packet build");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_udp_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let builder = PacketBuilder::ipv4(src_ip, dst_ip, 64).udp(src_port, dst_port);
        let mut buf = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut buf, payload).unwrap();
        buf
    }

    #[test]
    fn parse_dns_query_valid() {
        let pkt = make_udp_packet([192, 168, 1, 100], [8, 8, 8, 8], 54321, 53, b"dns-query");
        let info = parse_dns_query(&pkt).unwrap();
        assert_eq!(info.src_ip, [192, 168, 1, 100]);
        assert_eq!(info.dst_ip, [8, 8, 8, 8]);
        assert_eq!(info.src_port, 54321);
        assert_eq!(info.dst_port, 53);
        assert_eq!(info.dns_payload, b"dns-query");
    }

    #[test]
    fn parse_dns_query_wrong_port() {
        let pkt = make_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, b"http");
        assert!(parse_dns_query(&pkt).is_none());
    }

    #[test]
    fn spoofed_response_swaps_src_dst() {
        let original = DnsPacketInfo {
            src_ip: [192, 168, 1, 100],
            dst_ip: [8, 8, 8, 8],
            src_port: 54321,
            dst_port: 53,
            dns_payload: vec![],
        };
        let response = build_spoofed_response(&original, b"response");
        let info = etherparse::PacketHeaders::from_ip_slice(&response).unwrap();
        let ip = match &info.net {
            Some(etherparse::NetHeaders::Ipv4(h, _)) => h,
            _ => panic!("expected ipv4"),
        };
        assert_eq!(ip.source, [8, 8, 8, 8]);
        assert_eq!(ip.destination, [192, 168, 1, 100]);
    }
}
