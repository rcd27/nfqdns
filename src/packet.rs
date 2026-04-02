use etherparse::{NetSlice, PacketBuilder, SlicedPacket, TransportSlice};

/// Take an original IPv4/UDP packet, swap src/dst IP and ports,
/// replace UDP payload with dns_response_payload, recalculate checksums.
/// Returns None if the packet is not a valid IPv4/UDP packet.
pub fn build_spoofed_packet(
    original_packet: &[u8],
    dns_response_payload: &[u8],
) -> Option<Vec<u8>> {
    let sliced = SlicedPacket::from_ip(original_packet).ok()?;

    let ip_slice = match &sliced.net {
        Some(NetSlice::Ipv4(s)) => s,
        _ => return None,
    };

    let udp_slice = match &sliced.transport {
        Some(TransportSlice::Udp(s)) => s,
        _ => return None,
    };

    let orig_ip = ip_slice.header().to_header();
    let orig_udp = udp_slice.to_header();

    let src_ip = orig_ip.destination;
    let dst_ip = orig_ip.source;
    let src_port = orig_udp.destination_port;
    let dst_port = orig_udp.source_port;

    let builder = PacketBuilder::ipv4(src_ip, dst_ip, orig_ip.time_to_live).udp(src_port, dst_port);

    let mut result = Vec::with_capacity(builder.size(dns_response_payload.len()));
    builder.write(&mut result, dns_response_payload).ok()?;

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::{NetSlice, PacketBuilder, SlicedPacket, TransportSlice};

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
    fn src_dst_ip_and_ports_are_swapped() {
        let original = make_udp_packet([192, 168, 1, 100], [8, 8, 8, 8], 54321, 53, b"query");
        let response_payload = b"response";
        let spoofed = build_spoofed_packet(&original, response_payload).unwrap();

        let sliced = SlicedPacket::from_ip(&spoofed).unwrap();
        let ip = match &sliced.net {
            Some(NetSlice::Ipv4(s)) => s.header().to_header(),
            _ => panic!("expected ipv4"),
        };
        let udp = match &sliced.transport {
            Some(TransportSlice::Udp(s)) => s.to_header(),
            _ => panic!("expected udp"),
        };

        assert_eq!(ip.source, [8, 8, 8, 8]);
        assert_eq!(ip.destination, [192, 168, 1, 100]);
        assert_eq!(udp.source_port, 53);
        assert_eq!(udp.destination_port, 54321);
    }

    #[test]
    fn payload_is_replaced() {
        let original = make_udp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            12345,
            53,
            b"original_dns_query_data",
        );
        let new_payload = b"new_dns_response_data";
        let spoofed = build_spoofed_packet(&original, new_payload).unwrap();

        let sliced = SlicedPacket::from_ip(&spoofed).unwrap();
        let udp_payload = match &sliced.transport {
            Some(TransportSlice::Udp(s)) => s.payload().to_vec(),
            _ => panic!("expected udp"),
        };

        assert_eq!(udp_payload, new_payload);
    }

    #[test]
    fn invalid_packet_returns_none() {
        let result = build_spoofed_packet(b"\x00\x01\x02garbage_data", b"response");
        assert!(result.is_none());
    }
}
