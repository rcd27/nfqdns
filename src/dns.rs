use std::net::Ipv4Addr;

use simple_dns::{
    CLASS, Packet, PacketFlag, Question, ResourceRecord,
    rdata::{A, RData},
};

/// Parse a DNS query payload and return the queried domain name.
/// Returns None if the payload is not a valid DNS query with at least one question.
pub fn extract_domain(payload: &[u8]) -> Option<String> {
    let packet = Packet::parse(payload).ok()?;

    if packet.has_flags(PacketFlag::RESPONSE) {
        return None;
    }

    let question = packet.questions.first()?;
    Some(question.qname.to_string())
}

/// Craft a DNS response for the given query payload, with an A record pointing to redirect_ip.
/// Returns None if the payload cannot be parsed or is not a valid query.
pub fn craft_response(query_payload: &[u8], redirect_ip: Ipv4Addr) -> Option<Vec<u8>> {
    let query = Packet::parse(query_payload).ok()?;

    if query.has_flags(PacketFlag::RESPONSE) {
        return None;
    }

    let question = query.questions.first()?;

    let mut response = Packet::new_reply(query.id());

    let q = Question::new(
        question.qname.clone().into_owned(),
        question.qtype,
        question.qclass,
        false,
    );
    response.questions.push(q);

    let answer = ResourceRecord::new(
        question.qname.clone().into_owned(),
        CLASS::IN,
        60,
        RData::A(A::from(redirect_ip)),
    );
    response.answers.push(answer);

    response.build_bytes_vec_compressed().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_dns::{Name, TYPE};

    fn make_query(domain: &str) -> Vec<u8> {
        let mut packet = Packet::new_query(1234);
        let question = Question::new(
            Name::new_unchecked(domain),
            TYPE::A.into(),
            CLASS::IN.into(),
            false,
        );
        packet.questions.push(question);
        packet.build_bytes_vec_compressed().unwrap()
    }

    fn make_response(domain: &str) -> Vec<u8> {
        let mut packet = Packet::new_reply(5678);
        let question = Question::new(
            Name::new_unchecked(domain),
            TYPE::A.into(),
            CLASS::IN.into(),
            false,
        );
        packet.questions.push(question);
        packet.build_bytes_vec_compressed().unwrap()
    }

    #[test]
    fn extract_domain_from_query() {
        let query = make_query("instagram.com");
        let domain = extract_domain(&query).unwrap();
        assert_eq!(domain, "instagram.com");
    }

    #[test]
    fn extract_domain_from_response_returns_none() {
        let response = make_response("instagram.com");
        let result = extract_domain(&response);
        assert!(result.is_none());
    }

    #[test]
    fn extract_domain_invalid_payload_returns_none() {
        let result = extract_domain(b"\x00\x01\x02garbage");
        assert!(result.is_none());
    }

    #[test]
    fn craft_response_contains_correct_ip() {
        let query = make_query("twitter.com");
        let redirect_ip = Ipv4Addr::new(10, 0, 0, 1);
        let response_bytes = craft_response(&query, redirect_ip).unwrap();

        let parsed = Packet::parse(&response_bytes).unwrap();
        assert!(parsed.has_flags(PacketFlag::RESPONSE));
        assert_eq!(parsed.answers.len(), 1);

        match &parsed.answers[0].rdata {
            RData::A(a) => {
                let ip: Ipv4Addr = Ipv4Addr::from(a.address);
                assert_eq!(ip, redirect_ip);
            }
            other => panic!("unexpected rdata: {:?}", other),
        }
    }

    #[test]
    fn craft_response_from_response_returns_none() {
        let response = make_response("facebook.com");
        let result = craft_response(&response, Ipv4Addr::new(1, 2, 3, 4));
        assert!(result.is_none());
    }
}
