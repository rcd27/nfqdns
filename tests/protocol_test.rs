use nfqdns::protocol::*;

#[test]
fn alive_message_v2_format() {
    let payload = state_alive("0.1.2");
    let json = serde_json::to_string(&payload).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["type"], "state");
    assert_eq!(parsed["kind"], "alive");
    assert_eq!(parsed["version"], "0.1.2");
}

#[test]
fn fatal_message_v2_format() {
    let payload = state_fatal("NFQUEUE 100 already bound");
    let json = serde_json::to_string(&payload).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["type"], "state");
    assert_eq!(parsed["kind"], "fatal");
}

#[test]
fn gauge_message_v2_with_tunneled() {
    let payload = data_gauge(4582, 15, 120, 4447);
    let json = serde_json::to_string(&payload).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["type"], "data");
    assert_eq!(parsed["kind"], "gauge");
    assert_eq!(parsed["tunneled"], 15);
    assert_eq!(parsed["whitelisted"], 120);
}

#[test]
fn signal_tunnel_action() {
    let payload = data_signal_redirect("discord.com", RedirectAction::Tunnel);
    let json = serde_json::to_string(&payload).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["type"], "data");
    assert_eq!(parsed["kind"], "signal");
    assert_eq!(parsed["signal_type"], "DOMAIN_REDIRECTED");
    assert_eq!(parsed["fields"]["domain"], "discord.com");
    assert_eq!(parsed["fields"]["action"], "tunnel");
}

#[test]
fn all_messages_have_type_field() {
    let messages: Vec<Payload> = vec![
        state_alive("0.1.2"),
        state_fatal("error"),
        state_degraded("warning"),
        data_gauge(100, 5, 5, 90),
        data_signal_redirect("example.com", RedirectAction::Tunnel),
    ];
    for payload in &messages {
        let json = serde_json::to_string(payload).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("type").is_some(), "must have 'type': {json}");
        assert!(!json.contains('\n'), "single line: {json}");
    }
}
