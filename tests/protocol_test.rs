use nfqdns::protocol::{
    data_gauge, data_signal_redirect, state_alive, state_degraded, state_fatal,
};

// --- State messages ---

#[test]
fn alive_message_is_valid_json_with_state_field() {
    let json = state_alive("0.1.2");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["state"], "alive");
    assert_eq!(parsed["version"], "0.1.2");
}

#[test]
fn fatal_message_is_valid_json_with_state_field() {
    let json = state_fatal("NFQUEUE 100 already bound");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["state"], "fatal");
    assert_eq!(parsed["reason"], "NFQUEUE 100 already bound");
}

#[test]
fn degraded_message_is_valid_json_with_state_field() {
    let json = state_degraded("redirect list empty");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["state"], "degraded");
    assert_eq!(parsed["reason"], "redirect list empty");
}

// --- Data messages ---

#[test]
fn gauge_message_has_data_field() {
    let json = data_gauge(4582, 342, 120, 4120);
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["data"], "gauge");
    assert_eq!(parsed["total"], 4582);
    assert_eq!(parsed["redirected"], 342);
    assert_eq!(parsed["bypassed"], 120);
    assert_eq!(parsed["passed"], 4120);
}

#[test]
fn signal_redirect_has_data_field() {
    let json = data_signal_redirect("instagram.com", "192.168.1.50");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["data"], "signal");
    assert_eq!(parsed["name"], "DOMAIN_REDIRECTED");
    assert_eq!(parsed["domain"], "instagram.com");
    assert_eq!(parsed["redirect_ip"], "192.168.1.50");
}

// --- Protocol invariants ---

#[test]
fn all_messages_are_single_line() {
    let messages = vec![
        state_alive("0.1.2"),
        state_fatal("bind failed"),
        state_degraded("empty list"),
        data_gauge(100, 10, 5, 85),
        data_signal_redirect("example.com", "192.168.1.50"),
    ];

    for msg in messages {
        assert!(!msg.contains('\n'), "JSON Lines must be single-line: {}", msg);
    }
}

#[test]
fn all_messages_have_exactly_one_discriminator() {
    let messages = vec![
        state_alive("0.1.2"),
        state_fatal("bind failed"),
        state_degraded("empty list"),
        data_gauge(100, 10, 5, 85),
        data_signal_redirect("example.com", "192.168.1.50"),
    ];

    for msg in &messages {
        let parsed: serde_json::Value = serde_json::from_str(msg).unwrap();
        let obj = parsed.as_object().unwrap();
        let has_state = obj.contains_key("state");
        let has_data = obj.contains_key("data");

        assert!(
            has_state ^ has_data,
            "must have exactly one of 'state' or 'data': {}",
            msg
        );
    }
}
