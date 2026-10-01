// SPDX-License-Identifier: GPL-3.0-or-later

//! Pins the wire format to the examples in docs/ipc-protocol.md. If one of
//! these breaks, the specification and every client break with it.

use omarchy_security_proto::events::AlertResolved;
use omarchy_security_proto::methods::{KillProcessParams, NoParams, UsbSetPolicyParams};
use omarchy_security_proto::rpc::Outcome;
use omarchy_security_proto::types::*;
use omarchy_security_proto::*;
use serde_json::{Value, json};

fn parse_ok(frame: Value) -> Request {
    parse_request(frame.to_string().as_bytes()).expect("request parses")
}

fn parse_err(frame: &str) -> Response {
    parse_request(frame.as_bytes()).expect_err("request is rejected")
}

fn error_code(response: &Response) -> ErrorCode {
    match &response.outcome {
        Outcome::Error(e) => e.kind().expect("known error code"),
        Outcome::Result(r) => panic!("expected error, got result {r}"),
    }
}

#[test]
fn usbguard_set_policy_request_matches_spec() {
    let request = parse_ok(json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "USBGUARD_SET_POLICY",
        "params": { "device_id": 14, "target": "allow", "permanent": true }
    }));
    assert_eq!(request.id, Id::Number(7));
    assert_eq!(
        request.call,
        Call::UsbguardSetPolicy(UsbSetPolicyParams {
            device_id: 14,
            target: UsbTarget::Allow,
            permanent: true,
        })
    );
}

#[test]
fn usb_device_presented_event_matches_spec() {
    let event = Event::UsbDevicePresented(UsbDevice {
        device_id: 14,
        name: "Mass Storage Device".into(),
        vendor_id: "0951".into(),
        product_id: "1666".into(),
        serial: "00187D0F2E3B".into(),
        rule: UsbTarget::Block,
        interface_class: "08".into(),
        interfaces: vec![],
    });
    assert_eq!(event.topic(), types::Topic::Usbguard);
    let wire = serde_json::to_value(Notification::from(event.clone())).unwrap();
    assert_eq!(
        wire,
        json!({
            "jsonrpc": "2.0",
            "method": "USB_DEVICE_PRESENTED",
            "params": {
                "device_id": 14,
                "name": "Mass Storage Device",
                "vendor_id": "0951",
                "product_id": "1666",
                "serial": "00187D0F2E3B",
                "rule": "block",
                "interface_class": "08"
            }
        })
    );
    let back: Notification = serde_json::from_value(wire).unwrap();
    assert_eq!(back.event, event);
}

#[test]
fn params_may_be_omitted_null_or_empty_for_no_param_methods() {
    for params in [None, Some(Value::Null), Some(json!({}))] {
        let mut frame = json!({ "jsonrpc": "2.0", "id": 1, "method": "PING" });
        if let Some(p) = params {
            frame["params"] = p;
        }
        assert_eq!(parse_ok(frame).call, Call::Ping(NoParams {}));
    }
}

#[test]
fn request_round_trips_through_serialize() {
    let request = Request {
        id: Id::String("a".into()),
        call: Call::ThreatKillProcess(KillProcessParams {
            alert_id: 3,
            pid: 4242,
            signal: KillSignal::Kill,
        }),
    };
    let frame = encode_frame(&request).unwrap();
    assert!(frame.ends_with('\n'));
    assert_eq!(frame.matches('\n').count(), 1);
    let wire: Value = serde_json::from_str(&frame).unwrap();
    assert_eq!(wire["params"]["signal"], json!(9));
    assert_eq!(parse_request(frame.trim_end().as_bytes()).unwrap(), request);
}

#[test]
fn every_method_name_is_unique_and_dispatchable() {
    let mut seen = std::collections::HashSet::new();
    for method in Call::METHODS {
        assert!(seen.insert(method), "duplicate method {method}");
        let response = parse_err(
            &json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": [] }).to_string(),
        );
        // Known method, wrong params type → INVALID_PARAMS, not METHOD_NOT_FOUND.
        assert_eq!(error_code(&response), ErrorCode::InvalidParams, "{method}");
    }
}

#[test]
fn unknown_method_is_method_not_found() {
    let response = parse_err(r#"{"jsonrpc":"2.0","id":5,"method":"FORMAT_DISK"}"#);
    assert_eq!(response.id, Some(Id::Number(5)));
    assert_eq!(error_code(&response), ErrorCode::MethodNotFound);
}

#[test]
fn disallowed_signal_is_invalid_params() {
    let response = parse_err(
        r#"{"jsonrpc":"2.0","id":2,"method":"THREAT_KILL_PROCESS","params":{"alert_id":1,"pid":10,"signal":19}}"#,
    );
    assert_eq!(error_code(&response), ErrorCode::InvalidParams);
}

#[test]
fn unknown_param_field_is_invalid_params() {
    let response = parse_err(
        r#"{"jsonrpc":"2.0","id":2,"method":"USBGUARD_SET_POLICY","params":{"device_id":1,"target":"allow","permanant":true}}"#,
    );
    assert_eq!(error_code(&response), ErrorCode::InvalidParams);
}

#[test]
fn malformed_frames_are_rejected_with_the_right_code() {
    let cases = [
        ("{not json", ErrorCode::ParseError, None),
        (
            r#"[{"jsonrpc":"2.0","id":1,"method":"PING"}]"#,
            ErrorCode::InvalidRequest,
            None,
        ),
        (
            r#"{"jsonrpc":"1.0","id":3,"method":"PING"}"#,
            ErrorCode::InvalidRequest,
            Some(Id::Number(3)),
        ),
        (
            r#"{"jsonrpc":"2.0","method":"PING"}"#,
            ErrorCode::InvalidRequest,
            None,
        ),
        (
            r#"{"jsonrpc":"2.0","id":4}"#,
            ErrorCode::InvalidRequest,
            Some(Id::Number(4)),
        ),
    ];
    for (frame, code, id) in cases {
        let response = parse_err(frame);
        assert_eq!(error_code(&response), code, "{frame}");
        assert_eq!(response.id, id, "{frame}");
    }
}

#[test]
fn responses_serialize_as_result_or_error() {
    let ok = Response::result(Id::Number(1), &json!({}));
    assert_eq!(
        serde_json::to_value(&ok).unwrap(),
        json!({ "jsonrpc": "2.0", "id": 1, "result": {} })
    );

    let err = Response::error(
        None,
        RpcError::new(ErrorCode::HandshakeRequired, "send HELLO first"),
    );
    assert_eq!(
        serde_json::to_value(&err).unwrap(),
        json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32000, "message": "send HELLO first" } })
    );
    let back: Response = serde_json::from_value(serde_json::to_value(&err).unwrap()).unwrap();
    assert_eq!(back, err);
}

#[test]
fn every_event_maps_to_a_topic() {
    let event = Event::ThreatAlertResolved(AlertResolved {
        alert_id: 1,
        state: AlertState::Killed,
    });
    assert_eq!(event.topic(), Topic::Threat);
    let wire = serde_json::to_value(Notification::from(event)).unwrap();
    assert_eq!(wire["method"], json!("THREAT_ALERT_RESOLVED"));
    assert_eq!(wire["params"]["state"], json!("killed"));
}

#[test]
fn file_drops_are_threat_events() {
    let event = Event::ThreatFileDropped(FileDrop {
        path: "/tmp/x".into(),
        uid: 1000,
        size: 42,
        detected_at: 7,
    });
    assert_eq!(event.topic(), Topic::Threat);
    let wire = serde_json::to_value(Notification::from(event)).unwrap();
    assert_eq!(
        wire,
        json!({ "jsonrpc": "2.0", "method": "THREAT_FILE_DROPPED", "params": { "path": "/tmp/x", "uid": 1000, "size": 42, "detected_at": 7 } })
    );

    // `dropped_at` is left out when unknown, and optional when parsing.
    let alert = json!({ "alert_id": 1, "pid": 2, "ppid": 1, "uid": 1000, "start_time": 5, "binary_path": "/tmp/x", "argv": [], "origin": "tmp", "detected_at": 9, "state": "open" });
    let parsed: ThreatAlert = serde_json::from_value(alert.clone()).unwrap();
    assert_eq!(parsed.dropped_at, None);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), alert);
}

#[test]
fn firewall_mode_matches_spec() {
    assert_eq!(
        parse_ok(json!({"jsonrpc": "2.0", "id": 1, "method": "FIREWALL_GET_MODE"})).call,
        Call::FirewallGetMode(NoParams {})
    );
    let mode = FirewallMode {
        mode: FirewallModeKind::Ufw,
        ufw: UfwState {
            installed: true,
            enabled_in_conf: true,
            chains_loaded: Some(true),
            default_input: Some("drop".into()),
            default_output: Some("accept".into()),
            default_forward: None,
            logging: Some("low".into()),
            before_rules_modified: Some(false),
        },
        table_loaded: Some(true),
        docker_protection: DockerProtection::UfwDocker,
        detail: None,
    };
    let event = Event::FirewallModeChanged(mode.clone());
    assert_eq!(event.topic(), Topic::Firewall);
    let wire = serde_json::to_value(Notification::from(event)).unwrap();
    assert_eq!(
        wire,
        json!({ "jsonrpc": "2.0", "method": "FIREWALL_MODE_CHANGED", "params": {
            "mode": "ufw",
            "ufw": { "installed": true, "enabled_in_conf": true, "chains_loaded": true,
                     "default_input": "drop", "default_output": "accept", "logging": "low",
                     "before_rules_modified": false },
            "table_loaded": true,
            "docker_protection": "ufw-docker"
        } })
    );

    // Without the helper only the unprivileged fields are present.
    let unknown = json!({ "mode": "unknown", "ufw": { "installed": true, "enabled_in_conf": false },
                          "docker_protection": "none", "detail": "helper down" });
    let parsed: FirewallMode = serde_json::from_value(unknown.clone()).unwrap();
    assert_eq!(parsed.mode, FirewallModeKind::Unknown);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), unknown);
}

#[test]
fn set_mode_matches_spec() {
    use omarchy_security_proto::helper::HubMode;
    assert_eq!(
        parse_ok(
            json!({"jsonrpc": "2.0", "id": 1, "method": "FIREWALL_SET_MODE",
                        "params": {"mode": "standalone", "import_ufw_rules": true}})
        )
        .call,
        Call::FirewallSetMode(methods::FirewallSetModeParams {
            mode: HubMode::Standalone,
            import_ufw_rules: Some(true),
            dry_run: false,
        })
    );
    assert_eq!(
        parse_ok(
            json!({"jsonrpc": "2.0", "id": 1, "method": "FIREWALL_SET_MODE",
                        "params": {"mode": "standalone", "dry_run": true}})
        )
        .call,
        Call::FirewallSetMode(methods::FirewallSetModeParams {
            mode: HubMode::Standalone,
            import_ufw_rules: None,
            dry_run: true,
        })
    );
    assert_eq!(
        parse_ok(
            json!({"jsonrpc": "2.0", "id": 1, "method": "FIREWALL_SET_MODE",
                        "params": {"mode": "ufw"}})
        )
        .call,
        Call::FirewallSetMode(methods::FirewallSetModeParams {
            mode: HubMode::Ufw,
            import_ufw_rules: None,
            dry_run: false,
        })
    );
    // Only the two modes the hub chooses.
    for mode in ["both", "none", "unknown"] {
        let response = parse_err(
            &json!({"jsonrpc": "2.0", "id": 1, "method": "FIREWALL_SET_MODE",
                    "params": {"mode": mode}})
            .to_string(),
        );
        assert_eq!(error_code(&response), ErrorCode::InvalidParams, "{mode}");
    }
}

#[test]
fn ufw_rules_match_spec() {
    let rule = json!({ "action": "allow", "direction": "in", "protocol": "udp", "port": "53",
                       "src": "172.16.0.0/12", "dst": "172.17.0.1",
                       "comment": "allow-docker-dns", "ipv6": false });
    let parsed: UfwRule = serde_json::from_value(rule.clone()).unwrap();
    assert_eq!(
        (parsed.action, parsed.direction),
        (UfwAction::Allow, UfwDirection::In)
    );
    assert_eq!(serde_json::to_value(&parsed).unwrap(), rule);
    let list = methods::UfwRuleList {
        rules: vec![parsed],
        builtin: vec!["Loopback traffic is allowed".into()],
        source: "user.rules".into(),
    };
    assert_eq!(
        serde_json::to_value(&list).unwrap(),
        json!({ "rules": [rule], "builtin": ["Loopback traffic is allowed"], "source": "user.rules" })
    );
}

#[test]
fn error_codes_round_trip() {
    for code in ErrorCode::ALL {
        assert_eq!(ErrorCode::from_code(code.code()), Some(code));
    }
}

#[test]
fn check_status_orders_from_best_to_worst() {
    let worst = [CheckStatus::Pass, CheckStatus::Fail, CheckStatus::Warn]
        .into_iter()
        .max();
    assert_eq!(worst, Some(CheckStatus::Fail));
}

#[test]
fn socket_path_lives_in_the_runtime_dir() {
    assert_eq!(
        socket_path_in(std::path::Path::new("/run/user/1000")),
        std::path::PathBuf::from("/run/user/1000/omarchy-security/securityd.sock")
    );
}

#[test]
fn firewall_alerts_match_spec() {
    assert_eq!(
        parse_ok(
            json!({"jsonrpc": "2.0", "id": 1, "method": "FIREWALL_ALERT_LIST",
                        "params": {"limit": 20}})
        )
        .call,
        Call::FirewallAlertList(methods::FirewallAlertListParams { limit: Some(20) })
    );
    assert_eq!(
        parse_ok(json!({"jsonrpc": "2.0", "id": 1, "method": "FIREWALL_ALERT_LIST"})).call,
        Call::FirewallAlertList(Default::default())
    );
    assert_eq!(
        parse_ok(
            json!({"jsonrpc": "2.0", "id": 1, "method": "FIREWALL_ALERT_MUTE",
                        "params": {"alert_id": 3, "duration_secs": 28800}})
        )
        .call,
        Call::FirewallAlertMute(methods::FirewallAlertMuteParams {
            alert_id: 3,
            duration_secs: 28800
        })
    );
    let event = Event::FirewallAlert(FirewallAlert {
        alert_id: 3,
        source: AlertSource::Ufw,
        direction: AlertDirection::Inbound,
        protocol: "tcp".into(),
        src: "192.168.1.23".into(),
        dst: "192.168.1.10".into(),
        dst_port: Some(22),
        iface: "wlan0".into(),
        count: 2,
        first_seen: 1000,
        last_seen: 2000,
        muted_until: None,
    });
    assert_eq!(event.topic(), Topic::Firewall);
    assert_eq!(
        serde_json::to_value(Notification::from(event)).unwrap(),
        json!({ "jsonrpc": "2.0", "method": "FIREWALL_ALERT", "params": {
            "alert_id": 3, "source": "ufw", "direction": "inbound", "protocol": "tcp",
            "src": "192.168.1.23", "dst": "192.168.1.10", "dst_port": 22, "iface": "wlan0",
            "count": 2, "first_seen": 1000, "last_seen": 2000
        } })
    );
}

#[test]
fn temporary_decisions_match_spec() {
    let spec = json!({"verdict": "allow", "direction": "inbound", "address": "192.168.1.23",
                      "port": 22, "protocol": "tcp"});
    let request = parse_ok(
        json!({"jsonrpc": "2.0", "id": 1, "method": "FIREWALL_TEMP_ADD",
        "params": {"spec": spec, "duration_secs": 3600, "alert_id": 3}}),
    );
    let Call::FirewallTempAdd(params) = request.call else {
        panic!("{:?}", request.call)
    };
    assert_eq!((params.duration_secs, params.alert_id), (3600, Some(3)));
    assert_eq!(params.spec.verdict, Verdict::Allow);
    // The verdict lives in the spec; a separate one is an unknown field.
    let response = parse_err(
        &json!({"jsonrpc": "2.0", "id": 1, "method": "FIREWALL_TEMP_ADD",
                "params": {"spec": spec, "verdict": "allow", "duration_secs": 3600}})
        .to_string(),
    );
    assert_eq!(error_code(&response), ErrorCode::InvalidParams);
    assert_eq!(
        parse_ok(
            json!({"jsonrpc": "2.0", "id": 1, "method": "FIREWALL_TEMP_REMOVE",
                        "params": {"temp_id": 9}})
        )
        .call,
        Call::FirewallTempRemove(methods::TempTarget { temp_id: 9 })
    );

    let decision = TempDecision {
        temp_id: 9,
        spec: params.spec,
        backend: TempBackend::Ufw,
        created_at: 1000,
        expires_at: 3_601_000,
        alert_id: Some(3),
    };
    // The list also says which durations to offer; the event does not.
    let list = TempDecisionList {
        decisions: vec![decision.clone()],
        durations_secs: vec![300, 3600],
    };
    assert_eq!(
        serde_json::to_value(&list).unwrap()["durations_secs"],
        json!([300, 3600])
    );
    let event = Event::FirewallTempChanged(TempDecisionList {
        decisions: vec![decision],
        durations_secs: vec![],
    });
    assert_eq!(event.topic(), Topic::Firewall);
    assert_eq!(
        serde_json::to_value(Notification::from(event)).unwrap(),
        json!({ "jsonrpc": "2.0", "method": "FIREWALL_TEMP_CHANGED", "params": { "decisions": [{
            "temp_id": 9, "spec": spec, "backend": "ufw", "created_at": 1000,
            "expires_at": 3_601_000, "alert_id": 3
        }] } })
    );

    // A hub-added ufw rule says so.
    let rule = json!({ "action": "allow", "direction": "in", "protocol": "tcp", "port": "22",
                       "src": "192.168.1.23", "dst": "any",
                       "comment": "omarchy-security:tmp:9:1:3601", "ipv6": false,
                       "temp_id": 9, "expires_at": 3_601_000 });
    let parsed: UfwRule = serde_json::from_value(rule.clone()).unwrap();
    assert_eq!(parsed.temp_id, Some(9));
    assert_eq!(serde_json::to_value(&parsed).unwrap(), rule);
}

#[test]
fn vault_add_and_remove_match_spec() {
    let request = parse_ok(json!({
        "jsonrpc": "2.0", "id": 3, "method": "VAULT_ADD",
        "params": { "vault_id": "work", "name": "Work", "backend": "gocryptfs",
                    "source": "~/Vaults/work.enc", "mount_point": "~/Vaults/work" }
    }));
    assert_eq!(
        request.call,
        Call::VaultAdd(methods::VaultAddParams {
            vault_id: "work".into(),
            name: "Work".into(),
            backend: VaultBackend::Gocryptfs,
            source: "~/Vaults/work.enc".into(),
            mount_point: Some("~/Vaults/work".into()),
        })
    );
    // `mount_point` may be left out (a LUKS vault).
    let request = parse_ok(json!({
        "jsonrpc": "2.0", "id": 4, "method": "VAULT_ADD",
        "params": { "vault_id": "disk", "name": "Disk", "backend": "luks", "source": "/dev/sdb1" }
    }));
    assert!(matches!(request.call, Call::VaultAdd(p) if p.mount_point.is_none()));

    let event = Event::VaultRemoved(events::VaultRef {
        vault_id: "work".into(),
    });
    assert_eq!(event.topic(), Topic::Vault);
    let wire = serde_json::to_value(Notification::from(event)).unwrap();
    assert_eq!(
        wire,
        json!({ "jsonrpc": "2.0", "method": "VAULT_REMOVED", "params": { "vault_id": "work" } })
    );
}
