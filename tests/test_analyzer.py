from analyzer import compare_scans
from identity_matcher import match_hosts, score_host_pair


def test_same_ip_hostname_no_mac_port_added_links_and_reports_new_port():
    previous = [{
        "ip": "192.168.0.20",
        "hostname": "office-pc",
        "mac": "",
        "vendor": "",
        "open_ports": [80, 443],
        "role": "web-server",
    }]
    current = [{
        "ip": "192.168.0.20",
        "hostname": "office-pc",
        "mac": "",
        "vendor": "",
        "open_ports": [80, 443, 8080],
        "role": "web-server, alternative web service",
    }]

    scored = score_host_pair(previous[0], current[0])
    assert scored["decision"] in {"probable-link", "auto-link"}

    events = compare_scans(previous, current)
    assert {e["event_type"] for e in events} >= {"NEW_PORT_OPENED", "ROLE_CHANGED"}
    assert any(e["event_type"] == "NEW_PORT_OPENED" and e["new_value"] == "8080" for e in events)
    assert "HOST_AMBIGUOUS_MATCH" not in {e["event_type"] for e in events}


def test_global_mac_ip_changed_links_and_reports_port_diffs():
    previous = [{
        "ip": "192.168.0.20",
        "hostname": "old-name",
        "mac": "00:11:22:33:44:55",
        "vendor": "Test Vendor",
        "open_ports": [80],
        "role": "web-server",
    }]
    current = [{
        "ip": "192.168.0.45",
        "hostname": "new-name",
        "mac": "00:11:22:33:44:55",
        "vendor": "Test Vendor",
        "open_ports": [22, 443],
        "role": "SSH access, web-server",
    }]

    scored = score_host_pair(previous[0], current[0])
    assert scored["decision"] in {"probable-link", "auto-link"}

    events = compare_scans(previous, current)
    event_types = [e["event_type"] for e in events]
    assert "HOST_IP_CHANGED" in event_types
    assert any(e["event_type"] == "NEW_PORT_OPENED" and e["new_value"] == "22" for e in events)
    assert any(e["event_type"] == "NEW_PORT_OPENED" and e["new_value"] == "443" for e in events)
    assert any(e["event_type"] == "PORT_CLOSED" and e["old_value"] == "80" for e in events)


def test_same_ip_different_global_macs_is_not_auto_or_probable_link():
    previous = [{
        "ip": "192.168.0.20",
        "hostname": "device-a",
        "mac": "00:11:22:33:44:55",
        "open_ports": [80],
        "role": "web-server",
    }]
    current = [{
        "ip": "192.168.0.20",
        "hostname": "device-b",
        "mac": "00:AA:BB:CC:DD:EE",
        "open_ports": [80],
        "role": "web-server",
    }]

    scored = score_host_pair(previous[0], current[0])
    assert scored["decision"] in {"ambiguous", "no-link"}
    assert scored["decision"] not in {"auto-link", "probable-link"}


def test_only_best_ambiguous_candidate_is_reserved():
    previous = [
        {"ip": f"192.168.0.{idx}", "hostname": "shared", "mac": "02:11:22:33:44:55", "vendor": "", "open_ports": [80], "role": "web-server"}
        for idx in (10, 11, 12)
    ]
    current = [
        {"ip": "192.168.0.50", "hostname": "shared", "mac": "02:11:22:33:44:55", "vendor": "", "open_ports": [80], "role": "web-server"}
    ]

    result = match_hosts(previous, current)
    assert len(result["links"]) == 0
    assert len(result["ambiguous"]) == 1
    assert len(result["unmatched_previous"]) == 2
