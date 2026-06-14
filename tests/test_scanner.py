import pytest

import scanner


def test_scan_network_accepts_24_and_reports_progress(monkeypatch):
    calls = []
    def fake_scan(ip, ports, discovery_mode, timeout):
        calls.append(ip)
        return None
    monkeypatch.setattr(scanner, "_scan_single_host", fake_scan)

    progress = []
    result = scanner.scan_network("192.168.1.0/24", progress_cb=lambda c, t, h: progress.append((c, t, h)), max_workers=4)

    assert result == []
    assert len(calls) == 254
    assert progress[-1][:2] == (254, 254)


def test_scan_network_accepts_32(monkeypatch):
    monkeypatch.setattr(scanner, "_scan_single_host", lambda ip, ports, mode, timeout: {"ip": ip, "open_ports": [], "role": "—"})
    result = scanner.scan_network("192.168.1.5/32", max_workers=1)
    assert [host["ip"] for host in result] == ["192.168.1.5"]


def test_scan_network_rejects_oversized_before_scanning(monkeypatch):
    called = False
    def fake_scan(*args, **kwargs):
        nonlocal called
        called = True
    monkeypatch.setattr(scanner, "_scan_single_host", fake_scan)

    with pytest.raises(ValueError, match="too many addresses"):
        scanner.scan_network("10.0.0.0/8")
    assert called is False


def test_scan_network_rejects_ipv6_and_invalid_cidr():
    with pytest.raises(ValueError, match="IPv4"):
        scanner.scan_network("2001:db8::/120")
    with pytest.raises(ValueError, match="Invalid CIDR"):
        scanner.scan_network("not-a-cidr")


def test_discovery_modes(monkeypatch):
    monkeypatch.setattr(scanner, "resolve_hostname", lambda ip: "")
    monkeypatch.setattr(scanner, "get_mac_address", lambda ip: "")
    monkeypatch.setattr(scanner, "get_vendor_from_mac", lambda mac: "")

    monkeypatch.setattr(scanner, "ping_host", lambda ip, timeout_sec=0.3: True)
    monkeypatch.setattr(scanner, "scan_ports", lambda ip, ports=None, timeout=0.3: [])
    assert scanner._scan_single_host("127.0.0.1", [80], "icmp", 0.01) is not None

    monkeypatch.setattr(scanner, "ping_host", lambda ip, timeout_sec=0.3: False)
    monkeypatch.setattr(scanner, "scan_ports", lambda ip, ports=None, timeout=0.3: [80])
    assert scanner._scan_single_host("127.0.0.1", [80], "tcp", 0.01) is not None
    assert scanner._scan_single_host("127.0.0.1", [80], "mixed", 0.01) is not None

    monkeypatch.setattr(scanner, "scan_ports", lambda ip, ports=None, timeout=0.3: [])
    assert scanner._scan_single_host("127.0.0.1", [80], "mixed", 0.01) is None


def test_scan_network_sorts_hosts_and_skips_one_host_exception(monkeypatch):
    def fake_scan(ip, ports, discovery_mode, timeout):
        if ip.endswith(".2"):
            raise RuntimeError("boom")
        if ip.endswith(".1") or ip.endswith(".3"):
            return {"ip": ip, "open_ports": [], "role": "—"}
        return None
    monkeypatch.setattr(scanner, "_scan_single_host", fake_scan)

    progress = []
    result = scanner.scan_network("192.168.1.0/30", progress_cb=lambda c, t, h: progress.append((c, t, h)), max_workers=2)
    assert [host["ip"] for host in result] == ["192.168.1.1"]
    assert len(progress) == 2
