from datetime import datetime, timedelta
import sqlite3

import storage


def use_temp_db(monkeypatch, tmp_path):
    db_path = tmp_path / "scanner-test.db"
    monkeypatch.setattr(storage, "DB_PATH", db_path)
    return db_path


def test_stable_device_identity_same_mac_changed_ip(monkeypatch, tmp_path):
    db_path = use_temp_db(monkeypatch, tmp_path)
    storage.init_db()
    t1 = datetime(2026, 1, 1, 10, 0, 0)
    t2 = t1 + timedelta(minutes=5)

    storage.save_scan("192.168.0.0/24", t1, t1, [{
        "ip": "192.168.0.20", "mac": "00:11:22:33:44:55", "hostname": "office-pc",
        "vendor": "Test Vendor", "open_ports": [80], "role": "web-server",
    }])
    storage.save_scan("192.168.0.0/24", t2, t2, [{
        "ip": "192.168.0.45", "mac": "00:11:22:33:44:55", "hostname": "office-pc",
        "vendor": "Test Vendor", "open_ports": [80, 443], "role": "web-server",
    }])

    conn = sqlite3.connect(db_path)
    try:
        device_count = conn.execute("SELECT COUNT(*) FROM devices;").fetchone()[0]
        distinct_device_ids = conn.execute("SELECT COUNT(DISTINCT device_id) FROM hosts;").fetchone()[0]
        observed_ips = {row[0] for row in conn.execute("SELECT ip FROM hosts;").fetchall()}
        assert device_count == 1
        assert distinct_device_ids == 1
        assert observed_ips == {"192.168.0.20", "192.168.0.45"}
        assert conn.execute("PRAGMA integrity_check;").fetchone()[0] == "ok"
        assert conn.execute("PRAGMA foreign_key_check;").fetchall() == []
    finally:
        conn.close()

    passport = storage.get_device_passport("192.168.0.45")
    assert passport["appearances"] == 2
    assert "192.168.0.20" in passport["historical_summary"]
    assert "192.168.0.45" in passport["historical_summary"]


def test_same_ip_different_mac_creates_two_devices(monkeypatch, tmp_path):
    db_path = use_temp_db(monkeypatch, tmp_path)
    storage.init_db()
    t1 = datetime(2026, 1, 1, 10, 0, 0)
    t2 = t1 + timedelta(minutes=5)

    storage.save_scan("192.168.0.0/24", t1, t1, [{"ip": "192.168.0.20", "mac": "00:11:22:33:44:55"}])
    storage.save_scan("192.168.0.0/24", t2, t2, [{"ip": "192.168.0.20", "mac": "00:AA:BB:CC:DD:EE"}])

    conn = sqlite3.connect(db_path)
    try:
        assert conn.execute("SELECT COUNT(*) FROM devices;").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(DISTINCT device_id) FROM hosts;").fetchone()[0] == 2
    finally:
        conn.close()


def test_missing_mac_falls_back_to_ip_identity(monkeypatch, tmp_path):
    db_path = use_temp_db(monkeypatch, tmp_path)
    storage.init_db()
    t = datetime(2026, 1, 1, 10, 0, 0)
    storage.save_scan("192.168.0.0/24", t, t, [{"ip": "192.168.0.20", "hostname": "a", "mac": ""}])
    storage.save_scan("192.168.0.0/24", t, t, [{"ip": "192.168.0.20", "hostname": "a", "mac": ""}])
    conn = sqlite3.connect(db_path)
    try:
        assert conn.execute("SELECT COUNT(*) FROM devices;").fetchone()[0] == 1
    finally:
        conn.close()


def test_migration_v7_to_v8_preserves_existing_rows(monkeypatch, tmp_path):
    db_path = use_temp_db(monkeypatch, tmp_path)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);")
    cur.execute("INSERT INTO meta(key, value) VALUES ('schema_version', '7');")
    cur.execute("""
        CREATE TABLE devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE,
            hostname TEXT NOT NULL DEFAULT '',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            last_role TEXT NOT NULL DEFAULT '',
            last_open_ports TEXT NOT NULL DEFAULT '',
            mac TEXT NOT NULL DEFAULT '',
            vendor TEXT NOT NULL DEFAULT ''
        );
    """)
    cur.execute("""
        CREATE TABLE scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            network TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT NOT NULL,
            duration_sec INTEGER NOT NULL DEFAULT 0,
            host_count INTEGER NOT NULL DEFAULT 0,
            summary_text TEXT NOT NULL DEFAULT '',
            attention_score_total INTEGER NOT NULL DEFAULT 0
        );
    """)
    cur.execute("""
        CREATE TABLE hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            device_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            hostname TEXT NOT NULL DEFAULT '',
            open_ports TEXT NOT NULL DEFAULT '',
            role TEXT NOT NULL DEFAULT '',
            mac TEXT NOT NULL DEFAULT '',
            vendor TEXT NOT NULL DEFAULT '',
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
        );
    """)
    cur.execute("CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL, ip TEXT NOT NULL, event_type TEXT NOT NULL, old_value TEXT NOT NULL DEFAULT '', new_value TEXT NOT NULL DEFAULT '', description TEXT NOT NULL, created_at TEXT NOT NULL, match_confidence INTEGER NOT NULL DEFAULT -1, match_decision TEXT NOT NULL DEFAULT '', match_reasons TEXT NOT NULL DEFAULT '');")
    cur.execute("CREATE TABLE device_scores (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL, ip TEXT NOT NULL, attention_score INTEGER NOT NULL, attention_level TEXT NOT NULL, reasons TEXT NOT NULL, created_at TEXT NOT NULL);")
    cur.execute("INSERT INTO scans(id, network, started_at, finished_at) VALUES (1, '192.168.0.0/24', 'a', 'b');")
    cur.execute("INSERT INTO devices(id, ip, hostname, first_seen, last_seen, mac) VALUES (1, '192.168.0.20', 'pc', 'a', 'b', '00:11:22:33:44:55');")
    cur.execute("INSERT INTO hosts(id, scan_id, device_id, ip, hostname, mac) VALUES (1, 1, 1, '192.168.0.20', 'pc', '00:11:22:33:44:55');")
    cur.execute("INSERT INTO events(scan_id, ip, event_type, description, created_at) VALUES (1, '192.168.0.20', 'NEW_HOST', 'x', 'b');")
    conn.commit(); conn.close()

    storage.init_db()
    conn = sqlite3.connect(db_path)
    try:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(devices);").fetchall()}
        assert "identity_key" in columns
        assert conn.execute("SELECT COUNT(*) FROM scans;").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM hosts;").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM events;").fetchone()[0] == 1
        assert conn.execute("PRAGMA integrity_check;").fetchone()[0] == "ok"
        assert conn.execute("PRAGMA foreign_key_check;").fetchall() == []
    finally:
        conn.close()
