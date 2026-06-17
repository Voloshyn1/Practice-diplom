import sqlite3
import csv
from datetime import datetime
from pathlib import Path
from typing import Callable

from identity_matcher import normalize_mac

# Файл бази даних буде лежати поруч з .py-файлами
DB_PATH = Path(__file__).with_name("scanner.db")
SCHEMA_VERSION = 8


def _get_connection():
    """
    Внутрішня функція: відкриває з'єднання з базою даних.
    Кожен раз, коли треба щось зробити з БД, викликаємо її.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    """
    Ініціалізує БД та застосовує міграції.
    Викликається один раз при старті програми (у MainWindow).
    """
    apply_migrations()


def _ensure_meta_table(cur):
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """
    )


def _get_schema_version(cur) -> int:
    cur.execute("SELECT value FROM meta WHERE key = 'schema_version';")
    row = cur.fetchone()
    if not row:
        return 0
    try:
        return int(row[0])
    except (TypeError, ValueError):
        return 0


def _set_schema_version(cur, version: int):
    cur.execute(
        """
        INSERT INTO meta (key, value)
        VALUES ('schema_version', ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value;
        """,
        (str(version),),
    )


def _migration_001_initial_schema(cur):
    # Довідник пристроїв (інвентар мережі)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE,
            hostname TEXT NOT NULL DEFAULT '',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            last_role TEXT NOT NULL DEFAULT '',
            last_open_ports TEXT NOT NULL DEFAULT ''
        );
        """
    )

    # Таблиця сканувань
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            network TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT NOT NULL,
            duration_sec INTEGER NOT NULL DEFAULT 0,
            host_count INTEGER NOT NULL DEFAULT 0
        );
        """
    )

    # Таблиця хостів для кожного сканування
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            device_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            hostname TEXT NOT NULL DEFAULT '',
            open_ports TEXT NOT NULL DEFAULT '',
            role TEXT NOT NULL DEFAULT '',
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE,
            FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
        );
        """
    )

    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_hosts_scan_id ON hosts(scan_id);"
    )


def _table_exists(cur, table_name: str) -> bool:
    cur.execute(
        """
        SELECT 1
        FROM sqlite_master
        WHERE type = 'table' AND name = ?;
        """,
        (table_name,),
    )
    return cur.fetchone() is not None


def _get_table_columns(cur, table_name: str) -> set[str]:
    """
    Повертає множину назв колонок таблиці.
    Якщо таблиці не існує, повертає порожню множину.
    """
    if not _table_exists(cur, table_name):
        return set()

    cur.execute(f"PRAGMA table_info({table_name});")
    return {row[1] for row in cur.fetchall()}


def _ensure_column(
    cur,
    *,
    table_name: str,
    column_name: str,
    column_def: str,
):
    """
    Додає колонку через ALTER TABLE лише якщо її не існує.
    Це робить міграцію безпечною та ідемпотентною.
    """
    columns = _get_table_columns(cur, table_name)
    if column_name not in columns:
        cur.execute(
            f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_def};"
        )


def _migration_002_legacy_columns(cur):
    """
    Додає відсутні колонки у legacy-БД, створених до системи міграцій.
    Важливо: не видаляє/не пересоздає таблиці, щоб зберегти існуючі дані.
    """
    # Для save_scan() критично потрібні поля в scans.
    if _table_exists(cur, "scans"):
        _ensure_column(
            cur,
            table_name="scans",
            column_name="duration_sec",
            column_def="INTEGER NOT NULL DEFAULT 0",
        )
        _ensure_column(
            cur,
            table_name="scans",
            column_name="host_count",
            column_def="INTEGER NOT NULL DEFAULT 0",
        )

    # Для поточної логіки _upsert_device() та save_scan()
    # перевіряємо базові поля в devices/hosts.
    if _table_exists(cur, "devices"):
        _ensure_column(
            cur,
            table_name="devices",
            column_name="hostname",
            column_def="TEXT NOT NULL DEFAULT ''",
        )
        _ensure_column(
            cur,
            table_name="devices",
            column_name="last_role",
            column_def="TEXT NOT NULL DEFAULT ''",
        )
        _ensure_column(
            cur,
            table_name="devices",
            column_name="last_open_ports",
            column_def="TEXT NOT NULL DEFAULT ''",
        )

    if _table_exists(cur, "hosts"):
        _ensure_column(
            cur,
            table_name="hosts",
            column_name="hostname",
            column_def="TEXT NOT NULL DEFAULT ''",
        )
        _ensure_column(
            cur,
            table_name="hosts",
            column_name="open_ports",
            column_def="TEXT NOT NULL DEFAULT ''",
        )
        _ensure_column(
            cur,
            table_name="hosts",
            column_name="role",
            column_def="TEXT NOT NULL DEFAULT ''",
        )


def _migration_003_events_schema(cur):
    """
    Додає таблицю подій змін між скануваннями.
    """
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            event_type TEXT NOT NULL,
            old_value TEXT NOT NULL DEFAULT '',
            new_value TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );
        """
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_scan_id ON events(scan_id);"
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);"
    )


def _migration_004_attention_schema(cur):
    """
    Додає структури для оцінки уваги та текстового підсумку сканування.
    """
    # Додаємо поля у scans (потрібні для підсумку та агрегованої оцінки уваги)
    if _table_exists(cur, "scans"):
        _ensure_column(
            cur,
            table_name="scans",
            column_name="summary_text",
            column_def="TEXT NOT NULL DEFAULT ''",
        )
        _ensure_column(
            cur,
            table_name="scans",
            column_name="attention_score_total",
            column_def="INTEGER NOT NULL DEFAULT 0",
        )

    # Таблиця оцінок уваги по хостах у межах одного сканування
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS device_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            attention_score INTEGER NOT NULL,
            attention_level TEXT NOT NULL,
            reasons TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );
        """
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_device_scores_scan_id ON device_scores(scan_id);"
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_device_scores_ip ON device_scores(ip);"
    )


def _migration_005_history_indexes(cur):
    """
    Додає індекси для швидших запитів історії та паспорта пристрою.
    """
    cur.execute("CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_scans_finished_at ON scans(finished_at);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_ip_created ON events(ip, created_at);")


def _migration_006_host_enrichment(cur):
    """
    Додає поля для MAC/vendor у devices та hosts.
    """
    if _table_exists(cur, "devices"):
        _ensure_column(
            cur,
            table_name="devices",
            column_name="mac",
            column_def="TEXT NOT NULL DEFAULT ''",
        )
        _ensure_column(
            cur,
            table_name="devices",
            column_name="vendor",
            column_def="TEXT NOT NULL DEFAULT ''",
        )

    if _table_exists(cur, "hosts"):
        _ensure_column(
            cur,
            table_name="hosts",
            column_name="mac",
            column_def="TEXT NOT NULL DEFAULT ''",
        )
        _ensure_column(
            cur,
            table_name="hosts",
            column_name="vendor",
            column_def="TEXT NOT NULL DEFAULT ''",
        )

    cur.execute("CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_hosts_mac ON hosts(mac);")




def _migration_007_event_identity_metadata(cur):
    """
    Додає метадані confidence-based зіставлення хостів до подій.
    """
    if _table_exists(cur, "events"):
        _ensure_column(
            cur,
            table_name="events",
            column_name="match_confidence",
            column_def="INTEGER NOT NULL DEFAULT -1",
        )
        _ensure_column(
            cur,
            table_name="events",
            column_name="match_decision",
            column_def="TEXT NOT NULL DEFAULT ''",
        )
        _ensure_column(
            cur,
            table_name="events",
            column_name="match_reasons",
            column_def="TEXT NOT NULL DEFAULT ''",
        )


def _device_identity_key(*, ip: str, mac: str) -> str:
    norm_mac = normalize_mac(mac)
    if norm_mac:
        return f"mac:{norm_mac}"
    return f"ip:{(ip or '').strip()}"


def _migration_008_stable_device_identity(cur):
    """
    Rebuilds devices without UNIQUE(ip) and adds identity_key.

    Existing rows are preserved. Rows with the same non-empty normalized MAC are
    merged into one stable device row; hosts are remapped to the canonical row.
    IP remains an observation value and is no longer treated as permanent identity.
    """
    if not _table_exists(cur, "devices") or not _table_exists(cur, "hosts"):
        return

    columns = _get_table_columns(cur, "devices")
    if "identity_key" in columns:
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_identity_key ON devices(identity_key);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);")
        return

    cur.execute(
        """
        CREATE TABLE devices_v8 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identity_key TEXT NOT NULL UNIQUE,
            ip TEXT NOT NULL DEFAULT '',
            hostname TEXT NOT NULL DEFAULT '',
            mac TEXT NOT NULL DEFAULT '',
            vendor TEXT NOT NULL DEFAULT '',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            last_role TEXT NOT NULL DEFAULT '',
            last_open_ports TEXT NOT NULL DEFAULT ''
        );
        """
    )
    cur.execute(
        """
        CREATE TABLE device_id_map_v8 (
            old_id INTEGER PRIMARY KEY,
            new_id INTEGER NOT NULL
        );
        """
    )

    cur.execute(
        """
        SELECT id, ip, hostname, mac, vendor, first_seen, last_seen, last_role, last_open_ports
        FROM devices
        ORDER BY id;
        """
    )
    for old_id, ip, hostname, mac, vendor, first_seen, last_seen, role, ports in cur.fetchall():
        identity_key = _device_identity_key(ip=ip or "", mac=mac or "")
        cur.execute("SELECT id, first_seen, last_seen FROM devices_v8 WHERE identity_key = ?;", (identity_key,))
        existing = cur.fetchone()
        if existing:
            new_id, existing_first_seen, existing_last_seen = existing
            merged_first_seen = min(existing_first_seen, first_seen or existing_first_seen)
            merged_last_seen = max(existing_last_seen, last_seen or existing_last_seen)
            if (last_seen or "") >= (existing_last_seen or ""):
                cur.execute(
                    """
                    UPDATE devices_v8
                    SET ip = ?, hostname = ?, mac = ?, vendor = ?, first_seen = ?,
                        last_seen = ?, last_role = ?, last_open_ports = ?
                    WHERE id = ?;
                    """,
                    (
                        ip or "",
                        hostname or "",
                        normalize_mac(mac or "") or (mac or ""),
                        vendor or "",
                        merged_first_seen,
                        merged_last_seen,
                        role or "",
                        ports or "",
                        new_id,
                    ),
                )
            else:
                cur.execute(
                    "UPDATE devices_v8 SET first_seen = ?, last_seen = ? WHERE id = ?;",
                    (merged_first_seen, merged_last_seen, new_id),
                )
        else:
            cur.execute(
                """
                INSERT INTO devices_v8 (
                    id, identity_key, ip, hostname, mac, vendor, first_seen, last_seen,
                    last_role, last_open_ports
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    old_id,
                    identity_key,
                    ip or "",
                    hostname or "",
                    normalize_mac(mac or "") or (mac or ""),
                    vendor or "",
                    first_seen or "",
                    last_seen or "",
                    role or "",
                    ports or "",
                ),
            )
            new_id = old_id

        cur.execute(
            "INSERT INTO device_id_map_v8(old_id, new_id) VALUES (?, ?);",
            (old_id, new_id),
        )

    cur.execute(
        """
        CREATE TABLE hosts_v8 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            device_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            hostname TEXT NOT NULL DEFAULT '',
            open_ports TEXT NOT NULL DEFAULT '',
            role TEXT NOT NULL DEFAULT '',
            mac TEXT NOT NULL DEFAULT '',
            vendor TEXT NOT NULL DEFAULT '',
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE,
            FOREIGN KEY (device_id) REFERENCES devices_v8 (id) ON DELETE CASCADE
        );
        """
    )
    cur.execute(
        """
        INSERT INTO hosts_v8 (id, scan_id, device_id, ip, hostname, open_ports, role, mac, vendor)
        SELECT h.id, h.scan_id, m.new_id, h.ip, h.hostname, h.open_ports, h.role, h.mac, h.vendor
        FROM hosts h
        JOIN device_id_map_v8 m ON m.old_id = h.device_id;
        """
    )

    cur.execute("DROP TABLE hosts;")
    cur.execute("DROP TABLE devices;")
    cur.execute("ALTER TABLE devices_v8 RENAME TO devices;")
    cur.execute("ALTER TABLE hosts_v8 RENAME TO hosts;")
    cur.execute("DROP TABLE device_id_map_v8;")
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_identity_key ON devices(identity_key);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_hosts_scan_id ON hosts(scan_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_hosts_mac ON hosts(mac);")


def inspect_schema_state() -> dict[str, list[str]]:
    """
    Невеликий допоміжний інструмент для дебагу міграцій.
    Повертає поточний стан колонок ключових таблиць.
    """
    conn = _get_connection()
    try:
        cur = conn.cursor()
        tables = ["meta", "devices", "scans", "hosts", "events", "device_scores"]
        return {
            table: sorted(_get_table_columns(cur, table))
            for table in tables
        }
    finally:
        conn.close()


MIGRATIONS: dict[int, Callable] = {
    1: _migration_001_initial_schema,
    2: _migration_002_legacy_columns,
    3: _migration_003_events_schema,
    4: _migration_004_attention_schema,
    5: _migration_005_history_indexes,
    6: _migration_006_host_enrichment,
    7: _migration_007_event_identity_metadata,
    8: _migration_008_stable_device_identity,
}


def apply_migrations():
    """
    Застосовує всі міграції до актуальної версії SCHEMA_VERSION.
    """
    conn = _get_connection()
    try:
        with conn:
            cur = conn.cursor()
            _ensure_meta_table(cur)
            current_version = _get_schema_version(cur)

            for version in sorted(MIGRATIONS):
                if current_version < version <= SCHEMA_VERSION:
                    MIGRATIONS[version](cur)
                    _set_schema_version(cur, version)
    finally:
        conn.close()


def _upsert_device(
    cur,
    *,
    ip: str,
    hostname: str,
    mac: str,
    vendor: str,
    role: str,
    open_ports_str: str,
    seen_at: datetime,
) -> int:
    """
    Додає пристрій у devices або оновлює існуючий.
    Повертає id пристрою (device_id).
    """
    identity_key = _device_identity_key(ip=ip, mac=mac)
    cur.execute("SELECT id, first_seen FROM devices WHERE identity_key = ?;", (identity_key,))
    row = cur.fetchone()

    seen_iso = seen_at.isoformat()

    if row:
        device_id, first_seen = row
        # Оновлюємо останню інформацію
        cur.execute(
            """
            UPDATE devices
            SET hostname = ?,
                ip = ?,
                mac = ?,
                vendor = ?,
                last_seen = ?,
                last_role = ?,
                last_open_ports = ?
            WHERE id = ?;
            """,
            (hostname, ip, normalize_mac(mac) or mac, vendor, seen_iso, role, open_ports_str, device_id),
        )
        return device_id
    else:
        # Новий пристрій у мережі
        cur.execute(
            """
            INSERT INTO devices (
                identity_key, ip, hostname, mac, vendor, first_seen, last_seen, last_role, last_open_ports
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (identity_key, ip, hostname, normalize_mac(mac) or mac, vendor, seen_iso, seen_iso, role, open_ports_str),
        )
        return cur.lastrowid


def save_scan(
    network: str,
    started_at: datetime,
    finished_at: datetime,
    hosts: list[dict],
) -> int:
    """
    Зберігає одне сканування у базу:
      - запис у scans
      - список хостів у hosts
      - оновлює інвентар пристроїв у devices

    hosts – список словників:
        {
          "ip": "192.168.0.10",
          "open_ports": [80, 443],
          "role": "web-сервер",
          "hostname": "my-pc"   # (опційно)
        }

    Повертає id доданого сканування (щоб показати в інтерфейсі).
    """
    conn = _get_connection()
    try:
        with conn:
            cur = conn.cursor()

            # Обчислюємо тривалість сканування в секундах
            duration_sec = int((finished_at - started_at).total_seconds())

            # 1. Додаємо запис про саме сканування
            cur.execute(
                """
                INSERT INTO scans (network, started_at, finished_at, duration_sec, host_count)
                VALUES (?, ?, ?, ?, ?);
                """,
                (
                    network,
                    started_at.isoformat(),
                    finished_at.isoformat(),
                    duration_sec,
                    len(hosts),
                ),
            )
            scan_id = cur.lastrowid

            # 2. Додаємо всі знайдені хости + оновлюємо devices
            for host in hosts:
                ip = host.get("ip", "")
                ports = host.get("open_ports", [])
                role = host.get("role", "")
                hostname = host.get("hostname", "")
                mac = host.get("mac", "")
                vendor = host.get("vendor", "")

                ports_str = ",".join(str(p) for p in ports) if ports else ""

                # Оновлюємо / додаємо пристрій, отримуємо device_id
                device_id = _upsert_device(
                    cur,
                    ip=ip,
                    hostname=hostname,
                    mac=mac,
                    vendor=vendor,
                    role=role,
                    open_ports_str=ports_str,
                    seen_at=finished_at,
                )

                # Запис у таблицю hosts (конкретний результат цього скану)
                cur.execute(
                    """
                    INSERT INTO hosts (scan_id, device_id, ip, hostname, mac, vendor, open_ports, role)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (scan_id, device_id, ip, hostname, mac, vendor, ports_str, role),
                )

            return scan_id
    finally:
        conn.close()


def get_previous_scan_id(network: str, current_scan_id: int) -> int | None:
    """
    Повертає id попереднього сканування для тієї ж підмережі.
    """
    conn = _get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id
            FROM scans
            WHERE network = ? AND id < ?
            ORDER BY id DESC
            LIMIT 1;
            """,
            (network, current_scan_id),
        )
        row = cur.fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def load_hosts_for_scan(scan_id: int) -> list[dict]:
    """
    Завантажує список хостів для конкретного сканування.
    """
    conn = _get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT ip, hostname, mac, vendor, open_ports, role
            FROM hosts
            WHERE scan_id = ?
            ORDER BY ip;
            """,
            (scan_id,),
        )
        rows = cur.fetchall()
        result: list[dict] = []
        for ip, hostname, mac, vendor, ports_str, role in rows:
            ports = []
            if ports_str:
                ports = [int(p) for p in ports_str.split(",") if p.strip()]
            result.append({
                "ip": ip,
                "hostname": hostname or "",
                "mac": mac or "",
                "vendor": vendor or "",
                "open_ports": ports,
                "role": role or "",
            })
        return result
    finally:
        conn.close()


def _normalize_match_reasons(value) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return "; ".join(str(item) for item in value)
    return str(value)


def _normalize_match_confidence(value) -> int:
    if value is None or value == "":
        return -1
    try:
        return int(value)
    except (TypeError, ValueError):
        return -1


def save_events(scan_id: int, events: list[dict]):
    """
    Зберігає події для конкретного сканування.
    """
    if not events:
        return

    conn = _get_connection()
    try:
        with conn:
            cur = conn.cursor()
            for event in events:
                cur.execute(
                    """
                    INSERT INTO events (
                        scan_id, ip, event_type, old_value, new_value, description,
                        created_at, match_confidence, match_decision, match_reasons
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        scan_id,
                        event.get("ip", ""),
                        event.get("event_type", ""),
                        event.get("old_value", ""),
                        event.get("new_value", ""),
                        event.get("description", ""),
                        datetime.now().isoformat(),
                        _normalize_match_confidence(event.get("match_confidence", -1)),
                        event.get("match_decision", ""),
                        _normalize_match_reasons(event.get("match_reasons", "")),
                    ),
                )
    finally:
        conn.close()


def load_events_for_scan(scan_id: int) -> list[dict]:
    """
    Завантажує події для конкретного сканування.
    """
    conn = _get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, scan_id, ip, event_type, old_value, new_value, description,
                   created_at, match_confidence, match_decision, match_reasons
            FROM events
            WHERE scan_id = ?
            ORDER BY id ASC;
            """,
            (scan_id,),
        )
        rows = cur.fetchall()
        return [
            {
                "id": row[0],
                "scan_id": row[1],
                "ip": row[2],
                "event_type": row[3],
                "old_value": row[4],
                "new_value": row[5],
                "description": row[6],
                "created_at": row[7],
                "match_confidence": int(row[8] if row[8] is not None else -1),
                "match_decision": row[9] or "",
                "match_reasons": row[10] or "",
            }
            for row in rows
        ]
    finally:
        conn.close()


def load_events_for_latest_scan(network: str) -> list[dict]:
    """
    Завантажує події для останнього сканування конкретної підмережі.
    """
    conn = _get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id
            FROM scans
            WHERE network = ?
            ORDER BY id DESC
            LIMIT 1;
            """,
            (network,),
        )
        row = cur.fetchone()
        if not row:
            return []
        latest_scan_id = row[0]
    finally:
        conn.close()

    return load_events_for_scan(latest_scan_id)


def save_device_scores(scan_id: int, scores: list[dict]):
    """
    Зберігає оцінки уваги по хостах для конкретного сканування.
    """
    conn = _get_connection()
    try:
        with conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM device_scores WHERE scan_id = ?;", (scan_id,))
            for score_item in scores:
                reasons_list = score_item.get("reasons", [])
                reasons_text = " | ".join(reasons_list) if reasons_list else ""
                cur.execute(
                    """
                    INSERT INTO device_scores (
                        scan_id, ip, attention_score, attention_level, reasons, created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    (
                        scan_id,
                        score_item.get("ip", ""),
                        int(score_item.get("attention_score", 0)),
                        score_item.get("attention_level", "Low"),
                        reasons_text,
                        datetime.now().isoformat(),
                    ),
                )
    finally:
        conn.close()


def load_device_scores_for_scan(scan_id: int) -> list[dict]:
    """
    Завантажує оцінки уваги по хостах для конкретного сканування.
    """
    conn = _get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT ip, attention_score, attention_level, reasons
            FROM device_scores
            WHERE scan_id = ?
            ORDER BY attention_score DESC, ip ASC;
            """,
            (scan_id,),
        )
        rows = cur.fetchall()
        result: list[dict] = []
        for ip, score, level, reasons_text in rows:
            reasons = [r.strip() for r in reasons_text.split("|") if r.strip()] if reasons_text else []
            result.append({
                "ip": ip,
                "attention_score": score,
                "attention_level": level,
                "reasons": reasons,
            })
        return result
    finally:
        conn.close()


def save_scan_summary(scan_id: int, summary_text: str, attention_score_total: int):
    """
    Зберігає текст підсумку і загальну оцінку уваги для сканування.
    """
    conn = _get_connection()
    try:
        with conn:
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE scans
                SET summary_text = ?,
                    attention_score_total = ?
                WHERE id = ?;
                """,
                (summary_text, int(attention_score_total), scan_id),
            )
    finally:
        conn.close()


def load_summary_for_scan(scan_id: int) -> dict:
    """
    Завантажує збережений підсумок сканування.
    """
    conn = _get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT summary_text, attention_score_total
            FROM scans
            WHERE id = ?;
            """,
            (scan_id,),
        )
        row = cur.fetchone()
        if not row:
            return {"summary_text": "", "attention_score_total": 0}
        return {
            "summary_text": row[0] or "",
            "attention_score_total": int(row[1] or 0),
        }
    finally:
        conn.close()


def get_device_recent_events(ip: str, limit: int = 10) -> list[dict]:
    """
    Повертає останні події для вказаного IP.
    """
    conn = _get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT scan_id, event_type, old_value, new_value, description, created_at,
                   match_confidence, match_decision, match_reasons
            FROM events
            WHERE ip = ?
            ORDER BY id DESC
            LIMIT ?;
            """,
            (ip, limit),
        )
        rows = cur.fetchall()
        return [
            {
                "scan_id": row[0],
                "event_type": row[1],
                "old_value": row[2],
                "new_value": row[3],
                "description": row[4],
                "created_at": row[5],
                "match_confidence": int(row[6] if row[6] is not None else -1),
                "match_decision": row[7] or "",
                "match_reasons": row[8] or "",
            }
            for row in rows
        ]
    finally:
        conn.close()


def get_device_scan_history(ip: str) -> list[dict]:
    """
    Повертає історію появ пристрою в скануваннях.
    IP використовується як сумісний вхід: спочатку знаходимо останнє
    спостереження, а історію будуємо за stable device_id.
    """
    conn = _get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT device_id
            FROM hosts
            WHERE ip = ?
            ORDER BY scan_id DESC, id DESC
            LIMIT 1;
            """,
            (ip,),
        )
        device_row = cur.fetchone()
        if not device_row:
            return []
        device_id = device_row[0]
        cur.execute(
            """
            SELECT s.id, s.network, s.started_at, s.finished_at, s.host_count,
                   h.role, h.open_ports, h.hostname, h.mac, h.vendor, s.attention_score_total, h.ip
            FROM hosts h
            JOIN scans s ON s.id = h.scan_id
            WHERE h.device_id = ?
            ORDER BY s.id DESC;
            """,
            (device_id,),
        )
        rows = cur.fetchall()
        history: list[dict] = []
        for row in rows:
            history.append({
                "scan_id": row[0],
                "network": row[1],
                "started_at": row[2],
                "finished_at": row[3],
                "host_count": row[4],
                "role": row[5] or "",
                "open_ports": row[6] or "",
                "hostname": row[7] or "",
                "mac": row[8] or "",
                "vendor": row[9] or "",
                "attention_score_total": int(row[10] or 0),
                "ip": row[11] or "",
            })
        return history
    finally:
        conn.close()


def get_device_passport(ip: str) -> dict:
    """
    Повертає паспорт пристрою за IP останнього відомого спостереження.
    """
    conn = _get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT d.id, d.ip, d.hostname, d.mac, d.vendor, d.first_seen, d.last_seen,
                   d.last_role, d.last_open_ports
            FROM hosts h
            JOIN devices d ON d.id = h.device_id
            WHERE h.ip = ?
            ORDER BY h.scan_id DESC, h.id DESC
            LIMIT 1;
            """,
            (ip,),
        )
        row = cur.fetchone()
        if not row:
            return {}

        device_id = row[0]
        current_ip = row[1] or ip

        cur.execute("SELECT COUNT(*) FROM hosts WHERE device_id = ?;", (device_id,))
        appearances = int(cur.fetchone()[0] or 0)

        cur.execute("SELECT DISTINCT ip FROM hosts WHERE device_id = ?;", (device_id,))
        observed_ips = [r[0] for r in cur.fetchall() if r[0]]

        cur.execute(
            """
            SELECT attention_score, attention_level, reasons, scan_id, created_at, ip
            FROM device_scores
            WHERE ip IN (
                SELECT DISTINCT ip FROM hosts WHERE device_id = ?
            )
            ORDER BY id DESC
            LIMIT 1;
            """,
            (device_id,),
        )
        score_row = cur.fetchone()
        latest_score = {
            "attention_score": int(score_row[0]) if score_row else 0,
            "attention_level": score_row[1] if score_row else "Low",
            "reasons": score_row[2] if score_row else "",
            "scan_id": score_row[3] if score_row else None,
            "created_at": score_row[4] if score_row else "",
            "ip": score_row[5] if score_row else "",
        }
    finally:
        conn.close()

    recent_events: list[dict] = []
    for observed_ip in observed_ips:
        recent_events.extend(get_device_recent_events(observed_ip, limit=10))
    recent_events.sort(key=lambda item: item.get("created_at", ""), reverse=True)
    recent_events = recent_events[:10]

    historical_summary = (
        f"Пристрій {current_ip} з'являвся у {appearances} скануваннях. "
        f"Відомі IP: {', '.join(observed_ips) or '—'}. "
        f"Остання роль: {row[7] or '—'}. "
        f"Останні порти: {row[8] or '—'}."
    )

    return {
        "device_id": device_id,
        "ip": current_ip,
        "hostname": row[2] or "",
        "mac": row[3] or "",
        "vendor": row[4] or "",
        "first_seen": row[5] or "",
        "last_seen": row[6] or "",
        "current_role": row[7] or "",
        "current_open_ports": row[8] or "",
        "appearances": appearances,
        "latest_score": latest_score,
        "recent_events": recent_events,
        "historical_summary": historical_summary,
    }


def get_scan_history(limit: int = 50) -> list[dict]:
    """
    Повертає список останніх сканувань.
    """
    conn = _get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, network, started_at, finished_at, host_count, attention_score_total, summary_text
            FROM scans
            ORDER BY id DESC
            LIMIT ?;
            """,
            (limit,),
        )
        rows = cur.fetchall()
        result: list[dict] = []
        for row in rows:
            summary_text = row[6] or ""
            preview = summary_text.splitlines()[0] if summary_text else ""
            result.append({
                "scan_id": row[0],
                "network": row[1],
                "started_at": row[2],
                "finished_at": row[3],
                "host_count": int(row[4] or 0),
                "attention_score_total": int(row[5] or 0),
                "summary_preview": preview,
            })
        return result
    finally:
        conn.close()


def get_scan_details(scan_id: int) -> dict:
    """
    Повертає деталі конкретного сканування: summary, events, scores.
    """
    conn = _get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, network, started_at, finished_at, host_count, attention_score_total, summary_text
            FROM scans
            WHERE id = ?;
            """,
            (scan_id,),
        )
        row = cur.fetchone()
        if not row:
            return {}
    finally:
        conn.close()

    return {
        "scan_id": row[0],
        "network": row[1],
        "started_at": row[2],
        "finished_at": row[3],
        "host_count": int(row[4] or 0),
        "attention_score_total": int(row[5] or 0),
        "summary_text": row[6] or "",
        "events": load_events_for_scan(scan_id),
        "scores": load_device_scores_for_scan(scan_id),
    }


def _get_latest_scan_id() -> int | None:
    conn = _get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1;")
        row = cur.fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def export_latest_summary_txt(path: str):
    """
    Експортує підсумок останнього сканування у TXT.
    """
    latest_scan_id = _get_latest_scan_id()
    if latest_scan_id is None:
        raise ValueError("Немає сканувань для експорту.")

    details = get_scan_details(latest_scan_id)
    top_scores = details.get("scores", [])[:3]

    output = [
        f"ID сканування: {details.get('scan_id')}",
        f"Мережа: {details.get('network')}",
        f"Початок: {details.get('started_at')}",
        f"Завершення: {details.get('finished_at')}",
        f"Активних хостів: {details.get('host_count')}",
        f"Загальна оцінка уваги: {details.get('attention_score_total')}",
        "",
        "Підсумок:",
        details.get("summary_text", ""),
        "",
        "ТОП хостів за увагою:",
    ]
    for item in top_scores:
        reasons = "; ".join(item.get("reasons", []))
        output.append(
            f"- {item.get('ip')}: {item.get('attention_score')} "
            f"({item.get('attention_level')}) | {reasons}"
        )

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(output), encoding="utf-8")


def export_latest_events_csv(path: str):
    """
    Експортує події останнього сканування у CSV.
    """
    latest_scan_id = _get_latest_scan_id()
    if latest_scan_id is None:
        raise ValueError("Немає сканувань для експорту.")

    events = load_events_for_scan(latest_scan_id)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow([
            "id", "scan_id", "ip", "event_type", "old_value", "new_value",
            "description", "created_at", "match_confidence", "match_decision", "match_reasons"
        ])
        for event in events:
            writer.writerow([
                event.get("id", ""),
                event.get("scan_id", ""),
                event.get("ip", ""),
                event.get("event_type", ""),
                event.get("old_value", ""),
                event.get("new_value", ""),
                event.get("description", ""),
                event.get("created_at", ""),
                event.get("match_confidence", -1),
                event.get("match_decision", ""),
                event.get("match_reasons", ""),
            ])


def export_latest_scores_csv(path: str):
    """
    Експортує оцінки уваги останнього сканування у CSV.
    """
    latest_scan_id = _get_latest_scan_id()
    if latest_scan_id is None:
        raise ValueError("Немає сканувань для експорту.")

    scores = load_device_scores_for_scan(latest_scan_id)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["scan_id", "ip", "attention_score", "attention_level", "reasons"])
        for item in scores:
            writer.writerow([
                latest_scan_id,
                item.get("ip", ""),
                item.get("attention_score", 0),
                item.get("attention_level", ""),
                "; ".join(item.get("reasons", [])),
            ])
