import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Callable

# Файл бази даних буде лежати поруч з .py-файлами
DB_PATH = Path(__file__).with_name("scanner.db")
SCHEMA_VERSION = 1


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


MIGRATIONS: dict[int, Callable] = {
    1: _migration_001_initial_schema,
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
    role: str,
    open_ports_str: str,
    seen_at: datetime,
) -> int:
    """
    Додає пристрій у devices або оновлює існуючий.
    Повертає id пристрою (device_id).
    """
    cur.execute("SELECT id, first_seen FROM devices WHERE ip = ?;", (ip,))
    row = cur.fetchone()

    seen_iso = seen_at.isoformat()

    if row:
        device_id, first_seen = row
        # Оновлюємо останню інформацію
        cur.execute(
            """
            UPDATE devices
            SET hostname = ?,
                last_seen = ?,
                last_role = ?,
                last_open_ports = ?
            WHERE id = ?;
            """,
            (hostname, seen_iso, role, open_ports_str, device_id),
        )
        return device_id
    else:
        # Новий пристрій у мережі
        cur.execute(
            """
            INSERT INTO devices (
                ip, hostname, first_seen, last_seen, last_role, last_open_ports
            )
            VALUES (?, ?, ?, ?, ?, ?);
            """,
            (ip, hostname, seen_iso, seen_iso, role, open_ports_str),
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

                ports_str = ",".join(str(p) for p in ports) if ports else ""

                # Оновлюємо / додаємо пристрій, отримуємо device_id
                device_id = _upsert_device(
                    cur,
                    ip=ip,
                    hostname=hostname,
                    role=role,
                    open_ports_str=ports_str,
                    seen_at=finished_at,
                )

                # Запис у таблицю hosts (конкретний результат цього скану)
                cur.execute(
                    """
                    INSERT INTO hosts (scan_id, device_id, ip, hostname, open_ports, role)
                    VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    (scan_id, device_id, ip, hostname, ports_str, role),
                )

            return scan_id
    finally:
        conn.close()
