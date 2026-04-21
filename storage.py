import sqlite3
import csv
from datetime import datetime
from pathlib import Path
from typing import Callable

# Файл бази даних буде лежати поруч з .py-файлами
DB_PATH = Path(__file__).with_name("scanner.db")
SCHEMA_VERSION = 5


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
            SELECT ip, open_ports, role
            FROM hosts
            WHERE scan_id = ?
            ORDER BY ip;
            """,
            (scan_id,),
        )
        rows = cur.fetchall()
        result: list[dict] = []
        for ip, ports_str, role in rows:
            ports = []
            if ports_str:
                ports = [int(p) for p in ports_str.split(",") if p.strip()]
            result.append({
                "ip": ip,
                "open_ports": ports,
                "role": role or "",
            })
        return result
    finally:
        conn.close()


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
                        scan_id, ip, event_type, old_value, new_value, description, created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        scan_id,
                        event.get("ip", ""),
                        event.get("event_type", ""),
                        event.get("old_value", ""),
                        event.get("new_value", ""),
                        event.get("description", ""),
                        datetime.now().isoformat(),
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
            SELECT id, scan_id, ip, event_type, old_value, new_value, description, created_at
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
            SELECT scan_id, event_type, old_value, new_value, description, created_at
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
            }
            for row in rows
        ]
    finally:
        conn.close()


def get_device_scan_history(ip: str) -> list[dict]:
    """
    Повертає історію появ пристрою в скануваннях.
    """
    conn = _get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT s.id, s.network, s.started_at, s.finished_at, s.host_count,
                   h.role, h.open_ports, s.attention_score_total
            FROM hosts h
            JOIN scans s ON s.id = h.scan_id
            WHERE h.ip = ?
            ORDER BY s.id DESC;
            """,
            (ip,),
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
                "attention_score_total": int(row[7] or 0),
            })
        return history
    finally:
        conn.close()


def get_device_passport(ip: str) -> dict:
    """
    Повертає паспорт пристрою за IP.
    """
    conn = _get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT ip, hostname, first_seen, last_seen, last_role, last_open_ports
            FROM devices
            WHERE ip = ?;
            """,
            (ip,),
        )
        row = cur.fetchone()
        if not row:
            return {}

        cur.execute("SELECT COUNT(*) FROM hosts WHERE ip = ?;", (ip,))
        appearances = int(cur.fetchone()[0] or 0)

        cur.execute(
            """
            SELECT attention_score, attention_level, reasons, scan_id, created_at
            FROM device_scores
            WHERE ip = ?
            ORDER BY id DESC
            LIMIT 1;
            """,
            (ip,),
        )
        score_row = cur.fetchone()
        latest_score = {
            "attention_score": int(score_row[0]) if score_row else 0,
            "attention_level": score_row[1] if score_row else "Low",
            "reasons": score_row[2] if score_row else "",
            "scan_id": score_row[3] if score_row else None,
            "created_at": score_row[4] if score_row else "",
        }
    finally:
        conn.close()

    recent_events = get_device_recent_events(ip, limit=10)

    historical_summary = (
        f"Пристрій {ip} з'являвся у {appearances} скануваннях. "
        f"Остання роль: {row[4] or '—'}. "
        f"Останні порти: {row[5] or '—'}."
    )

    return {
        "ip": row[0],
        "hostname": row[1] or "",
        "first_seen": row[2] or "",
        "last_seen": row[3] or "",
        "current_role": row[4] or "",
        "current_open_ports": row[5] or "",
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
        writer.writerow(["id", "scan_id", "ip", "event_type", "old_value", "new_value", "description", "created_at"])
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
