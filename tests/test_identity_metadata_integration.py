import sqlite3
import unittest
from datetime import datetime

from report import build_scan_summary
from risk import calculate_host_scores
from storage import (
    DB_PATH,
    init_db,
    inspect_schema_state,
    load_events_for_scan,
    save_events,
    save_scan,
)


class IdentityMetadataIntegrationTests(unittest.TestCase):
    def setUp(self):
        if DB_PATH.exists():
            DB_PATH.unlink()

    def tearDown(self):
        if DB_PATH.exists():
            DB_PATH.unlink()

    def test_migration_v7_adds_identity_metadata_columns(self):
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        cur.execute("INSERT INTO meta(key, value) VALUES ('schema_version', '6')")
        cur.execute(
            """
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                ip TEXT NOT NULL,
                event_type TEXT NOT NULL,
                old_value TEXT NOT NULL DEFAULT '',
                new_value TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        conn.commit()
        conn.close()

        init_db()
        columns = inspect_schema_state()["events"]

        self.assertIn("match_confidence", columns)
        self.assertIn("match_decision", columns)
        self.assertIn("match_reasons", columns)

    def test_event_identity_metadata_persists_and_loads(self):
        init_db()
        scan_id = save_scan("192.168.0.0/24", datetime.now(), datetime.now(), [])

        save_events(scan_id, [{
            "ip": "192.168.0.10",
            "event_type": "HOST_IP_CHANGED",
            "old_value": "192.168.0.5",
            "new_value": "192.168.0.10",
            "description": "IP changed",
            "match_confidence": 91,
            "match_decision": "auto-link",
            "match_reasons": ["MAC збіг", "Hostname збіг"],
        }])

        loaded = load_events_for_scan(scan_id)[0]
        self.assertEqual(loaded["match_confidence"], 91)
        self.assertEqual(loaded["match_decision"], "auto-link")
        self.assertEqual(loaded["match_reasons"], "MAC збіг; Hostname збіг")

    def test_event_without_identity_metadata_gets_defaults(self):
        init_db()
        scan_id = save_scan("192.168.0.0/24", datetime.now(), datetime.now(), [])

        save_events(scan_id, [{
            "ip": "192.168.0.20",
            "event_type": "NEW_HOST",
            "old_value": "",
            "new_value": "active",
            "description": "Новий хост",
        }])

        loaded = load_events_for_scan(scan_id)[0]
        self.assertEqual(loaded["match_confidence"], -1)
        self.assertEqual(loaded["match_decision"], "")
        self.assertEqual(loaded["match_reasons"], "")

    def test_risk_handles_ambiguous_identity_event(self):
        scores = calculate_host_scores([{
            "ip": "192.168.0.30",
            "event_type": "HOST_AMBIGUOUS_MATCH",
            "match_confidence": 63,
            "match_decision": "ambiguous",
        }])

        self.assertGreater(scores[0]["attention_score"], 0)
        reasons = scores[0]["reasons"]
        self.assertIn("Потрібна ручна перевірка ідентичності пристрою", reasons)
        self.assertIn("Ідентичність хоста визначена з низькою впевненістю", reasons)

    def test_report_mentions_uncertain_identity(self):
        summary = build_scan_summary(
            network="192.168.0.0/24",
            active_host_count=2,
            events=[{"event_type": "HOST_AMBIGUOUS_MATCH", "match_decision": "ambiguous"}],
            host_scores=[{"ip": "192.168.0.30", "attention_score": 18, "attention_level": "Low", "reasons": ["test"]}],
            has_previous_scan=True,
        )

        self.assertIn("невизначену ідентичність", summary)


if __name__ == "__main__":
    unittest.main()
