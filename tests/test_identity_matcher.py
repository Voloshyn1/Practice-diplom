import unittest

from analyzer import compare_scans
from identity_matcher import (
    is_locally_administered_mac,
    jaccard_similarity,
    match_hosts,
    normalize_hostname,
    normalize_mac,
    score_host_pair,
)


class IdentityMatcherTests(unittest.TestCase):
    def test_normalize_mac_and_laa(self):
        self.assertEqual(normalize_mac('aa-bb-cc-dd-ee-ff'), 'AA:BB:CC:DD:EE:FF')
        self.assertTrue(is_locally_administered_mac('02:11:22:33:44:55'))
        self.assertFalse(is_locally_administered_mac('00:11:22:33:44:55'))

    def test_normalize_hostname(self):
        self.assertEqual(normalize_hostname(' Host-A.Office.Local '), 'host-a')
        self.assertEqual(normalize_hostname(''), '')

    def test_jaccard_both_empty_is_zero(self):
        self.assertEqual(jaccard_similarity([], []), 0.0)

    def test_same_mac_changed_ip_high_score(self):
        prev = {
            'ip': '192.168.0.10', 'hostname': 'pc1', 'mac': '00:11:22:33:44:55',
            'vendor': 'Intel', 'open_ports': [80, 443], 'role': 'web-сервер'
        }
        cur = {
            'ip': '192.168.0.22', 'hostname': 'pc1', 'mac': '00:11:22:33:44:55',
            'vendor': 'Intel', 'open_ports': [80, 443], 'role': 'web-сервер'
        }
        scored = score_host_pair(prev, cur)
        self.assertGreaterEqual(scored['score'], 70)
        self.assertIn(scored['decision'], {'auto-link', 'probable-link'})

    def test_same_ip_different_global_mac_penalty(self):
        prev = {
            'ip': '192.168.0.10', 'hostname': 'pc1', 'mac': '00:11:22:33:44:55',
            'vendor': 'Intel', 'open_ports': [80], 'role': 'web-сервер'
        }
        cur = {
            'ip': '192.168.0.10', 'hostname': 'pc1', 'mac': '10:11:22:33:44:55',
            'vendor': 'Intel', 'open_ports': [80], 'role': 'web-сервер'
        }
        scored = score_host_pair(prev, cur)
        self.assertLess(scored['score'], 85)

    def test_hostname_and_ports_without_mac(self):
        prev = {
            'ip': '192.168.0.10', 'hostname': 'workstation-01', 'mac': '',
            'vendor': '', 'open_ports': [22, 443], 'role': 'SSH-доступ, web-сервер'
        }
        cur = {
            'ip': '192.168.0.45', 'hostname': 'workstation-1', 'mac': '',
            'vendor': '', 'open_ports': [22, 443], 'role': 'SSH-доступ, web-сервер'
        }
        scored = score_host_pair(prev, cur)
        self.assertIn(scored['decision'], {'probable-link', 'ambiguous', 'no-link'})

    def test_completely_different_hosts_no_link(self):
        prev = {
            'ip': '192.168.0.10', 'hostname': 'db', 'mac': '00:11:22:33:44:55',
            'vendor': 'Dell', 'open_ports': [3306], 'role': 'MySQL'
        }
        cur = {
            'ip': '10.0.0.20', 'hostname': 'camera', 'mac': 'AA:BB:CC:DD:EE:FF',
            'vendor': 'Axis', 'open_ports': [554], 'role': 'RTSP'
        }
        scored = score_host_pair(prev, cur)
        self.assertEqual(scored['decision'], 'no-link')

    def test_one_previous_host_not_linked_twice(self):
        prev_hosts = [
            {'ip': '192.168.0.10', 'hostname': 'pc1', 'mac': '00:11:22:33:44:55', 'vendor': 'Intel', 'open_ports': [80], 'role': 'web-сервер'}
        ]
        current_hosts = [
            {'ip': '192.168.0.20', 'hostname': 'pc1', 'mac': '00:11:22:33:44:55', 'vendor': 'Intel', 'open_ports': [80], 'role': 'web-сервер'},
            {'ip': '192.168.0.21', 'hostname': 'pc1', 'mac': '00:11:22:33:44:55', 'vendor': 'Intel', 'open_ports': [80], 'role': 'web-сервер'},
        ]
        result = match_hosts(prev_hosts, current_hosts)
        self.assertEqual(len(result['links']), 1)

    def test_compare_scans_detects_port_change_for_matched_host(self):
        previous_hosts = [
            {'ip': '192.168.0.10', 'hostname': 'pc1', 'mac': '00:11:22:33:44:55', 'vendor': 'Intel', 'open_ports': [80], 'role': 'web-сервер'}
        ]
        current_hosts = [
            {'ip': '192.168.0.22', 'hostname': 'pc1', 'mac': '00:11:22:33:44:55', 'vendor': 'Intel', 'open_ports': [80, 3389], 'role': 'web-сервер'}
        ]
        events = compare_scans(previous_hosts, current_hosts)
        event_types = {e['event_type'] for e in events}
        self.assertIn('HOST_IP_CHANGED', event_types)
        self.assertIn('NEW_PORT_OPENED', event_types)


if __name__ == '__main__':
    unittest.main()
