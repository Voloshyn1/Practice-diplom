import unittest

from analyzer import compare_scans
from identity_matcher import (
    is_locally_administered_mac,
    hostname_similarity,
    jaccard_similarity,
    match_hosts,
    normalize_hostname,
    role_similarity,
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

    def test_hostname_similarity(self):
        self.assertEqual(hostname_similarity('Host-A.local', 'host-a'), 1.0)
        self.assertGreater(hostname_similarity('workstation-01', 'workstation-1'), 0.8)
        self.assertEqual(hostname_similarity('', 'workstation-1'), 0.0)

    def test_jaccard_both_empty_is_zero(self):
        self.assertEqual(jaccard_similarity([], []), 0.0)

    def test_role_similarity_token_overlap(self):
        self.assertGreater(role_similarity('web-server, SSH access', 'web-server'), 0.0)
        self.assertEqual(role_similarity('', 'web-server'), 0.0)

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

    def test_same_ip_hostname_ports_role_without_mac_is_probable_link(self):
        prev = {
            'ip': '192.168.0.152', 'hostname': 'Voloshyn', 'mac': '',
            'vendor': '', 'open_ports': [139, 445], 'role': 'NetBIOS, SMB / file-sharing'
        }
        cur = {
            'ip': '192.168.0.152', 'hostname': 'Voloshyn', 'mac': '',
            'vendor': '', 'open_ports': [139, 445], 'role': 'NetBIOS, SMB / file-sharing'
        }
        scored = score_host_pair(prev, cur)
        self.assertGreaterEqual(scored['score'], 70)
        self.assertIn(scored['decision'], {'probable-link', 'auto-link'})
        self.assertIn(
            'IP збігається, hostname, порти та роль підтверджують схожість без MAC',
            scored['reasons'],
        )

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

    def test_same_ip_with_strong_mac_conflict_does_not_get_exact_ip_boost(self):
        prev = {
            'ip': '192.168.0.152', 'hostname': 'Voloshyn', 'mac': '00:11:22:33:44:55',
            'vendor': 'Intel', 'open_ports': [139, 445], 'role': 'NetBIOS, SMB / file-sharing'
        }
        cur = {
            'ip': '192.168.0.152', 'hostname': 'Voloshyn', 'mac': '10:11:22:33:44:55',
            'vendor': 'Intel', 'open_ports': [139, 445], 'role': 'NetBIOS, SMB / file-sharing'
        }
        scored = score_host_pair(prev, cur)
        self.assertNotEqual(scored['decision'], 'auto-link')
        self.assertTrue(any('перевикористання IP' in p for p in scored['penalties']))

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
        self.assertTrue(all('identity confidence' not in e.get('description', '') for e in events))
        self.assertTrue(all('decision:' not in e.get('description', '') for e in events))

    def test_compare_scans_does_not_create_new_and_disappeared_for_same_ip_without_mac(self):
        previous_hosts = [
            {'ip': '192.168.0.152', 'hostname': 'Voloshyn', 'mac': '', 'vendor': '', 'open_ports': [139, 445], 'role': 'NetBIOS, SMB / file-sharing'}
        ]
        current_hosts = [
            {'ip': '192.168.0.152', 'hostname': 'Voloshyn', 'mac': '', 'vendor': '', 'open_ports': [139, 445], 'role': 'NetBIOS, SMB / file-sharing'}
        ]
        events = compare_scans(previous_hosts, current_hosts)
        bad_events = [
            e for e in events
            if e.get('ip') == '192.168.0.152' and e.get('event_type') in {'NEW_HOST', 'HOST_DISAPPEARED'}
        ]
        self.assertEqual(bad_events, [])


class AnalyzerLocalizationTests(unittest.TestCase):
    def test_ambiguous_match_description_is_ukrainian(self):
        previous = [{
            'ip': '192.168.0.10', 'hostname': 'printer-office', 'mac': '02:11:22:33:44:55',
            'vendor': '', 'open_ports': [80], 'role': 'web-сервер'
        }]
        current = [{
            'ip': '192.168.0.45', 'hostname': 'printer-office', 'mac': '02:11:22:33:44:55',
            'vendor': '', 'open_ports': [80, 443], 'role': 'web-сервер, альтернативний web-сервіс'
        }]

        events = compare_scans(previous, current)
        ambiguous_events = [e for e in events if e.get('event_type') == 'HOST_AMBIGUOUS_MATCH']

        self.assertTrue(ambiguous_events)
        self.assertIn('Невизначене зіставлення хоста', ambiguous_events[0]['description'])
        self.assertIn('Потрібна ручна перевірка', ambiguous_events[0]['description'])


if __name__ == '__main__':
    unittest.main()
