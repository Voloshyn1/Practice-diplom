import unittest

from oui_data import lookup_vendor_by_mac, normalize_oui_prefix
from scanner import get_vendor_from_mac


class OuiDataTests(unittest.TestCase):
    def test_normalize_oui_prefix_accepts_common_mac_formats(self):
        self.assertEqual(normalize_oui_prefix("00:50:56:AA:BB:CC"), "00:50:56")
        self.assertEqual(normalize_oui_prefix("00-50-56-AA-BB-CC"), "00:50:56")
        self.assertEqual(normalize_oui_prefix("005056AABBCC"), "00:50:56")

    def test_normalize_oui_prefix_rejects_empty_or_invalid_values(self):
        self.assertEqual(normalize_oui_prefix(""), "")
        self.assertEqual(normalize_oui_prefix("not-a-mac"), "")

    def test_lookup_vendor_by_mac_returns_known_unknown_and_empty(self):
        self.assertEqual(lookup_vendor_by_mac("00:50:56:AA:BB:CC"), "VMware")
        self.assertEqual(lookup_vendor_by_mac("AA:BB:CC:DD:EE:FF"), "Unknown")
        self.assertEqual(lookup_vendor_by_mac(""), "")

    def test_scanner_vendor_lookup_delegates_to_oui_data(self):
        self.assertEqual(get_vendor_from_mac("08-00-27-AA-BB-CC"), "Oracle / VirtualBox")


if __name__ == "__main__":
    unittest.main()
