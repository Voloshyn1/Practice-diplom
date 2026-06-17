import pytest

from report import disappeared_hosts_phrase, display_attention_level, format_ukrainian_count, build_scan_summary


@pytest.mark.parametrize("number,expected", [
    (0, "0 змін"), (1, "1 зміна"), (2, "2 зміни"), (4, "4 зміни"),
    (5, "5 змін"), (11, "11 змін"), (12, "12 змін"), (14, "14 змін"),
    (20, "20 змін"), (21, "21 зміна"), (22, "22 зміни"), (25, "25 змін"),
    (101, "101 зміна"), (111, "111 змін"),
])
def test_ukrainian_change_forms(number, expected):
    assert format_ukrainian_count(number, "зміна", "зміни", "змін") == expected


@pytest.mark.parametrize("number,expected", [(1, "1 хост"), (2, "2 хости"), (5, "5 хостів")])
def test_ukrainian_host_forms(number, expected):
    assert format_ukrainian_count(number, "хост", "хости", "хостів") == expected


@pytest.mark.parametrize("number,expected", [(1, "1 порт"), (2, "2 порти"), (5, "5 портів")])
def test_ukrainian_port_forms(number, expected):
    assert format_ukrainian_count(number, "порт", "порти", "портів") == expected


def test_disappeared_host_phrase_grammar():
    assert disappeared_hosts_phrase(1) == "1 хост зник"
    assert disappeared_hosts_phrase(2) == "2 хости зникли"
    assert disappeared_hosts_phrase(5) == "5 хостів зникли"


def test_summary_uses_ukrainian_attention_level():
    text = build_scan_summary(
        network="192.168.0.0/24",
        active_host_count=1,
        events=[{"event_type": "NEW_HOST"}],
        host_scores=[{"ip": "192.168.0.10", "attention_score": 20, "attention_level": "Moderate", "reasons": ["Новий хост"]}],
        has_previous_scan=True,
    )
    assert "Помірний" in text
    assert "Moderate" not in text


def test_display_attention_level_unknown_falls_back():
    assert display_attention_level("High") == "Високий"
    assert display_attention_level("Custom") == "Custom"
