from risk import calculate_host_scores, derive_attention_level


def test_ambiguous_identity_is_not_low():
    scores = calculate_host_scores([{"ip": "192.168.0.10", "event_type": "HOST_AMBIGUOUS_MATCH", "match_decision": "ambiguous"}])
    assert scores[0]["attention_score"] >= 20
    assert scores[0]["attention_level"] != "Low"


def test_score_clamped_to_100_with_many_events_and_bonuses():
    events = [{"ip": "192.168.0.10", "event_type": "NEW_PORT_OPENED", "new_value": "3389"} for _ in range(10)]
    assert calculate_host_scores(events)[0]["attention_score"] == 100


def test_event_without_ip_and_unknown_event_are_safe():
    assert calculate_host_scores([{"event_type": "NEW_HOST"}]) == []
    scores = calculate_host_scores([{"ip": "192.168.0.20", "event_type": "UNKNOWN"}])
    assert scores[0]["attention_score"] == 0
    assert derive_attention_level(scores[0]["attention_score"]) == "Low"


def test_port_bonuses_and_reason_deduplication():
    events = [
        {"ip": "192.168.0.10", "event_type": "NEW_PORT_OPENED", "new_value": "22"},
        {"ip": "192.168.0.10", "event_type": "NEW_PORT_OPENED", "new_value": "3389"},
        {"ip": "192.168.0.10", "event_type": "NEW_PORT_OPENED", "new_value": "445"},
    ]
    score = calculate_host_scores(events)[0]
    assert score["attention_score"] == 91
    assert score["reasons"].count("Виявлено сервіс віддаленого доступу") == 1
    assert "Виявлено SMB-сервіс" in score["reasons"]
