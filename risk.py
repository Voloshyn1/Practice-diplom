BASE_EVENT_SCORES = {
    "NEW_HOST": 20,
    "HOST_DISAPPEARED": 12,
    "HOST_IP_CHANGED": 10,
    "HOST_AMBIGUOUS_MATCH": 18,
    "NEW_PORT_OPENED": 12,
    "PORT_CLOSED": 4,
    "ROLE_CHANGED": 10,
}


def _extract_port(event: dict) -> int | None:
    raw_value = (event.get("new_value") or event.get("old_value") or "").strip()
    if not raw_value:
        return None
    try:
        return int(raw_value)
    except ValueError:
        return None


def derive_attention_level(score: int) -> str:
    if score <= 19:
        return "Low"
    if score <= 39:
        return "Moderate"
    if score <= 59:
        return "Elevated"
    if score <= 79:
        return "High"
    return "Critical"


def build_reasons_for_host(events: list[dict]) -> list[str]:
    """
    Формує короткий перелік причин оцінки уваги для хоста.
    """
    reasons: list[str] = []

    for event in events:
        event_type = event.get("event_type", "")
        port = _extract_port(event)

        if event_type == "NEW_HOST":
            reasons.append("Новий хост у мережі")
        elif event_type == "HOST_DISAPPEARED":
            reasons.append("Хост зник із мережі")
        elif event_type == "NEW_PORT_OPENED":
            if port is not None:
                reasons.append(f"На хості відкрився порт {port}")
            else:
                reasons.append("На хості відкрився новий порт")
            if port in (22, 3389):
                reasons.append("Виявлено сервіс віддаленого доступу")
            if port == 445:
                reasons.append("Виявлено SMB-сервіс")
        elif event_type == "PORT_CLOSED":
            if port is not None:
                reasons.append(f"На хості закрився порт {port}")
            else:
                reasons.append("На хості закрився порт")
        elif event_type == "ROLE_CHANGED":
            reasons.append("Змінилася роль вузла")
        elif event_type == "HOST_IP_CHANGED":
            reasons.append("Пристрій змінив IP-адресу")
        elif event_type == "HOST_AMBIGUOUS_MATCH":
            reasons.append("Невизначене зіставлення хоста між сканами")
            reasons.append("Потрібна ручна перевірка ідентичності пристрою")

        match_decision = (event.get("match_decision") or "").strip()
        if match_decision == "ambiguous":
            reasons.append("Ідентичність хоста визначена з низькою впевненістю")
        elif match_decision == "probable-link":
            reasons.append("Ймовірне зіставлення хоста між сканами")

    # Уникаємо дублювання причин, зберігаючи порядок
    unique_reasons = list(dict.fromkeys(reasons))
    return unique_reasons


def calculate_host_scores(events: list[dict]) -> list[dict]:
    """
    Рахує увагу по кожному хосту на основі подій поточного сканування.
    """
    by_ip: dict[str, list[dict]] = {}
    for event in events:
        ip = event.get("ip", "")
        if not ip:
            continue
        by_ip.setdefault(ip, []).append(event)

    scores: list[dict] = []
    for ip, host_events in by_ip.items():
        score = 0
        for event in host_events:
            event_type = event.get("event_type", "")
            score += BASE_EVENT_SCORES.get(event_type, 0)

            if event_type == "NEW_PORT_OPENED":
                port = _extract_port(event)
                if port == 22:
                    score += 10
                elif port == 3389:
                    score += 20
                elif port == 445:
                    score += 15

        # Бонус за кілька змін на одному хості в межах одного сканування
        if len(host_events) >= 2:
            score += 10

        score = max(0, min(100, score))
        scores.append({
            "ip": ip,
            "attention_score": score,
            "attention_level": derive_attention_level(score),
            "reasons": build_reasons_for_host(host_events),
        })

    scores.sort(key=lambda x: (-x["attention_score"], x["ip"]))
    return scores


def calculate_scan_attention_total(scores: list[dict]) -> int:
    """
    Загальна оцінка уваги для сканування:
    беремо найвищу оцінку хоста (0..100).
    """
    if not scores:
        return 0
    top_score = max(int(item.get("attention_score", 0)) for item in scores)
    return max(0, min(100, top_score))
