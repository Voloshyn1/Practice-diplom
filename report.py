ATTENTION_LEVEL_UK = {
    "Low": "Низький",
    "Moderate": "Помірний",
    "Elevated": "Підвищений",
    "High": "Високий",
    "Critical": "Критичний",
}


def ukrainian_plural(number: int, one: str, few: str, many: str) -> str:
    abs_number = abs(number)
    last_two = abs_number % 100
    last = abs_number % 10
    if 11 <= last_two <= 14:
        return many
    if last == 1:
        return one
    if 2 <= last <= 4:
        return few
    return many


def format_ukrainian_count(number: int, one: str, few: str, many: str) -> str:
    return f"{number} {ukrainian_plural(number, one, few, many)}"


def disappeared_hosts_phrase(number: int) -> str:
    noun = ukrainian_plural(number, "хост", "хости", "хостів")
    verb = "зник" if abs(number) % 10 == 1 and abs(number) % 100 != 11 else "зникли"
    return f"{number} {noun} {verb}"


def display_attention_level(level: str) -> str:
    return ATTENTION_LEVEL_UK.get(level, level)


def build_scan_summary(
    *,
    network: str,
    active_host_count: int,
    events: list[dict],
    host_scores: list[dict],
    has_previous_scan: bool,
) -> str:
    """
    Формує компактний текстовий підсумок сканування.
    """
    total_changes = len(events)
    new_hosts = sum(1 for e in events if e.get("event_type") == "NEW_HOST")
    disappeared_hosts = sum(1 for e in events if e.get("event_type") == "HOST_DISAPPEARED")
    port_changes = sum(
        1 for e in events if e.get("event_type") in {"NEW_PORT_OPENED", "PORT_CLOSED"}
    )
    ambiguous_identity_events = sum(
        1 for e in events
        if e.get("event_type") == "HOST_AMBIGUOUS_MATCH"
        or e.get("match_decision") == "ambiguous"
    )

    lines = [
        f"Сканування мережі {network} завершено.",
        f"Виявлено активних хостів: {active_host_count}.",
    ]

    if not has_previous_scan:
        lines.append("Попереднього сканування для порівняння не знайдено.")
        lines.append("Операторська підказка: виконайте наступне сканування для аналізу змін.")
        return "\n".join(lines)

    lines.append(
        "Порівняно з попереднім скануванням знайдено "
        f"{format_ukrainian_count(total_changes, 'зміну', 'зміни', 'змін')}: "
        f"{format_ukrainian_count(new_hosts, 'новий хост', 'нові хости', 'нових хостів')}, "
        f"{disappeared_hosts_phrase(disappeared_hosts)}, "
        f"{format_ukrainian_count(port_changes, 'зміну портів', 'зміни портів', 'змін портів')}."
    )

    if ambiguous_identity_events:
        lines.append("Частина змін має невизначену ідентичність хоста та потребує ручної перевірки.")

    if host_scores:
        lines.append("Найбільш важливі хости за рівнем уваги:")
        for idx, item in enumerate(host_scores[:3], start=1):
            reasons = item.get("reasons", [])
            short_reason = reasons[0] if reasons else "без уточнення"
            lines.append(
                f"{idx}. {item.get('ip', '')} — "
                f"{item.get('attention_score', 0)} "
                f"({display_attention_level(item.get('attention_level', 'Low'))}): "
                f"{short_reason}."
            )
    else:
        lines.append("Змін порівняно з попереднім скануванням не виявлено.")

    if any("віддаленого доступу" in " ".join(s.get("reasons", [])) for s in host_scores):
        lines.append("Операторська підказка: перевірте нові сервіси віддаленого доступу.")
    elif total_changes > 0:
        lines.append("Операторська підказка: перевірте зміни конфігурації на змінених хостах.")
    else:
        lines.append("Операторська підказка: стан мережі стабільний, продовжуйте періодичний моніторинг.")

    return "\n".join(lines)
