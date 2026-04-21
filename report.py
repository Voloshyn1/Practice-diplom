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
        f"{total_changes} змін: {new_hosts} нових хостів, "
        f"{disappeared_hosts} хостів зникли, {port_changes} змін портів."
    )

    if host_scores:
        lines.append("Найбільш важливі хости за рівнем уваги:")
        for idx, item in enumerate(host_scores[:3], start=1):
            reasons = item.get("reasons", [])
            short_reason = reasons[0] if reasons else "без уточнення"
            lines.append(
                f"{idx}. {item.get('ip', '')} — "
                f"{item.get('attention_score', 0)} ({item.get('attention_level', 'Low')}): "
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
