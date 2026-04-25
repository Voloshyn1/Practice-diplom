from storage import get_previous_scan_id, load_hosts_for_scan
from identity_matcher import match_hosts


def get_previous_scan_data(network: str, current_scan_id: int) -> tuple[int | None, list[dict]]:
    """
    Повертає id попереднього сканування для мережі і список його хостів.
    Якщо попереднього сканування немає, повертає (None, []).
    """
    previous_scan_id = get_previous_scan_id(network, current_scan_id)
    if previous_scan_id is None:
        return None, []

    previous_hosts = load_hosts_for_scan(previous_scan_id)
    return previous_scan_id, previous_hosts


def compare_scans(previous_hosts: list[dict], current_hosts: list[dict]) -> list[dict]:
    """
    Порівнює два результати сканування і повертає список подій змін.
    """
    events: list[dict] = []

    matched = match_hosts(previous_hosts, current_hosts)

    for link in matched["links"]:
        prev_host = link["prev"]
        cur_host = link["cur"]
        score = link["score"]
        decision = link["decision"]
        reasons = "; ".join(link.get("reasons", []))

        prev_ip = (prev_host.get("ip") or "").strip()
        cur_ip = (cur_host.get("ip") or "").strip()
        event_ip = cur_ip or prev_ip

        if prev_ip and cur_ip and prev_ip != cur_ip:
            events.append({
                "ip": event_ip,
                "event_type": "HOST_IP_CHANGED",
                "old_value": prev_ip,
                "new_value": cur_ip,
                "description": (
                    f"Пристрій змінив IP-адресу: {prev_ip} -> {cur_ip} "
                    f"(identity confidence: {score}, decision: {decision})"
                ),
                "match_confidence": score,
                "match_decision": decision,
                "match_reasons": reasons,
            })

        prev_ports = set(prev_host.get("open_ports", []))
        cur_ports = set(cur_host.get("open_ports", []))
        for port in sorted(cur_ports - prev_ports):
            events.append({
                "ip": event_ip,
                "event_type": "NEW_PORT_OPENED",
                "old_value": "",
                "new_value": str(port),
                "description": (
                    f"На хості {event_ip} відкрився порт {port} "
                    f"(identity confidence: {score}, decision: {decision})"
                ),
                "match_confidence": score,
                "match_decision": decision,
                "match_reasons": reasons,
            })
        for port in sorted(prev_ports - cur_ports):
            events.append({
                "ip": event_ip,
                "event_type": "PORT_CLOSED",
                "old_value": str(port),
                "new_value": "",
                "description": (
                    f"На хості {event_ip} закрився порт {port} "
                    f"(identity confidence: {score}, decision: {decision})"
                ),
                "match_confidence": score,
                "match_decision": decision,
                "match_reasons": reasons,
            })

        prev_role = (prev_host.get("role") or "").strip()
        cur_role = (cur_host.get("role") or "").strip()
        if prev_role != cur_role:
            events.append({
                "ip": event_ip,
                "event_type": "ROLE_CHANGED",
                "old_value": prev_role,
                "new_value": cur_role,
                "description": (
                    f"На хості {event_ip} змінилася роль: {prev_role} -> {cur_role} "
                    f"(identity confidence: {score}, decision: {decision})"
                ),
                "match_confidence": score,
                "match_decision": decision,
                "match_reasons": reasons,
            })

    for ambiguous in matched["ambiguous"]:
        cur = ambiguous["cur"]
        cur_ip = (cur.get("ip") or "").strip()
        top = ambiguous["candidates"][0]
        prev_ip = (top["prev"].get("ip") or "").strip()
        events.append({
            "ip": cur_ip,
            "event_type": "HOST_AMBIGUOUS_MATCH",
            "old_value": prev_ip,
            "new_value": cur_ip,
            "description": (
                f"Ambiguous identity match for host {cur_ip}: "
                f"top candidate {prev_ip} score {top['score']}. Manual review required."
            ),
            "match_confidence": top["score"],
            "match_decision": "ambiguous",
            "match_reasons": "; ".join(top.get("reasons", [])),
        })

    for host in matched["unmatched_current"]:
        ip = (host.get("ip") or "").strip()
        events.append({
            "ip": ip,
            "event_type": "NEW_HOST",
            "old_value": "",
            "new_value": "active",
            "description": f"Новий хост у мережі: {ip}",
        })

    for host in matched["unmatched_previous"]:
        ip = (host.get("ip") or "").strip()
        events.append({
            "ip": ip,
            "event_type": "HOST_DISAPPEARED",
            "old_value": "active",
            "new_value": "",
            "description": f"Хост зник із мережі: {ip}",
        })

    return events
