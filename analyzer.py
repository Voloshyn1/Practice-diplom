from storage import get_previous_scan_id, load_hosts_for_scan


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


def _hosts_by_ip(hosts: list[dict]) -> dict[str, dict]:
    return {h.get("ip", ""): h for h in hosts if h.get("ip")}


def compare_scans(previous_hosts: list[dict], current_hosts: list[dict]) -> list[dict]:
    """
    Порівнює два результати сканування і повертає список подій змін.
    """
    events: list[dict] = []

    prev_by_ip = _hosts_by_ip(previous_hosts)
    cur_by_ip = _hosts_by_ip(current_hosts)

    previous_ips = set(prev_by_ip.keys())
    current_ips = set(cur_by_ip.keys())

    # NEW_HOST: в поточному є, в попередньому не було
    for ip in sorted(current_ips - previous_ips):
        events.append({
            "ip": ip,
            "event_type": "NEW_HOST",
            "old_value": "",
            "new_value": "active",
            "description": f"Новий хост у мережі: {ip}",
        })

    # HOST_DISAPPEARED: був у попередньому, у поточному немає
    for ip in sorted(previous_ips - current_ips):
        events.append({
            "ip": ip,
            "event_type": "HOST_DISAPPEARED",
            "old_value": "active",
            "new_value": "",
            "description": f"Хост зник із мережі: {ip}",
        })

    # Спільні IP: порівняння портів і ролі
    for ip in sorted(previous_ips & current_ips):
        prev_host = prev_by_ip[ip]
        cur_host = cur_by_ip[ip]

        prev_ports = set(prev_host.get("open_ports", []))
        cur_ports = set(cur_host.get("open_ports", []))

        # NEW_PORT_OPENED
        for port in sorted(cur_ports - prev_ports):
            events.append({
                "ip": ip,
                "event_type": "NEW_PORT_OPENED",
                "old_value": "",
                "new_value": str(port),
                "description": f"На хості {ip} відкрився порт {port}",
            })

        # PORT_CLOSED
        for port in sorted(prev_ports - cur_ports):
            events.append({
                "ip": ip,
                "event_type": "PORT_CLOSED",
                "old_value": str(port),
                "new_value": "",
                "description": f"На хості {ip} закрився порт {port}",
            })

        # ROLE_CHANGED
        prev_role = (prev_host.get("role") or "").strip()
        cur_role = (cur_host.get("role") or "").strip()
        if prev_role != cur_role:
            events.append({
                "ip": ip,
                "event_type": "ROLE_CHANGED",
                "old_value": prev_role,
                "new_value": cur_role,
                "description": f"На хості {ip} змінилася роль: {prev_role} -> {cur_role}",
            })

    return events
