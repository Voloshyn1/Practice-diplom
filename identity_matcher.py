from __future__ import annotations

import difflib
import ipaddress
import re


def normalize_mac(mac: str) -> str:
    raw = (mac or "").strip().upper().replace("-", ":")
    if not raw:
        return ""
    hex_only = re.sub(r"[^0-9A-F]", "", raw)
    if len(hex_only) != 12:
        return ""
    return ":".join(hex_only[i:i + 2] for i in range(0, 12, 2))


def is_locally_administered_mac(mac: str) -> bool:
    norm = normalize_mac(mac)
    if not norm:
        return False
    first_octet = int(norm.split(":")[0], 16)
    return (first_octet & 0b00000010) != 0


def normalize_hostname(hostname: str) -> str:
    text = (hostname or "").strip().lower()
    if not text:
        return ""
    if text.endswith(".local"):
        text = text[:-6]
    text = text.split(".")[0]
    return text.strip()


def hostname_similarity(a: str, b: str) -> float:
    na = normalize_hostname(a)
    nb = normalize_hostname(b)
    if not na or not nb:
        return 0.0
    if na == nb:
        return 1.0
    return difflib.SequenceMatcher(a=na, b=nb).ratio()


def jaccard_similarity(a: list[int], b: list[int]) -> float:
    sa = set(a or [])
    sb = set(b or [])
    if not sa and not sb:
        return 0.0
    union = sa | sb
    if not union:
        return 0.0
    return len(sa & sb) / len(union)


def _tokenize_role(role: str) -> set[str]:
    text = (role or "").lower()
    parts = re.split(r"[^a-zа-яіїє0-9]+", text)
    return {p for p in parts if p}


def role_similarity(a: str, b: str) -> float:
    ta = _tokenize_role(a)
    tb = _tokenize_role(b)
    if not ta or not tb:
        return 0.0
    union = ta | tb
    if not union:
        return 0.0
    return len(ta & tb) / len(union)


def _mac_evidence(prev: dict, cur: dict) -> tuple[float, str]:
    prev_mac = normalize_mac(prev.get("mac", ""))
    cur_mac = normalize_mac(cur.get("mac", ""))
    if prev_mac and cur_mac and prev_mac == cur_mac:
        if is_locally_administered_mac(prev_mac):
            return 0.65, "MAC збіг (локально адміністрована адреса)"
        return 1.0, "MAC збіг"

    if prev_mac and cur_mac:
        prev_prefix = prev_mac[:8]
        cur_prefix = cur_mac[:8]
        if prev_prefix == cur_prefix:
            return 0.2, "Збіг OUI-префіксу MAC"

    return 0.0, ""


def _ip_evidence(prev: dict, cur: dict) -> tuple[float, str]:
    prev_ip = (prev.get("ip") or "").strip()
    cur_ip = (cur.get("ip") or "").strip()
    if not prev_ip or not cur_ip:
        return 0.0, ""
    if prev_ip == cur_ip:
        return 1.0, "IP збіг"
    try:
        p = ipaddress.ip_address(prev_ip)
        c = ipaddress.ip_address(cur_ip)
        if p.version == 4 and c.version == 4:
            if str(p).rsplit(".", 1)[0] == str(c).rsplit(".", 1)[0]:
                return 0.3, "Той самий /24 сегмент"
    except ValueError:
        return 0.0, ""
    return 0.0, ""


def score_host_pair(prev: dict, cur: dict) -> dict:
    mac_evidence, mac_reason = _mac_evidence(prev, cur)
    ip_evidence, ip_reason = _ip_evidence(prev, cur)
    host_evidence = hostname_similarity(prev.get("hostname", ""), cur.get("hostname", ""))
    port_evidence = jaccard_similarity(prev.get("open_ports", []), cur.get("open_ports", []))
    role_evidence = role_similarity(prev.get("role", ""), cur.get("role", ""))

    prev_vendor = (prev.get("vendor") or "").strip()
    cur_vendor = (cur.get("vendor") or "").strip()
    vendor_evidence = 1.0 if (
        prev_vendor and cur_vendor and
        prev_vendor.lower() != "unknown" and
        cur_vendor.lower() != "unknown" and
        prev_vendor == cur_vendor
    ) else 0.0

    base_score = 100 * (
        0.50 * mac_evidence +
        0.15 * ip_evidence +
        0.12 * host_evidence +
        0.10 * port_evidence +
        0.08 * role_evidence +
        0.05 * vendor_evidence
    )
    score = int(round(base_score))

    reasons: list[str] = []
    penalties: list[str] = []

    if mac_reason:
        reasons.append(mac_reason)
    if ip_reason:
        reasons.append(ip_reason)
    if host_evidence >= 0.99:
        reasons.append("Hostname збіг")
    elif host_evidence >= 0.70:
        reasons.append(f"Hostname схожий ({host_evidence:.2f})")
    if port_evidence >= 0.5:
        reasons.append(f"Схожий набір портів ({port_evidence:.2f})")
    if role_evidence >= 0.5:
        reasons.append(f"Схожа роль ({role_evidence:.2f})")
    if vendor_evidence == 1.0:
        reasons.append("Vendor збіг")

    prev_mac = normalize_mac(prev.get("mac", ""))
    cur_mac = normalize_mac(cur.get("mac", ""))
    prev_ip = (prev.get("ip") or "").strip()
    cur_ip = (cur.get("ip") or "").strip()

    strong_mac_conflict = (
        prev_ip and cur_ip and prev_ip == cur_ip and
        prev_mac and cur_mac and prev_mac != cur_mac and
        not is_locally_administered_mac(prev_mac) and
        not is_locally_administered_mac(cur_mac)
    )

    if strong_mac_conflict:
        score -= 20
        penalties.append("IP збігається, але MAC різний (можливе перевикористання IP)")

    if prev_mac and cur_mac and prev_mac == cur_mac:
        if host_evidence < 0.30 and port_evidence < 0.20:
            score -= 8
            penalties.append("MAC збіг без підтримки hostname/портів")

    # Пост-правила для кейсів без MAC, коли інші стабільні ознаки узгоджені.
    if (
        prev_ip and cur_ip and prev_ip == cur_ip and
        not strong_mac_conflict and
        host_evidence >= 0.90 and
        port_evidence >= 0.80 and
        role_evidence >= 0.80
    ):
        if score < 75:
            score = 75
        reasons.append("IP збігається, hostname, порти та роль підтверджують схожість без MAC")
    elif (
        prev_ip and cur_ip and prev_ip == cur_ip and
        not strong_mac_conflict and
        host_evidence >= 0.90 and
        (port_evidence >= 0.50 or role_evidence >= 0.50)
    ):
        if score < 65:
            score = 65
        reasons.append("IP збігається і є додаткові ознаки hostname/сервісів")

    score = max(0, min(100, score))

    if score >= 85:
        decision = "auto-link"
    elif score >= 70:
        decision = "probable-link"
    elif score >= 55:
        decision = "ambiguous"
    else:
        decision = "no-link"

    return {
        "score": score,
        "decision": decision,
        "features": {
            "mac_evidence": round(mac_evidence, 3),
            "ip_evidence": round(ip_evidence, 3),
            "hostname_evidence": round(host_evidence, 3),
            "port_evidence": round(port_evidence, 3),
            "role_evidence": round(role_evidence, 3),
            "vendor_evidence": round(vendor_evidence, 3),
        },
        "reasons": reasons,
        "penalties": penalties,
    }


def match_hosts(previous_hosts: list[dict], current_hosts: list[dict]) -> dict:
    pair_scores: list[dict] = []
    for prev_idx, prev in enumerate(previous_hosts):
        for cur_idx, cur in enumerate(current_hosts):
            scored = score_host_pair(prev, cur)
            pair_scores.append({
                "prev_idx": prev_idx,
                "cur_idx": cur_idx,
                "prev": prev,
                "cur": cur,
                "score": scored["score"],
                "decision": scored["decision"],
                "reasons": scored["reasons"],
                "features": scored["features"],
                "penalties": scored["penalties"],
            })

    pair_scores.sort(
        key=lambda x: (
            -x["score"],
            (x["prev"].get("ip") or ""),
            (x["cur"].get("ip") or ""),
        )
    )

    used_prev: set[int] = set()
    used_cur: set[int] = set()
    links: list[dict] = []

    for pair in pair_scores:
        if pair["prev_idx"] in used_prev or pair["cur_idx"] in used_cur:
            continue
        if pair["decision"] in {"auto-link", "probable-link"}:
            links.append(pair)
            used_prev.add(pair["prev_idx"])
            used_cur.add(pair["cur_idx"])

    ambiguous: list[dict] = []
    ambiguous_prev_idx: set[int] = set()
    for cur_idx, cur in enumerate(current_hosts):
        if cur_idx in used_cur:
            continue
        candidates = [
            p for p in pair_scores
            if p["cur_idx"] == cur_idx
            and p["prev_idx"] not in used_prev
            and p["decision"] == "ambiguous"
        ]
        if candidates:
            candidates.sort(key=lambda x: -x["score"])
            for cand in candidates:
                ambiguous_prev_idx.add(cand["prev_idx"])
            ambiguous.append({
                "cur": cur,
                "candidates": [
                    {
                        "prev": c["prev"],
                        "score": c["score"],
                        "reasons": c["reasons"],
                    }
                    for c in candidates[:3]
                ],
            })

    ambiguous_cur_ids = {id(item["cur"]) for item in ambiguous}
    unmatched_previous = [
        host for idx, host in enumerate(previous_hosts)
        if idx not in used_prev and idx not in ambiguous_prev_idx
    ]
    unmatched_current = [
        host for idx, host in enumerate(current_hosts)
        if idx not in used_cur and id(host) not in ambiguous_cur_ids
    ]

    return {
        "links": links,
        "ambiguous": ambiguous,
        "unmatched_previous": unmatched_previous,
        "unmatched_current": unmatched_current,
    }
