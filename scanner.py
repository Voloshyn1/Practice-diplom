import ipaddress          # для роботи з підмережами типу 192.168.0.0/24
import platform
import re
import subprocess         # для запуску системної команди ping
import socket             # для перевірки TCP-портів
from concurrent.futures import ThreadPoolExecutor, as_completed

from oui_data import lookup_vendor_by_mac
from ports_data import DEFAULT_TCP_PORTS, PORT_SERVICE_LABELS

# Типові порти, які будемо перевіряти на кожному живому хості
DEFAULT_PORTS = DEFAULT_TCP_PORTS
DEFAULT_DISCOVERY_MODE = "mixed"
DEFAULT_MAX_WORKERS = 64
MAX_SCAN_HOSTS = 4096


def ping_host(ip: str, timeout_sec: float = 0.3) -> bool:
    """
    Перевіряє, чи відповідає хост на ping.
    Повертає True, якщо є відповідь, і False, якщо ні.
    """
    os_name = platform.system().lower()

    if os_name == "windows":
        timeout_ms = max(1, int(timeout_sec * 1000))
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        # Для Linux/macOS: 1 echo-запит, а обмеження часу додатково
        # контролюється через timeout у subprocess.run.
        cmd = ["ping", "-c", "1", ip]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=max(1.0, timeout_sec + 0.7),
        )
        return result.returncode == 0  # 0 = успіх (є відповідь)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def scan_ports(ip: str, ports=None, timeout: float = 0.3) -> list[int]:
    """
    Перевіряє, які TCP-порти із заданого списку відкриті на вказаному IP.
    Повертає список відкритих портів.
    """
    if ports is None:
        ports = DEFAULT_PORTS

    open_ports: list[int] = []

    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            try:
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
            except OSError:
                # якщо якась помилка з сокетом – просто пропускаємо порт
                pass

    return open_ports


def resolve_hostname(ip: str) -> str:
    """
    Best-effort reverse DNS.
    Якщо ім'я не знайдено, повертає порожній рядок.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname or ""
    except (socket.herror, socket.gaierror, TimeoutError, OSError):
        return ""


def _normalize_mac(mac: str) -> str:
    cleaned = mac.strip().replace("-", ":").upper()
    return cleaned


def get_mac_address(ip: str) -> str:
    """
    Best-effort отримання MAC через локальну ARP-таблицю.
    Може не працювати на всіх ОС/мережах (це очікувана деградація).
    """
    os_name = platform.system().lower()
    commands: list[list[str]] = []
    if os_name == "windows":
        commands = [["arp", "-a", ip]]
    else:
        commands = [["arp", "-n", ip], ["arp", ip]]

    mac_pattern = re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")
    for cmd in commands:
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=1.0,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

        match = mac_pattern.search(result.stdout or "")
        if match:
            return _normalize_mac(match.group(0))

    return ""


def get_vendor_from_mac(mac: str) -> str:
    """
    Best-effort визначення виробника з OUI (локально, без зовнішніх API).
    """
    return lookup_vendor_by_mac(mac)


def classify_host(open_ports: list[int]) -> str:
    """
    За списком відкритих портів повертає текстове пояснення ролі хоста.
    Наприклад: "web-сервер, SSH".
    """
    if not open_ports:
        return "—"

    ports_set = set(open_ports)
    labels: list[str] = []

    for port in sorted(ports_set):
        label = PORT_SERVICE_LABELS.get(port)
        if label and label not in labels:
            labels.append(label)

    if not labels:
        labels.append("невідомий сервіс")

    return ", ".join(labels)


def _scan_single_host(
    ip_str: str,
    ports: list[int],
    discovery_mode: str,
    timeout: float,
) -> dict | None:
    """
    Сканує один хост і повертає host_info або None.
    """
    discovery_mode = (discovery_mode or DEFAULT_DISCOVERY_MODE).lower()

    ping_ok = False
    open_ports: list[int] = []
    is_alive = False

    if discovery_mode == "icmp":
        ping_ok = ping_host(ip_str, timeout_sec=timeout)
        is_alive = ping_ok
        if is_alive:
            open_ports = scan_ports(ip_str, ports=ports, timeout=timeout)
    elif discovery_mode == "tcp":
        open_ports = scan_ports(ip_str, ports=ports, timeout=timeout)
        is_alive = len(open_ports) > 0
    else:  # mixed (default)
        ping_ok = ping_host(ip_str, timeout_sec=timeout)
        if ping_ok:
            is_alive = True
            open_ports = scan_ports(ip_str, ports=ports, timeout=timeout)
        else:
            open_ports = scan_ports(ip_str, ports=ports, timeout=timeout)
            is_alive = len(open_ports) > 0

    if not is_alive:
        return None

    role = classify_host(open_ports)
    hostname = resolve_hostname(ip_str)
    mac = get_mac_address(ip_str)
    vendor = get_vendor_from_mac(mac)

    return {
        "ip": ip_str,
        "hostname": hostname,
        "mac": mac,
        "vendor": vendor,
        "open_ports": open_ports,
        "role": role,
    }


def scan_network(
    network_cidr: str,
    ports=None,
    progress_cb=None,
    discovery_mode: str = DEFAULT_DISCOVERY_MODE,
    max_workers: int = DEFAULT_MAX_WORKERS,
    timeout: float = 0.3,
) -> list[dict]:
    try:
        network = ipaddress.ip_network(network_cidr, strict=False)
    except ValueError as exc:
        raise ValueError("Invalid CIDR network.") from exc

    if network.version != 4:
        raise ValueError("Only IPv4 networks are supported by this scanner.")

    if network.num_addresses > MAX_SCAN_HOSTS:
        raise ValueError(
            f"The subnet contains too many addresses. Maximum allowed: {MAX_SCAN_HOSTS}."
        )

    alive_hosts: list[dict] = []

    ports = ports or DEFAULT_PORTS
    all_ips = [str(ip) for ip in network.hosts()]
    total = len(all_ips)

    workers = max(1, min(max_workers, 256))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_ip = {
            executor.submit(
                _scan_single_host,
                ip_str,
                ports,
                discovery_mode,
                timeout,
            ): ip_str
            for ip_str in all_ips
        }

        completed = 0
        for future in as_completed(future_to_ip):
            completed += 1
            try:
                host_info = future.result()
            except Exception:
                # A failure while probing one address should not abort the whole
                # subnet scan. The failed host is skipped and progress continues.
                host_info = None
            if host_info is not None:
                alive_hosts.append(host_info)
            if progress_cb is not None:
                progress_cb(completed, total, host_info)

    alive_hosts.sort(key=lambda h: ipaddress.ip_address(h["ip"]))
    return alive_hosts
