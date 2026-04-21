import ipaddress          # для роботи з підмережами типу 192.168.0.0/24
import platform
import subprocess         # для запуску системної команди ping
import socket             # для перевірки TCP-портів


# Типові порти, які будемо перевіряти на кожному живому хості
DEFAULT_PORTS = [22, 80, 443, 3389, 445]


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


def classify_host(open_ports: list[int]) -> str:
    """
    За списком відкритих портів повертає текстове пояснення ролі хоста.
    Наприклад: "web-сервер, SSH".
    """
    if not open_ports:
        return "—"

    ports_set = set(open_ports)
    labels: list[str] = []

    if 80 in ports_set or 443 in ports_set:
        labels.append("web-сервер")
    if 22 in ports_set:
        labels.append("SSH-доступ")
    if 3389 in ports_set:
        labels.append("RDP (віддалений доступ)")
    if 445 in ports_set:
        labels.append("SMB / file-sharing")

    if not labels:
        labels.append("невідомий сервіс")

    return ", ".join(labels)


def scan_network(network_cidr: str, ports=None, progress_cb=None) -> list[dict]:
    network = ipaddress.ip_network(network_cidr, strict=False)
    alive_hosts: list[dict] = []

    all_ips = list(network.hosts())
    total = len(all_ips)

    print("Сканування підмережі:", network_cidr)

    for idx, ip in enumerate(all_ips, start=1):
        ip_str = str(ip)
        print(f"Перевіряю {ip_str} ... ", end="")

        host_info = None

        if ping_host(ip_str):
            open_ports = scan_ports(ip_str, ports)
            role = classify_host(open_ports)

            host_info = {
                "ip": ip_str,
                "open_ports": open_ports,
                "role": role,
            }

            if open_ports:
                ports_str = ", ".join(str(p) for p in open_ports)
                print(f"АКТИВНИЙ, порти: {ports_str} → {role}")
            else:
                print(f"АКТИВНИЙ, але потрібних портів не знайдено → {role}")

            alive_hosts.append(host_info)
        else:
            print("немає відповіді")

        if progress_cb is not None:
            progress_cb(idx, total, host_info)

    return alive_hosts
