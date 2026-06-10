import sys
import ipaddress
from datetime import datetime

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QMessageBox,
    QProgressBar,
    QDialog,
    QFileDialog,
    QComboBox,
    QHeaderView,
)

from analyzer import compare_scans, get_previous_scan_data
from report import build_scan_summary
from risk import calculate_host_scores, calculate_scan_attention_total, derive_attention_level
from scanner import scan_network
from ports_data import DEFAULT_TCP_PORTS


def _confidence_text(event: dict) -> str:
    confidence = event.get("match_confidence", -1)
    return str(confidence) if confidence >= 0 else "—"


def _decision_text(event: dict) -> str:
    return event.get("match_decision") or "—"


def _configure_event_table_columns(
    table: QTableWidget,
    *,
    type_column: int,
    description_column: int,
    confidence_column: int,
    decision_column: int,
):
    """Keep event descriptions readable while identity metadata columns stay compact."""
    header = table.horizontalHeader()
    header.setSectionResizeMode(description_column, QHeaderView.Stretch)
    header.setSectionResizeMode(type_column, QHeaderView.Fixed)
    header.setSectionResizeMode(confidence_column, QHeaderView.Fixed)
    header.setSectionResizeMode(decision_column, QHeaderView.Fixed)
    table.setColumnWidth(type_column, 160)
    table.setColumnWidth(confidence_column, 90)
    table.setColumnWidth(decision_column, 125)


from storage import (
    export_latest_events_csv,
    export_latest_scores_csv,
    export_latest_summary_txt,
    get_device_passport,
    get_device_scan_history,
    get_scan_details,
    get_scan_history,
    init_db,
    load_device_scores_for_scan,
    load_events_for_scan,
    load_hosts_for_scan,
    load_summary_for_scan,
    save_device_scores,
    save_events,
    save_scan,
    save_scan_summary,
)


class DevicePassportDialog(QDialog):
    def __init__(self, ip: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Паспорт пристрою: {ip}")
        self.resize(820, 520)

        layout = QVBoxLayout(self)

        passport = get_device_passport(ip)
        if not passport:
            layout.addWidget(QLabel(f"Дані по хосту {ip} не знайдено."))
            return

        latest_score = passport.get("latest_score", {})
        reasons = latest_score.get("reasons", "")

        summary = QLabel(
            f"IP: {passport.get('ip', '')}\n"
            f"Hostname: {passport.get('hostname') or '—'}\n"
            f"MAC: {passport.get('mac') or '—'}\n"
            f"Vendor: {passport.get('vendor') or '—'}\n"
            f"First seen: {passport.get('first_seen') or '—'}\n"
            f"Last seen: {passport.get('last_seen') or '—'}\n"
            f"Поточна роль: {passport.get('current_role') or '—'}\n"
            f"Поточні порти: {passport.get('current_open_ports') or '—'}\n"
            f"Кількість появ у сканах: {passport.get('appearances', 0)}\n"
            f"Остання оцінка уваги: {latest_score.get('attention_score', 0)} "
            f"({latest_score.get('attention_level', 'Low')})\n"
            f"Причини: {reasons or '—'}\n"
            f"\nІсторичний підсумок: {passport.get('historical_summary', '')}"
        )
        summary.setWordWrap(True)
        layout.addWidget(summary)

        layout.addWidget(QLabel("Останні події по хосту:"))
        events_table = QTableWidget()
        events_table.setColumnCount(6)
        events_table.setHorizontalHeaderLabels(["Час", "Тип", "Опис", "Confidence", "Decision", "Scan ID"])
        _configure_event_table_columns(
            events_table,
            type_column=1,
            description_column=2,
            confidence_column=3,
            decision_column=4,
        )
        events_table.setColumnWidth(0, 150)
        events_table.setColumnWidth(5, 70)
        events_table.setSortingEnabled(False)
        events = passport.get("recent_events", [])
        events_table.setRowCount(len(events))
        for row, event in enumerate(events):
            confidence_text = _confidence_text(event)
            decision_text = _decision_text(event)
            for col, value in enumerate([
                event.get("created_at", ""),
                event.get("event_type", ""),
                event.get("description", ""),
                confidence_text,
                decision_text,
                str(event.get("scan_id", "")),
            ]):
                item = QTableWidgetItem(value)
                item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                events_table.setItem(row, col, item)
        events_table.setSortingEnabled(True)
        layout.addWidget(events_table)

        layout.addWidget(QLabel("Історія появ у скануваннях:"))
        history_table = QTableWidget()
        history_table.setColumnCount(6)
        history_table.setHorizontalHeaderLabels(
            ["Scan ID", "Finished", "Role", "Ports", "Total attention", "Network"]
        )
        history_table.setSortingEnabled(False)
        history = get_device_scan_history(ip)
        history_table.setRowCount(len(history))
        for row, h in enumerate(history):
            values = [
                str(h.get("scan_id", "")),
                h.get("finished_at", ""),
                h.get("role", ""),
                h.get("open_ports", ""),
                str(h.get("attention_score_total", 0)),
                h.get("network", ""),
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                history_table.setItem(row, col, item)
        history_table.horizontalHeader().setStretchLastSection(True)
        history_table.setSortingEnabled(True)
        layout.addWidget(history_table)


class ScanHistoryDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Історія сканувань")
        self.resize(900, 560)

        layout = QVBoxLayout(self)

        self.history_table = QTableWidget()
        self.history_table.setColumnCount(6)
        self.history_table.setHorizontalHeaderLabels([
            "Scan ID",
            "Network",
            "Finished",
            "Hosts",
            "Attention",
            "Summary preview",
        ])
        self.history_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.history_table.setColumnWidth(0, 70)
        self.history_table.setColumnWidth(1, 140)
        self.history_table.setColumnWidth(2, 150)
        self.history_table.setColumnWidth(3, 70)
        self.history_table.setColumnWidth(4, 85)
        self.history_table.setSortingEnabled(True)
        self.history_table.itemSelectionChanged.connect(self._show_selected_scan_details)
        layout.addWidget(self.history_table)

        self.detail_label = QLabel("Оберіть сканування для перегляду деталей.")
        self.detail_label.setWordWrap(True)
        layout.addWidget(self.detail_label)

        self.events_table = QTableWidget()
        self.events_table.setColumnCount(4)
        self.events_table.setHorizontalHeaderLabels(["Тип події", "Опис", "Confidence", "Decision"])
        _configure_event_table_columns(
            self.events_table,
            type_column=0,
            description_column=1,
            confidence_column=2,
            decision_column=3,
        )
        self.events_table.setSortingEnabled(True)
        layout.addWidget(self.events_table)

        self._populate_history()

    def _populate_history(self):
        scans = get_scan_history(limit=100)
        self.history_table.setSortingEnabled(False)
        self.history_table.setRowCount(len(scans))
        for row, scan in enumerate(scans):
            values = [
                str(scan.get("scan_id", "")),
                scan.get("network", ""),
                scan.get("finished_at", ""),
                str(scan.get("host_count", 0)),
                str(scan.get("attention_score_total", 0)),
                scan.get("summary_preview", ""),
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                self.history_table.setItem(row, col, item)
        self.history_table.setSortingEnabled(True)

    def _show_selected_scan_details(self):
        selected = self.history_table.selectedItems()
        if not selected:
            return
        row = selected[0].row()
        scan_id_item = self.history_table.item(row, 0)
        if scan_id_item is None:
            return
        scan_id = int(scan_id_item.text())

        details = get_scan_details(scan_id)
        if not details:
            self.detail_label.setText("Деталі сканування не знайдено.")
            self.events_table.setSortingEnabled(False)
            self.events_table.setRowCount(0)
            self.events_table.setSortingEnabled(True)
            return

        self.detail_label.setText(
            f"Scan ID: {details.get('scan_id')} | "
            f"Network: {details.get('network')} | "
            f"Hosts: {details.get('host_count')} | "
            f"Total attention: {details.get('attention_score_total')}\n\n"
            f"{details.get('summary_text', '')}"
        )

        events = details.get("events", [])
        self.events_table.setSortingEnabled(False)
        self.events_table.setRowCount(len(events))
        for r, event in enumerate(events):
            type_item = QTableWidgetItem(event.get("event_type", ""))
            type_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
            desc_item = QTableWidgetItem(event.get("description", ""))
            desc_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
            confidence_text = _confidence_text(event)
            decision_text = _decision_text(event)
            conf_item = QTableWidgetItem(confidence_text)
            conf_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
            decision_item = QTableWidgetItem(decision_text)
            decision_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
            self.events_table.setItem(r, 0, type_item)
            self.events_table.setItem(r, 1, desc_item)
            self.events_table.setItem(r, 2, conf_item)
            self.events_table.setItem(r, 3, decision_item)
        self.events_table.setSortingEnabled(True)


class ScanWorker(QThread):
    """
    Окремий потік для сканування, щоб не підвисав інтерфейс.
    """
    finished = Signal(list, str, datetime, datetime)  # hosts, network, started_at, finished_at
    progress = Signal(int, int, object)  # current, total, host_info (dict або None)
    error = Signal(str)

    def __init__(self, network: str, ports: list[int], discovery_mode: str, parent=None):
        super().__init__(parent)
        self.network = network
        self.ports = ports
        self.discovery_mode = discovery_mode

    def run(self):
        try:
            started_at = datetime.now()

            # Локальна функція, яку передамо в scanner.scan_network
            def progress_cb(current: int, total: int, host_info):
                self.progress.emit(current, total, host_info)

            hosts = scan_network(
                self.network,
                ports=self.ports,
                progress_cb=progress_cb,
                discovery_mode=self.discovery_mode,
            )
            finished_at = datetime.now()
            self.finished.emit(hosts, self.network, started_at, finished_at)
        except Exception as exc:
            self.error.emit(str(exc))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Програмний комплекс для активного сканування та аналізу мережевої інфраструктури локальної мережі")
        self.resize(800, 500)

        # Ініціалізуємо БД
        init_db()

        self.worker: ScanWorker | None = None
        self.last_progress_total: int = 0


        central = QWidget(self)
        self.setCentralWidget(central)

        main_layout = QVBoxLayout()
        central.setLayout(main_layout)


        top_layout = QHBoxLayout()

        self.network_label = QLabel("Підмережа:")
        self.network_input = QLineEdit()
        self.network_input.setPlaceholderText("наприклад, 192.168.0.0/24")
        self.network_input.setText("192.168.0.0/24")  # значення за замовчуванням

        self.ports_input = QLineEdit()
        self.ports_input.setPlaceholderText("Порти: 22,80,443,3389,445")
        self.ports_input.setText(",".join(str(p) for p in DEFAULT_TCP_PORTS))

        self.discovery_mode = QComboBox()
        self.discovery_mode.addItem("Змішаний (ICMP + TCP)", "mixed")
        self.discovery_mode.addItem("ICMP", "icmp")
        self.discovery_mode.addItem("TCP", "tcp")

        self.scan_button = QPushButton("Сканувати")
        self.scan_button.clicked.connect(self.on_scan_clicked)
        self.history_button = QPushButton("Історія сканувань")
        self.history_button.clicked.connect(self.on_history_clicked)
        self.export_button = QPushButton("Експорт")
        self.export_button.clicked.connect(self.on_export_clicked)

        top_layout.addWidget(self.network_label)
        top_layout.addWidget(self.network_input, stretch=1)
        top_layout.addWidget(self.ports_input, stretch=1)
        top_layout.addWidget(self.discovery_mode)
        top_layout.addWidget(self.scan_button)
        top_layout.addWidget(self.history_button)
        top_layout.addWidget(self.export_button)

        main_layout.addLayout(top_layout)


        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels([
            "IP-адреса активного хоста",
            "Відкриті TCP-порти",
            "Тип вузла / сервіси",
        ])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setColumnWidth(0, 170)
        self.table.setColumnWidth(1, 170)
        self.table.cellDoubleClicked.connect(self.on_main_table_double_click)
        self.table.setSortingEnabled(True)

        main_layout.addWidget(self.table)

        self.changes_title_label = QLabel("Виявлені зміни:")
        main_layout.addWidget(self.changes_title_label)

        self.changes_table = QTableWidget()
        self.changes_table.setColumnCount(4)
        self.changes_table.setHorizontalHeaderLabels([
            "Тип події",
            "Опис",
            "Confidence",
            "Decision",
        ])
        _configure_event_table_columns(
            self.changes_table,
            type_column=0,
            description_column=1,
            confidence_column=2,
            decision_column=3,
        )
        self.changes_table.setSortingEnabled(True)
        main_layout.addWidget(self.changes_table)

        self.changes_status_label = QLabel("")
        self.changes_status_label.setAlignment(Qt.AlignLeft)
        main_layout.addWidget(self.changes_status_label)

        self.scores_title_label = QLabel("Рівень уваги по хостах:")
        main_layout.addWidget(self.scores_title_label)

        self.scores_table = QTableWidget()
        self.scores_table.setColumnCount(4)
        self.scores_table.setHorizontalHeaderLabels([
            "IP",
            "Оцінка уваги",
            "Рівень уваги",
            "Причини",
        ])
        self.scores_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.scores_table.setColumnWidth(0, 150)
        self.scores_table.setColumnWidth(1, 80)
        self.scores_table.setColumnWidth(2, 110)
        self.scores_table.cellDoubleClicked.connect(self.on_scores_table_double_click)
        self.scores_table.setSortingEnabled(True)
        main_layout.addWidget(self.scores_table)

        self.summary_title_label = QLabel("Підсумок сканування:")
        main_layout.addWidget(self.summary_title_label)

        self.summary_text_label = QLabel("")
        self.summary_text_label.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        self.summary_text_label.setWordWrap(True)
        main_layout.addWidget(self.summary_text_label)


        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(1)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Готово.")
        main_layout.addWidget(self.progress_bar)


        self.status_label = QLabel("Готово до сканування.")
        self.status_label.setAlignment(Qt.AlignLeft)

        self.scan_id_label = QLabel("")  # сюди виведемо ID скану з БД
        self.scan_id_label.setAlignment(Qt.AlignRight)

        bottom_layout = QHBoxLayout()
        bottom_layout.addWidget(self.status_label)
        bottom_layout.addWidget(self.scan_id_label)

        main_layout.addLayout(bottom_layout)

    def _set_scan_controls_enabled(self, enabled: bool):
        self.scan_button.setEnabled(enabled)
        self.network_input.setEnabled(enabled)
        self.ports_input.setEnabled(enabled)
        self.discovery_mode.setEnabled(enabled)

    def _parse_ports_input(self) -> list[int] | None:
        raw = self.ports_input.text().strip()
        if not raw:
            return list(DEFAULT_TCP_PORTS)

        try:
            ports = []
            for chunk in raw.split(","):
                value = chunk.strip()
                if not value:
                    continue
                port = int(value)
                if port < 1 or port > 65535:
                    raise ValueError
                ports.append(port)
            ports = sorted(set(ports))
            if not ports:
                raise ValueError
            if len(ports) > 100:
                QMessageBox.warning(
                    self,
                    "Забагато портів",
                    "Для стабільної роботи вкажіть не більше 100 портів.",
                )
                return None
            return ports
        except ValueError:
            QMessageBox.warning(
                self,
                "Помилка формату портів",
                "Введіть порти у форматі: 22,80,443",
            )
            return None

    def on_scan_clicked(self):
        network = self.network_input.text().strip()
        if not network:
            QMessageBox.warning(self, "Помилка", "Будь ласка, введіть підмережу.")
            return
        try:
            ipaddress.ip_network(network, strict=False)
        except ValueError:
            QMessageBox.warning(
                self,
                "Помилка формату підмережі",
                "Введіть CIDR у форматі, наприклад: 192.168.0.0/24",
            )
            return
        ports = self._parse_ports_input()
        if ports is None:
            return

        # Блокуємо елементи на час сканування
        self._set_scan_controls_enabled(False)
        self.last_progress_total = 0

        # Очищаємо попередні таблиці без активного сортування, щоб рядки не змішувалися.
        self.table.setSortingEnabled(False)
        self.changes_table.setSortingEnabled(False)
        self.scores_table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self.changes_table.setRowCount(0)
        self.changes_status_label.setText("")
        self.scores_table.setRowCount(0)
        self.summary_text_label.setText("")
        self.scan_id_label.setText("")

        # Скидаємо прогрес-бар
        self.progress_bar.setRange(0, 0)  # невизначений прогрес, поки не знаємо total
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat(f"Сканування {network} ...")
        mode_label = self.discovery_mode.currentData()
        self.status_label.setText(f"Сканування {network} (mode: {mode_label}) ...")

        # Стартуємо потік зі сканером
        self.worker = ScanWorker(
            network=network,
            ports=ports,
            discovery_mode=self.discovery_mode.currentData(),
        )
        self.worker.finished.connect(self.on_scan_finished)
        self.worker.progress.connect(self.on_scan_progress)
        self.worker.error.connect(self.on_scan_error)
        self.worker.start()

    def on_scan_progress(self, current: int, total: int, host_info):
        """
        Оновлення прогрес-бару під час сканування.
        host_info = dict(...) для живого хоста або None, якщо пінг не відповів.
        """
        # Якщо ще не виставлено діапазон – виставляємо
        if self.progress_bar.maximum() != total:
            self.progress_bar.setRange(0, total)

        self.progress_bar.setValue(current)
        self.last_progress_total = total
        self.progress_bar.setFormat(f"Сканування: {current}/{total} адрес")
        self.status_label.setText(
            f"Сканування {self.network_input.text().strip() or 'підмережі'}: "
            f"{current}/{total} адрес"
        )

        # Якщо хочеш показувати хости «на льоту», можна тут додавати рядки:
        if host_info is not None and isinstance(host_info, dict):
            ip = host_info.get("ip", "")
            ports = host_info.get("open_ports", [])
            role = host_info.get("role", "")

            ports_str = ", ".join(str(p) for p in ports) if ports else "—"
            role_str = role if role else "—"

            row = self.table.rowCount()
            self.table.insertRow(row)

            ip_item = QTableWidgetItem(ip)
            ip_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)

            ports_item = QTableWidgetItem(ports_str)
            ports_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)

            role_item = QTableWidgetItem(role_str)
            role_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)

            self.table.setItem(row, 0, ip_item)
            self.table.setItem(row, 1, ports_item)
            self.table.setItem(row, 2, role_item)

    def on_scan_finished(self, hosts, network, started_at, finished_at):
        """
        Викликається, коли ScanWorker закінчив роботу.

        hosts – список словників:
            { "ip": "...", "open_ports": [...], "role": "..." }
        або список рядків – тоді ми нормалізуємо.
        """
        # Нормалізація формату hosts
        normalized_hosts = []
        for h in hosts:
            if isinstance(h, dict):
                normalized_hosts.append(h)
            else:
                normalized_hosts.append({
                    "ip": str(h),
                    "open_ports": [],
                    "role": "",
                })
        hosts = normalized_hosts

        # Розблоковуємо кнопки
        self._set_scan_controls_enabled(True)

        # Якщо ми не додавали хости "на льоту", можна
        # перезаповнити таблицю тут (на випадок змін)
        # Спочатку очищаємо, щоб не було дубляжу
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self.table.setRowCount(len(hosts))
        for row, host in enumerate(hosts):
            ip = host.get("ip", "")
            ports = host.get("open_ports", [])
            role = host.get("role", "")

            ports_str = ", ".join(str(p) for p in ports) if ports else "—"
            role_str = role if role else "—"

            ip_item = QTableWidgetItem(ip)
            ip_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)

            ports_item = QTableWidgetItem(ports_str)
            ports_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)

            role_item = QTableWidgetItem(role_str)
            role_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)

            self.table.setItem(row, 0, ip_item)
            self.table.setItem(row, 1, ports_item)
            self.table.setItem(row, 2, role_item)

        # Завершуємо прогрес-бар
        total = self.last_progress_total if self.last_progress_total > 0 else 1
        self.progress_bar.setRange(0, total)
        self.progress_bar.setValue(total)
        self.progress_bar.setFormat("Сканування завершено.")
        self.table.setSortingEnabled(True)

        # Зберігаємо в БД
        try:
            scan_id = save_scan(network, started_at, finished_at, hosts)
        except Exception as exc:
            self.progress_bar.setFormat("Сканування завершено, але збереження не вдалося.")
            self.status_label.setText("Помилка збереження результатів сканування.")
            QMessageBox.critical(
                self,
                "Помилка БД",
                f"Не вдалося зберегти результати сканування:\n{exc}",
            )
            return

        # Оновлюємо статуси
        if hosts:
            self.status_label.setText(f"Завершено: активних хостів {len(hosts)}.")
        else:
            self.status_label.setText("Завершено: активних хостів не знайдено.")

        self.scan_id_label.setText(f"ID останнього скану: {scan_id}")

        # Порівнюємо з попереднім скануванням цієї ж підмережі
        try:
            self._process_scan_changes(network=network, current_scan_id=scan_id)
        except Exception as exc:
            self.changes_table.setRowCount(0)
            self.changes_status_label.setText("Не вдалося виконати аналіз змін.")
            QMessageBox.warning(
                self,
                "Попередження",
                f"Скан збережено, але аналіз змін завершився помилкою:\n{exc}",
            )

    def _process_scan_changes(self, network: str, current_scan_id: int):
        """
        Аналізує зміни між поточним і попереднім скануванням.
        """
        current_hosts = load_hosts_for_scan(current_scan_id)
        previous_scan_id, previous_hosts = get_previous_scan_data(network, current_scan_id)

        has_previous_scan = previous_scan_id is not None
        if previous_scan_id is None:
            self.changes_table.setSortingEnabled(False)
            self.changes_table.setRowCount(0)
            self.changes_table.setSortingEnabled(True)
            self.changes_status_label.setText(
                "Попереднього сканування для порівняння не знайдено."
            )
            events = []
        else:
            events = compare_scans(previous_hosts, current_hosts)

        save_events(current_scan_id, events)

        saved_events = load_events_for_scan(current_scan_id)
        if previous_scan_id is not None and not saved_events:
            self.changes_table.setSortingEnabled(False)
            self.changes_table.setRowCount(0)
            self.changes_table.setSortingEnabled(True)
            self.changes_status_label.setText(
                "Змін порівняно з попереднім скануванням не виявлено."
            )
        elif saved_events:
            self.changes_status_label.setText(
                f"Виявлено змін: {len(saved_events)}"
            )
            self.changes_table.setSortingEnabled(False)
            self.changes_table.setRowCount(len(saved_events))

            for row, event in enumerate(saved_events):
                event_type = event.get("event_type", "")
                description = event.get("description", "")

                confidence_text = _confidence_text(event)
                decision_text = _decision_text(event)

                type_item = QTableWidgetItem(event_type)
                type_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                description_item = QTableWidgetItem(description)
                description_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                confidence_item = QTableWidgetItem(confidence_text)
                confidence_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                decision_item = QTableWidgetItem(decision_text)
                decision_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)

                self.changes_table.setItem(row, 0, type_item)
                self.changes_table.setItem(row, 1, description_item)
                self.changes_table.setItem(row, 2, confidence_item)
                self.changes_table.setItem(row, 3, decision_item)
            self.changes_table.setSortingEnabled(True)

        # Рахуємо і зберігаємо оцінки уваги
        host_scores = calculate_host_scores(saved_events)
        save_device_scores(current_scan_id, host_scores)
        saved_scores = load_device_scores_for_scan(current_scan_id)

        self.scores_table.setSortingEnabled(False)
        self.scores_table.setRowCount(len(saved_scores))
        for row, item in enumerate(saved_scores):
            ip_item = QTableWidgetItem(item.get("ip", ""))
            ip_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)

            score = int(item.get("attention_score", 0))
            score_item = QTableWidgetItem(str(score))
            score_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)

            level_item = QTableWidgetItem(item.get("attention_level", "Low"))
            level_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)

            reasons_text = "; ".join(item.get("reasons", []))
            reasons_item = QTableWidgetItem(reasons_text)
            reasons_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)

            self.scores_table.setItem(row, 0, ip_item)
            score_item.setData(Qt.DisplayRole, score)
            self.scores_table.setItem(row, 1, score_item)
            self.scores_table.setItem(row, 2, level_item)
            self.scores_table.setItem(row, 3, reasons_item)
        self.scores_table.setSortingEnabled(True)
        self.scores_table.sortItems(1, Qt.DescendingOrder)

        attention_total = calculate_scan_attention_total(saved_scores)
        summary_text = build_scan_summary(
            network=network,
            active_host_count=len(current_hosts),
            events=saved_events,
            host_scores=saved_scores,
            has_previous_scan=has_previous_scan,
        )
        save_scan_summary(current_scan_id, summary_text, attention_total)
        stored_summary = load_summary_for_scan(current_scan_id)

        total_score = stored_summary.get("attention_score_total", 0)
        total_level = derive_attention_level(int(total_score))
        visible_summary = (
            f"Загальна оцінка уваги: {total_score} ({total_level})\n\n"
            f"{stored_summary.get('summary_text', '')}"
        )
        self.summary_text_label.setText(visible_summary)

    def on_scan_error(self, message: str):
        """
        Обробка помилок сканування з worker-потоку.
        """
        self._set_scan_controls_enabled(True)
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Сканування завершилося з помилкою.")
        self.status_label.setText("Помилка під час сканування.")
        QMessageBox.critical(
            self,
            "Помилка сканування",
            f"Сканування не вдалося завершити:\n{message}",
        )

    def on_main_table_double_click(self, row: int, column: int):
        item = self.table.item(row, 0)
        if item is None:
            return
        ip = item.text().strip()
        if ip:
            dlg = DevicePassportDialog(ip, self)
            dlg.exec()

    def on_scores_table_double_click(self, row: int, column: int):
        item = self.scores_table.item(row, 0)
        if item is None:
            return
        ip = item.text().strip()
        if ip:
            dlg = DevicePassportDialog(ip, self)
            dlg.exec()

    def on_history_clicked(self):
        dlg = ScanHistoryDialog(self)
        dlg.exec()

    def on_export_clicked(self):
        directory = QFileDialog.getExistingDirectory(self, "Виберіть папку для експорту")
        if not directory:
            return
        try:
            summary_path = f"{directory}/latest_scan_summary.txt"
            events_path = f"{directory}/latest_scan_events.csv"
            scores_path = f"{directory}/latest_attention_scores.csv"

            export_latest_summary_txt(summary_path)
            export_latest_events_csv(events_path)
            export_latest_scores_csv(scores_path)

            QMessageBox.information(
                self,
                "Експорт завершено",
                "Файли успішно створені:\n"
                f"- {summary_path}\n"
                f"- {events_path}\n"
                f"- {scores_path}",
            )
        except Exception as exc:
            QMessageBox.critical(self, "Помилка експорту", str(exc))


def run_app():
    """
    Запуск графічного інтерфейсу.
    Викликається з main.py
    """
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
