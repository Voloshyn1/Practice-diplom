import sys
import ipaddress
from datetime import datetime, timedelta

from PySide6.QtCore import Qt, QThread, Signal, QTimer
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
    QFrame,
    QSplitter,
    QCheckBox,
    QSpinBox,
    QAbstractItemView,
    QSizePolicy,
    QPlainTextEdit,
)

from analyzer import compare_scans, get_previous_scan_data
from report import build_scan_summary
from risk import calculate_host_scores, calculate_scan_attention_total, derive_attention_level
from scanner import scan_network
from ports_data import DEFAULT_TCP_PORTS

SECTION_HEADING_STYLE = "font-weight: 600; margin-top: 6px;"
EMPTY_STATE_STYLE = "color: #a0a0a0; font-style: italic;"
CARD_STYLE = """
QFrame#OverviewCard {
    border: 1px solid palette(mid);
    border-radius: 6px;
    background: palette(base);
}
"""


def _make_section_label(text: str) -> QLabel:
    label = QLabel(text)
    label.setStyleSheet(SECTION_HEADING_STYLE)
    return label


def _polish_table(table: QTableWidget):
    table.setAlternatingRowColors(True)
    table.setEditTriggers(QAbstractItemView.NoEditTriggers)
    table.setSelectionBehavior(QAbstractItemView.SelectRows)
    table.setSelectionMode(QAbstractItemView.SingleSelection)
    table.verticalHeader().setVisible(False)


def _set_table_empty_state(label: QLabel, text: str, has_records: bool):
    label.setText("" if has_records else text)


def _display_event_type(event_type: str) -> str:
    return {
        "NEW_HOST": "Новий хост",
        "HOST_DISAPPEARED": "Хост не виявлено",
        "HOST_IP_CHANGED": "Зміна IP-адреси",
        "HOST_AMBIGUOUS_MATCH": "Невизначена ідентичність",
        "NEW_PORT_OPENED": "Відкрито новий порт",
        "PORT_CLOSED": "Порт закрито",
        "ROLE_CHANGED": "Зміна ролі",
    }.get(event_type, event_type)


def _display_attention_level(level: str) -> str:
    return {
        "Low": "Низький",
        "Moderate": "Помірний",
        "Elevated": "Підвищений",
        "High": "Високий",
        "Critical": "Критичний",
    }.get(level, level)


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
            f"({_display_attention_level(latest_score.get('attention_level', 'Low'))})\n"
            f"Причини: {reasons or '—'}\n"
            f"\nІсторичний підсумок: {passport.get('historical_summary', '')}"
        )
        summary.setWordWrap(True)
        layout.addWidget(summary)

        layout.addWidget(QLabel("Останні події по хосту:"))
        events_table = QTableWidget()
        events_table.setColumnCount(6)
        events_table.setHorizontalHeaderLabels(["Час", "Тип", "Опис", "Впевненість", "Рішення", "Scan ID"])
        _configure_event_table_columns(
            events_table,
            type_column=1,
            description_column=2,
            confidence_column=3,
            decision_column=4,
        )
        events_table.setColumnWidth(0, 150)
        events_table.setColumnWidth(5, 70)
        _polish_table(events_table)
        events_table.setSortingEnabled(False)
        events = passport.get("recent_events", [])
        events_table.setRowCount(len(events))
        for row, event in enumerate(events):
            confidence_text = _confidence_text(event)
            decision_text = _decision_text(event)
            event_type = event.get("event_type", "")
            for col, value in enumerate([
                event.get("created_at", ""),
                _display_event_type(event_type),
                event.get("description", ""),
                confidence_text,
                decision_text,
                str(event.get("scan_id", "")),
            ]):
                item = QTableWidgetItem(value)
                if col == 1 and event_type:
                    item.setToolTip(event_type)
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
        _polish_table(history_table)
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
        _polish_table(self.history_table)
        self.history_table.setSortingEnabled(True)
        self.history_table.itemSelectionChanged.connect(self._show_selected_scan_details)
        layout.addWidget(self.history_table)

        self.detail_label = QLabel("Оберіть сканування для перегляду деталей.")
        self.detail_label.setWordWrap(True)
        layout.addWidget(self.detail_label)

        self.events_table = QTableWidget()
        self.events_table.setColumnCount(4)
        self.events_table.setHorizontalHeaderLabels(["Тип події", "Опис", "Впевненість", "Рішення"])
        _configure_event_table_columns(
            self.events_table,
            type_column=0,
            description_column=1,
            confidence_column=2,
            decision_column=3,
        )
        _polish_table(self.events_table)
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
            event_type = event.get("event_type", "")
            type_item = QTableWidgetItem(_display_event_type(event_type))
            if event_type:
                type_item.setToolTip(event_type)
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
        self.resize(1200, 760)
        self.setMinimumSize(950, 650)

        init_db()

        self.worker: ScanWorker | None = None
        self.last_progress_total: int = 0
        self.last_scan_id: int | None = None
        self.next_run_at: datetime | None = None

        self.scheduler_timer = QTimer(self)
        self.scheduler_timer.setSingleShot(True)
        self.scheduler_timer.timeout.connect(self.on_scheduler_timeout)

        central = QWidget(self)
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setSpacing(8)

        self._build_controls(main_layout)
        self._build_overview_cards(main_layout)
        self._build_tables_and_summary(main_layout)
        self._build_progress_area(main_layout)
        self._reset_overview_cards()

    def _build_controls(self, main_layout: QVBoxLayout):
        controls_frame = QFrame()
        controls_frame.setFrameShape(QFrame.StyledPanel)
        controls_layout = QVBoxLayout(controls_frame)
        controls_layout.setContentsMargins(8, 8, 8, 8)
        controls_layout.setSpacing(6)

        row1 = QHBoxLayout()
        self.network_label = QLabel("Підмережа:")
        self.network_input = QLineEdit()
        self.network_input.setPlaceholderText("наприклад, 192.168.0.0/24")
        self.network_input.setText("192.168.0.0/24")
        self.network_input.setMinimumWidth(260)

        self.discovery_label = QLabel("Режим виявлення:")
        self.discovery_mode = QComboBox()
        self.discovery_mode.addItem("Змішаний (ICMP + TCP)", "mixed")
        self.discovery_mode.addItem("ICMP", "icmp")
        self.discovery_mode.addItem("TCP", "tcp")
        self.discovery_mode.setMinimumWidth(190)

        self.scan_button = QPushButton("Сканувати")
        self.scan_button.clicked.connect(self.on_scan_clicked)

        row1.addWidget(self.network_label)
        row1.addWidget(self.network_input, stretch=1)
        row1.addWidget(self.discovery_label)
        row1.addWidget(self.discovery_mode)
        row1.addWidget(self.scan_button)
        controls_layout.addLayout(row1)

        row2 = QHBoxLayout()
        self.ports_label = QLabel("TCP-порти:")
        self.ports_input = QLineEdit()
        self.ports_input.setPlaceholderText("Порти: 22,80,443,3389,445")
        self.ports_input.setText(",".join(str(p) for p in DEFAULT_TCP_PORTS))
        self.ports_input.setMinimumWidth(520)
        self.ports_input.textChanged.connect(self._update_ports_tooltip)
        self._update_ports_tooltip(self.ports_input.text())

        self.history_button = QPushButton("Історія")
        self.history_button.clicked.connect(self.on_history_clicked)
        self.export_button = QPushButton("Експорт")
        self.export_button.clicked.connect(self.on_export_clicked)

        row2.addWidget(self.ports_label)
        row2.addWidget(self.ports_input, stretch=1)
        row2.addWidget(self.history_button)
        row2.addWidget(self.export_button)
        controls_layout.addLayout(row2)

        scheduler_layout = QHBoxLayout()
        scheduler_title = _make_section_label("Періодичний моніторинг")
        self.scheduler_checkbox = QCheckBox("Увімкнути автосканування")
        self.scheduler_checkbox.toggled.connect(self.on_scheduler_toggled)
        self.scheduler_interval = QSpinBox()
        self.scheduler_interval.setRange(1, 1440)
        self.scheduler_interval.setValue(30)
        self.scheduler_interval.setSuffix("")
        self.scheduler_interval.valueChanged.connect(self.on_scheduler_interval_changed)
        self.scheduler_next_label = QLabel("Наступний запуск: —")
        scheduler_layout.addWidget(scheduler_title)
        scheduler_layout.addWidget(self.scheduler_checkbox)
        scheduler_layout.addWidget(self.scheduler_interval)
        scheduler_layout.addWidget(QLabel("хв"))
        scheduler_layout.addWidget(self.scheduler_next_label, stretch=1)
        controls_layout.addLayout(scheduler_layout)

        main_layout.addWidget(controls_frame)

    def _build_overview_cards(self, main_layout: QVBoxLayout):
        overview_layout = QHBoxLayout()
        self.overview_values: dict[str, QLabel] = {}
        for key, title in [
            ("hosts", "Активні хости"),
            ("changes", "Виявлені зміни"),
            ("attention", "Рівень уваги"),
            ("last_scan", "Останній скан"),
        ]:
            card = QFrame()
            card.setObjectName("OverviewCard")
            card.setStyleSheet(CARD_STYLE)
            card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(8, 4, 8, 4)
            title_label = QLabel(title)
            title_label.setStyleSheet("font-size: 11px; color: #b0b0b0;")
            value_label = QLabel("—")
            value_label.setStyleSheet("font-size: 18px; font-weight: 600; color: palette(text);")
            card_layout.addWidget(title_label)
            card_layout.addWidget(value_label)
            overview_layout.addWidget(card)
            self.overview_values[key] = value_label
        main_layout.addLayout(overview_layout)

    def _build_tables_and_summary(self, main_layout: QVBoxLayout):
        content_splitter = QSplitter(Qt.Vertical)
        content_splitter.setChildrenCollapsible(False)
        content_splitter.setHandleWidth(6)

        hosts_panel = QWidget()
        hosts_layout = QVBoxLayout(hosts_panel)
        hosts_layout.setContentsMargins(0, 0, 0, 0)
        self.hosts_title_label = _make_section_label("Активні хости")
        hosts_layout.addWidget(self.hosts_title_label)
        self.hosts_empty_label = QLabel("Активні хости ще не виявлені.")
        self.hosts_empty_label.setStyleSheet(EMPTY_STATE_STYLE)
        hosts_layout.addWidget(self.hosts_empty_label)

        self.table = QTableWidget()
        self.table.setMinimumHeight(210)
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels([
            "IP-адреса",
            "Відкриті TCP-порти",
            "Тип вузла / сервіси",
        ])
        _polish_table(self.table)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setColumnWidth(0, 150)
        self.table.setColumnWidth(1, 190)
        self.table.cellDoubleClicked.connect(self.on_main_table_double_click)
        self.table.setSortingEnabled(True)
        hosts_layout.addWidget(self.table)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(6)
        changes_panel = QWidget()
        changes_layout = QVBoxLayout(changes_panel)
        changes_layout.setContentsMargins(0, 0, 0, 0)
        self.changes_title_label = _make_section_label("Виявлені зміни")
        changes_layout.addWidget(self.changes_title_label)
        self.changes_status_label = QLabel("Виконайте щонайменше два сканування для аналізу змін.")
        self.changes_status_label.setStyleSheet(EMPTY_STATE_STYLE)
        changes_layout.addWidget(self.changes_status_label)
        self.changes_table = QTableWidget()
        self.changes_table.setMinimumHeight(210)
        self.changes_table.setColumnCount(4)
        self.changes_table.setHorizontalHeaderLabels([
            "Тип події",
            "Опис",
            "Впевненість",
            "Рішення",
        ])
        _polish_table(self.changes_table)
        _configure_event_table_columns(
            self.changes_table,
            type_column=0,
            description_column=1,
            confidence_column=2,
            decision_column=3,
        )
        self.changes_table.setSortingEnabled(True)
        self.changes_table.horizontalHeaderItem(2).setToolTip("Впевненість алгоритму зіставлення хоста між сканами")
        changes_layout.addWidget(self.changes_table)

        scores_panel = QWidget()
        scores_layout = QVBoxLayout(scores_panel)
        scores_layout.setContentsMargins(0, 0, 0, 0)
        self.scores_title_label = _make_section_label("Рівень уваги по хостах")
        self.scores_title_label.setToolTip("Attention score не є CVE або повною оцінкою вразливостей.")
        scores_layout.addWidget(self.scores_title_label)
        self.scores_empty_label = QLabel("Події, що потребують уваги, не виявлені.")
        self.scores_empty_label.setStyleSheet(EMPTY_STATE_STYLE)
        scores_layout.addWidget(self.scores_empty_label)
        self.scores_table = QTableWidget()
        self.scores_table.setMinimumHeight(210)
        self.scores_table.setColumnCount(4)
        self.scores_table.setHorizontalHeaderLabels([
            "IP",
            "Оцінка",
            "Рівень",
            "Причини",
        ])
        _polish_table(self.scores_table)
        self.scores_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.scores_table.setColumnWidth(0, 140)
        self.scores_table.setColumnWidth(1, 80)
        self.scores_table.setColumnWidth(2, 100)
        self.scores_table.cellDoubleClicked.connect(self.on_scores_table_double_click)
        self.scores_table.setSortingEnabled(True)
        scores_layout.addWidget(self.scores_table)

        splitter.addWidget(changes_panel)
        splitter.addWidget(scores_panel)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([760, 480])

        summary_panel = QWidget()
        summary_layout = QVBoxLayout(summary_panel)
        summary_layout.setContentsMargins(0, 0, 0, 0)
        self.summary_title_label = _make_section_label("Підсумок сканування")
        summary_layout.addWidget(self.summary_title_label)
        self.summary_text_label = QPlainTextEdit()
        self.summary_text_label.setReadOnly(True)
        self.summary_text_label.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        self.summary_text_label.setMinimumHeight(110)
        summary_layout.addWidget(self.summary_text_label)

        content_splitter.addWidget(hosts_panel)
        content_splitter.addWidget(splitter)
        content_splitter.addWidget(summary_panel)
        content_splitter.setStretchFactor(0, 2)
        content_splitter.setStretchFactor(1, 3)
        content_splitter.setStretchFactor(2, 1)
        content_splitter.setSizes([270, 310, 140])
        main_layout.addWidget(content_splitter, stretch=1)

    def _build_progress_area(self, main_layout: QVBoxLayout):
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(1)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("")
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)

        self.status_label = QLabel("Готово до сканування.")
        self.status_label.setAlignment(Qt.AlignLeft)
        self.scan_id_label = QLabel("Наступний запуск: —")
        self.scan_id_label.setAlignment(Qt.AlignRight)

        bottom_layout = QHBoxLayout()
        bottom_layout.addWidget(self.status_label, stretch=1)
        bottom_layout.addWidget(self.scan_id_label)
        main_layout.addLayout(bottom_layout)

    def _reset_overview_cards(self):
        self.overview_values["hosts"].setText("0")
        self.overview_values["changes"].setText("0")
        self.overview_values["attention"].setText(_display_attention_level("Low"))
        self.overview_values["last_scan"].setText("—")

    def _update_overview_cards(self, *, host_count: int, event_count: int, attention_total: int, attention_level: str, scan_id: int, finished_at: datetime):
        self.overview_values["hosts"].setText(str(host_count))
        self.overview_values["changes"].setText(str(event_count))
        self.overview_values["attention"].setText(f"{attention_total} / {_display_attention_level(attention_level)}")
        self.overview_values["last_scan"].setText(f"ID {scan_id} · {finished_at.strftime('%H:%M')}")

    def _update_ports_tooltip(self, text: str):
        value = text.strip() or ",".join(str(p) for p in DEFAULT_TCP_PORTS)
        self.ports_input.setToolTip(f"TCP-порти для сканування: {value}")

    def _is_scan_running(self) -> bool:
        return self.worker is not None and self.worker.isRunning()

    def _set_scan_controls_enabled(self, enabled: bool):
        self.scan_button.setEnabled(enabled)
        self.network_input.setEnabled(enabled)
        self.ports_input.setEnabled(enabled)
        self.discovery_mode.setEnabled(enabled)
        self.history_button.setEnabled(enabled)
        self.export_button.setEnabled(enabled)

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

    def _validate_scan_inputs(self) -> tuple[str, list[int]] | None:
        network = self.network_input.text().strip()
        if not network:
            QMessageBox.warning(self, "Помилка", "Будь ласка, введіть підмережу.")
            return None
        try:
            ipaddress.ip_network(network, strict=False)
        except ValueError:
            QMessageBox.warning(
                self,
                "Помилка формату підмережі",
                "Введіть CIDR у форматі, наприклад: 192.168.0.0/24",
            )
            return None
        ports = self._parse_ports_input()
        if ports is None:
            return None
        return network, ports

    def on_scan_clicked(self):
        self._start_scan(automatic=False)

    def _start_scan(self, *, automatic: bool):
        if self._is_scan_running():
            message = "Запланований запуск пропущено: попереднє сканування ще виконується."
            self.status_label.setText(message)
            if automatic:
                self._schedule_next_run()
            return

        validated = self._validate_scan_inputs()
        if validated is None:
            if automatic:
                self.status_label.setText("Автосканування не запущено: перевірте параметри сканування.")
                self._schedule_next_run()
            return
        network, ports = validated

        self._set_scan_controls_enabled(False)
        self.last_progress_total = 0

        self.table.setSortingEnabled(False)
        self.changes_table.setSortingEnabled(False)
        self.scores_table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self.changes_table.setRowCount(0)
        self.scores_table.setRowCount(0)
        self.summary_text_label.clear()
        self.hosts_empty_label.setText("Активні хости ще не виявлені.")
        self.changes_status_label.setText("Виконайте щонайменше два сканування для аналізу змін.")
        self.scores_empty_label.setText("Події, що потребують уваги, не виявлені.")

        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Сканування...")
        mode_label = self.discovery_mode.currentData()
        prefix = "Запущено автоматичне сканування" if automatic else "Сканування"
        self.status_label.setText(f"{prefix}: {network} (режим: {mode_label}).")

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
        if self.progress_bar.maximum() != total:
            self.progress_bar.setRange(0, total)

        self.progress_bar.setValue(current)
        self.last_progress_total = total
        self.progress_bar.setFormat(f"{current}/{total} адрес")
        self.status_label.setText(
            f"Сканування {self.network_input.text().strip() or 'підмережі'}: "
            f"{current}/{total} адрес"
        )

        if host_info is not None and isinstance(host_info, dict):
            self.hosts_empty_label.setText("")
            ip = host_info.get("ip", "")
            ports = host_info.get("open_ports", [])
            role = host_info.get("role", "")

            ports_str = ", ".join(str(p) for p in ports) if ports else "—"
            role_str = role if role else "—"

            row = self.table.rowCount()
            self.table.insertRow(row)

            for col, value in enumerate([ip, ports_str, role_str]):
                item = QTableWidgetItem(value)
                item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                self.table.setItem(row, col, item)

    def on_scan_finished(self, hosts, network, started_at, finished_at):
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

        self._set_scan_controls_enabled(True)

        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self.table.setRowCount(len(hosts))
        for row, host in enumerate(hosts):
            ip = host.get("ip", "")
            ports = host.get("open_ports", [])
            role = host.get("role", "")
            ports_str = ", ".join(str(p) for p in ports) if ports else "—"
            role_str = role if role else "—"
            for col, value in enumerate([ip, ports_str, role_str]):
                item = QTableWidgetItem(value)
                item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                self.table.setItem(row, col, item)

        _set_table_empty_state(self.hosts_empty_label, "Активні хости ще не виявлені.", bool(hosts))

        total = self.last_progress_total if self.last_progress_total > 0 else 1
        self.progress_bar.setRange(0, total)
        self.progress_bar.setValue(total)
        self.progress_bar.setFormat("Завершено")
        self.table.setSortingEnabled(True)

        try:
            scan_id = save_scan(network, started_at, finished_at, hosts)
        except Exception as exc:
            self.progress_bar.setFormat("Помилка збереження")
            self.status_label.setText("Помилка збереження результатів сканування.")
            self.changes_table.setSortingEnabled(True)
            self.scores_table.setSortingEnabled(True)
            self.worker = None
            QMessageBox.critical(
                self,
                "Помилка БД",
                f"Не вдалося зберегти результати сканування:\n{exc}",
            )
            if self.scheduler_checkbox.isChecked():
                self._schedule_next_run()
            return

        self.last_scan_id = scan_id
        self.status_label.setText(f"Сканування завершено: активних хостів {len(hosts)}.")
        self.scan_id_label.setText(f"ID останнього скану: {scan_id}")

        try:
            self._process_scan_changes(network=network, current_scan_id=scan_id, finished_at=finished_at, host_count=len(hosts))
        except Exception as exc:
            self.changes_table.setSortingEnabled(False)
            self.changes_table.setRowCount(0)
            self.changes_table.setSortingEnabled(True)
            self.scores_table.setSortingEnabled(True)
            self.changes_status_label.setText("Не вдалося виконати аналіз змін.")
            self._update_overview_cards(
                host_count=len(hosts),
                event_count=0,
                attention_total=0,
                attention_level="Low",
                scan_id=scan_id,
                finished_at=finished_at,
            )
            QMessageBox.warning(
                self,
                "Попередження",
                f"Скан збережено, але аналіз змін завершився помилкою:\n{exc}",
            )

        self.worker = None
        QTimer.singleShot(3000, self._hide_progress_if_idle)
        if self.scheduler_checkbox.isChecked():
            self._schedule_next_run()

    def _process_scan_changes(self, network: str, current_scan_id: int, finished_at: datetime, host_count: int):
        current_hosts = load_hosts_for_scan(current_scan_id)
        previous_scan_id, previous_hosts = get_previous_scan_data(network, current_scan_id)

        has_previous_scan = previous_scan_id is not None
        if previous_scan_id is None:
            self.changes_table.setSortingEnabled(False)
            self.changes_table.setRowCount(0)
            self.changes_table.setSortingEnabled(True)
            self.changes_status_label.setText("Виконайте щонайменше два сканування для аналізу змін.")
            events = []
        else:
            events = compare_scans(previous_hosts, current_hosts)

        save_events(current_scan_id, events)
        saved_events = load_events_for_scan(current_scan_id)

        if previous_scan_id is not None and not saved_events:
            self.changes_table.setSortingEnabled(False)
            self.changes_table.setRowCount(0)
            self.changes_table.setSortingEnabled(True)
            self.changes_status_label.setText("Змін порівняно з попереднім скануванням не виявлено.")
        elif saved_events:
            self.changes_status_label.setText("")
            self.changes_table.setSortingEnabled(False)
            self.changes_table.setRowCount(len(saved_events))
            for row, event in enumerate(saved_events):
                event_type = event.get("event_type", "")
                values = [
                    _display_event_type(event_type),
                    event.get("description", ""),
                    _confidence_text(event),
                    _decision_text(event),
                ]
                for col, value in enumerate(values):
                    item = QTableWidgetItem(value)
                    if col == 0 and event_type:
                        item.setToolTip(event_type)
                    item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                    self.changes_table.setItem(row, col, item)
            self.changes_table.setSortingEnabled(True)

        host_scores = calculate_host_scores(saved_events)
        save_device_scores(current_scan_id, host_scores)
        saved_scores = load_device_scores_for_scan(current_scan_id)

        self.scores_table.setSortingEnabled(False)
        self.scores_table.setRowCount(len(saved_scores))
        for row, item in enumerate(saved_scores):
            score = int(item.get("attention_score", 0))
            values = [
                item.get("ip", ""),
                score,
                _display_attention_level(item.get("attention_level", "Low")),
                "; ".join(item.get("reasons", [])),
            ]
            for col, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                cell.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                if col == 1:
                    cell.setData(Qt.DisplayRole, score)
                self.scores_table.setItem(row, col, cell)
        self.scores_table.setSortingEnabled(True)
        self.scores_table.sortItems(1, Qt.DescendingOrder)
        _set_table_empty_state(self.scores_empty_label, "Події, що потребують уваги, не виявлені.", bool(saved_scores))

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
            f"Загальна оцінка уваги: {total_score} ({_display_attention_level(total_level)})\n\n"
            f"{stored_summary.get('summary_text', '')}"
        )
        self.summary_text_label.setPlainText(visible_summary)
        self._update_overview_cards(
            host_count=host_count,
            event_count=len(saved_events),
            attention_total=int(total_score),
            attention_level=total_level,
            scan_id=current_scan_id,
            finished_at=finished_at,
        )

    def on_scan_error(self, message: str):
        self._set_scan_controls_enabled(True)
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Помилка")
        self.status_label.setText("Помилка під час сканування.")
        self.table.setSortingEnabled(True)
        self.changes_table.setSortingEnabled(True)
        self.scores_table.setSortingEnabled(True)
        self.worker = None
        QMessageBox.critical(
            self,
            "Помилка сканування",
            f"Сканування не вдалося завершити:\n{message}",
        )
        if self.scheduler_checkbox.isChecked():
            self._schedule_next_run()

    def _hide_progress_if_idle(self):
        if not self._is_scan_running():
            self.progress_bar.setVisible(False)

    def on_scheduler_toggled(self, checked: bool):
        if checked:
            self._schedule_next_run()
            self.status_label.setText(f"Автосканування увімкнено. {self.scheduler_next_label.text()}.")
        else:
            self.scheduler_timer.stop()
            self.next_run_at = None
            self.scheduler_next_label.setText("Наступний запуск: —")
            self.scan_id_label.setText(f"ID останнього скану: {self.last_scan_id}" if self.last_scan_id else "Наступний запуск: —")
            self.status_label.setText("Автосканування вимкнено.")

    def on_scheduler_interval_changed(self, value: int):
        if self.scheduler_checkbox.isChecked():
            self._schedule_next_run()

    def _schedule_next_run(self):
        if not self.scheduler_checkbox.isChecked():
            return
        interval_ms = self.scheduler_interval.value() * 60 * 1000
        self.scheduler_timer.start(interval_ms)
        self.next_run_at = datetime.now() + timedelta(minutes=self.scheduler_interval.value())
        next_text = self.next_run_at.strftime("%H:%M")
        self.scheduler_next_label.setText(f"Наступний запуск: {next_text}")
        base = f"ID останнього скану: {self.last_scan_id}" if self.last_scan_id else ""
        separator = " | " if base else ""
        self.scan_id_label.setText(f"{base}{separator}Наступний запуск: {next_text}")

    def on_scheduler_timeout(self):
        if self._is_scan_running():
            self.status_label.setText("Запланований запуск пропущено: попереднє сканування ще виконується.")
            self._schedule_next_run()
            return
        self.status_label.setText("Запущено автоматичне сканування.")
        self._start_scan(automatic=True)

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
