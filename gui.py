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
)

from scanner import scan_network
from storage import init_db, save_scan


class ScanWorker(QThread):
    """
    Окремий потік для сканування, щоб не підвисав інтерфейс.
    """
    finished = Signal(list, str, datetime, datetime)  # hosts, network, started_at, finished_at
    progress = Signal(int, int, object)  # current, total, host_info (dict або None)
    error = Signal(str)

    def __init__(self, network: str, parent=None):
        super().__init__(parent)
        self.network = network

    def run(self):
        try:
            started_at = datetime.now()

            # Локальна функція, яку передамо в scanner.scan_network
            def progress_cb(current: int, total: int, host_info):
                self.progress.emit(current, total, host_info)

            hosts = scan_network(self.network, progress_cb=progress_cb)
            finished_at = datetime.now()
            self.finished.emit(hosts, self.network, started_at, finished_at)
        except Exception as exc:
            self.error.emit(str(exc))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Сканер локальної мережі (прототип диплома)")
        self.resize(800, 500)

        # Ініціалізуємо БД
        init_db()

        self.worker: ScanWorker | None = None


        central = QWidget(self)
        self.setCentralWidget(central)

        main_layout = QVBoxLayout()
        central.setLayout(main_layout)


        top_layout = QHBoxLayout()

        self.network_label = QLabel("Підмережа:")
        self.network_input = QLineEdit()
        self.network_input.setPlaceholderText("наприклад, 192.168.0.0/24")
        self.network_input.setText("192.168.0.0/24")  # значення за замовчуванням

        self.scan_button = QPushButton("Сканувати")
        self.scan_button.clicked.connect(self.on_scan_clicked)

        top_layout.addWidget(self.network_label)
        top_layout.addWidget(self.network_input, stretch=1)
        top_layout.addWidget(self.scan_button)

        main_layout.addLayout(top_layout)


        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels([
            "IP-адреса активного хоста",
            "Відкриті TCP-порти",
            "Тип вузла / сервіси",
        ])
        self.table.horizontalHeader().setStretchLastSection(True)

        main_layout.addWidget(self.table)


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

        # Блокуємо елементи на час сканування
        self._set_scan_controls_enabled(False)

        # Очищаємо попередню таблицю
        self.table.setRowCount(0)
        self.scan_id_label.setText("")

        # Скидаємо прогрес-бар
        self.progress_bar.setRange(0, 0)  # невизначений прогрес, поки не знаємо total
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat(f"Сканування {network} ...")
        self.status_label.setText(f"Сканування {network} ...")

        # Стартуємо потік зі сканером
        self.worker = ScanWorker(network)
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
        self.progress_bar.setRange(0, len(hosts) if hosts else 1)
        self.progress_bar.setValue(len(hosts))
        self.progress_bar.setFormat("Сканування завершено.")

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
            self.status_label.setText(
                f"Сканування завершено. Знайдено {len(hosts)} активних хостів."
            )
        else:
            self.status_label.setText(
                "Сканування завершено. Активних хостів не знайдено."
            )

        self.scan_id_label.setText(f"ID останнього скану: {scan_id}")

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


def run_app():
    """
    Запуск графічного інтерфейсу.
    Викликається з main.py
    """
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
