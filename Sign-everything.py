#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2026 Tripswarlock
# SPDX-License-Identifier: GPL-3.0-only
"""
Sign Everything 1.1.0 (Подпиши всё)

Массовое подписание файлов отсоединённой подписью через КриптоПро CSP.
Работает локально: файлы и PIN-код не покидают компьютер.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

from PyQt5.QtCore import QSettings, QSize, Qt, QThread, pyqtSignal
from PyQt5.QtGui import (
    QColor,
    QFont,
    QFontMetrics,
    QIcon,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
    QTextOption,
)
from PyQt5.QtWidgets import (
    QAction,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QStyle,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

try:
    from cryptography.fernet import Fernet, InvalidToken
    CRYPTO_AVAILABLE = True
except Exception:  # pragma: no cover - зависит от окружения
    Fernet = None
    InvalidToken = Exception
    CRYPTO_AVAILABLE = False


APP_NAME = "Sign Everything"
APP_DISPLAY_NAME = "Подпиши всё"
APP_VERSION = "1.1.0"
APP_REPOSITORY = "https://github.com/Tripswarlock/sign-everything"
APP_WEBSITE = "https://tripswarlock.github.io/"
APP_AUTHOR = "Дмитрий Петровский"
APP_AUTHOR_URL = "https://github.com/Tripswarlock"
APP_EMAIL = "tripswarlock@gmail.com"
APP_LICENSE = "GNU General Public License v3.0"
APP_LICENSE_URL = APP_REPOSITORY + "/blob/main/LICENSE"
PIN_SERVICE = "sign-everything"
PIN_ACCOUNT = "signing-pin"


# ---------------------------------------------------------------------------
# КриптоПро
# ---------------------------------------------------------------------------

def find_cprocsp_tool(name: str) -> Optional[str]:
    """Находит cryptcp/certmgr в стандартных каталогах КриптоПро."""
    override = os.environ.get("CRYPTCP_PATH" if name == "cryptcp" else "CERTMGR_PATH")
    if override and os.path.isfile(override):
        return override

    roots = ["/opt/cprocsp/bin/amd64", "/opt/cprocsp/bin/aarch64", "/opt/cprocsp/bin"]
    for root in roots:
        candidate = os.path.join(root, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate

    found = shutil.which(name)
    return found


def is_signature_artifact(filename: str) -> bool:
    """Подписи и временные файлы подписей не должны попадать в обработку."""
    return filename.lower().endswith((".sig", ".sig.tmp"))


@dataclass
class CertificateInfo:
    cn: str
    subject: str
    email: str = ""
    serial: str = ""
    container: str = ""
    not_after: str = ""

    @property
    def display(self) -> str:
        text = self.cn or self.subject
        if self.email:
            text += f"  ·  {self.email}"
        if self.expired:
            text += "  ·  просрочен"
        return text

    @property
    def expired(self) -> bool:
        if not self.not_after:
            return False
        try:
            return datetime.strptime(
                self.not_after, "%m/%d/%Y %H:%M:%S UTC"
            ) < datetime.utcnow()
        except ValueError:
            return False

    @property
    def tooltip(self) -> str:
        parts = [self.subject]
        if self.serial:
            parts.append(f"Серийный номер: {self.serial}")
        if self.container:
            parts.append(f"Контейнер: {self.container}")
        if self.not_after:
            parts.append(f"Действителен до: {self.not_after}")
        if self.expired:
            parts.append("Статус: срок действия истёк")
        return "\n".join(parts)

    @property
    def on_token(self) -> bool:
        return "SCARD" in self.container.upper()


def _extract_cn(subject: str) -> str:
    match = re.search(r'(?:^|,\s*)CN=(?:"((?:[^"]|"")*)"|([^,]*))', subject)
    if not match:
        return ""
    value = match.group(1) if match.group(1) is not None else match.group(2)
    return value.replace('""', '"').strip()


def parse_certificates(output: str) -> List[CertificateInfo]:
    """Разбирает текстовый вывод `certmgr -list -u` на список сертификатов."""
    certs: List[CertificateInfo] = []
    blocks = re.split(r'(?m)^\s*Issuer\s*:', output)

    for block in blocks[1:]:
        block = "Issuer:" + block
        subject_match = re.search(r'(?m)^\s*Subject\s*:\s*(.+?)\s*$', block)
        if not subject_match:
            continue
        subject = subject_match.group(1).strip()
        cn = _extract_cn(subject)
        if not cn:
            continue

        email_match = re.search(r'(?:^|,\s*)E=([^,]+)', subject)
        serial_match = re.search(r'(?m)^\s*Serial\s*:\s*(.+?)\s*$', block)
        container_match = re.search(r'(?m)^\s*Container\s*:\s*(.+?)\s*$', block)
        valid_match = re.search(r'(?m)^\s*Not valid after\s*:\s*(.+?)\s*$', block)

        certs.append(
            CertificateInfo(
                cn=cn,
                subject=subject,
                email=email_match.group(1).strip() if email_match else "",
                serial=serial_match.group(1).strip() if serial_match else "",
                container=container_match.group(1).strip() if container_match else "",
                not_after=valid_match.group(1).strip() if valid_match else "",
            )
        )
    return certs


# ---------------------------------------------------------------------------
# Хранилище PIN-кода
# ---------------------------------------------------------------------------

class PinStoreError(RuntimeError):
    pass


class PinStore:
    """Хранит PIN в системном keyring, иначе — в зашифрованном локальном файле.

    Локальный файл шифруется Fernet-ключом, производным от случайного секрета
    (права 0600) и machine-id. Это защищает от случайного просмотра PIN в
    открытом виде, но не заменяет системный keyring для враждебной локальной
    среды.
    """

    def __init__(self):
        if sys.platform == "win32":
            config_base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
            data_base = Path(os.environ.get("LOCALAPPDATA", config_base))
        elif sys.platform == "darwin":
            config_base = Path.home() / "Library" / "Application Support"
            data_base = config_base
        else:
            config_base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
            data_base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))

        self.config_dir = config_base / "sign-everything"
        self.data_dir = data_base / "sign-everything"
        self.vault_path = self.config_dir / "pin.vault"
        self.key_path = self.data_dir / "vault.key"

        self.keyring = None
        self.last_error = ""
        try:
            import keyring  # type: ignore

            backend = keyring.get_keyring()
            module = type(backend).__module__.lower()
            if "fail" not in module and "null" not in module:
                self.keyring = keyring
        except Exception as exc:
            self.last_error = str(exc)

    @property
    def available(self) -> bool:
        return bool(self.keyring or CRYPTO_AVAILABLE)

    def backend_name(self) -> str:
        if self.keyring is not None:
            return "системное хранилище"
        if CRYPTO_AVAILABLE:
            return "зашифрованный локальный файл"
        return "недоступно"

    def save(self, pin: str) -> str:
        if not pin:
            self.clear()
            return self.backend_name()

        if self.keyring is not None:
            try:
                self.keyring.set_password(PIN_SERVICE, PIN_ACCOUNT, pin)
                self._remove_fallback()
                return "системное хранилище"
            except Exception as exc:
                self.last_error = str(exc)

        if not CRYPTO_AVAILABLE:
            raise PinStoreError(
                "Нет доступного хранилища PIN. Установите python3-cryptography "
                "или настройте системный keyring."
            )

        key = self._load_or_create_key()
        token = Fernet(key).encrypt(pin.encode("utf-8")).decode("ascii")
        self.config_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.config_dir, 0o700)
        except OSError:
            pass

        payload = json.dumps({"version": 1, "token": token}, ensure_ascii=False)
        tmp_path = self.vault_path.with_suffix(".tmp")
        tmp_path.write_text(payload, encoding="utf-8")
        try:
            os.chmod(tmp_path, 0o600)
        except OSError:
            pass
        os.replace(tmp_path, self.vault_path)
        return "зашифрованный локальный файл"

    def load(self) -> Tuple[Optional[str], str]:
        if self.keyring is not None:
            try:
                pin = self.keyring.get_password(PIN_SERVICE, PIN_ACCOUNT)
                if pin:
                    return pin, "системное хранилище"
            except Exception as exc:
                self.last_error = str(exc)

        if not self.vault_path.exists():
            return None, ""

        if not CRYPTO_AVAILABLE:
            raise PinStoreError(
                "PIN сохранён, но модуль cryptography не установлен. "
                "Установите python3-cryptography."
            )

        try:
            data = json.loads(self.vault_path.read_text(encoding="utf-8"))
            token = data["token"]
            key = self._load_or_create_key()
            pin = Fernet(key).decrypt(token.encode("ascii")).decode("utf-8")
            return pin, "зашифрованный локальный файл"
        except (InvalidToken, KeyError, ValueError) as exc:
            raise PinStoreError(
                "Не удалось расшифровать сохранённый PIN. Возможно, файл повреждён "
                "или перенесён с другого компьютера."
            ) from exc
        except OSError as exc:
            raise PinStoreError(f"Не удалось прочитать сохранённый PIN: {exc}") from exc

    def clear(self) -> None:
        if self.keyring is not None:
            try:
                self.keyring.delete_password(PIN_SERVICE, PIN_ACCOUNT)
            except Exception:
                pass
        self._remove_fallback()

    def _remove_fallback(self) -> None:
        for path in (self.vault_path, self.key_path):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass

    def _load_or_create_key(self) -> bytes:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.data_dir, 0o700)
        except OSError:
            pass

        if self.key_path.exists():
            secret = self.key_path.read_bytes()
            if len(secret) < 32:
                raise PinStoreError("Файл ключа хранилища PIN повреждён.")
        else:
            secret = os.urandom(32)
            self.key_path.write_bytes(secret)
            try:
                os.chmod(self.key_path, 0o600)
            except OSError:
                pass

        machine_id = ""
        for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                machine_id = Path(path).read_text(encoding="utf-8").strip()
                if machine_id:
                    break
            except OSError:
                continue
        if not machine_id:
            machine_id = platform.node()

        try:
            uid = str(os.getuid())
        except AttributeError:
            uid = os.environ.get("USERNAME", "")

        salt = f"{machine_id}|{uid}|{platform.node()}".encode("utf-8")
        derived = hashlib.pbkdf2_hmac("sha256", secret, salt, 200_000, dklen=32)
        return base64.urlsafe_b64encode(derived)


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

class SignWorker(QThread):
    progress = pyqtSignal(int)
    log_message = pyqtSignal(str)
    file_started = pyqtSignal(str, int, int)
    file_processed = pyqtSignal(str, bool)
    file_signed = pyqtSignal(str)
    completed = pyqtSignal(dict)
    cancelled = pyqtSignal(dict)

    def __init__(self, folder: str, dn: str, pin: str, cryptcp: str, parent=None):
        super().__init__(parent)
        self.folder = folder
        self.dn = dn
        self.pin = pin
        self.cryptcp = cryptcp
        self._stop = False
        self._proc: Optional[subprocess.Popen] = None
        self.processed_files = 0
        self.total_files = 0

    def request_stop(self) -> None:
        self._stop = True
        proc = self._proc
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                pass

    def _scan_files(self) -> List[str]:
        result: List[str] = []
        for root, _, filenames in os.walk(self.folder):
            for filename in filenames:
                if is_signature_artifact(filename):
                    continue
                source = os.path.join(root, filename)
                if not os.path.exists(source + ".sig"):
                    result.append(source)
        result.sort(key=lambda value: value.lower())
        return result

    @staticmethod
    def _clean_output(value: str) -> str:
        value = value.replace("\b", "").replace("\r", "\n")
        lines = []
        for line in value.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.lower().startswith("type pin-code"):
                continue
            lines.append(line)
        return " | ".join(lines[-4:])[:700]

    def _cancelled_result(self, started: float, signed: int, failed: int) -> dict:
        return {
            "total": self.total_files,
            "processed": self.processed_files,
            "signed": signed,
            "failed": failed,
            "cancelled": True,
            "duration": time.monotonic() - started,
        }

    def run(self) -> None:
        started = time.monotonic()
        files = self._scan_files()
        self.total_files = len(files)
        signed = 0
        failed = 0

        if not files:
            self.log_message.emit("Нет необработанных файлов: все документы уже подписаны.")
            self.completed.emit(
                {
                    "total": 0,
                    "processed": 0,
                    "signed": 0,
                    "failed": 0,
                    "cancelled": False,
                    "duration": time.monotonic() - started,
                }
            )
            return

        self.log_message.emit(f"К подписанию: {len(files)}. Сертификат: {self.dn}")
        self.progress.emit(0)

        for idx, source in enumerate(files, 1):
            if self._stop:
                self.cancelled.emit(self._cancelled_result(started, signed, failed))
                return

            filename = os.path.basename(source)
            self.file_started.emit(source, idx, len(files))
            target = source + ".sig"
            temp_target = source + ".sig.tmp"

            proc = None
            try:
                if os.path.exists(temp_target):
                    os.unlink(temp_target)

                proc = subprocess.Popen(
                    [
                        self.cryptcp,
                        "-sign",
                        "-detach",
                        "-dn",
                        self.dn,
                        source,
                        temp_target,
                    ],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
                self._proc = proc
                try:
                    stdout, stderr = proc.communicate(self.pin + "\n", timeout=120)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    stdout, stderr = proc.communicate()
                    raise TimeoutError("превышено время ожидания (120 с)")
            except FileNotFoundError:
                self.log_message.emit("Ошибка: не найден cryptcp. Проверьте установку КриптоПро CSP.")
                self.cancelled.emit(self._cancelled_result(started, signed, failed + 1))
                return
            except Exception as exc:
                if self._stop:
                    self._safe_unlink(temp_target)
                    self.cancelled.emit(self._cancelled_result(started, signed, failed))
                    return
                failed += 1
                self.processed_files = idx
                self.log_message.emit(f"Ошибка · {filename}: {exc}")
                self.file_processed.emit(source, False)
                self.progress.emit(int(idx / len(files) * 100))
                continue
            finally:
                self._proc = None

            if self._stop:
                self._safe_unlink(temp_target)
                self.cancelled.emit(self._cancelled_result(started, signed, failed))
                return

            rc = proc.returncode if proc is not None else -1
            success = rc == 0 and os.path.exists(temp_target) and os.path.getsize(temp_target) > 0
            if success:
                try:
                    os.replace(temp_target, target)
                    signed += 1
                    self.file_signed.emit(source)
                    self.log_message.emit(f"OK · {filename}")
                    processed_ok = True
                except OSError as exc:
                    failed += 1
                    self._safe_unlink(temp_target)
                    self.log_message.emit(f"Ошибка · {filename}: {exc}")
                    processed_ok = False
            else:
                failed += 1
                self._safe_unlink(temp_target)
                detail = self._clean_output((stderr or "") + "\n" + (stdout or ""))
                if not detail:
                    detail = f"cryptcp завершился с кодом {rc}"
                self.log_message.emit(f"Ошибка · {filename}: {detail}")
                processed_ok = False

            self.processed_files = idx
            self.file_processed.emit(source, processed_ok)
            self.progress.emit(int(idx / len(files) * 100))

        if self._stop:
            self.cancelled.emit(self._cancelled_result(started, signed, failed))
            return

        self.completed.emit(
            {
                "total": len(files),
                "processed": self.processed_files,
                "signed": signed,
                "failed": failed,
                "cancelled": False,
                "duration": time.monotonic() - started,
            }
        )

    @staticmethod
    def _safe_unlink(path: str) -> None:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Вспомогательные виджеты
# ---------------------------------------------------------------------------

def repolish(widget: QWidget) -> None:
    widget.style().unpolish(widget)
    widget.style().polish(widget)
    widget.update()


class ElidedLabel(QLabel):
    def __init__(self, text: str = "", parent=None):
        super().__init__(parent)
        self._full_text = ""
        self.set_full_text(text)

    def set_full_text(self, text: str) -> None:
        self._full_text = text or ""
        self.setToolTip(self._full_text)
        self._update_text()

    def full_text(self) -> str:
        return self._full_text

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._update_text()

    def minimumSizeHint(self):
        hint = super().minimumSizeHint()
        return QSize(0, hint.height())

    def _update_text(self) -> None:
        width = max(0, self.width() - 4)
        if width:
            text = QFontMetrics(self.font()).elidedText(
                self._full_text, Qt.ElideMiddle, width
            )
            super().setText(text)
        else:
            super().setText(self._full_text)


class StatCard(QFrame):
    def __init__(self, caption: str, accent: bool = False, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setMinimumHeight(58)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 7, 10, 6)
        layout.setSpacing(0)

        self.value_label = QLabel("0")
        self.value_label.setObjectName("StatValue")
        self.value_label.setProperty("accent", "true" if accent else "false")
        caption_label = QLabel(caption)
        caption_label.setObjectName("StatCaption")
        layout.addWidget(self.value_label)
        layout.addWidget(caption_label)

    def set_value(self, value: int) -> None:
        self.value_label.setText(str(value))


class DropZone(QFrame):
    folderDropped = pyqtSignal(str)
    chooseClicked = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("DropZone")
        self.setAcceptDrops(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(82)
        self.setProperty("dragActive", "false")
        self.setProperty("selected", "false")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(10)

        icon_label = QLabel()
        icon_label.setObjectName("DropIcon")
        icon_label.setFixedSize(36, 36)
        icon_label.setAlignment(Qt.AlignCenter)
        icon_label.setPixmap(
            self.style().standardIcon(QStyle.SP_DirOpenIcon).pixmap(22, 22)
        )
        layout.addWidget(icon_label)

        text_layout = QVBoxLayout()
        text_layout.setSpacing(1)
        self.title_label = QLabel("Перетащите папку с документами")
        self.title_label.setObjectName("DropTitle")
        self.path_label = ElidedLabel("Или выберите вручную · вложенные папки обрабатываются")
        self.path_label.setObjectName("DropHint")
        text_layout.addWidget(self.title_label)
        text_layout.addWidget(self.path_label)
        layout.addLayout(text_layout, 1)

        self.choose_button = QPushButton("Выбрать")
        self.choose_button.setObjectName("Secondary")
        self.choose_button.setCursor(Qt.PointingHandCursor)
        self.choose_button.clicked.connect(self.chooseClicked)
        layout.addWidget(self.choose_button)

    def set_folder(self, path: str) -> None:
        self.title_label.setText("Папка выбрана")
        self.path_label.set_full_text(path)
        self.setProperty("selected", "true")
        repolish(self)

    def clear_folder(self) -> None:
        self.title_label.setText("Перетащите папку с документами")
        self.path_label.set_full_text("Или выберите вручную · вложенные папки обрабатываются")
        self.setProperty("selected", "false")
        repolish(self)

    def _has_folder(self, mime_data) -> bool:
        if not mime_data.hasUrls():
            return False
        return any(url.isLocalFile() and os.path.isdir(url.toLocalFile()) for url in mime_data.urls())

    def dragEnterEvent(self, event):
        if self._has_folder(event.mimeData()):
            event.acceptProposedAction()
            self.setProperty("dragActive", "true")
            repolish(self)

    def dragLeaveEvent(self, event):
        self.setProperty("dragActive", "false")
        repolish(self)

    def dropEvent(self, event):
        self.setProperty("dragActive", "false")
        repolish(self)
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if os.path.isdir(path):
                self.folderDropped.emit(path)
                event.acceptProposedAction()
                return

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.chooseClicked.emit()
        super().mouseReleaseEvent(event)


def make_app_icon() -> QIcon:
    pixmap = QPixmap(64, 64)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setPen(Qt.NoPen)
    painter.setBrush(QColor("#2F6BFF"))
    painter.drawRoundedRect(2, 2, 60, 60, 14, 14)
    painter.setPen(QColor("#FFFFFF"))
    painter.setFont(QFont("DejaVu Sans", 28, QFont.Bold))
    painter.drawText(pixmap.rect(), Qt.AlignCenter, "S")
    painter.end()
    return QIcon(pixmap)


def make_eye_icon(visible: bool) -> QIcon:
    """Рисует глаз без внешних ресурсов: открытый или перечёркнутый."""
    pixmap = QPixmap(36, 36)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)

    pen = QPen(QColor("#40536C"), 2.1)
    pen.setCapStyle(Qt.RoundCap)
    pen.setJoinStyle(Qt.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.NoBrush)

    eye = QPainterPath()
    eye.moveTo(3, 18)
    eye.cubicTo(8, 8, 28, 8, 33, 18)
    eye.cubicTo(28, 28, 8, 28, 3, 18)
    painter.drawPath(eye)

    painter.setPen(Qt.NoPen)
    painter.setBrush(QColor("#40536C"))
    painter.drawEllipse(12, 12, 12, 12)

    if not visible:
        painter.setPen(pen)
        painter.drawLine(6, 6, 30, 30)

    painter.end()
    return QIcon(pixmap)


# ---------------------------------------------------------------------------
# Главное окно
# ---------------------------------------------------------------------------

APP_QSS = """
QMainWindow, QWidget#Root, QDialog { background: #F4F7FB; }
QScrollArea { background: transparent; border: 0; }
QScrollBar:vertical {
    background: transparent;
    width: 9px;
    margin: 2px;
}
QScrollBar::handle:vertical {
    background: #C9D5E6;
    min-height: 28px;
    border-radius: 4px;
}
QScrollBar::handle:vertical:hover { background: #AFC0D8; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }
QMenuBar {
    background: #F4F7FB;
    color: #40536C;
    font-size: 8pt;
    padding: 1px 4px;
    border: 0;
}
QMenuBar::item {
    background: transparent;
    padding: 3px 8px;
    border-radius: 6px;
}
QMenuBar::item:selected { background: #EAF1FF; color: #2F6BFF; }
QMenu {
    background: #FFFFFF;
    color: #172033;
    border: 1px solid #DCE4EF;
    padding: 4px;
}
QMenu::item { padding: 6px 18px; border-radius: 5px; }
QMenu::item:selected { background: #EAF1FF; color: #2F6BFF; }
QFrame#Header {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                stop:0 #102C55, stop:1 #2356A4);
    border-radius: 14px;
}
QLabel#BrandMark {
    background: rgba(255, 255, 255, 0.14);
    border: 1px solid rgba(255, 255, 255, 0.22);
    border-radius: 9px;
    color: #FFFFFF;
    font-size: 13pt;
    font-weight: 700;
}
QLabel#BrandTitle { color: #FFFFFF; font-size: 14pt; font-weight: 700; }
QLabel#BrandSubtitle { color: rgba(255, 255, 255, 0.72); font-size: 7.5pt; }
QLabel#HeaderBadge {
    background: rgba(255, 255, 255, 0.12);
    border: 1px solid rgba(255, 255, 255, 0.20);
    border-radius: 9px;
    color: #FFFFFF;
    padding: 3px 8px;
    font-size: 7pt;
    font-weight: 600;
}
QLabel#HeaderBadge[state="warn"] {
    background: rgba(255, 190, 92, 0.20);
    border-color: rgba(255, 210, 140, 0.45);
}
QFrame#Card {
    background: #FFFFFF;
    border: 1px solid #E4EAF3;
    border-radius: 12px;
}
QLabel#CardTitle { color: #172033; font-size: 8.5pt; font-weight: 700; }
QLabel#FieldLabel { color: #4A5A70; font-size: 7.5pt; font-weight: 600; }
QLabel#Hint { color: #8190A5; font-size: 7pt; }
QLabel#StatValue { color: #172033; font-size: 15pt; font-weight: 700; }
QLabel#StatValue[accent="true"] { color: #2F6BFF; }
QLabel#StatCaption { color: #7A899E; font-size: 7pt; }
QFrame#DropZone {
    background: #FFFFFF;
    border: 2px dashed #C8D6E8;
    border-radius: 12px;
}
QFrame#DropZone[dragActive="true"] {
    background: #F3F7FF;
    border-color: #2F6BFF;
}
QFrame#DropZone[selected="true"] {
    background: #F8FAFF;
    border: 1px solid #CFE0FF;
}
QLabel#DropTitle { color: #172033; font-size: 9.5pt; font-weight: 700; }
QLabel#DropHint { color: #7B8BA1; font-size: 7.5pt; }
QLabel#DropIcon {
    background: #EAF1FF;
    border-radius: 10px;
}
QComboBox, QLineEdit {
    background: #F8FAFD;
    border: 1px solid #DCE4EF;
    border-radius: 7px;
    padding: 5px 8px;
    color: #172033;
    font-size: 8.5pt;
    selection-background-color: #2F6BFF;
    min-height: 16px;
}
QComboBox:focus, QLineEdit:focus {
    background: #FFFFFF;
    border: 1px solid #2F6BFF;
}
QComboBox QAbstractItemView {
    background: #FFFFFF;
    border: 1px solid #DCE4EF;
    selection-background-color: #EAF1FF;
    selection-color: #172033;
    padding: 4px;
}
QComboBox QLineEdit {
    background: transparent;
    border: 0;
    padding: 0;
    min-height: 0;
}
QComboBox::drop-down {
    border: 0;
    width: 24px;
}
QPushButton {
    font-family: "DejaVu Sans";
    font-size: 8pt;
}
QPushButton#Secondary {
    background: #F1F5FB;
    color: #24405F;
    border: 1px solid #DCE5F1;
    border-radius: 7px;
    padding: 6px 10px;
    font-weight: 600;
}
QPushButton#Secondary:hover { background: #E8EFF9; }
QPushButton#Secondary:disabled { color: #A5B1C2; background: #F6F8FB; }
QPushButton#Primary {
    background: #2F6BFF;
    color: #FFFFFF;
    border: 0;
    border-radius: 8px;
    padding: 8px 14px;
    font-size: 8.5pt;
    font-weight: 700;
}
QPushButton#Primary:hover { background: #1F56DB; }
QPushButton#Primary:pressed { background: #1747BA; }
QPushButton#Primary:disabled { background: #C9D7EF; color: #F5F8FD; }
QPushButton#Danger {
    background: #FFF2F3;
    color: #C43A4C;
    border: 1px solid #F4CDD3;
    border-radius: 7px;
    padding: 6px 12px;
    font-weight: 600;
}
QPushButton#Danger:hover { background: #FFE7EA; }
QPushButton#Danger:disabled {
    background: #F7F8FA; color: #B6C0CD; border-color: #E6EAF0;
}
QPushButton#EyeButton {
    background: transparent;
    border: 0;
    border-radius: 6px;
    padding: 0;
}
QPushButton#EyeButton:hover { background: #EEF4FF; }
QPushButton#EyeButton:checked { background: #EAF1FF; }
QPushButton#Ghost {
    background: transparent;
    color: #5E7089;
    border: 0;
    border-radius: 6px;
    padding: 5px 6px;
}
QPushButton#Ghost:hover { color: #2F6BFF; background: #EEF4FF; }
QPushButton#Link {
    background: transparent;
    color: #5E7089;
    border: 0;
    padding: 3px 1px;
    text-decoration: underline;
}
QPushButton#Link:hover { color: #C43A4C; }
QCheckBox { color: #4A5A70; font-size: 8pt; spacing: 6px; }
QProgressBar {
    background: #E8EEF8;
    border: 0;
    border-radius: 3px;
    max-height: 6px;
    min-height: 6px;
}
QProgressBar::chunk { background: #2F6BFF; border-radius: 3px; }
QTextEdit#Log {
    background: #F8FAFD;
    border: 1px solid #E1E8F2;
    border-radius: 8px;
    color: #33465E;
    font-family: "DejaVu Sans Mono";
    font-size: 7.5pt;
    padding: 6px;
    selection-background-color: #D8E5FF;
}
QLabel#Chip {
    background: #EDF2F9;
    color: #607089;
    border-radius: 8px;
    padding: 4px 8px;
    font-size: 7pt;
    font-weight: 700;
}
QLabel#Chip[state="busy"] { background: #EAF1FF; color: #2F6BFF; }
QLabel#Chip[state="ok"] { background: #E8F7F1; color: #0F8A64; }
QLabel#Chip[state="error"] { background: #FFF0F2; color: #C43A4C; }
QLabel#PinStatus { color: #8190A5; font-size: 7pt; }
QLabel#PinStatus[state="ok"] { color: #0F8A64; }
QLabel#PinStatus[state="warn"] { color: #B26A00; }
QLabel#PinStatus[state="error"] { color: #C43A4C; }
QLabel#CurrentFile { color: #8190A5; font-size: 7pt; }
QLabel#Percent { color: #40536C; font-size: 8pt; font-weight: 700; }
QFrame#Separator { background: #E4EAF3; border: 0; }
QLabel#AboutTitle { color: #172033; font-size: 16pt; font-weight: 700; }
QLabel#AboutVersion { color: #8190A5; font-size: 8pt; }
QLabel#AboutDescription { color: #40536C; font-size: 8.5pt; }
QLabel#AboutCaption { color: #8190A5; font-size: 8pt; }
QLabel#AboutLink { color: #2F6BFF; font-size: 8.5pt; }
QLabel#AboutNote { color: #8190A5; font-size: 7.5pt; }
"""


class AboutDialog(QDialog):
    """Компактное окно «О программе» в духе WindowRecorder."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("О программе")
        self.setWindowIcon(make_app_icon())
        self.setModal(True)
        self.setSizeGripEnabled(False)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.setStyleSheet(APP_QSS)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 18, 22, 14)
        layout.setSpacing(8)

        header = QHBoxLayout()
        header.setSpacing(14)
        icon = QLabel()
        icon.setFixedSize(54, 54)
        icon.setPixmap(make_app_icon().pixmap(54, 54))
        header.addWidget(icon)

        title_box = QVBoxLayout()
        title_box.setSpacing(1)
        title = QLabel(APP_DISPLAY_NAME)
        title.setObjectName("AboutTitle")
        version = QLabel(f"Версия {APP_VERSION}")
        version.setObjectName("AboutVersion")
        title_box.addWidget(title)
        title_box.addWidget(version)
        header.addLayout(title_box)
        header.addStretch(1)
        layout.addLayout(header)

        description = QLabel(
            "Массовое подписание файлов отсоединённой подписью через КриптоПро CSP. "
            "Поддержка аппаратных токенов, выбор сертификата, журнал операций, "
            "остановка подписания и запоминание PIN-кода."
        )
        description.setObjectName("AboutDescription")
        description.setWordWrap(True)
        layout.addWidget(description)

        separator = QFrame()
        separator.setObjectName("Separator")
        separator.setFixedHeight(1)
        layout.addWidget(separator)

        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(5)
        grid.setColumnMinimumWidth(0, 104)
        rows = [
            ("Автор", APP_AUTHOR, APP_AUTHOR_URL),
            ("Почта", APP_EMAIL, "mailto:" + APP_EMAIL),
            ("Репозиторий", "github.com/Tripswarlock/sign-everything", APP_REPOSITORY),
            ("Страница проекта", "tripswarlock.github.io", APP_WEBSITE),
            ("Лицензия", APP_LICENSE, APP_LICENSE_URL),
        ]
        for row, (caption, text, url) in enumerate(rows):
            caption_label = QLabel(caption)
            caption_label.setObjectName("AboutCaption")
            grid.addWidget(caption_label, row, 0)
            link = QLabel()
            link.setObjectName("AboutLink")
            link.setTextFormat(Qt.RichText)
            link.setText(
                f'<a href="{html.escape(url)}" '
                f'style="color:#2F6BFF; text-decoration:none;">{html.escape(text)}</a>'
            )
            link.setOpenExternalLinks(True)
            link.setTextInteractionFlags(Qt.TextBrowserInteraction)
            link.setToolTip(url)
            grid.addWidget(link, row, 1)
        layout.addLayout(grid)

        note = QLabel(
            "Это свободное программное обеспечение под GNU GPL v3.0. "
            "© 2026 Tripswarlock."
        )
        note.setObjectName("AboutNote")
        note.setWordWrap(True)
        layout.addWidget(note)

        footer = QHBoxLayout()
        site = QLabel(
            f'<a href="{APP_WEBSITE}" style="color:#8190A5; text-decoration:none;">'
            f'{APP_WEBSITE.replace("https://", "")}</a>'
        )
        site.setObjectName("AboutNote")
        site.setTextFormat(Qt.RichText)
        site.setOpenExternalLinks(True)
        site.setTextInteractionFlags(Qt.TextBrowserInteraction)
        footer.addWidget(site)
        footer.addStretch(1)
        close_btn = QPushButton("Закрыть")
        close_btn.setObjectName("Secondary")
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.setFixedWidth(96)
        close_btn.clicked.connect(self.accept)
        footer.addWidget(close_btn)
        layout.addLayout(footer)

        self.setFixedWidth(560)
        self.adjustSize()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = QSettings("Tripswarlock", "SignEverything")
        self.pin_store = PinStore()
        self.cryptcp = find_cprocsp_tool("cryptcp")
        self.certmgr = find_cprocsp_tool("certmgr")

        self.current_folder: Optional[str] = None
        self.worker: Optional[SignWorker] = None
        self.total_files = 0
        self.already_signed = 0
        self.files_to_sign = 0
        self.processed_files = 0
        self._busy = False
        self._pin_saved = False
        self._loading_pin = False
        self._last_worker_summary: Optional[dict] = None

        self.setWindowTitle(f"{APP_NAME} {APP_VERSION} — подписание файлов КриптоПро")
        self.setWindowIcon(make_app_icon())
        self.setMinimumSize(680, 560)
        self.resize(680, 700)

        self._build_ui()
        self._restore_settings()
        self._load_saved_pin()
        self._check_environment()
        self.load_certificates()
        self._restore_folder()

    # ---- построение интерфейса -------------------------------------------------

    def _build_ui(self) -> None:
        self._build_menu()

        body = QWidget()
        body.setObjectName("Root")

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setWidget(body)
        scroll.viewport().setAutoFillBackground(False)
        self.setCentralWidget(scroll)
        self.setStyleSheet(APP_QSS)

        root = QVBoxLayout(body)
        root.setContentsMargins(16, 12, 16, 10)
        root.setSpacing(8)

        root.addWidget(self._build_header())
        self.drop_zone = DropZone()
        self.drop_zone.folderDropped.connect(self.select_folder_path)
        self.drop_zone.chooseClicked.connect(self.select_folder)
        root.addWidget(self.drop_zone)
        root.addWidget(self._build_stats())
        root.addWidget(self._build_settings())
        root.addWidget(self._build_actions())
        root.addWidget(self._build_log(), 1)

    def _build_menu(self) -> None:
        menu_bar = self.menuBar()
        menu_bar.setObjectName("MenuBar")
        help_menu = menu_bar.addMenu("Справка")

        about_action = QAction("О программе", self)
        about_action.setShortcut("F1")
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def show_about(self) -> None:
        dialog = AboutDialog(self)
        dialog.exec_()

    def _build_header(self) -> QFrame:
        header = QFrame()
        header.setObjectName("Header")
        header.setFixedHeight(72)
        layout = QHBoxLayout(header)
        layout.setContentsMargins(16, 10, 14, 10)
        layout.setSpacing(10)

        mark = QLabel("S")
        mark.setObjectName("BrandMark")
        mark.setAlignment(Qt.AlignCenter)
        mark.setFixedSize(34, 34)
        layout.addWidget(mark)

        text_layout = QVBoxLayout()
        text_layout.setSpacing(0)
        title = QLabel(APP_DISPLAY_NAME)
        title.setObjectName("BrandTitle")
        subtitle = QLabel("Подписание документов через КриптоПро CSP")
        subtitle.setObjectName("BrandSubtitle")
        text_layout.addWidget(title)
        text_layout.addWidget(subtitle)
        layout.addLayout(text_layout)
        layout.addStretch(1)

        self.token_badge = QLabel("Проверка токена…")
        self.token_badge.setObjectName("HeaderBadge")
        self.token_badge.setProperty("state", "warn")
        layout.addWidget(self.token_badge)

        version_badge = QLabel(f"v{APP_VERSION}")
        version_badge.setObjectName("HeaderBadge")
        layout.addWidget(version_badge)
        return header

    def _build_stats(self) -> QWidget:
        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        self.stat_total = StatCard("Всего документов")
        self.stat_todo = StatCard("К подписанию", accent=True)
        self.stat_signed = StatCard("Уже подписано")
        self.stat_processed = StatCard("Обработано")
        for card in (self.stat_total, self.stat_todo, self.stat_signed, self.stat_processed):
            layout.addWidget(card)
        return container

    def _build_settings(self) -> QFrame:
        card = QFrame()
        card.setObjectName("Card")
        outer = QVBoxLayout(card)
        outer.setContentsMargins(14, 10, 14, 8)
        outer.setSpacing(6)

        title_row = QHBoxLayout()
        title = QLabel("Параметры подписания")
        title.setObjectName("CardTitle")
        title_row.addWidget(title)
        title_row.addStretch(1)
        self.storage_label = QLabel(
            f"PIN: {self.pin_store.backend_name() if self.pin_store.available else 'хранилище недоступно'}"
        )
        self.storage_label.setObjectName("Hint")
        title_row.addWidget(self.storage_label)
        outer.addLayout(title_row)

        grid = QGridLayout()
        grid.setHorizontalSpacing(6)
        grid.setVerticalSpacing(5)
        grid.setColumnMinimumWidth(0, 66)
        grid.setColumnStretch(1, 1)

        cert_label = QLabel("Сертификат")
        cert_label.setObjectName("FieldLabel")
        grid.addWidget(cert_label, 0, 0)

        self.cert_combo = QComboBox()
        self.cert_combo.setEditable(True)
        self.cert_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.cert_combo.setMinimumHeight(30)
        self.cert_combo.lineEdit().setPlaceholderText("Сертификат не выбран — обновите список")
        self.cert_combo.currentIndexChanged.connect(self._on_cert_changed)
        self.cert_combo.editTextChanged.connect(lambda _: self._update_sign_enabled())
        grid.addWidget(self.cert_combo, 0, 1, 1, 3)

        self.refresh_btn = QPushButton()
        self.refresh_btn.setObjectName("Secondary")
        self.refresh_btn.setIcon(self.style().standardIcon(QStyle.SP_BrowserReload))
        self.refresh_btn.setIconSize(QSize(14, 14))
        self.refresh_btn.setCursor(Qt.PointingHandCursor)
        self.refresh_btn.setFixedSize(30, 30)
        self.refresh_btn.setToolTip("Обновить список сертификатов")
        self.refresh_btn.clicked.connect(self.load_certificates)
        grid.addWidget(self.refresh_btn, 0, 4)

        pin_label = QLabel("PIN-код")
        pin_label.setObjectName("FieldLabel")
        grid.addWidget(pin_label, 1, 0)

        self.pin_edit = QLineEdit()
        self.pin_edit.setPlaceholderText("Введите PIN-код")
        self.pin_edit.setEchoMode(QLineEdit.Password)
        self.pin_edit.setMinimumHeight(30)
        self.pin_edit.setFixedWidth(152)
        self.pin_edit.textEdited.connect(self._on_pin_edited)
        self.pin_edit.returnPressed.connect(self.start_signing)

        self.eye_btn = QPushButton()
        self.eye_btn.setObjectName("EyeButton")
        self.eye_btn.setCheckable(True)
        self.eye_btn.setCursor(Qt.PointingHandCursor)
        self.eye_btn.setFixedSize(30, 30)
        self.eye_btn.setIcon(make_eye_icon(False))
        self.eye_btn.setIconSize(QSize(22, 22))
        self.eye_btn.setToolTip("Показать PIN")
        self.eye_btn.setAccessibleName("Показать PIN")
        self.eye_btn.toggled.connect(self._toggle_pin_visibility)

        self.remember_check = QCheckBox("Запомнить PIN")
        self.remember_check.setToolTip(
            "PIN будет сохранён в системном хранилище или в зашифрованном файле "
            "после первого успешного подписания."
        )
        self.remember_check.stateChanged.connect(self._on_remember_changed)
        if not self.pin_store.available:
            self.remember_check.setEnabled(False)
            self.remember_check.setToolTip(
                "Установите python3-cryptography или настройте системный keyring."
            )

        self.forget_btn = QPushButton("Забыть")
        self.forget_btn.setObjectName("Link")
        self.forget_btn.setCursor(Qt.PointingHandCursor)
        self.forget_btn.setToolTip("Удалить сохранённый PIN и очистить поле")
        self.forget_btn.clicked.connect(self._forget_pin)

        pin_row = QHBoxLayout()
        pin_row.setSpacing(7)
        pin_row.addWidget(self.pin_edit)
        pin_row.addWidget(self.eye_btn)
        pin_row.addStretch(1)
        pin_row.addWidget(self.remember_check)
        pin_row.addWidget(self.forget_btn)
        grid.addLayout(pin_row, 1, 1, 1, 4)

        self.pin_status = QLabel("PIN не сохраняется в открытом виде")
        self.pin_status.setObjectName("PinStatus")
        grid.addWidget(self.pin_status, 2, 1, 1, 4)

        outer.addLayout(grid)
        return card

    def _build_actions(self) -> QFrame:
        card = QFrame()
        card.setObjectName("Card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 9, 14, 8)
        layout.setSpacing(6)

        row = QHBoxLayout()
        row.setSpacing(7)
        self.btn_sign = QPushButton("Подписать файлы")
        self.btn_sign.setObjectName("Primary")
        self.btn_sign.setCursor(Qt.PointingHandCursor)
        self.btn_sign.setMinimumHeight(36)
        self.btn_sign.setMinimumWidth(160)
        self.btn_sign.setEnabled(False)
        self.btn_sign.clicked.connect(self.start_signing)
        row.addWidget(self.btn_sign)

        self.btn_stop = QPushButton("Остановить")
        self.btn_stop.setObjectName("Danger")
        self.btn_stop.setCursor(Qt.PointingHandCursor)
        self.btn_stop.setMinimumHeight(36)
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_signing)
        row.addWidget(self.btn_stop)

        self.status_chip = QLabel("Ожидание")
        self.status_chip.setObjectName("Chip")
        self.status_chip.setProperty("state", "idle")
        row.addStretch(1)
        row.addWidget(self.status_chip)

        self.percent_label = QLabel("0%")
        self.percent_label.setObjectName("Percent")
        self.percent_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.percent_label.setFixedWidth(38)
        row.addWidget(self.percent_label)
        layout.addLayout(row)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        layout.addWidget(self.progress_bar)

        self.current_file = ElidedLabel("Выберите папку, чтобы начать")
        self.current_file.setObjectName("CurrentFile")
        layout.addWidget(self.current_file)
        return card

    def _build_log(self) -> QFrame:
        card = QFrame()
        card.setObjectName("Card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 8, 14, 8)
        layout.setSpacing(5)

        header = QHBoxLayout()
        title = QLabel("Журнал выполнения")
        title.setObjectName("CardTitle")
        header.addWidget(title)
        header.addStretch(1)

        self.copy_btn = QPushButton("Копировать")
        self.copy_btn.setObjectName("Ghost")
        self.copy_btn.setCursor(Qt.PointingHandCursor)
        self.copy_btn.clicked.connect(self._copy_log)
        header.addWidget(self.copy_btn)

        self.clear_btn = QPushButton("Очистить")
        self.clear_btn.setObjectName("Ghost")
        self.clear_btn.setCursor(Qt.PointingHandCursor)
        self.clear_btn.clicked.connect(self._clear_log)
        header.addWidget(self.clear_btn)
        layout.addLayout(header)

        self.log = QTextEdit()
        self.log.setObjectName("Log")
        self.log.setReadOnly(True)
        self.log.setMinimumHeight(80)
        self.log.setMinimumWidth(0)
        self.log.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.log.setLineWrapMode(QTextEdit.WidgetWidth)
        self.log.setWordWrapMode(QTextOption.WrapAtWordBoundaryOrAnywhere)
        self.log.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Expanding)
        self.log.document().setMaximumBlockCount(2500)
        layout.addWidget(self.log, 1)
        return card

    # ---- настройки и PIN -------------------------------------------------------

    def _restore_settings(self) -> None:
        geometry = self.settings.value("window/geometry")
        if geometry is not None:
            self.restoreGeometry(geometry)

    def _restore_folder(self) -> None:
        folder = self.settings.value("last_folder", "", type=str)
        if folder and os.path.isdir(folder):
            self.select_folder_path(folder, quiet=True)

    def _load_saved_pin(self) -> None:
        if not self.pin_store.available:
            self._set_pin_status(
                "Сохранение PIN недоступно: установите python3-cryptography", "error"
            )
            return

        self._loading_pin = True
        try:
            pin, backend = self.pin_store.load()
            if pin:
                self.pin_edit.setText(pin)
                self.remember_check.setChecked(True)
                self._pin_saved = True
                self._set_pin_status(f"PIN сохранён · {backend}", "ok")
                self._append_log(f"PIN загружен из хранилища ({backend}).")
            else:
                self._pin_saved = False
                self._set_pin_status(
                    "PIN не сохранён. Поставьте галочку «Запомнить PIN».", "muted"
                )
        except PinStoreError as exc:
            self._pin_saved = False
            self._set_pin_status(str(exc), "error")
            self._append_log(f"Хранилище PIN: {exc}")
        finally:
            self._loading_pin = False

    def _on_remember_changed(self, state: int) -> None:
        if self._loading_pin:
            return
        if state == Qt.Checked:
            if self.pin_edit.text().strip():
                self._set_pin_status(
                    "PIN будет сохранён после первого успешного подписания.", "warn"
                )
            else:
                self._set_pin_status("Введите PIN, чтобы сохранить его.", "muted")
        else:
            self._forget_pin(silent=True, clear_field=False)
            self._set_pin_status("PIN не сохраняется.", "muted")

    def _on_pin_edited(self, _text: str) -> None:
        if self._pin_saved:
            self._pin_saved = False
            try:
                self.pin_store.clear()
            except Exception:
                pass
        if self.remember_check.isChecked():
            self._set_pin_status(
                "Новый PIN будет сохранён после успешного подписания.", "warn"
            )

    def _save_pin_after_success(self) -> None:
        if self._pin_saved or not self.remember_check.isChecked():
            return
        pin = self.pin_edit.text().strip()
        if not pin:
            return
        try:
            backend = self.pin_store.save(pin)
            self._pin_saved = True
            self._set_pin_status(f"PIN сохранён · {backend}", "ok")
            self._append_log(f"PIN сохранён ({backend}).")
        except Exception as exc:
            self._set_pin_status(f"Не удалось сохранить PIN: {exc}", "error")
            self._append_log(f"Не удалось сохранить PIN: {exc}")

    def _forget_pin(self, silent: bool = False, clear_field: bool = True) -> None:
        try:
            self.pin_store.clear()
        except Exception as exc:
            self._append_log(f"Не удалось удалить сохранённый PIN: {exc}")
        self._pin_saved = False
        self._loading_pin = True
        if clear_field:
            self.pin_edit.clear()
        self.remember_check.setChecked(False)
        self._loading_pin = False
        if not silent:
            self._set_pin_status("Сохранённый PIN удалён.", "muted")
            self._append_log("Сохранённый PIN удалён.")

    def _toggle_pin_visibility(self, visible: bool) -> None:
        self.pin_edit.setEchoMode(QLineEdit.Normal if visible else QLineEdit.Password)
        self.eye_btn.setIcon(make_eye_icon(visible))
        self.eye_btn.setToolTip("Скрыть PIN" if visible else "Показать PIN")
        self.eye_btn.setAccessibleName("Скрыть PIN" if visible else "Показать PIN")

    def _set_pin_status(self, text: str, state: str = "muted") -> None:
        self.pin_status.setText(text)
        self.pin_status.setProperty("state", state)
        repolish(self.pin_status)

    # ---- среда и сертификаты ---------------------------------------------------

    def _check_environment(self) -> None:
        if not self.cryptcp:
            self._append_log(
                "ОШИБКА: cryptcp не найден. Установите КриптоПро CSP или задайте CRYPTCP_PATH."
            )
            self._set_token_badge("КриптоПро не найден", "warn")
        if not self.certmgr:
            self._append_log(
                "ОШИБКА: certmgr не найден. Список сертификатов будет недоступен."
            )

    def _set_token_badge(self, text: str, state: str = "ok") -> None:
        self.token_badge.setText(text)
        self.token_badge.setProperty("state", state)
        repolish(self.token_badge)

    def load_certificates(self, checked=None) -> None:
        if not self.certmgr:
            self._set_token_badge("КриптоПро не найден", "warn")
            return

        previous = self.cert_combo.currentData()
        if not isinstance(previous, str):
            previous = ""

        self.refresh_btn.setEnabled(False)
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            env = os.environ.copy()
            env["LC_ALL"] = "C.UTF-8"
            env["LANG"] = "C.UTF-8"
            result = subprocess.run(
                [self.certmgr, "-list", "-u"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20,
                env=env,
            )
        except FileNotFoundError:
            self._append_log("certmgr не найден. Проверьте установку КриптоПро CSP.")
            self._set_token_badge("КриптоПро не найден", "warn")
            return
        except subprocess.TimeoutExpired:
            self._append_log("certmgr не ответил за 20 секунд.")
            self._set_token_badge("Токен не отвечает", "warn")
            return
        except Exception as exc:
            self._append_log(f"Ошибка запуска certmgr: {exc}")
            self._set_token_badge("Ошибка проверки токена", "warn")
            return
        finally:
            self.refresh_btn.setEnabled(True)
            QApplication.restoreOverrideCursor()

        certs = parse_certificates(result.stdout)
        if not certs:
            self.cert_combo.blockSignals(True)
            self.cert_combo.clear()
            self.cert_combo.setCurrentText("")
            self.cert_combo.blockSignals(False)
            self._set_token_badge("Токен не найден", "warn")
            detail = (result.stderr or result.stdout).strip()
            if detail:
                self._append_log(f"Сертификаты не найдены: {detail[-300:]}")
            else:
                self._append_log("Сертификаты не найдены.")
            self._update_sign_enabled()
            return

        preferred = previous or self.settings.value("cert_cn", "", type=str)
        self.cert_combo.blockSignals(True)
        self.cert_combo.clear()
        selected_index = next(
            (index for index, cert in enumerate(certs) if not cert.expired), 0
        )
        for index, cert in enumerate(certs):
            self.cert_combo.addItem(cert.display, cert.cn)
            self.cert_combo.setItemData(index, cert.tooltip, Qt.ToolTipRole)
            if preferred and cert.cn == preferred:
                selected_index = index
        self.cert_combo.setCurrentIndex(selected_index)
        self.cert_combo.blockSignals(False)

        on_token = any(cert.on_token for cert in certs)
        if on_token:
            self._set_token_badge("Токен подключён", "ok")
        else:
            self._set_token_badge("Сертификат найден", "ok")
        expired_count = sum(1 for cert in certs if cert.expired)
        suffix = f" (просрочено: {expired_count})" if expired_count else ""
        self._append_log(f"Найдено сертификатов: {len(certs)}{suffix}.")
        self._on_cert_changed(selected_index)
        self._update_sign_enabled()

    def _on_cert_changed(self, _index: int) -> None:
        if isinstance(self.cert_combo.currentData(), str):
            self.settings.setValue("cert_cn", self.cert_combo.currentData())
        self._update_sign_enabled()

    def _selected_dn(self) -> str:
        data = self.cert_combo.currentData()
        current = self.cert_combo.currentText().strip()
        index = self.cert_combo.currentIndex()
        if isinstance(data, str) and index >= 0 and current == self.cert_combo.itemText(index):
            return data
        return current

    # ---- выбор папки и подсчёт -------------------------------------------------

    def select_folder(self) -> None:
        start = self.current_folder or str(Path.home())
        folder = QFileDialog.getExistingDirectory(self, "Выберите папку с документами", start)
        if folder:
            self.select_folder_path(folder)

    def select_folder_path(self, folder_path: str, quiet: bool = False) -> None:
        if not folder_path or not os.path.isdir(folder_path):
            self._append_log(f"Папка не найдена: {folder_path}")
            return
        self.current_folder = os.path.abspath(folder_path)
        self.drop_zone.set_folder(self.current_folder)
        self.settings.setValue("last_folder", self.current_folder)
        if not quiet:
            self._append_log(f"Выбрана папка: {self.current_folder}")
        self.scan_folder()

    def scan_folder(self, reset_processed: bool = True) -> None:
        if not self.current_folder:
            return

        total = 0
        signed = 0
        for root, _, filenames in os.walk(self.current_folder):
            for filename in filenames:
                if is_signature_artifact(filename):
                    continue
                total += 1
                if os.path.exists(os.path.join(root, filename) + ".sig"):
                    signed += 1

        self.total_files = total
        self.already_signed = signed
        self.files_to_sign = max(0, total - signed)
        if reset_processed:
            self.processed_files = 0
            self.progress_bar.setValue(0)
            self.percent_label.setText("0%")

        self.stat_total.set_value(total)
        self.stat_todo.set_value(self.files_to_sign)
        self.stat_signed.set_value(signed)
        self.stat_processed.set_value(self.processed_files)
        self.btn_sign.setText(
            f"Подписать файлы ({self.files_to_sign})"
            if self.files_to_sign
            else "Подписать файлы"
        )

        if reset_processed:
            self.current_file.set_full_text(
                "Выберите папку, чтобы начать"
                if not self.current_folder
                else "Готово к подписанию"
            )
        self._append_log(
            f"Документов: {total} · уже подписано: {signed} · к подписанию: {self.files_to_sign}."
        )
        if total == 0:
            self._set_chip("В папке нет файлов", "idle")
        elif self.files_to_sign == 0:
            self._set_chip("Всё подписано", "ok")
        else:
            self._set_chip("Готово", "idle")
        self._update_sign_enabled()

    def _update_sign_enabled(self) -> None:
        enabled = bool(
            not self._busy
            and self.cryptcp
            and self.current_folder
            and self.files_to_sign > 0
            and self._selected_dn()
        )
        self.btn_sign.setEnabled(enabled)

    # ---- запуск и завершение ---------------------------------------------------

    def start_signing(self) -> None:
        if self._busy:
            return
        if not self.current_folder:
            self._append_log("Ошибка: папка не выбрана.")
            return
        if self.files_to_sign <= 0:
            self._append_log("Нет файлов для подписания.")
            return

        dn = self._selected_dn()
        if not dn:
            self._append_log("Ошибка: не указан сертификат.")
            self.cert_combo.setFocus()
            return
        pin = self.pin_edit.text().strip()
        if not pin:
            self._append_log("Ошибка: не указан PIN-код.")
            self.pin_edit.setFocus()
            return
        if not self.cryptcp:
            self._append_log("Ошибка: cryptcp не найден.")
            return

        self.processed_files = 0
        self.stat_processed.set_value(0)
        self.progress_bar.setValue(0)
        self.percent_label.setText("0%")
        self._set_chip("Подписание…", "busy")
        self._append_log("─" * 48)
        self._append_log(
            f"Старт: {self.files_to_sign} файл(ов), сертификат: {dn}"
        )

        self.worker = SignWorker(self.current_folder, dn, pin, self.cryptcp, self)
        self.worker.progress.connect(self._on_progress)
        self.worker.log_message.connect(self._append_log)
        self.worker.file_started.connect(self._on_file_started)
        self.worker.file_processed.connect(self._on_file_processed)
        self.worker.file_signed.connect(self._on_file_signed)
        self.worker.completed.connect(self._on_signing_completed)
        self.worker.cancelled.connect(self._on_signing_cancelled)
        self.worker.finished.connect(self._on_worker_thread_finished)
        self._set_busy(True)
        self.worker.start()

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        for widget in (
            self.drop_zone,
            self.cert_combo,
            self.refresh_btn,
            self.pin_edit,
            self.eye_btn,
            self.remember_check,
            self.forget_btn,
        ):
            widget.setEnabled(not busy)
        self.remember_check.setEnabled(not busy and self.pin_store.available)
        self.btn_stop.setEnabled(busy and self.worker is not None)
        self.btn_stop.setText("Остановить")
        if not busy:
            self._update_sign_enabled()
        else:
            self.btn_sign.setEnabled(False)

    def stop_signing(self) -> None:
        if self.worker is not None and self.worker.isRunning():
            self._append_log("Останавливаем подписание…")
            self.btn_stop.setEnabled(False)
            self.btn_stop.setText("Останавливаем…")
            self.worker.request_stop()

    def _on_progress(self, value: int) -> None:
        self.progress_bar.setValue(value)
        self.percent_label.setText(f"{value}%")

    def _on_file_started(self, path: str, index: int, total: int) -> None:
        self.current_file.set_full_text(f"[{index}/{total}] {os.path.basename(path)}")

    def _on_file_processed(self, _path: str, _ok: bool) -> None:
        self.processed_files += 1
        self.stat_processed.set_value(self.processed_files)

    def _on_file_signed(self, _path: str) -> None:
        self._save_pin_after_success()

    def _on_signing_completed(self, summary: dict) -> None:
        self._last_worker_summary = summary
        self._set_busy(False)
        signed = summary.get("signed", 0)
        failed = summary.get("failed", 0)
        processed = summary.get("processed", signed + failed)
        self.processed_files = processed
        self.stat_processed.set_value(processed)
        self.progress_bar.setValue(100)
        self.percent_label.setText("100%")

        if failed:
            self._set_chip("Завершено с ошибками", "error")
        else:
            self._set_chip("Готово", "ok")
        self.current_file.set_full_text(
            f"Подписано: {signed} · ошибок: {failed}"
        )
        self._append_log(
            f"Завершено: подписано {signed}, ошибок {failed}, "
            f"время {summary.get('duration', 0):.1f} с."
        )
        self._notify(
            "Подписание завершено",
            f"Подписано: {signed}, ошибок: {failed}",
            failed == 0,
        )
        self.scan_folder(reset_processed=False)
        self.stat_processed.set_value(processed)
        if failed:
            self._set_chip("Завершено с ошибками", "error")
        else:
            self._set_chip("Готово", "ok")

    def _on_signing_cancelled(self, summary: dict) -> None:
        self._last_worker_summary = summary
        self._set_busy(False)
        signed = summary.get("signed", 0)
        self.processed_files = summary.get("processed", signed)
        self.stat_processed.set_value(self.processed_files)
        self.current_file.set_full_text(f"Подписание остановлено · подписано: {signed}")
        self._append_log("Подписание остановлено пользователем.")
        self.scan_folder(reset_processed=False)
        self.stat_processed.set_value(self.processed_files)
        self._set_chip("Остановлено", "error")

    def _on_worker_thread_finished(self) -> None:
        worker = self.worker
        self.worker = None
        if worker is not None:
            worker.deleteLater()
        if not self._busy:
            self.btn_stop.setEnabled(False)

    def _notify(self, title: str, message: str, ok: bool) -> None:
        if not shutil.which("notify-send"):
            return
        try:
            icon = "dialog-information" if ok else "dialog-warning"
            subprocess.Popen(
                ["notify-send", "-i", icon, title, message],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            pass

    def _set_chip(self, text: str, state: str = "idle") -> None:
        self.status_chip.setText(text)
        self.status_chip.setProperty("state", state)
        repolish(self.status_chip)

    # ---- журнал -----------------------------------------------------------------

    def _append_log(self, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        for line in str(message).splitlines():
            self.log.append(f"[{timestamp}] {line}")

    def _copy_log(self) -> None:
        QApplication.clipboard().setText(self.log.toPlainText())

    def _clear_log(self) -> None:
        self.log.clear()
        self._append_log("Журнал очищен.")

    def closeEvent(self, event):
        if self.worker is not None and self.worker.isRunning():
            answer = QMessageBox.question(
                self,
                "Подписание ещё выполняется",
                "Остановить подписание и закрыть приложение?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                event.ignore()
                return
            self.worker.request_stop()
            if not self.worker.wait(5000):
                event.ignore()
                QMessageBox.warning(
                    self,
                    "Не удалось остановить подписание",
                    "Процесс cryptcp не завершился за 5 секунд. "
                    "Попробуйте остановить подписание кнопкой и закрыть окно ещё раз.",
                )
                return
        self.settings.setValue("window/geometry", self.saveGeometry())
        super().closeEvent(event)


def main() -> int:
    if hasattr(Qt, "AA_EnableHighDpiScaling"):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, "AA_UseHighDpiPixmaps"):
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(APP_DISPLAY_NAME)
    app.setOrganizationName("Tripswarlock")
    app.setFont(QFont("DejaVu Sans", 10))
    app.setWindowIcon(make_app_icon())

    window = MainWindow()
    window.show()
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
