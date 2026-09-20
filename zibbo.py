from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import shutil
import struct
import sys
import tempfile
import threading
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from PySide6.QtCore import Qt, QThread, Signal, QUrl
from PySide6.QtGui import QAction, QColor, QDragEnterEvent, QDropEvent
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressDialog,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QAbstractItemView,
    QHeaderView,
)


APP_NAME = "Zibbo"
APP_VERSION = "1.0"

if os.name == "nt":
    APP_ROOT = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / APP_NAME
else:
    APP_ROOT = Path.home() / ".local" / "share" / APP_NAME

STORAGE_DIR = APP_ROOT / "Storage"
OBJECTS_DIR = STORAGE_DIR / "objects"
AUTH_PATH = APP_ROOT / "auth.json"
VAULT_PATH = STORAGE_DIR / "vault.json.enc"
SETTINGS_PATH = APP_ROOT / "settings.json"

for _path in (OBJECTS_DIR,):
    _path.mkdir(parents=True, exist_ok=True)


# -----------------------------
# Crypto primitives
# -----------------------------

PASSWORD_SCRYPT = {"n": 2**15, "r": 8, "p": 1, "dklen": 32}
MASTER_KEY_SIZE = 32
SALT_SIZE = 16
NONCE_SIZE = 12
FILE_CHUNK_SIZE = 4 * 1024 * 1024
FILE_MAGIC = b"ZIBBOOBJ"
VAULT_MAGIC = b"ZIBBOVLT"
FILE_VERSION = 1
VAULT_VERSION = 1


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def derive_password_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("Password cannot be empty.")
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=PASSWORD_SCRYPT["n"],
        r=PASSWORD_SCRYPT["r"],
        p=PASSWORD_SCRYPT["p"],
        dklen=PASSWORD_SCRYPT["dklen"],
        maxmem=128 * 1024 * 1024,
    )


def derive_object_key(master_key: bytes, salt: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"Zibbo object key v1",
    ).derive(master_key)


def atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".zibbo-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def atomic_write_json(path: Path, payload: dict) -> None:
    raw = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    atomic_write_bytes(path, raw)


def secure_random_filename(suffix: str = ".zib") -> str:
    return f"{uuid.uuid4().hex}{suffix}"


class AuthError(Exception):
    pass


class VaultCorruptError(Exception):
    pass


class OperationCancelled(Exception):
    pass


class AuthManager:
    def __init__(self, path: Path):
        self.path = path

    def is_configured(self) -> bool:
        return self.path.exists()

    def _read(self) -> dict | None:
        if not self.path.exists():
            return None
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            return data if isinstance(data, dict) else None
        except (OSError, json.JSONDecodeError):
            return None

    def create(self, password: str) -> bytes:
        if len(password) < 8:
            raise ValueError("Password must contain at least 8 characters.")
        if self.is_configured():
            raise RuntimeError("A password is already configured.")

        salt = os.urandom(SALT_SIZE)
        password_key = derive_password_key(password, salt)
        master_key = os.urandom(MASTER_KEY_SIZE)
        verifier = hmac.new(password_key, b"Zibbo password verifier v1", hashlib.sha256).digest()
        wrap_nonce = os.urandom(NONCE_SIZE)
        wrapped_master_key = AESGCM(password_key).encrypt(
            wrap_nonce,
            master_key,
            b"Zibbo master key v1",
        )

        config = {
            "version": 1,
            "algorithm": "scrypt+AES-256-GCM",
            "scrypt": PASSWORD_SCRYPT,
            "salt": base64.b64encode(salt).decode("ascii"),
            "verifier": base64.b64encode(verifier).decode("ascii"),
            "wrap_nonce": base64.b64encode(wrap_nonce).decode("ascii"),
            "wrapped_master_key": base64.b64encode(wrapped_master_key).decode("ascii"),
        }
        atomic_write_json(self.path, config)
        return master_key

    def unlock(self, password: str) -> bytes | None:
        config = self._read()
        if not config:
            return None
        try:
            salt = base64.b64decode(config["salt"], validate=True)
            verifier = base64.b64decode(config["verifier"], validate=True)
            wrap_nonce = base64.b64decode(config["wrap_nonce"], validate=True)
            wrapped_master = base64.b64decode(config["wrapped_master_key"], validate=True)
            password_key = derive_password_key(password, salt)
            calculated = hmac.new(
                password_key,
                b"Zibbo password verifier v1",
                hashlib.sha256,
            ).digest()
            if not hmac.compare_digest(calculated, verifier):
                return None
            return AESGCM(password_key).decrypt(
                wrap_nonce,
                wrapped_master,
                b"Zibbo master key v1",
            )
        except Exception:
            # Invalid authentication data must fail closed.
            return None

    def change_password(self, current_password: str, new_password: str) -> bool:
        master_key = self.unlock(current_password)
        if master_key is None:
            return False
        if len(new_password) < 8:
            raise ValueError("New password must contain at least 8 characters.")

        salt = os.urandom(SALT_SIZE)
        password_key = derive_password_key(new_password, salt)
        verifier = hmac.new(password_key, b"Zibbo password verifier v1", hashlib.sha256).digest()
        wrap_nonce = os.urandom(NONCE_SIZE)
        wrapped_master_key = AESGCM(password_key).encrypt(
            wrap_nonce,
            master_key,
            b"Zibbo master key v1",
        )
        config = {
            "version": 1,
            "algorithm": "scrypt+AES-256-GCM",
            "scrypt": PASSWORD_SCRYPT,
            "salt": base64.b64encode(salt).decode("ascii"),
            "verifier": base64.b64encode(verifier).decode("ascii"),
            "wrap_nonce": base64.b64encode(wrap_nonce).decode("ascii"),
            "wrapped_master_key": base64.b64encode(wrapped_master_key).decode("ascii"),
        }
        atomic_write_json(self.path, config)
        return True


# -----------------------------
# Encrypted metadata
# -----------------------------

class VaultMetadata:
    AAD = b"Zibbo vault metadata v1"

    def __init__(self, path: Path, master_key: bytes):
        self.path = path
        self.master_key = master_key

    def load(self) -> list[dict]:
        if not self.path.exists():
            return []
        try:
            blob = self.path.read_bytes()
            min_size = len(VAULT_MAGIC) + 1 + NONCE_SIZE + 16
            if len(blob) < min_size or blob[:8] != VAULT_MAGIC:
                raise VaultCorruptError("Encrypted vault metadata has an invalid format.")
            version = blob[8]
            if version != VAULT_VERSION:
                raise VaultCorruptError(f"Unsupported vault metadata version: {version}")
            nonce_start = 9
            nonce = blob[nonce_start : nonce_start + NONCE_SIZE]
            ciphertext = blob[nonce_start + NONCE_SIZE :]
            plaintext = AESGCM(self.master_key).decrypt(nonce, ciphertext, self.AAD)
            data = json.loads(plaintext.decode("utf-8"))
            if not isinstance(data, dict) or not isinstance(data.get("items"), list):
                raise VaultCorruptError("Encrypted vault metadata is not valid Zibbo data.")
            return data["items"]
        except VaultCorruptError:
            raise
        except Exception as exc:
            raise VaultCorruptError(f"Could not decrypt vault metadata: {exc}") from exc

    def save(self, items: list[dict]) -> None:
        payload = json.dumps(
            {
                "version": VAULT_VERSION,
                "updated_at": now_iso(),
                "items": items,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        nonce = os.urandom(NONCE_SIZE)
        ciphertext = AESGCM(self.master_key).encrypt(nonce, payload, self.AAD)
        blob = VAULT_MAGIC + bytes([VAULT_VERSION]) + nonce + ciphertext
        atomic_write_bytes(self.path, blob)


# -----------------------------
# Chunked authenticated file format
# -----------------------------

class EncryptedObjectStore:
    def __init__(self, objects_dir: Path, master_key: bytes):
        self.objects_dir = objects_dir
        self.master_key = master_key
        self.objects_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _pack_header(salt: bytes, nonce_prefix: bytes, chunk_size: int) -> bytes:
        return (
            FILE_MAGIC
            + bytes([FILE_VERSION])
            + salt
            + nonce_prefix
            + struct.pack(">I", chunk_size)
        )

    @staticmethod
    def _unpack_header(header: bytes) -> tuple[bytes, bytes, int]:
        expected_len = len(FILE_MAGIC) + 1 + SALT_SIZE + 4 + 4
        if len(header) != expected_len or header[:8] != FILE_MAGIC:
            raise ValueError("Invalid encrypted object header.")
        version = header[8]
        if version != FILE_VERSION:
            raise ValueError(f"Unsupported object version: {version}")
        salt_start = 9
        salt = header[salt_start : salt_start + SALT_SIZE]
        prefix_start = salt_start + SALT_SIZE
        nonce_prefix = header[prefix_start : prefix_start + 4]
        size = struct.unpack(">I", header[prefix_start + 4 : prefix_start + 8])[0]
        if not (64 * 1024 <= size <= 16 * 1024 * 1024):
            raise ValueError("Invalid encrypted object chunk size.")
        return salt, nonce_prefix, size

    def encrypt_path(self, source: Path, destination: Path, cancel: threading.Event | None = None, progress=None) -> None:
        source = Path(source)
        destination = Path(destination)
        salt = os.urandom(SALT_SIZE)
        nonce_prefix = os.urandom(4)
        chunk_size = FILE_CHUNK_SIZE
        header = self._pack_header(salt, nonce_prefix, chunk_size)
        key = derive_object_key(self.master_key, salt)
        temp_path = destination.with_suffix(destination.suffix + ".tmp")
        destination.parent.mkdir(parents=True, exist_ok=True)

        try:
            with source.open("rb") as src, temp_path.open("wb") as dst:
                dst.write(header)
                index = 0
                while True:
                    if cancel and cancel.is_set():
                        raise OperationCancelled()
                    chunk = src.read(chunk_size)
                    if not chunk:
                        break
                    nonce = nonce_prefix + struct.pack(">Q", index)
                    ciphertext = AESGCM(key).encrypt(nonce, chunk, header)
                    dst.write(ciphertext)
                    index += 1
                    if progress:
                        progress()
                dst.flush()
                os.fsync(dst.fileno())
            os.replace(temp_path, destination)
        except Exception:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    def decrypt_path(self, encrypted_path: Path, destination: Path, cancel: threading.Event | None = None, progress=None) -> None:
        encrypted_path = Path(encrypted_path)
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temp_path = destination.with_name(destination.name + ".zibbo_tmp")
        try:
            with encrypted_path.open("rb") as src:
                header_len = len(FILE_MAGIC) + 1 + SALT_SIZE + 4 + 4
                header = src.read(header_len)
                salt, nonce_prefix, chunk_size = self._unpack_header(header)
                key = derive_object_key(self.master_key, salt)
                with temp_path.open("wb") as dst:
                    index = 0
                    while True:
                        if cancel and cancel.is_set():
                            raise OperationCancelled()
                        ciphertext = src.read(chunk_size + 16)
                        if not ciphertext:
                            break
                        if len(ciphertext) < 16:
                            raise ValueError("Encrypted object is truncated.")
                        nonce = nonce_prefix + struct.pack(">Q", index)
                        plaintext = AESGCM(key).decrypt(nonce, ciphertext, header)
                        dst.write(plaintext)
                        index += 1
                        if progress:
                            progress()
                    dst.flush()
                    os.fsync(dst.fileno())
            os.replace(temp_path, destination)
        except Exception:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise


# -----------------------------
# Helpers for folders
# -----------------------------

def make_temp_zip(folder: Path, cancel: threading.Event | None = None) -> Path:
    fd, name = tempfile.mkstemp(prefix="zibbo_folder_", suffix=".zip")
    os.close(fd)
    zip_path = Path(name)
    try:
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            root_arc = folder.name
            archive.writestr(root_arc + "/", b"")
            for path in folder.rglob("*"):
                if cancel and cancel.is_set():
                    raise OperationCancelled()
                relative = path.relative_to(folder).as_posix()
                arcname = f"{root_arc}/{relative}"
                if path.is_dir():
                    archive.writestr(arcname.rstrip("/") + "/", b"")
                else:
                    archive.write(path, arcname)
        return zip_path
    except Exception:
        zip_path.unlink(missing_ok=True)
        raise


def safe_extract_zip(zip_path: Path, target_dir: Path, cancel: threading.Event | None = None) -> Path:
    target_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as archive:
        names = archive.namelist()
        if not names:
            raise ValueError("The encrypted folder archive is empty.")
        root_name = names[0].split("/", 1)[0]
        if not root_name:
            raise ValueError("Invalid folder archive root.")
        root_target = target_dir / root_name
        root_resolved = root_target.resolve()
        target_resolved = target_dir.resolve()
        if target_resolved not in root_resolved.parents and root_resolved != target_resolved:
            raise ValueError("Unsafe folder archive path.")
        for member in archive.infolist():
            if cancel and cancel.is_set():
                raise OperationCancelled()
            member_path = Path(member.filename)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise ValueError("Unsafe path inside encrypted folder archive.")
            output = (target_dir / member.filename).resolve()
            if target_resolved not in output.parents and output != target_resolved:
                raise ValueError("Unsafe extraction target.")
            archive.extract(member, target_dir)
        return root_target


# -----------------------------
# Worker thread
# -----------------------------

class VaultWorker(QThread):
    progress = Signal(int, str)
    item_done = Signal(dict)
    item_error = Signal(str, str)
    finished_ok = Signal()
    cancelled = Signal()

    def __init__(self, operation: str, items: list[dict], store: EncryptedObjectStore):
        super().__init__()
        self.operation = operation
        self.items = items
        self.store = store
        self.cancel_event = threading.Event()

    def cancel(self):
        self.cancel_event.set()

    def run(self):
        total = max(len(self.items), 1)
        completed = 0
        for item in self.items:
            if self.cancel_event.is_set():
                self.cancelled.emit()
                return
            try:
                if self.operation == "hide":
                    result = self._hide_one(item)
                elif self.operation == "unhide":
                    result = self._unhide_one(item)
                else:
                    raise ValueError("Unknown vault operation.")
                self.item_done.emit(result)
                completed += 1
                self.progress.emit(int(completed * 100 / total), f"Completed {completed} / {total}")
            except OperationCancelled:
                self.cancelled.emit()
                return
            except Exception as exc:
                self.item_error.emit(item.get("name", "Unknown item"), str(exc))
                completed += 1
                self.progress.emit(int(completed * 100 / total), f"Completed {completed} / {total}")
        self.finished_ok.emit()

    def _hide_one(self, item: dict) -> dict:
        source = Path(item["original_path"])
        if not source.exists():
            raise FileNotFoundError(f"Source not found: {source}")
        stored_name = secure_random_filename(".zib")
        destination = OBJECTS_DIR / stored_name
        self.progress.emit(0, f"Encrypting {item['name']}")
        if item["kind"] == "file":
            self.store.encrypt_path(source, destination, self.cancel_event)
            try:
                source.unlink()
            except Exception:
                destination.unlink(missing_ok=True)
                raise
        else:
            temp_zip = make_temp_zip(source, self.cancel_event)
            try:
                self.store.encrypt_path(temp_zip, destination, self.cancel_event)
            finally:
                temp_zip.unlink(missing_ok=True)
            try:
                shutil.rmtree(source)
            except Exception:
                destination.unlink(missing_ok=True)
                raise
        updated = dict(item)
        updated["state"] = "hidden"
        updated["stored_name"] = stored_name
        updated["updated_at"] = now_iso()
        return updated

    def _unhide_one(self, item: dict) -> dict:
        stored_name = item.get("stored_name")
        if not stored_name:
            raise ValueError("Encrypted object name is missing.")
        encrypted_path = OBJECTS_DIR / stored_name
        if not encrypted_path.exists():
            raise FileNotFoundError(f"Encrypted object not found: {encrypted_path}")

        target = Path(item["original_path"])
        if target.exists():
            raise FileExistsError(f"Target already exists: {target}")

        self.progress.emit(0, f"Restoring {item['name']}")
        if item["kind"] == "file":
            self.store.decrypt_path(encrypted_path, target, self.cancel_event)
        else:
            temp_dir = Path(tempfile.mkdtemp(prefix="zibbo_restore_"))
            try:
                temp_zip = temp_dir / "folder.zip"
                self.store.decrypt_path(encrypted_path, temp_zip, self.cancel_event)
                target_parent = target.parent
                target_parent.mkdir(parents=True, exist_ok=True)
                extracted_root = safe_extract_zip(temp_zip, target_parent, self.cancel_event)
                if extracted_root.resolve() != target.resolve():
                    # The archive's root must match the recorded original path name.
                    shutil.rmtree(extracted_root, ignore_errors=True)
                    raise ValueError("Archive root does not match the original folder name.")
            except Exception:
                # Only remove a newly-created target. Existing content is never touched.
                if target.exists():
                    shutil.rmtree(target, ignore_errors=True)
                raise
            finally:
                shutil.rmtree(temp_dir, ignore_errors=True)

        encrypted_path.unlink()
        updated = dict(item)
        updated["state"] = "visible"
        updated["stored_name"] = None
        updated["updated_at"] = now_iso()
        return updated


# -----------------------------
# UI dialogs
# -----------------------------

class PasswordDialog(QDialog):
    def __init__(self, parent=None, title="Unlock Zibbo", setup=False):
        super().__init__(parent)
        self.setup = setup
        self.setWindowTitle(title)
        self.setFixedWidth(440)

        layout = QVBoxLayout(self)
        heading = QLabel("Create your Zibbo password" if setup else "Zibbo is locked")
        heading.setObjectName("dialogTitle")
        description = QLabel(
            "Use at least 8 characters. Your password protects the vault key and is never stored in plaintext."
            if setup
            else "Enter your password to continue."
        )
        description.setObjectName("dialogDescription")
        description.setWordWrap(True)
        layout.addWidget(heading)
        layout.addWidget(description)
        layout.addSpacing(12)

        form = QFormLayout()
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setPlaceholderText("Password")
        form.addRow("Password:", self.password)

        self.confirm = None
        if setup:
            self.confirm = QLineEdit()
            self.confirm.setEchoMode(QLineEdit.Password)
            self.confirm.setPlaceholderText("Confirm password")
            form.addRow("Confirm:", self.confirm)
        layout.addLayout(form)
        layout.addSpacing(10)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        self.password.returnPressed.connect(self.accept)
        if self.confirm:
            self.confirm.returnPressed.connect(self.accept)
        layout.addWidget(buttons)

    def value(self) -> str:
        return self.password.text()

    def accept(self):
        password = self.password.text()
        if not password:
            QMessageBox.warning(self, "Invalid password", "Password cannot be empty.")
            return
        if self.setup and len(password) < 8:
            QMessageBox.warning(self, "Invalid password", "Password must contain at least 8 characters.")
            return
        if self.setup and password != self.confirm.text():
            QMessageBox.warning(self, "Password mismatch", "The passwords do not match.")
            return
        super().accept()


class ChangePasswordDialog(QDialog):
    def __init__(self, auth: AuthManager, parent=None):
        super().__init__(parent)
        self.auth = auth
        self.setWindowTitle("Change Password")
        self.setFixedWidth(440)

        layout = QVBoxLayout(self)
        heading = QLabel("Change Zibbo password")
        heading.setObjectName("dialogTitle")
        layout.addWidget(heading)
        layout.addSpacing(10)

        form = QFormLayout()
        self.current = QLineEdit(); self.current.setEchoMode(QLineEdit.Password)
        self.new = QLineEdit(); self.new.setEchoMode(QLineEdit.Password)
        self.confirm = QLineEdit(); self.confirm.setEchoMode(QLineEdit.Password)
        form.addRow("Current:", self.current)
        form.addRow("New:", self.new)
        form.addRow("Confirm:", self.confirm)
        layout.addLayout(form)
        layout.addSpacing(10)

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def save(self):
        current = self.current.text()
        new = self.new.text()
        confirm = self.confirm.text()
        if len(new) < 8:
            QMessageBox.warning(self, "Invalid password", "New password must contain at least 8 characters.")
            return
        if new != confirm:
            QMessageBox.warning(self, "Password mismatch", "The new passwords do not match.")
            return
        try:
            changed = self.auth.change_password(current, new)
        except Exception as exc:
            QMessageBox.critical(self, "Error", f"Could not change password:\n{exc}")
            return
        if not changed:
            QMessageBox.warning(self, "Wrong password", "The current password is incorrect.")
            return
        QMessageBox.information(self, "Password changed", "Your password has been changed successfully.")
        self.accept()


class SettingsDialog(QDialog):
    def __init__(self, current_theme: str, auth: AuthManager, parent=None):
        super().__init__(parent)
        self.auth = auth
        self.setWindowTitle("Settings")
        self.setFixedWidth(520)

        layout = QVBoxLayout(self)
        heading = QLabel("Zibbo Settings")
        heading.setObjectName("dialogTitle")
        layout.addWidget(heading)
        layout.addSpacing(8)

        form = QFormLayout()
        self.theme = QComboBox()
        self.theme.addItem("Dark", "dark")
        self.theme.addItem("Light", "light")
        self.theme.setCurrentIndex(0 if current_theme == "dark" else 1)
        self.storage = QLineEdit(str(STORAGE_DIR))
        self.storage.setReadOnly(True)
        form.addRow("Theme:", self.theme)
        form.addRow("Storage:", self.storage)
        layout.addLayout(form)
        layout.addSpacing(10)

        password_button = QPushButton("Change Password")
        password_button.clicked.connect(self.change_password)
        layout.addWidget(password_button)
        layout.addSpacing(8)

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def change_password(self):
        dialog = ChangePasswordDialog(self.auth, self)
        dialog.exec()

    def selected_theme(self) -> str:
        return self.theme.currentData()


# -----------------------------
# Main table
# -----------------------------

class FileTable(QTableWidget):
    paths_dropped = Signal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent):
        urls = event.mimeData().urls()
        paths = []
        for url in urls:
            if url.isLocalFile():
                path = Path(url.toLocalFile())
                if path.exists():
                    paths.append(str(path))
        if paths:
            self.paths_dropped.emit(paths)
            event.acceptProposedAction()
        else:
            event.ignore()


# -----------------------------
# Main window
# -----------------------------

DARK_QSS = r"""
QMainWindow, QDialog { background: #0f1115; }
QWidget { color: #f2f4f7; font-family: Segoe UI; font-size: 13px; }
QLabel#title { font-size: 25px; font-weight: 700; color: #ffffff; }
QLabel#subtitle { font-size: 12px; color: #8e96a3; }
QLabel#dialogTitle { font-size: 21px; font-weight: 700; color: #ffffff; }
QLabel#dialogDescription { color: #9299a5; }
QWidget#header, QWidget#toolbar, QWidget#footer, QWidget#statsCard {
    background: #171a20; border: 1px solid #252a33; border-radius: 14px;
}
QLineEdit, QComboBox {
    background: #14171c; color: #f2f4f7; border: 1px solid #2c323d;
    border-radius: 9px; padding: 10px 12px;
}
QLineEdit:focus, QComboBox:focus { border: 1px solid #4b5563; }
QPushButton {
    background: #252a33; color: #f2f4f7; border: none; border-radius: 9px;
    padding: 9px 14px; min-height: 18px;
}
QPushButton:hover { background: #303744; }
QPushButton:disabled { color: #6f7784; background: #1b1e24; }
QPushButton#accent { background: #2563eb; }
QPushButton#accent:hover { background: #3473ee; }
QPushButton#purple { background: #7c3aed; }
QPushButton#purple:hover { background: #8b5cf6; }
QPushButton#danger { background: #b91c1c; }
QPushButton#danger:hover { background: #d12a2a; }
QPushButton#success { background: #15803d; }
QPushButton#success:hover { background: #1b9d4b; }
QPushButton#ghost { background: transparent; color: #9ca3af; }
QPushButton#ghost:hover { background: #232832; color: #fff; }
QTableWidget { background: #13161b; color: #eef1f5; border: 1px solid #252a33; border-radius: 12px; gridline-color: #20252e; }
QTableWidget::item { padding: 12px 8px; }
QTableWidget::item:selected { background: #263040; }
QHeaderView::section { background: #1a1e25; color: #9aa3b2; border: none; border-bottom: 1px solid #272d38; padding: 11px; font-weight: 600; }
QStatusBar { background: #171a20; color: #838c9a; border-top: 1px solid #252a33; }
QProgressDialog { background: #171a20; }
QMenu { background: #171a20; color: #f2f4f7; border: 1px solid #2b313c; padding: 5px; }
QMenu::item { padding: 7px 24px; border-radius: 6px; }
QMenu::item:selected { background: #2b3442; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 4px; }
QScrollBar::handle:vertical { background: #3a424f; border-radius: 5px; min-height: 28px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
"""

LIGHT_QSS = r"""
QMainWindow, QDialog { background: #f4f6f8; }
QWidget { color: #20242b; font-family: Segoe UI; font-size: 13px; }
QLabel#title { font-size: 25px; font-weight: 700; color: #111827; }
QLabel#subtitle { font-size: 12px; color: #6b7280; }
QLabel#dialogTitle { font-size: 21px; font-weight: 700; color: #111827; }
QLabel#dialogDescription { color: #6b7280; }
QWidget#header, QWidget#toolbar, QWidget#footer, QWidget#statsCard {
    background: #ffffff; border: 1px solid #e5e7eb; border-radius: 14px;
}
QLineEdit, QComboBox {
    background: #ffffff; color: #111827; border: 1px solid #d1d5db;
    border-radius: 9px; padding: 10px 12px;
}
QLineEdit:focus, QComboBox:focus { border: 1px solid #9ca3af; }
QPushButton {
    background: #e5e7eb; color: #111827; border: none; border-radius: 9px;
    padding: 9px 14px; min-height: 18px;
}
QPushButton:hover { background: #d7dce2; }
QPushButton:disabled { color: #9ca3af; background: #eef0f2; }
QPushButton#accent { background: #2563eb; color: white; }
QPushButton#accent:hover { background: #3473ee; }
QPushButton#purple { background: #7c3aed; color: white; }
QPushButton#purple:hover { background: #8b5cf6; }
QPushButton#danger { background: #dc2626; color: white; }
QPushButton#danger:hover { background: #ef4444; }
QPushButton#success { background: #16a34a; color: white; }
QPushButton#success:hover { background: #22c55e; }
QPushButton#ghost { background: transparent; color: #6b7280; }
QPushButton#ghost:hover { background: #eef0f2; color: #111827; }
QTableWidget { background: #ffffff; color: #111827; border: 1px solid #e5e7eb; border-radius: 12px; gridline-color: #edf0f2; }
QTableWidget::item { padding: 12px 8px; }
QTableWidget::item:selected { background: #dbeafe; }
QHeaderView::section { background: #f8fafc; color: #64748b; border: none; border-bottom: 1px solid #e5e7eb; padding: 11px; font-weight: 600; }
QStatusBar { background: #ffffff; color: #6b7280; border-top: 1px solid #e5e7eb; }
QMenu { background: #ffffff; color: #111827; border: 1px solid #e5e7eb; padding: 5px; }
QMenu::item { padding: 7px 24px; border-radius: 6px; }
QMenu::item:selected { background: #eef2ff; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 4px; }
QScrollBar::handle:vertical { background: #cbd5e1; border-radius: 5px; min-height: 28px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
"""


class MainWindow(QMainWindow):
    def __init__(self, auth: AuthManager, master_key: bytes, settings: dict):
        super().__init__()
        self.auth = auth
        self.master_key = master_key
        self.settings = settings
        self.items: list[dict] = []
        self.worker: VaultWorker | None = None
        self.progress_dialog: QProgressDialog | None = None

        self.meta = VaultMetadata(VAULT_PATH, self.master_key)
        self.store = EncryptedObjectStore(OBJECTS_DIR, self.master_key)
        self.current_theme = self.settings.get("theme", "dark") if isinstance(self.settings, dict) else "dark"

        self.setWindowTitle(f"{APP_NAME} Vault {APP_VERSION}")
        self.resize(1120, 720)
        self.setMinimumSize(900, 600)
        self.setAcceptDrops(True)

        self._build_ui()
        self._load_items()
        self._apply_theme(self.current_theme)

    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(14, 14, 14, 10)
        layout.setSpacing(10)

        header = QWidget(); header.setObjectName("header")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(16, 12, 16, 12)
        title_box = QVBoxLayout()
        title = QLabel("Zibbo App Hider"); title.setObjectName("title")
        subtitle = QLabel("Encrypted file vault • fast local storage")
        subtitle.setObjectName("subtitle")
        title_box.addWidget(title); title_box.addWidget(subtitle)
        header_layout.addLayout(title_box)
        header_layout.addStretch()
        self.stats_label = QLabel("0 items")
        self.stats_label.setObjectName("subtitle")
        header_layout.addWidget(self.stats_label)
        self.settings_button = QPushButton("⚙ Settings"); self.settings_button.setObjectName("ghost")
        self.lock_button = QPushButton("🔒 Lock")
        self.settings_button.clicked.connect(self.open_settings)
        self.lock_button.clicked.connect(self.lock_app)
        header_layout.addWidget(self.settings_button)
        header_layout.addWidget(self.lock_button)
        layout.addWidget(header)

        toolbar = QWidget(); toolbar.setObjectName("toolbar")
        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(10, 8, 10, 8)
        self.search = QLineEdit(); self.search.setPlaceholderText("Search by name, path or status…")
        self.search.textChanged.connect(self.refresh_table)
        toolbar_layout.addWidget(self.search, 1)
        self.add_files = QPushButton("＋ Add Files"); self.add_files.setObjectName("accent")
        self.add_folder = QPushButton("＋ Add Folder"); self.add_folder.setObjectName("purple")
        toolbar_layout.addWidget(self.add_files); toolbar_layout.addWidget(self.add_folder)
        self.add_files.clicked.connect(self.add_files_clicked)
        self.add_folder.clicked.connect(self.add_folder_clicked)
        layout.addWidget(toolbar)

        self.table = FileTable()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Name", "Path", "Type", "Status"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(False)
        self.table.verticalHeader().setVisible(False)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        self.table.itemSelectionChanged.connect(self.update_button_state)
        self.table.paths_dropped.connect(self.add_paths)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.setIconSize(self.table.iconSize())
        layout.addWidget(self.table, 1)

        footer = QWidget(); footer.setObjectName("footer")
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(10, 8, 10, 8)
        self.hide_button = QPushButton("🔐 Hide Selected"); self.hide_button.setObjectName("danger")
        self.unhide_button = QPushButton("🔓 Unhide Selected"); self.unhide_button.setObjectName("success")
        self.delete_button = QPushButton("🗑 Delete"); self.delete_button.setObjectName("ghost")
        self.hide_button.clicked.connect(self.hide_selected)
        self.unhide_button.clicked.connect(self.unhide_selected)
        self.delete_button.clicked.connect(self.delete_selected)
        footer_layout.addWidget(self.hide_button)
        footer_layout.addWidget(self.unhide_button)
        footer_layout.addWidget(self.delete_button)
        footer_layout.addStretch()
        hint = QLabel("Drag & drop files or folders anywhere in the table")
        hint.setObjectName("subtitle")
        footer_layout.addWidget(hint)
        layout.addWidget(footer)

        self.statusBar().showMessage("Ready")
        self.update_button_state()

        # Keyboard shortcuts
        self.shortcut_delete = QAction(self)
        self.shortcut_delete.setShortcut("Delete")
        self.shortcut_delete.triggered.connect(self.delete_selected)
        self.addAction(self.shortcut_delete)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent):
        paths = []
        for url in event.mimeData().urls():
            if url.isLocalFile():
                p = Path(url.toLocalFile())
                if p.exists():
                    paths.append(str(p))
        if paths:
            self.add_paths(paths)
            event.acceptProposedAction()
        else:
            event.ignore()

    def _load_items(self):
        try:
            self.items = self.meta.load()
        except VaultCorruptError as exc:
            QMessageBox.critical(
                self,
                "Vault error",
                "Zibbo could not decrypt its encrypted metadata.\n\n"
                f"{exc}\n\nYour encrypted objects were left untouched.",
            )
            self.items = []
        self.refresh_table()

    def _save_items(self):
        self.meta.save(self.items)

    def refresh_table(self):
        query = self.search.text().strip().lower()
        self.table.setRowCount(0)
        visible_count = 0
        for index, item in enumerate(self.items):
            state = item.get("state", "visible")
            status = "Hidden" if state == "hidden" else "Visible"
            haystack = " ".join(
                [
                    str(item.get("name", "")),
                    str(item.get("original_path", "")),
                    str(item.get("kind", "")),
                    status,
                ]
            ).lower()
            if query and query not in haystack:
                continue

            row = self.table.rowCount()
            self.table.insertRow(row)
            name_item = QTableWidgetItem(str(item.get("name", "")))
            name_item.setData(Qt.UserRole, index)
            path_item = QTableWidgetItem(str(item.get("original_path", "")))
            path_item.setData(Qt.UserRole, index)
            type_item = QTableWidgetItem("Folder" if item.get("kind") == "folder" else "File")
            type_item.setData(Qt.UserRole, index)
            status_item = QTableWidgetItem(status)
            status_item.setData(Qt.UserRole, index)
            if state == "hidden":
                status_item.setForeground(QColor("#f59e0b"))
            else:
                if not Path(item.get("original_path", "")).exists():
                    status_item.setText("Missing")
                    status_item.setForeground(QColor("#ef4444"))
            self.table.setItem(row, 0, name_item)
            self.table.setItem(row, 1, path_item)
            self.table.setItem(row, 2, type_item)
            self.table.setItem(row, 3, status_item)
            self.table.setRowHeight(row, 46)
            visible_count += 1

        self.stats_label.setText(f"{len(self.items)} items • {sum(i.get('state') == 'hidden' for i in self.items)} hidden")
        self.statusBar().showMessage(f"Showing {visible_count} of {len(self.items)} items")
        self.update_button_state()

    def selected_indexes(self) -> list[int]:
        indices = []
        for row in sorted({index.row() for index in self.table.selectionModel().selectedRows()}):
            item = self.table.item(row, 0)
            if item is not None:
                idx = item.data(Qt.UserRole)
                if isinstance(idx, int):
                    indices.append(idx)
        return indices

    def update_button_state(self):
        indices = self.selected_indexes()
        selected = [self.items[i] for i in indices if 0 <= i < len(self.items)]
        has_visible = any(i.get("state") == "visible" for i in selected)
        has_hidden = any(i.get("state") == "hidden" for i in selected)
        self.hide_button.setEnabled(bool(selected) and has_visible and not self.worker)
        self.unhide_button.setEnabled(bool(selected) and has_hidden and not self.worker)
        self.delete_button.setEnabled(bool(selected) and not self.worker)
        self.add_files.setEnabled(not self.worker)
        self.add_folder.setEnabled(not self.worker)
        self.settings_button.setEnabled(not self.worker)
        self.lock_button.setEnabled(not self.worker)

    def add_files_clicked(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Add Files")
        if paths:
            self.add_paths(paths)

    def add_folder_clicked(self):
        path = QFileDialog.getExistingDirectory(self, "Add Folder")
        if path:
            self.add_paths([path])

    def add_paths(self, paths: list[str]):
        existing_visible = {
            os.path.normcase(os.path.abspath(item.get("original_path", "")))
            for item in self.items
            if item.get("state") == "visible"
        }
        added = 0
        skipped = 0
        for raw in paths:
            path = Path(os.path.abspath(raw))
            if not path.exists():
                skipped += 1
                continue
            normalized = os.path.normcase(str(path))
            if normalized in existing_visible:
                skipped += 1
                continue
            item = {
                "id": uuid.uuid4().hex,
                "name": path.name,
                "kind": "folder" if path.is_dir() else "file",
                "original_path": str(path),
                "state": "visible",
                "stored_name": None,
                "added_at": now_iso(),
                "updated_at": now_iso(),
            }
            self.items.append(item)
            existing_visible.add(normalized)
            added += 1
        if added:
            try:
                self._save_items()
            except Exception as exc:
                QMessageBox.critical(self, "Save error", f"Could not save encrypted metadata:\n{exc}")
        self.refresh_table()
        if added or skipped:
            self.statusBar().showMessage(f"Added {added} item(s); skipped {skipped}")

    def _authenticate(self, title: str) -> bool:
        dialog = PasswordDialog(self, title, setup=False)
        if dialog.exec() != QDialog.Accepted:
            return False
        if self.auth.unlock(dialog.value()) is None:
            QMessageBox.warning(self, "Access denied", "The password is incorrect.")
            return False
        return True

    def _start_worker(self, operation: str, selected: list[dict]):
        if not selected or self.worker:
            return
        if not self._authenticate("Confirm action"):
            return

        self.worker = VaultWorker(operation, selected, self.store)
        self.worker.item_done.connect(self._worker_item_done)
        self.worker.item_error.connect(self._worker_item_error)
        self.worker.progress.connect(self._worker_progress)
        self.worker.finished_ok.connect(self._worker_finished)
        self.worker.cancelled.connect(self._worker_cancelled)

        self.progress_dialog = QProgressDialog("Starting…", "Cancel", 0, 100, self)
        self.progress_dialog.setWindowTitle("Zibbo App Hider")
        self.progress_dialog.setAutoClose(False)
        self.progress_dialog.setAutoReset(False)
        self.progress_dialog.setValue(0)
        self.progress_dialog.canceled.connect(self.worker.cancel)
        self.progress_dialog.show()
        self.update_button_state()
        self.worker.start()

    def _worker_progress(self, value: int, message: str):
        if self.progress_dialog:
            self.progress_dialog.setLabelText(message)
            self.progress_dialog.setValue(value)
        self.statusBar().showMessage(message)

    def _worker_item_done(self, updated: dict):
        for idx, item in enumerate(self.items):
            if item.get("id") == updated.get("id"):
                self.items[idx] = updated
                break
        try:
            self._save_items()
        except Exception as exc:
            QMessageBox.critical(self, "Save error", f"Metadata could not be saved:\n{exc}")

    def _worker_item_error(self, name: str, error: str):
        # Errors are collected and shown together at the end to avoid a dialog storm.
        if not hasattr(self, "_worker_errors"):
            self._worker_errors = []
        self._worker_errors.append(f"{name}: {error}")

    def _finish_worker_common(self):
        worker = self.worker
        self.worker = None
        if self.progress_dialog:
            self.progress_dialog.close()
            self.progress_dialog.deleteLater()
            self.progress_dialog = None
        if worker:
            worker.deleteLater()
        self.refresh_table()
        self.update_button_state()

    def _worker_finished(self):
        errors = getattr(self, "_worker_errors", [])
        self._worker_errors = []
        self._finish_worker_common()
        if errors:
            QMessageBox.warning(self, "Some items failed", "\n".join(errors[:20]))
        else:
            QMessageBox.information(self, "Done", "The operation completed successfully.")

    def _worker_cancelled(self):
        errors = getattr(self, "_worker_errors", [])
        self._worker_errors = []
        self._finish_worker_common()
        message = "The operation was cancelled safely."
        if errors:
            message += "\n\n" + "\n".join(errors[:20])
        QMessageBox.information(self, "Cancelled", message)

    def hide_selected(self):
        indices = self.selected_indexes()
        selected = [self.items[i] for i in indices if self.items[i].get("state") == "visible"]
        if not selected:
            return
        answer = QMessageBox.question(
            self,
            "Hide selected items",
            f"Encrypt and hide {len(selected)} selected item(s)?\n\n"
            "The original item will be removed after successful encryption.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer == QMessageBox.Yes:
            self._worker_errors = []
            self._start_worker("hide", selected)

    def unhide_selected(self):
        indices = self.selected_indexes()
        selected = [self.items[i] for i in indices if self.items[i].get("state") == "hidden"]
        if not selected:
            return
        answer = QMessageBox.question(
            self,
            "Unhide selected items",
            f"Restore {len(selected)} selected item(s) to their original paths?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer == QMessageBox.Yes:
            self._worker_errors = []
            self._start_worker("unhide", selected)

    def delete_selected(self):
        indices = self.selected_indexes()
        if not indices or self.worker:
            return
        selected = [self.items[i] for i in indices]
        hidden_count = sum(item.get("state") == "hidden" for item in selected)
        visible_count = len(selected) - hidden_count
        if hidden_count:
            msg = (
                f"Delete {len(selected)} selected item(s)?\n\n"
                f"{hidden_count} hidden item(s) will be permanently deleted from the encrypted vault.\n"
                f"{visible_count} visible item(s) will only be removed from Zibbo's list; their original files will stay untouched."
            )
        else:
            msg = (
                f"Remove {len(selected)} selected item(s) from Zibbo?\n\n"
                "Their visible original files will stay untouched."
            )
        answer = QMessageBox.question(self, "Delete", msg, QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer != QMessageBox.Yes:
            return

        for item in selected:
            if item.get("state") == "hidden":
                stored = item.get("stored_name")
                if stored:
                    try:
                        (OBJECTS_DIR / stored).unlink(missing_ok=True)
                    except OSError as exc:
                        QMessageBox.critical(self, "Delete error", f"Could not delete encrypted object:\n{exc}")
                        return
        selected_ids = {item.get("id") for item in selected}
        self.items = [item for item in self.items if item.get("id") not in selected_ids]
        try:
            self._save_items()
        except Exception as exc:
            QMessageBox.critical(self, "Save error", f"Could not save encrypted metadata:\n{exc}")
        self.refresh_table()

    def show_context_menu(self, pos):
        indices = self.selected_indexes()
        if not indices:
            row = self.table.rowAt(pos.y())
            if row >= 0:
                self.table.selectRow(row)
                indices = self.selected_indexes()
        if not indices:
            return

        selected = [self.items[i] for i in indices]
        has_visible = any(i.get("state") == "visible" for i in selected)
        has_hidden = any(i.get("state") == "hidden" for i in selected)
        menu = QMenu(self)
        hide_action = menu.addAction("🔐 Hide selected")
        hide_action.setEnabled(has_visible and not self.worker)
        unhide_action = menu.addAction("🔓 Unhide selected")
        unhide_action.setEnabled(has_hidden and not self.worker)
        menu.addSeparator()
        delete_action = menu.addAction("🗑 Delete")
        delete_action.setEnabled(not self.worker)
        menu.addSeparator()
        reveal_action = menu.addAction("📂 Open original location")
        reveal_action.setEnabled(all(i.get("state") == "visible" for i in selected))
        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        if chosen == hide_action:
            self.hide_selected()
        elif chosen == unhide_action:
            self.unhide_selected()
        elif chosen == delete_action:
            self.delete_selected()
        elif chosen == reveal_action and selected:
            self.open_original_location(selected[0])

    def open_original_location(self, item: dict):
        path = Path(item.get("original_path", ""))
        target = path if path.is_dir() else path.parent
        if not target.exists():
            QMessageBox.warning(self, "Location missing", "The original location no longer exists.")
            return
        from PySide6.QtGui import QDesktopServices
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(target)))

    def open_settings(self):
        if self.worker:
            return
        if not self._authenticate("Unlock Settings"):
            return
        dialog = SettingsDialog(self.current_theme, self.auth, self)
        if dialog.exec() == QDialog.Accepted:
            self.current_theme = dialog.selected_theme()
            self.settings["theme"] = self.current_theme
            try:
                atomic_write_json(SETTINGS_PATH, self.settings)
            except Exception:
                pass
            self._apply_theme(self.current_theme)

    def _apply_theme(self, theme: str):
        QApplication.instance().setStyleSheet(LIGHT_QSS if theme == "light" else DARK_QSS)

    def lock_app(self):
        if self.worker:
            return
        dialog = PasswordDialog(self, "Unlock Zibbo")
        self.hide()
        while True:
            if dialog.exec() != QDialog.Accepted:
                self.show()
                return
            if self.auth.unlock(dialog.value()) is not None:
                self.show()
                self.statusBar().showMessage("Vault unlocked")
                return
            QMessageBox.warning(self, "Wrong password", "The password is incorrect.")

    def closeEvent(self, event):
        if self.worker:
            QMessageBox.information(self, "Operation running", "Please cancel the current operation before closing Zibbo.")
            event.ignore()
            return
        event.accept()


# -----------------------------
# Application bootstrap
# -----------------------------

def load_settings() -> dict:
    if not SETTINGS_PATH.exists():
        return {"theme": "dark"}
    try:
        with SETTINGS_PATH.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            return {"theme": "dark"}
        return data
    except (OSError, json.JSONDecodeError):
        return {"theme": "dark"}


def ensure_auth(auth: AuthManager, parent=None) -> bytes | None:
    if auth.is_configured():
        while True:
            dialog = PasswordDialog(parent, "Unlock Zibbo")
            if dialog.exec() != QDialog.Accepted:
                return None
            master_key = auth.unlock(dialog.value())
            if master_key is not None:
                return master_key
            QMessageBox.warning(parent, "Wrong password", "The password is incorrect.")
    dialog = PasswordDialog(parent, "Create Zibbo Password", setup=True)
    if dialog.exec() != QDialog.Accepted:
        return None
    try:
        return auth.create(dialog.value())
    except Exception as exc:
        QMessageBox.critical(parent, "Setup error", f"Could not create the password:\n{exc}")
        return None


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName("Zibbo App Hider")
    app.setStyle("Fusion")
    app.setStyleSheet(DARK_QSS)

    auth = AuthManager(AUTH_PATH)
    master_key = ensure_auth(auth)
    if master_key is None:
        return 0

    settings = load_settings()
    window = MainWindow(auth, master_key, settings)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())