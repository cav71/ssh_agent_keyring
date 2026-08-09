from __future__ import annotations

import base64
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from keyring.backend import KeyringBackend
from keyring.compat import properties
from keyring.errors import PasswordDeleteError, PasswordSetError

from .agent import SignerError, SSHAgentSigner, normalize_public_key
from .crypto import (
    KEY_BYTES,
    NONCE_BYTES,
    build_unlock_challenge,
    decrypt_record,
    derive_kek,
    derive_subkey,
    encrypt_record,
    random_bytes,
    record_id,
    unwrap_dek,
    wrap_dek,
)

STORE_VERSION = 1
DEFAULT_NAMESPACE = "ssh-agent-keyring"


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _b64decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode("ascii"))


def _default_store_path() -> Path:
    return Path.home() / ".local" / "share" / "ssh-agent-keyring" / "store.json"


def _default_config_path() -> Path:
    return Path.home() / ".config" / "ssh-agent-keyring" / "config.json"


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return None
    return json.loads(raw)


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except PermissionError:
        pass


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    _ensure_private_directory(path.parent)
    with tempfile.NamedTemporaryFile(
        "w",
        dir=path.parent,
        prefix=".tmp-",
        suffix=".json",
        encoding="utf-8",
        delete=False,
    ) as handle:
        temp_path = Path(handle.name)
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.chmod(temp_path, 0o600)
    temp_path.replace(path)


def _load_public_key_from_path(path_value: str | None) -> str | None:
    if not path_value:
        return None
    return normalize_public_key(Path(path_value).expanduser().read_text(encoding="utf-8"))


@dataclass(frozen=True)
class BackendConfig:
    store_path: Path
    public_key: str | None

    @classmethod
    def load(cls) -> "BackendConfig":
        config_payload = _read_json(_default_config_path()) or {}
        public_key = os.environ.get("SSH_AGENT_KEYRING_PUBLIC_KEY") or config_payload.get("public_key")
        public_key_path = os.environ.get("SSH_AGENT_KEYRING_PUBLIC_KEY_PATH") or config_payload.get("public_key_path")
        store_path = os.environ.get("SSH_AGENT_KEYRING_STORE_PATH") or config_payload.get("store_path")
        configured_key = normalize_public_key(public_key) if public_key else _load_public_key_from_path(public_key_path)
        return cls(
            store_path=Path(store_path).expanduser() if store_path else _default_store_path(),
            public_key=configured_key,
        )


class SSHAgentKeyring(KeyringBackend):
    def __init__(
        self,
        signer: SSHAgentSigner | None = None,
        config: BackendConfig | None = None,
    ) -> None:
        self.signer = signer or SSHAgentSigner()
        self.config = config or BackendConfig.load()
        super().__init__()

    @properties.classproperty
    def priority(cls) -> float:
        if not os.environ.get("SSH_AUTH_SOCK"):
            raise RuntimeError("SSH_AUTH_SOCK is not set.")
        return 2.2

    def get_password(self, service: str, username: str) -> str | None:
        store = self._load_store()
        if store is None:
            return None
        index_key, value_key = self._unlock_record_keys(store)
        record_name = record_id(index_key, service, username)
        record = store["records"].get(record_name)
        if record is None:
            return None
        try:
            payload = decrypt_record(
                value_key,
                record_name,
                _b64decode(record["nonce"]),
                _b64decode(record["ciphertext"]),
            )
        except InvalidTag as exc:
            raise RuntimeError("Stored keyring data is corrupted or was tampered with.") from exc
        if payload["service"] != service or payload["username"] != username:
            raise RuntimeError("Stored keyring data failed identity validation.")
        return payload["password"]

    def set_password(self, service: str, username: str, password: str) -> None:
        store = self._load_store()
        if store is None:
            store = self._create_store()
        index_key, value_key = self._unlock_record_keys(store)
        record_name = record_id(index_key, service, username)
        nonce, ciphertext = encrypt_record(value_key, record_name, service, username, str(password))
        store["records"][record_name] = {
            "nonce": _b64encode(nonce),
            "ciphertext": _b64encode(ciphertext),
        }
        self._save_store(store)

    def delete_password(self, service: str, username: str) -> None:
        store = self._load_store()
        if store is None:
            raise PasswordDeleteError("Password not found.")
        index_key, _ = self._unlock_record_keys(store)
        record_name = record_id(index_key, service, username)
        if record_name not in store["records"]:
            raise PasswordDeleteError("Password not found.")
        del store["records"][record_name]
        self._save_store(store)

    def _load_store(self) -> dict[str, Any] | None:
        store = _read_json(self.config.store_path)
        if store is None:
            return None
        if store.get("version") != STORE_VERSION:
            raise RuntimeError(f"Unsupported store version: {store.get('version')!r}")
        return store

    def _save_store(self, store: dict[str, Any]) -> None:
        _atomic_write_json(self.config.store_path, store)

    def _create_store(self) -> dict[str, Any]:
        public_key = self._select_public_key_for_new_store()
        store_id = random_bytes(16)
        salt = random_bytes(KEY_BYTES)
        dek = random_bytes(KEY_BYTES)
        wrap_nonce = random_bytes(NONCE_BYTES)
        challenge = build_unlock_challenge(store_id, public_key)
        signature = self._sign(public_key, challenge)
        kek = derive_kek(signature, salt)
        wrapped_dek = wrap_dek(kek, dek, challenge, wrap_nonce)
        return {
            "version": STORE_VERSION,
            "identity": {
                "public_key": public_key,
            },
            "unlock": {
                "store_id": _b64encode(store_id),
                "salt": _b64encode(salt),
                "nonce": _b64encode(wrap_nonce),
                "wrapped_dek": _b64encode(wrapped_dek),
            },
            "records": {},
        }

    def _select_public_key_for_new_store(self) -> str:
        if self.config.public_key:
            return self.config.public_key
        available = self.signer.list_public_keys()
        if not available:
            raise PasswordSetError("ssh-agent has no keys available for keyring unlock.")
        return available[0]

    def _unlock_record_keys(self, store: dict[str, Any]) -> tuple[bytes, bytes]:
        public_key = normalize_public_key(store["identity"]["public_key"])
        if self.config.public_key and self.config.public_key != public_key:
            raise RuntimeError("Configured public key does not match the keyring store identity.")
        store_id = _b64decode(store["unlock"]["store_id"])
        salt = _b64decode(store["unlock"]["salt"])
        wrap_nonce = _b64decode(store["unlock"]["nonce"])
        wrapped_dek = _b64decode(store["unlock"]["wrapped_dek"])
        challenge = build_unlock_challenge(store_id, public_key)
        try:
            signature = self._sign(public_key, challenge)
            kek = derive_kek(signature, salt)
            dek = unwrap_dek(kek, wrapped_dek, challenge, wrap_nonce)
        except (InvalidTag, RuntimeError) as exc:
            raise RuntimeError("Unable to unlock keyring store with the current ssh-agent key.") from exc
        index_key = derive_subkey(dek, b"index")
        value_key = derive_subkey(dek, b"value")
        return index_key, value_key

    def _sign(self, public_key: str, challenge: bytes) -> bytes:
        try:
            return self.signer.sign(public_key, DEFAULT_NAMESPACE, challenge)
        except SignerError as exc:
            raise RuntimeError(str(exc)) from exc
