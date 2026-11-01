from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import unittest
from pathlib import Path

import pytest

from keyring.errors import PasswordDeleteError

from ssh_agent_keyring.agent import SignerError, normalize_public_key
from ssh_agent_keyring.backend import BackendConfig, SSHAgentKeyring


PUBKEY_1 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC1example11111111111111111111111111111111111111111111111111111111111111111111"
PUBKEY_2 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2example22222222222222222222222222222222222222222222222222222222222222222222"


class FakeSigner:
    def __init__(self, available_keys: list[str] | None = None, fail_on_sign: bool = False) -> None:
        self.available_keys = [normalize_public_key(key) for key in (available_keys or [PUBKEY_1])]
        self.fail_on_sign = fail_on_sign

    def list_public_keys(self) -> list[str]:
        return list(self.available_keys)

    def sign(self, public_key: str, namespace: str, message: bytes) -> bytes:
        normalized = normalize_public_key(public_key)
        if self.fail_on_sign or normalized not in self.available_keys:
            raise SignerError("requested key is not available in ssh-agent")
        material = namespace.encode("utf-8") + b"\0" + normalized.encode("utf-8") + b"\0" + message
        digest = hmac.new(normalized.encode("utf-8"), material, hashlib.sha256).hexdigest()
        return f"sig:{digest}".encode("ascii")


class BackendTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.store_path = Path(self.tempdir.name) / "store.json"
        self.config = BackendConfig(store_path=self.store_path, public_key=None)
        self.signer = FakeSigner([PUBKEY_1, PUBKEY_2])
        self.backend = SSHAgentKeyring(signer=self.signer, config=self.config)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _read_store_text(self) -> str:
        return self.store_path.read_text(encoding="utf-8")

    def test_set_get_and_delete_roundtrip(self) -> None:
        self.backend.set_password("svc", "alice", "secret")
        self.assertEqual(self.backend.get_password("svc", "alice"), "secret")
        self.backend.delete_password("svc", "alice")
        self.assertIsNone(self.backend.get_password("svc", "alice"))

    def test_store_does_not_expose_plaintext_fields(self) -> None:
        self.backend.set_password("svc", "alice", "secret")
        store_text = self._read_store_text()
        self.assertNotIn("svc", store_text)
        self.assertNotIn("alice", store_text)
        self.assertNotIn("secret", store_text)

    def test_missing_password_returns_none(self) -> None:
        self.assertIsNone(self.backend.get_password("svc", "missing"))

    def test_empty_store_file_is_treated_as_missing(self) -> None:
        self.store_path.write_text("", encoding="utf-8")
        self.assertIsNone(self.backend.get_password("svc", "missing"))

    def test_delete_missing_password_raises(self) -> None:
        with self.assertRaises(PasswordDeleteError):
            self.backend.delete_password("svc", "missing")

    @pytest.mark.skipif(sys.platform == "win32", reason="ssh-agent works different in win32")
    def test_store_file_permissions_are_private(self) -> None:
        self.backend.set_password("svc", "alice", "secret")
        self.assertEqual(self.store_path.stat().st_mode & 0o777, 0o600)

    def test_tampered_record_is_detected(self) -> None:
        self.backend.set_password("svc", "alice", "secret")
        payload = json.loads(self._read_store_text())
        record = next(iter(payload["records"].values()))
        ciphertext = bytearray(__import__("base64").urlsafe_b64decode(record["ciphertext"]))
        ciphertext[-1] ^= 1
        record["ciphertext"] = __import__("base64").urlsafe_b64encode(bytes(ciphertext)).decode("ascii")
        self.store_path.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "corrupted or was tampered"):
            self.backend.get_password("svc", "alice")

    def test_wrong_agent_key_cannot_unlock_store(self) -> None:
        self.backend.set_password("svc", "alice", "secret")
        other_backend = SSHAgentKeyring(
            signer=FakeSigner([PUBKEY_2]),
            config=BackendConfig(store_path=self.store_path, public_key=None),
        )
        with self.assertRaisesRegex(RuntimeError, "Unable to unlock"):
            other_backend.get_password("svc", "alice")

    def test_configured_public_key_mismatch_is_rejected(self) -> None:
        self.backend.set_password("svc", "alice", "secret")
        mismatched_backend = SSHAgentKeyring(
            signer=self.signer,
            config=BackendConfig(store_path=self.store_path, public_key=normalize_public_key(PUBKEY_2)),
        )
        with self.assertRaisesRegex(RuntimeError, "Configured public key does not match"):
            mismatched_backend.get_password("svc", "alice")

    def test_first_available_key_is_persisted(self) -> None:
        self.backend.set_password("svc", "alice", "secret")
        payload = json.loads(self._read_store_text())
        self.assertEqual(payload["identity"]["public_key"], normalize_public_key(PUBKEY_1))

    def test_signer_failure_is_reported(self) -> None:
        failing_backend = SSHAgentKeyring(
            signer=FakeSigner([PUBKEY_1], fail_on_sign=True),
            config=BackendConfig(store_path=self.store_path, public_key=normalize_public_key(PUBKEY_1)),
        )
        with self.assertRaisesRegex(RuntimeError, "requested key is not available"):
            failing_backend.set_password("svc", "alice", "secret")


class NormalizePublicKeyTests(unittest.TestCase):
    def test_ed25519_key_is_accepted(self) -> None:
        key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleBase64KeyMaterial"
        self.assertEqual(normalize_public_key(key), key)

    def test_rsa_key_is_accepted(self) -> None:
        self.assertEqual(normalize_public_key(PUBKEY_1), PUBKEY_1)

    def test_ecdsa_key_is_rejected(self) -> None:
        # OpenSSH's ecdsa-* signing is not deterministic (no RFC 6979), which
        # breaks key derivation in crypto.derive_kek(). See crypto.py.
        key = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY="
        with self.assertRaisesRegex(SignerError, "Unsupported SSH public key type"):
            normalize_public_key(key)

    def test_sk_key_is_rejected(self) -> None:
        # FIDO/U2F "sk-*" keys add authenticator-side randomness on top of
        # any ECDSA nonce randomness, so they are not deterministic either.
        key = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t"
        with self.assertRaisesRegex(SignerError, "Unsupported SSH public key type"):
            normalize_public_key(key)

    def test_dss_key_is_rejected(self) -> None:
        key = "ssh-dss AAAAB3NzaC1kc3MAAACBAPexampleAAAAFQD"
        with self.assertRaisesRegex(SignerError, "Unsupported SSH public key type"):
            normalize_public_key(key)


if __name__ == "__main__":
    unittest.main()
