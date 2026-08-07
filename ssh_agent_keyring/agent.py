from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path


class SignerError(RuntimeError):
    pass


# crypto.derive_kek() feeds the raw signature into HKDF, so the same
# challenge must always produce the same signature or the store becomes
# unlockable after the first use. ssh-ed25519 (EdDSA) and ssh-rsa
# (PKCS#1 v1.5) are deterministic; OpenSSH's ecdsa-* signing uses a random
# nonce (no RFC 6979) and sk-* (FIDO/U2F) adds authenticator-side
# randomness, so both are rejected.
SUPPORTED_KEY_TYPES = ("ssh-ed25519", "ssh-rsa")


def normalize_public_key(public_key: str) -> str:
    parts = public_key.strip().split()
    if len(parts) < 2:
        raise SignerError("SSH public key must contain at least key type and key data.")
    key_type, key_data = parts[0], parts[1]
    if key_type not in SUPPORTED_KEY_TYPES:
        raise SignerError(
            f"Unsupported SSH public key type: {key_type}. "
            f"ssh-agent-keyring requires deterministic signatures and only "
            f"supports: {', '.join(SUPPORTED_KEY_TYPES)}."
        )
    return f"{key_type} {key_data}"


class SSHKeygenAgentSigner:
    def _ensure_agent(self) -> None:
        if not os.environ.get("SSH_AUTH_SOCK"):
            raise SignerError("SSH_AUTH_SOCK is not set; ssh-agent is not available.")
        if shutil.which("ssh-add") is None or shutil.which("ssh-keygen") is None:
            raise SignerError("ssh-add and ssh-keygen must both be available in PATH.")

    def list_public_keys(self) -> list[str]:
        self._ensure_agent()
        result = subprocess.run(
            ["ssh-add", "-L"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            message = result.stderr.strip() or result.stdout.strip() or "ssh-add -L failed"
            raise SignerError(message)
        output = result.stdout.strip()
        if not output or "The agent has no identities." in output:
            return []
        return [normalize_public_key(line) for line in output.splitlines() if line.strip()]

    def sign(self, public_key: str, namespace: str, message: bytes) -> bytes:
        self._ensure_agent()
        normalized = normalize_public_key(public_key)
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            key_path = tmpdir_path / "identity.pub"
            message_path = tmpdir_path / "message"
            key_path.write_text(normalized + "\n", encoding="utf-8")
            message_path.write_bytes(message)
            result = subprocess.run(
                [
                    "ssh-keygen",
                    "-Y",
                    "sign",
                    "-f",
                    str(key_path),
                    "-n",
                    namespace,
                    str(message_path),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                message = result.stderr.strip() or result.stdout.strip() or "ssh-keygen -Y sign failed"
                raise SignerError(message)
            return Path(str(message_path) + ".sig").read_bytes()
