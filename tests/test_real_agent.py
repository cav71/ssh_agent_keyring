from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import pytest
from pathlib import Path

from ssh_agent_keyring.agent import SSHAgentSigner, normalize_public_key
from ssh_agent_keyring.backend import BackendConfig, SSHAgentKeyring

HAVE_OPENSSH = shutil.which("ssh-agent") and shutil.which("ssh-keygen") and shutil.which("ssh-add")

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="working SSH agent not available on Windows")


@unittest.skipUnless(HAVE_OPENSSH, "requires ssh-agent, ssh-keygen and ssh-add on PATH")
class RealAgentTests(unittest.TestCase):
    """Exercises SSHAgentSigner against a real ssh-agent.

    These tests use `ssh-keygen`/`ssh-add` only as test fixtures (to spin up
    an agent and generate/load keys) and as an independent oracle to verify
    that SSHAgentSigner.sign() output is byte-for-byte identical to what
    `ssh-keygen -Y sign` would have produced -- required so stores created
    by earlier, subprocess-based versions of this package remain unlockable.
    """

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        tmp = Path(self.tempdir.name)

        launch = subprocess.run(
            ["ssh-agent", "-s"], capture_output=True, text=True, check=True
        )
        sock = None
        pid = None
        for line in launch.stdout.splitlines():
            if line.startswith("SSH_AUTH_SOCK="):
                sock = line.split("=", 1)[1].split(";", 1)[0]
            elif line.startswith("SSH_AGENT_PID="):
                pid = line.split("=", 1)[1].split(";", 1)[0]
        assert sock and pid
        self.addCleanup(lambda: subprocess.run(["kill", pid], check=False))

        self._env_patch = {"SSH_AUTH_SOCK": sock}
        self._old_env = {k: os.environ.get(k) for k in self._env_patch}
        os.environ.update(self._env_patch)

        def restore_env():
            for k, v in self._old_env.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

        self.addCleanup(restore_env)

        self.ed25519_key = tmp / "id_ed25519"
        self.rsa_key = tmp / "id_rsa"
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(self.ed25519_key), "-C", "test"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["ssh-keygen", "-t", "rsa", "-b", "2048", "-N", "", "-f", str(self.rsa_key), "-C", "test"],
            check=True,
            capture_output=True,
        )
        subprocess.run(["ssh-add", str(self.ed25519_key)], check=True, capture_output=True)
        subprocess.run(["ssh-add", str(self.rsa_key)], check=True, capture_output=True)

        self.ed25519_pub = normalize_public_key((tmp / "id_ed25519.pub").read_text())
        self.rsa_pub = normalize_public_key((tmp / "id_rsa.pub").read_text())
        self.signer = SSHAgentSigner()

    def _real_ssh_keygen_sign(self, pub_key_path: Path, namespace: str, message: bytes) -> bytes:
        result = subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(pub_key_path), "-n", namespace, "-"],
            input=message,
            capture_output=True,
            check=True,
        )
        return result.stdout

    def test_list_public_keys_matches_ssh_add(self) -> None:
        result = subprocess.run(["ssh-add", "-L"], capture_output=True, text=True, check=True)
        expected = {
            normalize_public_key(line) for line in result.stdout.splitlines() if line.strip()
        }
        self.assertEqual(set(self.signer.list_public_keys()), expected)

    def test_ed25519_signature_matches_ssh_keygen(self) -> None:
        message = b"ssh-agent-keyring unlock challenge"
        expected = self._real_ssh_keygen_sign(
            Path(self.tempdir.name) / "id_ed25519.pub", "ssh-agent-keyring", message
        )
        actual = self.signer.sign(self.ed25519_pub, "ssh-agent-keyring", message)
        self.assertEqual(actual, expected)

    def test_rsa_signature_matches_ssh_keygen(self) -> None:
        message = b"ssh-agent-keyring unlock challenge"
        expected = self._real_ssh_keygen_sign(
            Path(self.tempdir.name) / "id_rsa.pub", "ssh-agent-keyring", message
        )
        actual = self.signer.sign(self.rsa_pub, "ssh-agent-keyring", message)
        self.assertEqual(actual, expected)

    def test_backend_roundtrip_over_real_agent(self) -> None:
        store_path = Path(self.tempdir.name) / "store.json"
        backend = SSHAgentKeyring(
            signer=self.signer,
            config=BackendConfig(store_path=store_path, public_key=self.ed25519_pub),
        )
        backend.set_password("svc", "alice", "s3cret")
        self.assertEqual(backend.get_password("svc", "alice"), "s3cret")


if __name__ == "__main__":
    unittest.main()
