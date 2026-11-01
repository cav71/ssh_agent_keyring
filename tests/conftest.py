import contextlib
import re
import shutil
import dataclasses as dc
import os
import signal
import sys
from pathlib import Path
import subprocess

import pytest

from ssh_agent_keyring.agent import SSHAgentSigner, normalize_public_key


@dc.dataclass
class SSHAgent:
    pid: int
    sock: Path
    tmpdir: Path
    signer: SSHAgentSigner = dc.field(default_factory=SSHAgentSigner)

    def _create(self, name) -> Path:
        if name not in self._files:
            self._files[name] = self.tmpdir / name
        return self._files[name]

    @property
    def ed25519(self) -> Path:
        return self.tmpdir / "id_ed25519"

    @property
    def rsa(self) -> Path:
        return self.tmpdir / "id_rsa"

    @property
    def ed25519_pub(self):
        return normalize_public_key((self.tmpdir / "id_ed25519.pub").read_text())

    def id_rsa(self, pub: bool = False) -> Path:
        return normalize_public_key((self.tmpdir / "id_rsa.pub").read_text())

    def cleanup(self):
        if self.pid:
            os.kill(self.pid, signal.SIGTERM)

        for n in ["id_ed25519", "id_rsa"]:
            with contextlib.suppress(FileNotFoundError):
                (self.tmpdir / n).unlink()
            with contextlib.suppress(FileNotFoundError):
                (self.tmpdir / f"{n}.pub").unlink()

        self.tmpdir.unlink()

@pytest.fixture(scope="class")
def ssh_agent(request, tmp_path_factory):
    assert not hasattr(request.cls, "ssh_agent")

    if not (sshagent := os.getenv("SSHAGENT", shutil.which("ssh-agent"))):
        raise RuntimeError("cannot find ssh-agent")


    # launch ssh-agent
    launch = subprocess.run(
        [sshagent, "-s"], capture_output=True, text=True
    )
    cond = (
        launch.returncode
        and  sys.platform == "win32"
        and "1058" in launch.stderr
    )
    if cond:
        raise RuntimeError(f"""
On windows the ssh-agent ({sshagent}) is a service.
It must be started with (powershell as Admin):
  Set-Service -Name ssh-agent -StartupType Manual
""")

    sock = None
    pid = None
    for line in launch.stdout.splitlines():
        if line.startswith("SSH_AUTH_SOCK="):
            sock = line.split("=", 1)[1].split(";", 1)[0]
        elif line.startswith("SSH_AGENT_PID="):
            pid = line.split("=", 1)[1].split(";", 1)[0]
    assert sock and pid

    agent = SSHAgent(
        pid=int(pid),
        sock=Path(sock),
        tmpdir=tmp_path_factory.mktemp("deleteme"),
    )
    old = os.environ.copy()

    try:
        assert agent.sock.exists()

        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(agent.ed25519), "-C", "test"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["ssh-keygen", "-t", "rsa", "-b", "2048", "-N", "", "-f", str(agent.rsa), "-C", "test"],
            check=True,
            capture_output=True,
        )
        subprocess.run(["ssh-add", str(agent.ed25519)], check=True, capture_output=True)
        subprocess.run(["ssh-add", str(agent.rsa)], check=True, capture_output=True)

        os.environ["SSH_AUTH_SOCK"] = str(agent.sock)
        request.cls.ssh_agent = agent
        yield agent
    finally:
        os.environ = old
        agent.cleanup()