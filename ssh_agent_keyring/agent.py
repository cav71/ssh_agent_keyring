from __future__ import annotations

import base64
import hashlib
import os
import socket

from paramiko.agent import Agent, AgentKey
from paramiko.message import Message
from paramiko.ssh_exception import SSHException


class SignerError(RuntimeError):
    pass


# crypto.derive_kek() feeds the raw signature into HKDF, so the same
# challenge must always produce the same signature or the store becomes
# unlockable after the first use. ssh-ed25519 (EdDSA) and ssh-rsa
# (PKCS#1 v1.5) are deterministic; OpenSSH's ecdsa-* signing uses a random
# nonce (no RFC 6979) and sk-* (FIDO/U2F) adds authenticator-side
# randomness, so both are rejected.
SUPPORTED_KEY_TYPES = ("ssh-ed25519", "ssh-rsa")

# RSA agent signatures default to SHA-1 (the legacy "ssh-rsa" algorithm)
# unless a stronger hash is explicitly requested. `ssh-keygen -Y sign`
# always requests rsa-sha2-512 for RSA keys, so this must match to keep
# signatures (and therefore derived KEKs) identical across ssh-agent
# implementations and consistent with stores created by older versions
# of this package that shelled out to `ssh-keygen -Y sign`.
_RSA_SIGN_ALGORITHM = "rsa-sha2-512"

# Implements the SSHSIG signature format (OpenSSH PROTOCOL.sshsig), the
# same format produced by `ssh-keygen -Y sign`. Reproducing it in Python
# and signing through the ssh-agent wire protocol directly (rather than
# shelling out to `ssh-keygen`) means the challenge and signature never
# pass through, or depend on the integrity of, a `ssh-keygen` binary
# resolved from PATH.
_SSHSIG_MAGIC = b"SSHSIG"
_SSHSIG_VERSION = 1
_SSHSIG_HASH_ALGORITHM = "sha512"
_SSHSIG_LINE_WIDTH = 70


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


def _sshsig_string(data: bytes) -> bytes:
    message = Message()
    message.add_string(data)
    return message.asbytes()


def _sshsig_signed_data(namespace: str, message_hash: bytes) -> bytes:
    return (
        _SSHSIG_MAGIC
        + _sshsig_string(namespace.encode("utf-8"))
        + _sshsig_string(b"")
        + _sshsig_string(_SSHSIG_HASH_ALGORITHM.encode("ascii"))
        + _sshsig_string(message_hash)
    )


def _sshsig_armor(public_key_blob: bytes, namespace: str, message_hash: bytes, signature: bytes) -> bytes:
    blob = (
        _SSHSIG_MAGIC
        + _SSHSIG_VERSION.to_bytes(4, "big")
        + _sshsig_string(public_key_blob)
        + _sshsig_string(namespace.encode("utf-8"))
        + _sshsig_string(b"")
        + _sshsig_string(_SSHSIG_HASH_ALGORITHM.encode("ascii"))
        + _sshsig_string(signature)
    )
    encoded = base64.b64encode(blob).decode("ascii")
    lines = [encoded[i : i + _SSHSIG_LINE_WIDTH] for i in range(0, len(encoded), _SSHSIG_LINE_WIDTH)]
    armored = "-----BEGIN SSH SIGNATURE-----\n" + "\n".join(lines) + "\n-----END SSH SIGNATURE-----\n"
    return armored.encode("ascii")


class SSHAgentSigner:
    """Signs unlock challenges by talking to ssh-agent directly over its
    wire protocol, without spawning `ssh-add` or `ssh-keygen`.

    `sign()` produces output byte-for-byte identical to
    `ssh-keygen -Y sign -f <pubkey> -n <namespace>` for `ssh-ed25519` and
    `ssh-rsa` keys, so it can unlock stores created by earlier versions
    of this package.
    """

    def _connect(self) -> Agent:
        sock_path = os.environ.get("SSH_AUTH_SOCK")
        if not sock_path:
            raise SignerError("SSH_AUTH_SOCK is not set; ssh-agent is not available.")
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.connect(sock_path)
        except OSError as exc:
            raise SignerError(f"Unable to connect to ssh-agent at {sock_path}: {exc}") from exc
        finally:
            probe.close()
        try:
            return Agent()
        except SSHException as exc:
            raise SignerError(f"Unable to speak the ssh-agent protocol: {exc}") from exc

    def _agent_keys(self, agent: Agent) -> list[AgentKey]:
        try:
            return list(agent.get_keys())
        except SSHException as exc:
            raise SignerError(f"Unable to list ssh-agent identities: {exc}") from exc

    def list_public_keys(self) -> list[str]:
        agent = self._connect()
        try:
            return [normalize_public_key(f"{key.get_name()} {key.get_base64()}") for key in self._agent_keys(agent)]
        finally:
            agent.close()

    def sign(self, public_key: str, namespace: str, message: bytes) -> bytes:
        normalized = normalize_public_key(public_key)
        agent = self._connect()
        try:
            agent_key = None
            for key in self._agent_keys(agent):
                if normalize_public_key(f"{key.get_name()} {key.get_base64()}") == normalized:
                    agent_key = key
                    break
            if agent_key is None:
                raise SignerError("Requested key is not available in ssh-agent.")

            message_hash = hashlib.sha512(message).digest()
            signed_data = _sshsig_signed_data(namespace, message_hash)
            algorithm = _RSA_SIGN_ALGORITHM if agent_key.get_name() == "ssh-rsa" else None
            try:
                signature = bytes(agent_key.sign_ssh_data(signed_data, algorithm=algorithm))
            except SSHException as exc:
                raise SignerError(f"ssh-agent signing failed: {exc}") from exc
            return _sshsig_armor(agent_key.asbytes(), namespace, message_hash, signature)
        finally:
            agent.close()
