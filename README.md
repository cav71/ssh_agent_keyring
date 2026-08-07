# ssh-agent-keyring

`ssh-agent-keyring` is a Python [`keyring`](https://pypi.org/project/keyring/) backend that keeps secrets encrypted at rest and unlocks them transparently through `ssh-agent`.

It is designed for SSH-first environments such as headless Linux servers, remote development machines, and terminal-centric workflows where desktop keyring services are not available or not desirable.

## Why this exists

On a plain SSH server, the usual choices are often unsatisfying:

- desktop-oriented keyring backends are unavailable
- file-based backends usually require a separate keyring password
- plaintext storage is convenient, but unacceptable for real secrets

`ssh-agent-keyring` takes a different approach:

- secrets are stored **encrypted at rest**
- unlock happens through a configured SSH key already available in `ssh-agent`
- `keyring set/get/del` work in ordinary SSH sessions without a second keyring password

## Features

- `keyring` backend implementation: `ssh_agent_keyring.backend.SSHAgentKeyring`
- encrypted local store
- no plaintext secret storage
- no plaintext `service` / `username` metadata in the store
- no root or system service dependency
- works well in SSH sessions when `SSH_AUTH_SOCK` is available
- simple user-space configuration

## How it works

The backend stores a random data-encryption key (DEK) in wrapped form. To unwrap it, the backend:

1. uses `ssh-keygen -Y sign` with a configured SSH public key
2. relies on `ssh-agent` to produce a deterministic signature over a backend-specific challenge
3. derives a key-encryption key from that signature with HKDF-SHA256
4. unwraps the DEK
5. uses the DEK to encrypt and decrypt secret records with `ChaCha20Poly1305`

Record identifiers are derived with HMAC, so the on-disk store does not expose service and username pairs in plaintext.

Because the key-encryption key is derived from the raw signature bytes, only key types with deterministic signing are supported: `ssh-ed25519` and `ssh-rsa`. ECDSA (`ecdsa-*`) and security-key (`sk-*`) types are rejected — OpenSSH's ECDSA signing uses a random per-signature nonce (no RFC 6979), so the same challenge does not yield the same signature and the store could not be unlocked reliably.

## Requirements

- Python 3.10+
- [`keyring`](https://pypi.org/project/keyring/)
- [`cryptography`](https://pypi.org/project/cryptography/)
- OpenSSH tools providing:
  - `ssh-add`
  - `ssh-keygen`
- a running `ssh-agent`
- `SSH_AUTH_SOCK` set in the current environment
- the configured SSH key loaded in the agent

## Installation

From PyPI:

```bash
pip install ssh-agent-keyring
```

If you are installing in a user environment on a remote machine, a typical setup is:

```bash
python3 -m pip install --user ssh-agent-keyring
```

## Configuration

The backend reads configuration from:

```text
~/.config/ssh-agent-keyring/config.json
```

Example:

```json
{
  "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleBase64KeyMaterial",
  "store_path": "~/.local/share/ssh-agent-keyring/store.json"
}
```

Then select the backend in:

```text
~/.config/python_keyring/keyringrc.cfg
```

```ini
[backend]
default-keyring=ssh_agent_keyring.backend.SSHAgentKeyring
```

### Configuration fields

- `public_key`: SSH public key to use for unlocking the store
- `public_key_path`: path to a public key file; useful instead of embedding the key in JSON
- `store_path`: path to the encrypted JSON store

### Environment variable overrides

These override file-based configuration:

- `SSH_AGENT_KEYRING_PUBLIC_KEY`
- `SSH_AGENT_KEYRING_PUBLIC_KEY_PATH`
- `SSH_AGENT_KEYRING_STORE_PATH`

## Usage

With the Python API:

```python
import keyring

keyring.set_password("example-service", "alice", "s3cr3t")
print(keyring.get_password("example-service", "alice"))
keyring.delete_password("example-service", "alice")
```

With the CLI:

```bash
keyring set example-service alice
keyring get example-service alice
keyring del example-service alice
```

With this backend, `keyring set` prompts only for the secret being stored. It does **not** prompt for a separate keyring password.

## Operational model

Transparent unlock works when all of the following are true:

- `SSH_AUTH_SOCK` is available in the current session
- `ssh-agent` is reachable
- the configured key is loaded in that agent
- the current session is allowed to use that agent

If the agent is unavailable, the wrong key is configured, or the key is not loaded, the encrypted store cannot be unlocked.

## Security notes

This package improves on plaintext file storage, but it intentionally shifts trust to the SSH agent session.

Important implications:

- anyone able to use your `SSH_AUTH_SOCK` can potentially unlock the keyring during that session
- agent forwarding policy matters
- the security of the backend depends on the security of the selected SSH key and the agent socket
- this is not a hardware-backed secret manager or multi-user secret vault
- the backend invokes `ssh-keygen` from `PATH` and assumes it is genuine; on a system where an
  attacker can plant a malicious `ssh-keygen`/`ssh-agent` ahead of it on `PATH`, or otherwise
  observe process memory, the derived signature (which acts as the store's master key) can be
  captured regardless of how carefully this package avoids writing it to disk

The store is designed to avoid:

- plaintext secrets on disk
- plaintext service/user metadata on disk
- a second unlock password unrelated to your SSH workflow

The challenge message and the resulting signature are passed to `ssh-keygen` over stdin/stdout
pipes, not temporary files, so neither is ever written to disk.

## Limitations

- this backend depends on OpenSSH tooling and current `ssh-agent` behavior
- it is aimed at Unix-like environments
- it does not provide secret sharing, rotation workflows, audit logs, or remote synchronization
- it assumes the configured SSH key can be used for agent-backed signing

## Testing

Run the test suite with:

```bash
python3 -m unittest discover -s tests -v
```

The project includes tests for roundtrips, tampering, key mismatch, signer failures, and store handling edge cases.

## Development

Project layout:

- `ssh_agent_keyring/agent.py` - agent and signing integration
- `ssh_agent_keyring/crypto.py` - key derivation and encryption helpers
- `ssh_agent_keyring/backend.py` - `keyring` backend implementation
- `tests/test_backend.py` - automated test suite

## License

License information has not been added yet.
