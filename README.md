​
# ShellForge
​
**A secure-by-design Go protocol for encrypted remote shells, container access & management, and multiplexed tunnels.**
​
​
## Overview
​
**ShellForge**  gives you authenticated, end-to-end encrypted access to remote machines and the containers running on them, all over a single multiplexed TCP connection.
​
Where a traditional SSH stack stops at shells and port forwarding, ShellForge treats **containers as first-class citizens**: a client can remotely create, boot, exec into, and stream logs from Podman/Docker environments that are configurable, provisioned and resource-limited by the daemon and bound to a specific key pair.
​
Everything — interactive PTY shells, `-L`/`-R` port forwards, and container I/O — is carried as independent, flow-controlled **channels** inside one secure session.
​
---
​
## Table of Contents
​
- [Architecture](#architecture)
- [How a Session Works](#how-a-session-works)
- [Cryptography](#cryptography)
- [Authentication](#authentication)
- [Channel Multiplexing & Flow Control](#channel-multiplexing--flow-control)
- [Containers & Environments](#containers--environments)
- [Wire Format](#wire-format)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Security Model](#security-model)
- [Project Status](#project-status)
- [Roadmap](#roadmap)
- [License](#license)
​
---
​
## Architecture
​
ShellForge ships as one library and two binaries:
​
| Path | Description |
|------|-------------|
| `shellforge/` | The core protocol library: framing, handshake, crypto, multiplexing, flow control, containers, and storage. |
| `cmd/daemon/` | The server. Listens for connections, authenticates clients, and brokers shells, tunnels, and containers. |
| `cmd/client/` | The CLI. Connects to a daemon and opens shells, forwards ports, and manages containers. |
​
```mermaid
flowchart LR
    subgraph Client["cmd/client"]
        C1[Interactive PTY]
        C2["-L / -R tunnels"]
        C3[Container CLI]
    end
​
    subgraph Wire["Encrypted TCP Session"]
        M[["Channel Multiplexer<br/>(credit/window flow control)"]]
    end
​
    subgraph Daemon["cmd/daemon"]
        D1[Shell Loop<br/>PTY spawn]
        D2[Listener / Dialer]
        D3[Container Loop<br/>Podman / Docker]
        DB[(JSON store<br/>keys.json / envs.json)]
        SB[cgroups v2 · netns · jail]
    end
​
    C1 & C2 & C3 --> M
    M --> D1 & D2 & D3
    D3 --- SB
    Daemon --- DB
```
​
### Core components
​
| Component | File(s) | Responsibility |
|-----------|---------|----------------|
| **Framing / transport** | `protocol.go` | Length-prefixed, AEAD-sealed packet framing; one-reader invariant; nonce management. |
| **Handshake** | `daemon.go`, `client.go`, `ClientHello.go`, `ServerHello.go` | 3-phase init → hello → key-exchange negotiation. |
| **Key exchange** | `daemon.go` (`encryptSession`) | X25519 and hybrid X25519+ML-KEM-768, HKDF key derivation. |
| **Server identity** | `hostkey.go` | Ed25519 host key, transcript signing, TOFU `known_hosts` pinning. |
| **Client auth** | `auth.go`, `auth_server.go` | Password/PAM, Ed25519 pubkey, X.509 PKI. |
| **Multiplexing** | `protocol.go`, `channel.go`, `pipe.go` | 32-bit channel ID space, per-channel ring-buffered pipes. |
| **Flow control** | `flowcontrol.go` | SSH-style send/receive credit windows and `WindowAdjust`. |
| **Shells** | `shell.go` | PTY spawning, privilege drop, window resize. |
| **Containers** | `container.go`, `daemon.go` | Podman/Docker create/run/exec/logs/stats/inspect/top. |
| **Environments** | `ENV.go`, `db.go` | Per-key provisioned environments with lifespans. |
| **Isolation** | `sandbox.go`, `jail.go` | cgroup v2, veth/bridge networking, bind-mount jails. |
| **Storage** | `db.go` | JSON-file-backed store with atomic writes and a background reaper. |
​
---
​
## How a Session Works
​
A connection advances through a strict, staged handshake. Everything before Phase 3 is cleartext; everything after is AEAD-encrypted.
​
```mermaid
sequenceDiagram
    participant C as Client
    participant D as Daemon
​
    Note over C,D: Phase 1 — Init (cleartext)
    C->>D: ClientInit ("SHELLFORGE-v0.1.0-INIT")
    D-->>C: ServerInit  (rejects if init msg not allow-listed)
​
    Note over C,D: Phase 2 — ClientHello (cleartext)
    C->>D: ClientHello { KEX, cipher, share key, ClientRandom }
​
    Note over C,D: Phase 3 — Key Exchange
    D->>D: Derive shared secret · HKDF session keys
    D-->>C: ServerHello { server share key, host-key, host-sig }
    C->>C: Verify host-key signature · pin in known_hosts
    Note over C,D: 🔒 Session encrypted from here on
​
    Note over C,D: Phase 3.5 — Authentication
    C->>D: Auth (password / pubkey / PKI cert) + signature over Session ID
    D-->>C: AuthSuccess
​
    Note over C,D: Phase 4 — Channels
    C->>D: OpenChannel (shell / forward / container)
    D-->>C: Multiplexed, flow-controlled data
```
​
1. **Init** — The client sends an identifying init string. The daemon checks it against its `AcceptedInitMsgs` allow-list and replies with its own init message (or drops the connection).
2. **ClientHello** — The client advertises its chosen key-exchange algorithm, symmetric cipher, ephemeral share key, and 32 bytes of `ClientRandom`.
3. **Key exchange** — The daemon computes the shared secret, derives directional keys, and returns a `ServerHello` carrying its share key plus its **host key and a signature over the full handshake transcript**. The session is encrypted from this point forward.
4. **Authentication** — The client proves its identity (see [Authentication](#authentication)) by signing the server-issued `Session ID`.
5. **Channels** — The client opens multiplexed channels for shells, tunnels, or containers.
​
---
​
## Cryptography
​
### Key exchange (KEX)
​
| Algorithm | ID | Description |
|-----------|-----|-------------|
| `X25519` | `0x1000` | Classical elliptic-curve Diffie-Hellman. |
| `Hybrid X25519 + ML-KEM-768` | `0x2000` | **Post-quantum.** Classical X25519 secret and the ML-KEM-768 (FIPS 203) shared secret are concatenated and hashed with SHA-256: `secret = SHA256(x25519 ‖ mlkem)`. |
​
The hybrid mode means an attacker must break **both** X25519 **and** ML-KEM-768 to recover the session key — safe even against a future quantum adversary recording traffic today.
​
### Key derivation
​
Session keys are derived with **HKDF-SHA256**, using `ClientRandom ‖ SessionID` as the salt and separate context labels for each direction:
​
- `wireforge-client-to-server`
- `wireforge-server-to-client`
​
This produces independent send/receive keys so the two traffic directions never share a keystream.
​
### Symmetric ciphers (AEAD)
​
| Cipher | ID |
|--------|-----|
| ChaCha20-Poly1305 | `0x0001` |
| AES-256-GCM | `0x0002` |
| AES-128-GCM | `0x0003` |
​
Every packet is sealed with an AEAD. The 4-byte length header is passed as **associated data (AAD)**, and the nonce is derived from a monotonic per-direction sequence number — so a tampered length, reordered packet, or replayed frame fails authentication.
​
### Server identity & downgrade protection
​
The daemon holds a long-term **Ed25519 host key** (auto-generated and persisted as PKCS#8 PEM at `0600` on first run). On every handshake it signs a **domain-separated transcript** (`shellforge-handshake-v1`) that length-prefixes and binds:
​
- `ClientRandom` and `SessionID` (both parties' contributed randomness)
- the negotiated KEX algorithm and cipher (**downgrade protection**)
- the server's ephemeral share key
​
The client verifies this signature and pins the host key **trust-on-first-use** in `~/.shellforge/known_hosts`, with a constant-time comparison on subsequent connections to detect an active MITM.
​
---
​
## Authentication
​
After the encrypted channel is established, the client authenticates using one of three methods. In each case the client signs the server-issued **`Session ID`**, proving liveness and key ownership (defeating replay).
​
| Method | Flag | How it works |
|--------|------|--------------|
| **Password / PAM** | `AuthMethodPassword` (`0x01`) | Credentials are validated against the host's PAM `login` stack — respecting account expiry, lockouts, and directory (LDAP/AD) integrations. |
| **Public key** | `AuthMethodPublicKey` (`0x02`) | Raw Ed25519 key checked against the user's `~/.shellforge/authorized_keys`; the signature over the Session ID is verified. |
| **PKI / X.509** | `AuthMethodPKI` (`0x04`) | A DER X.509 client certificate is verified against the daemon's CA pool (enforcing `ExtKeyUsageClientAuth`); the certificate **Common Name becomes the username**. |
​
The daemon advertises which methods it supports in the `ServerHello`, and root login can be disabled via `AllowLoginAsRoot`.
​
---
​
## Channel Multiplexing & Flow Control
​
A single session carries many independent channels. The 32-bit channel-ID space is **partitioned by the high bit** so both peers can allocate IDs without collisions:
​
- **Server-initiated:** high bit clear — `0x0000_0001 … 0x7FFF_FFFF`
- **Client-initiated:** high bit set — `0x8000_0001 … 0xFFFF_FFFF`
​
Each channel gets **SSH-style credit/window flow control** (`flowcontrol.go`):
​
- A **receive window** equal to the receive ring capacity (256 KB) lets the shared read loop dispatch every packet without ever blocking — a compliant peer can never overflow the ring.
- A **send window** forces a producer to acquire credits before transmitting; when the peer's window is exhausted the producer **blocks in its own goroutine**, applying natural backpressure to the origin socket/PTY instead of freezing the multiplexer.
- Credits are replenished via batched `WindowAdjust` frames once the consumer has drained roughly half a window.
​
The result: one stalled shell or saturated tunnel cannot starve every other channel on the connection.
​
---
​
## Containers & Environments
​
ShellForge can broker access to **Podman/Docker** containers that are provisioned per public key and resource-limited by the daemon.
​
**Environments** (`ENVs`) are declared in a JSON config and bound to authorized keys, with settings such as:
​
- image build source (`dockerfile_path`) — images are **built on demand** and cached
- resource caps: `memory_limit`, `cpu_limit`, `gpu_limit`
- lifecycle policy: `survive_reboot`, `kill_after_exit`, `stop_after_exit`
- `life_span` and key/environment `expires_after` windows
​
Supported container operations (client → daemon):
​
| Operation | Client command |
|-----------|----------------|
| Interactive shell | `client container <name>@<host>` |
| Stream logs | `client container logs <name>@<host>` |
| One-shot exec | `client container command "<cmd>" <name>@<host>` |
| List containers | `client containers <host>` |
| Provision new env | `client make container\|system-user <name> <requestedName> <host>` |
​
> Additional observation commands (`inspect`, `stats`, `top`) exist in the daemon and are wired but currently commented out in the client CLI — see [Roadmap](#roadmap).
​
Expired keys and environments are cleaned up automatically by a **background reaper** and a **startup sweeper** that reconciles the JSON store on boot.
​
---
​
## Wire Format
​
Every packet on the wire has the following shape:
​
```
┌───────────────┬──────────────────────────────────────────────┐
│ PacketLength  │  AEAD-sealed ciphertext (+ 16-byte tag)        │
│  (4 bytes,    │  ┌──────────┬─────────────┬─────────────────┐ │
│   big-endian, │  │ PadLen(1)│  Payload    │  Random Padding │ │
│   used as AAD)│  │          │ Type + Data │  (8-byte align) │ │
│               │  └──────────┴─────────────┴─────────────────┘ │
└───────────────┴──────────────────────────────────────────────┘
```
​
- **Payload** = a 1-byte message type followed by the message-specific body.
- **Padding** is random and rounds the plaintext up to an 8-byte boundary, obscuring payload lengths from a passive observer.
- The **length header is authenticated** as AAD; the **nonce** encodes a monotonic sequence number, giving replay and reordering protection for free.
- Packets are capped at **64 KB** and a minimum size is enforced to reject abusive/empty frames — bounds are validated pre-authentication so a malformed frame can never panic the per-connection goroutine.
​
---
​
## Installation
​

> Requires **Go 1.25+**. Container features require **Podman** on the daemon host; PAM auth requires the system PAM libraries.
​
```bash
git clone https://github.com/the-mhdi/shellforge.git
cd shellforge
​
# Build both binaries
go build -o bin/daemon ./cmd/daemon
go build -o bin/client ./cmd/client
```
​
---
​
## Usage
​
### Start the daemon
​
```bash
# Using a config file (defaults to /etc/shellforge/config.json)
./bin/daemon --config /etc/shellforge/config.json \
             --envsConf /etc/shellforge/env_config.json
​
# Or override the listen address inline (default port: 77)
./bin/daemon --listen 0.0.0.0:77 --config config.json
```
​
### Connect a client
​
```bash
# Interactive shell
./bin/client user@203.0.113.10:77
​
# With a specific config directory (holds id_ed25519 + config.json)
./bin/client -c ~/.shellforge user@203.0.113.10:77
​
# Local port forward  (-L)  : expose a remote service on your machine
./bin/client user@host:77 -L 9000:127.0.0.1:5432
​
# Remote port forward (-R)  : expose a local service on the daemon
./bin/client user@host:77 -R 8080:127.0.0.1:3000
```
​
### Manage containers
​
```bash
# Interactive container shell
./bin/client container web@host:77
​
# Stream container logs
./bin/client container logs web@host:77
​
# Run a one-shot command
./bin/client container command "ps aux" web@host:77
​
# List available containers
./bin/client containers host:77
​
# Provision a new environment
./bin/client make container myimage myenv host:77
```
​
> `-c` / `--config` may appear anywhere in the argument list. It points at a **directory** containing `id_ed25519` (private key) and an optional `config.json`. If omitted, ShellForge looks in `~/.shellforge`, falling back to `~/.ssh` for the key.
​
---
​
## Configuration
​
### Daemon (`config.json`)
​
```json
{
  "AcceptedInitMsgs": ["SHELLFORGE-v0.1.0-INIT", "SHELLFORGE-CLIENT-INIT-MSG"],
  "DaemonInitMsg": "SHELLFORGE-v0.1.0-INIT-SERVER",
  "ListenAddr": "0.0.0.0",
  "Port": "77",
  "PasswordAuth": true,
  "PublicKeyAuth": false,
  "AuthorizedKeysPath": "",
  "AllowLoginAsRoot": false,
  "MaxConnectionsAllowed": 0,
  "MaxContainersConnectionsAllowed": 0,
  "EnvironmentsJsonConfig": "",
  "DatabaseDirectory": "",
  "HostKeyPath": ""
}
```
​
| Field | Meaning |
|-------|---------|
| `AcceptedInitMsgs` | Allow-list of client init strings. |
| `PasswordAuth` / `PublicKeyAuth` | Enable PAM and/or Ed25519 key auth. |
| `AuthorizedKeysPath` | Override the per-user `authorized_keys` location. |
| `AllowLoginAsRoot` | Permit root logins. |
| `MaxConnectionsAllowed` / `MaxContainersConnectionsAllowed` | Concurrency caps (`0` = unlimited). |
| `EnvironmentsJsonConfig` | Path to the environments definition file. |
| `DatabaseDirectory` | Where `keys.json` / `envs.json` live. |
| `HostKeyPath` | Ed25519 host key path (defaults to `/etc/shellforge/host_ed25519`). |
​
### containers (`env_config.json`)
​
```json
[
  {
    "active": true,
    "pubkey": ["c161cd235cab272ee9e8e1ad3de0009d31f2da3c8bac927d3148fc6f1dff2e8f"],
    "key_expires_afer": "0",
    "max_containers": 0,
    "environment": [
      {
        "type": "container",
        "setting": {
          "survive_reboot": true,
          "kill_after_exit": false,
          "stop_after_exit": false,
          "dockerfile_path": "/etc/shellforge/",
          "memory_limit": "1g",
          "cpu_limit": 1.5,
          "gpu_limit": "0"
        },
        "life_span": "0"
      }
    ],
    "expires_after": "5 minutes"
  }
]
```
​
### Client (`config.json`)
​
```json
{
  "PreferedKeyExAlgo": "",
  "PreferedEncyptionCipher": "",
  "ClientInitMessage": "SHELLFORGE-v0.1.0-INIT"
}
```
​
---
​
>  **NOTE** ShellForge implements a custom cryptographic protocol and has **not** undergone independent security review. Do not rely on it to protect production or sensitive systems yet.
​
---
​
## Project Status
​
ShellForge is **alpha (v0.1.0)** — the core protocol, handshake, encryption, multiplexing, shells, tunnels, and container flows are implemented and functional, but the project is under active development and APIs may change.
​
Known limitations currently include:
​
- **Session resume** is designed (`ResumeProof`) but disabled — every reconnect performs a full handshake.
- **Dynamic SOCKS5 forwarding (`-D`)** is a logged stub.
- Several container observation commands (`inspect`, `stats`, `top`) are implemented daemon-side but not yet exposed in the client CLI.
- Connection cleanup on abrupt client disconnect is still being hardened (orphaned listeners/channels).
​
---
​
## Roadmap
​
- [ ] Session resumption / fast reconnect
- [ ] Dynamic SOCKS5 proxy (`-D`)
- [ ] Wire up `container inspect` / `stats` / `top` in the client
- [ ] Graceful teardown of listeners & channels on disconnect
- [ ] Keepalive / ping to detect dead peers faster
- [ ] Independent security audit
- [ ] Comprehensive test coverage & fuzzing of all parsers
​
---
​
## Built With
​
- [`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto) — ChaCha20-Poly1305 and crypto primitives
- Go standard library `crypto/mlkem`, `crypto/ecdh`, `crypto/hkdf` — post-quantum KEX & key derivation
- [`creack/pty`](https://github.com/creack/pty) — PTY handling
- [`msteinert/pam`](https://github.com/msteinert/pam) — PAM authentication
- [`urfave/cli`](https://github.com/urfave/cli) — command-line interface
- `the-mhdi/wireforge` — TCP transport helpers
​
## License

ShellForge is licensed under the Apache License 2.0.

ShellForge is experimental security-sensitive software. The license permits use, modification, and distribution, but the project is provided without warranty and has not been externally audited.
---