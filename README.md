# ShellForge

ShellForge gives you authenticated, end-to-end encrypted access to remote machines and the containers running on them, all over a single multiplexed TCP connection. Where a traditional SSH stack stops at shells and port forwarding, ShellForge treats containers as first-class citizens: a client can remotely create, boot, exec into, and stream logs from Podman/Docker environments that are configurable, provisioned and resource-limited by the daemon and bound to a specific key pair.

## Features
- Remote container Creation/management
- Per-key isolated environments
- Secure remote shell (PTY)
- Local and remote TCP forwarding (`-L` / `-R`)
- Built-in flow control

## Architecture

```mermaid
flowchart LR

    subgraph Client["cmd/client"]
        C1["Interactive PTY"]
        C2["Port Forwarding (-L/-R)"]
        C3["Container CLI"]
    end

    subgraph Wire["Encrypted Session"]
        M["Channel Multiplexer<br/>Flow Control"]
    end

    subgraph Daemon["cmd/daemon"]
        D1["Shell Manager"]
        D2["Tunnel Manager"]
        D3["Container Manager"]
        DB[("JSON Store")]
        SB["Sandbox<br/>cgroups · netns"]
    end

    C3 --> M
    C1 --> M
    C2 --> M
    M --> D1
    M --> D2
    M --> D3
    D3 --- SB
    D3 --- DB
```

## Quick Start
> Requires Go 1.25+. Container features require Podman on the daemon host; PAM auth requires the system PAM libraries.

```bash
git clone https://github.com/the-mhdi/shellforge
cd shellforge
go build ./cmd/daemon
go build ./cmd/client
```

## Documentation

See the `docs/` directory:

- architecture.md
- protocol.md
- cryptography.md
- authentication.md
- configuration.md
- containers.md
- wire-format.md

BE CAREFUL Not independently security audited.

## License

Apache 2.0
