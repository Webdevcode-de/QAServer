# QAserver

QAserver is a Python-based application server that exposes small app modules (called **nodes**) over both SSH and HTTP.

A node is just a Python file in the project root. QAserver discovers those files automatically, applies security checks, and makes them available through:

- an **SSH interface** for terminal-style interaction
- a **web interface** with automatic replay-based fallback for prompt/response flows

The project is built around a lightweight plugin model, startup security validation, and safe-by-default module loading.

## Features

- **Node-based architecture**
  - Every `*.py` file in the project root can become a node
  - Files starting with `_` are excluded from node listing
  - The main server script excludes itself automatically
- **Dual access model**
  - SSH app server for interactive sessions
  - HTTP server for browser-based access
- **Automatic web fallback**
  - SSH-style `run(conn)` nodes can be replayed in the browser
  - Custom `web()` or `handle_web()` handlers override the fallback
- **Security scanning on startup and reload**
  - Uses Bandit when available
  - Uses Semgrep when available
  - Uses a regex-based fallback scan as a last line of defense
- **Security cache**
  - File hashes are cached to skip rescanning unchanged modules
  - Cache can be signed with the server host key
- **Basic access protection**
  - Username validation
  - IP banning support
  - Optional server password from configuration
  - ASCII captcha challenge for SSH logins
- **Live module reload behavior**
  - Nodes are rescanned when their file modification time changes

## How it works

### Nodes

Nodes are regular Python modules placed in the project directory.

A node typically exposes:

- `run(connection)` for SSH-style execution
- optional state handlers used with `keeponline()`
- optional `web(request)` or `handle_web(request)` for custom browser handling

QAserver automatically lists eligible nodes and loads them on demand.

### Security model

Before startup, QAserver scans all available node modules. During runtime, changed modules are rescanned before loading.

The security subsystem includes:

- Bandit SAST scanning
- Semgrep scanning
- regex fallback checks for dangerous patterns
- file-hash based scan cache
- username validation to block traversal-style input
- IP ban list support
- optional password verification

### Web mode

For nodes that only support prompt/response terminal interaction, the HTTP server can replay the node from the beginning and feed back prior answers. This works best for deterministic flows.

For advanced use cases such as streaming, side effects, or custom HTML/JSON responses, implement `web()` or `handle_web()` directly in the node.

## Project structure

Typical files in the repository:

```text
main.py              Main server entry point
_security.py         Security scanning and validation helpers
host.key             SSH host key and optional cache signing key
banned.txt           Banned IP addresses
scan_cache.json      Scan cache written by the security layer
server_config.json   Optional runtime configuration
*.py                 Node modules
```

## Requirements

- Python 3.10+
- `paramiko`

Optional but recommended:

- `bandit`
- `semgrep`

## Installation

Create and activate a virtual environment, then install dependencies.

```bash
python -m venv venv
source venv/bin/activate
pip install paramiko
```

On Windows PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install paramiko
```

Optional security tools:

```bash
pip install bandit semgrep
```

## Running the server

```bash
python main.py
```

By default, the server starts:

- SSH server on `0.0.0.0:2222`
- Web server on `0.0.0.0:8080`

## Configuration

### Optional password

Create a `server_config.json` file:

```json
{
  "server_password": "your-password"
}
```

If no password is configured, password authentication is effectively open to any value accepted by the SSH flow logic.

### Banned IPs

Add entries to `banned.txt`:

```text
# Example
203.0.113.10
198.51.100.7
```

### Host key

`host.key` is created automatically on first startup if it does not already exist.

## Writing a node

Example:

```python

def run(conn):
    name = conn.force_answer("Your name: ")
    conn.send(f"Hello, {name}!\n")
```

Optional custom web handler:

```python

def web(req):
    return "<h1>Hello from the web handler</h1>"
```

## Development notes

- Keep node logic deterministic when relying on automatic web replay.
- Avoid dangerous runtime features such as `eval`, `exec`, unrestricted shell execution, or unsafe deserialization.
- Test node behavior through both SSH and browser paths when relevant.
- Security-related changes should be reviewed carefully because they affect startup validation and runtime loading.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for workflow, coding, and security guidance.

## License

This repository is provided under the terms of the MIT License. See [LICENSE](./LICENSE).
