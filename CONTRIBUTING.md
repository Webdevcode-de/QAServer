# Contributing to QAserver

Thanks for contributing to QAserver.

This project is a small Python application server with a node-based plugin model, SSH and web entry points, and a security-first loading process. Please keep changes focused, readable, and easy to audit.

## Ground rules

- Prefer small, reviewable pull requests.
- Keep behavior explicit rather than clever.
- Treat security-related code as high-sensitivity code.
- Maintain compatibility with the existing node model unless a breaking change is intentional and documented.
- Write comments where behavior is security-sensitive, surprising, or protocol-driven.

## Development setup

Create a virtual environment and install dependencies.

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

On Windows PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Recommended optional tools:

```bash
pip install bandit semgrep
```

## Local run

```bash
python main.py
```

Default endpoints:

- SSH: `0.0.0.0:2222`
- Web: `0.0.0.0:8080`

## Project conventions

### General Python style

- Follow PEP 8.
- Use descriptive function and variable names.
- Prefer explicit imports over wildcard imports.
- Keep functions focused on one job.
- Preserve English-only log messages, comments, and user-facing text unless internationalization is introduced intentionally.

### Node conventions

Nodes are Python files in the project root.

A node may expose:

- `run(conn)` for terminal-style execution
- one or more follow-up handlers used by `keeponline()`
- `web(req)` or `handle_web(req)` for custom web behavior

When adding or changing nodes:

- Keep prompt/response flows deterministic when the browser fallback is expected to work.
- Avoid hidden global side effects.
- Make SSH output readable in a plain terminal.
- Make custom web responses valid and explicit about content type.

### Security conventions

Security changes need extra care.

Please follow these rules:

- Do not weaken username validation without a strong reason.
- Do not bypass `scan_module()` for normal module loading.
- Do not introduce unsafe dynamic execution such as `eval`, `exec`, or shell calls with unsanitized input.
- Prefer safe parsing and strict validation.
- Document any exception to the security model directly in code and in the pull request description.

## Testing checklist

Before opening a pull request, validate the following as applicable:

- The server starts cleanly with `python main.py`.
- Unchanged node files hit the scan cache on restart.
- Modified node files are rescanned before load.
- SSH login still works.
- Web rendering still works for existing nodes.
- Any new node works in the execution mode it claims to support.
- Bandit and Semgrep pass when installed.

## Pull request guidance

A good pull request should include:

- a clear summary of the change
- the reason for the change
- notable security implications
- manual test steps
- screenshots or terminal output when UI or interaction changes are involved

## Commit message suggestions

A simple format works well:

```text
area: short summary
```

Examples:

```text
security: fix cache signature verification
server: simplify startup scan flow
web: improve auto replay page layout
```

## Reporting security issues

Please do not open public issues for serious security vulnerabilities.

Instead, report them privately to the project maintainer or repository owner and include:

- affected file or subsystem
- reproduction steps
- impact assessment
- proposed mitigation, if known

## Documentation

When behavior changes, update documentation in the same pull request whenever possible:

- `README.md` for user-facing setup or usage changes
- `CONTRIBUTING.md` for workflow or engineering guidance
- inline comments for security-sensitive logic

## License

By contributing to this project, you agree that your contributions will be licensed under the repository license.
