# Agentic Docker Sandbox Baseline

Security-first baseline for running agentic tools in containers with:
- isolation defaults (`read_only`, dropped capabilities, internal network)
- file-based secret injection (no inline secret values)
- CI guardrails that fail PRs when hardening controls regress

## What This Includes

- [`docker-compose.yml`](docker-compose.yml): hardened runtime defaults
- [`profiles/seccomp-agent.json`](profiles/seccomp-agent.json): seccomp profile file
- [`profiles/apparmor-agent`](profiles/apparmor-agent): AppArmor profile stub
- [`src/guardrails.py`](src/guardrails.py): policy checks for compose hardening
- [`tests/test_guardrails.py`](tests/test_guardrails.py): regression tests
- [`.github/workflows/ci.yml`](.github/workflows/ci.yml): lint + tests + policy check

## Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
ruff check .
pytest
python -m src.guardrails docker-compose.yml
```

## Baseline Controls Enforced

| Control | Required |
| --- | --- |
| Filesystem | `read_only: true` |
| Linux capabilities | `cap_drop` includes `ALL` |
| Privilege escalation | `no-new-privileges:true` |
| Syscall filtering | `security_opt` includes `seccomp=...` |
| LSM profile | `security_opt` includes `apparmor=...` |
| Writable temp | `tmpfs` includes `/tmp` with `noexec,nosuid` |
| Secret handling | `secrets:` configured and no inline secret-like env values |
| Resource limits | `pids_limit`, `mem_limit` present |
| Network isolation | attached network marked `internal: true` |

## Secret Handling Pattern

1. Put runtime secret content in local `secrets/` files (ignored by git).
2. Mount secret with compose `secrets`.
3. Pass only file paths through env, for example `OPENAI_API_KEY_FILE=/run/secrets/api_token`.

This keeps secret values out of image layers, logs, and `docker inspect` env dumps.
