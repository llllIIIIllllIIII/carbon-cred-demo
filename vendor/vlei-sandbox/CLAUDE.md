# vLEI Sandbox — agent instructions

This project is a portable skill. The full instructions live in `SKILL.md`.
Read `SKILL.md` first, then the files under `references/` as needed.

Quick start for any agent:

```bash
python scripts/vlei_sandbox.py demo
```

Layout:
- `SKILL.md` — what this is, when to use it, full command reference
- `scripts/vlei_sandbox.py` — the CLI (mock engine + Docker orchestration)
- `scripts/keri.py`, `scripts/cesr.py`, `scripts/ed25519_compat.py` — the model
- `references/trust-chain.md` — credential structures and verification rules
- `references/real-environment.md` — Docker/KERIA/Signify walkthrough
- `references/application-patterns.md` — how to design applications on vLEI
- `assets/docker-compose.yaml` — the real environment, standalone
