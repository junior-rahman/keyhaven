# Keyhaven (working name)

A local-first password manager for Windows 11, Android and Chrome/Edge. It includes an MCP connector that lets AI agents fill logins without ever seeing the passwords.

- **Plan:** `docs/PLAN.md`
- **Rules for Claude Code:** `CLAUDE.md`
- **Prompts to paste, phase by phase:** `docs/PROMPTS.md`, or run `/phase N` inside Claude Code

## Quick start

```
cargo test --workspace          # 14 core tests (crypto vectors, policy table, site matching, audit, manifest, approvals)
pnpm install && pnpm -r lint && pnpm -r typecheck && pnpm -r test
```

The full check commands are in `CLAUDE.md`. Progress per phase is in `docs/PROGRESS.md`, and decisions in `docs/DECISIONS.md`.

Then open the folder in Claude Code and paste the Kickoff prompt from `docs/PROMPTS.md`.
