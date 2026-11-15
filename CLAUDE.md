# Keyhaven — instructions for Claude Code

Keyhaven is a local-first password manager with an MCP connector. **`docs/PLAN.md` is the source of truth.** Read it before starting any phase.

## Non-negotiable security rules
1. **Only `kh-core` (running inside the desktop app) touches key material.**
   - The MCP server, CLI, native host, extension and relay are thin clients.
   - Never add crypto or secret handling to them.
2. **Never add a pipe method that approves, unlocks, changes settings, exports or deletes.**
   - The allowed method list is in PLAN.md §7.
   - Adding to it requires updating that list and the same-user attack test in the same change.
3. Secrets live in `Zeroizing<>` or `Secret`. Never `Debug`, `Display`, log, `format!` or `serde_json::to_string` a secret.
   - `Secret` prints `[hidden]`. Keep it that way.
4. Do not change KDF parameters, AAD strings or subkey ids without bumping the format version and adding new test vectors.
   - Never edit `test-vectors/v1.json`.
5. Every AI-reachable path to a secret goes through `policy::decide` and returns `Gate::Presence`.
   - The test `no_ai_or_cli_path_reaches_a_secret_without_presence` must keep passing.
6. Don't use `unsafe` outside `kh-win`.
   - Every `unsafe` block there needs a `// SAFETY:` comment.
7. Never hand-roll crypto primitives, OAuth, or URL/PSL parsing. Use the crates and libraries named in PLAN.md §3.
8. Treat vault item text as untrusted data. Never interpolate it into prompts, tool descriptions or shell commands.

## How to work
- Work **one phase at a time** (PLAN.md §13).
- Start each phase in plan mode:
  1. List the files you'll create or change and the tests that prove the exit criteria.
  2. Wait for approval.
- **Tests first** for core logic: write the failing test, then the code.
- Keep commits small, one logical change each, with conventional messages (`feat(core): …`, `test(ipc): …`).
- Before saying a phase is done:
  1. Run the full check commands below.
  2. Tick its exit criteria in `docs/PROGRESS.md` (create this file if missing), with evidence: test names or command output.
- If the plan is wrong or ambiguous, stop and say so. Don't silently diverge, and record any decision in `docs/DECISIONS.md`.
- Pin dependency versions. Run `cargo deny check` and `pnpm audit` before adding a dependency, and prefer well-maintained crates.

## Commands
- Rust: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
- Windows-only crates: `cargo test -p kh_win` (only on Windows)
- TypeScript (once pnpm workspace exists): `pnpm -r lint && pnpm -r typecheck && pnpm -r test`

## State of the repo at hand-off
- `crates/kh-core` has keys, aead, item, policy, sites, audit, manifest, approvals and handshake modules, with 14 tests passing.
  - Missing: vault open/create, SQLite store and the IPC server.
- `crates/kh-win` was written against `windows` 0.62.2 but has **never been compiled**, since it was built on Linux.
  - Compile it on Windows first and fix any errors.
- `crates/kh-ffi` is a UniFFI skeleton that compiles. It isn't wired to `kh-core` yet.
- `apps/mcp-server/src` was type-checked against `@modelcontextprotocol/server` 2.4.0 and Zod 4.
  - Needs a package.json, a tsconfig and tests.
- `services/sync-server/src/items.ts` and `services/relay/src/server.ts` were type-checked and smoke-tested.
  - `device-link.stub.ts` is a test stand-in. Replace it in Phase 7.
- `schema/vault.sql` was validated in SQLite.
