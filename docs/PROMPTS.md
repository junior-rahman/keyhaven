# Prompts for Claude Code

Paste these into Claude Code from the repo root, one at a time. Start a fresh session (`/clear`) for each phase so context stays clean.
`CLAUDE.md` loads automatically, so the prompts don't need to repeat its rules.

---

## 0 · Kickoff (paste first)

```
Read CLAUDE.md and docs/PLAN.md fully, then look at every file under crates/, apps/, services/ and schema/.

Then, in plan mode, give me:
1. A one-paragraph summary of the architecture in your own words, including the "one process holds keys" rule.
2. Anything in PLAN.md that looks wrong, risky, contradictory or underspecified. Be specific, and don't fix anything yet.
3. Your plan for Phase 0 (repo tooling + CI), as a file list and the commands you'll run to prove it works.

Do not write code until I approve the Phase 0 plan.
```

## Phase 0 · Tooling

```
Implement Phase 0 from docs/PLAN.md §13.
- pnpm workspace for apps/* and services/* (TypeScript strict, ESLint, Vitest).
- GitHub Actions: Linux job (cargo fmt/clippy -D warnings/test, pnpm lint/typecheck/test) and Windows job (same, plus cargo test -p kh_win).
- cargo-deny config (licenses + advisories), Dependabot for cargo and npm.
- docs/PROGRESS.md and docs/DECISIONS.md.
Make the Windows job compile kh-win. If it fails, fix the code against the windows 0.62 API and explain each fix.
Finish by running every check command locally and pasting the results.
```

## Phase 1 · Core vault

```
Implement Phase 1: finish kh-core so a vault can be created, unlocked, and items created/read/updated/deleted in SQLite (schema/vault.sql).
Rules: tests first; every write is one transaction that bumps ver, re-seals with the versioned AAD, updates the manifest and appends to the audit chain.
Required tests: round-trip CRUD; restoring an older row is detected as RolledBack; deleting the last audit rows is detected as Truncated; Argon2 params below the floor are refused; KDF output matches test-vectors/v1.json.
Add proptest for item JSON round-trip and site_matches, and a cargo-fuzz target for item parsing (run it 10 minutes).
Update PROGRESS.md with evidence.
```

## Phase 2 · Desktop app + trusted core

```
Implement Phase 2: a Tauri 2 app in apps/desktop whose Rust backend hosts kh-core, plus crates/kh-ipc (named-pipe server and shared JSON-RPC types).
- Pipe: \\.\pipe\keyhaven-{SID}, first_pipe_instance(true), DACL for current user only, 64 KiB max message, only the methods listed in PLAN.md §7.
- Peer identity via kh-win::peer; mutual handshake via kh-core::handshake.
- Windows Hello quick unlock via kh-win::hello; approval window per PLAN.md §7 (hold 1 s, then Hello, 45 s TTL, "Block AI for 10 minutes").
- Lock on sleep, session lock and idle.
- UI: vault list, item detail, generator, settings, pairing profiles. Use the design direction I give you: <PASTE A, B or C>.
Write a Windows integration test showing that a pipe squatter is refused and an unknown binary is refused.
```

## Phase 3 · MCP server + CLI (the security-critical one)

```
Implement Phase 3: apps/mcp-server (from the existing src/), crates/kh-cli, and pairing profiles.
- Tools exactly as in PLAN.md §8, with outputSchema on each. fill_login is one blocking call (45 s approval < 60 s client timeout).
- Profiles: per-client token in %LOCALAPPDATA%\Keyhaven\clients\{profile}.token (ACL: current user), created only from the app UI.
- Write the same-user attack test (PLAN.md §14) as a PowerShell script in tests/attack/ and run it in Windows CI.
- Write the canary prompt-injection test with the SDK's in-memory client.
Then run /security-review on the diff and fix every finding before telling me it's done.
```

## Phase 4 · Browser

```
Implement Phase 4: crates/kh-native-host and apps/extension (MV3, Chrome + Edge).
Pairing via one-time code shown in the app; tab-bound fill ({tabId, origin}); no cross-origin iframe fill; save-new-login prompt; reveal_field tool gated per PLAN.md.
End-to-end tests (Playwright with the unpacked extension): look-alike domain refused, alice.github.io → mallory.github.io refused, IP-address exact match works.
```

## Phase 5 · Sync

```
Implement Phase 5: services/sync-server per PLAN.md §10, building on src/items.ts.
prelogin (stable fake params for unknown emails), login with auth verifier, add-device approval, Recovery Key sign-in, rate limits.
Tests: 400 on bad bodies, 409 on stale seq and on ver <= current, two simulated devices converge, a DB dump contains no plaintext from the seeded items.
Add the desktop sync client in kh-core behind a trait so it can be tested with a fake server.
```

## Phase 6 · Android

```
Implement Phase 6: wire crates/kh-ffi to kh-core and build apps/android (Kotlin, Compose) for a Galaxy Z Fold 7 (handle both folded and unfolded layouts).
Keystore device key + BiometricPrompt; AutofillService; Credential Manager password provider; app matching by package + signing-cert digest + Digital Asset Links; browser compatibility allowlist.
Instrumented tests for: correct app fills, wrong-signature app refused.
```

## Phase 7 · Remote relay

```
Implement Phase 7: services/relay per PLAN.md §12, replacing device-link.stub.ts with the real outbound WebSocket from the desktop core.
Use a maintained OAuth provider (do not write an OAuth server). Push approvals to the phone.
Tests: client without elicitation gets a clean refusal; desktop offline → device_offline; approve and deny paths.
```

## Phase 8 · Hardening & release

```
Phase 8: produce a release checklist in docs/RELEASE.md and work through it — code signing and Authenticode check in peer identity, SBOM, cargo-deny/pnpm audit clean, threat model in README matches the code, memory scan after lock, installer (per-machine install dir so peer-identity paths hold).
Then run a fresh-eyes review: spawn a subagent that has not seen this work, give it PLAN.md §4 and the repo, and ask it to find ways to get a secret without Windows Hello. Fix everything it finds.
```

---

## Handy one-liners during any phase
- "Show me which exit criteria for this phase are met, with evidence, and which aren't."
- "Before you continue: what assumptions have you made that aren't in PLAN.md?"
- "Run /security-review on everything since the last commit."
- "Write the test that would have caught that bug, then fix it."
