# Decisions

Each entry records a choice not spelled out in `docs/PLAN.md`, or a place where the work diverged from it.
Newest last. Don't edit old entries; add a new one that supersedes them.

## Phase 0

### D-001 Pin the Rust toolchain to 1.97.0
`rust-toolchain.toml` pins 1.97.0 with rustfmt and clippy, plus the `x86_64-pc-windows-msvc` target so kh-win can be type-checked from Linux.
Every machine and CI runner gets the same compiler and lints. Bump it deliberately, in its own commit.

### D-002 rustfmt: `max_width = 120`, `use_small_heuristics = "Max"`
This matches the hand-off code's style with the fewest reflows. It was applied once in its own commit (`style: apply rustfmt`), with no behaviour change.

### D-003 Workspace lints are actually enforced
`unsafe_code = "deny"` was declared in `[workspace.lints]`, but no crate opted in, so it wasn't applied.
- kh-core and kh-ffi now set `[lints] workspace = true`.
- `clippy::undocumented_unsafe_blocks = "deny"` enforces CLAUDE.md rule 6 mechanically.
- Cargo can't override a single inherited lint, so kh-win declares its own set. It allows `unsafe`, and denies `unsafe_op_in_unsafe_fn` and undocumented unsafe blocks.

### D-004 kh-win compiles to an empty crate off Windows
kh-win's dependencies are under `[target.'cfg(windows)'.dependencies]`, and `src/lib.rs` is `#![cfg(windows)]`.
This lets `cargo clippy/test --workspace` (the CLAUDE.md commands) run on Linux, so `default-members` was removed.
Callers must also gate their use of kh-win with `cfg(windows)`.

### D-005 kh-win: `windows-future` pinned to 0.3.2
- The hand-off depended on `windows-future = "0.100.0"`, which is built on `windows-core` 0.100.
- `windows` 0.62.2 uses `windows-core` 0.62 and `windows-future` 0.3.2.
- As a result, the `IAsyncOperation` returned by `RequestVerificationForWindowAsync` and the one the code named were different types. Every Hello call failed the `RuntimeType` / `Interface` trait bounds.
- The fix depends on `windows-future` 0.3.2, the exact version `windows` 0.62.2 re-uses. `windows` 0.62 doesn't re-export it.
- In the same commit, each `unsafe` block in `peer.rs` and `hello.rs` was narrowed to the one FFI call it wraps, with a `// SAFETY:` comment. Same calls, order and error handling.

Verified with `cargo clippy -p kh_win --target x86_64-pc-windows-msvc --all-targets -- -D warnings`. Linking and running need the Windows CI job.

### D-006 Licenses: allow MPL-2.0; our crates are private and unlicensed for now
- UniFFI (PLAN.md §3) is MPL-2.0. That is file-level copyleft and only matters if we modify UniFFI's own source files. It is allowed in `deny.toml`.
- Our crates are `publish = false`, and cargo-deny skips private crates in the license check.
- **Open:** choose a project license before any public release (Phase 8).

### D-007 TypeScript toolchain
- **Node:** 24 LTS in CI (`.nvmrc`), with `engines.node >= 22.13` so Node 22 still works locally. Vitest 5 and ESLint 10 both require ≥ 22.12/22.13.
- **TypeScript:** 6.0.3, not 7.x, because typescript-eslint 8.72 supports `typescript < 6.1`.
- **Dependency pins:** all dependencies are exact (`save-exact`). pnpm `minimumReleaseAge` is 7 days as a supply-chain guard, and `onlyBuiltDependencies: []` blocks install scripts.
- **Vitest:** no `vitest.config.ts` per package, because the defaults suffice. This is a small deviation from the Phase 0 plan. Add one when a package needs settings.

### D-008 Temporary lint override for hand-off TypeScript
Five hand-off files treat pipe and device-link responses as `any`:
- `apps/mcp-server/src/core-client.ts`
- `apps/mcp-server/src/tools/*.ts` (2 files)
- `services/relay/src/server.ts`
- `services/relay/src/device-link.stub.ts`

Typed lint rejects them (42 errors). The real fix is to validate every core response with Zod, which belongs to Phase 3 (mcp-server) and Phase 7 (relay).

Until then, one labelled block in `eslint.config.js` turns off the affected rules for exactly those files. New files get the full rule set.
- That block also silences `no-unnecessary-type-assertion` on `RELAY_STATE_KEY!`, which hides a real bug: an unset key becomes an empty HMAC key. It is listed in the open items below.
- **Remove the block in Phases 3 and 7.**

### D-009 `pnpm audit` gating
- CI fails on any advisory in production dependencies (`pnpm audit --prod`).
- The full audit runs as a non-blocking report.
- **At Phase 0:** one moderate, dev-only advisory, GHSA-g3hv-75wg-m249 (minimatch ReDoS via eslint 10.14.0). It is fixed in eslint 10.15.0, which is younger than the 7-day release-age guard until 2026-11-20. Take the Dependabot bump after that date rather than weakening the guard.

## Open questions from the kickoff review (need a decision before the phase named)
These are the 25 findings from the kickoff review, in short form. None is fixed yet.

| # | Item | Needed by |
|---|---|---|
| 1 | `Caller::Extension` gets `Gate::Open` for fill/totp/reveal/update in Standard mode, but is identified only by exe path + parent (spoofable). The core must verify the extension pairing on the pipe, or gate it | Phase 2 (policy), Phase 4 |
| 2 | Same-user squatter can pass the HMAC handshake (token readable by the user). Clients must also verify the pipe server process | Phase 2/3 |
| 3 | Peer identity needs a per-machine (admin) install dir; parent PIDs are reusable and spoofable | Phase 2 |
| 4 | AI `Create` is `Gate::Open` in code, but §4/§8 say approval + Hello | Phase 1 (policy) |
| 5 | Strict mode should deny AI reveal; code ignores `strict` for AI | Phase 1 |
| 6 | `get_totp` returns a secret to the model, contradicting §1/§8. Phase unassigned | Phase 3 |
| 7 | Relay device-link methods (`totp.begin/collect`, `approval.cancel`) aren't in the §7 method list or attack test; relay has no auth; `RELAY_STATE_KEY!` can be empty | Phase 7 |
| 8 | Whole-vault-file rollback isn't detected (counter only inside the file); manifest has no `Missing` result | Phase 1 |
| 9 | Approval TTL covers only the click, not hold + Hello; `pending` leaks if the future is dropped; limits aren't per profile | Phase 2 |
| 10 | KDF params have a floor but no ceiling; salt length unchecked | Phase 1 |
| 11 | Clipboard also needs `CanIncludeInClipboardHistory` and `CanUploadToCloudClipboard` | Phase 2 |
| 12 | Server must store only a hash of the auth subkey; fake prelogin params need a server secret | Phase 5 |
| 13 | "Recovery Key" vs "Secret Key / Recovery Kit" undefined; `recovery_vk` alone may bypass the password | Phase 1 |
| 14 | `Secret: Serialize` vs CLAUDE.md rule 3: write down the "only inside `seal`" exception | Phase 1 |
| 15 | AAD names: PLAN `kh/v1/vault/…`, `kh/v1/itemkey/…` vs code `kh/v1/vault-key/…`, `kh/v1/item-key/…`; audit AAD/context not in §5. Proposal: keep the code, fix PLAN (no data exists yet) | Phase 1 |
| 16 | Handshake client-proof byte order (PLAN `kN‖cN`, code `cN‖kN`); `hello.start/finish` missing from the method list | Phase 2 |
| 17 | Pipe name: PLAN uses the user SID, `core-client.ts` uses the username | Phase 3 |
| 18 | Item model drift: `ai_policy` fields, creator values, Android site rules, body padding, `decide` argument order | Phase 1 |
| 19 | CLI console-grant semantics differ between §4 and code; a "console" can't be verified from a pipe peer | Phase 3 |
| 20 | Sync route shape differs; `auth.ts` is a hard-coded stub | Phase 5 |
| 21 | Multi-device manifest model and 409 conflict resolution unspecified | Phase 5 (design in Phase 1) |
| 22 | Which tab `fill_login` targets; behaviour with no extension connected | Phase 3/4 |
| 23 | MCP server connects at startup, defaults the profile to `default`, has no message cap, timeout or parse guard | Phase 3 |
| 24 | Phase 0 "empty build" can only be proven on a Windows runner | Phase 0 (CI) |
| 25 | `tokio` `test-util` in normal deps; PSL refresh cadence; stale path comments in file headers | Phase 1 |
