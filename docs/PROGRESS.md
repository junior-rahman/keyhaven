# Progress

One section per phase of `docs/PLAN.md` §13. Tick a criterion only with evidence: test names, command output or a CI link.

## Phase 0: repo, CI, lint, fmt, cargo-deny, pnpm workspace

**Exit criterion:** CI green on an empty build (Windows and Linux runners).

| Criterion | Status | Evidence |
|---|---|---|
| Rust toolchain pinned | ✅ | `rust-toolchain.toml` (1.97.0). DECISIONS D-001 |
| `cargo fmt --all --check` clean | ✅ | Local, Linux: no output, exit 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` clean | ✅ | Local, Linux: `Finished`, 0 warnings |
| `cargo test --workspace` passes | ✅ | Local, Linux: `test result: ok. 14 passed; 0 failed` (kh_core). kh_ffi has 0 tests; kh_win is empty on Linux |
| kh-win compiles against `windows` 0.62 | ✅ type-check / ⏳ link | `cargo clippy -p kh_win --target x86_64-pc-windows-msvc --all-targets -- -D warnings`: `Finished`, 0 warnings. Linking and `cargo test -p kh_win` run only on the Windows CI job. DECISIONS D-005 |
| Every `unsafe` block has `// SAFETY:` | ✅ | Enforced by `clippy::undocumented_unsafe_blocks = "deny"` (D-003); kh-win passes |
| `cargo deny check` clean | ✅ | Local: `advisories ok, bans ok, licenses ok, sources ok` (1 warning: duplicate `syn` 2/3, transitive) |
| pnpm workspace: lint, typecheck, test | ✅ | Local (Node 22.23, pnpm 10.28.0): `pnpm -r lint` / `typecheck` / `test` all `Done` for mcp-server, sync-server and relay (no test files yet; `--passWithNoTests`) |
| `pnpm audit` | ✅ prod / ⚠️ dev | `pnpm audit --prod`: `No known vulnerabilities found`. Full audit: 1 moderate dev-only advisory (GHSA-g3hv-75wg-m249, via eslint). DECISIONS D-009 |
| GitHub Actions: Linux + Windows jobs | ⏳ | `.github/workflows/ci.yml`. Awaiting the first run on the Phase 0 PR |
| Dependabot (cargo, npm, actions) | ✅ | `.github/dependabot.yml` |
| PROGRESS.md and DECISIONS.md | ✅ | This file, `docs/DECISIONS.md` |

**Phase 0 is not done until the CI run is green on both runners.** Add the run link here when it is.
