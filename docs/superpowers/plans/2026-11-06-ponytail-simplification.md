# Ponytail simplification implementation plan

> **For agentic workers:** Use executing-plans/subagent-driven-development for isolated implementation tasks. Preserve behavior and existing security boundaries.

**Goal:** Apply the six approved audit findings without changing monitoring behavior, then create a separate PR and deploy with verified rollback.

**Architecture:** Reuse CheckContext for HTTP and existing Pydantic constraints for scalar configuration validation. Share low-level private-file I/O while retaining per-service validation/errors. Remove only redundant branches/wrappers and unsupported keyword input shapes.

**Tech Stack:** Existing Python/Django/httpx/Pydantic/SQLite; no new dependencies.

- [x] Establish clean baseline in isolated worktree; trace every affected caller and regression.
- [x] HTTP: remove duplicate load paths; support standalone checks with temporary closed context; preserve redirects, bounded bodies, latency and error handling. Simplify keyword input to validated list[str]. Run HTTP/context/proxy/analytics tests.
- [x] Secrets: share mode-0600/no-follow bounded reads and atomic writes; preserve limits, validators, service-specific diagnostics, environment precedence and no DB initialization. Run credential/proxy tests.
- [x] Config: move scalar ranges to Field constraints; keep cross-field/path/secret-safe validation and legacy compatibility. Run config/setup/diagnostics tests.
- [x] Dispatcher/UI: remove unreachable daily branches from operational history-cache path and redundant view no-store wrappers; keep global middleware policy. Run cache/owner/public security regressions.
- [x] Independent review; Ruff, complete Python3.12/13/14, Node, translations, CLI, migration drift and Compose checks.
- [ ] Commit/push separate stacked PR against existing feature branch; CI green; immutable builds; verified online backup/clone; local/VPS deploy and source/data/worker/HTTP read-back.

## Verified result before release

- Baseline: 1238 tests passed. Final: 1272 tests passed on each Python3.12/13/14.
- Ruff, diff whitespace, Node behavior checks, gettext, CLI, migration drift and
  both Compose configurations passed. Independent final review found no
  Important/Critical issues.
- Net production Python reduction: 291 lines including the new shared private-file
  module; no dependencies added or removed. Extra lines cover regression tests.
- Keywords/deface standalone content fetches remain: their origin retry/redirect
  semantics differ from the shared cycle loader, so removing those branches would
  change behavior or add compatibility knobs. HTTPbasic's duplicate loader is removed.
- Standalone WHOIS zero-TTL construction remains supported; full application config
  still rejects nonpositive WHOIS intervals. Other numeric bounds now reject invalid
  config earlier using existing sanitized Pydantic diagnostics; validate_config also
  revalidates mutable settings.
- Successful standalone HTTP redirect timing now uses the shared loader's single
  end-to-end span rather than adding individually rounded hop times. First-hop
  latency/severity and historical standalone redirect-count semantics are retained.
- Runtime release acceptance follows this implementation commit: verified backups,
  isolated real-config/credential reads, preservation/source/worker/HTTP checks and CI.
