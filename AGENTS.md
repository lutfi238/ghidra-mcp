# AGENTS.md - ghidra-mcp Project

You are a coding agent working on **ghidra-mcp**, a Model Context Protocol server that bridges Ghidra reverse engineering capabilities with AI tools.

## Project Snapshot

- Repo: `https://github.com/bethington/ghidra-mcp`
- Version: `5.6.0`
- Java target: `21`
- Ghidra target: `12.0.4`
- Runtime shape: Java Ghidra extension and headless server plus the Python MCP bridge in `bridge_mcp_ghidra.py`
- Endpoint inventory: `tests/endpoints.json` is the maintained repo snapshot and currently declares `225` MCP tools

## Architecture

- `bridge_mcp_ghidra.py` is the MCP entry point. It connects to the Ghidra HTTP server, fetches `/mcp/schema`, dynamically registers schema tools, and keeps bridge-side/static tools for connection, lazy loading, debugger proxying, and local orchestration.
- `src/main/java/com/xebyte/GhidraMCPPlugin.java` is the GUI plugin entry point. It exposes the HTTP server and registers shared service endpoints through `AnnotationScanner`.
- `src/main/java/com/xebyte/core/` contains shared services annotated with `@McpTool` and `@Param`. Services use `ProgramProvider` plus `ThreadingStrategy` dependencies; keep new behavior in the relevant service instead of growing the plugin entry point.
- `src/main/java/com/xebyte/headless/` contains the headless server and program/project management. Keep headless parity in mind when adding or changing shared endpoints.
- `debugger/` is the standalone debugger HTTP server used by bridge debugger tools through `GHIDRA_DEBUGGER_URL`.
- `fun-doc/` is an internal AI-assisted documentation/curation subsystem, not part of the MCP plugin surface.

## Current Priorities

1. Maintain headless server parity with GUI plugin endpoints.
2. Keep `tests/endpoints.json` synchronized with Java endpoint registrations.
3. Keep CI/CD and release-regression paths healthy.
4. Support community PR review without pushing directly to `main`.

## Commands

- Quick compile: `mvn clean compile -q`
- Build extension ZIP through the supported facade: `python -m tools.setup build`
- Manual Maven build: `mvn clean package assembly:single -DskipTests`
- Preflight: `python -m tools.setup preflight --ghidra-path F:\ghidra_12.0.4_PUBLIC`
- Deploy: `python -m tools.setup ensure-prereqs --ghidra-path F:\ghidra_12.0.4_PUBLIC` then `python -m tools.setup build` then `python -m tools.setup deploy --ghidra-path F:\ghidra_12.0.4_PUBLIC`
- Python unit tests: `pytest tests/unit/ -v --no-cov`
- Offline Java endpoint/scanner tests: `mvn test -Dtest='com.xebyte.offline.*Test'`
- Pester setup tests after PowerShell setup-script changes: `.\tests\pester\Run-Tests.ps1 -CI`
- Version bump: `python -m tools.setup bump-version --new X.Y.Z`

`tools.setup` uses Maven by default. Gradle support exists as a secondary/manual path; use `TOOLS_SETUP_BACKEND=gradle` only when intentionally validating the Gradle migration path.

## Change Guidance

- Create PRs for review; do not push directly to `main`.
- For user-facing behavior, update `CHANGELOG.md`.
- For `@McpTool` or `@Param` changes, keep `tests/endpoints.json` in sync. If parity fails, regenerate with `mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true`, then rerun the offline Java tests.
- For bridge changes, run the targeted Python unit tests in `tests/unit/` for bridge, tool registration, response schema, and endpoint catalog behavior.
- For `ghidra-mcp-setup.ps1` or setup tooling changes, run the Pester suite and the setup-related Python unit tests under `tests/unit/`.
- For deploy or live-regression changes, read `docs/TESTING.md`; benchmark-importing tiers are opt-in and mutate the active Ghidra project.
- For releases, use `docs/releases/RELEASE_CHECKLIST.md` instead of duplicating the runbook.

## Coding Conventions

- Keep endpoint responses JSON-shaped and follow nearby service patterns.
- Prefer annotated service methods over manual HTTP route additions unless the route is genuinely special.
- POST endpoints with a `program` parameter should pass `program` as a query parameter unless existing schema says otherwise.
- Wrap Ghidra database writes in transactions and end transactions in `finally` with the correct success flag.
- Own disposable Ghidra helpers such as decompilers and emulators in the smallest practical scope and release them in `finally`.
- Use `NamingConventions.java` for function, label, global, and structure-field naming validation.
- Prefer batch endpoints for repeated operations.
- Treat script execution endpoints as gated: `/run_script_inline` and `/run_ghidra_script` require `GHIDRA_MCP_ALLOW_SCRIPTS=1`.
- When binding beyond loopback in headless mode, require/expect `GHIDRA_MCP_AUTH_TOKEN`.

## Files And Docs

- Endpoint catalog: `tests/endpoints.json`
- Testing and live regression: `docs/TESTING.md`
- Tool usage guide: `docs/prompts/TOOL_USAGE_GUIDE.md`
- Project structure: `docs/PROJECT_STRUCTURE.md`
- Naming rules: `docs/NAMING_CONVENTIONS.md`
- Build/deploy helper: `tools/setup/`
- Project-local MCP config: `.mcp.json`

Avoid committing generated or local state unless a task explicitly requires it: `target/`, `build/`, `.gradle/`, `logs/`, `fun-doc/state.json`, `fun-doc/inventory.json`, and `fun-doc/provider_pauses.json`.
