# Ghidra MCP - Copilot Instructions

MCP server bridging Ghidra reverse engineering with AI tools. Java Ghidra extension + Python MCP bridge, version `5.6.0`, Java `21`, Ghidra `12.0.4`, and `225` cataloged MCP tools.

## Architecture

```text
AI tools <-> MCP bridge (bridge_mcp_ghidra.py) <-> Ghidra HTTP server <-> Ghidra services
```

- `bridge_mcp_ghidra.py` fetches `/mcp/schema` from the running Ghidra server and dynamically registers tools. It also owns static bridge/debugger helpers.
- `src/main/java/com/xebyte/GhidraMCPPlugin.java` is the GUI plugin entry point and HTTP server bootstrap.
- `src/main/java/com/xebyte/core/` contains shared `@McpTool` services registered through `AnnotationScanner`.
- `src/main/java/com/xebyte/headless/` contains the standalone headless server and project/program lifecycle support.
- `debugger/` exposes the optional debugger HTTP server on `GHIDRA_DEBUGGER_URL`.
- `fun-doc/` is an internal documentation curation subsystem, not the MCP plugin API.

## Build And Test Commands

```powershell
# Supported build facade
python -m tools.setup build

# Quick Java compile
mvn clean compile -q

# Manual Maven extension package
mvn clean package assembly:single -DskipTests

# Offline tests, no live Ghidra server
mvn test -Dtest='com.xebyte.offline.*Test'
pytest tests/unit/ -v --no-cov

# Setup-script tests after ghidra-mcp-setup.ps1 changes
.\tests\pester\Run-Tests.ps1 -CI

# Regenerate endpoint catalog after @McpTool/@Param changes
mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true

# Preflight and deploy
python -m tools.setup preflight --ghidra-path F:\ghidra_12.0.4_PUBLIC
python -m tools.setup ensure-prereqs --ghidra-path F:\ghidra_12.0.4_PUBLIC
python -m tools.setup build
python -m tools.setup deploy --ghidra-path F:\ghidra_12.0.4_PUBLIC

# Version bump
python -m tools.setup bump-version --new X.Y.Z
```

`tools.setup` uses Maven by default. Gradle support exists behind `TOOLS_SETUP_BACKEND=gradle` and for direct/manual migration validation.

## Adding Or Changing Endpoints

1. Add or update the `@McpTool` method in the relevant service class under `src/main/java/com/xebyte/core/` or headless service when the endpoint is headless-only.
2. Follow existing response, parameter, `ProgramProvider`, and `ThreadingStrategy` patterns in the same service.
3. Route naming-sensitive changes through `NamingConventions.java`.
4. Wrap Ghidra database writes in transactions and close disposable Ghidra helpers in `finally`.
5. Update `tests/endpoints.json`; if needed, regenerate with `mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true`.
6. Run offline Java tests and targeted Python tests.

For complex bridge-side orchestration, add a static `@mcp.tool()` in `bridge_mcp_ghidra.py` and add its name to `STATIC_TOOL_NAMES`.

## Change-To-Test Mapping

- `bridge_mcp_ghidra.py`: run bridge/tool/catalog/schema unit tests in `tests/unit/`.
- `src/main/java/com/xebyte/core/*Service.java`: run offline Java tests and the relevant integration subset when live Ghidra is available.
- `src/main/java/com/xebyte/headless/*`: run offline Java tests plus headless/deploy-related setup tests.
- `ghidra-mcp-setup.ps1`: run `.\tests\pester\Run-Tests.ps1 -CI`.
- `tools/setup/*`, `pom.xml`, or `build.gradle`: run setup CLI, Ghidra setup, Gradle task, version bump, and project consistency unit tests.
- User-facing behavior: update `CHANGELOG.md`.

## Gotchas

- `tests/endpoints.json` is the authoritative repo snapshot; runtime truth comes from `/mcp/schema`.
- POST endpoints with a `program` parameter expect it in the query string unless existing schema says otherwise.
- Script endpoints are disabled unless `GHIDRA_MCP_ALLOW_SCRIPTS=1`.
- Headless non-loopback binds should use `GHIDRA_MCP_AUTH_TOKEN`.
- Deploy/live benchmark tiers can mutate the active Ghidra project; read `docs/TESTING.md` before running them.
- Avoid committing generated state such as `target/`, `build/`, `.gradle/`, `logs/`, `fun-doc/state.json`, `fun-doc/inventory.json`, and `fun-doc/provider_pauses.json`.

## References

- Endpoint catalog: `tests/endpoints.json`
- Testing and release regression: `docs/TESTING.md`
- Tool usage guide: `docs/prompts/TOOL_USAGE_GUIDE.md`
- Project structure: `docs/PROJECT_STRUCTURE.md`
- Naming conventions: `docs/NAMING_CONVENTIONS.md`
- Release checklist: `docs/releases/RELEASE_CHECKLIST.md`
