# Ghidra MCP — Copilot Instructions

MCP server bridging Ghidra reverse engineering with AI tools. Java (Ghidra extension) + Python (MCP bridge), 199 MCP tools.

## Architecture

```
AI Tools <-> MCP Bridge (bridge_mcp_ghidra.py) <-> Ghidra Plugin (GhidraMCPPlugin.jar)
```

- **Plugin**: `src/main/java/com/xebyte/GhidraMCPPlugin.java` — HTTP server on port 8089, delegates to services
- **Bridge**: `bridge_mcp_ghidra.py` — dynamic tool registration from `/mcp/schema` + 7 static tools
- **Services**: `src/main/java/com/xebyte/core/` — 12 service classes, `@McpTool`/`@Param` annotated
- **Headless**: `src/main/java/com/xebyte/headless/` — standalone server without GUI
- **Annotation Scanner**: `AnnotationScanner.java` auto-discovers `@McpTool` methods, generates `/mcp/schema`

## Build & Test Commands

```powershell
# Build
mvn clean package assembly:single -DskipTests

# Quick compile check
mvn clean compile -q

# Offline tests (no Ghidra required)
mvn test -Dtest='com.xebyte.offline.*Test'
pytest tests/unit/ -v --no-cov

# Full integration tests (Ghidra on port 8089)
mvn test
pytest tests/

# Regenerate endpoint catalog after @McpTool changes
mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true

# Deploy
.\ghidra-mcp-setup.ps1 -Deploy

# Version bump
.\bump-version.ps1 -New X.Y.Z
```

## Adding New Endpoints

1. Add `@McpTool` + `@Param` method in the appropriate service class under `src/main/java/com/xebyte/core/`
2. `AnnotationScanner` auto-discovers it — no bridge or registry changes needed
3. Add entry to `tests/endpoints.json` with path, method, category, description
4. If `EndpointsJsonParityTest` fails, regenerate with `mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true`

For complex tools needing bridge-side logic, add a static `@mcp.tool()` in `bridge_mcp_ghidra.py` and add the name to `STATIC_TOOL_NAMES`.

## Code Conventions

- All endpoints return JSON
- Transactions must be committed for Ghidra database changes
- Prefer batch operations over individual calls
- `@Param(value = "program")` defaults to `ParamSource.QUERY` — POST endpoints must send `program` as URL query param, not in JSON body
- Wire naming validation through `NamingConventions.java`
- Services use constructor injection: `ProgramProvider` + `ThreadingStrategy`
- GUI operations from HTTP threads must use `SwingUtilities.invokeAndWait()`

## Key Files

- **Endpoint catalog**: `tests/endpoints.json` (199 endpoints, authoritative)
- **Tool usage guide**: [docs/prompts/TOOL_USAGE_GUIDE.md](docs/prompts/TOOL_USAGE_GUIDE.md)
- **Naming conventions**: [docs/NAMING_CONVENTIONS.md](docs/NAMING_CONVENTIONS.md)
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)
- **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)

## Gotchas

- Ghidra overwrites `FrontEndTool.xml` on exit — deploy must patch AFTER Ghidra exits
- Shared server renames not persisted by `save_program` — must checkin to persist
- Max ~5 shared server programs open at once — opening 20+ crashes Ghidra
- Plate comment `\n` creates literal text, not newlines — use actual multi-line text
