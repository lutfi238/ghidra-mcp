---
description: Add a new MCP tool endpoint to the Ghidra MCP server
mode: agent
---

# New MCP Endpoint

Create a new `@McpTool` endpoint following the project conventions.

## Steps

1. Identify the correct service class in `src/main/java/com/xebyte/core/` based on the tool's category
2. Add the method with `@McpTool` and `@Param` annotations
3. Follow existing patterns in the same service class for response format
4. Wire naming validation through `NamingConventions.java` if the tool modifies names
5. Use `ProgramProvider` for program access and `ThreadingStrategy` for thread safety
6. Wrap Ghidra database changes in transactions
7. Release disposable Ghidra helpers in `finally`
8. Return JSON via `JsonHelper`
9. Check whether headless parity is required in `src/main/java/com/xebyte/headless/`
10. Add or update the entry in `tests/endpoints.json`
11. Update `CHANGELOG.md` for user-facing behavior
12. Run `mvn clean compile -q` and the offline Java endpoint/scanner tests

## Conventions

- All endpoints return JSON
- POST endpoints: `program` param goes in URL query, not JSON body
- Follow existing `ProgramProvider` and `ThreadingStrategy` usage in the service
- Prefer batch operations over individual calls
- Script execution remains gated by `GHIDRA_MCP_ALLOW_SCRIPTS=1`

## Tests

```powershell
mvn clean compile -q
mvn test -Dtest='com.xebyte.offline.*Test'
```

If `EndpointsJsonParityTest` fails after annotation changes, regenerate the catalog and rerun the offline Java tests:

```powershell
mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true
```

## Reference

- Existing services: `src/main/java/com/xebyte/core/`
- Headless server: `src/main/java/com/xebyte/headless/`
- Annotation definitions: `McpTool.java`, `Param.java`, `ParamSource.java`
- Endpoint catalog: `tests/endpoints.json`
