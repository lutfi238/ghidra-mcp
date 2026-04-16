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
7. Return JSON via `JsonHelper`
8. Add entry to `tests/endpoints.json`
9. Run `mvn clean compile -q` to verify compilation

## Conventions

- All endpoints return JSON
- POST endpoints: `program` param goes in URL query, not JSON body
- GUI operations from HTTP threads must use `SwingUtilities.invokeAndWait()`
- Prefer batch operations over individual calls

## Reference

- Existing services: `src/main/java/com/xebyte/core/`
- Annotation definitions: `McpTool.java`, `Param.java`, `ParamSource.java`
- Endpoint catalog: `tests/endpoints.json`
