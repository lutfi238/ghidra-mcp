---
description: Run the appropriate test suite for ghidra-mcp
mode: agent
---

# Run Tests

Run the correct test suite based on what changed.

## Offline tests (no Ghidra required)

```powershell
# Java annotation scanner + endpoint parity
mvn test -Dtest='com.xebyte.offline.*Test'

# Python unit tests
pytest tests/unit/ -v --no-cov

# PowerShell setup-script tests
.\tests\pester\Run-Tests.ps1 -CI
```

## Integration tests (requires Ghidra on port 8089)

```powershell
mvn test
pytest tests/
```

## Match tests to changed files

- `bridge_mcp_ghidra.py`: run the relevant bridge, tool, response schema, and endpoint catalog tests in `tests/unit/`.
- `src/main/java/com/xebyte/core/*Service.java`: run offline Java tests first, then the relevant live integration subset when a Ghidra instance is available.
- `src/main/java/com/xebyte/headless/*`: run offline Java tests and setup/deploy tests relevant to headless behavior.
- `ghidra-mcp-setup.ps1`: run `.\tests\pester\Run-Tests.ps1 -CI`.
- `tools/setup/*`, `pom.xml`, or `build.gradle`: run setup CLI, Ghidra setup, Gradle task, version bump, and project consistency unit tests.
- Deploy/live-regression changes: read `docs/TESTING.md`; benchmark tiers are opt-in and can mutate the active Ghidra project.

## After modifying @McpTool annotations

If `EndpointsJsonParityTest` fails, regenerate the catalog:

```powershell
mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true
```

Then re-run offline tests to confirm parity.
