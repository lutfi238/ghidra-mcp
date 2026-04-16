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
```

## Integration tests (requires Ghidra on port 8089)

```powershell
mvn test
pytest tests/
```

## After modifying @McpTool annotations

If `EndpointsJsonParityTest` fails, regenerate the catalog:

```powershell
mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true
```

Then re-run offline tests to confirm parity.
