---
description: Build and deploy the Ghidra MCP plugin
mode: agent
---

# Build & Deploy

## Quick compile check

```powershell
mvn clean compile -q
```

## Full build (creates JAR)

```powershell
mvn clean package assembly:single -DskipTests
```

## Deploy to Ghidra

```powershell
.\ghidra-mcp-setup.ps1 -Deploy
```

This handles: Maven build → extension install → FrontEndTool.xml patching → Ghidra restart.

## First-time setup

```powershell
.\ghidra-mcp-setup.ps1 -SetupDeps
```

Installs Ghidra JARs to local Maven repository.

## Version bump

```powershell
.\bump-version.ps1 -New X.Y.Z
```

Updates version across all files atomically (pom.xml, bridge, docs, etc.).
