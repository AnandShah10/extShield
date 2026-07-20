# ExtShield Development Guide

## Overview

This document provides detailed guidance for developers working on ExtShield. For general contribution guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md).

ExtShield is a VS Code extension that provides visibility and best-effort controls over what other extensions are doing by patching core Node.js modules (`fs`, `http`/`https`, `child_process`) and using stack trace analysis for attribution.

## Development Setup

See [CONTRIBUTING.md](CONTRIBUTING.md) for building from source, running in an Extension Development Host, packaging, and the project layout.

Key commands:
- `npm install`
- `npm run compile` (or `npm run watch` for development)
- Press **F5** in VS Code to launch the Extension Development Host

**Tip**: Install test extensions (e.g. ones that make network calls or file I/O) in the dev host to exercise the monitoring.

## Architecture

### Core Components

- **monitor.ts**: Central patching layer using `safePatch` and `definePatch` for fault tolerance. All monitored APIs funnel through here.
- **attribution.ts**: Stack trace parsing to map calls back to specific extension IDs. Critical for "fail open" behavior.
- **policyManager.ts**: Persists and enforces per-extension policies (allow/deny paths, network, processes).
- **secretDetector.ts**: Pattern matching for sensitive paths and content (API keys, credentials, etc.).
- **scanner.ts**: Manifest analysis for risk scoring (permissions, activation events, dependencies, etc.).
- **threatIntel.ts**: Caching layer + network lookups against URLhaus and OpenPhish (with offline fallback).
- **trustedExtensions.ts**: Built-in allowlist + user-managed list synced via VS Code settings.
- **isolationAdvisor.ts**: Uses VS Code's `remote.extensionKind` API to suggest moving risky extensions to isolated hosts.
- **logStore.ts**: JSONL-based persistent storage with automatic pruning.
- **dashboardPanel.ts**: Webview-based UI for the full activity dashboard and risk scanner.
- **treeView.ts**: Sidebar TreeDataProvider implementation.
- **extension.ts**: Activation, command registration, and wiring everything together.

### Key Design Principles (from CONTRIBUTING.md)

- Never claim more isolation than VS Code provides
- Fail open on attribution failures
- Every patch must be individually fault-tolerant
- Commands must register before heavy initialization

See `CONTRIBUTING.md` for full details.

## Debugging

1. **Output Channel**: Use the command `ExtShield: Show Output Channel`. Most issues appear as `[warning]` or `[error]` entries.
2. **Developer Tools**: In the Extension Development Host, use `Developer: Toggle Developer Tools` to inspect the webview dashboard.
3. **Breakpoints**: The extension runs in the "Extension Host" debug session. Set breakpoints in `src/` files.
4. **Activity Log**: The in-memory log and on-disk JSONL (`~/.vscode/extensions/anandshah.extshield-*/logs/`) provide rich context.
5. **Verbose Logging**: Temporarily modify `log.ts` (if added) or add console logs that route through the output channel.

Common debugging scenarios:
- **Attribution failures**: Check stack traces in the log. The `getExtensionFromStack` function in `attribution.ts` is the key.
- **Patch failures**: Look for `safePatch` warnings in the output.
- **Webview issues**: Check browser console in the dashboard panel.

## Adding Monitoring for New APIs

1. Identify the built-in to patch (e.g. a new `fs` method or `process` property).
2. Add a `definePatch` or `safePatch` call in `monitor.ts` following existing patterns.
3. Ensure the wrapper calls `logActivity()` with appropriate context.
4. Update `types.ts` if new activity types are needed.
5. Add tests in the dev host by creating a sample extension that exercises the API.
6. Update documentation in README.md and this file.

**Important**: Always preserve the original function's `this` context and argument handling. Use the `createWrapper` helper where possible.

## Risk Scanner and Heuristics

The scanner in `scanner.ts` evaluates:
- Declared permissions in `package.json`
- Suspicious activationEvents
- Dependencies on known risky modules
- Publisher reputation (future enhancement)
- Presence of native modules or workers

To add new heuristics:
- Extend the `calculateRiskScore` function
- Add explanation text in the risk report
- Update the risk thresholds in settings if needed

## Testing Changes

Since this project uses manual testing in an Extension Development Host:

1. Make changes in `src/`
2. Compile (`npm run compile` or use watch mode)
3. Test in the launched Extension Development Host:
   - Install various extensions (good, risky, malicious-looking)
   - Trigger file I/O, network calls, process spawning
   - Verify attribution, policies, secret detection, threat intel
   - Check dashboard and sidebar
4. Test edge cases:
   - Unattributed calls (should fail open)
   - Patch errors (should not break other monitoring)
   - Remote development scenarios for isolation advisor
   - Network offline mode for threat intel

**Future**: Consider adding automated unit tests with `mocha` + `@vscode/test-electron` and integration tests.

## Code Style

- TypeScript strict mode (see `tsconfig.json`)
- Follow existing patterns for error handling and logging
- Prefer descriptive variable names
- Keep patches as thin as possible
- Document any new limitations in the Security Model section of README.md

## Releasing

1. Update version in `package.json`
2. Update `CHANGELOG.md`
3. Run `npm run compile`
4. Package with `npx @vscode/vsce package`
5. Test the `.vsix` in a clean VS Code instance
6. Publish via VS Code Marketplace

See VS Code extension publishing docs for details.

## Resources

- [VS Code Extension API](https://code.visualstudio.com/api)
- [VS Code Extension Guidelines](https://code.visualstudio.com/api/references/extension-guidelines)
- Project issues: https://github.com/AnandShah10/extShield/issues

---

*Contributions that follow these patterns and maintain the security model will be prioritized.*
