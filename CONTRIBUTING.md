# Contributing to ExtShield

See [DEVELOPMENT.md](DEVELOPMENT.md) for architecture overview, debugging tips, how to add new monitoring, testing practices, and release process. This file focuses on build instructions, project layout, and core design principles.

## Building from source

```bash
npm install
npm run compile
```

Press **F5** with this folder open in VS Code to launch an Extension Development Host with ExtShield active. Install a few other extensions in that dev host and watch the sidebar/dashboard populate as they run.

`npm run watch` recompiles on save during development.

## Packaging

Packaging into a `.vsix` for local install or Marketplace publishing uses [`@vscode/vsce`](https://www.npmjs.com/package/@vscode/vsce):

```bash
npx @vscode/vsce package
```

This requires a `LICENSE` file and a `publisher` field in `package.json` that matches a registered Azure DevOps publisher — see the [vsce publishing docs](https://code.visualstudio.com/api/working-with-extensions/publishing-extension) for the one-time publisher setup.

## Project layout

```
media/
  icon.svg              Activity Bar icon
src/
  extension.ts           activation, commands, sidebar/status bar wiring
  treeView.ts             the Activity Bar sidebar (TreeDataProvider)
  monitor.ts              patches fs/http/https/child_process (+ optional env)
  attribution.ts          stack-trace -> extension id resolution
  policyManager.ts        per-extension policy storage
  secretDetector.ts       sensitive-path and secret-content pattern matching
  scanner.ts              manifest-based risk scoring of installed extensions
  trustedExtensions.ts    trusted allowlist (built-in + user-managed)
  threatIntel.ts          URLhaus/OpenPhish lookups with caching and offline fallback
  isolationAdvisor.ts     remote.extensionKind-based isolation suggestions
  logStore.ts             on-disk JSONL persistence + retention pruning
  dashboardPanel.ts       webview UI (activity log + risk scan tabs)
  types.ts                shared TypeScript interfaces
```

## Design principles worth knowing before you send a PR

- **Never claim more isolation than VS Code actually provides.** ExtShield patches shared Node built-ins and attributes via stack traces — it is not a sandbox. Any new feature should be honest about what it can and can't guarantee (see the README's "Security Model & Limitations").
- **Fail open, not closed, on attribution misses.** If a call can't be confidently attributed to an extension, policies must not be enforced against it — an enforcement mistake that breaks an unrelated extension is worse than a monitoring gap.
- **Every patch point must be individually fault-tolerant.** Use the `safePatch`/`definePatch` pattern in `monitor.ts` — one built-in behaving unexpectedly in some VS Code host must never take down monitoring for everything else, let alone extension activation.
- **Commands register before real initialization runs**, in `extension.ts`. A failure during startup should degrade a feature, never cause VS Code's generic "command not found."

## Reporting issues

Please attach the contents of the "ExtShield" output channel (`ExtShield: Show Output Channel`) to bug reports — most issues are explained by a `[warning]` or `[error]` line there.