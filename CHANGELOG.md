# Changelog

All notable changes to ExtShield are documented here.

## 0.1.0 — Initial release

- Activity monitoring for file access, network requests, and spawned processes, attributed to the extension responsible.
- Automatic detection of sensitive file access and secret-like file content.
- Per-extension access policies (path restriction, network block, process-spawn block) with optional enforcement.
- Manifest-based risk scoring for all installed extensions.
- Trusted-extensions allowlist with a curated starter list, VS Code Settings Sync support, and manual export/import.
- Multi-source threat intelligence (URLhaus + OpenPhish community feed + static watch-list) blended into a single confidence score, with retroactive updates to persisted history when a delayed result arrives.
- One-click Extension Host isolation suggestions via `remote.extensionKind`, including proactive auto-suggestions above a configurable risk threshold.
- On-disk activity log persistence with configurable retention.
- Activity Bar sidebar view with a status toggle, one-click quick actions, and an inline-actionable risk list — no Command Palette required for day-to-day use.
- Full activity dashboard webview with filtering and per-extension actions.