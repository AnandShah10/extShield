# ExtShield — Zero-Trust Extension Monitor for VS Code

ExtShield watches what *other installed extensions* do — file access, outbound network calls, spawned processes, and (optionally) environment variable reads — and shows you which extension did what. It flags sensitive-looking file access and lets you set a best-effort access policy per extension. Everything below is usable entirely from the sidebar; you don't need the Command Palette day to day.

## Getting started

1. Click the shield icon in the **Activity Bar** (the vertical bar of icons on the far left/right of the window) to open the **ExtShield** view.
2. That's it — monitoring starts automatically. The view updates live as extensions do things.

If you don't see the icon, run **View → Open View...** and search for "ExtShield," or use `Ctrl/Cmd+Shift+P` → "ExtShield: Open Activity Dashboard" once — after that the icon stays in the Activity Bar.

## Using the sidebar

The ExtShield view has three parts:

**1. Status row** (top)
Shows `Monitoring: ON` or `OFF`, plus a live count of events, high-risk events, and blocked calls. Click it to toggle monitoring on/off — no settings menu needed.

**2. Quick Actions**
A flat list, click any row to run it:
- Open Activity Dashboard — the full live log, filterable, in a tab
- Scan Installed Extensions — refreshes the risk list below
- Manage Trusted Extensions — a checklist to mark extensions you don't want nagging you for a policy
- Suggest Extension Host Isolation — see "Isolation" below
- Set Access Policy… — pick any extension and restrict it
- Export Activity Log as JSON — full history, opens as a document
- Show Historical Log Location — where the on-disk log file lives
- Clear In-Memory Log — clears the live view only; disk history is untouched

**3. Extension Risk Scan**
A list of your installed extensions sorted by a heuristic risk score (updates when you click "Scan Installed Extensions"). Each row shows the score and, on hover, *why* it scored that way. Three icons sit on the right of each row — no menus, no palette:

| Icon | Action |
|---|---|
| ⚖️ (law) | Set an access policy for this specific extension |
| ✅ (verified) | Toggle it trusted/untrusted |
| 🖥️ (server-process) | Get an isolation suggestion for it |

Clicking the row itself is the same as the ⚖️ icon (set policy) — the fastest path for the most common action.

There's also a small toolbar at the top of the view itself (hover over the "ExtShield" header): a dashboard shortcut, a refresh button, and the monitoring toggle, all one click.

## The dashboard (optional, for deep-dives)

"Open Activity Dashboard" opens a full tab with two views:
- **Activity Log** — every file/network/process event, filterable by extension or target, color-coded by risk, with a live threat-intel badge on network calls.
- **Extension Risk Scan** — the same list as the sidebar, with more room, plus "Set policy…", "Mark trusted"/"Remove trust", and "Suggest isolation…" buttons per row.

Use the sidebar for quick day-to-day glances and actions; use the dashboard when you actually want to read through what happened.

## What gets flagged automatically (no action needed)

- Reading files that look like secrets (`.env`, `id_rsa`, cloud credentials, `.npmrc`, PEM keys, etc.) pops a warning with "Open Dashboard" / "Set Policy" buttons right there.
- Contacting a network host flagged by the free URLhaus malicious-host feed pops a similar warning.
- Both are logged either way, flagged or not, so the activity log stays a complete record.

## Settings

Settings → search "ExtShield", or edit directly in `settings.json`:

| Setting | Default | What it does |
|---|---|---|
| `extshield.enabled` | `true` | Master on/off (same as the sidebar status row) |
| `extshield.blockOnPolicyViolation` | `false` | Actually enforce policies (block), not just log violations |
| `extshield.monitorEnvAccess` | `false` | Experimental: log which extension reads which env var name |
| `extshield.notifyOnSecretAccess` | `true` | Pop a warning on sensitive file/content access |
| `extshield.logRetentionEntries` | `2000` | Max events kept in memory/dashboard |
| `extshield.diskLogRetentionDays` | `30` | Days of on-disk history kept; `0` = forever |
| `extshield.threatIntel.enabled` | `true` | Check contacted hosts against URLhaus |
| `extshield.threatIntel.cacheTtlMinutes` | `60` | How long to cache a host's threat-intel result |

## Isolation suggestions, in plain terms

Clicking the 🖥️ icon (or "Suggest Extension Host Isolation") does one of two things:
- **Not connected to Remote-SSH / Dev Containers / WSL right now?** You'll get a plain message saying there's no second process to isolate anything into — nothing to click through, just the honest answer.
- **Connected?** You'll get a choice to run that specific extension in the remote/container process instead of your local machine (or vice versa), via VS Code's own `remote.extensionKind` setting. Confirming offers to reload the window so it takes effect.

## Troubleshooting

- **A command says "not found"** — this means the extension failed to initialize. Open the "ExtShield" output channel (bottom panel → Output → pick "ExtShield" from the dropdown, or click the warning row at the top of the sidebar) to see why, then reload the window after fixing it.
- **Sidebar shows "ExtShield failed to initialize"** — same as above; click that row to jump straight to the output channel.
- **Nothing shows up in the Activity Log** — monitoring only sees activity from *other* extensions after ExtShield has started; try triggering something in another extension (e.g. open a file it processes), then check again.

## Building from source

\`\`\`bash
npm install
npm run compile
\`\`\`
Press **F5** with this folder open to launch an Extension Development Host with ExtShield active.

---

## What this actually is (read this before relying on it)

VS Code has **no built-in permission system or sandbox for extensions** — all extensions share one process and one set of Node built-ins, with no OS-level isolation. ExtShield works by patching those shared built-ins (`fs`, `http`/`https`, `child_process`) and using the JS call stack to attribute each call to the extension that made it. That gives real visibility and a best-effort blocking layer, **not** a true sandbox:

- A sufficiently motivated extension can bypass monitoring (native addons, worker threads, bundled copies of Node core modules, or grabbing function references before ExtShield activates).
- Web Extensions (running in a browser Worker, e.g. vscode.dev) aren't covered at all — there's no shared Node process there to patch.
- Blocking only applies at the exact patched entry points; anything reaching the OS a different way isn't caught.
- Stack-trace attribution is best-effort; unattributable events are logged as "(unattributed)" and policies aren't enforced against them (fails open, on purpose).
- Risk scores are manifest-based heuristics — a prioritization signal, not a verdict.
- Threat-intel checks happen *after* the network call already went out, so they inform review/alerting, not blocking. "Clean" means "not currently listed," not "verified safe."
- Isolation suggestions only do something in a Remote-SSH/Container/WSL setup, since that's the only place VS Code actually gives you a second, separate process to move an extension into.

Treat ExtShield like a network monitor or audit log: excellent for visibility and catching sloppy/obvious bad behavior, not a guarantee against a sophisticated, determined attacker.

## Project layout

\`\`\`
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
  threatIntel.ts          URLhaus lookups with caching and offline fallback
  isolationAdvisor.ts     remote.extensionKind-based isolation suggestions
  logStore.ts             on-disk JSONL persistence + retention pruning
  dashboardPanel.ts       webview UI (activity log + risk scan tabs)
  types.ts                shared TypeScript interfaces
\`\`\`

## Further ideas

- Retroactively update persisted log entries when a delayed threat-intel result comes back.
- Share/export the trusted-extensions list across machines.
- Blend multiple threat-intel sources with a confidence score.
- Auto-surface isolation suggestions for anything scoring above a threshold, instead of only on request.
