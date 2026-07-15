# ExtShield — Zero-Trust Extension Monitor for VS Code

ExtShield watches what *other installed extensions* do inside the shared VS Code extension host process — file access, outbound network calls, spawned processes, and (optionally) environment variable reads — and attributes each action back to the extension that triggered it. It flags sensitive-looking file access (`.env`, private keys, cloud credentials) and lets you define a best-effort access policy per extension.

## Read this first: what this actually is

VS Code has **no built-in permission system or sandbox for extensions**. All extensions (other than Web Extensions) share one Node.js process and one set of built-in modules (`fs`, `http`, `child_process`, etc.), with no OS-level isolation between them. That's a platform limitation, not something any third-party extension — including this one — can fully fix.

**What ExtShield actually does:** it monkey-patches the shared Node.js built-ins (`fs`, `fs.promises`, `http`, `https`, `child_process`) and uses the JavaScript call stack to identify which extension's code is on the stack when a call happens (by matching `.vscode/extensions/<publisher>.<name>-<version>/...` in the stack trace). This gives real, useful **visibility** and a **best-effort blocking layer** for calls that go through those specific patched functions.

**What it cannot do:**
- It cannot create a true sandbox or security boundary. An extension that really wants to bypass monitoring can do so — e.g. by using a native addon, a bundled/rebuilt copy of a Node core module, a Worker thread, WASM, or by capturing references to the original functions before ExtShield activates (activation order isn't guaranteed).
- It cannot attribute or police **Web Extensions** running in a Worker inside the browser/vscode.dev host — there's no shared, patchable Node process there.
- Blocking is enforced only at the specific patched entry points (`fs.readFile`, `https.request`, `child_process.spawn`, etc.) and their promise variants. Anything that reaches the OS through a different path won't be caught.
- Stack-trace attribution is best-effort. Async call chains, `setTimeout`-deferred work, and some bundlers can obscure or omit the calling extension's frame, in which case the event is logged as "(unattributed)" and policies are **not enforced** against it (fail-open, by design, to avoid randomly breaking unrelated extensions).
- The risk scores in the "Extension Risk Scan" tab are static heuristics based on the extension's manifest (activation events, contributed debuggers/terminals, command count, etc.). They are a prioritization signal, not a verdict — treat a high score as "worth watching," not "malicious."

In short: ExtShield is a **monitoring and best-effort policy tool**, not a real sandbox. Treat it the way you'd treat a network monitor or an audit log — great for visibility and catching sloppy or obviously bad behavior, not a guarantee against a determined, sophisticated attacker.

## Features

- **Activity dashboard** (`ExtShield: Open Activity Dashboard`) — live table of file reads/writes/deletes, directory listings, HTTP(S) requests, and spawned processes, each tagged with the attributed extension and a risk level, plus filtering and a per-run summary.
- **Secret-access detection** — flags reads of files that look like secrets (`.env`, `id_rsa`, `credentials.json`, `.npmrc`, PEM/key files, etc.) and scans small text file contents for patterns like AWS access keys, GitHub/Slack tokens, JWTs, and PEM private-key headers. You get a warning notification with quick actions to open the dashboard or set a policy.
- **Per-extension access policy** (`ExtShield: Set Access Policy for an Extension`) — restrict an extension to one or more allowed path prefixes (e.g. only `/…/project/src`), and optionally block its network access or process spawning outright. Enable `extshield.blockOnPolicyViolation` in settings to actually enforce these (off by default, since enforcement can break an otherwise-legitimate extension if attribution or your path list is off).
- **Extension risk scan** (`ExtShield: Scan Installed Extensions for Risk`) — static manifest-based heuristic scoring of every installed extension, shown in the dashboard's "Extension Risk Scan" tab.
- **Activity log export** — dump the current session's event log as JSON for offline review.
- **Status bar indicator** showing event count and high-risk count at a glance; click it to open the dashboard.

## Settings

| Setting | Default | Description |
|---|---|---|
| `extshield.enabled` | `true` | Master on/off switch for monitoring. |
| `extshield.blockOnPolicyViolation` | `false` | Attempt to block calls that violate a configured policy (best-effort — see limitations above). |
| `extshield.monitorEnvAccess` | `false` | Experimental: wrap `process.env` in a Proxy to log which extension reads which environment variable names. Off by default since it touches a very hot, widely-used object. |
| `extshield.logRetentionEntries` | `2000` | Max in-memory activity log entries. |
| `extshield.notifyOnSecretAccess` | `true` | Pop a warning notification when a sensitive file/content pattern is detected. |

## Commands

- `ExtShield: Open Activity Dashboard`
- `ExtShield: Scan Installed Extensions for Risk`
- `ExtShield: Set Access Policy for an Extension`
- `ExtShield: Toggle Monitoring On/Off`
- `ExtShield: Clear Activity Log`
- `ExtShield: Export Activity Log as JSON`

## Building and running locally

```bash
npm install
npm run compile
```

Then press **F5** in VS Code (with this folder open) to launch an Extension Development Host with ExtShield active. Install a few other extensions in that dev host and watch the dashboard populate as they run.

To package for distribution you'd normally use [`@vscode/vsce`](https://www.npmjs.com/package/@vscode/vsce) (`vsce package`) to produce a `.vsix` — not included here since it requires publisher registration.

## Project layout

```
src/
  extension.ts      activation, commands, status bar, wiring
  monitor.ts         patches fs/http/https/child_process (+ optional env), records events
  attribution.ts     stack-trace -> extension id resolution
  policyManager.ts   per-extension policy storage (VS Code globalState)
  secretDetector.ts  sensitive-path and secret-content pattern matching
  scanner.ts          static manifest-based risk scoring of installed extensions
  dashboardPanel.ts   webview UI (activity log + risk scan tabs)
  types.ts            shared TypeScript interfaces
```

## Suggested next steps if you want to harden this further

- Persist the activity log to disk (currently in-memory per session) for historical review.
- Add a "trusted extensions" allowlist so well-known extensions don't need manual policy setup.
- Correlate `net.request` events with the destination's reputation via an external threat-intel feed.
- Explore VS Code's Extension Host isolation options (e.g. running specific extensions out-of-process) where available, rather than relying solely on in-process patching.
