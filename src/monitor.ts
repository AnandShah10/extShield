import * as fs from 'fs';
import * as http from 'http';
import * as https from 'https';
import * as child_process from 'child_process';
import { attributeCaller, captureStack } from './attribution';
import { isSensitivePath, scanContentForSecrets } from './secretDetector';
import { PolicyManager } from './policyManager';
import { ActivityEvent, EventKind, RiskLevel } from './types';

export interface MonitorConfig {
  blockOnPolicyViolation: boolean;
  monitorEnvAccess: boolean;
  notifyOnSecretAccess: boolean;
}

type Unpatch = () => void;

export class Monitor {
  private idCounter = 1;
  // Session token makes ids unique across activations, not just within one —
  // needed so a delayed threat-intel result can find the right persisted
  // on-disk record even after a reload, without ids from different sessions
  // colliding in the same day's log file.
  private sessionToken = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 7)}`;

  private genId(): string {
    return `${this.sessionToken}-${this.idCounter++}`;
  }
  private unpatchers: Unpatch[] = [];
  private running = false;

  constructor(
    private policyManager: PolicyManager,
    private config: MonitorConfig,
    private onEvent: (evt: ActivityEvent) => void,
    private onSecretHit: (evt: ActivityEvent, matches: string[]) => void,
    private onWarning: (message: string) => void = () => undefined
  ) {}

  isRunning(): boolean {
    return this.running;
  }

  /**
   * Every individual patch attempt is wrapped so that a single built-in
   * behaving unexpectedly can never take down the rest of monitoring — let
   * alone extension activation itself. Failures are reported via onWarning
   * and simply mean that one specific call site goes unwatched.
   */
  private safePatch(label: string, fn: () => Unpatch | void): void {
    try {
      const undo = fn();
      if (undo) {
        this.unpatchers.push(undo);
      }
    } catch (err: any) {
      this.onWarning(`Could not patch ${label}: ${err?.message ?? err}. That call site will not be monitored.`);
    }
  }

  /**
   * Redefines a property via Object.defineProperty rather than plain
   * assignment (`obj[name] = value`). This matters because the real VS Code
   * extension host (unlike a plain Node REPL) exposes some built-ins —
   * observed on `fs.readFile`, and plausibly others — as accessor
   * properties with only a getter and no setter. Plain assignment to such a
   * property throws "Cannot set property X of #<Y> which has only a
   * getter" in strict-mode code (which all compiled TS classes run as).
   * Object.defineProperty sidesteps the missing setter entirely and
   * succeeds as long as the property is configurable — which is true for
   * the common "lazy getter that replaces itself on first read" pattern
   * used internally by Node and, evidently, by VS Code's extension host.
   * If a property genuinely isn't configurable, this throws and safePatch()
   * catches it, skipping just that one call site.
   */
  private definePatch(obj: any, name: string, wrap: (original: Function) => Function): Unpatch {
    const original = obj[name];
    if (typeof original !== 'function') {
      throw new Error(`property is not a function (got ${typeof original})`);
    }
    const bound = original.bind(obj);
    const wrapped = wrap(bound);
    const existingDescriptor = Object.getOwnPropertyDescriptor(obj, name);
    const enumerable = existingDescriptor?.enumerable !== false;

    Object.defineProperty(obj, name, {
      value: wrapped,
      writable: true,
      configurable: true,
      enumerable
    });

    return () => {
      try {
        Object.defineProperty(obj, name, {
          value: original,
          writable: true,
          configurable: true,
          enumerable
        });
      } catch {
        // best-effort restore only
      }
    };
  }

  start(): void {
    if (this.running) {
      return;
    }
    this.running = true;
    try {
      this.patchFs();
    } catch (err: any) {
      this.onWarning(`fs monitoring failed to initialize: ${err?.message ?? err}`);
    }
    try {
      this.patchNetwork();
    } catch (err: any) {
      this.onWarning(`Network monitoring failed to initialize: ${err?.message ?? err}`);
    }
    try {
      this.patchChildProcess();
    } catch (err: any) {
      this.onWarning(`child_process monitoring failed to initialize: ${err?.message ?? err}`);
    }
    if (this.config.monitorEnvAccess) {
      try {
        this.patchEnv();
      } catch (err: any) {
        this.onWarning(`Environment-variable monitoring failed to initialize: ${err?.message ?? err}`);
      }
    }
  }

  stop(): void {
    if (!this.running) {
      return;
    }
    for (const undo of this.unpatchers.reverse()) {
      try {
        undo();
      } catch {
        // best effort restore
      }
    }
    this.unpatchers = [];
    this.running = false;
  }

  private record(
    kind: EventKind,
    target: string,
    risk: RiskLevel,
    blocked: boolean,
    reason?: string
  ): { extensionId: string | null } {
    const { extensionId } = attributeCaller(captureStack());
    const evt: ActivityEvent = {
      id: this.genId(),
      timestamp: Date.now(),
      extensionId,
      kind,
      target,
      risk,
      blocked,
      reason
    };
    this.onEvent(evt);
    return { extensionId };
  }

  // ---------- fs ----------

  private patchFs(): void {
    const targets: Array<[any, string]> = [
      [fs, 'readFile'],
      [fs, 'readFileSync'],
      [fs, 'writeFile'],
      [fs, 'writeFileSync'],
      [fs, 'appendFile'],
      [fs, 'appendFileSync'],
      [fs, 'unlink'],
      [fs, 'unlinkSync'],
      [fs, 'readdir'],
      [fs, 'readdirSync']
    ];

    for (const [obj, name] of targets) {
      this.safePatch(`fs.${name}`, () =>
        this.definePatch(obj, name, (original) => (...args: any[]) => this.wrapFsCall(name, original, args))
      );
    }

    // fs.promises has its own copies of these functions.
    const fsp: any = fs.promises;
    const asyncTargets = ['readFile', 'writeFile', 'appendFile', 'unlink', 'readdir'];
    for (const name of asyncTargets) {
      this.safePatch(`fs.promises.${name}`, () =>
        this.definePatch(fsp, name, (original) => (...args: any[]) => this.wrapFsPromiseCall(name, original, args))
      );
    }
  }

  private classifyFsOp(name: string): { kind: EventKind; verb: 'read' | 'write' | 'delete' | 'list' } {
    if (name.startsWith('read') && name !== 'readdir' && !name.startsWith('readdirSync')) {
      return { kind: 'fs.read', verb: 'read' };
    }
    if (name.startsWith('readdir')) {
      return { kind: 'fs.readdir', verb: 'list' };
    }
    if (name.startsWith('write') || name.startsWith('append')) {
      return { kind: 'fs.write', verb: 'write' };
    }
    return { kind: 'fs.delete', verb: 'delete' };
  }

  private wrapFsCall(name: string, original: Function, args: any[]) {
    const filePath = typeof args[0] === 'string' ? args[0] : String(args[0]);
    const { kind, verb } = this.classifyFsOp(name);
    const isAsyncCallback = typeof args[args.length - 1] === 'function' && !name.endsWith('Sync');

    const sensitive = isSensitivePath(filePath);
    const risk: RiskLevel = sensitive ? 'high' : verb === 'delete' ? 'medium' : 'low';

    const { extensionId } = attributeCaller(captureStack());
    const pathAllowed = this.policyManager.isPathAllowed(extensionId, filePath);
    const shouldBlock = this.config.blockOnPolicyViolation && !pathAllowed;

    const evt: ActivityEvent = {
      id: this.genId(),
      timestamp: Date.now(),
      extensionId,
      kind,
      target: filePath,
      risk: shouldBlock ? 'high' : risk,
      blocked: shouldBlock,
      reason: shouldBlock ? 'Blocked: path outside allowed policy' : sensitive ? 'Sensitive file path' : undefined
    };
    this.onEvent(evt);

    if (shouldBlock) {
      const err = Object.assign(new Error(`EXTSHIELD_BLOCKED: policy denies access to ${filePath}`), {
        code: 'EACCES'
      });
      if (isAsyncCallback) {
        const cb = args[args.length - 1];
        setImmediate(() => cb(err));
        return undefined;
      }
      throw err;
    }

    const result = original(...args);

    if (sensitive && this.config.notifyOnSecretAccess && verb === 'read') {
      this.onSecretHit(evt, ['sensitive-path']);
    }

    // Best-effort content scan for sync reads of small text files.
    if (verb === 'read' && name === 'readFileSync' && typeof result === 'string') {
      const hits = scanContentForSecrets(result);
      if (hits.length > 0 && this.config.notifyOnSecretAccess) {
        this.onSecretHit(evt, hits);
      }
    }

    return result;
  }

  private async wrapFsPromiseCall(name: string, original: Function, args: any[]) {
    const filePath = typeof args[0] === 'string' ? args[0] : String(args[0]);
    const { kind, verb } = this.classifyFsOp(name);
    const sensitive = isSensitivePath(filePath);
    const risk: RiskLevel = sensitive ? 'high' : verb === 'delete' ? 'medium' : 'low';

    const { extensionId } = attributeCaller(captureStack());
    const pathAllowed = this.policyManager.isPathAllowed(extensionId, filePath);
    const shouldBlock = this.config.blockOnPolicyViolation && !pathAllowed;

    const evt: ActivityEvent = {
      id: this.genId(),
      timestamp: Date.now(),
      extensionId,
      kind,
      target: filePath,
      risk: shouldBlock ? 'high' : risk,
      blocked: shouldBlock,
      reason: shouldBlock ? 'Blocked: path outside allowed policy' : sensitive ? 'Sensitive file path' : undefined
    };
    this.onEvent(evt);

    if (shouldBlock) {
      const err = Object.assign(new Error(`EXTSHIELD_BLOCKED: policy denies access to ${filePath}`), {
        code: 'EACCES'
      });
      throw err;
    }

    const result = await original(...args);

    if (sensitive && this.config.notifyOnSecretAccess && verb === 'read') {
      this.onSecretHit(evt, ['sensitive-path']);
    }
    if (verb === 'read' && typeof result === 'string') {
      const hits = scanContentForSecrets(result);
      if (hits.length > 0 && this.config.notifyOnSecretAccess) {
        this.onSecretHit(evt, hits);
      }
    }

    return result;
  }

  // ---------- network ----------

  private patchNetwork(): void {
    for (const mod of [http, https]) {
      const label = mod === http ? 'http' : 'https';
      this.safePatch(`${label}.request`, () =>
        this.definePatch(mod, 'request', (original) => (...args: any[]) => this.wrapNetCall(original, args))
      );
      this.safePatch(`${label}.get`, () =>
        this.definePatch(mod, 'get', (original) => (...args: any[]) => this.wrapNetCall(original, args))
      );
    }
  }

  private extractHost(args: any[]): string {
    const first = args[0];
    if (typeof first === 'string') {
      try {
        return new URL(first).host;
      } catch {
        return first;
      }
    }
    if (first instanceof URL) {
      return first.host;
    }
    if (first && typeof first === 'object') {
      const opts = first as http.RequestOptions;
      return `${opts.hostname || opts.host || 'unknown-host'}${opts.port ? ':' + opts.port : ''}`;
    }
    return 'unknown-host';
  }

  private wrapNetCall(original: Function, args: any[]) {
    const host = this.extractHost(args);
    const { extensionId } = attributeCaller(captureStack());
    const allowed = this.policyManager.isNetworkAllowed(extensionId);
    const shouldBlock = this.config.blockOnPolicyViolation && !allowed;

    const evt: ActivityEvent = {
      id: this.genId(),
      timestamp: Date.now(),
      extensionId,
      kind: 'net.request',
      target: host,
      risk: 'medium',
      blocked: shouldBlock,
      reason: shouldBlock ? 'Blocked: network access denied by policy' : undefined
    };
    this.onEvent(evt);

    if (shouldBlock) {
      throw Object.assign(new Error(`EXTSHIELD_BLOCKED: policy denies network access to ${host}`), {
        code: 'ECONNREFUSED'
      });
    }

    return original(...args);
  }

  // ---------- child_process ----------

  private patchChildProcess(): void {
    const targets: Array<keyof typeof child_process> = ['exec', 'execFile', 'spawn'];
    for (const name of targets) {
      this.safePatch(`child_process.${String(name)}`, () =>
        this.definePatch(
          child_process,
          name as string,
          (original) => (...args: any[]) => this.wrapChildProcessCall(String(name), original, args)
        )
      );
    }
  }

  private wrapChildProcessCall(name: string, original: Function, args: any[]) {
    const command = typeof args[0] === 'string' ? args[0] : Array.isArray(args[0]) ? args[0].join(' ') : String(args[0]);
    const { extensionId } = attributeCaller(captureStack());
    const allowed = this.policyManager.isChildProcessAllowed(extensionId);
    const shouldBlock = this.config.blockOnPolicyViolation && !allowed;

    const evt: ActivityEvent = {
      id: this.genId(),
      timestamp: Date.now(),
      extensionId,
      kind: 'child.exec',
      target: `${name}: ${command}`,
      risk: 'high',
      blocked: shouldBlock,
      reason: shouldBlock ? 'Blocked: process spawning denied by policy' : 'Process spawn always flagged high-risk'
    };
    this.onEvent(evt);

    if (shouldBlock) {
      throw Object.assign(new Error(`EXTSHIELD_BLOCKED: policy denies spawning processes (${command})`), {
        code: 'EACCES'
      });
    }

    return original(...args);
  }

  // ---------- env (experimental, opt-in) ----------

  private patchEnv(): void {
    this.safePatch('process.env', () => {
      const original = process.env;
      const seen = new Set<string>();
      const proxied = new Proxy(original, {
        get: (target, prop: string) => {
          if (typeof prop === 'string' && !seen.has(prop)) {
            seen.add(prop);
            const { extensionId } = attributeCaller(captureStack());
            const looksSecret = /key|secret|token|password|credential/i.test(prop);
            this.onEvent({
              id: this.genId(),
              timestamp: Date.now(),
              extensionId,
              kind: 'env.read',
              target: prop,
              risk: looksSecret ? 'high' : 'low',
              blocked: false,
              reason: looksSecret ? 'Env var name suggests a secret' : undefined
            });
          }
          return (target as any)[prop];
        }
      });

      // process.env is a value, not a function, so definePatch() (which
      // wraps functions) doesn't apply — but the same underlying problem
      // and fix apply: plain `process.env = proxied` throws if the real
      // property is a getter-only accessor, while Object.defineProperty
      // succeeds as long as it's configurable.
      const existingDescriptor = Object.getOwnPropertyDescriptor(process, 'env');
      Object.defineProperty(process, 'env', {
        value: proxied,
        writable: true,
        configurable: true,
        enumerable: existingDescriptor?.enumerable !== false
      });

      return () => {
        try {
          Object.defineProperty(process, 'env', {
            value: original,
            writable: true,
            configurable: true,
            enumerable: existingDescriptor?.enumerable !== false
          });
        } catch {
          // best-effort restore only
        }
      };
    });
  }
}
