/**
 * dsh-egress-gate — deterministic network egress gate for DeepSeek Harness.
 *
 * Content scanning (dsh-read-guard) guards what enters the model; this guards
 * where data may leave to. `web_fetch` / `web_search` calls are checked
 * against a destination allowlist in `tools/pre-execute` and denied before
 * they run. Shell commands are scanned for fetch-verb URLs — observation by
 * default, honest about precision, enforcement opt-in.
 *
 * Family: read (what agents read) · write · do · call · leave-behind ·
 * **egress (where data may flow)**.
 */
import type { Context } from '@deepseek-ai/cordis';
import Schema from '@deepseek-ai/schemastery';
import {
  checkUrls,
  summarizeVerdicts,
  urlsFromShellCommand,
  urlsFromWebArgs,
  type EgressPolicy,
} from './policy.js';

export const name = 'dsh-egress-gate';

export interface Config {
  /** Web tools gated at full precision (deny before the call runs). */
  webTools: string[];
  /** Shell tool scanned for fetch-verb URLs. */
  shellTool: string;
  /** Host allowlist; non-empty means "only these" (suffix match). */
  allow: string[];
  /** Host denylist; always wins. */
  deny: string[];
  /** Shell findings: observe (warn) or enforce (deny the whole command). */
  shellMode: 'observe' | 'enforce';
}

export const Config: Schema<Config> = Schema.object({
  webTools: Schema.array(Schema.string()).default(['web_fetch', 'web_search']).description('web tools gated at full precision'),
  shellTool: Schema.string().default('bash').description("shell tool scanned for fetch-verb URLs; empty string disables the shell scan"),
  allow: Schema.array(Schema.string()).default([]).description('host allowlist; non-empty means only these (suffix match)'),
  deny: Schema.array(Schema.string()).default([]).description('host denylist; always wins'),
  shellMode: Schema.union(['observe', 'enforce']).default('observe').description('shell URL findings: warn or deny'),
});

// Harness surface restated so the plugin typechecks standalone; identical
// declarations merge cleanly inside the source checkout.
interface ToolExecView {
  readonly name: string;
  readonly arguments: unknown;
  readonly agent?: unknown;
}

type PreToolDecisionView =
  | { kind: 'allow' }
  | { kind: 'deny'; reason: string; info?: { name: string; code: string } };

declare module '@deepseek-ai/cordis' {
  interface Events {
    'tools/pre-execute': (
      exec: ToolExecView,
      next: () => Promise<PreToolDecisionView>,
    ) => Promise<PreToolDecisionView>;
  }
}

function firstString(args: unknown, keys: readonly string[]): string | undefined {
  if (typeof args !== 'object' || args === null) return undefined;
  const record = args as Record<string, unknown>;
  for (const key of keys) {
    if (typeof record[key] === 'string') return record[key] as string;
  }
  return undefined;
}

export function apply(ctx: Context, config: Config) {
  const webTools = new Set(config.webTools);
  const policy: EgressPolicy = {
    ...(config.allow.length > 0 ? { allow: config.allow } : {}),
    ...(config.deny.length > 0 ? { deny: config.deny } : {}),
  };
  console.log(
    `[dsh-egress-gate] active: web gate on [${[...webTools].join(', ')}], ` +
      `shell=${config.shellTool}:${config.shellMode}, allow=${config.allow.length} deny=${config.deny.length} pattern(s)`,
  );

  ctx.on('tools/pre-execute', async (exec, next) => {
    if (webTools.has(exec.name)) {
      const verdicts = checkUrls(urlsFromWebArgs(exec.arguments), policy);
      const denied = verdicts.filter((v) => v.action === 'deny');
      if (denied.length > 0) {
        const summary = summarizeVerdicts(verdicts);
        console.warn(`[dsh-egress-gate] denied ${exec.name}: ${summary}`);
        return {
          kind: 'deny',
          reason: `dsh-egress-gate: destination not allowed (${summary}). The session's egress policy does not cover this host.`,
          info: { name: 'dsh-egress-gate', code: 'EGRESS_DENIED' },
        };
      }
      return next();
    }
    if (config.shellTool !== '' && exec.name === config.shellTool) {
      const command = firstString(exec.arguments, ['command', 'cmd', 'script']);
      if (command === undefined) return next();
      const verdicts = checkUrls(urlsFromShellCommand(command), policy);
      const denied = verdicts.filter((v) => v.action === 'deny');
      if (denied.length > 0) {
        const summary = summarizeVerdicts(verdicts);
        if (config.shellMode === 'enforce') {
          console.warn(`[dsh-egress-gate] denied ${exec.name}: ${summary}`);
          return {
            kind: 'deny',
            reason: `dsh-egress-gate: command fetches a denied destination (${summary}).`,
            info: { name: 'dsh-egress-gate', code: 'EGRESS_DENIED' },
          };
        }
        console.warn(
          `[dsh-egress-gate] ${exec.name} would fetch a denied destination (${summary}) — ` +
            `observed only; set shellMode: 'enforce' to deny.`,
        );
      }
      return next();
    }
    return next();
  });
}
