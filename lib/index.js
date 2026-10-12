import Schema from '@deepseek-ai/schemastery';
import { checkUrls, summarizeVerdicts, urlsFromShellCommand, urlsFromWebArgs, } from './policy.js';
export const name = 'dsh-egress-gate';
export const Config = Schema.object({
    webTools: Schema.array(Schema.string()).default(['web_fetch', 'web_search']).description('web tools gated at full precision'),
    shellTool: Schema.string().default('bash').description("shell tool scanned for fetch-verb URLs; empty string disables the shell scan"),
    allow: Schema.array(Schema.string()).default([]).description('host allowlist; non-empty means only these (suffix match)'),
    deny: Schema.array(Schema.string()).default([]).description('host denylist; always wins'),
    shellMode: Schema.union(['observe', 'enforce']).default('observe').description('shell URL findings: warn or deny'),
});
function firstString(args, keys) {
    if (typeof args !== 'object' || args === null)
        return undefined;
    const record = args;
    for (const key of keys) {
        if (typeof record[key] === 'string')
            return record[key];
    }
    return undefined;
}
export function apply(ctx, config) {
    const webTools = new Set(config.webTools);
    const policy = {
        ...(config.allow.length > 0 ? { allow: config.allow } : {}),
        ...(config.deny.length > 0 ? { deny: config.deny } : {}),
    };
    console.log(`[dsh-egress-gate] active: web gate on [${[...webTools].join(', ')}], ` +
        `shell=${config.shellTool}:${config.shellMode}, allow=${config.allow.length} deny=${config.deny.length} pattern(s)`);
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
            if (command === undefined)
                return next();
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
                console.warn(`[dsh-egress-gate] ${exec.name} would fetch a denied destination (${summary}) — ` +
                    `observed only; set shellMode: 'enforce' to deny.`);
            }
            return next();
        }
        return next();
    });
}
