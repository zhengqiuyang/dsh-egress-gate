/**
 * Pure egress policy: which URLs is this session allowed to reach?
 * Deny always wins; a non-empty allow list means "only these hosts" (exact
 * or suffix match — `example.com` covers `api.example.com`).
 */

export interface EgressPolicy {
  allow?: string[];
  deny?: string[];
}

export type UrlVerdict =
  | { url: string; host: string; action: 'allow' }
  | { url: string; host: string; action: 'deny'; matchedBy: string };

const URL_RE = /https?:\/\/[^\s<>"'`)\]}]+/gi;
/** Fetch/call verbs inside shell commands whose following URLs we gate. */
const SHELL_FETCH_RE =
  /\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|fetch|http)\b[^\n;|&]*?(https?:\/\/[^\s<>"'`)\]}]+)/gi;

function hostOf(rawUrl: string): string | null {
  try {
    return new URL(rawUrl).hostname.toLowerCase().replace(/\.$/, '');
  } catch {
    return null;
  }
}

function hostMatches(host: string, pattern: string): boolean {
  const p = pattern.toLowerCase().replace(/\.$/, '');
  if (p === host) return true;
  // `example.com` covers subdomains; `*.example.com` is the explicit form.
  if (p.startsWith('*.')) {
    const base = p.slice(2);
    return host === base || host.endsWith('.' + base);
  }
  return host.endsWith('.' + p);
}

export function checkUrl(rawUrl: string, policy: EgressPolicy): UrlVerdict {
  const host = hostOf(rawUrl);
  if (host === null) {
    return { url: rawUrl, host: '(unparseable)', action: 'allow' };
  }
  for (const p of policy.deny ?? []) {
    if (hostMatches(host, p)) {
      return { url: rawUrl, host, action: 'deny', matchedBy: `deny:${p}` };
    }
  }
  if ((policy.allow ?? []).length > 0) {
    for (const p of policy.allow ?? []) {
      if (hostMatches(host, p)) {
        return { url: rawUrl, host, action: 'allow' };
      }
    }
    return { url: rawUrl, host, action: 'deny', matchedBy: 'allowlist' };
  }
  return { url: rawUrl, host, action: 'allow' };
}

export function checkUrls(urls: readonly string[], policy: EgressPolicy): UrlVerdict[] {
  return urls.map((u) => checkUrl(u, policy));
}

/** URLs a web tool intends to reach, from its arguments. */
export function urlsFromWebArgs(args: unknown): string[] {
  if (typeof args !== 'object' || args === null) return [];
  const record = args as Record<string, unknown>;
  const urls: string[] = [];
  if (typeof record.url === 'string') urls.push(record.url);
  if (typeof record.search === 'string') {
    // A search query itself can carry a URL someone wants fetched.
    for (const m of record.search.matchAll(URL_RE)) urls.push(m[0]);
  }
  return urls;
}

/**
 * URLs a shell command would fetch. Honest about precision: this extracts
 * URLs that follow fetch verbs on the same command segment — it cannot see
 * through scripts, variables, or proxies.
 */
export function urlsFromShellCommand(command: string): string[] {
  const urls: string[] = [];
  for (const m of command.matchAll(SHELL_FETCH_RE)) urls.push(m[1] ?? '');
  return urls.filter((u) => u.length > 0);
}

export function summarizeVerdicts(verdicts: readonly UrlVerdict[]): string {
  const denied = verdicts.filter((v) => v.action === 'deny');
  if (denied.length === 0) return 'egress ok';
  return denied.map((v) => `${v.host} (${v.matchedBy})`).join(', ');
}
