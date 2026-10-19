# dsh-egress-gate

> **If this helps you, please give it a star** — it helps others find it. Thanks!
Deterministic network egress gate for
[DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (dsh).

Content scanning (dsh-read-guard) guards what **enters** the model; this
guards where data may **leave** to. `web_fetch` / `web_search` calls are
checked against a destination allowlist in `tools/pre-execute` and denied
before they run. Shell commands are scanned for fetch-verb URLs —
observation by default, enforcement opt-in, honest about precision. Zero LLM
calls in the trust path.

Family: read · write · do · call · leave-behind · **egress (where data may
flow)**.

## Why now (checked 2026-10-12)

Empty lane. Five keyword searches (`network allowlist`, `egress firewall`,
`url filter`, `web fetch restrict`, …) return nothing on GitHub; the awesome
list has no entry gating destinations. Neighbours are all different axes:
content-pattern secret rules (dsh-defend), LLM-judged commands
(dsh-jev-guard), proxy *configuration* (official network-proxy docs). For
teams, "which hosts may the agent reach" is the first compliance question —
and the deterministic answer was unowned.

## Policy

- Deny always wins; a non-empty `allow` list means "only these hosts"
  (`example.com` covers `api.example.com`; `*.example.com` is the explicit
  form).
- Web tools are enforced at full precision — the URL is in the arguments.
- Shell: URLs following `curl` / `wget` / `Invoke-WebRequest` /
  `Invoke-RestMethod` / `fetch` / `http` on the same command segment. This
  cannot see through scripts, variables, or proxies — so it warns by
  default and denies only when you opt into `shellMode: 'enforce'`.

## Install

```sh
dsh plugin --profile default add github:zhengqiuyang/dsh-egress-gate
```

Prebuilt `lib/` ships in the repo — git installs need no build step and no
`allowBuilds` authorization.

## Configure

```yaml
- id: dsh-egress-gate
  name: dsh-egress-gate
  config:
    webTools: [web_fetch, web_search]
    shellTool: bash            # '' disables the shell scan
    allow: [docs.deepseek.com, github.com]
    deny: [pastebin.example]
    shellMode: observe         # observe | enforce
```

## Compatibility

- **DSH**: verified against the 0.2.x line (source snapshot 0.2.1-alpha.2); installs on any profile via `dsh plugin add` (prebuilt `lib/`, no build approval).
- **Node**: >= 20 (CI matrix: Node 20/22/24 on Ubuntu and Windows).
- **Disposable-profile evidence (2026-10-19)**: `dsh plugin --profile <fresh> add github:zhengqiuyang/dsh-egress-gate` → installed in 30s; boot shows `[dsh-egress-gate] active: …`; `dsh plugin --profile <fresh> remove dsh-egress-gate` → dependencies cleared, bundles restored.

## Develop

```sh
npm install && npm test
```

## Kill criteria

If dsh ships first-party destination policy, or proxy-layer plugins add
per-host rules, this freezes at its last working version with a postmortem
here.
