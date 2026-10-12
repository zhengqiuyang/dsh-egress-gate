/**
 * Unit tests for the pure egress policy — no DSH host needed.
 */
import assert from 'node:assert/strict';
import {
  checkUrl,
  checkUrls,
  urlsFromShellCommand,
  urlsFromWebArgs,
  summarizeVerdicts,
} from '../lib/policy.js';

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  ok  ${name}`);
  } catch (err) {
    failed++;
    console.error(`FAIL  ${name}`);
    console.error(err.message);
  }
}

console.log('host matching');

await test('exact host matches; suffix covers subdomains', () => {
  assert.equal(checkUrl('https://example.com/x', { allow: ['example.com'] }).action, 'allow');
  assert.equal(checkUrl('https://api.example.com/x', { allow: ['example.com'] }).action, 'allow');
  assert.equal(checkUrl('https://notexample.com/x', { allow: ['example.com'] }).action, 'deny');
});

await test('deny always wins over allow', () => {
  const v = checkUrl('https://evil.example.com/x', { allow: ['example.com'], deny: ['evil.example.com'] });
  assert.equal(v.action, 'deny');
  assert.equal(v.matchedBy, 'deny:evil.example.com');
});

await test('wildcard form matches subdomains only', () => {
  assert.equal(checkUrl('https://a.example.com/x', { allow: ['*.example.com'] }).action, 'allow');
  assert.equal(checkUrl('https://example.com/x', { allow: ['*.example.com'] }).action, 'allow');
  assert.equal(checkUrl('https://example.org/x', { allow: ['*.example.com'] }).action, 'deny');
});

await test('empty policy allows everything', () => {
  assert.equal(checkUrl('https://anywhere.net/x', {}).action, 'allow');
});

await test('unparseable url passes through as allow', () => {
  assert.equal(checkUrl('not a url', {}).action, 'allow');
});

console.log('url extraction');

await test('web_fetch args url extracted', () => {
  assert.deepEqual(urlsFromWebArgs({ url: 'https://x.example.com/a' }), ['https://x.example.com/a']);
});

await test('web_search query with embedded url extracted', () => {
  const urls = urlsFromWebArgs({ search: 'see https://docs.example.com/guide for details' });
  assert.equal(urls.length, 1);
  assert.ok(urls[0].startsWith('https://docs.example.com'));
});

await test('shell fetch verbs extracted, unrelated urls not', () => {
  const cmd = 'curl -s https://api.example.com/ping && echo done && cat README.md';
  const urls = urlsFromShellCommand(cmd);
  assert.equal(urls.length, 1);
  assert.equal(urls[0], 'https://api.example.com/ping');
});

await test('powershell invoke-webrequest extracted', () => {
  const urls = urlsFromShellCommand('Invoke-WebRequest -Uri https://collector.example.com/x -Method POST');
  assert.equal(urls.length, 1);
  assert.ok(urls[0].includes('collector.example.com'));
});

await test('plain echo with url is not a fetch', () => {
  assert.equal(urlsFromShellCommand('echo "see https://example.com"').length, 0);
});

console.log('decisions');

await test('checkUrls flags only denied hosts', () => {
  const verdicts = checkUrls(
    ['https://ok.example.com/a', 'https://bad.example.org/b'],
    { allow: ['example.com'] },
  );
  assert.equal(verdicts[0].action, 'allow');
  assert.equal(verdicts[1].action, 'deny');
  assert.equal(verdicts[1].matchedBy, 'allowlist');
});

await test('summary names denied hosts', () => {
  const s = summarizeVerdicts(checkUrls(['https://a.bad.io/x'], { deny: ['bad.io'] }));
  assert.ok(s.includes('a.bad.io') || s.includes('bad.io'));
  assert.ok(s.includes('deny:bad.io'));
});

console.log('');
console.log(`${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
