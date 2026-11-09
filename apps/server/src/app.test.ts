import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildApp } from './app.ts';

test('GET /api/v1/health returns ok', async () => {
  const app = buildApp();
  const res = await app.inject({ method: 'GET', url: '/api/v1/health' });
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.json(), { status: 'ok' });
  await app.close();
});

test('logs never contain headers, query strings or bodies', async () => {
  let out = '';
  const app = buildApp({ write: (s: string) => void (out += s) });
  await app.inject({
    method: 'POST',
    url: '/api/v1/health?token=SECRET-QUERY',
    headers: { authorization: 'Bearer SECRET-HEADER', cookie: 'sid=SECRET-COOKIE' },
    payload: { password: 'SECRET-BODY' },
  });
  await app.close();
  assert.ok(out.includes('/api/v1/health'), 'request was logged');
  for (const s of ['SECRET-QUERY', 'SECRET-HEADER', 'SECRET-COOKIE', 'SECRET-BODY']) {
    assert.ok(!out.includes(s), `${s} must not be logged`);
  }
});

test('request bodies over the default limit are rejected', async () => {
  const app = buildApp();
  const res = await app.inject({
    method: 'POST',
    url: '/api/v1/health',
    payload: { x: 'a'.repeat(20 * 1024) },
  });
  assert.equal(res.statusCode, 413);
  await app.close();
});
