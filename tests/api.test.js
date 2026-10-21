const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { env, TENANT, ORG, USER, mintToken, startEnv, startMockCrm, SCHEMA } = require('./helpers');
const { runOnce } = require('../src/worker');

let t;
before(async () => { t = await startEnv(); });
after(async () => { await t.stop(); });

const lead = (over = {}) => ({
  formVersion: '1',
  fields: { full_name: 'Asha Sharma', email: 'Asha@Example.com', message: 'Please contact me', ...over.fields },
  consent: { accepted: true, policyVersion: 'privacy-v1' }, ...over.rest,
});
let n = 0;
async function publishedForm(extra = {}) {
  const r = await t.request('POST', '/api/v1/forms', { body: { name: `Form ${Date.now()}-${n++}`, websiteId: '77', schema: SCHEMA, ...extra } });
  assert.equal(r.status, 200, r.text);
  const p = await t.request('POST', `/api/v1/forms/${r.json.data.id}/publish`);
  assert.equal(p.status, 200, p.text);
  return p.json.data;
}
const submit = (key, body, headers) => t.request('POST', `/api/v1/public/forms/${key}/submissions`, { body, headers: { Authorization: null, 'X-Tenant-Id': null, 'X-Organization-Id': null, ...headers } });
const worker = (extra = {}) => runOnce(t.pool, { maxAttempts: 3, baseDelayMs: 10, ...extra });
const due = (id) => t.pool.query(`UPDATE crm_delivery_jobs SET next_attempt_at = now() WHERE submission_id = $1`, [id]);

describe('authentication', () => {
  test('missing token -> 401', async () => assert.equal((await t.request('GET', '/api/v1/forms', { headers: { Authorization: null } })).status, 401));
  test('malformed scheme -> 401', async () => assert.equal((await t.request('GET', '/api/v1/forms', { headers: { Authorization: 'Basic abc' } })).status, 401));
  test('garbage token -> 401', async () => assert.equal((await t.request('GET', '/api/v1/forms', { headers: { Authorization: 'Bearer not.a.jwt' } })).status, 401));
  test('wrong signature -> 401', async () => {
    const tok = mintToken({}, { secret: 'another-secret-another-secret-1' });
    assert.equal((await t.request('GET', '/api/v1/forms', { headers: { Authorization: `Bearer ${tok}` } })).status, 401);
  });
  test('expired token -> 401', async () => {
    const tok = mintToken({}, { opts: { expiresIn: '-1h' } });
    assert.equal((await t.request('GET', '/api/v1/forms', { headers: { Authorization: `Bearer ${tok}` } })).status, 401);
  });
  test('wrong audience -> 401', async () => {
    const tok = mintToken({}, { opts: { audience: 'other' } });
    assert.equal((await t.request('GET', '/api/v1/forms', { headers: { Authorization: `Bearer ${tok}` } })).status, 401);
  });
  test('alg=none token -> 401', async () => {
    const b = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const tok = `${b({ alg: 'none', typ: 'JWT' })}.${b({ sub: USER, tenant_id: TENANT, organization_ids: [ORG], permissions: ['*'], iss: 'triostack-identity', aud: 'lead-capture-api', exp: 9999999999 })}.`;
    assert.equal((await t.request('GET', '/api/v1/forms', { headers: { Authorization: `Bearer ${tok}` } })).status, 401);
  });
  test('token without identity claims -> 401', async () => {
    const tok = mintToken({ tenant_id: undefined });
    assert.equal((await t.request('GET', '/api/v1/forms', { headers: { Authorization: `Bearer ${tok}` } })).status, 401);
  });
  test('auto-assigned token + headers work with no manual headers', async () => {
    const r = await t.request('GET', '/api/v1/forms', { headers: { Authorization: undefined, 'X-Tenant-Id': undefined, 'X-Organization-Id': undefined } });
    assert.equal(r.status, 200);
  });
  test('org header omitted: auto-assigned from the single org claim', async () => {
    const r = await t.request('GET', '/api/v1/forms', { headers: { 'X-Organization-Id': null, 'X-Tenant-Id': null } });
    assert.equal(r.status, 200);
  });
  test('multi-org token without org header -> 400', async () => {
    const claims = { organization_ids: [ORG, '555'] };
    const r = await t.request('GET', '/api/v1/forms', { claims, headers: { 'X-Organization-Id': null } });
    assert.equal(r.status, 400);
  });
  test('multi-org token with a valid org header -> 200', async () => {
    const claims = { organization_ids: [ORG, '555'] };
    assert.equal((await t.request('GET', '/api/v1/forms', { claims, headers: { 'X-Organization-Id': '555' } })).status, 200);
  });
  test('org header not in claims -> 403', async () => assert.equal((await t.request('GET', '/api/v1/forms', { headers: { 'X-Organization-Id': '424242' } })).status, 403));
  test('tenant header not matching claims -> 403', async () => assert.equal((await t.request('GET', '/api/v1/forms', { headers: { 'X-Tenant-Id': '424242' } })).status, 403));
  test('valid token without permission -> 403', async () => {
    const claims = { permissions: ['forms.read'] };
    assert.equal((await t.request('POST', '/api/v1/forms', { claims, body: { name: 'x', websiteId: '1' } })).status, 403);
    assert.equal((await t.request('GET', '/api/v1/forms', { claims })).status, 200);
  });
  test('spoofed X-User-Id is ignored', async () => {
    const r = await t.request('POST', '/api/v1/forms', { headers: { 'X-User-Id': '666' }, body: { name: `spoof-${Date.now()}`, websiteId: '1' } });
    assert.equal(r.status, 200);
    assert.equal(r.json.data.createdByUserId, USER);
  });
  test('request id is echoed; invalid ones replaced', async () => {
    const a = await t.request('GET', '/health/live', { headers: { 'X-Request-Id': 'abc-123' } });
    assert.equal(a.headers.get('x-request-id'), 'abc-123');
    const b = await t.request('GET', '/health/live', { headers: { 'X-Request-Id': 'bad id!!' } });
    assert.match(b.headers.get('x-request-id'), /^req_/);
  });
});

describe('BIGINT safety', () => {
  test('IDs are decimal strings and big tenant ids round-trip exactly', async () => {
    const r = await t.request('POST', '/api/v1/forms', { body: { name: `big-${Date.now()}`, websiteId: '9223372036854775807' } });
    assert.equal(r.status, 200);
    const d = r.json.data;
    for (const k of ['id', 'tenantId', 'organizationId', 'websiteId', 'createdByUserId']) assert.equal(typeof d[k], 'string', k);
    assert.equal(d.tenantId, TENANT);
    assert.equal(d.websiteId, '9223372036854775807');
    assert.match(r.text, /"tenantId":"9223372036854775000"/); // never a JS number
  });
  test('websiteId above int64 or as a Number is rejected', async () => {
    assert.equal((await t.request('POST', '/api/v1/forms', { body: { name: 'a', websiteId: '9223372036854775808' } })).status, 422);
    assert.equal((await t.request('POST', '/api/v1/forms', { body: { name: 'a', websiteId: 77 } })).status, 422);
  });
  test('non-numeric path id -> 400', async () => assert.equal((await t.request('GET', '/api/v1/forms/abc')).status, 400));
  test('generated IDs are unique and increasing as BigInt', async () => {
    const { nextId } = require('../src/ids');
    const ids = Array.from({ length: 20000 }, nextId);
    assert.equal(new Set(ids).size, ids.length);
    for (let i = 1; i < ids.length; i++) assert.ok(BigInt(ids[i]) > BigInt(ids[i - 1]));
  });
});

describe('form management', () => {
  test('create, duplicate name -> 409, get, list, patch', async () => {
    const name = `Contact ${Date.now()}`;
    const c = await t.request('POST', '/api/v1/forms', { body: { name, websiteId: '5', allowedOrigins: ['https://site.example'], schema: SCHEMA } });
    assert.equal(c.status, 200);
    assert.equal((await t.request('POST', '/api/v1/forms', { body: { name, websiteId: '5' } })).status, 409);
    const g = await t.request('GET', `/api/v1/forms/${c.json.data.id}`);
    assert.equal(g.json.data.versions.length, 1);
    const l = await t.request('GET', '/api/v1/forms?limit=1');
    assert.equal(l.json.data.length, 1);
    assert.ok(l.json.nextCursor);
    const p = await t.request('PATCH', `/api/v1/forms/${c.json.data.id}`, { body: { name: `${name} v2` } });
    assert.equal(p.json.data.name, `${name} v2`);
  });
  test('validation errors -> 422', async () => {
    assert.equal((await t.request('POST', '/api/v1/forms', { body: {} })).status, 422);
    assert.equal((await t.request('POST', '/api/v1/forms', { body: { name: 'a', websiteId: '1', schema: { fields: [{ name: 'Bad Name', type: 'text' }] } } })).status, 422);
    assert.equal((await t.request('POST', '/api/v1/forms', { body: { name: 'a', websiteId: '1', schema: { fields: [{ name: 'a', type: 'text' }, { name: 'a', type: 'text' }] } } })).status, 422);
    assert.equal((await t.request('POST', '/api/v1/forms', { body: { name: 'a', websiteId: '1', allowedOrigins: ['javascript:alert(1)'] } })).status, 422);
  });
  test('versions increment and are immutable; publish picks version', async () => {
    const f = (await t.request('POST', '/api/v1/forms', { body: { name: `v-${Date.now()}`, websiteId: '1' } })).json.data;
    assert.equal((await t.request('POST', `/api/v1/forms/${f.id}/publish`)).status, 404); // nothing to publish
    const v1 = await t.request('POST', `/api/v1/forms/${f.id}/versions`, { body: { schema: SCHEMA } });
    const v2 = await t.request('POST', `/api/v1/forms/${f.id}/versions`, { body: { schema: { fields: [{ name: 'a', type: 'text' }] } } });
    assert.equal(v1.json.data.version, 1);
    assert.equal(v2.json.data.version, 2);
    const p = await t.request('POST', `/api/v1/forms/${f.id}/publish`, { body: { version: 1 } });
    assert.equal(p.json.data.publishedVersionId, v1.json.data.id);
    assert.equal((await t.request('POST', `/api/v1/forms/${f.id}/publish`, { body: { version: 9 } })).status, 404);
    const [r1, r2] = await Promise.all([1, 2].map(() => t.request('POST', `/api/v1/forms/${f.id}/versions`, { body: { schema: SCHEMA } })));
    assert.deepEqual([r1.status, r2.status], [200, 200]); // concurrent version creation gets distinct numbers
    assert.notEqual(r1.json.data.version, r2.json.data.version);
  });
  test('cross-tenant and cross-org access is blocked (404) and lists are scoped', async () => {
    const f = await publishedForm();
    const other = { tenant_id: '8001', organization_ids: ['8002'] };
    assert.equal((await t.request('GET', `/api/v1/forms/${f.id}`, { claims: other })).status, 404);
    assert.equal((await t.request('PATCH', `/api/v1/forms/${f.id}`, { claims: other, body: { name: 'hack' } })).status, 404);
    assert.equal((await t.request('POST', `/api/v1/forms/${f.id}/unpublish`, { claims: other })).status, 404);
    assert.equal((await t.request('GET', `/api/v1/forms/${f.id}/submissions`, { claims: other })).status, 404);
    assert.equal((await t.request('GET', '/api/v1/forms', { claims: other })).json.data.length, 0);
    const sameTenantOtherOrg = { organization_ids: ['8002'] };
    assert.equal((await t.request('GET', `/api/v1/forms/${f.id}`, { claims: sameTenantOtherOrg })).status, 404);
  });
  test('bad cursor -> 400', async () => assert.equal((await t.request('GET', '/api/v1/forms?cursor=zzz')).status, 400));
});

describe('public intake', () => {
  test('only published forms are public; unpublish hides the form', async () => {
    const f = await publishedForm();
    assert.equal((await t.request('GET', `/api/v1/public/forms/${f.publicKey}`, { headers: { Authorization: null } })).status, 200);
    assert.equal((await submit(f.publicKey, lead())).status, 200);
    await t.request('POST', `/api/v1/forms/${f.id}/unpublish`);
    assert.equal((await submit(f.publicKey, lead({ fields: { full_name: 'Other' } }))).status, 404);
    assert.equal((await t.request('GET', `/api/v1/public/forms/${f.publicKey}`)).status, 404);
    assert.equal((await submit('pk_unknown', lead())).status, 404);
  });
  test('valid submission is stored with server-side tenant/org and normalized values', async () => {
    const f = await publishedForm();
    const r = await submit(f.publicKey, lead());
    assert.equal(r.status, 200);
    assert.equal(r.json.data.duplicate, false);
    const s = await t.request('GET', `/api/v1/submissions/${r.json.data.id}`);
    assert.equal(s.json.data.tenantId, TENANT);
    assert.equal(s.json.data.organizationId, ORG);
    assert.equal(s.json.data.fields.email, 'asha@example.com');
    assert.equal(typeof s.json.data.id, 'string');
  });
  test('client-supplied tenant/org/user/crm fields are rejected, not trusted', async () => {
    const f = await publishedForm();
    const r = await submit(f.publicKey, lead({ fields: { tenant_id: '1', organization_id: '2', user_id: '3', crm_owner: 'x' } }));
    assert.equal(r.status, 422);
    assert.ok(r.json.error.details.tenant_id);
  });
  test('removes duplicates: identical content is stored once', async () => {
    const f = await publishedForm();
    const a = await submit(f.publicKey, lead());
    const b = await submit(f.publicKey, lead({ fields: { email: ' ASHA@example.com ' } })); // normalizes to same content
    assert.equal(a.status, 200);
    assert.equal(b.status, 200);
    assert.equal(b.json.data.duplicate, true);
    assert.equal(b.json.data.id, a.json.data.id);
    const rows = await t.pool.query('SELECT count(*)::int AS n FROM lead_capture_submissions WHERE form_id=$1', [f.id]);
    assert.equal(rows.rows[0].n, 1);
    const jobs = await t.pool.query('SELECT count(*)::int AS n FROM crm_delivery_jobs WHERE tenant_id=$1 AND submission_id=$2', [TENANT, a.json.data.id]);
    assert.equal(jobs.rows[0].n, 1);
  });
  test('Idempotency-Key dedupes retries even if content differs; different key is new', async () => {
    const f = await publishedForm();
    const a = await submit(f.publicKey, lead(), { 'Idempotency-Key': 'key-1' });
    const b = await submit(f.publicKey, lead({ fields: { message: 'changed' } }), { 'Idempotency-Key': 'key-1' });
    const c = await submit(f.publicKey, lead({ fields: { message: 'changed' } }), { 'Idempotency-Key': 'key-2' });
    assert.equal(b.json.data.id, a.json.data.id);
    assert.notEqual(c.json.data.id, a.json.data.id);
    assert.equal((await submit(f.publicKey, lead(), { 'Idempotency-Key': 'bad key with spaces' })).status, 400);
  });
  test('concurrent identical submissions create exactly one row', async () => {
    const f = await publishedForm();
    const rs = await Promise.all(Array.from({ length: 8 }, () => submit(f.publicKey, lead())));
    assert.equal(rs.filter((r) => r.json.data.duplicate === false).length, 1);
    assert.equal(new Set(rs.map((r) => r.json.data.id)).size, 1);
    const rows = await t.pool.query('SELECT count(*)::int AS n FROM lead_capture_submissions WHERE form_id=$1', [f.id]);
    assert.equal(rows.rows[0].n, 1);
  });
  test('server-side validation -> 422', async () => {
    const f = await publishedForm();
    const cases = [
      lead({ fields: { full_name: '' } }),
      lead({ fields: { email: 'not-an-email' } }),
      lead({ fields: { phone: 'abc' } }),
      lead({ fields: { interest: 'other' } }),
      lead({ fields: { message: 'x'.repeat(5001) } }),
      lead({ fields: { full_name: 123 } }),
      lead({ fields: { bogus: 'x' } }),
      { fields: lead().fields }, // consent missing but required
      { ...lead(), consent: { accepted: false } },
      { formVersion: '1' }, // no fields
    ];
    for (const [i, body] of cases.entries()) assert.equal((await submit(f.publicKey, body)).status, 422, `case ${i}`);
  });
  test('stale formVersion -> 409', async () => {
    const f = await publishedForm();
    const r = await submit(f.publicKey, lead({ rest: { formVersion: '7' } }));
    assert.equal(r.status, 409);
  });
  test('origin allow-list enforced; allowed origin gets CORS header', async () => {
    const f = await publishedForm({ allowedOrigins: ['https://site.example'] });
    assert.equal((await submit(f.publicKey, lead(), { Origin: 'https://evil.example' })).status, 403);
    const ok = await submit(f.publicKey, lead(), { Origin: 'https://site.example' });
    assert.equal(ok.status, 200);
    assert.equal(ok.headers.get('access-control-allow-origin'), 'https://site.example');
    const pre = await t.request('OPTIONS', `/api/v1/public/forms/${f.publicKey}/submissions`, { headers: { Origin: 'https://site.example' } });
    assert.equal(pre.status, 204);
  });
  test('oversized payload -> 413, invalid JSON -> 400', async () => {
    const f = await publishedForm();
    assert.equal((await submit(f.publicKey, lead({ fields: { message: 'x'.repeat(40000) } }))).status, 413);
    const r = await t.request('POST', `/api/v1/public/forms/${f.publicKey}/submissions`, { raw: '{bad json', headers: { Authorization: null } });
    assert.equal(r.status, 400);
  });
  test('rate limit -> 429 with Retry-After', async () => {
    const lt = await startEnv({ rateLimit: { max: 3, windowMs: 60000 } });
    try {
      const codes = [];
      for (let i = 0; i < 5; i++) codes.push((await lt.request('GET', '/api/v1/public/forms/pk_x', { headers: { Authorization: null } })).status);
      assert.deepEqual(codes, [404, 404, 404, 429, 429]);
      const r = await lt.request('GET', '/api/v1/public/forms/pk_x');
      assert.ok(r.headers.get('retry-after'));
    } finally { await lt.stop(); }
  });
  test('atomicity: every stored submission has exactly one delivery job', async () => {
    const r = await t.pool.query(
      `SELECT count(*)::int AS n FROM lead_capture_submissions s LEFT JOIN crm_delivery_jobs j ON j.submission_id = s.id WHERE j.id IS NULL`);
    assert.equal(r.rows[0].n, 0);
  });
});

describe('submissions admin + audit', () => {
  test('list, get, scoping and audit trail', async () => {
    const f = await publishedForm();
    const s = (await submit(f.publicKey, lead())).json.data;
    const l = await t.request('GET', `/api/v1/forms/${f.id}/submissions`);
    assert.equal(l.json.data.length, 1);
    const other = { organization_ids: ['8002'] };
    assert.equal((await t.request('GET', `/api/v1/submissions/${s.id}`, { claims: other })).status, 404);
    assert.equal((await t.request('GET', `/api/v1/submissions/${s.id}`, { claims: { permissions: ['forms.read'] } })).status, 403);
    await t.request('GET', `/api/v1/submissions/${s.id}`);
    const a = await t.pool.query(`SELECT * FROM audit_logs WHERE action='submission.read' AND resource_id=$1`, [s.id]);
    assert.equal(a.rows.length, 1);
    assert.equal(a.rows[0].actor_user_id, USER);
    assert.equal(a.rows[0].tenant_id, TENANT);
    assert.match(a.rows[0].request_id, /^req_test_/);
  });
});

describe('CRM delivery', () => {
  let crm;
  before(() => { process.env.CRM_TEST_TOKEN = 'super-secret-crm-token'; });
  after(async () => { if (crm) await crm.close(); });

  async function setup(responses) {
    if (crm) await crm.close();
    crm = await startMockCrm(responses);
    const f = await publishedForm();
    const i = await t.request('PATCH', `/api/v1/forms/${f.id}/crm-integration`, { body: { enabled: true, destinationUrl: crm.url, secretRef: 'CRM_TEST_TOKEN' } });
    assert.equal(i.status, 200, i.text);
    const s = (await submit(f.publicKey, lead())).json.data;
    return { f, s };
  }
  const delivery = async (id) => (await t.request('GET', `/api/v1/submissions/${id}/delivery`)).json.data;

  test('integration settings validated; secret value never exposed', async () => {
    const f = await publishedForm();
    assert.equal((await t.request('PATCH', `/api/v1/forms/${f.id}/crm-integration`, { body: { enabled: true, destinationUrl: 'ftp://x', secretRef: 'ok' } })).status, 422);
    assert.equal((await t.request('GET', `/api/v1/forms/${f.id}/crm-integration`)).status, 404);
    const ok = await t.request('PATCH', `/api/v1/forms/${f.id}/crm-integration`, { body: { enabled: false, destinationUrl: 'https://crm.example/leads', secretRef: 'CRM_TEST_TOKEN' } });
    assert.equal(ok.status, 200);
    assert.ok(!ok.text.includes('super-secret-crm-token'));
    assert.equal((await t.request('PATCH', `/api/v1/forms/${f.id}/crm-integration`, { claims: { permissions: ['forms.read'] }, body: {} })).status, 403);
  });
  test('2xx -> delivered with external id; CRM got server credential + idempotency key', async () => {
    const { s } = await setup([{ status: 201, body: { id: 'crm-777' } }]);
    await worker();
    const d = await delivery(s.id);
    assert.equal(d.state, 'delivered');
    assert.equal(d.externalCrmRecordId, 'crm-777');
    assert.equal(crm.calls.length, 1);
    assert.equal(crm.calls[0].headers.authorization, 'Bearer super-secret-crm-token');
    assert.equal(crm.calls[0].headers['idempotency-key'], s.id);
    assert.equal(crm.calls[0].body.fields.email, 'asha@example.com');
    await worker();
    assert.equal(crm.calls.length, 1); // delivered jobs are not re-sent
  });
  test('duplicate submission does not create a second CRM delivery', async () => {
    const { f } = await setup([]);
    await submit(f.publicKey, lead());
    await submit(f.publicKey, lead());
    await worker();
    assert.equal(crm.calls.length, 1);
  });
  test('5xx is retried with attempts recorded, then succeeds', async () => {
    const { s } = await setup([{ status: 503 }, { status: 200, body: { id: 'ok' } }]);
    await worker();
    let d = await delivery(s.id);
    assert.equal(d.state, 'pending');
    assert.equal(d.attemptCount, 1);
    assert.equal(d.lastError, 'http_503');
    await due(s.id);
    await worker();
    d = await delivery(s.id);
    assert.equal(d.state, 'delivered');
    assert.equal(d.attempts.length, 2);
  });
  test('429 respects Retry-After', async () => {
    const { s } = await setup([{ status: 429, headers: { 'Retry-After': '120' } }]);
    await worker();
    const d = await delivery(s.id);
    assert.equal(d.state, 'pending');
    const secs = (new Date(d.nextAttemptAt) - Date.now()) / 1000;
    assert.ok(secs > 100 && secs <= 125, `next attempt in ${secs}s`);
  });
  test('network failure is transient', async () => {
    const { s } = await setup([]);
    await t.pool.query(`UPDATE crm_integrations SET destination_url='http://127.0.0.1:1/x' WHERE tenant_id=$1`, [TENANT]);
    await worker();
    const d = await delivery(s.id);
    assert.equal(d.state, 'pending');
    assert.equal(d.lastError, 'network_error');
  });
  test('400/422 and 401/403 are parked (needs_attention), not retried', async () => {
    for (const status of [422, 400, 401, 403]) {
      const { s } = await setup([{ status }]);
      await worker();
      const d = await delivery(s.id);
      assert.equal(d.state, 'needs_attention', `status ${status}`);
      assert.equal(d.attemptCount, 1);
      await worker();
      assert.equal(crm.calls.length, 1);
    }
  });
  test('max attempts -> dead_letter, then audited replay succeeds', async () => {
    const { s } = await setup([{ status: 500 }, { status: 500 }, { status: 500 }, { status: 200, body: { id: 'late' } }]);
    for (let i = 0; i < 3; i++) { await worker(); await due(s.id); }
    let d = await delivery(s.id);
    assert.equal(d.state, 'dead_letter');
    assert.equal((await t.request('POST', `/api/v1/submissions/${s.id}/delivery/retry`, { claims: { permissions: ['delivery.read'] } })).status, 403);
    const r = await t.request('POST', `/api/v1/submissions/${s.id}/delivery/retry`);
    assert.equal(r.status, 200);
    assert.equal((await t.request('POST', `/api/v1/submissions/${s.id}/delivery/retry`)).status, 409); // already pending
    await worker();
    d = await delivery(s.id);
    assert.equal(d.state, 'delivered');
    assert.equal((await t.request('POST', `/api/v1/submissions/${s.id}/delivery/retry`)).status, 409); // delivered: no replay
    const a = await t.pool.query(`SELECT 1 FROM audit_logs WHERE action='delivery.retry' AND resource_id=$1`, [s.id]);
    assert.equal(a.rows.length, 1);
  });
  test('missing credential parks the job without leaking secrets', async () => {
    const { s } = await setup([]);
    await t.pool.query(`UPDATE crm_integrations SET secret_ref='NOT_SET_ANYWHERE' WHERE tenant_id=$1`, [TENANT]);
    await worker();
    const r = await t.request('GET', `/api/v1/submissions/${s.id}/delivery`);
    assert.equal(r.json.data.state, 'needs_attention');
    assert.equal(r.json.data.lastError, 'credential_missing');
  });
  test('no integration -> not_configured; retry blocked until enabled', async () => {
    const f = await publishedForm();
    const s = (await submit(f.publicKey, lead())).json.data;
    await worker();
    assert.equal((await delivery(s.id)).state, 'not_configured');
    assert.equal((await t.request('POST', `/api/v1/submissions/${s.id}/delivery/retry`)).status, 409);
  });
  test('delivery of another tenant is not visible', async () => {
    const { s } = await setup([]);
    const r = await t.request('GET', `/api/v1/submissions/${s.id}/delivery`, { claims: { tenant_id: '8001', organization_ids: ['8002'] } });
    assert.equal(r.status, 404);
  });
});

describe('ops', () => {
  test('health live/ready; metrics hidden without token; unknown route -> 404 JSON', async () => {
    assert.equal((await t.request('GET', '/health/live')).status, 200);
    assert.equal((await t.request('GET', '/health/ready')).status, 200);
    assert.equal((await t.request('GET', '/metrics')).status, 404);
    const r = await t.request('GET', '/nope');
    assert.equal(r.status, 404);
    assert.ok(r.json.error);
  });
  test('errors never leak stack traces or tokens', async () => {
    const tok = mintToken();
    const r = await t.request('GET', '/api/v1/forms/abc', { headers: { Authorization: `Bearer ${tok}` } });
    assert.ok(!r.text.includes(tok));
    assert.ok(!/at .*\.js/.test(r.text));
  });
});

