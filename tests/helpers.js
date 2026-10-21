const jwt = require('jsonwebtoken');
const http = require('http');
const { Pool } = require('pg');
const { loadConfig } = require('../src/config');
const { createPool, migrate } = require('../src/db');
const { createApp } = require('../src/app');

const env = {
  JWT_SECRET: 'test-secret-test-secret-123456', JWT_ISSUER: 'triostack-identity', JWT_AUDIENCE: 'lead-capture-api',
  RATE_LIMIT_MAX: '100000',
  DB_HOST: process.env.TEST_DB_HOST || 'localhost', DB_PORT: process.env.TEST_DB_PORT || '5433',
  DB_USER: process.env.DB_USER || 'postgres', DB_PASSWORD: process.env.DB_PASSWORD || 'postgres',
};

const TENANT = '9223372036854775000'; // > Number.MAX_SAFE_INTEGER: proves no precision loss
const ORG = '9223372036854775001';
const USER = '9223372036854775002';

function mintToken(over = {}, signOpts = {}) {
  const claims = { sub: USER, tenant_id: TENANT, organization_ids: [ORG], permissions: ['*'], ...over };
  return jwt.sign(claims, signOpts.secret || env.JWT_SECRET, {
    algorithm: 'HS256', issuer: 'triostack-identity', audience: 'lead-capture-api', expiresIn: '1h', ...signOpts.opts,
  });
}

// Client that AUTO-ASSIGNS Authorization / X-Tenant-Id / X-Organization-Id / X-Request-Id when a call omits them.
// Pass a header value of `null` to deliberately send none (to test rejection paths).
function makeClient(base) {
  return async function request(method, path, { body, headers = {}, claims, raw } = {}) {
    const h = { 'Content-Type': 'application/json', ...headers };
    const tenant = (claims && claims.tenant_id) || TENANT;
    const org = (claims && (claims.organization_ids || [claims.organization_id])[0]) || ORG;
    if (h.Authorization === undefined) h.Authorization = `Bearer ${mintToken(claims)}`;
    if (h['X-Tenant-Id'] === undefined) h['X-Tenant-Id'] = tenant;
    if (h['X-Organization-Id'] === undefined) h['X-Organization-Id'] = org;
    if (h['X-Request-Id'] === undefined) h['X-Request-Id'] = `req_test_${Math.random().toString(36).slice(2)}`;
    for (const k of Object.keys(h)) if (h[k] === null) delete h[k];
    const res = await fetch(base + path, { method, headers: h, body: raw !== undefined ? raw : body === undefined ? undefined : JSON.stringify(body) });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* not json */ }
    return { status: res.status, json, text, headers: res.headers };
  };
}

async function startEnv(appOverrides = {}) {
  const dbName = `leads_test_${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
  const admin = new Pool({ host: env.DB_HOST, port: Number(env.DB_PORT), user: env.DB_USER, password: env.DB_PASSWORD, database: 'postgres' });
  await admin.query(`CREATE DATABASE ${dbName}`);
  const config = { ...loadConfig({ ...env, DB_NAME: dbName }), ...appOverrides };
  const pool = createPool(config.db);
  await migrate(pool);
  const server = http.createServer(createApp({ pool, config }));
  await new Promise((r) => server.listen(0, r));
  const base = `http://127.0.0.1:${server.address().port}`;
  return {
    pool, base, config, request: makeClient(base),
    async stop() {
      await new Promise((r) => server.close(r));
      await pool.end();
      await admin.query(`DROP DATABASE ${dbName} WITH (FORCE)`);
      await admin.end();
    },
  };
}

// Scriptable mock CRM.  responses: array of {status, headers, body} consumed per request.
async function startMockCrm(responses = []) {
  const calls = [];
  const server = http.createServer((req, res) => {
    let data = '';
    req.on('data', (d) => (data += d));
    req.on('end', () => {
      calls.push({ headers: req.headers, body: JSON.parse(data || '{}') });
      const r = responses.shift() || { status: 200, body: { id: `crm_${calls.length}` } };
      res.writeHead(r.status, { 'Content-Type': 'application/json', ...(r.headers || {}) });
      res.end(JSON.stringify(r.body || {}));
    });
  });
  await new Promise((r) => server.listen(0, r));
  return { url: `http://127.0.0.1:${server.address().port}/leads`, calls, responses, close: () => new Promise((r) => server.close(r)) };
}

const SCHEMA = {
  consentRequired: true,
  fields: [
    { name: 'full_name', type: 'text', required: true },
    { name: 'email', type: 'email', required: true },
    { name: 'phone', type: 'phone' },
    { name: 'interest', type: 'select', options: ['sales', 'support'] },
    { name: 'message', type: 'textarea' },
  ],
};

module.exports = { env, TENANT, ORG, USER, mintToken, makeClient, startEnv, startMockCrm, SCHEMA };
