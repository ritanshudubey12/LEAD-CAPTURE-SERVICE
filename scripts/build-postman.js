// Generates postman/lead-capture.postman_collection.json and postman/local.postman_environment.json
// Run: node scripts/build-postman.js
try { process.loadEnvFile(require('path').join(__dirname, '..', '.env')); } catch { /* optional */ }
const fs = require('fs');
const path = require('path');

const out = path.join(__dirname, '..', 'postman');
fs.mkdirSync(out, { recursive: true });

// Collection-level pre-request: auto-assign JWT + tenant/org when they are empty or the token is near expiry.
const collectionPre = `
const secret = pm.variables.get('jwt_secret');
const now = Math.floor(Date.now() / 1000);
let exp = Number(pm.collectionVariables.get('token_exp') || 0);
if (!pm.variables.get('tenantId')) pm.collectionVariables.set('tenantId', '1001');
if (!pm.variables.get('orgId')) pm.collectionVariables.set('orgId', '2001');
if (!pm.variables.get('userId')) pm.collectionVariables.set('userId', '3001');
const b64 = (w) => CryptoJS.enc.Base64.stringify(w).replace(/=+$/, '').replace(/\\+/g, '-').replace(/\\//g, '_');
const sign = (over, key) => {
  const header = b64(CryptoJS.enc.Utf8.parse(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const payload = b64(CryptoJS.enc.Utf8.parse(JSON.stringify(Object.assign({
    sub: pm.variables.get('userId'), tenant_id: pm.variables.get('tenantId'),
    organization_ids: [pm.variables.get('orgId')], permissions: ['*'],
    iss: pm.variables.get('jwt_issuer'), aud: pm.variables.get('jwt_audience'), iat: now, exp: now + 3600,
  }, over))));
  return header + '.' + payload + '.' + b64(CryptoJS.HmacSHA256(header + '.' + payload, key || secret));
};
if (!pm.variables.get('token') || exp - now < 60) {
  pm.collectionVariables.set('token', sign({}));
  pm.collectionVariables.set('token_exp', String(now + 3600));
}
// Extra tokens used by the negative-case folder (always regenerated).
pm.collectionVariables.set('expired_token', sign({ iat: now - 7200, exp: now - 3600 }));
pm.collectionVariables.set('bad_signature_token', sign({}, 'a-completely-different-secret'));
pm.collectionVariables.set('limited_token', sign({ permissions: ['forms.read'] }));
pm.collectionVariables.set('other_tenant_token', sign({ tenant_id: '8001', organization_ids: ['8002'] }));
`;

const authHeaders = [
  { key: 'Authorization', value: 'Bearer {{token}}' },
  { key: 'X-Tenant-Id', value: '{{tenantId}}' },
  { key: 'X-Organization-Id', value: '{{orgId}}' },
  { key: 'X-Request-Id', value: 'pm-{{$guid}}' },
];
const json = { key: 'Content-Type', value: 'application/json' };

const schema = {
  consentRequired: true,
  fields: [
    { name: 'full_name', type: 'text', required: true },
    { name: 'email', type: 'email', required: true },
    { name: 'phone', type: 'phone' },
    { name: 'message', type: 'textarea' },
  ],
};
const leadBody = (extra = '') => `{
  "formVersion": "{{formVersion}}",
  "fields": { "full_name": "Asha Sharma", "email": "{{leadEmail}}", "message": "Please contact me${extra}" },
  "consent": { "accepted": true, "policyVersion": "privacy-v1" }
}`;

const STATUS_NAMES = { 200: 'OK', 400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found', 409: 'Conflict', 413: 'Payload Too Large', 422: 'Unprocessable Entity' };
const ok = (extra = '', status = 200) => `pm.test('Status is ${status} ${STATUS_NAMES[status]}', () => pm.response.to.have.status(${status}));\n${extra}`;
const bodyIs = (expr, label) => `pm.test('${label}', () => { const j = pm.response.json(); pm.expect(${expr}).to.be.true; });`;
const errIs = (code) => bodyIs(`j.error && j.error.code === '${code}'`, `error code is ${code}`);

// status: expected HTTP status (default 200). hdr: replaces the default auth headers (negative cases).
function req(name, method, p, { body, auth = true, pre = '', test = '', headers = [], status = 200, hdr } = {}) {
  const url = `{{baseUrl}}${p}`;
  return {
    name,
    event: [
      ...(pre ? [{ listen: 'prerequest', script: { type: 'text/javascript', exec: pre.split('\n') } }] : []),
      { listen: 'test', script: { type: 'text/javascript', exec: ok(test, status).split('\n') } },
    ],
    request: {
      method,
      header: [...(hdr || (auth ? authHeaders : [])), ...(body !== undefined ? [json] : []), ...headers],
      ...(body ? { body: { mode: 'raw', raw: body } } : {}),
      url: { raw: url, host: ['{{baseUrl}}'], path: p.replace(/^\//, '').split('/') },
    },
  };
}

const items = [
  { name: '1. Health', item: [
    req('Health live', 'GET', '/health/live', { auth: false, test: bodyIs("j.status === 'ok'", 'status ok') }),
    req('Health ready', 'GET', '/health/ready', { auth: false, test: bodyIs("j.status === 'ready'", 'db ready') }),
  ] },
  { name: '2. Forms (Bearer JWT)', item: [
    req('Create form', 'POST', '/api/v1/forms', {
      pre: "pm.collectionVariables.set('formName', 'Contact ' + Date.now());",
      body: JSON.stringify({ name: '{{formName}}', websiteId: '77', allowedOrigins: ['https://site.example'], schema }, null, 2),
      test: `const d = pm.response.json().data;
pm.collectionVariables.set('formId', d.id);
pm.collectionVariables.set('publicKey', d.publicKey);
${bodyIs("typeof j.data.id === 'string' && j.data.tenantId === pm.variables.get('tenantId')", 'ids are strings and tenant matches')}`,
    }),
    req('List forms', 'GET', '/api/v1/forms?limit=10', { test: bodyIs('Array.isArray(j.data) && j.data.length > 0', 'has forms') }),
    req('Get form', 'GET', '/api/v1/forms/{{formId}}', { test: bodyIs("j.data.id === pm.variables.get('formId') && j.data.versions.length === 1", 'form with 1 version') }),
    req('Update form', 'PATCH', '/api/v1/forms/{{formId}}', {
      body: JSON.stringify({ name: '{{formName}} (edited)' }),
      test: bodyIs("j.data.name.endsWith('(edited)')", 'name updated'),
    }),
    req('Create new version', 'POST', '/api/v1/forms/{{formId}}/versions', {
      body: JSON.stringify({ schema }, null, 2),
      test: bodyIs('j.data.version === 2', 'version 2 created'),
    }),
    req('Publish latest version', 'POST', '/api/v1/forms/{{formId}}/publish', {
      test: bodyIs("j.data.status === 'published'", 'published'),
    }),
  ] },
  { name: '3. Public intake (no JWT)', item: [
    req('Get public form schema', 'GET', '/api/v1/public/forms/{{publicKey}}', {
      auth: false, headers: [{ key: 'Origin', value: 'https://site.example' }],
      test: `pm.collectionVariables.set('formVersion', pm.response.json().data.formVersion);
${bodyIs("j.data.formVersion === '2'", 'serves published version 2')}`,
    }),
    req('Submit lead', 'POST', '/api/v1/public/forms/{{publicKey}}/submissions', {
      auth: false, headers: [{ key: 'Origin', value: 'https://site.example' }],
      pre: "pm.collectionVariables.set('leadEmail', 'asha+' + Date.now() + '@example.com');",
      body: leadBody(),
      test: `pm.collectionVariables.set('submissionId', pm.response.json().data.id);
${bodyIs('j.data.duplicate === false', 'stored as new lead')}`,
    }),
    req('Submit same lead again (duplicate removed)', 'POST', '/api/v1/public/forms/{{publicKey}}/submissions', {
      auth: false, headers: [{ key: 'Origin', value: 'https://site.example' }],
      body: leadBody(),
      test: bodyIs("j.data.duplicate === true && j.data.id === pm.variables.get('submissionId')", 'duplicate returns original id'),
    }),
    req('Submit lead with Idempotency-Key', 'POST', '/api/v1/public/forms/{{publicKey}}/submissions', {
      auth: false, headers: [{ key: 'Idempotency-Key', value: 'pm-{{$guid}}' }],
      pre: "pm.collectionVariables.set('leadEmail2', 'raj+' + Date.now() + '@example.com');",
      body: leadBody(' (idempotent)').replace('{{leadEmail}}', '{{leadEmail2}}'),
      test: bodyIs('j.data.duplicate === false', 'new lead'),
    }),
  ] },
  { name: '4. Submissions & CRM delivery (Bearer JWT)', item: [
    req('List submissions', 'GET', '/api/v1/forms/{{formId}}/submissions', { test: bodyIs('j.data.length === 2', 'exactly 2 stored (duplicate removed)') }),
    req('Get submission', 'GET', '/api/v1/submissions/{{submissionId}}', { test: bodyIs("j.data.fields.email === pm.variables.get('leadEmail')", 'email matches') }),
    req('Configure CRM integration', 'PATCH', '/api/v1/forms/{{formId}}/crm-integration', {
      body: JSON.stringify({ enabled: true, destinationUrl: 'https://crm.example.com/leads', secretRef: 'CRM_SERVICE_TOKEN' }, null, 2),
      test: bodyIs('j.data.enabled === true && !JSON.stringify(j).includes("change-me")', 'enabled; secret value not exposed'),
    }),
    req('Get CRM integration', 'GET', '/api/v1/forms/{{formId}}/crm-integration', { test: bodyIs("j.data.secretRef === 'CRM_SERVICE_TOKEN'", 'secret referenced by name') }),
    req('Retry delivery', 'POST', '/api/v1/submissions/{{submissionId}}/delivery/retry', { test: bodyIs("j.data.state === 'pending'", 'queued') }),
    req('Delivery status', 'GET', '/api/v1/submissions/{{submissionId}}/delivery', { test: bodyIs("['pending','needs_attention','delivered','dead_letter'].includes(j.data.state)", 'has delivery state') }),
  ] },
  { name: '5. Negative cases (expected errors)', item: [
    { name: 'Authentication', item: [
      req('No token -> 401', 'GET', '/api/v1/forms', { auth: false, status: 401, test: errIs('unauthorized') }),
      req('Malformed scheme (Basic) -> 401', 'GET', '/api/v1/forms', { hdr: [{ key: 'Authorization', value: 'Basic abc' }], status: 401 }),
      req('Garbage token -> 401', 'GET', '/api/v1/forms', { hdr: [{ key: 'Authorization', value: 'Bearer not.a.jwt' }], status: 401 }),
      req('Wrong signature -> 401', 'GET', '/api/v1/forms', { hdr: [{ key: 'Authorization', value: 'Bearer {{bad_signature_token}}' }], status: 401 }),
      req('Expired token -> 401', 'GET', '/api/v1/forms', { hdr: [{ key: 'Authorization', value: 'Bearer {{expired_token}}' }], status: 401 }),
    ] },
    { name: 'Tenant / organization / permission', item: [
      req('Tenant header mismatch -> 403', 'GET', '/api/v1/forms', { hdr: [authHeaders[0], { key: 'X-Tenant-Id', value: '424242' }], status: 403, test: errIs('forbidden') }),
      req('Organization header not in token -> 403', 'GET', '/api/v1/forms', { hdr: [authHeaders[0], authHeaders[1], { key: 'X-Organization-Id', value: '424242' }], status: 403 }),
      req('Tenant/org headers omitted -> auto-assigned from token (200)', 'GET', '/api/v1/forms', { hdr: [authHeaders[0]] }),
      req('Spoofed X-User-Id ignored (200, actor = token user)', 'POST', '/api/v1/forms', {
        headers: [{ key: 'X-User-Id', value: '666' }],
        pre: "pm.collectionVariables.set('spoofName', 'Spoof ' + Date.now());",
        body: JSON.stringify({ name: '{{spoofName}}', websiteId: '1' }),
        test: bodyIs("j.data.createdByUserId === pm.variables.get('userId')", 'createdByUserId comes from the token'),
      }),
      req('Token without forms.write -> 403', 'POST', '/api/v1/forms', {
        hdr: [{ key: 'Authorization', value: 'Bearer {{limited_token}}' }, authHeaders[1], authHeaders[2]],
        body: JSON.stringify({ name: 'nope', websiteId: '1' }), status: 403,
      }),
      req('Other tenant cannot read this form -> 404', 'GET', '/api/v1/forms/{{formId}}', {
        hdr: [{ key: 'Authorization', value: 'Bearer {{other_tenant_token}}' }, { key: 'X-Tenant-Id', value: '8001' }, { key: 'X-Organization-Id', value: '8002' }], status: 404,
      }),
      req('Other tenant cannot read submission -> 404', 'GET', '/api/v1/submissions/{{submissionId}}', {
        hdr: [{ key: 'Authorization', value: 'Bearer {{other_tenant_token}}' }, { key: 'X-Tenant-Id', value: '8001' }, { key: 'X-Organization-Id', value: '8002' }], status: 404,
      }),
    ] },
    { name: 'Forms validation', item: [
      req('Create form without name -> 422', 'POST', '/api/v1/forms', { body: '{}', status: 422, test: errIs('validation_failed') }),
      req('Duplicate form name -> 409', 'POST', '/api/v1/forms', { body: JSON.stringify({ name: '{{spoofName}}', websiteId: '1' }), status: 409, test: errIs('conflict') }),
      req('websiteId as a number -> 422', 'POST', '/api/v1/forms', { body: '{"name":"x","websiteId":77}', status: 422 }),
      req('Invalid schema field name -> 422', 'POST', '/api/v1/forms/{{formId}}/versions', { body: '{"schema":{"fields":[{"name":"Bad Name","type":"text"}]}}', status: 422 }),
      req('Non-numeric formId -> 400', 'GET', '/api/v1/forms/abc', { status: 400, test: errIs('invalid_id') }),
      req('Bad cursor -> 400', 'GET', '/api/v1/forms?cursor=zzz', { status: 400 }),
      req('Publish non-existent version -> 404', 'POST', '/api/v1/forms/{{formId}}/publish', { body: '{"version":99}', status: 404 }),
      req('Invalid CRM destination -> 422', 'PATCH', '/api/v1/forms/{{formId}}/crm-integration', { body: '{"enabled":true,"destinationUrl":"ftp://x","secretRef":"bad"}', status: 422 }),
      req('Retry while already pending -> 409', 'POST', '/api/v1/submissions/{{submissionId}}/delivery/retry', { status: 409, test: errIs('not_retryable') }),
    ] },
    { name: 'Public intake rejections', item: [
      req('Unknown public key -> 404', 'POST', '/api/v1/public/forms/pk_unknown/submissions', { auth: false, body: leadBody(), status: 404 }),
      req('Invalid email -> 422', 'POST', '/api/v1/public/forms/{{publicKey}}/submissions', { auth: false, body: leadBody().replace('{{leadEmail}}', 'not-an-email'), status: 422 }),
      req('Missing required full_name -> 422', 'POST', '/api/v1/public/forms/{{publicKey}}/submissions', {
        auth: false, body: '{"formVersion":"{{formVersion}}","fields":{"email":"a@b.co"},"consent":{"accepted":true,"policyVersion":"v1"}}', status: 422,
      }),
      req('Client-supplied tenant_id rejected -> 422', 'POST', '/api/v1/public/forms/{{publicKey}}/submissions', {
        auth: false, body: leadBody().replace('"message"', '"tenant_id": "1", "message"'), status: 422,
        test: bodyIs('j.error.details.tenant_id === "unknown field"', 'tenant_id is not trusted'),
      }),
      req('Consent not accepted -> 422', 'POST', '/api/v1/public/forms/{{publicKey}}/submissions', {
        auth: false, body: leadBody().replace('"accepted": true', '"accepted": false'), status: 422,
      }),
      req('Stale formVersion -> 409', 'POST', '/api/v1/public/forms/{{publicKey}}/submissions', {
        auth: false, body: leadBody().replace('{{formVersion}}', '1'), status: 409, test: errIs('stale_form_version'),
      }),
      req('Origin not allowed -> 403', 'POST', '/api/v1/public/forms/{{publicKey}}/submissions', {
        auth: false, headers: [{ key: 'Origin', value: 'https://evil.example' }], body: leadBody(), status: 403, test: errIs('origin_not_allowed'),
      }),
      req('Invalid Idempotency-Key -> 400', 'POST', '/api/v1/public/forms/{{publicKey}}/submissions', {
        auth: false, headers: [{ key: 'Idempotency-Key', value: 'has spaces' }], body: leadBody(), status: 400,
      }),
      req('Invalid JSON -> 400', 'POST', '/api/v1/public/forms/{{publicKey}}/submissions', { auth: false, body: '{bad json', status: 400, test: errIs('invalid_json') }),
      req('Payload too large -> 413', 'POST', '/api/v1/public/forms/{{publicKey}}/submissions', {
        auth: false, pre: "pm.collectionVariables.set('bigPayload', JSON.stringify({ fields: { message: 'x'.repeat(40000) } }));",
        body: '{{bigPayload}}', status: 413,
      }),
    ] },
    { name: 'Ops', item: [
      req('Metrics hidden without token -> 404', 'GET', '/metrics', { auth: false, status: 404 }),
      req('Unknown route -> 404', 'GET', '/api/v1/nope', { status: 404 }),
    ] },
  ] },
  { name: '6. Cleanup', item: [
    req('Unpublish form', 'POST', '/api/v1/forms/{{formId}}/unpublish', { test: bodyIs("j.data.status === 'unpublished'", 'unpublished') }),
    req('Unpublished form is no longer public -> 404', 'GET', '/api/v1/public/forms/{{publicKey}}', { auth: false, status: 404 }),
    req('Submit to unpublished form -> 404', 'POST', '/api/v1/public/forms/{{publicKey}}/submissions', { auth: false, body: leadBody(), status: 404 }),
  ] },
];

const collection = {
  info: {
    name: 'Lead Capture API',
    description: 'Folders 1-4 and 6 are happy-path calls that return 200 OK; folder 5 sends bad input on purpose and asserts the exact expected error status. A collection pre-request script auto-generates the Bearer JWT and tenant/org headers when they are empty.',
    schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json',
  },
  event: [{ listen: 'prerequest', script: { type: 'text/javascript', exec: collectionPre.split('\n') } }],
  variable: ['token', 'token_exp', 'formId', 'publicKey', 'formVersion', 'submissionId', 'leadEmail', 'leadEmail2', 'formName', 'spoofName', 'bigPayload', 'expired_token', 'bad_signature_token', 'limited_token', 'other_tenant_token'].map((key) => ({ key, value: '' })),
  item: items,
};

const environment = {
  name: 'Lead Capture - Local',
  values: [
    ['baseUrl', 'http://localhost:3001'],
    ['jwt_secret', process.env.JWT_SECRET || 'PUT-YOUR-JWT_SECRET-HERE'],
    ['jwt_issuer', process.env.JWT_ISSUER || 'triostack-identity'],
    ['jwt_audience', process.env.JWT_AUDIENCE || 'lead-capture-api'],
    ['tenantId', '1001'], ['orgId', '2001'], ['userId', '3001'],
  ].map(([key, value]) => ({ key, value, enabled: true })),
};

fs.writeFileSync(path.join(out, 'lead-capture.postman_collection.json'), JSON.stringify(collection, null, 2));
fs.writeFileSync(path.join(out, 'local.postman_environment.json'), JSON.stringify(environment, null, 2));
console.log('Wrote postman/lead-capture.postman_collection.json and postman/local.postman_environment.json');
