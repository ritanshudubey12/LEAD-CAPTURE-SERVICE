const express = require('express');
const crypto = require('crypto');
const { HttpError, asyncH, errorHandler } = require('./http');
const { authenticate, need } = require('./auth');
const { nextId, isId } = require('./ids');
const { tx } = require('./db');
const { validateSchema, validateSubmission } = require('./validation');

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

const formOut = (r) => ({
  id: r.id, tenantId: r.tenant_id, organizationId: r.organization_id, websiteId: r.website_id,
  name: r.name, status: r.status, publicKey: r.public_key, publishedVersionId: r.published_version_id,
  allowedOrigins: r.allowed_origins, createdByUserId: r.created_by_user_id,
  createdAt: r.created_at, updatedAt: r.updated_at,
});
const versionOut = (r) => ({
  id: r.id, formId: r.form_id, version: r.version, schema: r.schema_json,
  createdByUserId: r.created_by_user_id, createdAt: r.created_at,
});
const submissionOut = (r) => ({
  id: r.id, tenantId: r.tenant_id, organizationId: r.organization_id, websiteId: r.website_id,
  formId: r.form_id, formVersionId: r.form_version_id, fields: r.fields_json, consent: r.consent_json,
  status: r.status, receivedAt: r.received_at,
});
const integrationOut = (r) => ({
  formId: r.form_id, enabled: r.enabled, destinationUrl: r.destination_url, secretRef: r.secret_ref,
  updatedAt: r.updated_at,
});

function makeLimiter({ max, windowMs }) {
  const hits = new Map();
  return (key) => {
    const now = Date.now();
    if (hits.size > 10000) for (const [k, v] of hits) if (v.reset <= now) hits.delete(k);
    let e = hits.get(key);
    if (!e || e.reset <= now) { e = { count: 0, reset: now + windowMs }; hits.set(key, e); }
    e.count += 1;
    return e.count <= max ? 0 : Math.ceil((e.reset - now) / 1000);
  };
}

function parseOrigins(v) {
  if (v === undefined) return undefined;
  if (!Array.isArray(v) || v.length > 20) throw new HttpError(422, 'validation_failed', 'Validation failed', { allowedOrigins: 'must be an array of up to 20 origins' });
  return v.map((o) => {
    try {
      const u = new URL(o);
      if (!/^https?:$/.test(u.protocol) || u.origin !== o) throw new Error();
      return u.origin;
    } catch {
      throw new HttpError(422, 'validation_failed', 'Validation failed', { allowedOrigins: `invalid origin: ${String(o).slice(0, 100)}` });
    }
  });
}

function createApp({ pool, config }) {
  const app = express();
  app.disable('x-powered-by');
  if (config.trustProxy) app.set('trust proxy', 1);

  app.use((req, res, next) => {
    const h = req.headers['x-request-id'];
    req.requestId = typeof h === 'string' && /^[\w.-]{1,64}$/.test(h) ? h : `req_${crypto.randomUUID()}`;
    res.setHeader('X-Request-Id', req.requestId);
    next();
  });
  app.use(express.json({ limit: config.maxBodyBytes }));

  const q = (c, text, params) => (c || pool).query(text, params);
  const audit = (c, ctx, action, resource, resourceId) => q(c,
    `INSERT INTO audit_logs (id, actor_user_id, tenant_id, organization_id, action, resource, resource_id, request_id)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [nextId(), ctx.userId, ctx.tenantId, ctx.orgId, action, resource, resourceId || null, ctx.requestId]);
  const idParam = (req, name) => {
    if (!isId(req.params[name])) throw new HttpError(400, 'invalid_id', `${name} must be a decimal BIGINT string`);
    return req.params[name];
  };
  const getForm = async (c, ctx, id, lock) => {
    const { rows } = await q(c, `SELECT * FROM lead_capture_forms WHERE id=$1 AND tenant_id=$2 AND organization_id=$3 ${lock ? 'FOR UPDATE' : ''}`,
      [id, ctx.tenantId, ctx.orgId]);
    if (!rows[0]) throw new HttpError(404, 'not_found', 'Form not found');
    return rows[0];
  };
  const page = (req) => {
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 25, 1), 100);
    const cursor = req.query.cursor;
    if (cursor !== undefined && !isId(cursor)) throw new HttpError(400, 'invalid_cursor', 'cursor must be a decimal BIGINT string');
    return { limit, cursor };
  };

  // ---------- Ops ----------
  app.get('/health/live', (req, res) => res.json({ status: 'ok' }));
  app.get('/health/ready', asyncH(async (req, res) => {
    try { await pool.query('SELECT 1'); res.json({ status: 'ready' }); } catch { res.status(503).json({ status: 'db_unavailable' }); }
  }));
  app.get('/metrics', asyncH(async (req, res) => {
    if (!config.metricsToken || req.headers.authorization !== `Bearer ${config.metricsToken}`) throw new HttpError(404, 'not_found', 'Not found');
    const { rows } = await pool.query('SELECT state, count(*)::int AS n FROM crm_delivery_jobs GROUP BY state');
    const age = await pool.query(`SELECT COALESCE(EXTRACT(EPOCH FROM now() - min(next_attempt_at)),0)::int AS s FROM crm_delivery_jobs WHERE state='pending'`);
    res.type('text/plain').send(
      rows.map((r) => `lead_delivery_jobs{state="${r.state}"} ${r.n}`).concat(`lead_outbox_oldest_pending_seconds ${age.rows[0].s}`).join('\n') + '\n');
  }));

  // ---------- Public intake (no JWT) ----------
  const limiter = makeLimiter(config.rateLimit);
  const pub = express.Router();
  pub.use((req, res, next) => {
    const wait = limiter(`${req.ip}:${req.params.publicKey || ''}`);
    if (wait) { res.setHeader('Retry-After', wait); return next(new HttpError(429, 'rate_limited', 'Too many requests')); }
    next();
  });
  const publishedForm = async (key) => {
    const { rows } = await pool.query(
      `SELECT f.*, v.version, v.schema_json, v.id AS version_id FROM lead_capture_forms f
         JOIN lead_capture_form_versions v ON v.id = f.published_version_id
        WHERE f.public_key = $1 AND f.status = 'published'`, [key]);
    if (!rows[0]) throw new HttpError(404, 'not_found', 'Form not found');
    return rows[0];
  };
  const checkOrigin = (req, res, form) => {
    const origin = req.headers.origin;
    if (!origin) return;
    if (form.allowed_origins.length && !form.allowed_origins.includes(origin)) throw new HttpError(403, 'origin_not_allowed', 'Origin not allowed');
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  };

  pub.options('/forms/:publicKey/submissions', (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Idempotency-Key');
    res.status(204).end();
  });
  pub.get('/forms/:publicKey', asyncH(async (req, res) => {
    const f = await publishedForm(req.params.publicKey);
    checkOrigin(req, res, f);
    res.json({ data: { name: f.name, formVersion: String(f.version), schema: f.schema_json } });
  }));
  pub.post('/forms/:publicKey/submissions', asyncH(async (req, res) => {
    const form = await publishedForm(req.params.publicKey);
    checkOrigin(req, res, form);
    const body = req.body || {};
    if (body.formVersion !== undefined && String(body.formVersion) !== String(form.version)) {
      throw new HttpError(409, 'stale_form_version', 'Form has been updated; reload the form', { currentVersion: String(form.version) });
    }
    const { fields, consent } = validateSubmission(form.schema_json, body);

    // Duplicate removal: explicit Idempotency-Key, otherwise a hash of the normalized content.
    const idem = req.headers['idempotency-key'];
    if (idem !== undefined && !/^[\x21-\x7e]{1,128}$/.test(idem)) throw new HttpError(400, 'invalid_idempotency_key', 'Idempotency-Key must be 1-128 printable characters');
    const canonical = JSON.stringify(Object.keys(fields).sort().map((k) => [k, fields[k]]));
    const dedupe = sha(idem ? `idem:${idem}` : `content:${canonical}`);

    const result = await tx(pool, async (c) => {
      const id = nextId();
      const ins = await q(c,
        `INSERT INTO lead_capture_submissions (id, tenant_id, organization_id, website_id, form_id, form_version_id, fields_json, consent_json, idempotency_key_hash)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (form_id, idempotency_key_hash) DO NOTHING RETURNING id`,
        [id, form.tenant_id, form.organization_id, form.website_id, form.id, form.version_id, fields, consent, dedupe]);
      if (!ins.rows[0]) {
        const ex = await q(c, 'SELECT id FROM lead_capture_submissions WHERE form_id=$1 AND idempotency_key_hash=$2', [form.id, dedupe]);
        return { id: ex.rows[0].id, duplicate: true };
      }
      const integ = await q(c, 'SELECT enabled FROM crm_integrations WHERE form_id=$1', [form.id]);
      await q(c,
        `INSERT INTO crm_delivery_jobs (id, tenant_id, organization_id, submission_id, state) VALUES ($1,$2,$3,$4,$5)`,
        [nextId(), form.tenant_id, form.organization_id, id, integ.rows[0]?.enabled ? 'pending' : 'not_configured']);
      return { id, duplicate: false };
    });
    res.json({ data: { id: result.id, status: 'received', duplicate: result.duplicate } });
  }));
  app.use('/api/v1/public', pub);

  // ---------- Protected management API ----------
  const api = express.Router();
  api.use(authenticate(config));

  api.post('/forms', need('forms.write'), asyncH(async (req, res) => {
    const { name, websiteId, schema } = req.body || {};
    const errors = {};
    if (typeof name !== 'string' || !name.trim() || name.length > 200) errors.name = 'is required (max 200 chars)';
    if (!isId(websiteId)) errors.websiteId = 'must be a decimal BIGINT string';
    if (Object.keys(errors).length) throw new HttpError(422, 'validation_failed', 'Validation failed', errors);
    const origins = parseOrigins(req.body.allowedOrigins) || [];
    const normalized = schema !== undefined ? validateSchema(schema) : null;
    const ctx = req.ctx;
    const out = await tx(pool, async (c) => {
      const id = nextId();
      const f = await q(c,
        `INSERT INTO lead_capture_forms (id, tenant_id, organization_id, website_id, name, public_key, allowed_origins, created_by_user_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
        [id, ctx.tenantId, ctx.orgId, websiteId, name.trim(), `pk_${crypto.randomBytes(16).toString('hex')}`, origins, ctx.userId]);
      if (normalized) {
        await q(c, 'INSERT INTO lead_capture_form_versions (id, form_id, version, schema_json, created_by_user_id) VALUES ($1,$2,1,$3,$4)',
          [nextId(), id, normalized, ctx.userId]);
      }
      await audit(c, ctx, 'form.create', 'form', id);
      return f.rows[0];
    });
    res.json({ data: formOut(out) });
  }));

  api.get('/forms', need('forms.read'), asyncH(async (req, res) => {
    const { limit, cursor } = page(req);
    const { rows } = await pool.query(
      `SELECT * FROM lead_capture_forms WHERE tenant_id=$1 AND organization_id=$2 AND ($3::bigint IS NULL OR id < $3::bigint)
        ORDER BY id DESC LIMIT $4`, [req.ctx.tenantId, req.ctx.orgId, cursor || null, limit + 1]);
    const more = rows.length > limit;
    const data = rows.slice(0, limit).map(formOut);
    res.json({ data, nextCursor: more ? data[data.length - 1].id : null });
  }));

  api.get('/forms/:formId', need('forms.read'), asyncH(async (req, res) => {
    const f = await getForm(null, req.ctx, idParam(req, 'formId'));
    const v = await pool.query('SELECT * FROM lead_capture_form_versions WHERE form_id=$1 ORDER BY version', [f.id]);
    res.json({ data: { ...formOut(f), versions: v.rows.map(versionOut) } });
  }));

  api.patch('/forms/:formId', need('forms.write'), asyncH(async (req, res) => {
    const id = idParam(req, 'formId');
    const { name, websiteId } = req.body || {};
    const errors = {};
    if (name !== undefined && (typeof name !== 'string' || !name.trim() || name.length > 200)) errors.name = 'must be a non-empty string (max 200)';
    if (websiteId !== undefined && !isId(websiteId)) errors.websiteId = 'must be a decimal BIGINT string';
    if (Object.keys(errors).length) throw new HttpError(422, 'validation_failed', 'Validation failed', errors);
    const origins = parseOrigins(req.body.allowedOrigins);
    const out = await tx(pool, async (c) => {
      const f = await getForm(c, req.ctx, id, true);
      const r = await q(c,
        `UPDATE lead_capture_forms SET name=$2, website_id=$3, allowed_origins=$4, updated_at=now() WHERE id=$1 RETURNING *`,
        [id, name !== undefined ? name.trim() : f.name, websiteId ?? f.website_id, origins ?? f.allowed_origins]);
      await audit(c, req.ctx, 'form.update', 'form', id);
      return r.rows[0];
    });
    res.json({ data: formOut(out) });
  }));

  api.post('/forms/:formId/versions', need('forms.write'), asyncH(async (req, res) => {
    const id = idParam(req, 'formId');
    const schema = validateSchema((req.body || {}).schema);
    const out = await tx(pool, async (c) => {
      await getForm(c, req.ctx, id, true); // row lock serializes version numbering
      const n = await q(c, 'SELECT COALESCE(max(version),0)+1 AS v FROM lead_capture_form_versions WHERE form_id=$1', [id]);
      const r = await q(c,
        'INSERT INTO lead_capture_form_versions (id, form_id, version, schema_json, created_by_user_id) VALUES ($1,$2,$3,$4,$5) RETURNING *',
        [nextId(), id, n.rows[0].v, schema, req.ctx.userId]);
      await audit(c, req.ctx, 'form.version.create', 'form', id);
      return r.rows[0];
    });
    res.json({ data: versionOut(out) });
  }));

  api.post('/forms/:formId/publish', need('forms.publish'), asyncH(async (req, res) => {
    const id = idParam(req, 'formId');
    const wanted = req.body && req.body.version;
    if (wanted !== undefined && !Number.isInteger(wanted)) throw new HttpError(422, 'validation_failed', 'Validation failed', { version: 'must be an integer' });
    const out = await tx(pool, async (c) => {
      await getForm(c, req.ctx, id, true);
      const v = await q(c,
        `SELECT id FROM lead_capture_form_versions WHERE form_id=$1 ${wanted !== undefined ? 'AND version=$2' : ''} ORDER BY version DESC LIMIT 1`,
        wanted !== undefined ? [id, wanted] : [id]);
      if (!v.rows[0]) throw new HttpError(404, 'version_not_found', 'No such form version to publish');
      const r = await q(c, `UPDATE lead_capture_forms SET status='published', published_version_id=$2, updated_at=now() WHERE id=$1 RETURNING *`, [id, v.rows[0].id]);
      await audit(c, req.ctx, 'form.publish', 'form', id);
      return r.rows[0];
    });
    res.json({ data: formOut(out) });
  }));

  api.post('/forms/:formId/unpublish', need('forms.publish'), asyncH(async (req, res) => {
    const id = idParam(req, 'formId');
    const out = await tx(pool, async (c) => {
      await getForm(c, req.ctx, id, true);
      const r = await q(c, `UPDATE lead_capture_forms SET status='unpublished', published_version_id=NULL, updated_at=now() WHERE id=$1 RETURNING *`, [id]);
      await audit(c, req.ctx, 'form.unpublish', 'form', id);
      return r.rows[0];
    });
    res.json({ data: formOut(out) });
  }));

  api.get('/forms/:formId/submissions', need('submissions.read'), asyncH(async (req, res) => {
    const id = idParam(req, 'formId');
    await getForm(null, req.ctx, id);
    const { limit, cursor } = page(req);
    const { rows } = await pool.query(
      `SELECT * FROM lead_capture_submissions WHERE form_id=$1 AND tenant_id=$2 AND organization_id=$3 AND ($4::bigint IS NULL OR id < $4::bigint)
        ORDER BY id DESC LIMIT $5`, [id, req.ctx.tenantId, req.ctx.orgId, cursor || null, limit + 1]);
    const more = rows.length > limit;
    const data = rows.slice(0, limit).map(submissionOut);
    res.json({ data, nextCursor: more ? data[data.length - 1].id : null });
  }));

  const getSubmission = async (c, ctx, id) => {
    const { rows } = await q(c, 'SELECT * FROM lead_capture_submissions WHERE id=$1 AND tenant_id=$2 AND organization_id=$3', [id, ctx.tenantId, ctx.orgId]);
    if (!rows[0]) throw new HttpError(404, 'not_found', 'Submission not found');
    return rows[0];
  };

  api.get('/submissions/:submissionId', need('submissions.read'), asyncH(async (req, res) => {
    const id = idParam(req, 'submissionId');
    const s = await getSubmission(null, req.ctx, id);
    await audit(null, req.ctx, 'submission.read', 'submission', id);
    res.json({ data: submissionOut(s) });
  }));

  api.get('/submissions/:submissionId/delivery', need('delivery.read'), asyncH(async (req, res) => {
    const id = idParam(req, 'submissionId');
    await getSubmission(null, req.ctx, id);
    const j = (await pool.query('SELECT * FROM crm_delivery_jobs WHERE submission_id=$1', [id])).rows[0];
    const a = await pool.query('SELECT * FROM crm_delivery_attempts WHERE delivery_job_id=$1 ORDER BY attempt_number DESC, id DESC LIMIT 20', [j.id]);
    res.json({ data: {
      submissionId: id, state: j.state, attemptCount: j.attempt_count, nextAttemptAt: j.next_attempt_at,
      deliveredAt: j.delivered_at, externalCrmRecordId: j.external_crm_record_id, lastError: j.last_error,
      attempts: a.rows.map((r) => ({ attempt: r.attempt_number, result: r.result_class, httpStatus: r.http_status, latencyMs: r.latency_ms, errorCode: r.error_code, at: r.created_at })),
    } });
  }));

  api.post('/submissions/:submissionId/delivery/retry', need('delivery.retry'), asyncH(async (req, res) => {
    const id = idParam(req, 'submissionId');
    const out = await tx(pool, async (c) => {
      const s = await getSubmission(c, req.ctx, id);
      const j = (await q(c, 'SELECT * FROM crm_delivery_jobs WHERE submission_id=$1 FOR UPDATE', [id])).rows[0];
      if (!['needs_attention', 'dead_letter', 'not_configured'].includes(j.state)) {
        throw new HttpError(409, 'not_retryable', `Delivery is ${j.state}`);
      }
      const integ = (await q(c, 'SELECT enabled FROM crm_integrations WHERE form_id=$1', [s.form_id])).rows[0];
      if (!integ || !integ.enabled) throw new HttpError(409, 'crm_not_configured', 'CRM integration is not enabled for this form');
      await q(c, `UPDATE crm_delivery_jobs SET state='pending', attempt_count=0, next_attempt_at=now(), last_error=NULL, updated_at=now() WHERE id=$1`, [j.id]);
      await audit(c, req.ctx, 'delivery.retry', 'submission', id);
      return { submissionId: id, state: 'pending' };
    });
    res.json({ data: out });
  }));

  api.get('/forms/:formId/crm-integration', need('settings.write'), asyncH(async (req, res) => {
    const id = idParam(req, 'formId');
    await getForm(null, req.ctx, id);
    const { rows } = await pool.query('SELECT * FROM crm_integrations WHERE form_id=$1', [id]);
    if (!rows[0]) throw new HttpError(404, 'not_found', 'No CRM integration configured');
    res.json({ data: integrationOut(rows[0]) });
  }));

  api.patch('/forms/:formId/crm-integration', need('settings.write'), asyncH(async (req, res) => {
    const id = idParam(req, 'formId');
    const { enabled, destinationUrl, secretRef } = req.body || {};
    const errors = {};
    let url;
    try {
      url = new URL(destinationUrl);
      if (!['https:', 'http:'].includes(url.protocol) || (config.production && url.protocol !== 'https:')) throw new Error();
    } catch { errors.destinationUrl = config.production ? 'must be an https URL' : 'must be an http(s) URL'; }
    if (typeof secretRef !== 'string' || !/^[A-Z][A-Z0-9_]{0,63}$/.test(secretRef)) errors.secretRef = 'must be the NAME of a secret/env entry (A-Z, 0-9, _)';
    if (typeof enabled !== 'boolean') errors.enabled = 'must be boolean';
    if (Object.keys(errors).length) throw new HttpError(422, 'validation_failed', 'Validation failed', errors);
    const out = await tx(pool, async (c) => {
      await getForm(c, req.ctx, id, true);
      const r = await q(c,
        `INSERT INTO crm_integrations (id, tenant_id, organization_id, form_id, enabled, destination_url, secret_ref)
         VALUES ($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT (form_id) DO UPDATE SET enabled=$5, destination_url=$6, secret_ref=$7, updated_at=now() RETURNING *`,
        [nextId(), req.ctx.tenantId, req.ctx.orgId, id, enabled, url.toString(), secretRef]);
      await audit(c, req.ctx, 'crm_integration.update', 'form', id);
      return r.rows[0];
    });
    res.json({ data: integrationOut(out) });
  }));

  app.use('/api/v1', api);
  app.use((req, res, next) => next(new HttpError(404, 'not_found', 'Route not found')));
  app.use(errorHandler);
  return app;
}

module.exports = { createApp };
