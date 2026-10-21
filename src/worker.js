const { nextId } = require('./ids');

const backoffMs = (n, base, retryAfterSec) => {
  if (retryAfterSec) return retryAfterSec * 1000;
  return Math.min(base * 2 ** (n - 1), 3600000) * (1 + Math.random() * 0.2);
};

function classify(status) {
  if (status >= 200 && status < 300) return 'delivered';
  if (status === 429 || status >= 500) return 'transient';
  return 'permanent'; // 400/422/401/403/other 4xx: do not hammer the CRM
}

async function deliver(pool, jobId, opts) {
  const { rows } = await pool.query(
    `SELECT j.id, j.attempt_count, j.submission_id, s.fields_json, s.consent_json, s.received_at, s.form_id,
            i.enabled, i.destination_url, i.secret_ref
       FROM crm_delivery_jobs j
       JOIN lead_capture_submissions s ON s.id = j.submission_id
       LEFT JOIN crm_integrations i ON i.form_id = s.form_id
      WHERE j.id = $1`, [jobId]);
  const job = rows[0];
  if (!job) return;

  const finish = (state, extra = {}) => pool.query(
    `UPDATE crm_delivery_jobs SET state = $2, attempt_count = $3, next_attempt_at = COALESCE($4, now()),
            delivered_at = $5, external_crm_record_id = $6, last_error = $7, updated_at = now() WHERE id = $1`,
    [jobId, state, extra.attempts ?? job.attempt_count, extra.nextAt ?? null, extra.deliveredAt ?? null,
      extra.externalId ?? null, extra.error ?? null]);
  const record = (n, cls, status, latency, code) => pool.query(
    `INSERT INTO crm_delivery_attempts (id, delivery_job_id, attempt_number, result_class, http_status, latency_ms, error_code)
     VALUES ($1,$2,$3,$4,$5,$6,$7)`, [nextId(), jobId, n, cls, status, latency, code]);

  if (!job.enabled) return finish('not_configured');

  const attempt = job.attempt_count + 1;
  const secret = process.env[job.secret_ref];
  if (!secret) {
    await record(attempt, 'permanent', null, 0, 'credential_missing');
    return finish('needs_attention', { attempts: attempt, error: 'credential_missing' });
  }

  const started = Date.now();
  let status = null;
  let body = null;
  let retryAfter = null;
  let errorCode = null;
  try {
    const res = await opts.fetchImpl(job.destination_url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${secret}`,
        'Idempotency-Key': job.submission_id,
      },
      body: JSON.stringify({
        externalRef: job.submission_id, formId: job.form_id, fields: job.fields_json,
        consent: job.consent_json, receivedAt: job.received_at,
      }),
      signal: AbortSignal.timeout(opts.timeoutMs),
    });
    status = res.status;
    retryAfter = Number(res.headers.get('retry-after')) || null;
    body = await res.json().catch(() => null);
  } catch (e) {
    errorCode = e.name === 'TimeoutError' ? 'timeout' : 'network_error';
  }

  const latency = Date.now() - started;
  const cls = status === null ? 'transient' : classify(status);
  errorCode = errorCode || (cls === 'delivered' ? null : `http_${status}`);
  await record(attempt, cls, status, latency, errorCode);

  if (cls === 'delivered') {
    const ext = body && (body.id ?? body.recordId);
    return finish('delivered', { attempts: attempt, deliveredAt: new Date(), externalId: ext != null ? String(ext) : null });
  }
  if (cls === 'permanent') return finish('needs_attention', { attempts: attempt, error: errorCode });
  if (attempt >= opts.maxAttempts) return finish('dead_letter', { attempts: attempt, error: errorCode });
  const delay = backoffMs(attempt, opts.baseDelayMs, retryAfter);
  return finish('pending', { attempts: attempt, error: errorCode, nextAt: new Date(Date.now() + delay) });
}

// Claims due jobs (60s lease, SKIP LOCKED so multiple workers are safe) and delivers them.
async function runOnce(pool, options = {}) {
  const opts = { fetchImpl: fetch, maxAttempts: 5, baseDelayMs: 2000, timeoutMs: 10000, batch: 20, ...options };
  const { rows } = await pool.query(
    `UPDATE crm_delivery_jobs SET next_attempt_at = now() + interval '60 seconds'
      WHERE id IN (SELECT id FROM crm_delivery_jobs WHERE state = 'pending' AND next_attempt_at <= now()
                    ORDER BY next_attempt_at LIMIT $1 FOR UPDATE SKIP LOCKED)
      RETURNING id`, [opts.batch]);
  for (const r of rows) {
    try { await deliver(pool, r.id, opts); } catch (e) {
      console.error(JSON.stringify({ level: 'error', job: r.id, msg: e.message }));
    }
  }
  return rows.length;
}

function startWorker(pool, options) {
  let stopped = false;
  let timer;
  const loop = async () => {
    try { await runOnce(pool, options); } catch (e) { console.error(JSON.stringify({ level: 'error', msg: e.message })); }
    if (!stopped) timer = setTimeout(loop, options.intervalMs || 2000);
  };
  loop();
  return () => { stopped = true; clearTimeout(timer); };
}

module.exports = { runOnce, startWorker };
