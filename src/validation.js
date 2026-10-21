const { HttpError } = require('./http');

const FIELD_TYPES = new Set(['text', 'email', 'phone', 'textarea', 'select']);
const NAME_RE = /^[a-z][a-z0-9_]{0,63}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PHONE_RE = /^[+0-9 ()-]{6,20}$/;

const fail = (details) => new HttpError(422, 'validation_failed', 'Validation failed', details);

function validateSchema(schema) {
  const errors = {};
  if (!schema || typeof schema !== 'object' || !Array.isArray(schema.fields)) {
    throw fail({ schema: 'must be an object with a fields array' });
  }
  if (schema.fields.length < 1 || schema.fields.length > 50) errors.fields = 'must contain 1-50 fields';
  const seen = new Set();
  const fields = [];
  schema.fields.slice(0, 50).forEach((f, i) => {
    const p = `fields[${i}]`;
    if (!f || typeof f !== 'object') return (errors[p] = 'must be an object');
    if (typeof f.name !== 'string' || !NAME_RE.test(f.name)) errors[`${p}.name`] = 'must match ^[a-z][a-z0-9_]{0,63}$';
    else if (seen.has(f.name)) errors[`${p}.name`] = 'duplicate field name';
    else seen.add(f.name);
    if (!FIELD_TYPES.has(f.type)) errors[`${p}.type`] = `must be one of ${[...FIELD_TYPES].join(', ')}`;
    if (f.type === 'select' && (!Array.isArray(f.options) || !f.options.length || !f.options.every((o) => typeof o === 'string'))) {
      errors[`${p}.options`] = 'select fields need a non-empty string options array';
    }
    if (f.maxLength !== undefined && !(Number.isInteger(f.maxLength) && f.maxLength > 0 && f.maxLength <= 5000)) {
      errors[`${p}.maxLength`] = 'must be an integer 1-5000';
    }
    fields.push({
      name: f.name, type: f.type, label: typeof f.label === 'string' ? f.label : f.name,
      required: f.required === true, maxLength: f.maxLength, options: f.options,
    });
  });
  if (Object.keys(errors).length) throw fail(errors);
  return { fields, consentRequired: schema.consentRequired === true };
}

// Validates a public submission against the published schema; returns normalized values.
function validateSubmission(schema, body) {
  const errors = {};
  if (!body || typeof body.fields !== 'object' || body.fields === null || Array.isArray(body.fields)) {
    throw fail({ fields: 'must be an object' });
  }
  const known = new Map(schema.fields.map((f) => [f.name, f]));
  for (const k of Object.keys(body.fields)) if (!known.has(k)) errors[k] = 'unknown field';

  const out = {};
  for (const f of schema.fields) {
    let v = body.fields[f.name];
    if (v === undefined || v === null || (typeof v === 'string' && v.trim() === '')) {
      if (f.required) errors[f.name] = 'is required';
      continue;
    }
    if (typeof v !== 'string') { errors[f.name] = 'must be a string'; continue; }
    v = v.trim();
    if (f.type === 'email') v = v.toLowerCase();
    const max = f.maxLength || (f.type === 'textarea' ? 5000 : f.type === 'email' ? 254 : 1000);
    if (v.length > max) errors[f.name] = `must be at most ${max} characters`;
    else if (f.type === 'email' && !EMAIL_RE.test(v)) errors[f.name] = 'must be a valid email';
    else if (f.type === 'phone' && !PHONE_RE.test(v)) errors[f.name] = 'must be a valid phone number';
    else if (f.type === 'select' && !f.options.includes(v)) errors[f.name] = 'is not an allowed value';
    else out[f.name] = v;
  }

  let consent = null;
  if (body.consent !== undefined) {
    if (!body.consent || typeof body.consent !== 'object') errors.consent = 'must be an object';
    else consent = { accepted: body.consent.accepted === true, policyVersion: String(body.consent.policyVersion ?? '').slice(0, 64) };
  }
  if (schema.consentRequired && !(consent && consent.accepted)) errors.consent = 'consent must be accepted';

  if (Object.keys(errors).length) throw fail(errors);
  return { fields: out, consent };
}

module.exports = { validateSchema, validateSubmission };
