const jwt = require('jsonwebtoken');
const { HttpError } = require('./http');
const { isId } = require('./ids');

const asId = (v) => (typeof v === 'number' && Number.isSafeInteger(v) ? String(v) : v);

// Verifies the Bearer JWT, derives the user from claims only (X-User-Id is ignored),
// and validates X-Tenant-Id / X-Organization-Id selectors against the verified claims.
function authenticate(config) {
  return (req, res, next) => {
    const m = /^Bearer\s+([A-Za-z0-9._~+/=-]+)$/i.exec(req.headers.authorization || '');
    if (!m) return next(new HttpError(401, 'unauthorized', 'Missing or malformed Bearer token'));

    let claims;
    try {
      claims = jwt.verify(m[1], config.jwtSecret, {
        algorithms: ['HS256'],
        issuer: config.jwtIssuer,
        audience: config.jwtAudience,
        clockTolerance: 5,
      });
    } catch (e) {
      return next(new HttpError(401, 'unauthorized', 'Invalid or expired token'));
    }
    if (!claims.exp) return next(new HttpError(401, 'unauthorized', 'Token has no expiry'));

    const userId = asId(claims.sub);
    const tenantId = asId(claims.tenant_id);
    let orgIds = claims.organization_ids ?? claims.organization_id;
    orgIds = (Array.isArray(orgIds) ? orgIds : [orgIds]).map(asId);
    if (!isId(userId) || !isId(tenantId) || !orgIds.length || !orgIds.every(isId)) {
      return next(new HttpError(401, 'unauthorized', 'Token is missing required identity claims'));
    }

    const tenantHeader = req.headers['x-tenant-id'];
    if (tenantHeader !== undefined && tenantHeader !== tenantId) {
      return next(new HttpError(403, 'forbidden', 'Tenant not permitted for this token'));
    }

    let orgId = req.headers['x-organization-id'];
    if (orgId === undefined) {
      if (orgIds.length !== 1) {
        return next(new HttpError(400, 'organization_required', 'X-Organization-Id header is required'));
      }
      orgId = orgIds[0];
    } else if (!orgIds.includes(orgId)) {
      return next(new HttpError(403, 'forbidden', 'Organization not permitted for this token'));
    }

    const perms = Array.isArray(claims.permissions) ? claims.permissions : [];
    req.ctx = { userId, tenantId, orgId, perms: new Set(perms), requestId: req.requestId };
    next();
  };
}

const need = (perm) => (req, res, next) =>
  req.ctx.perms.has(perm) || req.ctx.perms.has('*')
    ? next()
    : next(new HttpError(403, 'forbidden', `Missing permission ${perm}`));

module.exports = { authenticate, need };
