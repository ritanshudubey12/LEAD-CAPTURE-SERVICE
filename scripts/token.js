// Prints a dev JWT plus ready-to-use headers.  Usage: npm run token [-- tenantId orgId userId]
try { process.loadEnvFile(require('path').join(__dirname, '..', '.env')); } catch { /* .env optional */ }
const jwt = require('jsonwebtoken');

const [tenantId = '1001', orgId = '2001', userId = '3001'] = process.argv.slice(2);
const token = jwt.sign(
  { sub: userId, tenant_id: tenantId, organization_ids: [orgId], permissions: ['*'] },
  process.env.JWT_SECRET,
  { algorithm: 'HS256', issuer: process.env.JWT_ISSUER || 'triostack-identity', audience: process.env.JWT_AUDIENCE || 'lead-capture-api', expiresIn: '8h' },
);
console.log(`Authorization: Bearer ${token}\nX-Tenant-Id: ${tenantId}\nX-Organization-Id: ${orgId}`);
