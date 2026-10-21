function loadConfig(env = process.env) {
  const secret = env.JWT_SECRET;
  if (!secret || secret.length < 16) throw new Error('JWT_SECRET must be set (min 16 chars)');
  return {
    port: Number(env.PORT) || 3000,
    production: env.NODE_ENV === 'production',
    jwtSecret: secret,
    jwtIssuer: env.JWT_ISSUER || 'triostack-identity',
    jwtAudience: env.JWT_AUDIENCE || 'lead-capture-api',
    maxBodyBytes: env.MAX_BODY_BYTES || '32kb',
    trustProxy: env.TRUST_PROXY === 'true',
    metricsToken: env.METRICS_TOKEN || '',
    rateLimit: { max: Number(env.RATE_LIMIT_MAX) || 30, windowMs: Number(env.RATE_LIMIT_WINDOW_MS) || 60000 },
    db: {
      host: env.DB_HOST || 'localhost',
      port: Number(env.DB_PORT) || 5432,
      user: env.DB_USER || 'postgres',
      password: env.DB_PASSWORD || 'postgres',
      database: env.DB_NAME || 'leads',
    },
    worker: {
      intervalMs: Number(env.WORKER_INTERVAL_MS) || 2000,
      maxAttempts: Number(env.CRM_MAX_ATTEMPTS) || 5,
      baseDelayMs: Number(env.CRM_BASE_DELAY_MS) || 2000,
      timeoutMs: Number(env.CRM_TIMEOUT_MS) || 10000,
    },
  };
}

module.exports = { loadConfig };
