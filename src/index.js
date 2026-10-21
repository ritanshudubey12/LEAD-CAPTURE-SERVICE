const { loadConfig } = require('./config');
const { createPool, migrate } = require('./db');
const { createApp } = require('./app');
const { startWorker } = require('./worker');

async function main() {
  const config = loadConfig();
  const pool = createPool(config.db);
  for (let i = 0; ; i++) { // wait for the database
    try { await migrate(pool); break; } catch (e) {
      if (i >= 20) throw e;
      await new Promise((r) => setTimeout(r, 1500));
    }
  }
  const app = createApp({ pool, config });
  const server = app.listen(config.port, () => console.log(`Lead Capture API listening on ${config.port}`));
  const stopWorker = startWorker(pool, config.worker);
  const shutdown = () => { stopWorker(); server.close(() => pool.end().then(() => process.exit(0))); };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((e) => { console.error(e); process.exit(1); });
