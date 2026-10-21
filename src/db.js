const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

// pg returns BIGINT as strings by default; that is relied upon so IDs never touch Number.
const createPool = (db) => new Pool(db);

async function migrate(pool) {
  const sql = fs.readFileSync(path.join(__dirname, '..', 'db', 'schema.sql'), 'utf8');
  const c = await pool.connect();
  try {
    await c.query('SELECT pg_advisory_lock(727274)'); // safe with several instances starting together
    await c.query(sql);
  } finally {
    await c.query('SELECT pg_advisory_unlock(727274)').catch(() => {});
    c.release();
  }
}

async function tx(pool, fn) {
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const r = await fn(c);
    await c.query('COMMIT');
    return r;
  } catch (e) {
    await c.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    c.release();
  }
}

module.exports = { createPool, migrate, tx };
