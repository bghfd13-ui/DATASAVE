'use strict';

const crypto = require('node:crypto');
const express = require('express');
const { Pool } = require('pg');

const PORT = Number(process.env.PORT || 10000);
const DATABASE_URL = process.env.DATABASE_URL;
const API_KEY = process.env.DATASTORE_API_KEY;
const ALLOWED_UNIVERSE_ID = String(process.env.ALLOWED_UNIVERSE_ID || '173164');

if (!DATABASE_URL) throw new Error('DATABASE_URL is required');
if (!API_KEY || API_KEY.length < 24) {
  throw new Error('DATASTORE_API_KEY is required and must contain at least 24 characters');
}

const pool = new Pool({ connectionString: DATABASE_URL, max: 10 });
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '256kb', strict: true }));

const rateBuckets = new Map();
const RATE_WINDOW_MS = 60_000;
const RATE_LIMIT = Number(process.env.RATE_LIMIT_PER_MINUTE || 1200);

function jsonError(res, status, code, message) {
  return res.status(status).json({ ok: false, code, error: message });
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left || ''), 'utf8');
  const b = Buffer.from(String(right || ''), 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function rateLimit(req, res, next) {
  const now = Date.now();
  const key = req.ip || req.socket.remoteAddress || 'unknown';
  let bucket = rateBuckets.get(key);
  if (!bucket || now - bucket.startedAt >= RATE_WINDOW_MS) {
    bucket = { startedAt: now, count: 0 };
    rateBuckets.set(key, bucket);
  }
  bucket.count += 1;
  if (bucket.count > RATE_LIMIT) {
    return jsonError(res, 429, 'rate_limited', 'Too many requests');
  }
  next();
}

function authenticate(req, res, next) {
  const body = req.body || {};
  if (!safeEqual(body.apiKey, API_KEY)) {
    return jsonError(res, 401, 'unauthorized', 'Invalid API key');
  }
  if (String(body.universeId || '') !== ALLOWED_UNIVERSE_ID) {
    return jsonError(res, 403, 'wrong_universe', 'Universe is not allowed');
  }
  next();
}

function cleanText(value, field, maxLength, allowEmpty = false) {
  const text = String(value == null ? '' : value);
  if ((!allowEmpty && text.length === 0) || text.length > maxLength || /[\u0000-\u001f]/.test(text)) {
    const error = new Error(`Invalid ${field}`);
    error.status = 400;
    error.code = 'invalid_identity';
    throw error;
  }
  return text;
}

function identity(body) {
  const kind = cleanText(body.kind || 'normal', 'kind', 16);
  if (!['normal', 'ordered', 'global'].includes(kind)) {
    const error = new Error('Invalid kind');
    error.status = 400;
    error.code = 'invalid_kind';
    throw error;
  }
  return {
    universeId: ALLOWED_UNIVERSE_ID,
    kind,
    name: cleanText(body.name, 'name', 80),
    scope: cleanText(body.scope == null ? 'global' : body.scope, 'scope', 80, true),
    key: cleanText(body.key, 'key', 160),
  };
}

function params(id) {
  return [id.universeId, id.kind, id.name, id.scope, id.key];
}

function finiteNumber(value, field) {
  const number = Number(value);
  if (!Number.isFinite(number)) {
    const error = new Error(`Invalid ${field}`);
    error.status = 400;
    error.code = 'invalid_number';
    throw error;
  }
  return number;
}

function numericValue(value) {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS datastore_entries (
      universe_id TEXT NOT NULL,
      store_kind TEXT NOT NULL,
      store_name TEXT NOT NULL,
      scope TEXT NOT NULL,
      entry_key TEXT NOT NULL,
      value JSONB NOT NULL,
      numeric_value DOUBLE PRECISION,
      version BIGINT NOT NULL DEFAULT 1,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (universe_id, store_kind, store_name, scope, entry_key)
    )
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS datastore_ordered_lookup
    ON datastore_entries (universe_id, store_kind, store_name, scope, numeric_value)
    WHERE numeric_value IS NOT NULL
  `);
}

app.get('/healthz', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, service: 'pekora-global-datastore' });
  } catch (_error) {
    res.status(503).json({ ok: false, service: 'pekora-global-datastore' });
  }
});

app.use('/v1', rateLimit, authenticate);

app.post('/v1/get', async (req, res, next) => {
  try {
    const id = identity(req.body);
    const result = await pool.query(
      `SELECT value, version::text AS version
       FROM datastore_entries
       WHERE universe_id=$1 AND store_kind=$2 AND store_name=$3 AND scope=$4 AND entry_key=$5`,
      params(id),
    );
    if (result.rowCount === 0) return res.json({ ok: true, found: false, version: '0' });
    return res.json({ ok: true, found: true, value: result.rows[0].value, version: result.rows[0].version });
  } catch (error) {
    next(error);
  }
});

app.post('/v1/set', async (req, res, next) => {
  try {
    const id = identity(req.body);
    if (!Object.prototype.hasOwnProperty.call(req.body, 'value')) {
      return jsonError(res, 400, 'missing_value', 'value is required');
    }
    const value = req.body.value;
    const result = await pool.query(
      `INSERT INTO datastore_entries
         (universe_id, store_kind, store_name, scope, entry_key, value, numeric_value, version)
       VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,1)
       ON CONFLICT (universe_id, store_kind, store_name, scope, entry_key)
       DO UPDATE SET value=EXCLUDED.value,
                     numeric_value=EXCLUDED.numeric_value,
                     version=datastore_entries.version+1,
                     updated_at=NOW()
       RETURNING version::text AS version`,
      [...params(id), JSON.stringify(value), numericValue(value)],
    );
    res.json({ ok: true, version: result.rows[0].version });
  } catch (error) {
    next(error);
  }
});

app.post('/v1/cas', async (req, res, next) => {
  try {
    const id = identity(req.body);
    if (!Object.prototype.hasOwnProperty.call(req.body, 'value')) {
      return jsonError(res, 400, 'missing_value', 'value is required');
    }
    const expectedVersion = Number(req.body.expectedVersion);
    if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 0) {
      return jsonError(res, 400, 'invalid_version', 'expectedVersion must be a non-negative integer');
    }
    const value = req.body.value;
    let result;
    if (expectedVersion === 0) {
      result = await pool.query(
        `INSERT INTO datastore_entries
           (universe_id, store_kind, store_name, scope, entry_key, value, numeric_value, version)
         VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,1)
         ON CONFLICT DO NOTHING
         RETURNING version::text AS version`,
        [...params(id), JSON.stringify(value), numericValue(value)],
      );
    } else {
      result = await pool.query(
        `UPDATE datastore_entries
         SET value=$6::jsonb, numeric_value=$7, version=version+1, updated_at=NOW()
         WHERE universe_id=$1 AND store_kind=$2 AND store_name=$3 AND scope=$4 AND entry_key=$5
           AND version=$8
         RETURNING version::text AS version`,
        [...params(id), JSON.stringify(value), numericValue(value), expectedVersion],
      );
    }
    if (result.rowCount === 0) {
      return res.json({ ok: false, conflict: true, code: 'version_conflict' });
    }
    res.json({ ok: true, version: result.rows[0].version });
  } catch (error) {
    next(error);
  }
});

app.post('/v1/remove', async (req, res, next) => {
  try {
    const id = identity(req.body);
    const result = await pool.query(
      `DELETE FROM datastore_entries
       WHERE universe_id=$1 AND store_kind=$2 AND store_name=$3 AND scope=$4 AND entry_key=$5
       RETURNING value`,
      params(id),
    );
    if (result.rowCount === 0) return res.json({ ok: true, found: false });
    res.json({ ok: true, found: true, value: result.rows[0].value });
  } catch (error) {
    next(error);
  }
});

app.post('/v1/increment', async (req, res, next) => {
  try {
    const id = identity(req.body);
    const delta = finiteNumber(req.body.delta == null ? 1 : req.body.delta, 'delta');
    const result = await pool.query(
      `INSERT INTO datastore_entries
         (universe_id, store_kind, store_name, scope, entry_key, value, numeric_value, version)
       VALUES ($1,$2,$3,$4,$5,to_jsonb($6::double precision),$6,1)
       ON CONFLICT (universe_id, store_kind, store_name, scope, entry_key)
       DO UPDATE SET numeric_value=COALESCE(datastore_entries.numeric_value,0)+$6,
                     value=to_jsonb((COALESCE(datastore_entries.numeric_value,0)+$6)::double precision),
                     version=datastore_entries.version+1,
                     updated_at=NOW()
       RETURNING numeric_value AS value, version::text AS version`,
      [...params(id), delta],
    );
    res.json({ ok: true, value: result.rows[0].value, version: result.rows[0].version });
  } catch (error) {
    next(error);
  }
});

app.post('/v1/ordered', async (req, res, next) => {
  try {
    const id = identity(req.body);
    const ascending = req.body.ascending === true;
    const pageSize = Math.max(1, Math.min(100, Number(req.body.pageSize) || 50));
    const minimum = req.body.minimum == null ? null : finiteNumber(req.body.minimum, 'minimum');
    const maximum = req.body.maximum == null ? null : finiteNumber(req.body.maximum, 'maximum');
    const direction = ascending ? 'ASC' : 'DESC';
    const result = await pool.query(
      `SELECT entry_key AS key, numeric_value AS value
       FROM datastore_entries
       WHERE universe_id=$1 AND store_kind=$2 AND store_name=$3 AND scope=$4
         AND numeric_value IS NOT NULL
         AND ($5::double precision IS NULL OR numeric_value >= $5)
         AND ($6::double precision IS NULL OR numeric_value <= $6)
       ORDER BY numeric_value ${direction}, entry_key ASC
       LIMIT $7`,
      [id.universeId, id.kind, id.name, id.scope, minimum, maximum, pageSize],
    );
    res.json({ ok: true, entries: result.rows });
  } catch (error) {
    next(error);
  }
});

app.use((error, _req, res, _next) => {
  console.error(error && error.stack ? error.stack : error);
  jsonError(res, error.status || 500, error.code || 'server_error', error.status ? error.message : 'Internal server error');
});

let server;
async function start() {
  await initializeDatabase();
  server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`pekora-global-datastore listening on 0.0.0.0:${PORT}`);
  });
}

async function shutdown(signal) {
  console.log(`${signal}: shutting down`);
  if (server) await new Promise((resolve) => server.close(resolve));
  await pool.end();
  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

if (require.main === module) {
  start().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}

module.exports = { app, initializeDatabase, pool };
