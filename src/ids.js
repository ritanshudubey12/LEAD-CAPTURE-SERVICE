// Snowflake-style 63-bit ID generator. Returns decimal strings; IDs are never converted to Number.
const EPOCH = 1700000000000n;
const NODE = BigInt(process.env.NODE_ID || 1) & 1023n;
let lastMs = 0n;
let seq = 0n;

function nextId() {
  let now = BigInt(Date.now());
  if (now < lastMs) now = lastMs;
  if (now === lastMs) {
    seq = (seq + 1n) & 4095n;
    if (seq === 0n) now = lastMs + 1n;
  } else {
    seq = 0n;
  }
  lastMs = now;
  return (((now - EPOCH) << 22n) | (NODE << 12n) | seq).toString();
}

const MAX_BIGINT = 9223372036854775807n;

function isId(v) {
  return typeof v === 'string' && /^[1-9][0-9]{0,18}$/.test(v) && BigInt(v) <= MAX_BIGINT;
}

module.exports = { nextId, isId };
