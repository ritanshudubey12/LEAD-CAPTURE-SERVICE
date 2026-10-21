class HttpError extends Error {
  constructor(status, code, message, details) {
    super(message || code);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

const asyncH = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function errorHandler(err, req, res, next) { // eslint-disable-line no-unused-vars
  let status = 500;
  let body = { code: 'internal_error', message: 'Internal server error' };
  if (err instanceof HttpError) {
    status = err.status;
    body = { code: err.code, message: err.message, ...(err.details ? { details: err.details } : {}) };
  } else if (err.type === 'entity.too.large') {
    status = 413;
    body = { code: 'payload_too_large', message: 'Request body too large' };
  } else if (err.type === 'entity.parse.failed') {
    status = 400;
    body = { code: 'invalid_json', message: 'Request body is not valid JSON' };
  } else if (err.code === '23505') {
    status = 409;
    body = { code: 'conflict', message: 'Resource already exists' };
  } else {
    console.error(JSON.stringify({ level: 'error', requestId: req.requestId, msg: err.message }));
  }
  res.status(status).json({ error: body, requestId: req.requestId });
}

module.exports = { HttpError, asyncH, errorHandler };
