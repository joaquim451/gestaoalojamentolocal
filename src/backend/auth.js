const crypto = require('crypto');

const TOKEN_TTL_SECONDS = Number(process.env.AUTH_TOKEN_TTL_SECONDS || 60 * 60 * 12);

function toBase64Url(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function fromBase64Url(input) {
  const normalized = String(input).replace(/-/g, '+').replace(/_/g, '/');
  const padding = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  return Buffer.from(`${normalized}${padding}`, 'base64');
}

function getJwtSecret() {
  return process.env.AUTH_JWT_SECRET || 'dev-only-change-this-secret';
}

function hashPassword(plainTextPassword) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(plainTextPassword), salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(plainTextPassword, passwordHash) {
  const [salt, storedHash] = String(passwordHash || '').split(':');
  if (!salt || !storedHash) {
    return false;
  }

  const computedHash = crypto.scryptSync(String(plainTextPassword), salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(storedHash, 'hex'), Buffer.from(computedHash, 'hex'));
}

function createToken(payload) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'HS256', typ: 'JWT' };
  const body = {
    ...payload,
    iat: now,
    exp: now + TOKEN_TTL_SECONDS
  };

  const encodedHeader = toBase64Url(JSON.stringify(header));
  const encodedBody = toBase64Url(JSON.stringify(body));
  const signature = crypto
    .createHmac('sha256', getJwtSecret())
    .update(`${encodedHeader}.${encodedBody}`)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  return `${encodedHeader}.${encodedBody}.${signature}`;
}

function verifyToken(token) {
  const [encodedHeader, encodedBody, encodedSignature] = String(token || '').split('.');
  if (!encodedHeader || !encodedBody || !encodedSignature) {
    return { ok: false, error: 'Token malformado.' };
  }

  const expectedSignature = crypto
    .createHmac('sha256', getJwtSecret())
    .update(`${encodedHeader}.${encodedBody}`)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  if (encodedSignature !== expectedSignature) {
    return { ok: false, error: 'Assinatura inválida.' };
  }

  let payload;
  try {
    payload = JSON.parse(fromBase64Url(encodedBody).toString('utf8'));
  } catch (_error) {
    return { ok: false, error: 'Payload do token inválido.' };
  }

  const now = Math.floor(Date.now() / 1000);
  if (!payload.exp || payload.exp < now) {
    return { ok: false, error: 'Token expirado.' };
  }

  return { ok: true, payload };
}

module.exports = {
  hashPassword,
  verifyPassword,
  createToken,
  verifyToken
};
