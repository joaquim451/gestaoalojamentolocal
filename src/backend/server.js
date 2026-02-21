const express = require('express');
const morgan = require('morgan');
const crypto = require('crypto');
const { readDb, writeDb, nextId } = require('./store');
const { getBookingConfig, pingBookingConnection, syncAccommodation } = require('./bookingClient');
const { hashPassword, verifyPassword, createToken, verifyToken } = require('./auth');

const app = express();
const port = Number(process.env.PORT || 3000);
const RESERVATION_STATUSES = new Set(['confirmed', 'cancelled', 'checked_in', 'checked_out']);
const USER_ROLES = new Set(['admin', 'manager']);
const AUTH_PASSWORD_MIN_LENGTH = Number(process.env.AUTH_PASSWORD_MIN_LENGTH || 10);
const AUTH_LOGIN_MAX_ATTEMPTS = Number(process.env.AUTH_LOGIN_MAX_ATTEMPTS || 5);
const AUTH_LOGIN_LOCK_MINUTES = Number(process.env.AUTH_LOGIN_LOCK_MINUTES || 15);
const AUTH_REFRESH_TOKEN_TTL_DAYS = Number(process.env.AUTH_REFRESH_TOKEN_TTL_DAYS || 30);

app.use(express.json());
app.use(morgan('dev'));

function isValidIsoDate(value) {
  if (!value || typeof value !== 'string') {
    return false;
  }
  return !Number.isNaN(Date.parse(value));
}

function hasDateRangeOverlap(aStart, aEnd, bStart, bEnd) {
  return new Date(aStart) < new Date(bEnd) && new Date(aEnd) > new Date(bStart);
}

function formatIsoDateOnly(inputDate) {
  return new Date(inputDate).toISOString().slice(0, 10);
}

function addDays(inputDate, days) {
  const date = new Date(inputDate);
  date.setUTCDate(date.getUTCDate() + days);
  return date;
}

function countNights(checkIn, checkOut) {
  const start = new Date(checkIn);
  const end = new Date(checkOut);
  return Math.floor((end - start) / (24 * 60 * 60 * 1000));
}

function getNow() {
  if (process.env.TEST_NOW && isValidIsoDate(process.env.TEST_NOW)) {
    return new Date(process.env.TEST_NOW);
  }
  return new Date();
}

function normalizeWeekdaysInput(value) {
  if (!Array.isArray(value)) {
    return [];
  }

  const normalized = value
    .map((item) => Number.parseInt(item, 10))
    .filter((item) => Number.isInteger(item) && item >= 0 && item <= 6);

  return [...new Set(normalized)];
}

function intersectWeekdaySets(weekdaySets) {
  if (!Array.isArray(weekdaySets) || weekdaySets.length === 0) {
    return [];
  }

  let intersection = [...weekdaySets[0]];
  for (let i = 1; i < weekdaySets.length; i += 1) {
    intersection = intersection.filter((day) => weekdaySets[i].includes(day));
  }
  return intersection;
}

function pickSeasonalMultiplier(seasonalAdjustments, dateStr) {
  if (!Array.isArray(seasonalAdjustments)) {
    return 1;
  }
  for (const item of seasonalAdjustments) {
    if (!item || !item.startDate || !item.endDate || !item.multiplier) {
      continue;
    }
    if (dateStr >= item.startDate && dateStr <= item.endDate) {
      return Number(item.multiplier) || 1;
    }
  }
  return 1;
}

function pickAvailabilityConstraints(availabilityRules, accommodationId, dateStr) {
  const matching = (availabilityRules || []).filter((item) => {
    return item.accommodationId === accommodationId && dateStr >= item.startDate && dateStr <= item.endDate;
  });

  const positiveMaxNights = matching
    .map((item) => Number(item.maxNights) || 0)
    .filter((value) => value > 0);

  const positiveMaxAdvanceDays = matching
    .map((item) => Number(item.maxAdvanceDays) || 0)
    .filter((value) => value > 0);

  const arrivalWeekdaySets = matching
    .map((item) => normalizeWeekdaysInput(item.allowedArrivalWeekdays))
    .filter((days) => days.length > 0);

  const departureWeekdaySets = matching
    .map((item) => normalizeWeekdaysInput(item.allowedDepartureWeekdays))
    .filter((days) => days.length > 0);

  return {
    closed: matching.some((item) => Boolean(item.closed)),
    closedToArrival: matching.some((item) => Boolean(item.closedToArrival)),
    closedToDeparture: matching.some((item) => Boolean(item.closedToDeparture)),
    minNights: matching.reduce((acc, item) => Math.max(acc, Number(item.minNights) || 0), 0),
    maxNights: positiveMaxNights.length > 0 ? Math.min(...positiveMaxNights) : 0,
    minAdvanceHours: matching.reduce((acc, item) => Math.max(acc, Number(item.minAdvanceHours) || 0), 0),
    maxAdvanceDays: positiveMaxAdvanceDays.length > 0 ? Math.min(...positiveMaxAdvanceDays) : 0,
    allowedArrivalWeekdays: arrivalWeekdaySets.length > 0 ? intersectWeekdaySets(arrivalWeekdaySets) : [],
    allowedDepartureWeekdays: departureWeekdaySets.length > 0 ? intersectWeekdaySets(departureWeekdaySets) : [],
    matchingRuleIds: matching.map((item) => item.id)
  };
}

function normalizeUsersCollection(db) {
  if (!Array.isArray(db.users)) {
    db.users = [];
  }
}

function normalizeAuditLogsCollection(db) {
  if (!Array.isArray(db.auditLogs)) {
    db.auditLogs = [];
  }
}

function normalizeAuthSessionsCollection(db) {
  if (!Array.isArray(db.authSessions)) {
    db.authSessions = [];
  }
}

function normalizeDomainCollections(db) {
  if (!Array.isArray(db.accommodations)) {
    db.accommodations = [];
  }
  if (!Array.isArray(db.reservations)) {
    db.reservations = [];
  }
  if (!Array.isArray(db.ratePlans)) {
    db.ratePlans = [];
  }
  if (!Array.isArray(db.availabilityRules)) {
    db.availabilityRules = [];
  }
}

function buildOpaqueToken() {
  return crypto.randomBytes(48).toString('base64url');
}

function hashOpaqueToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

function createRefreshSession(db, userId) {
  normalizeAuthSessionsCollection(db);
  const refreshToken = buildOpaqueToken();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + AUTH_REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000);

  const session = {
    id: nextId('sess'),
    userId,
    tokenHash: hashOpaqueToken(refreshToken),
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
    lastUsedAt: null,
    expiresAt: expiresAt.toISOString(),
    revokedAt: null
  };

  db.authSessions.push(session);
  return { refreshToken, session };
}

function findActiveSessionByRefreshToken(db, refreshToken) {
  normalizeAuthSessionsCollection(db);
  const tokenHash = hashOpaqueToken(refreshToken);
  const session = db.authSessions.find((item) => item.tokenHash === tokenHash);
  if (!session) {
    return { ok: false, error: 'Sessao nao encontrada.' };
  }
  if (session.revokedAt) {
    return { ok: false, error: 'Sessao revogada.' };
  }
  if (new Date(session.expiresAt) <= new Date()) {
    return { ok: false, error: 'Sessao expirada.' };
  }
  return { ok: true, session };
}

function appendAuditLog(db, event) {
  normalizeAuditLogsCollection(db);
  db.auditLogs.push({
    id: nextId('audit'),
    at: new Date().toISOString(),
    ...event
  });
}

function parsePositiveInt(value, fallback, min, max) {
  const parsed = Number.parseInt(value, 10);
  if (Number.isNaN(parsed)) {
    return fallback;
  }
  return Math.min(Math.max(parsed, min), max);
}

function parseSortDir(value, fallback = 'desc') {
  return String(value || '').toLowerCase() === 'asc' ? 'asc' : fallback;
}

function compareValues(a, b) {
  const aDate = Date.parse(a);
  const bDate = Date.parse(b);
  const bothDates = !Number.isNaN(aDate) && !Number.isNaN(bDate);
  if (bothDates) {
    return aDate - bDate;
  }

  const aNumber = Number(a);
  const bNumber = Number(b);
  const bothNumbers = !Number.isNaN(aNumber) && !Number.isNaN(bNumber);
  if (bothNumbers) {
    return aNumber - bNumber;
  }

  return String(a || '').localeCompare(String(b || ''), 'pt-PT', { sensitivity: 'base' });
}

function sortItems(items, sortBy, sortDir) {
  const direction = sortDir === 'asc' ? 1 : -1;
  return [...items].sort((left, right) => direction * compareValues(left[sortBy], right[sortBy]));
}

function paginateItems(items, page, pageSize) {
  const total = items.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const safePage = Math.min(page, totalPages);
  const start = (safePage - 1) * pageSize;
  return {
    data: items.slice(start, start + pageSize),
    meta: { page: safePage, pageSize, total, totalPages }
  };
}

function serializeUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    failedLoginAttempts: Number(user.failedLoginAttempts || 0),
    lockUntil: user.lockUntil || null,
    lastFailedLoginAt: user.lastFailedLoginAt || null,
    lastLoginAt: user.lastLoginAt || null,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt
  };
}

function isUserLocked(user) {
  if (!user || !user.lockUntil) {
    return false;
  }
  return new Date(user.lockUntil) > new Date();
}

function ensureBootstrapAdmin(db) {
  normalizeUsersCollection(db);
  if (db.users.length > 0) {
    return null;
  }

  const now = new Date().toISOString();
  const bootstrapUser = {
    id: nextId('usr'),
    name: process.env.AUTH_BOOTSTRAP_ADMIN_NAME || 'Admin',
    email: (process.env.AUTH_BOOTSTRAP_ADMIN_EMAIL || 'admin@gestaoalojamentolocal.local').toLowerCase(),
    role: 'admin',
    passwordHash: hashPassword(process.env.AUTH_BOOTSTRAP_ADMIN_PASSWORD || 'change-me-now'),
    failedLoginAttempts: 0,
    lockUntil: null,
    lastFailedLoginAt: null,
    lastLoginAt: null,
    createdAt: now,
    updatedAt: now
  };

  db.users.push(bootstrapUser);
  return bootstrapUser;
}

function authRequired(req, res, next) {
  const rawHeader = req.headers.authorization || '';
  const [scheme, token] = String(rawHeader).split(' ');
  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ ok: false, error: 'Autenticacao obrigatoria. Use Bearer token.' });
  }

  const result = verifyToken(token);
  if (!result.ok) {
    return res.status(401).json({ ok: false, error: result.error });
  }

  const db = readDb();
  normalizeUsersCollection(db);
  const user = db.users.find((item) => item.id === result.payload.sub);
  if (!user) {
    return res.status(401).json({ ok: false, error: 'Utilizador do token ja nao existe.' });
  }

  req.auth = { userId: user.id, role: user.role, email: user.email };
  req.authUser = user;
  return next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.auth.role)) {
      return res.status(403).json({ ok: false, error: 'Sem permissao para esta acao.' });
    }
    return next();
  };
}

app.get('/health', (req, res) => {
  res.json({ ok: true, service: 'gestaoalojamentolocal-api', now: new Date().toISOString() });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  const normalizedEmail = String(email || '').toLowerCase().trim();

  if (!email || !password) {
    return res.status(400).json({ ok: false, error: 'Campos obrigatorios: email, password' });
  }

  const db = readDb();
  normalizeUsersCollection(db);
  const bootstrapUser = ensureBootstrapAdmin(db);
  const user = db.users.find((item) => item.email === normalizedEmail);

  if (user && isUserLocked(user)) {
    appendAuditLog(db, {
      action: 'auth.login.blocked',
      actor: { userId: user.id, email: user.email, role: user.role },
      target: { type: 'user', id: user.id },
      metadata: { reason: 'account_locked', lockUntil: user.lockUntil }
    });
    writeDb(db);
    return res.status(423).json({ ok: false, error: 'Conta temporariamente bloqueada por tentativas falhadas.' });
  }

  if (!user || !verifyPassword(password, user.passwordHash)) {
    if (user) {
      user.failedLoginAttempts = Number(user.failedLoginAttempts || 0) + 1;
      user.lastFailedLoginAt = new Date().toISOString();
      if (user.failedLoginAttempts >= AUTH_LOGIN_MAX_ATTEMPTS) {
        const lockUntil = new Date(Date.now() + AUTH_LOGIN_LOCK_MINUTES * 60 * 1000).toISOString();
        user.lockUntil = lockUntil;
      }
      user.updatedAt = new Date().toISOString();
    }

    appendAuditLog(db, {
      action: 'auth.login.failed',
      actor: { userId: user ? user.id : null, email: normalizedEmail, role: user ? user.role : null },
      target: null,
      metadata: {
        reason: 'invalid_credentials',
        failedLoginAttempts: user ? user.failedLoginAttempts : null,
        lockUntil: user ? user.lockUntil : null
      }
    });
    writeDb(db);
    return res.status(401).json({ ok: false, error: 'Credenciais invalidas.' });
  }

  user.failedLoginAttempts = 0;
  user.lockUntil = null;
  user.lastFailedLoginAt = null;
  user.lastLoginAt = new Date().toISOString();
  user.updatedAt = new Date().toISOString();

  const token = createToken({ sub: user.id, email: user.email, role: user.role });
  const { refreshToken, session } = createRefreshSession(db, user.id);
  appendAuditLog(db, {
    action: 'auth.login.success',
    actor: { userId: user.id, email: user.email, role: user.role },
    target: { type: 'user', id: user.id },
    metadata: { bootstrapAdminCreated: Boolean(bootstrapUser), sessionId: session.id }
  });
  writeDb(db);

  return res.json({ ok: true, token, refreshToken, user: serializeUser(user) });
});

app.post('/api/auth/refresh', (req, res) => {
  const { refreshToken } = req.body || {};
  if (!refreshToken) {
    return res.status(400).json({ ok: false, error: 'Campo obrigatorio: refreshToken' });
  }

  const db = readDb();
  normalizeUsersCollection(db);
  const sessionResult = findActiveSessionByRefreshToken(db, refreshToken);
  if (!sessionResult.ok) {
    appendAuditLog(db, {
      action: 'auth.refresh.failed',
      actor: { userId: null, email: null, role: null },
      target: null,
      metadata: { reason: sessionResult.error }
    });
    writeDb(db);
    return res.status(401).json({ ok: false, error: 'Refresh token invalido.' });
  }

  const oldSession = sessionResult.session;
  const user = db.users.find((item) => item.id === oldSession.userId);
  if (!user) {
    oldSession.revokedAt = new Date().toISOString();
    oldSession.updatedAt = oldSession.revokedAt;
    appendAuditLog(db, {
      action: 'auth.refresh.failed',
      actor: { userId: oldSession.userId, email: null, role: null },
      target: { type: 'session', id: oldSession.id },
      metadata: { reason: 'user_not_found' }
    });
    writeDb(db);
    return res.status(401).json({ ok: false, error: 'Refresh token invalido.' });
  }

  oldSession.revokedAt = new Date().toISOString();
  oldSession.updatedAt = oldSession.revokedAt;
  oldSession.lastUsedAt = oldSession.revokedAt;

  const { refreshToken: nextRefreshToken, session: nextSession } = createRefreshSession(db, user.id);
  const token = createToken({ sub: user.id, email: user.email, role: user.role });

  appendAuditLog(db, {
    action: 'auth.refresh.success',
    actor: { userId: user.id, email: user.email, role: user.role },
    target: { type: 'session', id: nextSession.id },
    metadata: { rotatedFromSessionId: oldSession.id }
  });
  writeDb(db);

  return res.json({
    ok: true,
    token,
    refreshToken: nextRefreshToken,
    user: serializeUser(user)
  });
});

app.use('/api', (req, res, next) => {
  if (req.path === '/auth/login' || req.path === '/auth/refresh') {
    return next();
  }
  return authRequired(req, res, next);
});

app.get('/api/auth/me', (req, res) => {
  return res.json({ ok: true, user: serializeUser(req.authUser) });
});

app.post('/api/auth/change-password', (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ ok: false, error: 'Campos obrigatorios: currentPassword, newPassword' });
  }
  if (String(newPassword).length < AUTH_PASSWORD_MIN_LENGTH) {
    return res.status(400).json({
      ok: false,
      error: `newPassword deve ter pelo menos ${AUTH_PASSWORD_MIN_LENGTH} caracteres.`
    });
  }
  if (currentPassword === newPassword) {
    return res.status(400).json({ ok: false, error: 'newPassword deve ser diferente da password atual.' });
  }

  const db = readDb();
  normalizeUsersCollection(db);
  const index = db.users.findIndex((item) => item.id === req.auth.userId);
  if (index === -1) {
    return res.status(404).json({ ok: false, error: 'Utilizador nao encontrado.' });
  }

  const user = db.users[index];
  if (!verifyPassword(currentPassword, user.passwordHash)) {
    return res.status(401).json({ ok: false, error: 'Password atual invalida.' });
  }

  user.passwordHash = hashPassword(newPassword);
  user.updatedAt = new Date().toISOString();
  db.users[index] = user;

  normalizeAuthSessionsCollection(db);
  let revokedSessions = 0;
  const now = new Date().toISOString();
  db.authSessions.forEach((session) => {
    if (session.userId === user.id && !session.revokedAt) {
      session.revokedAt = now;
      session.updatedAt = now;
      revokedSessions += 1;
    }
  });

  appendAuditLog(db, {
    action: 'auth.change_password',
    actor: { userId: user.id, email: user.email, role: user.role },
    target: { type: 'user', id: user.id },
    metadata: { revokedSessions }
  });
  writeDb(db);

  return res.json({ ok: true, message: 'Password atualizada com sucesso.' });
});

app.post('/api/auth/logout', (req, res) => {
  const { refreshToken, allSessions } = req.body || {};
  const db = readDb();
  normalizeAuthSessionsCollection(db);

  const revokeAll = Boolean(allSessions);
  let revokedCount = 0;

  if (revokeAll) {
    const now = new Date().toISOString();
    db.authSessions.forEach((session) => {
      if (session.userId === req.auth.userId && !session.revokedAt) {
        session.revokedAt = now;
        session.updatedAt = now;
        revokedCount += 1;
      }
    });
  } else {
    if (!refreshToken) {
      return res.status(400).json({
        ok: false,
        error: 'Campo obrigatorio: refreshToken (ou use allSessions=true)'
      });
    }

    const sessionResult = findActiveSessionByRefreshToken(db, refreshToken);
    if (!sessionResult.ok || sessionResult.session.userId !== req.auth.userId) {
      return res.status(401).json({ ok: false, error: 'Refresh token invalido.' });
    }

    sessionResult.session.revokedAt = new Date().toISOString();
    sessionResult.session.updatedAt = sessionResult.session.revokedAt;
    revokedCount = 1;
  }

  appendAuditLog(db, {
    action: 'auth.logout',
    actor: { userId: req.auth.userId, email: req.auth.email, role: req.auth.role },
    target: { type: 'user', id: req.auth.userId },
    metadata: { allSessions: revokeAll, revokedCount }
  });
  writeDb(db);

  return res.json({ ok: true, message: 'Logout concluido.', revokedCount });
});

app.get('/api/users', requireRole('admin'), (req, res) => {
  const db = readDb();
  normalizeUsersCollection(db);
  return res.json({ ok: true, data: db.users.map(serializeUser) });
});

app.post('/api/users', requireRole('admin'), (req, res) => {
  const { name, email, password, role } = req.body || {};
  if (!name || !email || !password) {
    return res.status(400).json({ ok: false, error: 'Campos obrigatorios: name, email, password' });
  }
  if (String(password).length < AUTH_PASSWORD_MIN_LENGTH) {
    return res.status(400).json({
      ok: false,
      error: `password deve ter pelo menos ${AUTH_PASSWORD_MIN_LENGTH} caracteres.`
    });
  }

  const normalizedEmail = String(email).toLowerCase().trim();
  if (!normalizedEmail.includes('@')) {
    return res.status(400).json({ ok: false, error: 'email invalido.' });
  }

  const nextRole = role || 'manager';
  if (!USER_ROLES.has(nextRole)) {
    return res.status(400).json({ ok: false, error: 'role invalido. Valores permitidos: admin, manager' });
  }

  const db = readDb();
  normalizeUsersCollection(db);
  const exists = db.users.some((item) => item.email === normalizedEmail);
  if (exists) {
    return res.status(409).json({ ok: false, error: 'Ja existe utilizador com este email.' });
  }

  const now = new Date().toISOString();
  const user = {
    id: nextId('usr'),
    name: String(name).trim(),
    email: normalizedEmail,
    role: nextRole,
    passwordHash: hashPassword(password),
    failedLoginAttempts: 0,
    lockUntil: null,
    lastFailedLoginAt: null,
    lastLoginAt: null,
    createdAt: now,
    updatedAt: now
  };

  db.users.push(user);
  appendAuditLog(db, {
    action: 'users.create',
    actor: { userId: req.auth.userId, email: req.auth.email, role: req.auth.role },
    target: { type: 'user', id: user.id },
    metadata: { role: user.role, email: user.email }
  });
  writeDb(db);

  return res.status(201).json({ ok: true, data: serializeUser(user) });
});

app.get('/api/audit-logs', requireRole('admin'), (req, res) => {
  const { action, userId, limit, page, pageSize, sortBy, sortDir } = req.query || {};
  const db = readDb();
  normalizeAuditLogsCollection(db);

  let logs = db.auditLogs;
  if (action) {
    logs = logs.filter((item) => item.action === action);
  }
  if (userId) {
    logs = logs.filter((item) => item.actor && item.actor.userId === userId);
  }

  const allowedSortFields = new Set(['at', 'action']);
  const selectedSortBy = allowedSortFields.has(sortBy) ? sortBy : 'at';
  const selectedSortDir = parseSortDir(sortDir, 'desc');
  const sorted = sortItems(logs, selectedSortBy, selectedSortDir);

  if (limit !== undefined && !page && !pageSize) {
    const max = Math.min(Number(limit) || 100, 500);
    return res.json({
      ok: true,
      data: sorted.slice(0, max),
      meta: { page: 1, pageSize: max, total: sorted.length, totalPages: 1, sortBy: selectedSortBy, sortDir: selectedSortDir }
    });
  }

  const selectedPage = parsePositiveInt(page, 1, 1, 100000);
  const selectedPageSize = parsePositiveInt(pageSize, 50, 1, 200);
  const paginated = paginateItems(sorted, selectedPage, selectedPageSize);
  return res.json({
    ok: true,
    data: paginated.data,
    meta: { ...paginated.meta, sortBy: selectedSortBy, sortDir: selectedSortDir }
  });
});

app.get('/api/config/booking', requireRole('admin'), (req, res) => {
  res.json({ ok: true, booking: getBookingConfig() });
});

app.get('/api/accommodations', (req, res) => {
  const { page, pageSize, sortBy, sortDir } = req.query || {};
  const db = readDb();
  normalizeDomainCollections(db);
  const allowedSortFields = new Set(['name', 'city', 'municipality', 'createdAt', 'updatedAt']);
  const selectedSortBy = allowedSortFields.has(sortBy) ? sortBy : 'createdAt';
  const selectedSortDir = parseSortDir(sortDir, 'desc');
  const selectedPage = parsePositiveInt(page, 1, 1, 100000);
  const selectedPageSize = parsePositiveInt(pageSize, 50, 1, 200);

  const sorted = sortItems(db.accommodations, selectedSortBy, selectedSortDir);
  const paginated = paginateItems(sorted, selectedPage, selectedPageSize);

  res.json({
    ok: true,
    data: paginated.data,
    meta: { ...paginated.meta, sortBy: selectedSortBy, sortDir: selectedSortDir }
  });
});

app.post('/api/accommodations', (req, res) => {
  const { name, city, municipality, localRegistrationNumber } = req.body || {};
  if (!name) {
    return res.status(400).json({ ok: false, error: 'Campo obrigatorio: name' });
  }

  const db = readDb();
  normalizeDomainCollections(db);

  const accommodation = {
    id: nextId('acc'),
    name,
    city: city || null,
    municipality: municipality || null,
    localRegistrationNumber: localRegistrationNumber || null,
    bookingConnection: {
      enabled: false,
      hotelId: null,
      lastSyncAt: null,
      lastConnectionCheck: null,
      statusMessage: 'Desligado'
    },
    insurance: {
      policyNumber: null,
      expiresAt: null,
      minimumCoverageEur: 75000
    },
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };

  db.accommodations.push(accommodation);
  appendAuditLog(db, {
    action: 'accommodations.create',
    actor: { userId: req.auth.userId, email: req.auth.email, role: req.auth.role },
    target: { type: 'accommodation', id: accommodation.id },
    metadata: { name: accommodation.name, city: accommodation.city, municipality: accommodation.municipality }
  });
  writeDb(db);
  return res.status(201).json({ ok: true, data: accommodation });
});

app.get('/api/accommodations/:id', (req, res) => {
  const db = readDb();
  normalizeDomainCollections(db);
  const accommodation = db.accommodations.find((item) => item.id === req.params.id);
  if (!accommodation) {
    return res.status(404).json({ ok: false, error: 'Alojamento nao encontrado' });
  }
  return res.json({ ok: true, data: accommodation });
});

app.put('/api/accommodations/:id', (req, res) => {
  const { name, city, municipality, localRegistrationNumber } = req.body || {};
  const db = readDb();
  normalizeDomainCollections(db);

  const index = db.accommodations.findIndex((item) => item.id === req.params.id);
  if (index === -1) {
    return res.status(404).json({ ok: false, error: 'Alojamento nao encontrado' });
  }

  if (name !== undefined && !String(name).trim()) {
    return res.status(400).json({ ok: false, error: 'name nao pode ser vazio.' });
  }

  const current = db.accommodations[index];
  const updated = {
    ...current,
    name: name !== undefined ? String(name).trim() : current.name,
    city: city !== undefined ? city : current.city,
    municipality: municipality !== undefined ? municipality : current.municipality,
    localRegistrationNumber:
      localRegistrationNumber !== undefined ? localRegistrationNumber : current.localRegistrationNumber,
    updatedAt: new Date().toISOString()
  };

  db.accommodations[index] = updated;
  appendAuditLog(db, {
    action: 'accommodations.update',
    actor: { userId: req.auth.userId, email: req.auth.email, role: req.auth.role },
    target: { type: 'accommodation', id: updated.id },
    metadata: {
      name: updated.name,
      city: updated.city,
      municipality: updated.municipality,
      localRegistrationNumber: updated.localRegistrationNumber
    }
  });
  writeDb(db);

  return res.json({ ok: true, data: updated });
});

app.delete('/api/accommodations/:id', (req, res) => {
  const force = String(req.query.force || 'false') === 'true';
  const db = readDb();
  normalizeDomainCollections(db);

  const index = db.accommodations.findIndex((item) => item.id === req.params.id);
  if (index === -1) {
    return res.status(404).json({ ok: false, error: 'Alojamento nao encontrado' });
  }

  const hasBlockingReservation = db.reservations.some((item) => {
    return item.accommodationId === req.params.id && item.status !== 'cancelled';
  });

  if (hasBlockingReservation && !force) {
    return res.status(409).json({
      ok: false,
      error: 'Existem reservas ativas para este alojamento. Use force=true para remover mesmo assim.'
    });
  }

  const [removedAccommodation] = db.accommodations.splice(index, 1);
  let removedReservations = 0;
  if (force) {
    const before = db.reservations.length;
    db.reservations = db.reservations.filter((item) => item.accommodationId !== req.params.id);
    removedReservations = before - db.reservations.length;
  }

  appendAuditLog(db, {
    action: 'accommodations.delete',
    actor: { userId: req.auth.userId, email: req.auth.email, role: req.auth.role },
    target: { type: 'accommodation', id: removedAccommodation.id },
    metadata: { force, removedReservations }
  });
  writeDb(db);

  return res.json({
    ok: true,
    data: removedAccommodation,
    message: force
      ? `Alojamento removido com sucesso. Reservas removidas: ${removedReservations}.`
      : 'Alojamento removido com sucesso.'
  });
});

app.get('/api/rate-plans', (req, res) => {
  const { accommodationId, page, pageSize, sortBy, sortDir } = req.query || {};
  const db = readDb();
  normalizeDomainCollections(db);

  let data = db.ratePlans;
  if (accommodationId) {
    data = data.filter((item) => item.accommodationId === accommodationId);
  }

  const allowedSortFields = new Set(['name', 'baseNightlyRate', 'createdAt', 'updatedAt']);
  const selectedSortBy = allowedSortFields.has(sortBy) ? sortBy : 'createdAt';
  const selectedSortDir = parseSortDir(sortDir, 'desc');
  const selectedPage = parsePositiveInt(page, 1, 1, 100000);
  const selectedPageSize = parsePositiveInt(pageSize, 50, 1, 200);

  const sorted = sortItems(data, selectedSortBy, selectedSortDir);
  const paginated = paginateItems(sorted, selectedPage, selectedPageSize);

  return res.json({
    ok: true,
    data: paginated.data,
    meta: { ...paginated.meta, sortBy: selectedSortBy, sortDir: selectedSortDir }
  });
});

app.post('/api/rate-plans', (req, res) => {
  const {
    accommodationId,
    name,
    currency,
    baseNightlyRate,
    weekendMultiplier,
    extraAdultFee,
    extraChildFee,
    minNights,
    seasonalAdjustments
  } = req.body || {};

  if (!accommodationId || !name) {
    return res.status(400).json({ ok: false, error: 'Campos obrigatorios: accommodationId, name' });
  }

  const baseRate = Number(baseNightlyRate);
  if (!Number.isFinite(baseRate) || baseRate <= 0) {
    return res.status(400).json({ ok: false, error: 'baseNightlyRate deve ser numero positivo.' });
  }

  const db = readDb();
  normalizeDomainCollections(db);
  const accommodation = db.accommodations.find((item) => item.id === accommodationId);
  if (!accommodation) {
    return res.status(404).json({ ok: false, error: 'Alojamento nao encontrado' });
  }

  const plan = {
    id: nextId('rp'),
    accommodationId,
    name: String(name).trim(),
    currency: currency || 'EUR',
    baseNightlyRate: baseRate,
    weekendMultiplier: Number.isFinite(Number(weekendMultiplier)) ? Number(weekendMultiplier) : 1,
    extraAdultFee: Number.isFinite(Number(extraAdultFee)) ? Number(extraAdultFee) : 0,
    extraChildFee: Number.isFinite(Number(extraChildFee)) ? Number(extraChildFee) : 0,
    minNights: Number.isFinite(Number(minNights)) ? Number(minNights) : 1,
    seasonalAdjustments: Array.isArray(seasonalAdjustments) ? seasonalAdjustments : [],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };

  db.ratePlans.push(plan);
  appendAuditLog(db, {
    action: 'rate_plans.create',
    actor: { userId: req.auth.userId, email: req.auth.email, role: req.auth.role },
    target: { type: 'rate_plan', id: plan.id },
    metadata: { accommodationId: plan.accommodationId, name: plan.name, currency: plan.currency }
  });
  writeDb(db);

  return res.status(201).json({ ok: true, data: plan });
});

app.get('/api/availability-rules', (req, res) => {
  const { accommodationId, page, pageSize, sortBy, sortDir } = req.query || {};
  const db = readDb();
  normalizeDomainCollections(db);

  let data = db.availabilityRules;
  if (accommodationId) {
    data = data.filter((item) => item.accommodationId === accommodationId);
  }

  const allowedSortFields = new Set(['startDate', 'endDate', 'createdAt', 'updatedAt']);
  const selectedSortBy = allowedSortFields.has(sortBy) ? sortBy : 'startDate';
  const selectedSortDir = parseSortDir(sortDir, 'asc');
  const selectedPage = parsePositiveInt(page, 1, 1, 100000);
  const selectedPageSize = parsePositiveInt(pageSize, 50, 1, 200);

  const sorted = sortItems(data, selectedSortBy, selectedSortDir);
  const paginated = paginateItems(sorted, selectedPage, selectedPageSize);
  return res.json({
    ok: true,
    data: paginated.data,
    meta: { ...paginated.meta, sortBy: selectedSortBy, sortDir: selectedSortDir }
  });
});

app.post('/api/availability-rules', (req, res) => {
  const {
    accommodationId,
    startDate,
    endDate,
    closed,
    closedToArrival,
    closedToDeparture,
    minNights,
    maxNights,
    minAdvanceHours,
    maxAdvanceDays,
    allowedArrivalWeekdays,
    allowedDepartureWeekdays,
    note
  } = req.body || {};
  if (!accommodationId || !startDate || !endDate) {
    return res.status(400).json({ ok: false, error: 'Campos obrigatorios: accommodationId, startDate, endDate' });
  }
  if (!isValidIsoDate(startDate) || !isValidIsoDate(endDate) || new Date(startDate) > new Date(endDate)) {
    return res.status(400).json({ ok: false, error: 'Intervalo de datas invalido.' });
  }

  const db = readDb();
  normalizeDomainCollections(db);
  const accommodation = db.accommodations.find((item) => item.id === accommodationId);
  if (!accommodation) {
    return res.status(404).json({ ok: false, error: 'Alojamento nao encontrado' });
  }

  const normalizedMinNights = Number.isFinite(Number(minNights)) ? Number(minNights) : 0;
  const normalizedMaxNights = Number.isFinite(Number(maxNights)) ? Number(maxNights) : 0;
  const normalizedMinAdvanceHours = Number.isFinite(Number(minAdvanceHours)) ? Number(minAdvanceHours) : 0;
  const normalizedMaxAdvanceDays = Number.isFinite(Number(maxAdvanceDays)) ? Number(maxAdvanceDays) : 0;
  const normalizedArrivalWeekdays = normalizeWeekdaysInput(allowedArrivalWeekdays);
  const normalizedDepartureWeekdays = normalizeWeekdaysInput(allowedDepartureWeekdays);

  if (normalizedMaxNights > 0 && normalizedMaxNights < normalizedMinNights) {
    return res.status(400).json({ ok: false, error: 'maxNights nao pode ser inferior a minNights.' });
  }
  if (normalizedMinAdvanceHours < 0 || normalizedMaxAdvanceDays < 0) {
    return res.status(400).json({ ok: false, error: 'minAdvanceHours/maxAdvanceDays nao podem ser negativos.' });
  }
  if (Array.isArray(allowedArrivalWeekdays) && normalizedArrivalWeekdays.length !== allowedArrivalWeekdays.length) {
    return res.status(400).json({ ok: false, error: 'allowedArrivalWeekdays deve conter apenas inteiros de 0 a 6.' });
  }
  if (Array.isArray(allowedDepartureWeekdays) && normalizedDepartureWeekdays.length !== allowedDepartureWeekdays.length) {
    return res.status(400).json({ ok: false, error: 'allowedDepartureWeekdays deve conter apenas inteiros de 0 a 6.' });
  }

  const rule = {
    id: nextId('ar'),
    accommodationId,
    startDate: formatIsoDateOnly(startDate),
    endDate: formatIsoDateOnly(endDate),
    closed: Boolean(closed),
    closedToArrival: Boolean(closedToArrival),
    closedToDeparture: Boolean(closedToDeparture),
    minNights: Math.max(normalizedMinNights, 0),
    maxNights: Math.max(normalizedMaxNights, 0),
    minAdvanceHours: Math.max(normalizedMinAdvanceHours, 0),
    maxAdvanceDays: Math.max(normalizedMaxAdvanceDays, 0),
    allowedArrivalWeekdays: normalizedArrivalWeekdays,
    allowedDepartureWeekdays: normalizedDepartureWeekdays,
    note: note || null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };

  db.availabilityRules.push(rule);
  appendAuditLog(db, {
    action: 'availability_rules.create',
    actor: { userId: req.auth.userId, email: req.auth.email, role: req.auth.role },
    target: { type: 'availability_rule', id: rule.id },
    metadata: {
      accommodationId: rule.accommodationId,
      startDate: rule.startDate,
      endDate: rule.endDate,
      closed: rule.closed,
      closedToArrival: rule.closedToArrival,
      closedToDeparture: rule.closedToDeparture,
      minNights: rule.minNights,
      maxNights: rule.maxNights,
      minAdvanceHours: rule.minAdvanceHours,
      maxAdvanceDays: rule.maxAdvanceDays,
      allowedArrivalWeekdays: rule.allowedArrivalWeekdays,
      allowedDepartureWeekdays: rule.allowedDepartureWeekdays
    }
  });
  writeDb(db);

  return res.status(201).json({ ok: true, data: rule });
});

app.post('/api/rate-quote', (req, res) => {
  const { accommodationId, ratePlanId, checkIn, checkOut, adults, children } = req.body || {};
  if (!accommodationId || !checkIn || !checkOut) {
    return res.status(400).json({ ok: false, error: 'Campos obrigatorios: accommodationId, checkIn, checkOut' });
  }
  if (!isValidIsoDate(checkIn) || !isValidIsoDate(checkOut) || new Date(checkIn) >= new Date(checkOut)) {
    return res.status(400).json({ ok: false, error: 'Intervalo de datas invalido.' });
  }

  const db = readDb();
  normalizeDomainCollections(db);
  const accommodation = db.accommodations.find((item) => item.id === accommodationId);
  if (!accommodation) {
    return res.status(404).json({ ok: false, error: 'Alojamento nao encontrado' });
  }

  const plans = db.ratePlans.filter((item) => item.accommodationId === accommodationId);
  if (plans.length === 0) {
    return res.status(404).json({ ok: false, error: 'Nao existem rate plans para este alojamento.' });
  }

  const plan = ratePlanId
    ? plans.find((item) => item.id === ratePlanId)
    : plans[0];
  if (!plan) {
    return res.status(404).json({ ok: false, error: 'Rate plan nao encontrado para este alojamento.' });
  }

  const nights = countNights(checkIn, checkOut);
  const minNightsFromPlan = Number(plan.minNights || 1);
  const arrivalConstraints = pickAvailabilityConstraints(db.availabilityRules, accommodationId, formatIsoDateOnly(checkIn));
  const departureConstraints = pickAvailabilityConstraints(db.availabilityRules, accommodationId, formatIsoDateOnly(checkOut));
  const checkInDay = new Date(checkIn).getUTCDay();
  const checkOutDay = new Date(checkOut).getUTCDay();
  const now = getNow();
  const hoursUntilCheckIn = (new Date(checkIn) - now) / (60 * 60 * 1000);
  const daysUntilCheckIn = (new Date(checkIn) - now) / (24 * 60 * 60 * 1000);

  const effectiveMinAdvanceHours = Math.max(
    Number(arrivalConstraints.minAdvanceHours || 0),
    Number(departureConstraints.minAdvanceHours || 0)
  );
  const effectiveMaxAdvanceDaysCandidates = [
    Number(arrivalConstraints.maxAdvanceDays || 0),
    Number(departureConstraints.maxAdvanceDays || 0)
  ].filter((value) => value > 0);
  const effectiveMaxAdvanceDays = effectiveMaxAdvanceDaysCandidates.length > 0
    ? Math.min(...effectiveMaxAdvanceDaysCandidates)
    : 0;

  if (arrivalConstraints.closedToArrival) {
    return res.status(409).json({
      ok: false,
      error: `Check-in indisponivel em ${formatIsoDateOnly(checkIn)} (closedToArrival).`,
      details: { date: formatIsoDateOnly(checkIn), matchingRuleIds: arrivalConstraints.matchingRuleIds }
    });
  }
  if (departureConstraints.closedToDeparture) {
    return res.status(409).json({
      ok: false,
      error: `Check-out indisponivel em ${formatIsoDateOnly(checkOut)} (closedToDeparture).`,
      details: { date: formatIsoDateOnly(checkOut), matchingRuleIds: departureConstraints.matchingRuleIds }
    });
  }
  if (
    arrivalConstraints.allowedArrivalWeekdays.length > 0
    && !arrivalConstraints.allowedArrivalWeekdays.includes(checkInDay)
  ) {
    return res.status(409).json({
      ok: false,
      error: `Check-in nao permitido no dia da semana ${checkInDay}.`,
      details: { checkInDay, allowedArrivalWeekdays: arrivalConstraints.allowedArrivalWeekdays }
    });
  }
  if (
    departureConstraints.allowedDepartureWeekdays.length > 0
    && !departureConstraints.allowedDepartureWeekdays.includes(checkOutDay)
  ) {
    return res.status(409).json({
      ok: false,
      error: `Check-out nao permitido no dia da semana ${checkOutDay}.`,
      details: { checkOutDay, allowedDepartureWeekdays: departureConstraints.allowedDepartureWeekdays }
    });
  }
  if (effectiveMinAdvanceHours > 0 && hoursUntilCheckIn < effectiveMinAdvanceHours) {
    return res.status(409).json({
      ok: false,
      error: `Reserva requer antecedencia minima de ${effectiveMinAdvanceHours} horas.`,
      details: { effectiveMinAdvanceHours, hoursUntilCheckIn: Number(hoursUntilCheckIn.toFixed(2)) }
    });
  }
  if (effectiveMaxAdvanceDays > 0 && daysUntilCheckIn > effectiveMaxAdvanceDays) {
    return res.status(409).json({
      ok: false,
      error: `Reserva permite antecedencia maxima de ${effectiveMaxAdvanceDays} dias.`,
      details: { effectiveMaxAdvanceDays, daysUntilCheckIn: Number(daysUntilCheckIn.toFixed(2)) }
    });
  }

  const safeAdults = Number.isFinite(Number(adults)) ? Number(adults) : 1;
  const safeChildren = Number.isFinite(Number(children)) ? Number(children) : 0;
  const perNightDetails = [];
  let subtotal = 0;
  let minNightsFromRules = 0;
  let maxNightsFromRules = 0;
  const triggeredRuleIds = new Set();

  for (let i = 0; i < nights; i += 1) {
    const date = addDays(checkIn, i);
    const dateStr = formatIsoDateOnly(date);
    const availability = pickAvailabilityConstraints(db.availabilityRules, accommodationId, dateStr);
    if (availability.closed) {
      return res.status(409).json({
        ok: false,
        error: `Data indisponivel para reserva: ${dateStr}.`,
        details: { date: dateStr, matchingRuleIds: availability.matchingRuleIds }
      });
    }
    minNightsFromRules = Math.max(minNightsFromRules, availability.minNights);
    maxNightsFromRules = maxNightsFromRules === 0
      ? availability.maxNights
      : (availability.maxNights > 0 ? Math.min(maxNightsFromRules, availability.maxNights) : maxNightsFromRules);
    availability.matchingRuleIds.forEach((id) => triggeredRuleIds.add(id));

    const dayOfWeek = date.getUTCDay();
    const isWeekend = dayOfWeek === 5 || dayOfWeek === 6;
    const weekendMult = isWeekend ? Number(plan.weekendMultiplier || 1) : 1;
    const seasonalMult = pickSeasonalMultiplier(plan.seasonalAdjustments, dateStr);
    const base = Number(plan.baseNightlyRate);
    const nightlyRate = base * weekendMult * seasonalMult;
    subtotal += nightlyRate;

    perNightDetails.push({
      date: dateStr,
      baseRate: base,
      weekendMultiplier: weekendMult,
      seasonalMultiplier: seasonalMult,
      maxNightsConstraint: availability.maxNights,
      minNightsConstraint: availability.minNights,
      nightlyRate: Number(nightlyRate.toFixed(2))
    });
  }

  const effectiveMinNights = Math.max(minNightsFromPlan, minNightsFromRules || 0);
  if (nights < effectiveMinNights) {
    return res.status(400).json({
      ok: false,
      error: `Estadia minima: ${effectiveMinNights} noites.`,
      details: { minNightsFromPlan, minNightsFromRules, nights }
    });
  }
  if (maxNightsFromRules > 0 && nights > maxNightsFromRules) {
    return res.status(400).json({
      ok: false,
      error: `Estadia maxima: ${maxNightsFromRules} noites.`,
      details: { maxNightsFromRules, nights }
    });
  }

  const extraAdults = Math.max(safeAdults - 2, 0);
  const occupancyFees = nights * (
    extraAdults * Number(plan.extraAdultFee || 0)
    + safeChildren * Number(plan.extraChildFee || 0)
  );
  const total = Number((subtotal + occupancyFees).toFixed(2));

  return res.json({
    ok: true,
    data: {
      accommodationId,
      ratePlanId: plan.id,
      ratePlanName: plan.name,
      currency: plan.currency,
      checkIn,
      checkOut,
      nights,
      guests: { adults: safeAdults, children: safeChildren },
      constraints: {
        minNightsFromPlan,
        minNightsFromRules,
        maxNightsFromRules,
        effectiveMinNights,
        effectiveMinAdvanceHours,
        effectiveMaxAdvanceDays,
        closedToArrival: arrivalConstraints.closedToArrival,
        closedToDeparture: departureConstraints.closedToDeparture,
        allowedArrivalWeekdays: arrivalConstraints.allowedArrivalWeekdays,
        allowedDepartureWeekdays: departureConstraints.allowedDepartureWeekdays,
        triggeredAvailabilityRuleIds: [...triggeredRuleIds]
      },
      perNightDetails,
      pricing: {
        subtotal: Number(subtotal.toFixed(2)),
        occupancyFees: Number(occupancyFees.toFixed(2)),
        total
      }
    }
  });
});

app.get('/api/availability-calendar', (req, res) => {
  const { accommodationId, dateFrom, dateTo, ratePlanId, adults, children } = req.query || {};
  if (!accommodationId || !dateFrom || !dateTo) {
    return res.status(400).json({ ok: false, error: 'Campos obrigatorios: accommodationId, dateFrom, dateTo' });
  }
  if (!isValidIsoDate(dateFrom) || !isValidIsoDate(dateTo) || new Date(dateFrom) > new Date(dateTo)) {
    return res.status(400).json({ ok: false, error: 'Intervalo de datas invalido.' });
  }

  const db = readDb();
  normalizeDomainCollections(db);
  const accommodation = db.accommodations.find((item) => item.id === accommodationId);
  if (!accommodation) {
    return res.status(404).json({ ok: false, error: 'Alojamento nao encontrado' });
  }

  const plans = db.ratePlans.filter((item) => item.accommodationId === accommodationId);
  const selectedPlan = ratePlanId ? plans.find((item) => item.id === ratePlanId) : plans[0] || null;
  if (ratePlanId && !selectedPlan) {
    return res.status(404).json({ ok: false, error: 'Rate plan nao encontrado para este alojamento.' });
  }

  const safeAdults = Number.isFinite(Number(adults)) ? Number(adults) : 1;
  const safeChildren = Number.isFinite(Number(children)) ? Number(children) : 0;
  const extraAdults = Math.max(safeAdults - 2, 0);
  const start = new Date(dateFrom);
  const end = new Date(dateTo);
  const days = [];

  for (let cursor = new Date(start); cursor <= end; cursor = addDays(cursor, 1)) {
    const dateStr = formatIsoDateOnly(cursor);
    const nextDay = formatIsoDateOnly(addDays(cursor, 1));
    const now = getNow();
    const hoursUntilDate = (new Date(dateStr) - now) / (60 * 60 * 1000);
    const daysUntilDate = (new Date(dateStr) - now) / (24 * 60 * 60 * 1000);
    const dayOfWeek = cursor.getUTCDay();

    const bookedReservations = db.reservations.filter((item) => {
      if (item.accommodationId !== accommodationId || item.status === 'cancelled') {
        return false;
      }
      return hasDateRangeOverlap(item.checkIn, item.checkOut, dateStr, nextDay);
    });

    const availability = pickAvailabilityConstraints(db.availabilityRules, accommodationId, dateStr);
    const isArrivalWeekdayAllowed = availability.allowedArrivalWeekdays.length === 0
      || availability.allowedArrivalWeekdays.includes(dayOfWeek);
    const isWithinMinAdvance = hoursUntilDate >= Number(availability.minAdvanceHours || 0);
    const isWithinMaxAdvance = Number(availability.maxAdvanceDays || 0) === 0
      || daysUntilDate <= Number(availability.maxAdvanceDays || 0);
    const canBookArrivalNow = isArrivalWeekdayAllowed && isWithinMinAdvance && isWithinMaxAdvance;

    let status = 'available';
    let reason = null;
    if (bookedReservations.length > 0) {
      status = 'booked';
      reason = 'occupied_by_reservation';
    } else if (availability.closed) {
      status = 'closed';
      reason = 'blackout_rule';
    }

    let pricing = null;
    if (selectedPlan) {
      const dayOfWeek = cursor.getUTCDay();
      const isWeekend = dayOfWeek === 5 || dayOfWeek === 6;
      const weekendMult = isWeekend ? Number(selectedPlan.weekendMultiplier || 1) : 1;
      const seasonalMult = pickSeasonalMultiplier(selectedPlan.seasonalAdjustments, dateStr);
      const baseRate = Number(selectedPlan.baseNightlyRate);
      const baseWithMultipliers = baseRate * weekendMult * seasonalMult;
      const occupancySurcharge = extraAdults * Number(selectedPlan.extraAdultFee || 0)
        + safeChildren * Number(selectedPlan.extraChildFee || 0);
      const nightlyTotal = baseWithMultipliers + occupancySurcharge;

      pricing = {
        currency: selectedPlan.currency,
        baseRate,
        weekendMultiplier: weekendMult,
        seasonalMultiplier: seasonalMult,
        occupancySurcharge: Number(occupancySurcharge.toFixed(2)),
        suggestedNightlyTotal: Number(nightlyTotal.toFixed(2))
      };
    }

    days.push({
      date: dateStr,
      status,
      reason,
      closedToArrival: availability.closedToArrival,
      closedToDeparture: availability.closedToDeparture,
      allowedArrivalWeekdays: availability.allowedArrivalWeekdays,
      allowedDepartureWeekdays: availability.allowedDepartureWeekdays,
      minAdvanceHours: availability.minAdvanceHours,
      maxAdvanceDays: availability.maxAdvanceDays,
      canBookArrivalNow,
      maxNightsConstraint: availability.maxNights,
      minNightsConstraint: availability.minNights,
      triggeredAvailabilityRuleIds: availability.matchingRuleIds,
      reservationIds: bookedReservations.map((item) => item.id),
      pricing
    });
  }

  return res.json({
    ok: true,
    data: {
      accommodationId,
      dateFrom: formatIsoDateOnly(start),
      dateTo: formatIsoDateOnly(end),
      guests: { adults: safeAdults, children: safeChildren },
      ratePlan: selectedPlan
        ? { id: selectedPlan.id, name: selectedPlan.name, currency: selectedPlan.currency }
        : null,
      days
    }
  });
});

app.get('/api/reservations', (req, res) => {
  const { accommodationId, dateFrom, dateTo, status, page, pageSize, sortBy, sortDir } = req.query || {};
  const db = readDb();
  normalizeDomainCollections(db);

  let data = db.reservations;
  if (accommodationId) {
    data = data.filter((item) => item.accommodationId === accommodationId);
  }
  if (status) {
    data = data.filter((item) => item.status === status);
  }
  if (dateFrom || dateTo) {
    if ((dateFrom && !isValidIsoDate(dateFrom)) || (dateTo && !isValidIsoDate(dateTo))) {
      return res.status(400).json({ ok: false, error: 'dateFrom/dateTo invalidos. Use formato ISO (YYYY-MM-DD).' });
    }
    const fromDate = dateFrom || '1970-01-01';
    const toDate = dateTo || '9999-12-31';
    data = data.filter((item) => hasDateRangeOverlap(item.checkIn, item.checkOut, fromDate, toDate));
  }

  const allowedSortFields = new Set(['checkIn', 'checkOut', 'createdAt', 'updatedAt', 'guestName', 'status']);
  const selectedSortBy = allowedSortFields.has(sortBy) ? sortBy : 'checkIn';
  const selectedSortDir = parseSortDir(sortDir, 'asc');
  const selectedPage = parsePositiveInt(page, 1, 1, 100000);
  const selectedPageSize = parsePositiveInt(pageSize, 50, 1, 200);

  const sorted = sortItems(data, selectedSortBy, selectedSortDir);
  const paginated = paginateItems(sorted, selectedPage, selectedPageSize);

  return res.json({
    ok: true,
    data: paginated.data,
    meta: { ...paginated.meta, sortBy: selectedSortBy, sortDir: selectedSortDir }
  });
});

app.post('/api/reservations', (req, res) => {
  const { accommodationId, guestName, checkIn, checkOut, adults, children, source, status } = req.body || {};
  if (!accommodationId || !guestName || !checkIn || !checkOut) {
    return res.status(400).json({
      ok: false,
      error: 'Campos obrigatorios: accommodationId, guestName, checkIn, checkOut'
    });
  }
  if (!isValidIsoDate(checkIn) || !isValidIsoDate(checkOut)) {
    return res.status(400).json({ ok: false, error: 'checkIn/checkOut invalidos. Use formato ISO (YYYY-MM-DD).' });
  }
  if (new Date(checkIn) >= new Date(checkOut)) {
    return res.status(400).json({ ok: false, error: 'checkOut deve ser posterior a checkIn.' });
  }

  const nextStatus = status || 'confirmed';
  if (!RESERVATION_STATUSES.has(nextStatus)) {
    return res.status(400).json({
      ok: false,
      error: 'status invalido. Valores permitidos: confirmed, cancelled, checked_in, checked_out'
    });
  }

  const db = readDb();
  normalizeDomainCollections(db);
  const accommodation = db.accommodations.find((item) => item.id === accommodationId);
  if (!accommodation) {
    return res.status(404).json({ ok: false, error: 'Alojamento nao encontrado' });
  }

  const hasConflict = db.reservations.some((item) => {
    if (item.accommodationId !== accommodationId || item.status === 'cancelled') {
      return false;
    }
    return hasDateRangeOverlap(item.checkIn, item.checkOut, checkIn, checkOut);
  });
  if (hasConflict) {
    return res.status(409).json({ ok: false, error: 'Conflito de datas: ja existe reserva para este intervalo.' });
  }

  const reservation = {
    id: nextId('res'),
    accommodationId,
    guestName,
    checkIn,
    checkOut,
    adults: Number.isFinite(Number(adults)) ? Number(adults) : 1,
    children: Number.isFinite(Number(children)) ? Number(children) : 0,
    source: source || 'direct',
    status: nextStatus,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };

  db.reservations.push(reservation);
  appendAuditLog(db, {
    action: 'reservations.create',
    actor: { userId: req.auth.userId, email: req.auth.email, role: req.auth.role },
    target: { type: 'reservation', id: reservation.id },
    metadata: {
      accommodationId: reservation.accommodationId,
      checkIn: reservation.checkIn,
      checkOut: reservation.checkOut,
      status: reservation.status
    }
  });
  writeDb(db);
  return res.status(201).json({ ok: true, data: reservation });
});

app.get('/api/reservations/:id', (req, res) => {
  const db = readDb();
  normalizeDomainCollections(db);
  const reservation = db.reservations.find((item) => item.id === req.params.id);
  if (!reservation) {
    return res.status(404).json({ ok: false, error: 'Reserva nao encontrada' });
  }
  return res.json({ ok: true, data: reservation });
});

app.put('/api/reservations/:id', (req, res) => {
  const { guestName, checkIn, checkOut, adults, children, source, status } = req.body || {};
  const db = readDb();
  normalizeDomainCollections(db);
  const index = db.reservations.findIndex((item) => item.id === req.params.id);
  if (index === -1) {
    return res.status(404).json({ ok: false, error: 'Reserva nao encontrada' });
  }

  const current = db.reservations[index];
  const nextGuestName = guestName || current.guestName;
  const nextCheckIn = checkIn || current.checkIn;
  const nextCheckOut = checkOut || current.checkOut;
  const nextStatus = status || current.status;

  if (!nextGuestName || !nextCheckIn || !nextCheckOut) {
    return res.status(400).json({ ok: false, error: 'Campos obrigatorios: guestName, checkIn, checkOut' });
  }
  if (!isValidIsoDate(nextCheckIn) || !isValidIsoDate(nextCheckOut)) {
    return res.status(400).json({ ok: false, error: 'checkIn/checkOut invalidos. Use formato ISO (YYYY-MM-DD).' });
  }
  if (new Date(nextCheckIn) >= new Date(nextCheckOut)) {
    return res.status(400).json({ ok: false, error: 'checkOut deve ser posterior a checkIn.' });
  }
  if (!RESERVATION_STATUSES.has(nextStatus)) {
    return res.status(400).json({
      ok: false,
      error: 'status invalido. Valores permitidos: confirmed, cancelled, checked_in, checked_out'
    });
  }

  const hasConflict = db.reservations.some((item) => {
    if (item.id === current.id || item.accommodationId !== current.accommodationId) {
      return false;
    }
    if (item.status === 'cancelled' || nextStatus === 'cancelled') {
      return false;
    }
    return hasDateRangeOverlap(item.checkIn, item.checkOut, nextCheckIn, nextCheckOut);
  });
  if (hasConflict) {
    return res.status(409).json({ ok: false, error: 'Conflito de datas: ja existe reserva para este intervalo.' });
  }

  const updatedReservation = {
    ...current,
    guestName: nextGuestName,
    checkIn: nextCheckIn,
    checkOut: nextCheckOut,
    adults: Number.isFinite(Number(adults)) ? Number(adults) : current.adults,
    children: Number.isFinite(Number(children)) ? Number(children) : current.children,
    source: source || current.source,
    status: nextStatus,
    updatedAt: new Date().toISOString()
  };

  db.reservations[index] = updatedReservation;
  appendAuditLog(db, {
    action: 'reservations.update',
    actor: { userId: req.auth.userId, email: req.auth.email, role: req.auth.role },
    target: { type: 'reservation', id: updatedReservation.id },
    metadata: {
      accommodationId: updatedReservation.accommodationId,
      checkIn: updatedReservation.checkIn,
      checkOut: updatedReservation.checkOut,
      status: updatedReservation.status
    }
  });
  writeDb(db);

  return res.json({ ok: true, data: updatedReservation });
});

app.patch('/api/reservations/:id/status', (req, res) => {
  const { status } = req.body || {};
  if (!status || !RESERVATION_STATUSES.has(status)) {
    return res.status(400).json({
      ok: false,
      error: 'status invalido. Valores permitidos: confirmed, cancelled, checked_in, checked_out'
    });
  }

  const db = readDb();
  normalizeDomainCollections(db);
  const index = db.reservations.findIndex((item) => item.id === req.params.id);
  if (index === -1) {
    return res.status(404).json({ ok: false, error: 'Reserva nao encontrada' });
  }

  const reservation = db.reservations[index];
  reservation.status = status;
  reservation.updatedAt = new Date().toISOString();
  db.reservations[index] = reservation;
  appendAuditLog(db, {
    action: 'reservations.update_status',
    actor: { userId: req.auth.userId, email: req.auth.email, role: req.auth.role },
    target: { type: 'reservation', id: reservation.id },
    metadata: { status: reservation.status }
  });
  writeDb(db);

  return res.json({ ok: true, data: reservation });
});

app.delete('/api/reservations/:id', (req, res) => {
  const db = readDb();
  normalizeDomainCollections(db);
  const index = db.reservations.findIndex((item) => item.id === req.params.id);
  if (index === -1) {
    return res.status(404).json({ ok: false, error: 'Reserva nao encontrada' });
  }

  const [removed] = db.reservations.splice(index, 1);
  appendAuditLog(db, {
    action: 'reservations.delete',
    actor: { userId: req.auth.userId, email: req.auth.email, role: req.auth.role },
    target: { type: 'reservation', id: removed.id },
    metadata: { accommodationId: removed.accommodationId }
  });
  writeDb(db);

  return res.json({ ok: true, data: removed, message: 'Reserva removida com sucesso.' });
});

app.get('/api/calendar', (req, res) => {
  const { accommodationId, dateFrom, dateTo } = req.query || {};
  if (!accommodationId) {
    return res.status(400).json({ ok: false, error: 'Campo obrigatorio: accommodationId' });
  }
  if (!dateFrom || !dateTo || !isValidIsoDate(dateFrom) || !isValidIsoDate(dateTo)) {
    return res.status(400).json({
      ok: false,
      error: 'Campos obrigatorios: dateFrom e dateTo em formato ISO (YYYY-MM-DD).'
    });
  }
  if (new Date(dateFrom) >= new Date(dateTo)) {
    return res.status(400).json({ ok: false, error: 'dateTo deve ser posterior a dateFrom.' });
  }

  const db = readDb();
  normalizeDomainCollections(db);
  const accommodation = db.accommodations.find((item) => item.id === accommodationId);
  if (!accommodation) {
    return res.status(404).json({ ok: false, error: 'Alojamento nao encontrado' });
  }

  const reservations = db.reservations.filter((item) => {
    if (item.accommodationId !== accommodationId || item.status === 'cancelled') {
      return false;
    }
    return hasDateRangeOverlap(item.checkIn, item.checkOut, dateFrom, dateTo);
  });

  return res.json({ ok: true, data: { accommodationId, dateFrom, dateTo, reservations } });
});

app.patch('/api/accommodations/:id/booking-connection', requireRole('admin'), async (req, res) => {
  const { enabled, hotelId, force } = req.body || {};
  if (typeof enabled !== 'boolean') {
    return res.status(400).json({ ok: false, error: 'Campo obrigatorio: enabled (boolean)' });
  }

  const db = readDb();
  normalizeDomainCollections(db);
  const index = db.accommodations.findIndex((item) => item.id === req.params.id);
  if (index === -1) {
    return res.status(404).json({ ok: false, error: 'Alojamento nao encontrado' });
  }

  const accommodation = db.accommodations[index];
  if (enabled && !hotelId && !accommodation.bookingConnection.hotelId) {
    return res.status(400).json({ ok: false, error: 'hotelId e obrigatorio para ligar o alojamento a Booking API' });
  }

  const nextHotelId = hotelId || accommodation.bookingConnection.hotelId || null;
  const check = enabled
    ? await pingBookingConnection({ hotelId: nextHotelId })
    : { ok: true, message: 'Conexao Booking desligada manualmente.' };

  if (enabled && !check.ok && !force) {
    return res.status(502).json({
      ok: false,
      error: check.message,
      details: check.details || null,
      hint: 'Use force=true para guardar ligacao mesmo com falha de validacao.'
    });
  }

  accommodation.bookingConnection = {
    enabled,
    hotelId: nextHotelId,
    lastSyncAt: accommodation.bookingConnection.lastSyncAt || null,
    lastConnectionCheck: new Date().toISOString(),
    statusMessage: check.ok ? check.message : `Ligado com aviso: ${check.message}`
  };
  accommodation.updatedAt = new Date().toISOString();
  db.accommodations[index] = accommodation;
  writeDb(db);

  return res.json({ ok: true, data: accommodation.bookingConnection, warning: check.ok ? null : check.message });
});

app.post('/api/accommodations/:id/booking-sync', requireRole('admin'), async (req, res) => {
  const db = readDb();
  normalizeDomainCollections(db);
  const index = db.accommodations.findIndex((item) => item.id === req.params.id);
  if (index === -1) {
    return res.status(404).json({ ok: false, error: 'Alojamento nao encontrado' });
  }

  const accommodation = db.accommodations[index];
  const result = await syncAccommodation(accommodation.bookingConnection, req.body || null);
  if (!result.ok) {
    return res.status(502).json({ ok: false, error: result.message, details: result.details || null });
  }

  accommodation.bookingConnection.lastSyncAt = new Date().toISOString();
  accommodation.bookingConnection.statusMessage = result.message;
  accommodation.updatedAt = new Date().toISOString();
  db.accommodations[index] = accommodation;
  writeDb(db);

  return res.json({ ok: true, message: result.message, data: accommodation.bookingConnection, details: result.details });
});

app.get('/api/legal/complaints-book-link', (req, res) => {
  res.json({ ok: true, url: 'https://www.livroreclamacoes.pt/Inicio/' });
});

app.use((req, res) => {
  return res.status(404).json({ ok: false, error: 'Endpoint nao encontrado' });
});

if (require.main === module) {
  app.listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`API online em http://localhost:${port}`);
  });
}

module.exports = { app };
