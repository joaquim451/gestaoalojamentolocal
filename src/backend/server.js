const express = require('express');
const morgan = require('morgan');
const { readDb, writeDb, nextId } = require('./store');
const { getBookingConfig, pingBookingConnection, syncAccommodation } = require('./bookingClient');
const { hashPassword, verifyPassword, createToken, verifyToken } = require('./auth');

const app = express();
const port = Number(process.env.PORT || 3000);
const RESERVATION_STATUSES = new Set(['confirmed', 'cancelled', 'checked_in', 'checked_out']);
const USER_ROLES = new Set(['admin', 'manager']);
const AUTH_PASSWORD_MIN_LENGTH = Number(process.env.AUTH_PASSWORD_MIN_LENGTH || 10);

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

function normalizeDomainCollections(db) {
  if (!Array.isArray(db.accommodations)) {
    db.accommodations = [];
  }
  if (!Array.isArray(db.reservations)) {
    db.reservations = [];
  }
}

function appendAuditLog(db, event) {
  normalizeAuditLogsCollection(db);
  db.auditLogs.push({
    id: nextId('audit'),
    at: new Date().toISOString(),
    ...event
  });
}

function serializeUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt
  };
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

  if (!user || !verifyPassword(password, user.passwordHash)) {
    appendAuditLog(db, {
      action: 'auth.login.failed',
      actor: { userId: user ? user.id : null, email: normalizedEmail, role: user ? user.role : null },
      target: null,
      metadata: { reason: 'invalid_credentials' }
    });
    writeDb(db);
    return res.status(401).json({ ok: false, error: 'Credenciais invalidas.' });
  }

  const token = createToken({ sub: user.id, email: user.email, role: user.role });
  appendAuditLog(db, {
    action: 'auth.login.success',
    actor: { userId: user.id, email: user.email, role: user.role },
    target: { type: 'user', id: user.id },
    metadata: { bootstrapAdminCreated: Boolean(bootstrapUser) }
  });
  writeDb(db);

  return res.json({ ok: true, token, user: serializeUser(user) });
});

app.use('/api', (req, res, next) => {
  if (req.path === '/auth/login') {
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
  appendAuditLog(db, {
    action: 'auth.change_password',
    actor: { userId: user.id, email: user.email, role: user.role },
    target: { type: 'user', id: user.id },
    metadata: null
  });
  writeDb(db);

  return res.json({ ok: true, message: 'Password atualizada com sucesso.' });
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
  const { action, userId, limit } = req.query || {};
  const db = readDb();
  normalizeAuditLogsCollection(db);

  let logs = db.auditLogs;
  if (action) {
    logs = logs.filter((item) => item.action === action);
  }
  if (userId) {
    logs = logs.filter((item) => item.actor && item.actor.userId === userId);
  }

  const max = Math.min(Number(limit) || 100, 500);
  const data = [...logs].reverse().slice(0, max);
  return res.json({ ok: true, data });
});

app.get('/api/config/booking', (req, res) => {
  res.json({ ok: true, booking: getBookingConfig() });
});

app.get('/api/accommodations', (req, res) => {
  const db = readDb();
  normalizeDomainCollections(db);
  res.json({ ok: true, data: db.accommodations });
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

app.get('/api/reservations', (req, res) => {
  const { accommodationId, dateFrom, dateTo, status } = req.query || {};
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

  return res.json({ ok: true, data });
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

app.patch('/api/accommodations/:id/booking-connection', async (req, res) => {
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

app.post('/api/accommodations/:id/booking-sync', async (req, res) => {
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
