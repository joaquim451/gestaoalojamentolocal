const express = require('express');
const morgan = require('morgan');
const { readDb, writeDb, nextId } = require('./store');
const { getBookingConfig, pingBookingConnection, syncAccommodation } = require('./bookingClient');

const app = express();
const port = Number(process.env.PORT || 3000);
const RESERVATION_STATUSES = new Set(['confirmed', 'cancelled', 'checked_in', 'checked_out']);

app.use(express.json());
app.use(morgan('dev'));

function isValidIsoDate(value) {
  if (!value || typeof value !== 'string') {
    return false;
  }

  const time = Date.parse(value);
  return !Number.isNaN(time);
}

function hasDateRangeOverlap(aStart, aEnd, bStart, bEnd) {
  return new Date(aStart) < new Date(bEnd) && new Date(aEnd) > new Date(bStart);
}

app.get('/health', (req, res) => {
  res.json({ ok: true, service: 'gestaoalojamentolocal-api', now: new Date().toISOString() });
});

app.get('/api/config/booking', (req, res) => {
  res.json({ ok: true, booking: getBookingConfig() });
});

app.get('/api/accommodations', (req, res) => {
  const db = readDb();
  res.json({ ok: true, data: db.accommodations });
});

app.post('/api/accommodations', (req, res) => {
  const { name, city, municipality, localRegistrationNumber } = req.body || {};

  if (!name) {
    return res.status(400).json({ ok: false, error: 'Campo obrigatório: name' });
  }

  const db = readDb();

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
  const accommodation = db.accommodations.find((item) => item.id === req.params.id);
  if (!accommodation) {
    return res.status(404).json({ ok: false, error: 'Alojamento não encontrado' });
  }

  return res.json({ ok: true, data: accommodation });
});

app.get('/api/reservations', (req, res) => {
  const { accommodationId, dateFrom, dateTo, status } = req.query || {};
  const db = readDb();

  let data = db.reservations;

  if (accommodationId) {
    data = data.filter((item) => item.accommodationId === accommodationId);
  }

  if (status) {
    data = data.filter((item) => item.status === status);
  }

  if (dateFrom || dateTo) {
    if ((dateFrom && !isValidIsoDate(dateFrom)) || (dateTo && !isValidIsoDate(dateTo))) {
      return res.status(400).json({ ok: false, error: 'dateFrom/dateTo inválidos. Use formato ISO (YYYY-MM-DD).' });
    }

    const fromDate = dateFrom || '1970-01-01';
    const toDate = dateTo || '9999-12-31';

    data = data.filter((item) => hasDateRangeOverlap(item.checkIn, item.checkOut, fromDate, toDate));
  }

  return res.json({ ok: true, data });
});

app.post('/api/reservations', (req, res) => {
  const {
    accommodationId,
    guestName,
    checkIn,
    checkOut,
    adults,
    children,
    source,
    status
  } = req.body || {};

  if (!accommodationId || !guestName || !checkIn || !checkOut) {
    return res.status(400).json({
      ok: false,
      error: 'Campos obrigatórios: accommodationId, guestName, checkIn, checkOut'
    });
  }

  if (!isValidIsoDate(checkIn) || !isValidIsoDate(checkOut)) {
    return res.status(400).json({ ok: false, error: 'checkIn/checkOut inválidos. Use formato ISO (YYYY-MM-DD).' });
  }

  if (new Date(checkIn) >= new Date(checkOut)) {
    return res.status(400).json({ ok: false, error: 'checkOut deve ser posterior a checkIn.' });
  }

  const nextStatus = status || 'confirmed';
  if (!RESERVATION_STATUSES.has(nextStatus)) {
    return res.status(400).json({
      ok: false,
      error: 'status inválido. Valores permitidos: confirmed, cancelled, checked_in, checked_out'
    });
  }

  const db = readDb();
  const accommodation = db.accommodations.find((item) => item.id === accommodationId);

  if (!accommodation) {
    return res.status(404).json({ ok: false, error: 'Alojamento não encontrado' });
  }

  const hasConflict = db.reservations.some((item) => {
    if (item.accommodationId !== accommodationId) {
      return false;
    }
    if (item.status === 'cancelled') {
      return false;
    }
    return hasDateRangeOverlap(item.checkIn, item.checkOut, checkIn, checkOut);
  });

  if (hasConflict) {
    return res.status(409).json({ ok: false, error: 'Conflito de datas: já existe reserva para este intervalo.' });
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
  writeDb(db);

  return res.status(201).json({ ok: true, data: reservation });
});

app.patch('/api/reservations/:id/status', (req, res) => {
  const { status } = req.body || {};

  if (!status || !RESERVATION_STATUSES.has(status)) {
    return res.status(400).json({
      ok: false,
      error: 'status inválido. Valores permitidos: confirmed, cancelled, checked_in, checked_out'
    });
  }

  const db = readDb();
  const index = db.reservations.findIndex((item) => item.id === req.params.id);

  if (index === -1) {
    return res.status(404).json({ ok: false, error: 'Reserva não encontrada' });
  }

  const reservation = db.reservations[index];
  reservation.status = status;
  reservation.updatedAt = new Date().toISOString();

  db.reservations[index] = reservation;
  writeDb(db);

  return res.json({ ok: true, data: reservation });
});

app.get('/api/calendar', (req, res) => {
  const { accommodationId, dateFrom, dateTo } = req.query || {};

  if (!accommodationId) {
    return res.status(400).json({ ok: false, error: 'Campo obrigatório: accommodationId' });
  }

  if (!dateFrom || !dateTo || !isValidIsoDate(dateFrom) || !isValidIsoDate(dateTo)) {
    return res.status(400).json({
      ok: false,
      error: 'Campos obrigatórios: dateFrom e dateTo em formato ISO (YYYY-MM-DD).'
    });
  }

  if (new Date(dateFrom) >= new Date(dateTo)) {
    return res.status(400).json({ ok: false, error: 'dateTo deve ser posterior a dateFrom.' });
  }

  const db = readDb();
  const accommodation = db.accommodations.find((item) => item.id === accommodationId);
  if (!accommodation) {
    return res.status(404).json({ ok: false, error: 'Alojamento não encontrado' });
  }

  const reservations = db.reservations.filter((item) => {
    if (item.accommodationId !== accommodationId || item.status === 'cancelled') {
      return false;
    }
    return hasDateRangeOverlap(item.checkIn, item.checkOut, dateFrom, dateTo);
  });

  return res.json({
    ok: true,
    data: {
      accommodationId,
      dateFrom,
      dateTo,
      reservations
    }
  });
});

app.patch('/api/accommodations/:id/booking-connection', async (req, res) => {
  const { enabled, hotelId, force } = req.body || {};

  if (typeof enabled !== 'boolean') {
    return res.status(400).json({ ok: false, error: 'Campo obrigatório: enabled (boolean)' });
  }

  const db = readDb();
  const index = db.accommodations.findIndex((item) => item.id === req.params.id);

  if (index === -1) {
    return res.status(404).json({ ok: false, error: 'Alojamento não encontrado' });
  }

  const accommodation = db.accommodations[index];

  if (enabled && !hotelId && !accommodation.bookingConnection.hotelId) {
    return res.status(400).json({ ok: false, error: 'hotelId é obrigatório para ligar o alojamento à Booking API' });
  }

  const nextHotelId = hotelId || accommodation.bookingConnection.hotelId || null;
  const check = enabled
    ? await pingBookingConnection({ hotelId: nextHotelId })
    : { ok: true, message: 'Conexão Booking desligada manualmente.' };

  if (enabled && !check.ok && !force) {
    return res.status(502).json({
      ok: false,
      error: check.message,
      details: check.details || null,
      hint: 'Use force=true para guardar ligação mesmo com falha de validação.'
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
  const index = db.accommodations.findIndex((item) => item.id === req.params.id);

  if (index === -1) {
    return res.status(404).json({ ok: false, error: 'Alojamento não encontrado' });
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
  res.json({
    ok: true,
    url: 'https://www.livroreclamacoes.pt/Inicio/'
  });
});

app.use((req, res) => {
  return res.status(404).json({ ok: false, error: 'Endpoint não encontrado' });
});

app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`API online em http://localhost:${port}`);
});
