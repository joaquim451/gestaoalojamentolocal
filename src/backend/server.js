const express = require('express');
const morgan = require('morgan');
const { readDb, writeDb, nextId } = require('./store');
const { getBookingConfig, pingBookingConnection, syncAccommodation } = require('./bookingClient');

const app = express();
const port = Number(process.env.PORT || 3000);

app.use(express.json());
app.use(morgan('dev'));

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
