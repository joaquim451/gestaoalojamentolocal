const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const TEMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'gal-tests-'));
const DB_PATH = path.join(TEMP_DIR, 'db.json');

process.env.DB_PATH = DB_PATH;

const { app } = require('../src/backend/server');

function resetDb() {
  const initial = {
    accommodations: [
      {
        id: 'acc_test_1',
        name: 'Alojamento Teste',
        city: 'Lisboa',
        municipality: 'Lisboa',
        localRegistrationNumber: null,
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
      }
    ],
    reservations: []
  };

  fs.writeFileSync(DB_PATH, JSON.stringify(initial, null, 2), 'utf8');
}

async function request(server, method, route, body) {
  const address = server.address();
  const response = await fetch(`http://127.0.0.1:${address.port}${route}`, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined
  });
  return {
    status: response.status,
    json: await response.json()
  };
}

let server;

test.beforeEach(() => {
  resetDb();
  server = app.listen(0);
});

test.afterEach(async () => {
  await new Promise((resolve) => server.close(resolve));
});

test('POST /api/reservations cria reserva válida', async () => {
  const response = await request(server, 'POST', '/api/reservations', {
    accommodationId: 'acc_test_1',
    guestName: 'Maria Silva',
    checkIn: '2026-03-10',
    checkOut: '2026-03-12'
  });

  assert.equal(response.status, 201);
  assert.equal(response.json.ok, true);
  assert.equal(response.json.data.accommodationId, 'acc_test_1');
});

test('POST /api/reservations bloqueia sobreposição de datas', async () => {
  const first = await request(server, 'POST', '/api/reservations', {
    accommodationId: 'acc_test_1',
    guestName: 'Cliente 1',
    checkIn: '2026-03-10',
    checkOut: '2026-03-12'
  });

  const second = await request(server, 'POST', '/api/reservations', {
    accommodationId: 'acc_test_1',
    guestName: 'Cliente 2',
    checkIn: '2026-03-11',
    checkOut: '2026-03-13'
  });

  assert.equal(first.status, 201);
  assert.equal(second.status, 409);
  assert.equal(second.json.ok, false);
});

test('PUT /api/reservations/:id atualiza reserva sem conflito', async () => {
  const created = await request(server, 'POST', '/api/reservations', {
    accommodationId: 'acc_test_1',
    guestName: 'Cliente Inicial',
    checkIn: '2026-03-10',
    checkOut: '2026-03-12'
  });

  const updated = await request(server, 'PUT', `/api/reservations/${created.json.data.id}`, {
    guestName: 'Cliente Atualizado',
    checkIn: '2026-03-12',
    checkOut: '2026-03-14'
  });

  assert.equal(updated.status, 200);
  assert.equal(updated.json.data.guestName, 'Cliente Atualizado');
  assert.equal(updated.json.data.checkIn, '2026-03-12');
});

test('DELETE /api/reservations/:id remove reserva', async () => {
  const created = await request(server, 'POST', '/api/reservations', {
    accommodationId: 'acc_test_1',
    guestName: 'Cliente Delete',
    checkIn: '2026-03-10',
    checkOut: '2026-03-12'
  });

  const deleted = await request(server, 'DELETE', `/api/reservations/${created.json.data.id}`);
  const fetched = await request(server, 'GET', `/api/reservations/${created.json.data.id}`);

  assert.equal(deleted.status, 200);
  assert.equal(deleted.json.ok, true);
  assert.equal(fetched.status, 404);
});
