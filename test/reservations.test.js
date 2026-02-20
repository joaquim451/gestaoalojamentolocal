const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const TEMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'gal-tests-'));
const DB_PATH = path.join(TEMP_DIR, 'db.json');

process.env.DB_PATH = DB_PATH;
process.env.AUTH_JWT_SECRET = 'test-secret';
process.env.AUTH_BOOTSTRAP_ADMIN_EMAIL = 'admin@test.local';
process.env.AUTH_BOOTSTRAP_ADMIN_PASSWORD = 'test-password-123';
process.env.AUTH_BOOTSTRAP_ADMIN_NAME = 'Test Admin';
process.env.AUTH_LOGIN_MAX_ATTEMPTS = '3';
process.env.AUTH_LOGIN_LOCK_MINUTES = '5';

const { app } = require('../src/backend/server');

function resetDb() {
  const initial = {
    users: [],
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
    reservations: [],
    auditLogs: []
  };

  fs.writeFileSync(DB_PATH, JSON.stringify(initial, null, 2), 'utf8');
}

async function request(server, method, route, body, token) {
  const address = server.address();
  const headers = { 'Content-Type': 'application/json' };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(`http://127.0.0.1:${address.port}${route}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined
  });

  return {
    status: response.status,
    json: await response.json()
  };
}

async function loginAsAdmin(server) {
  const response = await request(server, 'POST', '/api/auth/login', {
    email: process.env.AUTH_BOOTSTRAP_ADMIN_EMAIL,
    password: process.env.AUTH_BOOTSTRAP_ADMIN_PASSWORD
  });

  assert.equal(response.status, 200);
  assert.equal(response.json.ok, true);
  return response.json.token;
}

async function login(server, email, password) {
  const response = await request(server, 'POST', '/api/auth/login', { email, password });
  assert.equal(response.status, 200);
  assert.equal(response.json.ok, true);
  return response.json.token;
}

let server;

test.beforeEach(() => {
  resetDb();
  server = app.listen(0);
});

test.afterEach(async () => {
  await new Promise((resolve) => server.close(resolve));
});

test('GET /api/reservations requires authentication', async () => {
  const response = await request(server, 'GET', '/api/reservations');
  assert.equal(response.status, 401);
  assert.equal(response.json.ok, false);
});

test('POST /api/auth/login returns token and user', async () => {
  const response = await request(server, 'POST', '/api/auth/login', {
    email: process.env.AUTH_BOOTSTRAP_ADMIN_EMAIL,
    password: process.env.AUTH_BOOTSTRAP_ADMIN_PASSWORD
  });

  assert.equal(response.status, 200);
  assert.equal(response.json.ok, true);
  assert.equal(typeof response.json.token, 'string');
  assert.equal(response.json.user.email, process.env.AUTH_BOOTSTRAP_ADMIN_EMAIL);
});

test('POST /api/auth/login locks account after max failed attempts', async () => {
  for (let i = 0; i < 3; i += 1) {
    const failed = await request(server, 'POST', '/api/auth/login', {
      email: process.env.AUTH_BOOTSTRAP_ADMIN_EMAIL,
      password: `wrong-password-${i}`
    });
    assert.equal(failed.status, 401);
  }

  const blocked = await request(server, 'POST', '/api/auth/login', {
    email: process.env.AUTH_BOOTSTRAP_ADMIN_EMAIL,
    password: process.env.AUTH_BOOTSTRAP_ADMIN_PASSWORD
  });

  assert.equal(blocked.status, 423);
  assert.equal(blocked.json.ok, false);
});

test('POST /api/auth/change-password updates credentials', async () => {
  const token = await loginAsAdmin(server);

  const changed = await request(
    server,
    'POST',
    '/api/auth/change-password',
    {
      currentPassword: process.env.AUTH_BOOTSTRAP_ADMIN_PASSWORD,
      newPassword: 'new-test-password-456'
    },
    token
  );

  const oldLogin = await request(server, 'POST', '/api/auth/login', {
    email: process.env.AUTH_BOOTSTRAP_ADMIN_EMAIL,
    password: process.env.AUTH_BOOTSTRAP_ADMIN_PASSWORD
  });

  const newLogin = await request(server, 'POST', '/api/auth/login', {
    email: process.env.AUTH_BOOTSTRAP_ADMIN_EMAIL,
    password: 'new-test-password-456'
  });

  assert.equal(changed.status, 200);
  assert.equal(changed.json.ok, true);
  assert.equal(oldLogin.status, 401);
  assert.equal(newLogin.status, 200);
});

test('POST /api/auth/change-password rejects wrong current password', async () => {
  const token = await loginAsAdmin(server);
  const changed = await request(
    server,
    'POST',
    '/api/auth/change-password',
    {
      currentPassword: 'wrong-password',
      newPassword: 'new-test-password-456'
    },
    token
  );

  assert.equal(changed.status, 401);
  assert.equal(changed.json.ok, false);
});

test('POST /api/users allows admin to create manager', async () => {
  const token = await loginAsAdmin(server);
  const created = await request(
    server,
    'POST',
    '/api/users',
    {
      name: 'Gestor Teste',
      email: 'gestor@test.local',
      password: 'manager-password-123',
      role: 'manager'
    },
    token
  );

  assert.equal(created.status, 201);
  assert.equal(created.json.ok, true);
  assert.equal(created.json.data.role, 'manager');
});

test('GET /api/users blocks manager role', async () => {
  const adminToken = await loginAsAdmin(server);
  await request(
    server,
    'POST',
    '/api/users',
    {
      name: 'Gestor Teste',
      email: 'gestor2@test.local',
      password: 'manager-password-123',
      role: 'manager'
    },
    adminToken
  );

  const managerToken = await login(server, 'gestor2@test.local', 'manager-password-123');
  const usersList = await request(server, 'GET', '/api/users', null, managerToken);

  assert.equal(usersList.status, 403);
  assert.equal(usersList.json.ok, false);
});

test('GET /api/audit-logs returns critical events for admin', async () => {
  const token = await loginAsAdmin(server);
  await request(
    server,
    'POST',
    '/api/reservations',
    {
      accommodationId: 'acc_test_1',
      guestName: 'Audit Cliente',
      checkIn: '2026-08-10',
      checkOut: '2026-08-12'
    },
    token
  );

  const logsResponse = await request(server, 'GET', '/api/audit-logs?limit=20', null, token);
  assert.equal(logsResponse.status, 200);
  assert.equal(logsResponse.json.ok, true);

  const actions = logsResponse.json.data.map((item) => item.action);
  assert.equal(actions.includes('auth.login.success'), true);
  assert.equal(actions.includes('reservations.create'), true);
});

test('GET /api/audit-logs blocks manager role', async () => {
  const adminToken = await loginAsAdmin(server);
  await request(
    server,
    'POST',
    '/api/users',
    {
      name: 'Gestor Audit',
      email: 'gestor-audit@test.local',
      password: 'manager-password-123',
      role: 'manager'
    },
    adminToken
  );

  const managerToken = await login(server, 'gestor-audit@test.local', 'manager-password-123');
  const response = await request(server, 'GET', '/api/audit-logs', null, managerToken);
  assert.equal(response.status, 403);
  assert.equal(response.json.ok, false);
});

test('PUT /api/accommodations/:id updates accommodation fields', async () => {
  const token = await loginAsAdmin(server);
  const updated = await request(
    server,
    'PUT',
    '/api/accommodations/acc_test_1',
    {
      name: 'Alojamento Teste Atualizado',
      city: 'Porto',
      municipality: 'Porto',
      localRegistrationNumber: 'AL-12345'
    },
    token
  );

  assert.equal(updated.status, 200);
  assert.equal(updated.json.ok, true);
  assert.equal(updated.json.data.name, 'Alojamento Teste Atualizado');
  assert.equal(updated.json.data.city, 'Porto');
});

test('DELETE /api/accommodations/:id blocks when active reservations exist', async () => {
  const token = await loginAsAdmin(server);
  await request(
    server,
    'POST',
    '/api/reservations',
    {
      accommodationId: 'acc_test_1',
      guestName: 'Reserva Ativa',
      checkIn: '2026-09-10',
      checkOut: '2026-09-12'
    },
    token
  );

  const response = await request(server, 'DELETE', '/api/accommodations/acc_test_1', null, token);
  assert.equal(response.status, 409);
  assert.equal(response.json.ok, false);
});

test('DELETE /api/accommodations/:id force removes accommodation and reservations', async () => {
  const token = await loginAsAdmin(server);
  await request(
    server,
    'POST',
    '/api/reservations',
    {
      accommodationId: 'acc_test_1',
      guestName: 'Reserva Forcada',
      checkIn: '2026-10-10',
      checkOut: '2026-10-12'
    },
    token
  );

  const removed = await request(server, 'DELETE', '/api/accommodations/acc_test_1?force=true', null, token);
  const reservations = await request(server, 'GET', '/api/reservations', null, token);

  assert.equal(removed.status, 200);
  assert.equal(removed.json.ok, true);
  assert.equal(reservations.json.data.length, 0);
});

test('POST /api/reservations creates valid reservation', async () => {
  const token = await loginAsAdmin(server);
  const response = await request(
    server,
    'POST',
    '/api/reservations',
    {
      accommodationId: 'acc_test_1',
      guestName: 'Maria Silva',
      checkIn: '2026-03-10',
      checkOut: '2026-03-12'
    },
    token
  );

  assert.equal(response.status, 201);
  assert.equal(response.json.ok, true);
  assert.equal(response.json.data.accommodationId, 'acc_test_1');
});

test('POST /api/reservations blocks overlapping dates', async () => {
  const token = await loginAsAdmin(server);
  const first = await request(
    server,
    'POST',
    '/api/reservations',
    {
      accommodationId: 'acc_test_1',
      guestName: 'Cliente 1',
      checkIn: '2026-03-10',
      checkOut: '2026-03-12'
    },
    token
  );

  const second = await request(
    server,
    'POST',
    '/api/reservations',
    {
      accommodationId: 'acc_test_1',
      guestName: 'Cliente 2',
      checkIn: '2026-03-11',
      checkOut: '2026-03-13'
    },
    token
  );

  assert.equal(first.status, 201);
  assert.equal(second.status, 409);
  assert.equal(second.json.ok, false);
});

test('PUT /api/reservations/:id updates reservation without conflict', async () => {
  const token = await loginAsAdmin(server);
  const created = await request(
    server,
    'POST',
    '/api/reservations',
    {
      accommodationId: 'acc_test_1',
      guestName: 'Cliente Inicial',
      checkIn: '2026-03-10',
      checkOut: '2026-03-12'
    },
    token
  );

  const updated = await request(
    server,
    'PUT',
    `/api/reservations/${created.json.data.id}`,
    {
      guestName: 'Cliente Atualizado',
      checkIn: '2026-03-12',
      checkOut: '2026-03-14'
    },
    token
  );

  assert.equal(updated.status, 200);
  assert.equal(updated.json.data.guestName, 'Cliente Atualizado');
  assert.equal(updated.json.data.checkIn, '2026-03-12');
});

test('DELETE /api/reservations/:id removes reservation', async () => {
  const token = await loginAsAdmin(server);
  const created = await request(
    server,
    'POST',
    '/api/reservations',
    {
      accommodationId: 'acc_test_1',
      guestName: 'Cliente Delete',
      checkIn: '2026-03-10',
      checkOut: '2026-03-12'
    },
    token
  );

  const deleted = await request(server, 'DELETE', `/api/reservations/${created.json.data.id}`, null, token);
  const fetched = await request(server, 'GET', `/api/reservations/${created.json.data.id}`, null, token);

  assert.equal(deleted.status, 200);
  assert.equal(deleted.json.ok, true);
  assert.equal(fetched.status, 404);
});

test('GET /api/reservations filters by status and date range', async () => {
  const token = await loginAsAdmin(server);
  await request(
    server,
    'POST',
    '/api/reservations',
    {
      accommodationId: 'acc_test_1',
      guestName: 'Filtro 1',
      checkIn: '2026-04-01',
      checkOut: '2026-04-03',
      status: 'confirmed'
    },
    token
  );

  const created2 = await request(
    server,
    'POST',
    '/api/reservations',
    {
      accommodationId: 'acc_test_1',
      guestName: 'Filtro 2',
      checkIn: '2026-04-10',
      checkOut: '2026-04-12',
      status: 'confirmed'
    },
    token
  );

  await request(
    server,
    'PATCH',
    `/api/reservations/${created2.json.data.id}/status`,
    {
      status: 'cancelled'
    },
    token
  );

  const filtered = await request(
    server,
    'GET',
    '/api/reservations?status=cancelled&dateFrom=2026-04-01&dateTo=2026-04-30',
    null,
    token
  );

  assert.equal(filtered.status, 200);
  assert.equal(filtered.json.data.length, 1);
  assert.equal(filtered.json.data[0].status, 'cancelled');
});

test('PATCH /api/reservations/:id/status updates state', async () => {
  const token = await loginAsAdmin(server);
  const created = await request(
    server,
    'POST',
    '/api/reservations',
    {
      accommodationId: 'acc_test_1',
      guestName: 'Patch Status',
      checkIn: '2026-05-10',
      checkOut: '2026-05-12'
    },
    token
  );

  const patched = await request(
    server,
    'PATCH',
    `/api/reservations/${created.json.data.id}/status`,
    {
      status: 'checked_in'
    },
    token
  );

  assert.equal(patched.status, 200);
  assert.equal(patched.json.data.status, 'checked_in');
});

test('GET /api/calendar returns active reservations in range', async () => {
  const token = await loginAsAdmin(server);
  await request(
    server,
    'POST',
    '/api/reservations',
    {
      accommodationId: 'acc_test_1',
      guestName: 'Calendar 1',
      checkIn: '2026-06-10',
      checkOut: '2026-06-12',
      status: 'confirmed'
    },
    token
  );

  const cancelled = await request(
    server,
    'POST',
    '/api/reservations',
    {
      accommodationId: 'acc_test_1',
      guestName: 'Calendar Cancelled',
      checkIn: '2026-06-14',
      checkOut: '2026-06-16',
      status: 'confirmed'
    },
    token
  );

  await request(
    server,
    'PATCH',
    `/api/reservations/${cancelled.json.data.id}/status`,
    {
      status: 'cancelled'
    },
    token
  );

  const calendar = await request(
    server,
    'GET',
    '/api/calendar?accommodationId=acc_test_1&dateFrom=2026-06-01&dateTo=2026-06-30',
    null,
    token
  );

  assert.equal(calendar.status, 200);
  assert.equal(calendar.json.data.reservations.length, 1);
  assert.equal(calendar.json.data.reservations[0].guestName, 'Calendar 1');
});

test('POST /api/reservations rejects invalid date order', async () => {
  const token = await loginAsAdmin(server);
  const response = await request(
    server,
    'POST',
    '/api/reservations',
    {
      accommodationId: 'acc_test_1',
      guestName: 'Data Invalida',
      checkIn: '2026-07-15',
      checkOut: '2026-07-10'
    },
    token
  );

  assert.equal(response.status, 400);
  assert.equal(response.json.ok, false);
});
