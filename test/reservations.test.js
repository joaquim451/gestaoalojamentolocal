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
process.env.TEST_NOW = '2026-01-01T00:00:00.000Z';

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
    ratePlans: [],
    availabilityRules: [],
    auditLogs: [],
    authSessions: []
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

async function loginWithTokens(server, email, password) {
  const response = await request(server, 'POST', '/api/auth/login', { email, password });
  assert.equal(response.status, 200);
  assert.equal(response.json.ok, true);
  return { token: response.json.token, refreshToken: response.json.refreshToken };
}

async function createManagerAndLogin(server, email) {
  const adminToken = await loginAsAdmin(server);
  await request(
    server,
    'POST',
    '/api/users',
    {
      name: 'Gestor Permissoes',
      email,
      password: 'manager-password-123',
      role: 'manager'
    },
    adminToken
  );
  return login(server, email, 'manager-password-123');
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
  assert.equal(typeof response.json.refreshToken, 'string');
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

test('POST /api/auth/refresh rotates refresh token', async () => {
  const loginResult = await request(server, 'POST', '/api/auth/login', {
    email: process.env.AUTH_BOOTSTRAP_ADMIN_EMAIL,
    password: process.env.AUTH_BOOTSTRAP_ADMIN_PASSWORD
  });

  const refreshed = await request(server, 'POST', '/api/auth/refresh', {
    refreshToken: loginResult.json.refreshToken
  });

  const reusedOld = await request(server, 'POST', '/api/auth/refresh', {
    refreshToken: loginResult.json.refreshToken
  });

  assert.equal(refreshed.status, 200);
  assert.equal(refreshed.json.ok, true);
  assert.equal(typeof refreshed.json.token, 'string');
  assert.equal(typeof refreshed.json.refreshToken, 'string');
  assert.equal(refreshed.json.refreshToken === loginResult.json.refreshToken, false);
  assert.equal(reusedOld.status, 401);
});

test('POST /api/auth/logout revokes provided refresh token', async () => {
  const session = await loginWithTokens(
    server,
    process.env.AUTH_BOOTSTRAP_ADMIN_EMAIL,
    process.env.AUTH_BOOTSTRAP_ADMIN_PASSWORD
  );

  const logout = await request(
    server,
    'POST',
    '/api/auth/logout',
    { refreshToken: session.refreshToken },
    session.token
  );
  const refreshAfterLogout = await request(server, 'POST', '/api/auth/refresh', {
    refreshToken: session.refreshToken
  });

  assert.equal(logout.status, 200);
  assert.equal(logout.json.ok, true);
  assert.equal(refreshAfterLogout.status, 401);
});

test('POST /api/auth/logout with allSessions revokes every session', async () => {
  const first = await loginWithTokens(
    server,
    process.env.AUTH_BOOTSTRAP_ADMIN_EMAIL,
    process.env.AUTH_BOOTSTRAP_ADMIN_PASSWORD
  );
  const second = await loginWithTokens(
    server,
    process.env.AUTH_BOOTSTRAP_ADMIN_EMAIL,
    process.env.AUTH_BOOTSTRAP_ADMIN_PASSWORD
  );

  const logoutAll = await request(
    server,
    'POST',
    '/api/auth/logout',
    { allSessions: true },
    first.token
  );

  const refreshFirst = await request(server, 'POST', '/api/auth/refresh', {
    refreshToken: first.refreshToken
  });
  const refreshSecond = await request(server, 'POST', '/api/auth/refresh', {
    refreshToken: second.refreshToken
  });

  assert.equal(logoutAll.status, 200);
  assert.equal(logoutAll.json.ok, true);
  assert.equal(logoutAll.json.revokedCount >= 2, true);
  assert.equal(refreshFirst.status, 401);
  assert.equal(refreshSecond.status, 401);
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

test('GET /api/config/booking blocks manager role', async () => {
  const managerToken = await createManagerAndLogin(server, 'gestor-config@test.local');
  const response = await request(server, 'GET', '/api/config/booking', null, managerToken);
  assert.equal(response.status, 403);
  assert.equal(response.json.ok, false);
});

test('PATCH /api/accommodations/:id/booking-connection blocks manager role', async () => {
  const managerToken = await createManagerAndLogin(server, 'gestor-booking@test.local');
  const response = await request(
    server,
    'PATCH',
    '/api/accommodations/acc_test_1/booking-connection',
    { enabled: false },
    managerToken
  );
  assert.equal(response.status, 403);
  assert.equal(response.json.ok, false);
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

test('GET /api/audit-logs supports pagination metadata', async () => {
  const token = await loginAsAdmin(server);
  await request(
    server,
    'POST',
    '/api/reservations',
    {
      accommodationId: 'acc_test_1',
      guestName: 'Audit Page 1',
      checkIn: '2026-11-10',
      checkOut: '2026-11-12'
    },
    token
  );
  await request(
    server,
    'POST',
    '/api/reservations',
    {
      accommodationId: 'acc_test_1',
      guestName: 'Audit Page 2',
      checkIn: '2026-11-13',
      checkOut: '2026-11-15'
    },
    token
  );

  const firstPage = await request(server, 'GET', '/api/audit-logs?page=1&pageSize=1', null, token);
  const secondPage = await request(server, 'GET', '/api/audit-logs?page=2&pageSize=1', null, token);

  assert.equal(firstPage.status, 200);
  assert.equal(secondPage.status, 200);
  assert.equal(firstPage.json.meta.page, 1);
  assert.equal(firstPage.json.meta.pageSize, 1);
  assert.equal(secondPage.json.meta.page, 2);
  assert.equal(firstPage.json.data[0].id === secondPage.json.data[0].id, false);
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

test('GET /api/accommodations supports sorting and pagination', async () => {
  const token = await loginAsAdmin(server);
  await request(
    server,
    'POST',
    '/api/accommodations',
    { name: 'B Casa', city: 'Braga' },
    token
  );
  await request(
    server,
    'POST',
    '/api/accommodations',
    { name: 'A Casa', city: 'Aveiro' },
    token
  );

  const response = await request(
    server,
    'GET',
    '/api/accommodations?sortBy=name&sortDir=asc&page=1&pageSize=2',
    null,
    token
  );

  assert.equal(response.status, 200);
  assert.equal(response.json.meta.page, 1);
  assert.equal(response.json.meta.pageSize, 2);
  assert.equal(response.json.data.length, 2);
  assert.equal(response.json.data[0].name, 'A Casa');
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

test('POST /api/rate-plans creates rate plan and GET /api/rate-plans lists it', async () => {
  const token = await loginAsAdmin(server);
  const created = await request(
    server,
    'POST',
    '/api/rate-plans',
    {
      accommodationId: 'acc_test_1',
      name: 'Tarifa Standard',
      currency: 'EUR',
      baseNightlyRate: 95,
      weekendMultiplier: 1.2,
      extraAdultFee: 15,
      extraChildFee: 8,
      minNights: 1
    },
    token
  );

  const listed = await request(
    server,
    'GET',
    '/api/rate-plans?accommodationId=acc_test_1&page=1&pageSize=10&sortBy=name&sortDir=asc',
    null,
    token
  );

  assert.equal(created.status, 201);
  assert.equal(created.json.ok, true);
  assert.equal(listed.status, 200);
  assert.equal(listed.json.ok, true);
  assert.equal(listed.json.data.length, 1);
  assert.equal(listed.json.data[0].name, 'Tarifa Standard');
});

test('POST /api/rate-quote calculates dynamic total', async () => {
  const token = await loginAsAdmin(server);
  const plan = await request(
    server,
    'POST',
    '/api/rate-plans',
    {
      accommodationId: 'acc_test_1',
      name: 'Tarifa Flex',
      currency: 'EUR',
      baseNightlyRate: 100,
      weekendMultiplier: 1.2,
      extraAdultFee: 10,
      extraChildFee: 5,
      minNights: 1,
      seasonalAdjustments: [
        { startDate: '2026-12-01', endDate: '2026-12-31', multiplier: 1.1 }
      ]
    },
    token
  );

  const quote = await request(
    server,
    'POST',
    '/api/rate-quote',
    {
      accommodationId: 'acc_test_1',
      ratePlanId: plan.json.data.id,
      checkIn: '2026-12-04',
      checkOut: '2026-12-06',
      adults: 3,
      children: 1
    },
    token
  );

  assert.equal(quote.status, 200);
  assert.equal(quote.json.ok, true);
  assert.equal(quote.json.data.nights, 2);
  assert.equal(quote.json.data.pricing.total, 294);
});

test('POST /api/rate-quote blocks blackout dates from availability rules', async () => {
  const token = await loginAsAdmin(server);
  const plan = await request(
    server,
    'POST',
    '/api/rate-plans',
    {
      accommodationId: 'acc_test_1',
      name: 'Tarifa Blackout',
      currency: 'EUR',
      baseNightlyRate: 90
    },
    token
  );

  await request(
    server,
    'POST',
    '/api/availability-rules',
    {
      accommodationId: 'acc_test_1',
      startDate: '2026-12-24',
      endDate: '2026-12-26',
      closed: true,
      note: 'Natal fechado'
    },
    token
  );

  const quote = await request(
    server,
    'POST',
    '/api/rate-quote',
    {
      accommodationId: 'acc_test_1',
      ratePlanId: plan.json.data.id,
      checkIn: '2026-12-24',
      checkOut: '2026-12-26',
      adults: 2,
      children: 0
    },
    token
  );

  assert.equal(quote.status, 409);
  assert.equal(quote.json.ok, false);
});

test('POST /api/rate-quote enforces min nights from availability rules', async () => {
  const token = await loginAsAdmin(server);
  const plan = await request(
    server,
    'POST',
    '/api/rate-plans',
    {
      accommodationId: 'acc_test_1',
      name: 'Tarifa MinNights',
      currency: 'EUR',
      baseNightlyRate: 80,
      minNights: 1
    },
    token
  );

  await request(
    server,
    'POST',
    '/api/availability-rules',
    {
      accommodationId: 'acc_test_1',
      startDate: '2026-12-10',
      endDate: '2026-12-31',
      closed: false,
      minNights: 3,
      note: 'Epoca alta'
    },
    token
  );

  const shortStay = await request(
    server,
    'POST',
    '/api/rate-quote',
    {
      accommodationId: 'acc_test_1',
      ratePlanId: plan.json.data.id,
      checkIn: '2026-12-12',
      checkOut: '2026-12-14',
      adults: 2,
      children: 0
    },
    token
  );

  const validStay = await request(
    server,
    'POST',
    '/api/rate-quote',
    {
      accommodationId: 'acc_test_1',
      ratePlanId: plan.json.data.id,
      checkIn: '2026-12-12',
      checkOut: '2026-12-15',
      adults: 2,
      children: 0
    },
    token
  );

  assert.equal(shortStay.status, 400);
  assert.equal(shortStay.json.ok, false);
  assert.equal(validStay.status, 200);
  assert.equal(validStay.json.ok, true);
});

test('POST /api/rate-quote blocks closedToArrival and closedToDeparture', async () => {
  const token = await loginAsAdmin(server);
  const plan = await request(
    server,
    'POST',
    '/api/rate-plans',
    {
      accommodationId: 'acc_test_1',
      name: 'Tarifa CTA CTD',
      currency: 'EUR',
      baseNightlyRate: 90
    },
    token
  );

  await request(
    server,
    'POST',
    '/api/availability-rules',
    {
      accommodationId: 'acc_test_1',
      startDate: '2026-12-20',
      endDate: '2026-12-20',
      closedToArrival: true
    },
    token
  );
  await request(
    server,
    'POST',
    '/api/availability-rules',
    {
      accommodationId: 'acc_test_1',
      startDate: '2026-12-22',
      endDate: '2026-12-22',
      closedToDeparture: true
    },
    token
  );

  const ctaBlocked = await request(
    server,
    'POST',
    '/api/rate-quote',
    {
      accommodationId: 'acc_test_1',
      ratePlanId: plan.json.data.id,
      checkIn: '2026-12-20',
      checkOut: '2026-12-21'
    },
    token
  );

  const ctdBlocked = await request(
    server,
    'POST',
    '/api/rate-quote',
    {
      accommodationId: 'acc_test_1',
      ratePlanId: plan.json.data.id,
      checkIn: '2026-12-21',
      checkOut: '2026-12-22'
    },
    token
  );

  assert.equal(ctaBlocked.status, 409);
  assert.equal(ctdBlocked.status, 409);
});

test('POST /api/rate-quote enforces max nights from availability rules', async () => {
  const token = await loginAsAdmin(server);
  const plan = await request(
    server,
    'POST',
    '/api/rate-plans',
    {
      accommodationId: 'acc_test_1',
      name: 'Tarifa MaxNights',
      currency: 'EUR',
      baseNightlyRate: 85
    },
    token
  );

  await request(
    server,
    'POST',
    '/api/availability-rules',
    {
      accommodationId: 'acc_test_1',
      startDate: '2026-12-10',
      endDate: '2026-12-31',
      maxNights: 2
    },
    token
  );

  const tooLong = await request(
    server,
    'POST',
    '/api/rate-quote',
    {
      accommodationId: 'acc_test_1',
      ratePlanId: plan.json.data.id,
      checkIn: '2026-12-12',
      checkOut: '2026-12-15'
    },
    token
  );

  const allowed = await request(
    server,
    'POST',
    '/api/rate-quote',
    {
      accommodationId: 'acc_test_1',
      ratePlanId: plan.json.data.id,
      checkIn: '2026-12-12',
      checkOut: '2026-12-14'
    },
    token
  );

  assert.equal(tooLong.status, 400);
  assert.equal(allowed.status, 200);
});

test('POST /api/rate-quote enforces arrival/departure weekdays', async () => {
  const token = await loginAsAdmin(server);
  const plan = await request(
    server,
    'POST',
    '/api/rate-plans',
    {
      accommodationId: 'acc_test_1',
      name: 'Tarifa Weekdays',
      currency: 'EUR',
      baseNightlyRate: 95
    },
    token
  );

  await request(
    server,
    'POST',
    '/api/availability-rules',
    {
      accommodationId: 'acc_test_1',
      startDate: '2026-03-01',
      endDate: '2026-03-31',
      allowedArrivalWeekdays: [1],
      allowedDepartureWeekdays: [3]
    },
    token
  );

  const invalidArrival = await request(
    server,
    'POST',
    '/api/rate-quote',
    {
      accommodationId: 'acc_test_1',
      ratePlanId: plan.json.data.id,
      checkIn: '2026-03-03',
      checkOut: '2026-03-05'
    },
    token
  );

  const invalidDeparture = await request(
    server,
    'POST',
    '/api/rate-quote',
    {
      accommodationId: 'acc_test_1',
      ratePlanId: plan.json.data.id,
      checkIn: '2026-03-02',
      checkOut: '2026-03-05'
    },
    token
  );

  const valid = await request(
    server,
    'POST',
    '/api/rate-quote',
    {
      accommodationId: 'acc_test_1',
      ratePlanId: plan.json.data.id,
      checkIn: '2026-03-02',
      checkOut: '2026-03-04'
    },
    token
  );

  assert.equal(invalidArrival.status, 409);
  assert.equal(invalidDeparture.status, 409);
  assert.equal(valid.status, 200);
});

test('POST /api/rate-quote enforces advance notice windows', async () => {
  const token = await loginAsAdmin(server);
  const plan = await request(
    server,
    'POST',
    '/api/rate-plans',
    {
      accommodationId: 'acc_test_1',
      name: 'Tarifa Advance',
      currency: 'EUR',
      baseNightlyRate: 88
    },
    token
  );

  await request(
    server,
    'POST',
    '/api/availability-rules',
    {
      accommodationId: 'acc_test_1',
      startDate: '2026-01-01',
      endDate: '2026-12-31',
      minAdvanceHours: 48,
      maxAdvanceDays: 90
    },
    token
  );

  const tooSoon = await request(
    server,
    'POST',
    '/api/rate-quote',
    {
      accommodationId: 'acc_test_1',
      ratePlanId: plan.json.data.id,
      checkIn: '2026-01-02',
      checkOut: '2026-01-04'
    },
    token
  );

  const tooFar = await request(
    server,
    'POST',
    '/api/rate-quote',
    {
      accommodationId: 'acc_test_1',
      ratePlanId: plan.json.data.id,
      checkIn: '2026-06-15',
      checkOut: '2026-06-17'
    },
    token
  );

  const valid = await request(
    server,
    'POST',
    '/api/rate-quote',
    {
      accommodationId: 'acc_test_1',
      ratePlanId: plan.json.data.id,
      checkIn: '2026-02-15',
      checkOut: '2026-02-17'
    },
    token
  );

  assert.equal(tooSoon.status, 409);
  assert.equal(tooFar.status, 409);
  assert.equal(valid.status, 200);
});

test('GET /api/availability-calendar returns booked and closed days', async () => {
  const token = await loginAsAdmin(server);
  const plan = await request(
    server,
    'POST',
    '/api/rate-plans',
    {
      accommodationId: 'acc_test_1',
      name: 'Tarifa Calendar',
      currency: 'EUR',
      baseNightlyRate: 90
    },
    token
  );

  await request(
    server,
    'POST',
    '/api/availability-rules',
    {
      accommodationId: 'acc_test_1',
      startDate: '2026-12-21',
      endDate: '2026-12-21',
      closed: true
    },
    token
  );

  await request(
    server,
    'POST',
    '/api/reservations',
    {
      accommodationId: 'acc_test_1',
      guestName: 'Reserva Calendar',
      checkIn: '2026-12-20',
      checkOut: '2026-12-21'
    },
    token
  );

  const calendar = await request(
    server,
    'GET',
    `/api/availability-calendar?accommodationId=acc_test_1&ratePlanId=${plan.json.data.id}&dateFrom=2026-12-20&dateTo=2026-12-21`,
    null,
    token
  );

  assert.equal(calendar.status, 200);
  assert.equal(calendar.json.ok, true);
  assert.equal(calendar.json.data.days[0].status, 'booked');
  assert.equal(calendar.json.data.days[1].status, 'closed');
});

test('GET /api/availability-calendar includes suggested daily price', async () => {
  const token = await loginAsAdmin(server);
  const plan = await request(
    server,
    'POST',
    '/api/rate-plans',
    {
      accommodationId: 'acc_test_1',
      name: 'Tarifa Price Daily',
      currency: 'EUR',
      baseNightlyRate: 100,
      weekendMultiplier: 1.2,
      extraAdultFee: 10,
      extraChildFee: 5,
      seasonalAdjustments: [
        { startDate: '2026-12-01', endDate: '2026-12-31', multiplier: 1.1 }
      ]
    },
    token
  );

  const calendar = await request(
    server,
    'GET',
    `/api/availability-calendar?accommodationId=acc_test_1&ratePlanId=${plan.json.data.id}&dateFrom=2026-12-05&dateTo=2026-12-05&adults=3&children=1`,
    null,
    token
  );

  assert.equal(calendar.status, 200);
  assert.equal(calendar.json.ok, true);
  assert.equal(calendar.json.data.days.length, 1);
  assert.equal(calendar.json.data.days[0].status, 'available');
  assert.equal(typeof calendar.json.data.days[0].closedToArrival, 'boolean');
  assert.equal(typeof calendar.json.data.days[0].closedToDeparture, 'boolean');
  assert.equal(calendar.json.data.days[0].pricing.suggestedNightlyTotal, 147);
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

test('GET /api/reservations supports sorting and pagination', async () => {
  const token = await loginAsAdmin(server);
  await request(
    server,
    'POST',
    '/api/reservations',
    {
      accommodationId: 'acc_test_1',
      guestName: 'Pag 1',
      checkIn: '2026-12-01',
      checkOut: '2026-12-03'
    },
    token
  );
  await request(
    server,
    'POST',
    '/api/reservations',
    {
      accommodationId: 'acc_test_1',
      guestName: 'Pag 2',
      checkIn: '2026-12-04',
      checkOut: '2026-12-06'
    },
    token
  );
  await request(
    server,
    'POST',
    '/api/reservations',
    {
      accommodationId: 'acc_test_1',
      guestName: 'Pag 3',
      checkIn: '2026-12-07',
      checkOut: '2026-12-09'
    },
    token
  );

  const response = await request(
    server,
    'GET',
    '/api/reservations?sortBy=checkIn&sortDir=asc&page=2&pageSize=2',
    null,
    token
  );

  assert.equal(response.status, 200);
  assert.equal(response.json.meta.page, 2);
  assert.equal(response.json.meta.pageSize, 2);
  assert.equal(response.json.data.length, 1);
  assert.equal(response.json.data[0].guestName, 'Pag 3');
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
