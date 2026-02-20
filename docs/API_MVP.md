# API MVP (Backend)

Base URL local: `http://localhost:3000`

## Health
- `GET /health`

## Autenticação
- `POST /api/auth/login`
```json
{
  "email": "admin@gestaoalojamentolocal.local",
  "password": "change-me-now"
}
```
- Após tentativas falhadas consecutivas, a conta fica temporariamente bloqueada (`HTTP 423`).
- `GET /api/auth/me` (requer Bearer token)
- `POST /api/auth/change-password` (requer Bearer token)
```json
{
  "currentPassword": "change-me-now",
  "newPassword": "new-strong-password-123"
}
```
- `POST /api/auth/refresh`
```json
{
  "refreshToken": "opaque-refresh-token"
}
```
- `POST /api/auth/logout` (requer Bearer token)
```json
{
  "refreshToken": "opaque-refresh-token"
}
```
ou
```json
{
  "allSessions": true
}
```
- Todos os endpoints `/api/*` exceto `/api/auth/login` e `/api/auth/refresh` requerem header:
  - `Authorization: Bearer <token>`

## Utilizadores
- `GET /api/users` (apenas role `admin`)
- `POST /api/users` (apenas role `admin`)
```json
{
  "name": "Gestor Operacional",
  "email": "gestor@empresa.pt",
  "password": "password-segura-123",
  "role": "manager"
}
```
- `role` permitida: `admin`, `manager`

## Auditoria
- `GET /api/audit-logs` (apenas role `admin`)
  - filtros opcionais: `action`, `userId`, `limit` (max 500), `page`, `pageSize`, `sortBy`, `sortDir`
  - devolve eventos por ordem mais recente primeiro

## Configuração Booking
- `GET /api/config/booking` (apenas role `admin`)
- Retorna apenas metadados (sem password), incluindo `hasCredentials`.

## Alojamentos
- `GET /api/accommodations`
  - query opcionais: `page`, `pageSize`, `sortBy`, `sortDir`
- `POST /api/accommodations`
  - body mínimo:
```json
{
  "name": "Apartamento Alfama"
}
```
- `GET /api/accommodations/:id`
- `PUT /api/accommodations/:id`
  - permite atualizar: `name`, `city`, `municipality`, `localRegistrationNumber`
- `DELETE /api/accommodations/:id`
  - bloqueia se existirem reservas ativas
  - para remoção forçada (e apagar reservas associadas): `DELETE /api/accommodations/:id?force=true`

## Rate Plans e Cotação
- `GET /api/rate-plans`
  - filtros opcionais: `accommodationId`
  - paginação/ordenação opcionais: `page`, `pageSize`, `sortBy`, `sortDir`
- `POST /api/rate-plans`
```json
{
  "accommodationId": "acc_123",
  "name": "Tarifa Standard",
  "currency": "EUR",
  "baseNightlyRate": 95,
  "weekendMultiplier": 1.2,
  "extraAdultFee": 15,
  "extraChildFee": 8,
  "minNights": 1,
  "seasonalAdjustments": [
    {
      "startDate": "2026-12-01",
      "endDate": "2026-12-31",
      "multiplier": 1.1
    }
  ]
}
```
- `POST /api/rate-quote`
```json
{
  "accommodationId": "acc_123",
  "ratePlanId": "rp_123",
  "checkIn": "2026-12-04",
  "checkOut": "2026-12-06",
  "adults": 3,
  "children": 1
}
```

## Regras de Disponibilidade
- `GET /api/availability-rules`
  - filtros opcionais: `accommodationId`
  - paginação/ordenação opcionais: `page`, `pageSize`, `sortBy`, `sortDir`
- `POST /api/availability-rules`
```json
{
  "accommodationId": "acc_123",
  "startDate": "2026-12-24",
  "endDate": "2026-12-26",
  "closed": true,
  "closedToArrival": false,
  "closedToDeparture": false,
  "minNights": 0,
  "maxNights": 0,
  "note": "Natal fechado"
}
```
- Efeito no `POST /api/rate-quote`:
  - bloqueia cotação em datas `closed=true` (`HTTP 409`)
  - bloqueia check-in em datas `closedToArrival=true`
  - bloqueia check-out em datas `closedToDeparture=true`
  - aplica estadia mínima por período (`minNights`)
  - aplica estadia máxima por período (`maxNights`)

## Calendário de Disponibilidade (Diário)
- `GET /api/availability-calendar`
  - query obrigatórios: `accommodationId`, `dateFrom`, `dateTo`
  - query opcionais: `ratePlanId`, `adults`, `children`
  - devolve por dia:
    - estado (`available`, `booked`, `closed`)
    - IDs de reservas a ocupar a data
    - regras de disponibilidade acionadas
    - flags de restrição (`closedToArrival`, `closedToDeparture`, `minNightsConstraint`, `maxNightsConstraint`)
    - preço sugerido por noite (quando existir rate plan)

## Reservas
- `GET /api/reservations`
  - filtros opcionais: `accommodationId`, `status`, `dateFrom`, `dateTo`
  - paginação/ordenação opcionais: `page`, `pageSize`, `sortBy`, `sortDir`
- `POST /api/reservations`
  - body mínimo:
```json
{
  "accommodationId": "acc_123",
  "guestName": "Maria Silva",
  "checkIn": "2026-03-10",
  "checkOut": "2026-03-14"
}
```
  - campos opcionais: `adults`, `children`, `source`, `status`
  - validações:
    - `checkOut` tem de ser posterior a `checkIn`
    - evita sobreposição de datas no mesmo alojamento (reservas `cancelled` não bloqueiam)
- `PATCH /api/reservations/:id/status`
  - body:
```json
{
  "status": "cancelled"
}
```
  - valores permitidos: `confirmed`, `cancelled`, `checked_in`, `checked_out`
- `GET /api/reservations/:id`
- `PUT /api/reservations/:id`
  - permite atualizar: `guestName`, `checkIn`, `checkOut`, `adults`, `children`, `source`, `status`
  - mantém validações de datas e sobreposição
- `DELETE /api/reservations/:id`
  - remove reserva do registo local

## Calendário Unificado (MVP)
- `GET /api/calendar?accommodationId=acc_123&dateFrom=2026-03-01&dateTo=2026-03-31`
- retorna reservas ativas do alojamento no intervalo (exclui `cancelled`)

## Booking API - Ligar/Desligar por Alojamento
- `PATCH /api/accommodations/:id/booking-connection` (apenas role `admin`)
  - liga (com validação live):
```json
{
  "enabled": true,
  "hotelId": "1234567"
}
```
  - liga forçado (guarda mesmo com falha de validação):
```json
{
  "enabled": true,
  "hotelId": "1234567",
  "force": true
}
```
  - desliga:
```json
{
  "enabled": false
}
```

Regras:
- Para ligar (`enabled=true`), é obrigatório `hotelId` (se ainda não existir guardado).
- Com validação live ativa, o backend testa ligação à Booking via HTTP Basic Auth.
- O estado fica persistido por alojamento.

## Booking API - Sincronização Real (HTTP)
- `POST /api/accommodations/:id/booking-sync` (apenas role `admin`)
- O corpo enviado é repassado para o endpoint configurado de sync.
- Se vazio, backend envia payload default (`hotelId`, `timestamp`) em JSON ou XML conforme config.

## Compliance utilitário
- `GET /api/legal/complaints-book-link`

## Variáveis de ambiente (Booking)
- `AUTH_JWT_SECRET`
- `AUTH_TOKEN_TTL_SECONDS`
- `AUTH_PASSWORD_MIN_LENGTH`
- `AUTH_LOGIN_MAX_ATTEMPTS`
- `AUTH_LOGIN_LOCK_MINUTES`
- `AUTH_REFRESH_TOKEN_TTL_DAYS`
- `AUTH_BOOTSTRAP_ADMIN_NAME`
- `AUTH_BOOTSTRAP_ADMIN_EMAIL`
- `AUTH_BOOTSTRAP_ADMIN_PASSWORD`
- `BOOKING_USERNAME`
- `BOOKING_PASSWORD`
- `BOOKING_API_BASE_URL`
- `BOOKING_CONNECTIVITY_PING_PATH`
- `BOOKING_CONNECTIVITY_SYNC_PATH`
- `BOOKING_SYNC_HTTP_METHOD`
- `BOOKING_SYNC_CONTENT_TYPE`
- `BOOKING_ENABLE_LIVE_CHECK`

## Arranque
1. `npm install`
2. Definir variáveis em `.env` (a partir de `.env.example`)
3. `npm run dev` ou `npm start`
