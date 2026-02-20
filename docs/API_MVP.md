# API MVP (Backend)

Base URL local: `http://localhost:3000`

## Health
- `GET /health`

## Configuração Booking
- `GET /api/config/booking`
- Retorna apenas metadados (sem password), incluindo `hasCredentials`.

## Alojamentos
- `GET /api/accommodations`
- `POST /api/accommodations`
  - body mínimo:
```json
{
  "name": "Apartamento Alfama"
}
```

## Reservas
- `GET /api/reservations`
  - filtros opcionais: `accommodationId`, `status`, `dateFrom`, `dateTo`
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

## Calendário Unificado (MVP)
- `GET /api/calendar?accommodationId=acc_123&dateFrom=2026-03-01&dateTo=2026-03-31`
- retorna reservas ativas do alojamento no intervalo (exclui `cancelled`)

## Booking API - Ligar/Desligar por Alojamento
- `PATCH /api/accommodations/:id/booking-connection`
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
- `POST /api/accommodations/:id/booking-sync`
- O corpo enviado é repassado para o endpoint configurado de sync.
- Se vazio, backend envia payload default (`hotelId`, `timestamp`) em JSON ou XML conforme config.

## Compliance utilitário
- `GET /api/legal/complaints-book-link`

## Variáveis de ambiente (Booking)
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
