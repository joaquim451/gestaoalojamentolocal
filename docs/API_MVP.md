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
