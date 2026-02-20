const DEFAULT_TIMEOUT_MS = Number(process.env.BOOKING_TIMEOUT_MS || 10000);

function hasCredentials() {
  return Boolean(process.env.BOOKING_USERNAME && process.env.BOOKING_PASSWORD);
}

function getBookingConfig() {
  return {
    baseUrl: process.env.BOOKING_API_BASE_URL || 'https://distribution-xml.booking.com/2.4',
    timeoutMs: DEFAULT_TIMEOUT_MS,
    pingPathTemplate: process.env.BOOKING_CONNECTIVITY_PING_PATH || '/hotels/{hotelId}',
    syncPathTemplate: process.env.BOOKING_CONNECTIVITY_SYNC_PATH || '/hotels/{hotelId}/availability',
    syncMethod: process.env.BOOKING_SYNC_HTTP_METHOD || 'POST',
    syncContentType: process.env.BOOKING_SYNC_CONTENT_TYPE || 'application/json',
    liveCheckEnabled: (process.env.BOOKING_ENABLE_LIVE_CHECK || 'true') === 'true',
    hasCredentials: hasCredentials(),
    usernamePreview: process.env.BOOKING_USERNAME ? `${process.env.BOOKING_USERNAME.slice(0, 3)}***` : null
  };
}

function buildAuthHeader() {
  const username = process.env.BOOKING_USERNAME || '';
  const password = process.env.BOOKING_PASSWORD || '';
  const token = Buffer.from(`${username}:${password}`).toString('base64');
  return `Basic ${token}`;
}

function buildEndpoint(baseUrl, pathTemplate, hotelId) {
  const path = String(pathTemplate || '').replace('{hotelId}', encodeURIComponent(String(hotelId)));
  return `${String(baseUrl).replace(/\/$/, '')}${path.startsWith('/') ? '' : '/'}${path}`;
}

async function bookingRequest({ method, pathTemplate, hotelId, body, contentType }) {
  const cfg = getBookingConfig();
  const url = buildEndpoint(cfg.baseUrl, pathTemplate, hotelId);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), cfg.timeoutMs);

  try {
    const headers = {
      Accept: 'application/json, application/xml, text/xml, */*',
      Authorization: buildAuthHeader()
    };

    if (body !== undefined && body !== null) {
      headers['Content-Type'] = contentType || cfg.syncContentType;
    }

    const response = await fetch(url, {
      method,
      headers,
      body: body !== undefined && body !== null ? body : undefined,
      signal: controller.signal
    });

    const rawBody = await response.text();

    return {
      ok: response.ok,
      status: response.status,
      url,
      bodySnippet: rawBody ? rawBody.slice(0, 500) : ''
    };
  } catch (error) {
    return {
      ok: false,
      status: null,
      url,
      bodySnippet: '',
      error: error && error.name === 'AbortError' ? 'timeout' : String(error)
    };
  } finally {
    clearTimeout(timeout);
  }
}

async function pingBookingConnection(linkConfig) {
  if (!linkConfig || !linkConfig.hotelId) {
    return {
      ok: false,
      message: 'hotelId em falta para validar conexão Booking.'
    };
  }

  if (!hasCredentials()) {
    return {
      ok: false,
      message: 'Credenciais Booking em falta (BOOKING_USERNAME/BOOKING_PASSWORD).'
    };
  }

  const cfg = getBookingConfig();
  if (!cfg.liveCheckEnabled) {
    return {
      ok: true,
      message: 'Ligação validada localmente (BOOKING_ENABLE_LIVE_CHECK=false).'
    };
  }

  const result = await bookingRequest({
    method: 'GET',
    pathTemplate: cfg.pingPathTemplate,
    hotelId: linkConfig.hotelId
  });

  if (!result.ok) {
    return {
      ok: false,
      message: `Falha ao validar ligação Booking. HTTP=${result.status || 'N/A'}`,
      details: result
    };
  }

  return {
    ok: true,
    message: `Ligação Booking validada com sucesso. HTTP=${result.status}`,
    details: result
  };
}

function buildSyncPayload(linkConfig, payload, contentType) {
  if ((contentType || '').includes('xml')) {
    return payload
      || `<sync><hotel_id>${linkConfig.hotelId}</hotel_id><timestamp>${new Date().toISOString()}</timestamp></sync>`;
  }

  return JSON.stringify(
    payload || {
      hotelId: linkConfig.hotelId,
      timestamp: new Date().toISOString()
    }
  );
}

async function syncAccommodation(linkConfig, payload) {
  if (!linkConfig || !linkConfig.enabled) {
    return {
      ok: false,
      message: 'Conexão Booking desligada para este alojamento.'
    };
  }

  if (!linkConfig.hotelId) {
    return {
      ok: false,
      message: 'hotelId em falta para sincronizar com Booking.'
    };
  }

  if (!hasCredentials()) {
    return {
      ok: false,
      message: 'Credenciais Booking em falta (BOOKING_USERNAME/BOOKING_PASSWORD).'
    };
  }

  const cfg = getBookingConfig();
  const body = buildSyncPayload(linkConfig, payload, cfg.syncContentType);

  const result = await bookingRequest({
    method: cfg.syncMethod,
    pathTemplate: cfg.syncPathTemplate,
    hotelId: linkConfig.hotelId,
    body,
    contentType: cfg.syncContentType
  });

  if (!result.ok) {
    return {
      ok: false,
      message: `Falha na sincronização Booking. HTTP=${result.status || 'N/A'}`,
      details: result
    };
  }

  return {
    ok: true,
    message: `Sincronização Booking concluída. HTTP=${result.status}`,
    details: result
  };
}

module.exports = {
  getBookingConfig,
  pingBookingConnection,
  syncAccommodation
};
