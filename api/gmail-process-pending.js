
"use strict";

// PAPI RIKI - PASO 9.16.9
// Procesador persistente de Gmail.
// Ejecucion manual autenticada.
// NO activa Gmail Watch.
// NO confirma gastos.
// NO envia notificaciones.
//
// Si un correo BCP no puede interpretarse,
// el evento NO se finaliza.
// El cursor NO avanza.

const crypto = require("node:crypto");
const { createClient } = require("@supabase/supabase-js");

const SUPABASE_URL =
  "https://kbwrxebdcpgsplfjpkxv.supabase.co";

const PUBLIC_KEY =
  "sb_publishable_khEJIOxXl5ytDpXFABTWcg_hKC0lak2";

const GMAIL_API =
  "https://gmail.googleapis.com/gmail/v1/users/me";

const BCP_SENDER =
  "notificaciones@notificacionesbcp.com.pe";

const BCP_SUBJECT =
  "realizaste un consumo con tu tarjeta de debito bcp";

const MONTHS = {
  enero:1, febrero:2, marzo:3, abril:4,
  mayo:5, junio:6, julio:7, agosto:8,
  septiembre:9, octubre:10,
  noviembre:11, diciembre:12
};

function reply(res, status, data) {
  return res.status(status).json(data);
}

function normalize(value) {
  return String(value || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function validId(value) {
  return typeof value === "string" &&
    /^[0-9]{1,30}$/.test(value);
}

function decrypt(value, keyHex) {
  if (!/^[a-f0-9]{64}$/i.test(keyHex || "")) {
    throw Error("Invalid encryption key");
  }

  const parts = String(value || "").split(".");

  if (parts.length !== 4 || parts[0] !== "v1") {
    throw Error("Invalid encrypted token");
  }

  const iv = Buffer.from(parts[1], "base64url");
  const tag = Buffer.from(parts[2], "base64url");

  if (iv.length !== 12 || tag.length !== 16) {
    throw Error("Invalid encryption format");
  }

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    Buffer.from(keyHex, "hex"),
    iv
  );

  decipher.setAuthTag(tag);

  return Buffer.concat([
    decipher.update(
      Buffer.from(parts[3], "base64url")
    ),
    decipher.final()
  ]).toString("utf8");
}

async function accessToken(encrypted) {
  const env = process.env;

  const refreshToken = decrypt(
    encrypted,
    env.GMAIL_ENCRYPTION_KEY
  );

  const params = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    client_secret: env.GOOGLE_CLIENT_SECRET,
    refresh_token: refreshToken,
    grant_type: "refresh_token"
  });

  const response = await fetch(
    "https://oauth2.googleapis.com/token",
    {
      method: "POST",
      headers: {
        "Content-Type":
          "application/x-www-form-urlencoded"
      },
      body: params.toString(),
      signal: AbortSignal.timeout(12000)
    }
  );

  if (!response.ok) {
    throw Error("OAuth refresh failed");
  }

  const data = await response.json();

  if (!data.access_token) {
    throw Error("Missing access token");
  }

  return data.access_token;
}

async function gmailGet(path, token, params = {}) {
  const url = new URL(GMAIL_API + path);

  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) {
      url.searchParams.set(key, String(value));
    }
  }

  const response = await fetch(url, {
    headers: {
      Authorization: "Bearer " + token
    },
    signal: AbortSignal.timeout(12000)
  });

  // No ignorar mensajes eliminados o historiales
  // caducados: requieren recuperacion explicita.
  if (!response.ok) {
    const error = new Error("Gmail API failure");
    error.status = response.status;
    throw error;
  }

  return response.json();
}

function header(message, name) {
  const headers = message.payload?.headers || [];

  return headers.find(
    h => String(h.name).toLowerCase() ===
      name.toLowerCase()
  )?.value || "";
}

function decode(value) {
  return Buffer.from(
    value,
    "base64url"
  ).toString("utf8");
}

function plainText(part, depth = 0) {
  if (!part || depth > 12) {
    return "";
  }

  if (
    part.mimeType === "text/plain" &&
    part.body?.data
  ) {
    return decode(part.body.data);
  }

  for (const child of part.parts || []) {
    const text = plainText(child, depth + 1);

    if (text) return text;
  }

  return "";
}

function isBCP(message) {
  const from = normalize(
    header(message, "From")
  ).toLowerCase();

  const address = from.includes("<")
    ? from.match(/<([^<>]+)>/)?.[1]
    : from;

  const subject = normalize(
    header(message, "Subject")
  ).toLowerCase();

  return (
    address === BCP_SENDER &&
    subject.includes(BCP_SUBJECT)
  );
}

function parseAmount(value) {
  let raw = String(value).trim();

  if (!/^\d[\d.,]*$/.test(raw)) {
    throw Error("Invalid amount");
  }

  if (raw.includes(",") && raw.includes(".")) {
    raw = raw.lastIndexOf(",") >
      raw.lastIndexOf(".")
      ? raw.replace(/\./g, "").replace(",", ".")
      : raw.replace(/,/g, "");
  } else if (raw.includes(",")) {
    const parts = raw.split(",");

    raw = parts.length === 2 &&
      parts[1].length === 2
      ? raw.replace(",", ".")
      : raw.replace(/,/g, "");
  }

  const amount = Number(raw);

  if (
    !Number.isFinite(amount) ||
    amount <= 0 ||
    amount > 999999999 ||
    amount !== Math.round(amount * 100) / 100
  ) {
    throw Error("Invalid amount");
  }

  return amount;
}

function parseDate(body) {
  const match = body.match(
    /Fecha y hora\s+(\d{1,2}) de ([a-z]+) de (\d{4})\s*-\s*(\d{1,2}):(\d{2})\s*(AM|PM)/i
  );

  if (!match) {
    throw Error("Missing transaction date");
  }

  const day = Number(match[1]);
  const month = MONTHS[match[2].toLowerCase()];
  const year = Number(match[3]);
  const hour12 = Number(match[4]);
  const minute = Number(match[5]);

  if (
    !month ||
    year < 2000 ||
    year > 2100 ||
    hour12 < 1 ||
    hour12 > 12 ||
    minute > 59
  ) {
    throw Error("Invalid transaction date");
  }

  const check = new Date(
    Date.UTC(year, month - 1, day)
  );

  if (
    check.getUTCFullYear() !== year ||
    check.getUTCMonth() !== month - 1 ||
    check.getUTCDate() !== day
  ) {
    throw Error("Invalid calendar date");
  }

  const hour = hour12 % 12 +
    (match[6].toUpperCase() === "PM" ? 12 : 0);

  return new Date(
    `${year}-${String(month).padStart(2, "0")}-` +
    `${String(day).padStart(2, "0")}T` +
    `${String(hour).padStart(2, "0")}:` +
    `${String(minute).padStart(2, "0")}:00-05:00`
  ).toISOString();
}

function parseBCP(message) {
  const body = normalize(
    plainText(message.payload)
  );

  if (!body) {
    throw Error("BCP plain text unavailable");
  }

  if (!/Consumo Tarjeta de Debito/i.test(body)) {
    throw Error("BCP operation unrecognized");
  }

  const amount = body.match(
    /Total del consumo\s*(S\/|US\$|\$)\s*(\d[\d.,]*)/i
  );

  const merchant = body.match(
    /Empresa\s+(.+?)(?=\s+Numero de operacion|\s+No reconoces|\s+Seguimos mejorando|$)/i
  );

  if (!amount || !merchant) {
    throw Error("BCP fields missing");
  }

  const name = merchant[1].trim();

  if (
    !name ||
    name.length > 150 ||
    /^(Numero de operacion|No reconoces|Seguimos mejorando)\b/i
      .test(name)
  ) {
    throw Error("Invalid merchant");
  }

  return {
    gmail_message_id: message.id,
    merchant: name,
    amount: parseAmount(amount[2]),
    currency: amount[1] === "S/" ? "PEN" : "USD",
    transaction_date: parseDate(body)
  };
}

async function readHistory(start, end, token) {
  const ids = new Set();
  let pageToken;
  let complete = false;

  for (let page = 0; page < 10; page++) {
    const result = await gmailGet(
      "/history",
      token,
      {
        startHistoryId: start,
        historyTypes: "messageAdded",
        maxResults: 100,
        pageToken
      }
    );

    if (!validId(String(result.historyId || ""))) {
      throw Error("Invalid history response");
    }

    for (const item of result.history || []) {
      if (!validId(String(item.id || ""))) {
        throw Error("Invalid history entry");
      }

      // No procesar cambios posteriores
      // al evento reservado.
      if (BigInt(item.id) > BigInt(end)) {
        continue;
      }

      for (const added of item.messagesAdded || []) {
        if (added.message?.id) {
          ids.add(added.message.id);
        }

        if (ids.size > 50) {
          throw Error("Batch too large");
        }
      }
    }

    pageToken = result.nextPageToken;

    if (!pageToken) {
      complete = true;
      break;
    }
  }

  if (!complete) {
    throw Error("History pagination incomplete");
  }

  return [...ids];
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Allow", "POST");

  if (req.method !== "POST") {
    return reply(res, 405, {
      ok: false,
      message: "Metodo no permitido"
    });
  }

  const env = process.env;

  if (
    !env.SUPABASE_SECRET_KEY ||
    !env.GOOGLE_CLIENT_ID ||
    !env.GOOGLE_CLIENT_SECRET ||
    !env.GMAIL_ENCRYPTION_KEY
  ) {
    return reply(res, 503, {
      ok: false,
      message: "Configuracion incompleta"
    });
  }

  const match = String(
    req.headers.authorization || ""
  ).match(/^Bearer\s+(\S+)$/i);

  if (!match) {
    return reply(res, 401, {
      ok: false,
      message: "Autenticacion requerida"
    });
  }

  let claimed = false;

  try {
    const auth = createClient(
      SUPABASE_URL,
      PUBLIC_KEY,
      {
        auth: {
          persistSession: false,
          autoRefreshToken: false
        }
      }
    );

    const { data: authData, error: authError } =
      await auth.auth.getUser(match[1]);

    if (authError || !authData?.user?.id) {
      return reply(res, 401, {
        ok: false,
        message: "Sesion invalida"
      });
    }

    const userId = authData.user.id;

    const admin = createClient(
      SUPABASE_URL,
      env.SUPABASE_SECRET_KEY,
      {
        auth: {
          persistSession: false,
          autoRefreshToken: false
        }
      }
    );

    const { data: monitor, error: monitorError } =
      await admin
        .from("gmail_monitor_state")
        .select(
          "last_history_id,monitor_status,started_at"
        )
        .eq("user_id", userId)
        .maybeSingle();

    if (monitorError) throw monitorError;

    if (
      !monitor ||
      monitor.monitor_status !== "active" ||
      !validId(monitor.last_history_id)
    ) {
      return reply(res, 409, {
        ok: false,
        message: "Monitor no inicializado",
        processing_started: false
      });
    }

    const { data: connection, error: connectionError } =
      await admin
        .from("gmail_connections")
        .select("refresh_token_encrypted,status")
        .eq("user_id", userId)
        .maybeSingle();

    if (
      connectionError ||
      !connection ||
      connection.status !== "connected" ||
      !connection.refresh_token_encrypted
    ) {
      return reply(res, 409, {
        ok: false,
        message: "Gmail no conectado"
      });
    }

    // No reclamar el evento hasta comprobar
    // que podemos obtener un token de Gmail.
    const token = await accessToken(
      connection.refresh_token_encrypted
    );

    const { data: claims, error: claimError } =
      await admin.rpc("claim_gmail_event", {
        p_user_id: userId
      });

    if (claimError) throw claimError;

    if (!claims?.length) {
      return reply(res, 200, {
        ok: true,
        message: "No hay eventos disponibles",
        processed: 0
      });
    }

    claimed = true;

    const event = claims[0];

    if (!validId(event.event_history_id)) {
      throw Error("Invalid event history");
    }

    if (
      BigInt(event.event_history_id) <
      BigInt(monitor.last_history_id)
    ) {
      throw Error("Event precedes current cursor");
    }

    const ids = await readHistory(
      monitor.last_history_id,
      event.event_history_id,
      token
    );

    let saved = 0;
    let existing = 0;
    let ignored = 0;

    for (const id of ids) {
      const message = await gmailGet(
        "/messages/" + encodeURIComponent(id),
        token,
        { format: "full" }
      );

      if (!isBCP(message)) {
        ignored++;
        continue;
      }

      // El remitente visible NO prueba
      // autenticidad. Bloquear el guardado
      // hasta implementar esa verificacion.
      throw Error(
        "BCP authentication verification pending"
      );

      // El guardado mediante save_bcp_candidate
      // se habilitara exclusivamente despues
      // de validar la autenticidad del mensaje.
    }

    // Finalizar solo cuando todas las páginas
    // y mensajes fueron atendidos sin error.
    const { data: finished, error: finishError } =
      await admin.rpc("finish_gmail_event", {
        p_user_id: userId,
        p_event_id: event.event_id,
        p_claim_token: event.reservation_token,
        p_new_history_id: event.event_history_id
      });

    if (finishError || finished !== true) {
      throw Error("Atomic completion failed");
    }

    return reply(res, 200, {
      ok: true,
      event_completed: true,
      scanned_messages: ids.length,
      candidates_created: saved,
      candidates_existing: existing,
      ignored_messages: ignored,
      cursor_updated: true,
      expenses_confirmed: 0,
      notifications_sent: 0
    });

  } catch (error) {
    console.error("Gmail processor failed");

    return reply(res, 503, {
      ok: false,
      message: claimed
        ? "Evento pendiente de recuperacion"
        : "No se pudo iniciar el procesamiento",
      cursor_update_confirmed: false
    });
  }
};
