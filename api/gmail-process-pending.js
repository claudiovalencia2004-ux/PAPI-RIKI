
"use strict";

// PAPI RIKI - PASO 9.18.1
// Gmail History -> BCP -> Supabase
//
// No activa Gmail Watch.
// No confirma gastos.
// No envia Web Push.
// No modifica index.html.
// Procesamiento autenticado y bajo demanda.

const crypto = require("node:crypto");
const { createClient } = require("@supabase/supabase-js");
const { parseBCP } = require("../lib/bcp-secure-candidate");

const URL = "https://kbwrxebdcpgsplfjpkxv.supabase.co";
const PUBLIC_KEY =
  "sb_publishable_khEJIOxXl5ytDpXFABTWcg_hKC0lak2";

const GMAIL =
  "https://gmail.googleapis.com/gmail/v1/users/me";

const SENDER =
  "notificaciones@notificacionesbcp.com.pe";

const DOMAIN = "notificacionesbcp.com.pe";

const SUBJECT =
  "realizaste un consumo con tu tarjeta de debito bcp";

function reply(res, code, data) {
  return res.status(code).json(data);
}

function validHistory(value) {
  return typeof value === "string" &&
    /^[0-9]{1,30}$/.test(value);
}

function normalize(value) {
  return String(value || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase();
}

function headers(message, name) {
  return (message.payload?.headers || [])
    .filter(h =>
      String(h.name).toLowerCase() ===
      name.toLowerCase()
    )
    .map(h => String(h.value || ""));
}

function senderAddress(value) {
  const match = value.match(
    /<([^<>\s]+@[^<>\s]+)>/
  );

  return (match ? match[1] : value)
    .trim()
    .toLowerCase();
}

function isBCP(message) {
  const from = headers(message, "From");
  const subject = headers(message, "Subject");

  return from.length === 1 &&
    subject.length === 1 &&
    senderAddress(from[0]) === SENDER &&
    normalize(subject[0]).includes(SUBJECT);
}

// Solo se consideran resultados de autenticacion
// atribuidos al receptor mx.google.com.
//
// Este control es conservador. Una cabecera
// Authentication-Results puede ser falsificada
// por un remitente; la confianza en su origen
// debe validarse antes de habilitar produccion.

function checkAuthentication(message) {
  const results = headers(
    message,
    "Authentication-Results"
  );

  const trusted = results.filter(value =>
    /^\s*mx\.google\.com\s*;/i.test(value)
  );

  if (trusted.length !== 1) {
    return false;
  }

  const value = trusted[0].toLowerCase();

  if (!/\bdmarc=pass\b/.test(value)) {
    return false;
  }

  const fromMatch = value.match(
    /\bheader\.from=([a-z0-9.-]+)/i
  );

  if (
    !fromMatch ||
    fromMatch[1] !== DOMAIN
  ) {
    return false;
  }

  const dkim = [...value.matchAll(
    /\bdkim=pass\b[^;\r\n]*?\bheader\.i=@([a-z0-9.-]+)/g
  )];

  const aligned = dkim.some(match =>
    match[1] === DOMAIN ||
    match[1].endsWith("." + DOMAIN)
  );

  // No aceptar un correo sin DKIM alineado.
  return aligned;
}

function decrypt(encrypted, hexKey) {
  if (!/^[a-f0-9]{64}$/i.test(hexKey || "")) {
    throw Error("Encryption configuration invalid");
  }

  const parts = String(encrypted).split(".");

  if (parts.length !== 4 || parts[0] !== "v1") {
    throw Error("Encrypted token invalid");
  }

  const iv = Buffer.from(parts[1], "base64url");
  const tag = Buffer.from(parts[2], "base64url");

  if (iv.length !== 12 || tag.length !== 16) {
    throw Error("Encrypted token invalid");
  }

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    Buffer.from(hexKey, "hex"),
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

async function getAccessToken(encrypted) {
  const env = process.env;

  const refresh = decrypt(
    encrypted,
    env.GMAIL_ENCRYPTION_KEY
  );

  const params = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    client_secret: env.GOOGLE_CLIENT_SECRET,
    refresh_token: refresh,
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
    throw Error("Access token missing");
  }

  return data.access_token;
}

async function gmailGet(path, token, params = {}) {
  const url = new URL(GMAIL + path);

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

  if (!response.ok) {
    const error = new Error("Gmail request failed");
    error.status = response.status;
    throw error;
  }

  return response.json();
}

async function getMessageIds(start, end, token) {
  const ids = new Set();
  let pageToken;
  let completed = false;

  for (let page = 0; page < 10; page++) {
    const data = await gmailGet(
      "/history",
      token,
      {
        startHistoryId: start,
        historyTypes: "messageAdded",
        maxResults: 100,
        pageToken
      }
    );

    if (!validHistory(String(data.historyId || ""))) {
      throw Error("Invalid Gmail history response");
    }

    for (const entry of data.history || []) {
      if (!validHistory(String(entry.id || ""))) {
        throw Error("Invalid history entry");
      }

      if (BigInt(entry.id) > BigInt(end)) {
        continue;
      }

      for (const added of entry.messagesAdded || []) {
        const id = added.message?.id;

        if (id) ids.add(id);

        if (ids.size > 50) {
          throw Error("Too many messages in batch");
        }
      }
    }

    pageToken = data.nextPageToken;

    if (!pageToken) {
      completed = true;
      break;
    }
  }

  if (!completed) {
    throw Error("History pagination incomplete");
  }

  return [...ids];
}

function createClientSafe(key) {
  return createClient(URL, key, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false
    }
  });
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
      message: "Inicia sesion"
    });
  }

  let claimed = false;

  try {
    const auth = createClientSafe(PUBLIC_KEY);

    const { data: authData, error: authError } =
      await auth.auth.getUser(match[1]);

    if (authError || !authData?.user?.id) {
      return reply(res, 401, {
        ok: false,
        message: "Sesion invalida"
      });
    }

    const userId = authData.user.id;
    const admin = createClientSafe(
      env.SUPABASE_SECRET_KEY
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
      !validHistory(monitor.last_history_id)
    ) {
      return reply(res, 409, {
        ok: false,
        message: "Monitor Gmail no inicializado",
        processing_started: false
      });
    }

    const { data: connection, error: connError } =
      await admin
        .from("gmail_connections")
        .select("status,refresh_token_encrypted")
        .eq("user_id", userId)
        .maybeSingle();

    if (
      connError ||
      connection?.status !== "connected" ||
      !connection.refresh_token_encrypted
    ) {
      return reply(res, 409, {
        ok: false,
        message: "Gmail no conectado"
      });
    }

    const token = await getAccessToken(
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
        message: "Sin eventos pendientes",
        candidates_created: 0
      });
    }

    claimed = true;
    const event = claims[0];

    if (!validHistory(event.event_history_id)) {
      throw Error("Invalid event history");
    }

    if (
      BigInt(event.event_history_id) <
      BigInt(monitor.last_history_id)
    ) {
      throw Error("Event precedes cursor");
    }

    const ids = await getMessageIds(
      monitor.last_history_id,
      event.event_history_id,
      token
    );

    let created = 0;
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

      // SEGURIDAD:
      // El parser puede extraer el gasto,
      // pero no se habilita el guardado real
      // hasta validar de forma fiable el
      // origen de Authentication-Results.

      if (!checkAuthentication(message)) {
        throw Error(
          "BCP authentication not verified"
        );
      }

      // Validar los campos del consumo.
      // Esto NO confirma autenticidad por si solo.
      const candidate = parseBCP(message);

      if (
        !message.internalDate ||
        !Number.isFinite(
          Number(message.internalDate)
        )
      ) {
        throw Error("Invalid Gmail receive date");
      }

      if (
        Number(message.internalDate) <
        Date.parse(monitor.started_at)
      ) {
        ignored++;
        continue;
      }

      // Bloqueo deliberado hasta verificar
      // el origen de la cabecera de autenticacion.
      //
      // No establecer authenticationVerified
      // en true basandose solo en el texto
      // de Authentication-Results.
      //
      // La llamada a save_bcp_candidate
      // se habilitara tras esa validacion.

      throw Error(
        "Trusted Gmail authentication integration pending"
      );
    }

    // Solo se llega aqui cuando no hubo
    // candidatos BCP que requieran guardado.
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
      candidates_created: created,
      candidates_existing: existing,
      ignored_messages: ignored,
      cursor_updated: true,
      expenses_confirmed: 0,
      notifications_sent: 0
    });

  } catch (error) {
    console.error("PAPI RIKI Gmail processing failed");

    return reply(res, 503, {
      ok: false,
      message: claimed
        ? "Evento pendiente de recuperacion"
        : "No se pudo iniciar el procesamiento",
      cursor_update_confirmed: false
    });
  }
};
