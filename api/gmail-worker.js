
"use strict";

// PAPI RIKI - WORKER GMAIL
// Procesa eventos reales bajo demanda.
// NO activa Gmail Watch.
// NO confirma gastos.
// NO envia Web Push.
//
// Los candidatos son avisos NO VERIFICADOS.
// Requieren confirmacion individual.

const crypto = require("node:crypto");
const { createClient } = require("@supabase/supabase-js");
const { parseBCP } = require("../lib/bcp-secure-candidate");

const SUPABASE_URL =
  "https://kbwrxebdcpgsplfjpkxv.supabase.co";

const GMAIL =
  "https://gmail.googleapis.com/gmail/v1/users/me";

function respond(res, status, data) {
  return res.status(status).json(data);
}

function validHistory(value) {
  return typeof value === "string" &&
    /^[0-9]{1,30}$/.test(value);
}

function authorized(req) {
  const secret = process.env.GMAIL_WORKER_SECRET;

  if (!secret || Buffer.byteLength(secret) < 32) {
    return false;
  }

  const match = String(
    req.headers.authorization || ""
  ).match(/^Bearer\s+(\S+)$/i);

  if (!match) return false;

  const received = Buffer.from(match[1]);
  const expected = Buffer.from(secret);

  return received.length === expected.length &&
    crypto.timingSafeEqual(received, expected);
}

function adminClient() {
  if (!process.env.SUPABASE_SECRET_KEY) {
    throw Error("Missing Supabase configuration");
  }

  return createClient(
    SUPABASE_URL,
    process.env.SUPABASE_SECRET_KEY,
    {
      auth: {
        persistSession: false,
        autoRefreshToken: false
      }
    }
  );
}

function decrypt(encrypted) {
  const keyHex = process.env.GMAIL_ENCRYPTION_KEY;

  if (!/^[a-f0-9]{64}$/i.test(keyHex || "")) {
    throw Error("Invalid encryption configuration");
  }

  const parts = String(encrypted || "").split(".");

  if (parts.length !== 4 || parts[0] !== "v1") {
    throw Error("Invalid encrypted token");
  }

  const iv = Buffer.from(parts[1], "base64url");
  const tag = Buffer.from(parts[2], "base64url");

  if (iv.length !== 12 || tag.length !== 16) {
    throw Error("Invalid encryption metadata");
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

async function getAccessToken(encrypted) {
  const env = process.env;

  if (!env.GOOGLE_CLIENT_ID ||
      !env.GOOGLE_CLIENT_SECRET) {
    throw Error("Google OAuth configuration missing");
  }

  const body = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    client_secret: env.GOOGLE_CLIENT_SECRET,
    refresh_token: decrypt(encrypted),
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
      body: body.toString(),
      signal: AbortSignal.timeout(12000)
    }
  );

  if (!response.ok) {
    throw Error("Google OAuth refresh failed");
  }

  const data = await response.json();

  if (!data.access_token) {
    throw Error("Google access token missing");
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
    const error = new Error("Gmail API request failed");
    error.status = response.status;
    throw error;
  }

  return response.json();
}

async function readHistory(start, end, token) {
  const ids = new Set();
  let pageToken;
  let finished = false;

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

    if (!validHistory(String(result.historyId || ""))) {
      throw Error("Invalid history response");
    }

    for (const entry of result.history || []) {
      if (!validHistory(String(entry.id || ""))) {
        throw Error("Invalid history entry");
      }

      if (BigInt(entry.id) > BigInt(end)) {
        continue;
      }

      for (const item of entry.messagesAdded || []) {
        const id = item.message?.id;

        if (typeof id === "string" && id) {
          ids.add(id);
        }

        if (ids.size > 30) {
          throw Error("Batch exceeds safe limit");
        }
      }
    }

    pageToken = result.nextPageToken;

    if (!pageToken) {
      finished = true;
      break;
    }
  }

  if (!finished) {
    throw Error("Incomplete Gmail history");
  }

  return [...ids];
}

function normalize(value) {
  return String(value || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase();
}

function header(message, name) {
  return (message.payload?.headers || [])
    .filter(h =>
      String(h.name).toLowerCase() ===
      name.toLowerCase()
    )
    .map(h => String(h.value || ""));
}

function isBCP(message) {
  const from = header(message, "From");
  const subject = header(message, "Subject");

  if (from.length !== 1 || subject.length !== 1) {
    return false;
  }

  const match = from[0].match(
    /<([^<>\s]+@[^<>\s]+)>/
  );

  const address = (match ? match[1] : from[0])
    .trim()
    .toLowerCase();

  return (
    address ===
      "notificaciones@notificacionesbcp.com.pe" &&
    normalize(subject[0]).includes(
      "realizaste un consumo con tu tarjeta de debito bcp"
    )
  );
}

async function processUser(admin, monitor) {
  const userId = monitor.user_id;

  if (!validHistory(monitor.last_history_id)) {
    throw Error("Monitor cursor invalid");
  }

  const { data: connection, error: connectionError } =
    await admin
      .from("gmail_connections")
      .select("refresh_token_encrypted,status")
      .eq("user_id", userId)
      .maybeSingle();

  if (
    connectionError ||
    connection?.status !== "connected" ||
    !connection.refresh_token_encrypted
  ) {
    throw Error("Gmail connection unavailable");
  }

  const token = await getAccessToken(
    connection.refresh_token_encrypted
  );

  const { data: claims, error: claimError } =
    await admin.rpc("claim_gmail_event", {
      p_user_id: userId
    });

  if (claimError) {
    throw Error("Event reservation failed");
  }

  if (!claims?.length) {
    return {
      processed: false,
      candidates_created: 0
    };
  }

  const event = claims[0];

  if (!validHistory(event.event_history_id)) {
    throw Error("Invalid event history ID");
  }

  // Un evento antiguo puede quedar pendiente
  // despues de que el cursor haya avanzado.
  // No debe provocar una regresion.
  if (
    BigInt(event.event_history_id) <
    BigInt(monitor.last_history_id)
  ) {
    throw Error("Stale event requires reconciliation");
  }

  const ids = await readHistory(
    monitor.last_history_id,
    event.event_history_id,
    token
  );

  let created = 0;
  let existing = 0;

  for (const id of ids) {
    const message = await gmailGet(
      "/messages/" + encodeURIComponent(id),
      token,
      { format: "full" }
    );

    if (!isBCP(message)) {
      continue;
    }

    const received = Number(message.internalDate);

    if (
      !Number.isFinite(received) ||
      received <= 0 ||
      !Number.isFinite(
        Date.parse(monitor.started_at)
      )
    ) {
      throw Error("Invalid message timestamp");
    }

    if (received < Date.parse(monitor.started_at)) {
      continue;
    }

    // Solo candidato pendiente de revision.
    // From y Subject NO prueban autenticidad.
    const candidate = parseBCP(message);

    const { data: saved, error: saveError } =
      await admin.rpc("save_bcp_candidate", {
        p_user_id: userId,
        p_gmail_message_id:
          candidate.gmail_message_id,
        p_merchant: candidate.merchant,
        p_amount: candidate.amount,
        p_currency: candidate.currency,
        p_transaction_date:
          candidate.transaction_date
      });

    if (saveError || saved?.length !== 1) {
      throw Error("Candidate save failed");
    }

    if (saved[0].was_created) {
      created++;
    } else {
      existing++;
    }
  }

  // Solo avanzar si todas las lecturas
  // y escrituras terminaron correctamente.
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

  return {
    processed: true,
    candidates_created: created,
    candidates_existing: existing,
    messages_scanned: ids.length
  };
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Allow", "POST");

  if (req.method !== "POST") {
    return respond(res, 405, {
      ok: false,
      message: "Method not allowed"
    });
  }

  if (!authorized(req)) {
    return respond(res, 401, {
      ok: false,
      message: "Unauthorized"
    });
  }

  try {
    const admin = adminClient();

    const { data: monitors, error } =
      await admin
        .from("gmail_monitor_state")
        .select(
          "user_id,last_history_id,started_at,monitor_status"
        )
        .eq("monitor_status", "active")
        .limit(5);

    if (error) {
      throw Error("Monitor query failed");
    }

    const results = [];
    let failures = 0;

    for (const monitor of monitors || []) {
      try {
        const result = await processUser(
          admin,
          monitor
        );

        results.push(result);
      } catch {
        failures++;

        // No registrar correos, tokens
        // ni datos bancarios.
        console.error(
          "Gmail processing requires recovery"
        );
      }
    }

    return respond(res, failures ? 503 : 200, {
      ok: failures === 0,
      worker: "gmail-history",
      active_monitors: (monitors || []).length,
      events_completed: results.filter(
        r => r.processed
      ).length,
      candidates_created: results.reduce(
        (sum, r) =>
          sum + (r.candidates_created || 0),
        0
      ),
      failures,
      expenses_confirmed: 0,
      notifications_sent: 0,
      gmail_watch_activated: false
    });

  } catch {
    console.error("Gmail worker failed");

    return respond(res, 503, {
      ok: false,
      message: "Worker unavailable"
    });
  }
};
