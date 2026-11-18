
"use strict";

// PAPI RIKI - PASO 9.18.3
// Gmail History -> BCP -> Supabase
//
// Guarda candidatos NO VERIFICADOS como pending.
// No registra movimientos financieros.
// No confirma gastos.
// No envia Web Push.
// No activa Gmail Watch.
//
// Requiere:
// - Supabase Auth
// - gmail_connections
// - gmail_monitor_state
// - gmail_events
// - save_bcp_candidate
// - claim_gmail_event
// - finish_gmail_event
// - lib/bcp-secure-candidate.js

const crypto = require("node:crypto");
const { createClient } = require("@supabase/supabase-js");
const { parseBCP } = require("../lib/bcp-secure-candidate");

const SUPABASE_URL =
  "https://kbwrxebdcpgsplfjpkxv.supabase.co";

const PUBLIC_KEY =
  "sb_publishable_khEJIOxXl5ytDpXFABTWcg_hKC0lak2";

const GMAIL_API =
  "https://gmail.googleapis.com/gmail/v1/users/me";

function reply(res, status, data) {
  return res.status(status).json(data);
}

function validHistory(value) {
  return typeof value === "string" &&
    /^[0-9]{1,30}$/.test(value);
}

function supabase(key) {
  return createClient(SUPABASE_URL, key, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false
    }
  });
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
    throw Error("Invalid encrypted token");
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

async function refreshToken(encrypted) {
  const env = process.env;

  const refresh = decrypt(
    encrypted,
    env.GMAIL_ENCRYPTION_KEY
  );

  const body = new URLSearchParams({
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
      body: body.toString(),
      signal: AbortSignal.timeout(12000)
    }
  );

  if (!response.ok) {
    throw Error("OAuth refresh failed");
  }

  const result = await response.json();

  if (!result.access_token) {
    throw Error("Access token unavailable");
  }

  return result.access_token;
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

  if (!response.ok) {
    const error = new Error("Gmail API failed");
    error.status = response.status;
    throw error;
  }

  return response.json();
}

async function readHistory(start, end, token) {
  const ids = new Set();
  let pageToken;
  let completed = false;

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
      throw Error("Invalid Gmail history");
    }

    for (const entry of result.history || []) {
      if (!validHistory(String(entry.id || ""))) {
        throw Error("Invalid history entry");
      }

      if (BigInt(entry.id) > BigInt(end)) {
        continue;
      }

      for (const added of entry.messagesAdded || []) {
        const id = added.message?.id;

        if (typeof id === "string" && id) {
          ids.add(id);
        }

        if (ids.size > 50) {
          throw Error("Batch limit exceeded");
        }
      }
    }

    pageToken = result.nextPageToken;

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

function possibleBCP(message) {
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

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Allow", "POST");

  if (req.method !== "POST") {
    return reply(res, 405, {
      ok: false,
      message: "Method not allowed"
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
      message: "Server configuration incomplete"
    });
  }

  const authorization = String(
    req.headers.authorization || ""
  );

  const match = authorization.match(
    /^Bearer\s+(\S+)$/i
  );

  if (!match) {
    return reply(res, 401, {
      ok: false,
      message: "Authentication required"
    });
  }

  try {
    const auth = supabase(PUBLIC_KEY);

    const { data: identity, error: authError } =
      await auth.auth.getUser(match[1]);

    if (authError || !identity?.user?.id) {
      return reply(res, 401, {
        ok: false,
        message: "Invalid session"
      });
    }

    const userId = identity.user.id;
    const admin = supabase(env.SUPABASE_SECRET_KEY);

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
        message: "Gmail monitor not initialized",
        cursor_updated: false
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
        message: "Gmail not connected"
      });
    }

    const token = await refreshToken(
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
        message: "No events available",
        candidates_created: 0
      });
    }

    const event = claims[0];

    // Desde este punto, un fallo deja
    // el evento reservado para recuperacion.
    // No se avanza el cursor si hay errores.

    try {
      if (!validHistory(event.event_history_id)) {
        throw Error("Invalid event cursor");
      }

      if (
        BigInt(event.event_history_id) <
        BigInt(monitor.last_history_id)
      ) {
        throw Error("Event cursor is outdated");
      }

      const ids = await readHistory(
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

        if (!possibleBCP(message)) {
          ignored++;
          continue;
        }

        const received = Number(
          message.internalDate
        );

        if (
          !Number.isFinite(received) ||
          received <= 0 ||
          !Number.isFinite(
            Date.parse(monitor.started_at)
          )
        ) {
          throw Error("Invalid receive timestamp");
        }

        if (received < Date.parse(monitor.started_at)) {
          ignored++;
          continue;
        }

        // Un mensaje que coincide con el remitente
        // visible NO es necesariamente autentico.
        //
        // Solo se guarda como candidato pendiente.
        // Nunca como gasto financiero confirmado.

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
          throw Error("Candidate persistence failed");
        }

        if (saved[0].was_created) {
          created++;
        } else {
          existing++;
        }
      }

      // Finalizar unicamente despues de
      // procesar y guardar todos los mensajes.
      //
      // La RPC verifica el token de reserva
      // y actualiza evento y cursor juntos.

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
        notifications_sent: 0,
        review_required: true
      });

    } catch (error) {
      console.error("Gmail batch failed");

      return reply(res, 503, {
        ok: false,
        message: "Event retained for recovery",
        cursor_update_confirmed: false
      });
    }

  } catch (error) {
    console.error("Gmail processing initialization failed");

    return reply(res, 503, {
      ok: false,
      message: "Unable to start Gmail processing"
    });
  }
};
