
"use strict";

// ==========================================
// PAPI RIKI - PASO 9.16.3
// PROCESADOR GMAIL - MODO SEGURO
// ==========================================
//
// Este modulo:
// - Renueva el token OAuth de Gmail.
// - Consulta Gmail History.
// - Recupera mensajes nuevos.
// - Identifica posibles avisos BCP.
// - No escribe en Supabase.
// - No modifica el cursor.
// - No registra gastos.
// - No envia notificaciones.
//
// Uso exclusivo desde el servidor.
// ==========================================

const crypto = require("node:crypto");

const GMAIL_API =
  "https://gmail.googleapis.com/gmail/v1/users/me";

const BCP_SENDER =
  "notificaciones@notificacionesbcp.com.pe";

const BCP_SUBJECT =
  "realizaste un consumo con tu tarjeta de debito bcp";

const MAX_PAGES = 10;
const MAX_MESSAGES = 50;

function normalize(value) {
  return String(value || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function decryptToken(encrypted, keyHex) {
  if (!/^[a-f0-9]{64}$/i.test(keyHex || "")) {
    throw Error("Invalid encryption configuration");
  }

  const parts = String(encrypted || "").split(".");

  if (parts.length !== 4 || parts[0] !== "v1") {
    throw Error("Invalid encrypted token format");
  }

  const key = Buffer.from(keyHex, "hex");
  const iv = Buffer.from(parts[1], "base64url");
  const tag = Buffer.from(parts[2], "base64url");
  const ciphertext =
    Buffer.from(parts[3], "base64url");

  if (iv.length !== 12 || tag.length !== 16) {
    throw Error("Invalid encrypted token");
  }

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    iv
  );

  decipher.setAuthTag(tag);

  return Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ]).toString("utf8");
}

async function refreshAccessToken(encryptedToken) {
  const env = process.env;

  if (
    !env.GOOGLE_CLIENT_ID ||
    !env.GOOGLE_CLIENT_SECRET ||
    !env.GMAIL_ENCRYPTION_KEY
  ) {
    throw Error("OAuth configuration incomplete");
  }

  const refreshToken = decryptToken(
    encryptedToken,
    env.GMAIL_ENCRYPTION_KEY
  );

  const body = new URLSearchParams({
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
      body: body.toString(),
      signal: AbortSignal.timeout(12000)
    }
  );

  if (!response.ok) {
    throw Error("OAuth token refresh failed");
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

  if (response.status === 404) {
    const error = new Error(
      "Gmail resource or history unavailable"
    );
    error.code = "GMAIL_NOT_FOUND";
    throw error;
  }

  if (!response.ok) {
    throw Error("Gmail API request failed");
  }

  return response.json();
}

function decodeBase64Url(value) {
  if (!value) return "";

  return Buffer.from(
    value,
    "base64url"
  ).toString("utf8");
}

function extractText(part, depth = 0) {
  if (!part || depth > 12) return "";

  if (
    part.mimeType === "text/plain" &&
    part.body?.data
  ) {
    return decodeBase64Url(part.body.data);
  }

  const children = part.parts || [];

  for (const child of children) {
    const text = extractText(child, depth + 1);
    if (text) return text;
  }

  return "";
}

function getHeader(headers, name) {
  const header = (headers || []).find(
    item =>
      String(item.name).toLowerCase() ===
      name.toLowerCase()
  );

  return header?.value || "";
}

function isBCPCandidate(message) {
  const headers = message.payload?.headers || [];

  const from = getHeader(headers, "From");
  const subject = getHeader(headers, "Subject");

  const address = from.includes("<")
    ? from.match(/<([^<>]+)>/)?.[1]
    : from;

  const normalizedAddress =
    String(address || "").trim().toLowerCase();

  const normalizedSubject =
    normalize(subject).toLowerCase();

  return (
    normalizedAddress === BCP_SENDER &&
    normalizedSubject.includes(BCP_SUBJECT)
  );
}

async function collectNewMessageIds(
  startHistoryId,
  accessToken
) {
  if (!/^[0-9]+$/.test(String(startHistoryId))) {
    throw Error("Invalid Gmail history cursor");
  }

  const ids = new Set();

  let pageToken;
  let latestHistoryId = null;
  let complete = false;

  for (let page = 0; page < MAX_PAGES; page++) {
    const result = await gmailGet(
      "/history",
      accessToken,
      {
        startHistoryId,
        historyTypes: "messageAdded",
        maxResults: 100,
        pageToken
      }
    );

    if (!/^[0-9]+$/.test(
      String(result.historyId || "")
    )) {
      throw Error("Invalid Gmail history response");
    }

    latestHistoryId = String(result.historyId);

    for (const entry of result.history || []) {
      for (const added of entry.messagesAdded || []) {
        const id = added.message?.id;

        if (id) ids.add(id);

        if (ids.size > MAX_MESSAGES) {
          throw Error(
            "History exceeds safe processing limit"
          );
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
    throw Error(
      "History pagination incomplete"
    );
  }

  return {
    messageIds: [...ids],
    latestHistoryId
  };
}

async function inspectNewMessages(
  encryptedRefreshToken,
  startHistoryId
) {
  // Solo lectura: no escribir estados ni cursor.

  const token = await refreshAccessToken(
    encryptedRefreshToken
  );

  const history = await collectNewMessageIds(
    startHistoryId,
    token
  );

  const candidates = [];

  for (const id of history.messageIds) {
    let message;

    try {
      message = await gmailGet(
        "/messages/" + encodeURIComponent(id),
        token,
        { format: "full" }
      );
    } catch (error) {
      // Un mensaje puede haberse eliminado.
      // Otros errores deben interrumpir el lote.
      if (error.code === "GMAIL_NOT_FOUND") {
        continue;
      }

      throw error;
    }

    if (!isBCPCandidate(message)) {
      continue;
    }

    const body = extractText(message.payload);

    candidates.push({
      gmail_message_id: message.id,
      gmail_history_id: message.historyId,
      received_at: message.internalDate
        ? new Date(
            Number(message.internalDate)
          ).toISOString()
        : null,
      bank: "BCP",
      body,
      verification_status: "unverified",
      status: "candidate"
    });
  }

  return {
    ok: true,
    mode: "read_only",
    scanned_messages: history.messageIds.length,
    candidates,
    proposed_history_id:
      history.latestHistoryId,
    cursor_updated: false,
    expenses_created: 0,
    notifications_sent: 0
  };
}

module.exports = {
  inspectNewMessages
};
