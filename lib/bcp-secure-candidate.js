
"use strict";

// ==========================================
// PAPI RIKI - PASO 9.17.4
// VALIDADOR Y GUARDADO BCP
// ==========================================
//
// No activa Gmail Watch.
// No modifica el cursor.
// No confirma gastos.
// No envia Web Push.
// No contiene claves privadas.
//
// El guardado exige que el procesador
// haya establecido una prueba de
// autenticacion confiable.
// ==========================================

const BCP_EMAIL =
  "notificaciones@notificacionesbcp.com.pe";

const BCP_SUBJECT =
  "realizaste un consumo con tu tarjeta de debito bcp";

const MONTHS = {
  enero: 1,
  febrero: 2,
  marzo: 3,
  abril: 4,
  mayo: 5,
  junio: 6,
  julio: 7,
  agosto: 8,
  septiembre: 9,
  octubre: 10,
  noviembre: 11,
  diciembre: 12
};

function normalize(value) {
  return String(value ?? "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function getHeaders(message, name) {
  return (message?.payload?.headers || [])
    .filter(item =>
      String(item.name || "").toLowerCase() ===
      name.toLowerCase()
    )
    .map(item => String(item.value || ""));
}

function getHeader(message, name) {
  const values = getHeaders(message, name);

  if (values.length !== 1) {
    throw new Error(
      "Missing or ambiguous " + name
    );
  }

  return values[0];
}

function getSender(message) {
  const raw = getHeader(message, "From");

  const match = raw.match(
    /<([^<>\s]+@[^<>\s]+)>/
  );

  return (match ? match[1] : raw)
    .trim()
    .toLowerCase();
}

function decode(value) {
  if (!value) return "";

  return Buffer.from(
    value,
    "base64url"
  ).toString("utf8");
}

function extractPlain(part, depth = 0) {
  if (!part || depth > 15) return "";

  if (
    part.mimeType === "text/plain" &&
    part.body?.data
  ) {
    return decode(part.body.data);
  }

  for (const child of part.parts || []) {
    const text = extractPlain(
      child,
      depth + 1
    );

    if (text) return text;
  }

  return "";
}

function htmlToText(html) {
  return String(html || "")
    .replace(
      /<(script|style|head)\b[^>]*>[\s\S]*?<\/\1\s*>/gi,
      " "
    )
    .replace(/<br\s*\/?>/gi, " ")
    .replace(/<\/(p|div|tr|td|th|li)>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;|&#160;/gi, " ")
    .replace(/&sol;|&#47;/gi, "/")
    .replace(/&amp;/gi, "&")
    .replace(/&quot;/gi, '"')
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&#(\d+);/g,
      (_, n) => String.fromCodePoint(Number(n)))
    .replace(/\s+/g, " ")
    .trim();
}

function extractHtml(part, depth = 0) {
  if (!part || depth > 15) return "";

  if (
    part.mimeType === "text/html" &&
    part.body?.data
  ) {
    return htmlToText(decode(part.body.data));
  }

  for (const child of part.parts || []) {
    const text = extractHtml(
      child,
      depth + 1
    );

    if (text) return text;
  }

  return "";
}

function getBody(message) {
  const plain = extractPlain(message.payload);

  if (plain) return normalize(plain);

  return normalize(
    extractHtml(message.payload)
  );
}

function parseAmount(value) {
  let raw = String(value).trim();

  if (!/^\d[\d.,]*$/.test(raw)) {
    throw new Error("Invalid amount");
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
    Math.abs(
      amount * 100 - Math.round(amount * 100)
    ) > 0.000001
  ) {
    throw new Error("Invalid amount");
  }

  return Math.round(amount * 100) / 100;
}

function parseDate(body) {
  const match = body.match(
    /Fecha y hora\s+(\d{1,2}) de ([a-z]+) de (\d{4})\s*-\s*(\d{1,2}):(\d{2})\s*(AM|PM)/i
  );

  if (!match) {
    throw new Error("Date not found");
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
    minute < 0 ||
    minute > 59
  ) {
    throw new Error("Invalid date");
  }

  const check = new Date(
    Date.UTC(year, month - 1, day)
  );

  if (
    check.getUTCFullYear() !== year ||
    check.getUTCMonth() !== month - 1 ||
    check.getUTCDate() !== day
  ) {
    throw new Error("Invalid calendar date");
  }

  const hour =
    hour12 % 12 +
    (match[6].toUpperCase() === "PM" ? 12 : 0);

  const iso =
    `${year}-${String(month).padStart(2, "0")}-` +
    `${String(day).padStart(2, "0")}T` +
    `${String(hour).padStart(2, "0")}:` +
    `${String(minute).padStart(2, "0")}:00-05:00`;

  return new Date(iso).toISOString();
}

function parseBCP(message) {
  if (
    !message?.id ||
    !/^[a-zA-Z0-9_-]{5,255}$/.test(message.id)
  ) {
    throw new Error("Invalid Gmail message ID");
  }

  if (getSender(message) !== BCP_EMAIL) {
    throw new Error("Unknown sender");
  }

  const subject = normalize(
    getHeader(message, "Subject")
  ).toLowerCase();

  if (!subject.includes(BCP_SUBJECT)) {
    throw new Error("Unknown subject");
  }

  const body = getBody(message);

  if (!body) {
    throw new Error("Email body unavailable");
  }

  if (!/Consumo Tarjeta de Debito/i.test(body)) {
    throw new Error("Unknown operation");
  }

  const amountMatch = body.match(
    /Total del consumo\s*(S\/|US\$|\$)\s*(\d[\d.,]*)/i
  );

  if (!amountMatch) {
    throw new Error("Amount not found");
  }

  const merchantMatch = body.match(
    /Empresa\s+(.+?)(?=\s+Numero de operacion|\s+No reconoces|\s+Seguimos mejorando|$)/i
  );

  if (!merchantMatch) {
    throw new Error("Merchant not found");
  }

  const merchant = merchantMatch[1].trim();

  if (
    !merchant ||
    merchant.length > 150 ||
    /^(Numero de operacion|No reconoces|Seguimos mejorando)\b/i
      .test(merchant)
  ) {
    throw new Error("Invalid merchant");
  }

  return {
    gmail_message_id: message.id,
    bank: "BCP",
    merchant,
    amount: parseAmount(amountMatch[2]),
    currency:
      amountMatch[1] === "S/" ? "PEN" : "USD",
    transaction_date: parseDate(body),
    status: "pending"
  };
}

// ==========================================
// GUARDADO PRIVADO EN SUPABASE
// ==========================================

async function saveBCPCandidate({
  admin,
  userId,
  message,
  startedAt,
  authenticationVerified = false
}) {
  if (!admin || !userId || !message) {
    throw new Error("Missing processing context");
  }

  // Esta evidencia debe proceder de una
  // verificacion de confianza del receptor.
  // No basta con el campo From ni con una
  // cabecera Authentication-Results arbitraria.
  //
  // Mientras no exista esa verificacion,
  // la funcion falla sin escribir datos.

  if (authenticationVerified !== true) {
    throw new Error(
      "Trusted email authentication required"
    );
  }

  if (
    !startedAt ||
    !Number.isFinite(Date.parse(startedAt))
  ) {
    throw new Error("Invalid monitor start");
  }

  const received = Number(
    message.internalDate
  );

  if (
    !Number.isFinite(received) ||
    received <= 0
  ) {
    throw new Error("Invalid receive timestamp");
  }

  if (received < Date.parse(startedAt)) {
    return {
      skipped: true,
      reason: "historical_message"
    };
  }

  const candidate = parseBCP(message);

  const { data, error } = await admin.rpc(
    "save_bcp_candidate",
    {
      p_user_id: userId,
      p_gmail_message_id:
        candidate.gmail_message_id,
      p_merchant: candidate.merchant,
      p_amount: candidate.amount,
      p_currency: candidate.currency,
      p_transaction_date:
        candidate.transaction_date
    }
  );

  if (error) {
    throw new Error(
      "Candidate persistence failed"
    );
  }

  if (
    !Array.isArray(data) ||
    data.length !== 1 ||
    !data[0].expense_id
  ) {
    throw new Error(
      "Candidate persistence unconfirmed"
    );
  }

  return {
    saved: true,
    created: data[0].was_created,
    status: data[0].expense_status,
    expense_id: data[0].expense_id
  };
}

module.exports = {
  parseBCP,
  saveBCPCandidate
};
