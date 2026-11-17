
"use strict";

// =============================================
// PAPI RIKI - PASO 9.16.7
// PROCESAMIENTO CONTROLADO DE GMAIL
// =============================================
//
// - Autenticacion mediante Supabase.
// - Consulta Gmail History.
// - Detecta consumos BCP.
// - Guarda candidatos pendientes.
// - Evita duplicados por Gmail message ID.
// - No confirma gastos.
// - No modifica movimientos financieros.
// - No envia notificaciones.
// - No avanza el cursor.
// - No activa Gmail Watch.
//
// IMPORTANTE:
// La ejecucion permanece bloqueada hasta
// inicializar un cursor real de Gmail.
// =============================================

const { createClient } =
  require("@supabase/supabase-js");

const {
  inspectNewMessages
} = require("../lib/gmail-processor");

const SUPABASE_URL =
  "https://kbwrxebdcpgsplfjpkxv.supabase.co";

const PUBLIC_KEY =
  "sb_publishable_khEJIOxXl5ytDpXFABTWcg_hKC0lak2";

function response(res, status, message, extra = {}) {
  return res.status(status).json({
    ok: status === 200,
    message,
    ...extra
  });
}

function validCursor(value) {
  return (
    typeof value === "string" &&
    /^[0-9]{1,30}$/.test(value)
  );
}

function normalize(value) {
  return String(value ?? "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

// =============================================
// EXTRAER IMPORTE
// =============================================

function parseAmount(raw) {
  let value = String(raw).trim();

  if (!/^\d[\d.,]*$/.test(value)) {
    throw Error("Invalid amount");
  }

  if (value.includes(",") && value.includes(".")) {
    if (value.lastIndexOf(",") >
        value.lastIndexOf(".")) {
      value = value.replace(/\./g, "")
        .replace(",", ".");
    } else {
      value = value.replace(/,/g, "");
    }
  } else if (value.includes(",")) {
    const parts = value.split(",");

    value = (
      parts.length === 2 &&
      parts[1].length === 2
    )
      ? value.replace(",", ".")
      : value.replace(/,/g, "");
  }

  const amount = Number(value);

  if (
    !Number.isFinite(amount) ||
    amount <= 0 ||
    amount > 999999999 ||
    !Number.isSafeInteger(Math.round(amount * 100))
  ) {
    throw Error("Invalid amount");
  }

  return Math.round(amount * 100) / 100;
}

// =============================================
// EXTRAER FECHA PERU
// =============================================

function parseDate(body) {
  const months = {
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

  const match = body.match(
    /Fecha y hora\s+(\d{1,2}) de ([a-z]+) de (\d{4})\s*-\s*(\d{1,2}):(\d{2})\s*(AM|PM)/i
  );

  if (!match) {
    throw Error("Transaction date not found");
  }

  const day = Number(match[1]);
  const month = months[match[2].toLowerCase()];
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
    throw Error("Invalid date");
  }

  const valid = new Date(
    Date.UTC(year, month - 1, day)
  );

  if (
    valid.getUTCFullYear() !== year ||
    valid.getUTCMonth() !== month - 1 ||
    valid.getUTCDate() !== day
  ) {
    throw Error("Invalid date");
  }

  let hour = hour12 % 12;

  if (match[6].toUpperCase() === "PM") {
    hour += 12;
  }

  const date =
    `${year}-` +
    `${String(month).padStart(2, "0")}-` +
    `${String(day).padStart(2, "0")}T` +
    `${String(hour).padStart(2, "0")}:` +
    `${String(minute).padStart(2, "0")}:00-05:00`;

  return new Date(date).toISOString();
}

// =============================================
// EXTRAER CANDIDATO BCP
// =============================================

function parseBCPCandidate(candidate) {
  const body = normalize(candidate.body);

  if (!candidate.gmail_message_id ||
      !/^[A-Za-z0-9_-]{5,255}$/.test(
        candidate.gmail_message_id
      )) {
    throw Error("Invalid Gmail message ID");
  }

  if (!/Consumo Tarjeta de Debito/i.test(body)) {
    throw Error("Operation not recognized");
  }

  const amountMatch = body.match(
    /Total del consumo\s*(S\/|US\$|\$)\s*(\d[\d.,]*)/i
  );

  if (!amountMatch) {
    throw Error("Amount not found");
  }

  const merchantMatch = body.match(
    /Empresa\s+(.+?)(?=\s+Numero de operacion|\s+No reconoces|\s+Seguimos mejorando|$)/i
  );

  if (!merchantMatch) {
    throw Error("Merchant not found");
  }

  const merchant = merchantMatch[1].trim();

  if (
    !merchant ||
    merchant.length > 150 ||
    /^(Numero de operacion|No reconoces|Seguimos mejorando)\b/i
      .test(merchant)
  ) {
    throw Error("Invalid merchant");
  }

  return {
    gmail_message_id: candidate.gmail_message_id,
    merchant,
    amount: parseAmount(amountMatch[2]),
    currency:
      amountMatch[1] === "S/" ? "PEN" : "USD",
    transaction_date: parseDate(body)
  };
}

// =============================================
// ENDPOINT AUTENTICADO
// =============================================

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Allow", "POST");

  if (req.method !== "POST") {
    return response(
      res, 405, "Metodo no permitido."
    );
  }

  const authorization =
    req.headers.authorization || "";

  const match = authorization.match(
    /^Bearer\s+(\S+)$/i
  );

  if (!match) {
    return response(
      res, 401, "Autenticacion requerida."
    );
  }

  if (!process.env.SUPABASE_SECRET_KEY) {
    return response(
      res, 503, "Configuracion incompleta."
    );
  }

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
      return response(
        res, 401, "Sesion invalida."
      );
    }

    const userId = authData.user.id;

    const admin = createClient(
      SUPABASE_URL,
      process.env.SUPABASE_SECRET_KEY,
      {
        auth: {
          persistSession: false,
          autoRefreshToken: false
        }
      }
    );

    // =====================================
    // COMPROBAR MONITOR
    // =====================================

    const { data: monitor, error: monitorError } =
      await admin
        .from("gmail_monitor_state")
        .select(
          "last_history_id,monitor_status,started_at"
        )
        .eq("user_id", userId)
        .maybeSingle();

    if (monitorError) {
      throw Error("Monitor query failed");
    }

    if (
      !monitor ||
      !validCursor(monitor.last_history_id) ||
      monitor.monitor_status !== "active"
    ) {
      return response(
        res,
        409,
        "El monitor Gmail todavia no esta activo.",
        {
          cursor_initialized: false,
          processing_started: false,
          expenses_created: 0
        }
      );
    }

    // =====================================
    // COMPROBAR EVENTOS
    // =====================================

    const { data: events, error: eventError } =
      await admin
        .from("gmail_events")
        .select("id,gmail_history_id")
        .eq("user_id", userId)
        .eq("status", "pending")
        .order("created_at", {
          ascending: true
        })
        .limit(20);

    if (eventError) {
      throw Error("Event query failed");
    }

    if (!events?.length) {
      return response(
        res,
        200,
        "No hay eventos pendientes.",
        {
          pending_events: 0,
          expenses_created: 0,
          cursor_updated: false
        }
      );
    }

    // =====================================
    // COMPROBAR CONEXION GMAIL
    // =====================================

    const { data: connection, error: connectionError } =
      await admin
        .from("gmail_connections")
        .select(
          "refresh_token_encrypted,status"
        )
        .eq("user_id", userId)
        .maybeSingle();

    if (
      connectionError ||
      !connection ||
      connection.status !== "connected" ||
      !connection.refresh_token_encrypted
    ) {
      return response(
        res, 409, "Gmail no conectado."
      );
    }

    // =====================================
    // INSPECCIONAR GMAIL
    // =====================================

    const inspection = await inspectNewMessages(
      connection.refresh_token_encrypted,
      monitor.last_history_id
    );

    if (!inspection.ok) {
      throw Error("Gmail inspection failed");
    }

    let created = 0;
    let existing = 0;
    let rejected = 0;

    // =====================================
    // GUARDAR CANDIDATOS
    // =====================================

    for (const candidate of inspection.candidates) {
      let parsed;

      try {
        parsed = parseBCPCandidate(candidate);
      } catch (error) {
        // No aceptar un correo con datos
        // incompletos o inconsistentes.
        rejected++;
        continue;
      }

      // No guardar mensajes anteriores al
      // inicio configurado del monitor.
      if (
        !candidate.received_at ||
        !Number.isFinite(
          Date.parse(candidate.received_at)
        )
      ) {
        rejected++;
        continue;
      }

      if (
        new Date(candidate.received_at) <
        new Date(monitor.started_at)
      ) {
        continue;
      }

      const { data: saved, error: saveError } =
        await admin.rpc("save_bcp_candidate", {
          p_user_id: userId,
          p_gmail_message_id:
            parsed.gmail_message_id,
          p_merchant: parsed.merchant,
          p_amount: parsed.amount,
          p_currency: parsed.currency,
          p_transaction_date:
            parsed.transaction_date
        });

      if (saveError) {
        throw Error("Candidate persistence failed");
      }

      if (!saved?.length) {
        throw Error("Candidate not confirmed");
      }

      if (saved[0].was_created) {
        created++;
      } else {
        existing++;
      }
    }

    // =====================================
    // NO AVANZAR CURSOR TODAVIA
    // =====================================
    //
    // El cursor solo podra avanzar cuando
    // implementemos:
    //
    // 1. Control de concurrencia.
    // 2. Finalizacion atomica de eventos.
    // 3. Gestion de mensajes no verificables.
    // 4. Recuperacion de errores.
    //
    // Esta version no marca eventos
    // como completados.

    return response(
      res,
      200,
      "Procesamiento preliminar completado.",
      {
        mode: "preliminary",
        scanned_messages:
          inspection.scanned_messages,
        candidates_found:
          inspection.candidates.length,
        candidates_created: created,
        candidates_existing: existing,
        candidates_rejected: rejected,
        cursor_updated: false,
        events_completed: 0,
        expenses_confirmed: 0,
        notifications_sent: 0
      }
    );

  } catch (error) {
    console.error(
      "PAPI RIKI Gmail processing failed"
    );

    return response(
      res,
      503,
      "No se pudo completar el procesamiento."
    );
  }
};
