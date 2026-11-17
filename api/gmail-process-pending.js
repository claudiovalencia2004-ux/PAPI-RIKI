
"use strict";

// ==========================================
// PAPI RIKI - PASO 9.16.4
// CONECTOR DE EVENTOS GMAIL
// ==========================================
//
// - Requiere usuario autenticado.
// - Consulta eventos pendientes en Supabase.
// - Utiliza el procesador Gmail existente.
// - No devuelve contenido de correos.
// - No modifica eventos ni cursores.
// - No registra gastos.
// - No envia notificaciones.
// - No activa Gmail Watch.
//
// Esta es una integracion de solo lectura.
// ==========================================

const { createClient } =
  require("@supabase/supabase-js");

const {
  inspectNewMessages
} = require("../lib/gmail-processor");

const SUPABASE_URL =
  "https://kbwrxebdcpgsplfjpkxv.supabase.co";

const PUBLIC_KEY =
  "sb_publishable_khEJIOxXl5ytDpXFABTWcg_hKC0lak2";

function respond(res, status, message, extra = {}) {
  return res.status(status).json({
    ok: status === 200,
    message,
    ...extra
  });
}

function validHistoryId(value) {
  return (
    typeof value === "string" &&
    /^[0-9]{1,30}$/.test(value)
  );
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Allow", "POST");

  if (req.method !== "POST") {
    return respond(
      res,
      405,
      "Metodo no permitido."
    );
  }

  const authorization =
    req.headers.authorization || "";

  const match = authorization.match(
    /^Bearer\s+(\S+)$/i
  );

  if (!match) {
    return respond(
      res,
      401,
      "Autenticacion requerida."
    );
  }

  if (!process.env.SUPABASE_SECRET_KEY) {
    return respond(
      res,
      503,
      "Configuracion incompleta."
    );
  }

  try {
    // ======================================
    // 1. AUTENTICAR USUARIO
    // ======================================

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
      return respond(
        res,
        401,
        "Sesion invalida."
      );
    }

    const userId = authData.user.id;

    // ======================================
    // 2. CLIENTE PRIVADO DE SUPABASE
    // ======================================

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

    // ======================================
    // 3. CONSULTAR EVENTOS PENDIENTES
    // ======================================

    const { data: events, error: eventError } =
      await admin
        .from("gmail_events")
        .select("id,gmail_history_id,status")
        .eq("user_id", userId)
        .eq("status", "pending")
        .order("created_at", {
          ascending: true
        })
        .limit(20);

    if (eventError) {
      throw Error("Event query failed");
    }

    if (!events || events.length === 0) {
      return respond(
        res,
        200,
        "No hay eventos pendientes.",
        {
          pending_events: 0,
          processing_started: false,
          expenses_created: 0
        }
      );
    }

    // ======================================
    // 4. COMPROBAR ESTADO DEL MONITOR
    // ======================================

    const { data: monitor, error: monitorError } =
      await admin
        .from("gmail_monitor_state")
        .select(
          "last_history_id,monitor_status"
        )
        .eq("user_id", userId)
        .maybeSingle();

    if (monitorError) {
      throw Error("Monitor query failed");
    }

    // No inventar un historyId.
    // Sin cursor real no es seguro
    // procesar el historial.

    if (
      !monitor ||
      !validHistoryId(monitor.last_history_id)
    ) {
      return respond(
        res,
        409,
        "El cursor real de Gmail aun no esta inicializado.",
        {
          pending_events: events.length,
          cursor_initialized: false,
          processing_started: false
        }
      );
    }

    // ======================================
    // 5. OBTENER CONEXION GMAIL
    // ======================================

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
      return respond(
        res,
        409,
        "Conexion Gmail no disponible."
      );
    }

    // ======================================
    // 6. INSPECCIONAR CAMBIOS GMAIL
    // ======================================

    // El modulo existente renueva OAuth,
    // consulta History y recupera mensajes.
    //
    // Importante:
    // No guardamos sus resultados todavia.
    // No modificamos el cursor.
    // No devolvemos el cuerpo de mensajes.

    const result = await inspectNewMessages(
      connection.refresh_token_encrypted,
      monitor.last_history_id
    );

    if (!result.ok) {
      throw Error("Gmail inspection failed");
    }

    // ======================================
    // 7. DEVOLVER SOLO METADATOS
    // ======================================

    return respond(
      res,
      200,
      "Inspeccion Gmail completada.",
      {
        mode: "read_only",
        pending_events: events.length,
        scanned_messages:
          result.scanned_messages,
        bcp_candidates:
          result.candidates.length,
        cursor_initialized: true,
        cursor_updated: false,
        events_completed: 0,
        expenses_created: 0,
        notifications_sent: 0
      }
    );

  } catch (error) {
    // No imprimir tokens ni contenido
    // de correos en los registros.

    console.error(
      "PAPI RIKI Gmail processing check failed"
    );

    return respond(
      res,
      503,
      "No se pudo inspeccionar Gmail."
    );
  }
};
