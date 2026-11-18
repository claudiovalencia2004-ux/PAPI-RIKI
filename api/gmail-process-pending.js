
"use strict";

// ============================================
// PAPI RIKI - PASO 9.17.1
// CONTROL SEGURO DEL PROCESADOR GMAIL
// ============================================
//
// Conserva el sistema financiero existente.
//
// Este endpoint:
// 1. Autentica al usuario de Supabase.
// 2. Comprueba su conexion Gmail.
// 3. Comprueba el cursor real.
// 4. Consulta eventos pendientes.
// 5. Impide procesar eventos ficticios.
// 6. No confirma gastos.
// 7. No avanza cursores sin procesar.
// 8. No activa Gmail Watch.
// 9. No envia notificaciones todavia.
//
// El procesamiento de mensajes reales se
// habilitara al integrar y validar el
// detector de autenticidad y formato BCP.
// ============================================

const { createClient } =
  require("@supabase/supabase-js");

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

function createSupabase(key) {
  return createClient(
    SUPABASE_URL,
    key,
    {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
        detectSessionInUrl: false
      }
    }
  );
}

module.exports = async function handler(req, res) {

  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Allow", "POST");

  // ========================================
  // 1. VALIDAR METODO
  // ========================================

  if (req.method !== "POST") {
    return respond(
      res,
      405,
      "Metodo no permitido."
    );
  }

  // ========================================
  // 2. VALIDAR CONFIGURACION
  // ========================================

  const SECRET_KEY =
    process.env.SUPABASE_SECRET_KEY;

  if (!SECRET_KEY) {
    return respond(
      res,
      503,
      "Configuracion del servidor incompleta."
    );
  }

  // ========================================
  // 3. VALIDAR SESION
  // ========================================

  const authorization =
    req.headers.authorization || "";

  const match = authorization.match(
    /^Bearer\s+(\S+)$/i
  );

  if (!match) {
    return respond(
      res,
      401,
      "Debes iniciar sesion."
    );
  }

  try {

    const auth = createSupabase(PUBLIC_KEY);

    const {
      data: authData,
      error: authError
    } = await auth.auth.getUser(match[1]);

    if (authError || !authData?.user?.id) {
      return respond(
        res,
        401,
        "Sesion invalida o caducada."
      );
    }

    const userId = authData.user.id;

    // ======================================
    // 4. CONEXION PRIVADA
    // ======================================

    const admin = createSupabase(SECRET_KEY);

    // ======================================
    // 5. COMPROBAR GMAIL
    // ======================================

    const {
      data: connection,
      error: connectionError
    } = await admin
      .from("gmail_connections")
      .select("status,refresh_token_encrypted")
      .eq("user_id", userId)
      .maybeSingle();

    if (connectionError) {
      throw new Error(
        "Gmail connection query failed"
      );
    }

    if (
      !connection ||
      connection.status !== "connected" ||
      !connection.refresh_token_encrypted
    ) {
      return respond(
        res,
        409,
        "Gmail no esta conectado.",
        {
          gmail_connected: false
        }
      );
    }

    // ======================================
    // 6. CONSULTAR MONITOR
    // ======================================

    const {
      data: monitor,
      error: monitorError
    } = await admin
      .from("gmail_monitor_state")
      .select(
        "started_at,last_history_id," +
        "monitor_status,watch_expiration"
      )
      .eq("user_id", userId)
      .maybeSingle();

    if (monitorError) {
      throw new Error(
        "Monitor query failed"
      );
    }

    // ======================================
    // 7. CONSULTAR EVENTOS
    // ======================================

    const {
      data: events,
      error: eventsError
    } = await admin
      .from("gmail_events")
      .select(
        "id,gmail_history_id,status,attempts"
      )
      .eq("user_id", userId)
      .in("status", [
        "pending",
        "processing",
        "failed"
      ])
      .order("created_at", {
        ascending: true
      })
      .limit(50);

    if (eventsError) {
      throw new Error(
        "Events query failed"
      );
    }

    const pending = events || [];

    // ======================================
    // 8. VALIDAR CURSOR
    // ======================================

    const cursorValid =
      validHistoryId(
        monitor?.last_history_id
      );

    const active =
      monitor?.monitor_status === "active";

    // No utilizar identificadores ficticios.
    // No activar el monitor automaticamente.

    if (!cursorValid || !active) {
      return respond(
        res,
        200,
        "Procesador preparado. Monitor inactivo.",
        {
          gmail_connected: true,
          cursor_initialized: cursorValid,
          monitor_status:
            monitor?.monitor_status || "inactive",
          pending_events: pending.length,
          processing_enabled: false,
          cursor_updated: false,
          expenses_created: 0,
          expenses_confirmed: 0,
          notifications_sent: 0,
          next_step:
            "Inicializar un cursor real de Gmail."
        }
      );
    }

    // ======================================
    // 9. NO PROCESAR SIN VALIDACION
    // ======================================

    // La autenticidad de los mensajes BCP
    // y la extraccion de HTML deben estar
    // verificadas antes de guardar candidatos.
    //
    // No finalizar eventos ni avanzar
    // el cursor desde este endpoint.

    return respond(
      res,
      200,
      "Monitor disponible. Procesamiento protegido.",
      {
        gmail_connected: true,
        cursor_initialized: true,
        monitor_status: "active",
        pending_events: pending.length,
        processing_enabled: false,
        cursor_updated: false,
        expenses_created: 0,
        expenses_confirmed: 0,
        notifications_sent: 0,
        next_step:
          "Integrar procesamiento BCP validado."
      }
    );

  } catch (error) {

    // No registrar tokens ni correos.
    console.error(
      "PAPI RIKI Gmail processor error"
    );

    return respond(
      res,
      503,
      "Error comprobando el procesador Gmail."
    );
  }
};
