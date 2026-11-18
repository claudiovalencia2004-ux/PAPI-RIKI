
"use strict";

// PAPI RIKI - PASO 9.19.2
// Trabajador interno de Gmail.
//
// Primera fase:
// - Autenticacion servidor a servidor.
// - Consulta eventos pendientes.
// - Comprueba estado del monitor.
// - No procesa mensajes todavia.
// - No modifica cursores.
// - No confirma gastos.
// - No envia Web Push.
// - No activa Gmail Watch.

const crypto = require("node:crypto");

const { createClient } =
  require("@supabase/supabase-js");

const SUPABASE_URL =
  "https://kbwrxebdcpgsplfjpkxv.supabase.co";

function respond(res, status, data) {
  return res.status(status).json(data);
}

function authorized(req) {
  const secret = process.env.GMAIL_WORKER_SECRET;

  if (
    !secret ||
    Buffer.byteLength(secret) < 32
  ) {
    return false;
  }

  const authorization = String(
    req.headers.authorization || ""
  );

  const match = authorization.match(
    /^Bearer\s+(\S+)$/i
  );

  if (!match) return false;

  const supplied = Buffer.from(match[1]);
  const expected = Buffer.from(secret);

  if (supplied.length !== expected.length) {
    return false;
  }

  return crypto.timingSafeEqual(
    supplied,
    expected
  );
}

function createAdmin() {
  const key = process.env.SUPABASE_SECRET_KEY;

  if (!key) {
    throw Error("Supabase configuration missing");
  }

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
    const admin = createAdmin();

    // Consultar monitores activos.
    // No consultar tokens OAuth aqui.

    const { data: monitors, error: monitorError } =
      await admin
        .from("gmail_monitor_state")
        .select("user_id,monitor_status,last_history_id")
        .eq("monitor_status", "active")
        .limit(100);

    if (monitorError) {
      throw Error("Monitor query failed");
    }

    const users = (monitors || []).map(
      monitor => monitor.user_id
    );

    if (users.length === 0) {
      return respond(res, 200, {
        ok: true,
        mode: "preflight",
        active_monitors: 0,
        pending_events: 0,
        processing_enabled: false,
        message: "No active Gmail monitors"
      });
    }

    const { count, error: eventsError } =
      await admin
        .from("gmail_events")
        .select("id", {
          count: "exact",
          head: true
        })
        .in("user_id", users)
        .eq("status", "pending");

    if (eventsError) {
      throw Error("Event query failed");
    }

    return respond(res, 200, {
      ok: true,
      mode: "preflight",
      active_monitors: users.length,
      pending_events: count || 0,
      processing_enabled: false,
      cursor_updated: false,
      expenses_created: 0,
      notifications_sent: 0
    });

  } catch {
    console.error("Gmail worker preflight failed");

    return respond(res, 503, {
      ok: false,
      message: "Worker unavailable"
    });
  }
};
