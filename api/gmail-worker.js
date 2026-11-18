
"use strict";

// PAPI RIKI - Gmail Worker
// Acceso exclusivo mediante secreto del servidor.
// No necesita sesion del usuario.
// No confirma gastos ni envia notificaciones.
// No activa Gmail Watch.

const crypto = require("node:crypto");
const { createClient } = require("@supabase/supabase-js");

const SUPABASE_URL =
  "https://kbwrxebdcpgsplfjpkxv.supabase.co";

function authorized(req) {
  const secret = process.env.GMAIL_WORKER_SECRET;

  if (!secret || Buffer.byteLength(secret) < 32) {
    return false;
  }

  const match = String(
    req.headers.authorization || ""
  ).match(/^Bearer\s+(\S+)$/i);

  if (!match) return false;

  const a = Buffer.from(match[1]);
  const b = Buffer.from(secret);

  return a.length === b.length &&
    crypto.timingSafeEqual(a, b);
}

function adminClient() {
  if (!process.env.SUPABASE_SECRET_KEY) {
    throw Error("Missing Supabase key");
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

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    return res.status(405).json({
      ok: false,
      message: "Method not allowed"
    });
  }

  if (!authorized(req)) {
    return res.status(401).json({
      ok: false,
      message: "Unauthorized"
    });
  }

  try {
    const admin = adminClient();

    const { data: monitors, error: monitorError } =
      await admin
        .from("gmail_monitor_state")
        .select("user_id,last_history_id")
        .eq("monitor_status", "active")
        .limit(50);

    if (monitorError) throw monitorError;

    const results = [];

    for (const monitor of monitors || []) {
      const { count, error } = await admin
        .from("gmail_events")
        .select("id", {
          count: "exact",
          head: true
        })
        .eq("user_id", monitor.user_id)
        .eq("status", "pending");

      if (error) throw error;

      results.push({
        pending_events: count || 0,
        cursor_initialized:
          Boolean(monitor.last_history_id)
      });
    }

    return res.status(200).json({
      ok: true,
      worker: "ready",
      active_monitors: results.length,
      total_pending_events:
        results.reduce(
          (sum, item) => sum + item.pending_events,
          0
        ),
      processing_enabled: false,
      gmail_watch_active: false,
      expenses_confirmed: 0,
      notifications_sent: 0
    });

  } catch {
    console.error("Gmail worker failed");

    return res.status(503).json({
      ok: false,
      message: "Worker unavailable"
    });
  }
};
