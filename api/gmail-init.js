
"use strict";

// PAPI RIKI - PASO 9.18.5
// Obtiene un cursor real de Gmail.
// NO activa Gmail Watch.
// NO lee mensajes.
// NO registra gastos.
// NO cambia el estado del monitor a active.

const crypto = require("node:crypto");
const { createClient } = require("@supabase/supabase-js");

const SUPABASE_URL =
  "https://kbwrxebdcpgsplfjpkxv.supabase.co";

const PUBLIC_KEY =
  "sb_publishable_khEJIOxXl5ytDpXFABTWcg_hKC0lak2";

function client(key) {
  return createClient(SUPABASE_URL, key, {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  });
}

function decrypt(value, hex) {
  if (!/^[a-f0-9]{64}$/i.test(hex || "")) {
    throw Error("Invalid encryption key");
  }

  const parts = String(value || "").split(".");

  if (parts.length !== 4 || parts[0] !== "v1") {
    throw Error("Invalid token format");
  }

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    Buffer.from(hex, "hex"),
    Buffer.from(parts[1], "base64url")
  );

  decipher.setAuthTag(
    Buffer.from(parts[2], "base64url")
  );

  return Buffer.concat([
    decipher.update(
      Buffer.from(parts[3], "base64url")
    ),
    decipher.final()
  ]).toString("utf8");
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Allow", "POST");

  if (req.method !== "POST") {
    return res.status(405).json({
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
    return res.status(503).json({
      ok: false,
      message: "Configuracion incompleta"
    });
  }

  const match = String(
    req.headers.authorization || ""
  ).match(/^Bearer\s+(\S+)$/i);

  if (!match) {
    return res.status(401).json({
      ok: false,
      message: "Inicia sesion"
    });
  }

  try {
    const auth = client(PUBLIC_KEY);

    const { data, error } =
      await auth.auth.getUser(match[1]);

    if (error || !data?.user?.id) {
      return res.status(401).json({
        ok: false,
        message: "Sesion invalida"
      });
    }

    const userId = data.user.id;
    const admin = client(env.SUPABASE_SECRET_KEY);

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
      return res.status(409).json({
        ok: false,
        message: "Gmail no conectado"
      });
    }

    const refresh = decrypt(
      connection.refresh_token_encrypted,
      env.GMAIL_ENCRYPTION_KEY
    );

    const params = new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      refresh_token: refresh,
      grant_type: "refresh_token"
    });

    const tokenResponse = await fetch(
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

    if (!tokenResponse.ok) {
      throw Error("OAuth refresh failed");
    }

    const tokens = await tokenResponse.json();

    if (!tokens.access_token) {
      throw Error("Missing access token");
    }

    // Obtener historyId real del perfil Gmail.
    const profileResponse = await fetch(
      "https://gmail.googleapis.com/gmail/v1/users/me/profile",
      {
        headers: {
          Authorization:
            "Bearer " + tokens.access_token
        },
        signal: AbortSignal.timeout(12000)
      }
    );

    if (!profileResponse.ok) {
      throw Error("Gmail profile failed");
    }

    const profile = await profileResponse.json();

    const historyId = String(
      profile.historyId || ""
    );

    if (!/^[0-9]{1,30}$/.test(historyId)) {
      throw Error("Invalid Gmail historyId");
    }

    // No sobrescribir un cursor existente.
    const { data: monitor, error: monitorError } =
      await admin
        .from("gmail_monitor_state")
        .select("last_history_id,monitor_status")
        .eq("user_id", userId)
        .maybeSingle();

    if (monitorError) throw monitorError;

    if (!monitor) {
      return res.status(409).json({
        ok: false,
        message: "Monitor no encontrado"
      });
    }

    if (
      monitor.last_history_id ||
      monitor.monitor_status !== "inactive"
    ) {
      return res.status(409).json({
        ok: false,
        message: "Monitor ya inicializado"
      });
    }

    const { error: saveError } = await admin
      .from("gmail_monitor_state")
      .update({
        last_history_id: historyId,
        last_checked_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      })
      .eq("user_id", userId)
      .is("last_history_id", null)
      .eq("monitor_status", "inactive");

    if (saveError) {
      throw Error("Cursor save failed");
    }

    return res.status(200).json({
      ok: true,
      cursor_initialized: true,
      monitor_status: "inactive",
      gmail_watch_active: false,
      historical_expenses_imported: 0
    });

  } catch (error) {
    console.error("Gmail cursor initialization failed");

    return res.status(503).json({
      ok: false,
      message: "No se pudo inicializar Gmail"
    });
  }
};
