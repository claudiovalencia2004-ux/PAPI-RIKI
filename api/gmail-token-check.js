
"use strict";

// PAPI RIKI - PASO 9.12.1
// Verificar renovación OAuth Gmail.
//
// - Requiere autenticación de Supabase.
// - Solo comprueba la conexión del usuario.
// - No consulta mensajes de Gmail.
// - No devuelve tokens ni secretos.
// - No modifica movimientos financieros.

const crypto = require("node:crypto");
const { createClient } = require("@supabase/supabase-js");

const SUPABASE_URL =
  "https://kbwrxebdcpgsplfjpkxv.supabase.co";

const PUBLIC_KEY =
  "sb_publishable_khEJIOxXl5ytDpXFABTWcg_hKC0lak2";

function decrypt(value, keyHex) {
  const key = Buffer.from(keyHex, "hex");

  if (key.length !== 32) {
    throw Error("Invalid encryption key");
  }

  const parts = String(value).split(".");

  if (parts.length !== 4 || parts[0] !== "v1") {
    throw Error("Invalid token format");
  }

  const iv = Buffer.from(parts[1], "base64url");
  const tag = Buffer.from(parts[2], "base64url");
  const encrypted = Buffer.from(parts[3], "base64url");

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
    decipher.update(encrypted),
    decipher.final()
  ]).toString("utf8");
}

function reply(res, status, message) {
  return res.status(status).json({
    ok: status === 200,
    message
  });
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Allow", "POST");

  if (req.method !== "POST") {
    return reply(res, 405, "Método no permitido.");
  }

  const env = process.env;

  if (
    !env.SUPABASE_SECRET_KEY ||
    !env.GOOGLE_CLIENT_ID ||
    !env.GOOGLE_CLIENT_SECRET ||
    !/^[a-f0-9]{64}$/i.test(
      env.GMAIL_ENCRYPTION_KEY || ""
    )
  ) {
    return reply(res, 503, "Configuración incompleta.");
  }

  const authorization =
    req.headers.authorization || "";

  const match = authorization.match(
    /^Bearer\s+(\S+)$/i
  );

  if (!match) {
    return reply(res, 401, "Inicia sesión.");
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
      return reply(res, 401, "Sesión inválida.");
    }

    const admin = createClient(
      SUPABASE_URL,
      env.SUPABASE_SECRET_KEY,
      {
        auth: {
          persistSession: false,
          autoRefreshToken: false
        }
      }
    );

    const { data: connection, error: dbError } =
      await admin
        .from("gmail_connections")
        .select("refresh_token_encrypted,status")
        .eq("user_id", authData.user.id)
        .maybeSingle();

    if (dbError) {
      throw Error("Database error");
    }

    if (
      !connection ||
      connection.status !== "connected" ||
      !connection.refresh_token_encrypted
    ) {
      return reply(
        res,
        404,
        "No hay una conexión Gmail activa."
      );
    }

    const refreshToken = decrypt(
      connection.refresh_token_encrypted,
      env.GMAIL_ENCRYPTION_KEY
    );

    const params = new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      refresh_token: refreshToken,
      grant_type: "refresh_token"
    });

    // Solicitar un access token nuevo a Google.
    // No consultar mensajes.
    const response = await fetch(
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

    if (!response.ok) {
      return reply(
        res,
        502,
        "Google rechazó la renovación OAuth."
      );
    }

    const tokens = await response.json();

    if (!tokens.access_token) {
      throw Error("Missing access token");
    }

    return res.status(200).json({
      ok: true,
      gmail_oauth: "valid",
      refresh_successful: true,
      messages_read: 0,
      expenses_created: 0,
      notification_sent: false
    });

  } catch (error) {
    console.error("Gmail token check failed");

    return reply(
      res,
      500,
      "No se pudo verificar el token."
    );
  }
};
