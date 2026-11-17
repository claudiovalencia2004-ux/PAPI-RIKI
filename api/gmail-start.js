
"use strict";

// PAPI RIKI - PASO 9.8.3
// Inicio seguro de autorizacion OAuth para Gmail.
// No contiene claves privadas ni tokens.
// Requiere una sesion autenticada de Supabase.

const crypto = require("node:crypto");
const { createClient } = require("@supabase/supabase-js");

const BASE = "https://papi-riki.vercel.app";

const SUPABASE_URL =
  "https://kbwrxebdcpgsplfjpkxv.supabase.co";

const PUBLIC_KEY =
  "sb_publishable_khEJIOxXl5ytDpXFABTWcg_hKC0lak2";

const REDIRECT = BASE + "/api/gmail-callback";

const SCOPE =
  "https://www.googleapis.com/auth/gmail.readonly";

function b64(buffer) {
  return Buffer.from(buffer).toString("base64url");
}

function sha(value) {
  return crypto
    .createHash("sha256")
    .update(value)
    .digest("hex");
}

function hmac(value, key) {
  return b64(
    crypto
      .createHmac("sha256", key)
      .update(value)
      .digest()
  );
}

function fail(res, status, message) {
  return res.status(status).json({
    ok: false,
    message
  });
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Allow", "POST");

  // Solo aceptar POST.
  if (req.method !== "POST") {
    return fail(res, 405, "Metodo no permitido.");
  }

  const env = process.env;

  // Verificar que las variables secretas
  // esten configuradas en Vercel.
  if (
    !env.GOOGLE_CLIENT_ID ||
    !env.GOOGLE_CLIENT_SECRET ||
    !env.SUPABASE_SECRET_KEY ||
    !/^[a-f0-9]{64}$/i.test(
      env.GMAIL_STATE_SECRET || ""
    ) ||
    !/^[a-f0-9]{64}$/i.test(
      env.GMAIL_ENCRYPTION_KEY || ""
    )
  ) {
    return fail(
      res,
      503,
      "Configuracion incompleta del servidor."
    );
  }

  // Exigir una sesion de PAPI RIKI.
  const authorization =
    req.headers.authorization || "";

  const match = authorization.match(
    /^Bearer\s+(\S+)$/i
  );

  if (!match) {
    return fail(
      res,
      401,
      "Debes iniciar sesion en PAPI RIKI."
    );
  }

  try {
    // Validar el token del usuario.
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

    const { data, error } =
      await auth.auth.getUser(match[1]);

    if (error || !data?.user?.id) {
      return fail(
        res,
        401,
        "Sesion invalida o caducada."
      );
    }

    // Cliente privilegiado:
    // solo se ejecuta en Vercel.
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

    // Crear valores aleatorios para
    // proteger el flujo OAuth.
    const nonce = b64(
      crypto.randomBytes(32)
    );

    const verifier = b64(
      crypto.randomBytes(32)
    );

    const challenge = b64(
      crypto
        .createHash("sha256")
        .update(verifier)
        .digest()
    );

    // La autorizacion dura 10 minutos.
    const expires =
      Date.now() + 10 * 60 * 1000;

    const stateData = JSON.stringify({
      nonce,
      userId: data.user.id,
      expires
    });

    const statePayload = b64(
      Buffer.from(stateData, "utf8")
    );

    const state =
      statePayload +
      "." +
      hmac(
        statePayload,
        env.GMAIL_STATE_SECRET
      );

    // Registrar el estado temporal.
    const { error: dbError } = await admin
      .from("gmail_oauth_states")
      .insert({
        state_hash: sha(nonce),
        user_id: data.user.id,
        expires_at:
          new Date(expires).toISOString()
      });

    if (dbError) {
      throw new Error(
        "No se pudo preparar OAuth."
      );
    }

    // Guardar temporalmente el verificador PKCE
    // en una cookie protegida.
    const cookieData = b64(
      Buffer.from(
        JSON.stringify({
          nonce,
          verifier
        })
      )
    );

    const cookieValue =
      cookieData +
      "." +
      hmac(
        cookieData,
        env.GMAIL_STATE_SECRET
      );

    res.setHeader(
      "Set-Cookie",
      "papi_gmail_oauth=" +
        cookieValue +
        "; Path=/api/gmail-callback" +
        "; HttpOnly; Secure; SameSite=Lax" +
        "; Max-Age=600"
    );

    // Construir la URL oficial de Google.
    const url = new URL(
      "https://accounts.google.com/o/oauth2/v2/auth"
    );

    url.searchParams.set(
      "client_id",
      env.GOOGLE_CLIENT_ID
    );

    url.searchParams.set(
      "redirect_uri",
      REDIRECT
    );

    url.searchParams.set(
      "response_type",
      "code"
    );

    url.searchParams.set(
      "scope",
      SCOPE
    );

    url.searchParams.set(
      "access_type",
      "offline"
    );

    url.searchParams.set(
      "prompt",
      "consent"
    );

    url.searchParams.set(
      "state",
      state
    );

    url.searchParams.set(
      "code_challenge",
      challenge
    );

    url.searchParams.set(
      "code_challenge_method",
      "S256"
    );

    // Devolver la URL al navegador autenticado.
    return res.status(200).json({
      ok: true,
      authorization_url: url.toString()
    });

  } catch (error) {
    console.error(
      "Gmail OAuth start failed"
    );

    return fail(
      res,
      500,
      "No se pudo iniciar la conexion con Gmail."
    );
  }
};
