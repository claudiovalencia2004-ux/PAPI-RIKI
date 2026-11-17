
"use strict";

// PAPI RIKI - PASO 9.8.4
// Callback seguro OAuth de Gmail.
// No contiene claves privadas.
// No lee correos bancarios.
// Guarda el refresh token cifrado.

const crypto = require("node:crypto");
const { createClient } = require("@supabase/supabase-js");

const SUPABASE_URL =
  "https://kbwrxebdcpgsplfjpkxv.supabase.co";

const BASE = "https://papi-riki.vercel.app";

const REDIRECT = BASE + "/api/gmail-callback";

function sha(value) {
  return crypto
    .createHash("sha256")
    .update(value)
    .digest("hex");
}

function verifySigned(value, secret) {
  if (!value || typeof value !== "string") {
    throw new Error("Missing signed value");
  }

  const parts = value.split(".");

  if (parts.length !== 2) {
    throw new Error("Invalid signed value");
  }

  const [payload, signature] = parts;

  const expected = crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest();

  const received = Buffer.from(
    signature,
    "base64url"
  );

  if (
    received.length !== expected.length ||
    !crypto.timingSafeEqual(received, expected)
  ) {
    throw new Error("Invalid signature");
  }

  return JSON.parse(
    Buffer.from(payload, "base64url").toString("utf8")
  );
}

function encrypt(value, keyHex) {
  const key = Buffer.from(keyHex, "hex");

  if (key.length !== 32) {
    throw new Error("Invalid encryption key");
  }

  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    key,
    iv
  );

  const ciphertext = Buffer.concat([
    cipher.update(value, "utf8"),
    cipher.final()
  ]);

  const tag = cipher.getAuthTag();

  return [
    "v1",
    iv.toString("base64url"),
    tag.toString("base64url"),
    ciphertext.toString("base64url")
  ].join(".");
}

function go(res, status) {
  res.statusCode = 303;

  res.setHeader(
    "Location",
    BASE + "/gmail-connect.html?status=" + status
  );

  return res.end();
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Allow", "GET");

  // Eliminar la cookie temporal al terminar.
  res.setHeader(
    "Set-Cookie",
    "papi_gmail_oauth=; Path=/api/gmail-callback;" +
    " HttpOnly; Secure; SameSite=Lax; Max-Age=0"
  );

  if (req.method !== "GET") {
    return res.status(405).end();
  }

  const env = process.env;

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
    return go(res, "configuration_error");
  }

  const { code, state, error } = req.query;

  if (
    error ||
    !code ||
    !state ||
    typeof code !== "string" ||
    typeof state !== "string"
  ) {
    return go(res, "cancelled");
  }

  try {
    const stateData = verifySigned(
      state,
      env.GMAIL_STATE_SECRET
    );

    const cookies = Object.fromEntries(
      (req.headers.cookie || "")
        .split(";")
        .map(s => s.trim())
        .filter(Boolean)
        .map(s => {
          const index = s.indexOf("=");

          return [
            s.slice(0, index),
            s.slice(index + 1)
          ];
        })
    );

    const cookieData = verifySigned(
      cookies.papi_gmail_oauth,
      env.GMAIL_STATE_SECRET
    );

    if (
      stateData.nonce !== cookieData.nonce ||
      !stateData.userId ||
      !cookieData.verifier ||
      !Number.isFinite(stateData.expires) ||
      Date.now() > stateData.expires
    ) {
      throw new Error(
        "OAuth state expired or mismatched"
      );
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

    // Consumir el estado una sola vez.
    const { data: used, error: stateError } =
      await admin
        .from("gmail_oauth_states")
        .delete()
        .eq("state_hash", sha(stateData.nonce))
        .eq("user_id", stateData.userId)
        .gt(
          "expires_at",
          new Date().toISOString()
        )
        .select("state_hash");

    if (stateError || used?.length !== 1) {
      throw new Error(
        "OAuth state already used or invalid"
      );
    }

    // Intercambiar el código OAuth
    // por tokens desde el servidor.
    const params = new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: REDIRECT,
      grant_type: "authorization_code",
      code_verifier: cookieData.verifier
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
      throw new Error(
        "Google token exchange failed"
      );
    }

    const tokens = await tokenResponse.json();

    if (
      !tokens.access_token ||
      !tokens.refresh_token
    ) {
      throw new Error(
        "Missing OAuth tokens"
      );
    }

    // Obtener la dirección de Gmail autorizada.
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
      throw new Error(
        "Gmail profile unavailable"
      );
    }

    const profile = await profileResponse.json();

    if (!profile.emailAddress) {
      throw new Error(
        "Missing Gmail address"
      );
    }

    // Cifrar el refresh token.
    const encryptedRefreshToken = encrypt(
      tokens.refresh_token,
      env.GMAIL_ENCRYPTION_KEY
    );

    const expiresAt = new Date(
      Date.now() +
      Math.max(
        0,
        Number(tokens.expires_in || 3600) - 60
      ) * 1000
    ).toISOString();

    // Guardar la conexión.
    const { error: saveError } = await admin
      .from("gmail_connections")
      .upsert({
        user_id: stateData.userId,
        gmail_address: profile.emailAddress,
        refresh_token_encrypted:
          encryptedRefreshToken,
        token_expires_at: expiresAt,
        status: "connected",
        updated_at: new Date().toISOString()
      }, {
        onConflict: "user_id"
      });

    if (saveError) {
      throw new Error(
        "Could not store Gmail connection"
      );
    }

    return go(res, "connected");

  } catch (error) {
    // No registrar códigos ni tokens OAuth.
    console.error(
      "Gmail OAuth callback failed"
    );

    return go(res, "error");
  }
};
