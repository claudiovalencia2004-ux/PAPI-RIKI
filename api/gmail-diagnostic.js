
"use strict";

// PAPI RIKI - Diagnóstico OAuth
// No devuelve valores secretos.
// Acceso exclusivo al usuario autenticado.

const { createClient } = require("@supabase/supabase-js");

const URL_SUPABASE =
  "https://kbwrxebdcpgsplfjpkxv.supabase.co";

const PUBLIC_KEY =
  "sb_publishable_khEJIOxXl5ytDpXFABTWcg_hKC0lak2";

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Allow", "POST");

  if (req.method !== "POST") {
    return res.status(405).json({
      ok: false,
      message: "Método no permitido"
    });
  }

  const authorization = req.headers.authorization || "";
  const match = authorization.match(/^Bearer\s+(\S+)$/i);

  if (!match) {
    return res.status(401).json({
      ok: false,
      message: "Autenticación requerida"
    });
  }

  try {
    const auth = createClient(URL_SUPABASE, PUBLIC_KEY, {
      auth: {
        persistSession: false,
        autoRefreshToken: false
      }
    });

    const { data, error } =
      await auth.auth.getUser(match[1]);

    if (error || !data?.user?.id) {
      return res.status(401).json({
        ok: false,
        message: "Sesión inválida"
      });
    }

    const env = process.env;

    const checks = {
      GOOGLE_CLIENT_ID:
        Boolean(env.GOOGLE_CLIENT_ID),

      GOOGLE_CLIENT_SECRET:
        Boolean(env.GOOGLE_CLIENT_SECRET),

      SUPABASE_SECRET_KEY:
        Boolean(env.SUPABASE_SECRET_KEY),

      GMAIL_STATE_SECRET:
        /^[a-f0-9]{64}$/i.test(
          env.GMAIL_STATE_SECRET || ""
        ),

      GMAIL_ENCRYPTION_KEY:
        /^[a-f0-9]{64}$/i.test(
          env.GMAIL_ENCRYPTION_KEY || ""
        )
    };

    return res.status(200).json({
      ok: true,
      checks,
      allConfigured:
        Object.values(checks).every(Boolean)
    });

  } catch (error) {
    console.error("OAuth diagnostic failed");

    return res.status(500).json({
      ok: false,
      message: "Error interno de diagnóstico"
    });
  }
};
