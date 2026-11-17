
"use strict";

// PAPI RIKI - Diagnostico OAuth
// No devuelve claves ni tokens.
// Acceso restringido a usuario autenticado.

const { createClient } = require("@supabase/supabase-js");

const SUPABASE_URL =
  "https://kbwrxebdcpgsplfjpkxv.supabase.co";

const PUBLIC_KEY =
  "sb_publishable_khEJIOxXl5ytDpXFABTWcg_hKC0lak2";

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Allow", "POST");

  if (req.method !== "POST") {
    return res.status(405).json({
      ok: false,
      message: "Metodo no permitido."
    });
  }

  const authorization =
    req.headers.authorization || "";

  const match = authorization.match(
    /^Bearer\s+(\S+)$/i
  );

  if (!match) {
    return res.status(401).json({
      ok: false,
      message: "Autenticacion requerida."
    });
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

    const { data, error } =
      await auth.auth.getUser(match[1]);

    if (error || !data?.user?.id) {
      return res.status(401).json({
        ok: false,
        message: "Sesion invalida."
      });
    }

    const env = process.env;

    // Resultado general sin identificar
    // ni exponer variables individuales.
    const configured =
      Boolean(env.GOOGLE_CLIENT_ID) &&
      Boolean(env.GOOGLE_CLIENT_SECRET) &&
      Boolean(env.SUPABASE_SECRET_KEY) &&
      /^[a-f0-9]{64}$/i.test(
        env.GMAIL_STATE_SECRET || ""
      ) &&
      /^[a-f0-9]{64}$/i.test(
        env.GMAIL_ENCRYPTION_KEY || ""
      );

    return res.status(200).json({
      ok: true,
      oauthConfigurationComplete: configured,
      message: configured
        ? "Configuracion OAuth completa."
        : "Alguna variable falta o tiene formato incorrecto."
    });

  } catch (error) {
    console.error("Diagnostico OAuth fallido");

    return res.status(500).json({
      ok: false,
      message: "No se pudo completar el diagnostico."
    });
  }
};
