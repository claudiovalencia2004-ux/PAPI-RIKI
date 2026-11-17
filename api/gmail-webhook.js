
"use strict";

// ==========================================
// PAPI RIKI - PASO 9.14.2
// GMAIL PUB/SUB WEBHOOK
// RECEPCION Y PERSISTENCIA SEGURA
// ==========================================
//
// - Verifica token OIDC de Google.
// - Verifica cuenta de servicio y audiencia.
// - Comprueba la suscripcion Pub/Sub.
// - Identifica al usuario por Gmail conectado.
// - Guarda historyId en Supabase.
// - Evita duplicados.
// - No lee mensajes de Gmail.
// - No registra gastos.
// - No envia notificaciones al iPhone.
// ==========================================

const { OAuth2Client } =
  require("google-auth-library");

const { createClient } =
  require("@supabase/supabase-js");

const AUDIENCE =
  "https://papi-riki.vercel.app/api/gmail-webhook";

const SERVICE_ACCOUNT =
  "papi-riki-gmail-push@papi-riki-finance.iam.gserviceaccount.com";

const SUBSCRIPTION =
  "projects/papi-riki-finance/subscriptions/papi-riki-gmail-push";

const SUPABASE_URL =
  "https://kbwrxebdcpgsplfjpkxv.supabase.co";

const googleClient = new OAuth2Client();

function reply(res, status, data) {
  return res.status(status).json(data);
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
    return reply(res, 405, {
      ok: false,
      message: "Metodo no permitido."
    });
  }

  // ======================================
  // 1. VERIFICAR IDENTIDAD DE GOOGLE
  // ======================================

  const authorization =
    req.headers.authorization || "";

  const match = authorization.match(
    /^Bearer\s+(\S+)$/i
  );

  if (!match) {
    return reply(res, 401, {
      ok: false,
      message: "Autenticacion requerida."
    });
  }

  try {
    const ticket =
      await googleClient.verifyIdToken({
        idToken: match[1],
        audience: AUDIENCE
      });

    const identity = ticket.getPayload();

    if (
      !identity ||
      identity.email !== SERVICE_ACCOUNT ||
      identity.email_verified !== true
    ) {
      return reply(res, 403, {
        ok: false,
        message: "Identidad no autorizada."
      });
    }

  } catch (error) {
    console.error("Google OIDC validation failed");

    return reply(res, 401, {
      ok: false,
      message: "Token de Google invalido."
    });
  }

  // ======================================
  // 2. VALIDAR MENSAJE PUB/SUB
  // ======================================

  try {
    const envelope = req.body;

    if (
      !envelope ||
      typeof envelope !== "object" ||
      envelope.subscription !== SUBSCRIPTION ||
      !envelope.message ||
      typeof envelope.message.data !== "string"
    ) {
      return reply(res, 400, {
        ok: false,
        message: "Mensaje Pub/Sub invalido."
      });
    }

    const encoded = envelope.message.data;

    if (
      encoded.length > 8192 ||
      !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)
    ) {
      return reply(res, 400, {
        ok: false,
        message: "Payload invalido."
      });
    }

    const raw = Buffer.from(
      encoded,
      "base64"
    ).toString("utf8");

    const notification = JSON.parse(raw);

    if (
      typeof notification.emailAddress !== "string" ||
      !validHistoryId(
        String(notification.historyId || "")
      )
    ) {
      return reply(res, 400, {
        ok: false,
        message: "Notificacion Gmail invalida."
      });
    }

    const email = notification.emailAddress
      .trim()
      .toLowerCase();

    if (
      !email ||
      email.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    ) {
      return reply(res, 400, {
        ok: false,
        message: "Cuenta Gmail invalida."
      });
    }

    // ====================================
    // 3. CONECTAR CON SUPABASE
    // ====================================

    if (!process.env.SUPABASE_SECRET_KEY) {
      return reply(res, 503, {
        ok: false,
        message: "Servidor sin configurar."
      });
    }

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

    // ====================================
    // 4. IDENTIFICAR USUARIO
    // ====================================

    const { data: connections, error: findError } =
      await admin
        .from("gmail_connections")
        .select("user_id")
        .eq("gmail_address", email)
        .eq("status", "connected")
        .limit(2);

    if (findError) {
      throw new Error(
        "Error consultando conexion Gmail."
      );
    }

    if (!connections || connections.length === 0) {
      // No reconocer una cuenta desconocida
      // como un gasto valido.
      return reply(res, 200, {
        ok: true,
        accepted: false,
        reason: "unlinked_account"
      });
    }

    if (connections.length !== 1) {
      // No asociar un aviso ambiguo.
      return reply(res, 409, {
        ok: false,
        message: "Conexion Gmail ambigua."
      });
    }

    const userId = connections[0].user_id;

    // ====================================
    // 5. GUARDAR EVENTO SIN DUPLICAR
    // ====================================

    const { error: insertError } =
      await admin
        .from("gmail_events")
        .upsert({
          user_id: userId,
          gmail_history_id:
            String(notification.historyId),
          status: "pending"
        }, {
          onConflict:
            "user_id,gmail_history_id",
          ignoreDuplicates: true
        });

    if (insertError) {
      throw new Error(
        "Error guardando evento Gmail."
      );
    }

    // ====================================
    // 6. CONFIRMAR ENTREGA A PUB/SUB
    // ====================================

    return reply(res, 200, {
      ok: true,
      authenticated: true,
      persisted: true,
      processing_enabled: false,
      expenses_created: 0,
      notification_sent: false
    });

  } catch (error) {
    // No imprimir tokens ni datos bancarios.
    console.error("Gmail event persistence failed");

    // Pub/Sub puede reintentar.
    return reply(res, 503, {
      ok: false,
      message: "No se pudo guardar el evento."
    });
  }
};
