
"use strict";

// ============================================
// PAPI RIKI - PASO 9.19.1
// GMAIL PUB/SUB WEBHOOK SEGURO
// ============================================
//
// Recibe eventos autenticados de Google.
// Identifica la conexion Gmail.
// Guarda eventos pendientes en Supabase.
// Evita duplicados.
//
// NO lee correos.
// NO confirma gastos.
// NO envia Web Push.
// NO activa Gmail Watch.
// NO ejecuta el procesador todavia.
//
// El procesamiento automatico requiere
// un trabajador interno independiente.
// ============================================

const { OAuth2Client } =
  require("google-auth-library");

const { createClient } =
  require("@supabase/supabase-js");

const SUPABASE_URL =
  "https://kbwrxebdcpgsplfjpkxv.supabase.co";

const AUDIENCE =
  "https://papi-riki.vercel.app/api/gmail-webhook";

const SERVICE_ACCOUNT =
  "papi-riki-gmail-push@papi-riki-finance.iam.gserviceaccount.com";

const SUBSCRIPTION =
  "projects/papi-riki-finance/subscriptions/papi-riki-gmail-push";

const googleClient = new OAuth2Client();

function respond(res, status, data) {
  return res.status(status).json(data);
}

function validHistoryId(value) {
  return (
    typeof value === "string" &&
    /^[0-9]{1,30}$/.test(value)
  );
}

function validEmail(value) {
  return (
    typeof value === "string" &&
    value.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)
  );
}

function decodeNotification(encoded) {
  if (
    typeof encoded !== "string" ||
    encoded.length === 0 ||
    encoded.length > 8192 ||
    !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)
  ) {
    throw Error("Invalid PubSub data");
  }

  const raw = Buffer.from(
    encoded,
    "base64"
  ).toString("utf8");

  if (raw.length > 4096) {
    throw Error("Payload too large");
  }

  const notification = JSON.parse(raw);

  if (
    !notification ||
    typeof notification !== "object"
  ) {
    throw Error("Invalid Gmail notification");
  }

  const email = String(
    notification.emailAddress || ""
  ).trim().toLowerCase();

  const historyId = String(
    notification.historyId || ""
  );

  if (
    !validEmail(email) ||
    !validHistoryId(historyId)
  ) {
    throw Error("Invalid Gmail notification fields");
  }

  return { email, historyId };
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

async function verifyGoogle(req) {
  const authorization = String(
    req.headers.authorization || ""
  );

  const match = authorization.match(
    /^Bearer\s+(\S+)$/i
  );

  if (!match) {
    return false;
  }

  const ticket =
    await googleClient.verifyIdToken({
      idToken: match[1],
      audience: AUDIENCE
    });

  const identity = ticket.getPayload();

  return Boolean(
    identity &&
    identity.email_verified === true &&
    identity.email === SERVICE_ACCOUNT &&
    (
      identity.iss === "https://accounts.google.com" ||
      identity.iss === "accounts.google.com"
    )
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

  // ========================================
  // 1. VERIFICAR IDENTIDAD DE GOOGLE
  // ========================================

  try {
    const authorized = await verifyGoogle(req);

    if (!authorized) {
      return respond(res, 401, {
        ok: false,
        message: "Unauthorized"
      });
    }
  } catch {
    console.error("PubSub authentication failed");

    return respond(res, 401, {
      ok: false,
      message: "Authentication failed"
    });
  }

  // ========================================
  // 2. VALIDAR MENSAJE
  // ========================================

  let notification;

  try {
    const envelope = req.body;

    if (
      !envelope ||
      typeof envelope !== "object" ||
      envelope.subscription !== SUBSCRIPTION ||
      !envelope.message ||
      typeof envelope.message !== "object"
    ) {
      throw Error("Invalid envelope");
    }

    notification = decodeNotification(
      envelope.message.data
    );

  } catch {
    return respond(res, 400, {
      ok: false,
      message: "Invalid notification"
    });
  }

  // ========================================
  // 3. IDENTIFICAR USUARIO
  // ========================================

  try {
    const admin = createAdmin();

    const { data: connections, error: lookupError } =
      await admin
        .from("gmail_connections")
        .select("user_id")
        .eq("gmail_address", notification.email)
        .eq("status", "connected")
        .limit(2);

    if (lookupError) {
      throw Error("Connection lookup failed");
    }

    if (!connections || connections.length === 0) {
      // No existe una conexion asociada.
      // No crear eventos para usuarios desconocidos.
      return respond(res, 200, {
        ok: true,
        accepted: false,
        reason: "unlinked_account"
      });
    }

    if (connections.length !== 1) {
      // No asociar eventos a una cuenta ambigua.
      // Devolver error para permitir reintento.
      return respond(res, 503, {
        ok: false,
        message: "Ambiguous connection"
      });
    }

    const userId = connections[0].user_id;

    // ======================================
    // 4. GUARDAR EVENTO SIN DUPLICADOS
    // ======================================

    const { error: insertError } =
      await admin
        .from("gmail_events")
        .upsert(
          {
            user_id: userId,
            gmail_history_id:
              notification.historyId,
            status: "pending"
          },
          {
            onConflict:
              "user_id,gmail_history_id",
            ignoreDuplicates: true
          }
        );

    if (insertError) {
      throw Error("Event persistence failed");
    }

    // ======================================
    // 5. CONFIRMAR ENTREGA
    // ======================================

    // HTTP 200 indica que el evento quedo
    // almacenado o ya existia.
    //
    // NO significa que el gasto fue procesado.
    // NO ejecuta Gmail History.
    // NO envia notificaciones al iPhone.

    return respond(res, 200, {
      ok: true,
      authenticated: true,
      persisted: true,
      processing_enabled: false,
      expenses_confirmed: 0,
      notifications_sent: 0
    });

  } catch {
    console.error("Gmail event persistence failed");

    // Un error temporal permite que Pub/Sub
    // vuelva a intentar la entrega.
    return respond(res, 503, {
      ok: false,
      message: "Event persistence unavailable"
    });
  }
};
