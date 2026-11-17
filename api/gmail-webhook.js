
"use strict";

// ==========================================
// PAPI RIKI - PASO 9.13.12
// WEBHOOK GMAIL PUB/SUB
// ==========================================
//
// MODO RECEPCION SEGURA
//
// - Verifica tokens firmados por Google.
// - Valida la cuenta de servicio.
// - Valida la audiencia OAuth.
// - Comprueba el formato del mensaje.
// - No lee Gmail.
// - No registra gastos.
// - No envía notificaciones.
// - No expone secretos.
// ==========================================

const { OAuth2Client } =
  require("google-auth-library");

const AUDIENCE =
  "https://papi-riki.vercel.app/api/gmail-webhook";

const SERVICE_ACCOUNT =
  "papi-riki-gmail-push@papi-riki-finance.iam.gserviceaccount.com";

const GOOGLE_CLIENT = new OAuth2Client();

function respond(res, status, data) {
  return res.status(status).json(data);
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Allow", "POST");

  if (req.method !== "POST") {
    return respond(res, 405, {
      ok: false,
      message: "Metodo no permitido."
    });
  }

  // 1. Verificar encabezado Authorization.
  const authorization =
    req.headers.authorization || "";

  const match = authorization.match(
    /^Bearer\s+(\S+)$/i
  );

  if (!match) {
    return respond(res, 401, {
      ok: false,
      message: "Token de Google requerido."
    });
  }

  try {
    // 2. Verificar firma, emisor y audiencia.
    const ticket =
      await GOOGLE_CLIENT.verifyIdToken({
        idToken: match[1],
        audience: AUDIENCE
      });

    const payload = ticket.getPayload();

    // 3. Comprobar identidad exacta.
    if (
      !payload ||
      payload.email !== SERVICE_ACCOUNT ||
      payload.email_verified !== true
    ) {
      return respond(res, 403, {
        ok: false,
        message: "Cuenta de servicio no autorizada."
      });
    }

    // 4. Validar sobre Pub/Sub.
    const envelope = req.body;

    if (
      !envelope ||
      typeof envelope !== "object" ||
      !envelope.message ||
      typeof envelope.message.data !== "string"
    ) {
      return respond(res, 400, {
        ok: false,
        message: "Mensaje Pub/Sub invalido."
      });
    }

    // 5. Decodificar notificacion Gmail.
    const raw = Buffer.from(
      envelope.message.data,
      "base64"
    ).toString("utf8");

    const notification = JSON.parse(raw);

    if (
      typeof notification.emailAddress !== "string" ||
      !/^\d+$/.test(
        String(notification.historyId || "")
      )
    ) {
      return respond(res, 400, {
        ok: false,
        message: "Notificacion Gmail invalida."
      });
    }

    // 6. Confirmar recepcion.
    // No registrar datos financieros.
    // No almacenar contenido de correos.
    // No enviar push al iPhone.

    return respond(res, 200, {
      ok: true,
      received: true,
      authenticated: true,
      processing_enabled: false
    });

  } catch (error) {
    console.error(
      "Gmail Pub/Sub verification failed"
    );

    return respond(res, 401, {
      ok: false,
      message: "No se pudo verificar Google."
    });
  }
};
