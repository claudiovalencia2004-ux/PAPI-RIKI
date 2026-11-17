
"use strict";

// PAPI RIKI - Servidor Web Push
// Endpoint: POST /api/push-test
// Requiere sesión válida de Supabase.
// Solo envía a dispositivos del usuario autenticado.
// No acepta destinatarios ni mensajes arbitrarios.

const { createClient } = require("@supabase/supabase-js");
const webpush = require("web-push");

const SUPABASE_URL =
  "https://kbwrxebdcpgsplfjpkxv.supabase.co";

const SUPABASE_PUBLISHABLE_KEY =
  "sb_publishable_khEJIOxXl5ytDpXFABTWcg_hKC0lak2";

const VAPID_SUBJECT =
  "https://papi-riki.vercel.app";

function respond(res, status, data) {
  return res.status(status).json(data);
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Allow", "POST");

  // 1. Solo permitir POST.
  if (req.method !== "POST") {
    return respond(res, 405, {
      ok: false,
      message: "Método no permitido."
    });
  }

  // 2. Comprobar configuración del servidor.
  const {
    SUPABASE_SECRET_KEY,
    VAPID_PUBLIC_KEY,
    VAPID_PRIVATE_KEY
  } = process.env;

  if (
    !SUPABASE_SECRET_KEY ||
    !VAPID_PUBLIC_KEY ||
    !VAPID_PRIVATE_KEY
  ) {
    return respond(res, 503, {
      ok: false,
      message: "Faltan variables del servidor."
    });
  }

  // 3. Exigir token de usuario.
  const authorization = req.headers.authorization || "";

  const match = authorization.match(
    /^Bearer\s+(\S+)$/i
  );

  if (!match) {
    return respond(res, 401, {
      ok: false,
      message: "Debes iniciar sesión."
    });
  }

  const accessToken = match[1];

  try {
    // Cliente público exclusivamente para
    // validar la identidad del usuario.
    const authClient = createClient(
      SUPABASE_URL,
      SUPABASE_PUBLISHABLE_KEY,
      {
        auth: {
          persistSession: false,
          autoRefreshToken: false
        }
      }
    );

    const { data: authData, error: authError } =
      await authClient.auth.getUser(accessToken);

    if (authError || !authData?.user?.id) {
      return respond(res, 401, {
        ok: false,
        message: "Sesión inválida o caducada."
      });
    }

    const userId = authData.user.id;

    // Cliente privilegiado solo en servidor.
    // Nunca se devuelve su clave al navegador.
    const admin = createClient(
      SUPABASE_URL,
      SUPABASE_SECRET_KEY,
      {
        auth: {
          persistSession: false,
          autoRefreshToken: false
        }
      }
    );

    // 4. Buscar exclusivamente suscripciones
    // del usuario autenticado.
    const { data: devices, error: dbError } =
      await admin
        .from("push_subscriptions")
        .select("id,endpoint,p256dh,auth_key")
        .eq("user_id", userId)
        .limit(10);

    if (dbError) {
      console.error("Error consultando suscripciones");
      return respond(res, 500, {
        ok: false,
        message: "No se pudieron consultar dispositivos."
      });
    }

    if (!devices?.length) {
      return respond(res, 404, {
        ok: false,
        message: "No tienes dispositivos registrados."
      });
    }

    // 5. Configurar Web Push.
    webpush.setVapidDetails(
      VAPID_SUBJECT,
      VAPID_PUBLIC_KEY,
      VAPID_PRIVATE_KEY
    );

    // Mensaje fijo de prueba.
    // No permite texto suministrado por terceros.
    const payload = JSON.stringify({
      title: "PAPI RIKI",
      body: "¡Brochacho! Tu primera notificación funciona.",
      type: "test"
    });

    let sent = 0;
    let failed = 0;
    let expired = 0;

    // 6. Enviar a cada dispositivo propio.
    for (const device of devices) {
      const subscription = {
        endpoint: device.endpoint,
        keys: {
          p256dh: device.p256dh,
          auth: device.auth_key
        }
      };

      try {
        await webpush.sendNotification(
          subscription,
          payload,
          {
            TTL: 60,
            urgency: "normal",
            timeout: 10000
          }
        );

        sent++;

      } catch (error) {
        failed++;

        // Suscripciones expiradas o revocadas.
        if (
          error.statusCode === 404 ||
          error.statusCode === 410
        ) {
          expired++;

          // Eliminar solo la suscripción
          // que el proveedor declaró inválida.
          const { error: deleteError } =
            await admin
              .from("push_subscriptions")
              .delete()
              .eq("id", device.id)
              .eq("user_id", userId);

          if (deleteError) {
            console.error(
              "No se pudo limpiar suscripción expirada"
            );
          }
        } else {
          console.error(
            "Error Web Push:",
            error.statusCode || "desconocido"
          );
        }
      }
    }

    // 7. Respuesta sin revelar secretos.
    return respond(res, sent > 0 ? 200 : 502, {
      ok: sent > 0,
      message: sent > 0
        ? "Notificación aceptada por el servicio push."
        : "No se pudo enviar la notificación.",
      sent,
      failed,
      expired
    });

  } catch (error) {
    console.error(
      "Error servidor push:",
      error.message
    );

    return respond(res, 500, {
      ok: false,
      message: "Error interno del servidor."
    });
  }
};
