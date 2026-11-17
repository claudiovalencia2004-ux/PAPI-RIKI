
"use strict";

// PAPI RIKI - API de prueba Web Push
// Primera etapa: comprobar configuración segura.
// Todavía no envía notificaciones.

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Allow", "GET");

  if (req.method !== "GET") {
    return res.status(405).json({
      ok: false,
      message: "Método no permitido"
    });
  }

  const publicKeyConfigured =
    Boolean(process.env.VAPID_PUBLIC_KEY);

  const privateKeyConfigured =
    Boolean(process.env.VAPID_PRIVATE_KEY);

  return res.status(200).json({
    ok: true,
    application: "PAPI RIKI",
    stage: "push-server-configuration",
    vapidPublicConfigured: publicKeyConfigured,
    vapidPrivateConfigured: privateKeyConfigured,
    sendingEnabled: false,
    message:
      "Servidor disponible. Envío push todavía desactivado."
  });
};
