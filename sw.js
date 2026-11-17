
/*
 * PAPI RIKI
 * Service Worker - Version 1
 * Preparado para notificaciones Web Push.
 *
 * No contiene claves privadas.
 * No accede a Gmail ni a bancos.
 * No almacena datos financieros.
 */

"use strict";

// Instalación del Service Worker
self.addEventListener("install", () => {
  self.skipWaiting();
});

// Activación
self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

// Recepción de notificaciones push
self.addEventListener("push", (event) => {
  let payload = {};

  try {
    if (event.data) {
      payload = event.data.json();
    }
  } catch (error) {
    payload = {};
  }

  // No confiamos en URLs externas enviadas
  // dentro de las notificaciones.
  const title = "PAPI RIKI";

  const body =
    typeof payload.body === "string"
      ? payload.body.slice(0, 180)
      : "Tienes un movimiento pendiente de revisar.";

  const options = {
    body,
    tag: "papi-riki-movimiento",
    renotify: true,
    data: {
      url: "/"
    }
  };

  // Mostrar siempre una notificación visible
  event.waitUntil(
    self.registration.showNotification(
      title,
      options
    )
  );
});

// Al tocar una notificación
self.addEventListener("notificationclick", (event) => {
  event.notification.close();

  event.waitUntil((async () => {
    const destination =
      new URL("/", self.location.origin).href;

    const windows = await self.clients.matchAll({
      type: "window",
      includeUncontrolled: true
    });

    for (const windowClient of windows) {
      if (
        new URL(windowClient.url).origin ===
        self.location.origin
      ) {
        await windowClient.focus();
        return;
      }
    }

    await self.clients.openWindow(destination);
  })());
});
