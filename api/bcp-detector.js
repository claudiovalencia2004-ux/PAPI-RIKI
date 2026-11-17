
"use strict";

// ==========================================
// PAPI RIKI - DETECTOR BCP
// PASO 9.11.1
// ==========================================
//
// Reconoce consumos de tarjeta de débito BCP.
//
// MODO PRUEBA:
// - No consulta Gmail.
// - No modifica Supabase.
// - No registra gastos.
// - No envía notificaciones.
// - No utiliza claves secretas.
//
// Solo devuelve datos extraídos de un
// ejemplo ficticio con el formato BCP.
// ==========================================

const EXPECTED_SENDER =
  "notificaciones@notificacionesbcp.com.pe";

const EXPECTED_SUBJECT =
  "Realizaste un consumo con tu Tarjeta de Débito BCP";

function normalize(text) {
  return String(text || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function parseAmount(value) {
  const raw = String(value).trim();

  // Formato peruano:
  // 1.234,56 o 1,234.56 o 1234.56
  let number = raw.replace(/[^\d.,]/g, "");

  if (number.includes(",") && number.includes(".")) {
    if (number.lastIndexOf(",") > number.lastIndexOf(".")) {
      number = number.replace(/\./g, "").replace(",", ".");
    } else {
      number = number.replace(/,/g, "");
    }
  } else if (number.includes(",")) {
    const parts = number.split(",");
    number = parts.length === 2 && parts[1].length === 2
      ? number.replace(",", ".")
      : number.replace(/,/g, "");
  }

  const result = Number(number);

  if (!Number.isFinite(result) || result <= 0) {
    throw new Error("Importe inválido");
  }

  return Math.round(result * 100) / 100;
}

function parseBCPEmail(email) {
  const sender = String(email.from || "").toLowerCase();
  const subject = normalize(email.subject).toLowerCase();
  const body = normalize(email.body);

  if (!sender.includes("<" + EXPECTED_SENDER + ">") &&
      sender.trim() !== EXPECTED_SENDER) {
    throw new Error("Remitente no reconocido");
  }

  if (!subject.includes(
    normalize(EXPECTED_SUBJECT).toLowerCase()
  )) {
    throw new Error("Asunto no reconocido");
  }

  if (!/consumo tarjeta de debito/i.test(body)) {
    throw new Error("Tipo de operación no reconocido");
  }

  const amountMatch = body.match(
    /Total del consumo\s*(S\/|US\$|\$)\s*([\d.,]+)/i
  );

  if (!amountMatch) {
    throw new Error("No se encontró el importe");
  }

  const currency =
    amountMatch[1] === "S/" ? "PEN" : "USD";

  const amount = parseAmount(amountMatch[2]);

  const merchantMatch = body.match(
    /Empresa\s+(.+?)(?=\s+Numero de operacion|\s+No reconoces|\s+Seguimos mejorando|$)/i
  );

  if (!merchantMatch) {
    throw new Error("No se encontró el comercio");
  }

  const merchant = merchantMatch[1].trim();

  const dateMatch = body.match(
    /Fecha y hora\s+(\d{1,2}) de ([a-z]+) de (\d{4})\s*-\s*(\d{1,2}):(\d{2})\s*(AM|PM)/i
  );

  if (!dateMatch) {
    throw new Error("No se encontró la fecha");
  }

  const months = {
    enero:1,
    febrero:2,
    marzo:3,
    abril:4,
    mayo:5,
    junio:6,
    julio:7,
    agosto:8,
    septiembre:9,
    octubre:10,
    noviembre:11,
    diciembre:12
  };

  const month = months[dateMatch[2].toLowerCase()];

  if (!month) {
    throw new Error("Mes no reconocido");
  }

  let hour = Number(dateMatch[4]) % 12;

  if (dateMatch[6].toUpperCase() === "PM") {
    hour += 12;
  }

  const transactionDate =
    dateMatch[3] + "-" +
    String(month).padStart(2, "0") + "-" +
    dateMatch[1].padStart(2, "0") + "T" +
    String(hour).padStart(2, "0") + ":" +
    dateMatch[5] + ":00-05:00";

  const parsedDate = new Date(transactionDate);

  if (Number.isNaN(parsedDate.getTime())) {
    throw new Error("Fecha inválida");
  }

  return {
    bank: "BCP",
    operation_type: "debit_card_purchase",
    merchant,
    amount,
    currency,
    transaction_date: parsedDate.toISOString(),
    status: "pending",
    gmail_message_id: email.messageId || null
  };
}

// ==========================================
// EJEMPLO DE PRUEBA
// ==========================================

const TEST_EMAIL = {
  messageId: "bcp-test-example-001",

  from:
    "BCP Notificaciones <notificaciones@notificacionesbcp.com.pe>",

  subject:
    "Realizaste un consumo con tu Tarjeta de Débito BCP - Servicio de Notificaciones BCP",

  body: `
    Hola,

    Realizaste un consumo de S/ 1.00
    con tu Tarjeta de Débito BCP
    en COMERCIO DE PRUEBA.

    Monto
    Total del consumo S/ 1.00

    Datos de la operación

    Operación realizada
    Consumo Tarjeta de Débito

    Fecha y hora
    11 de noviembre de 2026 - 08:07 PM

    Número de Tarjeta de Débito
    ************0000

    Empresa
    COMERCIO DE PRUEBA

    Número de operación
    000000
  `
};

// ==========================================
// ENDPOINT DE PRUEBA
// ==========================================

// No recibe correos del usuario.
// No expone credenciales.
// No escribe en ninguna base de datos.

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Allow", "GET");

  if (req.method !== "GET") {
    return res.status(405).json({
      ok: false,
      message: "Método no permitido"
    });
  }

  try {
    const result = parseBCPEmail(TEST_EMAIL);

    return res.status(200).json({
      ok: true,
      mode: "test",
      detector: "BCP Debit Card",
      result,
      saved_to_database: false,
      notification_sent: false
    });

  } catch (error) {
    return res.status(422).json({
      ok: false,
      message: error.message
    });
  }
};
