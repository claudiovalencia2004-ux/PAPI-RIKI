
"use strict";

// ==========================================
// PAPI RIKI - PASO 9.11.3
// DETECTOR BCP CORREGIDO
// ==========================================
//
// MODO PRUEBA
//
// - No accede a Gmail.
// - No modifica Supabase.
// - No registra gastos.
// - No envía notificaciones.
// - No utiliza claves secretas.
//
// Valida siete escenarios con datos ficticios.
// ==========================================

const SENDER =
  "notificaciones@notificacionesbcp.com.pe";

const SUBJECT =
  "realizaste un consumo con tu tarjeta de debito bcp";

const MONTHS = {
  enero: 1,
  febrero: 2,
  marzo: 3,
  abril: 4,
  mayo: 5,
  junio: 6,
  julio: 7,
  agosto: 8,
  septiembre: 9,
  octubre: 10,
  noviembre: 11,
  diciembre: 12
};

// ==========================================
// NORMALIZAR TEXTO
// ==========================================

function normalize(value) {
  return String(value ?? "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

// ==========================================
// VALIDAR IMPORTE
// ==========================================

function parseAmount(value) {
  let raw = String(value).trim();

  if (!/^\d[\d.,]*$/.test(raw)) {
    throw new Error("Importe invalido");
  }

  if (raw.includes(",") && raw.includes(".")) {
    if (raw.lastIndexOf(",") > raw.lastIndexOf(".")) {
      raw = raw.replace(/\./g, "").replace(",", ".");
    } else {
      raw = raw.replace(/,/g, "");
    }
  } else if (raw.includes(",")) {
    const parts = raw.split(",");

    raw =
      parts.length === 2 && parts[1].length <= 2
        ? raw.replace(",", ".")
        : raw.replace(/,/g, "");
  }

  const amount = Number(raw);

  if (
    !Number.isFinite(amount) ||
    amount <= 0 ||
    !Number.isSafeInteger(Math.round(amount * 100))
  ) {
    throw new Error("Importe invalido");
  }

  return Math.round(amount * 100) / 100;
}

// ==========================================
// VALIDAR FECHA
// ==========================================

function parseDate(body) {
  const match = body.match(
    /Fecha y hora\s+(\d{1,2}) de ([a-z]+) de (\d{4})\s*-\s*(\d{1,2}):(\d{2})\s*(AM|PM)/i
  );

  if (!match) {
    throw new Error("Fecha no encontrada");
  }

  const day = Number(match[1]);
  const month = MONTHS[match[2].toLowerCase()];
  const year = Number(match[3]);
  const hour12 = Number(match[4]);
  const minute = Number(match[5]);

  if (
    !month ||
    year < 2000 ||
    year > 2100 ||
    hour12 < 1 ||
    hour12 > 12 ||
    minute < 0 ||
    minute > 59
  ) {
    throw new Error("Fecha invalida");
  }

  const valid = new Date(
    Date.UTC(year, month - 1, day)
  );

  if (
    valid.getUTCFullYear() !== year ||
    valid.getUTCMonth() !== month - 1 ||
    valid.getUTCDate() !== day
  ) {
    throw new Error("Fecha invalida");
  }

  let hour = hour12 % 12;

  if (match[6].toUpperCase() === "PM") {
    hour += 12;
  }

  // Hora de Peru: UTC-05:00.
  const local =
    `${year}-` +
    `${String(month).padStart(2, "0")}-` +
    `${String(day).padStart(2, "0")}T` +
    `${String(hour).padStart(2, "0")}:` +
    `${String(minute).padStart(2, "0")}:00-05:00`;

  const parsed = new Date(local);

  if (Number.isNaN(parsed.getTime())) {
    throw new Error("Fecha invalida");
  }

  return parsed.toISOString();
}

// ==========================================
// VALIDAR COMERCIO
// ==========================================

function parseMerchant(body) {
  // Buscar el campo Empresa y detenerse
  // antes del siguiente campo conocido.
  //
  // El limite evita interpretar
  // "Numero de operacion" como comercio.

  const match = body.match(
    /(?:^|\s)Empresa\s+(.+?)(?=\s+Numero de operacion|\s+No reconoces|\s+Seguimos mejorando|$)/i
  );

  if (!match) {
    throw new Error("Comercio no encontrado");
  }

  const merchant = match[1].trim();

  if (
    !merchant ||
    /^Numero de operacion\b/i.test(merchant) ||
    /^No reconoces\b/i.test(merchant) ||
    /^Seguimos mejorando\b/i.test(merchant)
  ) {
    throw new Error("Comercio no encontrado");
  }

  if (merchant.length > 150) {
    throw new Error("Comercio demasiado largo");
  }

  return merchant;
}

// ==========================================
// DETECTAR CORREO BCP
// ==========================================

function parseBCPEmail(email) {
  const from = normalize(email.from).toLowerCase();

  const subject = normalize(
    email.subject
  ).toLowerCase();

  const body = normalize(email.body);

  const address = from.includes("<")
    ? from.match(/<([^<>]+)>/)?.[1]
    : from;

  if (address !== SENDER) {
    throw new Error("Remitente no reconocido");
  }

  if (!subject.includes(SUBJECT)) {
    throw new Error("Asunto no reconocido");
  }

  if (!/Consumo Tarjeta de Debito/i.test(body)) {
    throw new Error("Operacion no reconocida");
  }

  const amountMatch = body.match(
    /Total del consumo\s*(S\/|US\$|\$)\s*(\d[\d.,]*)/i
  );

  if (!amountMatch) {
    throw new Error("Importe no encontrado");
  }

  const amount = parseAmount(
    amountMatch[2]
  );

  const currency =
    amountMatch[1] === "S/" ? "PEN" : "USD";

  const merchant = parseMerchant(body);

  const transactionDate = parseDate(body);

  return {
    bank: "BCP",
    operation_type: "debit_card_purchase",
    merchant,
    amount,
    currency,
    transaction_date: transactionDate,
    status: "pending",
    gmail_message_id: email.messageId || null
  };
}

// ==========================================
// CORREO FICTICIO
// ==========================================

const VALID_EMAIL = {
  messageId: "bcp-test-001",

  from:
    "BCP Notificaciones <notificaciones@notificacionesbcp.com.pe>",

  subject:
    "Realizaste un consumo con tu Tarjeta de Débito BCP",

  body: `
    Realizaste un consumo de S/ 1.00
    con tu Tarjeta de Débito BCP
    en COMERCIO DE PRUEBA.

    Total del consumo S/ 1.00

    Operación realizada
    Consumo Tarjeta de Débito

    Fecha y hora
    11 de noviembre de 2026 - 08:07 PM

    Empresa
    COMERCIO DE PRUEBA

    Número de operación
    000000
  `
};

// ==========================================
// EJECUTAR PRUEBA INDIVIDUAL
// ==========================================

function runTest(name, email, shouldPass) {
  try {
    const result = parseBCPEmail(email);

    if (!shouldPass) {
      return {
        test: name,
        passed: false,
        error: "Se acepto un correo invalido"
      };
    }

    return {
      test: name,
      passed: true,
      result
    };

  } catch (error) {
    if (shouldPass) {
      return {
        test: name,
        passed: false,
        error: error.message
      };
    }

    return {
      test: name,
      passed: true
    };
  }
}

// ==========================================
// SIETE PRUEBAS
// ==========================================

function runAllTests() {
  const tests = [
    runTest(
      "Consumo valido",
      VALID_EMAIL,
      true
    ),

    runTest(
      "Remitente diferente",
      {
        ...VALID_EMAIL,
        from: "desconocido@example.com"
      },
      false
    ),

    runTest(
      "Asunto incorrecto",
      {
        ...VALID_EMAIL,
        subject: "Promocion bancaria"
      },
      false
    ),

    runTest(
      "Importe inexistente",
      {
        ...VALID_EMAIL,
        body: VALID_EMAIL.body.replace(
          "Total del consumo S/ 1.00",
          "Total del consumo"
        )
      },
      false
    ),

    runTest(
      "Importe cero",
      {
        ...VALID_EMAIL,
        body: VALID_EMAIL.body.replace(
          "Total del consumo S/ 1.00",
          "Total del consumo S/ 0.00"
        )
      },
      false
    ),

    runTest(
      "Fecha invalida",
      {
        ...VALID_EMAIL,
        body: VALID_EMAIL.body.replace(
          "11 de noviembre de 2026",
          "31 de febrero de 2026"
        )
      },
      false
    ),

    runTest(
      "Comercio inexistente",
      {
        ...VALID_EMAIL,
        body: VALID_EMAIL.body.replace(
          "Empresa\n    COMERCIO DE PRUEBA",
          "Empresa\n    "
        )
      },
      false
    )
  ];

  return tests;
}

// ==========================================
// ENDPOINT DE PRUEBAS
// ==========================================

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Allow", "GET");

  if (req.method !== "GET") {
    return res.status(405).json({
      ok: false,
      message: "Metodo no permitido"
    });
  }

  const tests = runAllTests();

  const passed = tests.filter(
    test => test.passed
  ).length;

  const failed = tests.length - passed;

  return res.status(failed === 0 ? 200 : 422).json({
    ok: failed === 0,
    detector: "BCP Debit Card",
    mode: "test",
    total: tests.length,
    passed,
    failed,
    tests,
    saved_to_database: false,
    notification_sent: false
  });
};
