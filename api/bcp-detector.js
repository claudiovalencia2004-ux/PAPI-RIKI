
"use strict";

// ==========================================
// PAPI RIKI - PASO 9.11.2
// DETECTOR BCP + VALIDACION
// ==========================================

// Solo pruebas con datos ficticios.
// No consulta Gmail.
// No escribe en Supabase.
// No envía notificaciones.

const SENDER =
  "notificaciones@notificacionesbcp.com.pe";

const SUBJECT =
  "realizaste un consumo con tu tarjeta de debito bcp";

const MONTHS = {
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

function normalize(value) {
  return String(value ?? "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function parseAmount(value) {
  let raw=String(value).trim();

  if (!/^\d[\d.,]*$/.test(raw)) {
    throw Error("Importe invalido");
  }

  if (raw.includes(",") && raw.includes(".")) {
    if (raw.lastIndexOf(",") > raw.lastIndexOf(".")) {
      raw=raw.replace(/\./g,"").replace(",",".");
    } else {
      raw=raw.replace(/,/g,"");
    }
  } else if (raw.includes(",")) {
    const parts=raw.split(",");
    raw=parts.length===2 && parts[1].length<=2
      ?raw.replace(",",".")
      :raw.replace(/,/g,"");
  }

  const amount=Number(raw);

  if (!Number.isFinite(amount) || amount<=0) {
    throw Error("Importe invalido");
  }

  return Math.round(amount*100)/100;
}

function parseDate(body) {
  const match=body.match(
    /Fecha y hora\s+(\d{1,2}) de ([a-z]+) de (\d{4})\s*-\s*(\d{1,2}):(\d{2})\s*(AM|PM)/i
  );

  if (!match)throw Error("Fecha no encontrada");

  const day=Number(match[1]);
  const month=MONTHS[match[2].toLowerCase()];
  const year=Number(match[3]);
  const hour12=Number(match[4]);
  const minute=Number(match[5]);

  if (!month || hour12<1 || hour12>12 ||
      minute>59 || year<2000) {
    throw Error("Fecha invalida");
  }

  const valid=new Date(Date.UTC(year,month-1,day));

  if (
    valid.getUTCFullYear()!==year ||
    valid.getUTCMonth()!==month-1 ||
    valid.getUTCDate()!==day
  ) {
    throw Error("Fecha invalida");
  }

  let hour=hour12%12;

  if (match[6].toUpperCase()==="PM") {
    hour+=12;
  }

  const local=
    `${year}-${String(month).padStart(2,"0")}-`+
    `${String(day).padStart(2,"0")}T`+
    `${String(hour).padStart(2,"0")}:`+
    `${String(minute).padStart(2,"0")}:00-05:00`;

  return new Date(local).toISOString();
}

function parseBCPEmail(email) {
  const from=normalize(email.from).toLowerCase();
  const subject=normalize(email.subject).toLowerCase();
  const body=normalize(email.body);

  const address=from.includes("<")
    ?from.match(/<([^<>]+)>/)?.[1]
    :from;

  if (address!==SENDER) {
    throw Error("Remitente no reconocido");
  }

  if (!subject.includes(SUBJECT)) {
    throw Error("Asunto no reconocido");
  }

  if (!/Consumo Tarjeta de Debito/i.test(body)) {
    throw Error("Operacion no reconocida");
  }

  const amountMatch=body.match(
    /Total del consumo\s*(S\/|US\$|\$)\s*(\d[\d.,]*)/i
  );

  if (!amountMatch) {
    throw Error("Importe no encontrado");
  }

  const amount=parseAmount(amountMatch[2]);

  const merchantMatch=body.match(
    /Empresa\s+(.+?)(?=\s+Numero de operacion|\s+No reconoces|\s+Seguimos mejorando|$)/i
  );

  if (!merchantMatch || !merchantMatch[1].trim()) {
    throw Error("Comercio no encontrado");
  }

  return {
    bank:"BCP",
    operation_type:"debit_card_purchase",
    merchant:merchantMatch[1].trim(),
    amount,
    currency:amountMatch[1]==="S/"?"PEN":"USD",
    transaction_date:parseDate(body),
    status:"pending",
    gmail_message_id:email.messageId||null
  };
}

// ==========================================
// CORREO FICTICIO DE PRUEBA
// ==========================================

const validEmail={
  messageId:"bcp-test-001",
  from:"BCP Notificaciones <notificaciones@notificacionesbcp.com.pe>",
  subject:"Realizaste un consumo con tu Tarjeta de Débito BCP",
  body:`
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

function runTest(name,email,shouldPass) {
  try {
    const result=parseBCPEmail(email);

    return {
      test:name,
      passed:shouldPass,
      result:shouldPass?result:undefined,
      error:shouldPass?undefined:"Se acepto un correo invalido"
    };

  } catch (error) {
    return {
      test:name,
      passed:!shouldPass,
      error:shouldPass?error.message:undefined
    };
  }
}

module.exports=async function handler(req,res) {
  res.setHeader("Cache-Control","no-store");
  res.setHeader("Allow","GET");

  if(req.method!=="GET") {
    return res.status(405).json({
      ok:false,
      message:"Metodo no permitido"
    });
  }

  const tests=[
    runTest("Consumo valido",validEmail,true),

    runTest("Remitente diferente",{
      ...validEmail,
      from:"desconocido@example.com"
    },false),

    runTest("Asunto incorrecto",{
      ...validEmail,
      subject:"Promocion bancaria"
    },false),

    runTest("Importe inexistente",{
      ...validEmail,
      body:validEmail.body.replace(
        "Total del consumo S/ 1.00",
        "Total del consumo"
      )
    },false),

    runTest("Importe cero",{
      ...validEmail,
      body:validEmail.body.replace(
        "Total del consumo S/ 1.00",
        "Total del consumo S/ 0.00"
      )
    },false),

    runTest("Fecha invalida",{
      ...validEmail,
      body:validEmail.body.replace(
        "11 de noviembre de 2026",
        "31 de febrero de 2026"
      )
    },false),

    runTest("Comercio inexistente",{
      ...validEmail,
      body:validEmail.body.replace(
        "Empresa\n    COMERCIO DE PRUEBA",
        "Empresa\n    "
      )
    },false)
  ];

  const passed=tests.filter(t=>t.passed).length;

  return res.status(passed===tests.length?200:422).json({
    ok:passed===tests.length,
    total:tests.length,
    passed,
    failed:tests.length-passed,
    tests,
    saved_to_database:false,
    notification_sent:false
  });
};
