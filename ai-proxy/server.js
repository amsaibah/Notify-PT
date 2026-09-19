import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import fetch from "node-fetch";

dotenv.config();

const app = express();

function nowIso() {
  return new Date().toISOString();
}

function makeReqId() {
  return Math.random().toString(16).slice(2) + "-" + Date.now().toString(16);
}

function safeJson(obj, max = 900) {
  try {
    const s = JSON.stringify(obj);
    return s.length > max ? s.slice(0, max) + "…" : s;
  } catch {
    return "(unserializable)";
  }
}

app.use(cors({
  origin: true,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "x-extension-token"],
  maxAge: 86400
}));
app.use(express.json());

// Basic request logging (helps confirm the extension is calling the proxy)
app.use((req, res, next) => {
  const rid = makeReqId();
  req._rid = rid;
  const start = Date.now();

  res.on("finish", () => {
    const ms = Date.now() - start;
    console.log(
      `[${nowIso()}] [${rid}] ${req.method} ${req.originalUrl} -> ${res.statusCode} (${ms}ms)`
    );
  });

  next();
});

/**
 * HEALTH CHECK
 */
app.get("/", (req, res) => {
  res.send("AI Proxy running...");
});

/**
 * 🔥 SCAN ENDPOINT (Extension will call this)
 */
app.post("/scan", async (req, res) => {

  const rid = req._rid || "no-rid";

  // simple extension protection
  if (req.headers["x-extension-token"] !== "blue-team-ploy") {
    console.warn(`[${nowIso()}] [${rid}] Forbidden: bad x-extension-token`);
    return res.status(403).send("Forbidden");
  }

  try {

    if (!process.env.GEMINI_API_KEY) {
      console.warn(`[${nowIso()}] [${rid}] Missing GEMINI_API_KEY in .env`);
      return res.status(500).json({
        explanation: "Missing GEMINI_API_KEY in .env"
      });
    }

    const { summary } = req.body;

    const host = summary?.page?.hostname || "unknown";
    const level = summary?.assessment?.level || "unknown";
    const score = summary?.assessment?.score;
    console.log(`[${nowIso()}] [${rid}] /scan host=${host} level=${level} score=${score ?? "—"}`);

    const prompt = `
You are a cybersecurity analyst.

Explain the phishing/security risk in 1-2 sentences and give 2 safety tips.

Signals:
${JSON.stringify(summary)}
`;

    const primaryModel = (process.env.GEMINI_MODEL || "gemini-2.5-flash-lite").trim();
    const modelsToTry = [primaryModel, "gemini-2.5-flash-lite"].filter((m, i, a) => m && a.indexOf(m) === i);

    const body = {
      contents: [{
        parts: [{ text: prompt }]
      }]
    };

    let lastErr = "";
    let data = null;
    for (const model of modelsToTry) {
      const t0 = Date.now();
      console.log(`[${nowIso()}] [${rid}] Gemini request model=${model}`);
      const response = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${process.env.GEMINI_API_KEY}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(body),
        }
      );

      const elapsed = Date.now() - t0;
      console.log(`[${nowIso()}] [${rid}] Gemini response model=${model} status=${response.status} (${elapsed}ms)`);

      if (response.ok) {
        data = await response.json().catch(() => ({}));
        break;
      }

      const errText = await response.text().catch(() => "");
      lastErr = `Gemini error ${response.status} (${model}): ${errText.slice(0, 500)}`;
      console.warn(`[${nowIso()}] [${rid}] ${lastErr}`);
    }

    if (!data) {
      return res.status(502).json({
        explanation: lastErr || "Gemini request failed."
      });
    }

    const text =
      data?.candidates?.[0]?.content?.parts?.[0]?.text || "No AI response.";

    res.json({
      explanation: text
    });

  } catch (err) {

    console.error(`[${nowIso()}] [${rid}] SCAN ERROR:`, err);
    try {
      console.error(`[${nowIso()}] [${rid}] Body summary:`, safeJson(req.body?.summary));
    } catch {
      // ignore
    }

    res.status(500).json({
      explanation: "AI analysis failed."
    });
  }
});

app.listen(3000, () => {
  const model = (process.env.GEMINI_MODEL || "gemini-2.5-flash-lite").trim();
  console.log("🔥 AI Proxy running on http://localhost:3000");
  console.log(`[${nowIso()}] Config: GEMINI_MODEL=${model} GEMINI_API_KEY=${process.env.GEMINI_API_KEY ? "(set)" : "(missing)"}`);
});

process.on("unhandledRejection", (reason) => {
  console.error(`[${nowIso()}] UnhandledRejection:`, reason);
});

process.on("uncaughtException", (err) => {
  console.error(`[${nowIso()}] UncaughtException:`, err);
});
