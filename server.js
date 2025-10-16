import express from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import net from "net";
import path from "path";
import { fileURLToPath } from "url";
import ipaddr from "ipaddr.js";
import dns from "node:dns/promises";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(helmet());
app.disable("x-powered-by");
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const API_KEY = process.env.SCAN_API_KEY || "replace_me_with_strong_key";
const ALLOWLIST = (process.env.ALLOWLIST || "127.0.0.1,localhost,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16").split(",").map(s=>s.trim()).filter(Boolean);
const MAX_PORT_RANGE = 200;
const MAX_CONCURRENCY = 50;
const DEFAULT_TIMEOUT_MS = 2000;

app.use(rateLimit({ windowMs: 60_000, max: 60 }));

function requireApiKey(req, res, next) {
  const k = req.headers["x-api-key"] || req.query.api_key;
  if (!k || k !== API_KEY) {
    return res.status(401).json({ ok: false, error: "Missing/invalid API key" });
  }
  next();
}

function cidrContains(cidr, ipStr) {
  try {
    if (!cidr.includes("/")) return false;
    const [netStr, lenStr] = cidr.split("/");
    const len = parseInt(lenStr, 10);
    const ip = ipaddr.parse(ipStr);
    const net = ipaddr.parse(netStr);
    return ip.match(net, len);
  } catch (e) {
    return false;
  }
}

async function hostAllowedAsync(host) {
  if (!host) return false;
  const trimmed = host.replace(/:\d+$/, "");
  if (ipaddr.isValid(trimmed)) {
    for (const rule of ALLOWLIST) {
      if (rule.includes("/")) {
        if (cidrContains(rule, trimmed)) return true;
      } else if (ipaddr.isValid(rule)) {
        if (trimmed === rule) return true;
      } else if (trimmed === rule) {
        return true;
      }
    }
    return false;
  }
  try {
    const records = await dns.lookup(trimmed, { all: true });
    const addresses = records.map(r => r.address);
    for (const addr of addresses) {
      for (const rule of ALLOWLIST) {
        if (rule.includes("/")) {
          if (cidrContains(rule, addr)) return true;
        } else if (ipaddr.isValid(rule)) {
          if (addr === rule) return true;
        } else if (trimmed === rule) {
          return true;
        }
      }
    }
    return false;
  } catch (e) {
    return false;
  }
}

function checkTcpPort(host, port, timeoutMs = DEFAULT_TIMEOUT_MS) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let resolved = false;

    const onDone = (result) => {
      if (resolved) return;
      resolved = true;
      try { socket.destroy(); } catch (e) {}
      resolve({ host, port, ...result });
    };

    socket.setTimeout(timeoutMs);
    socket.once("connect", () => onDone({ status: "open" }));
    socket.once("timeout", () => onDone({ status: "timeout" }));
    socket.once("error", (err) => {
      if (err && err.code === "ECONNREFUSED") {
        onDone({ status: "closed", error: err.code });
      } else {
        onDone({ status: "error", error: (err && err.code) || String(err) });
      }
    });
    socket.connect(port, host);
  });
}

async function mapWithConcurrency(items, fn, concurrency = 10) {
  const results = [];
  const executing = new Set();
  for (const item of items) {
    const p = (async () => {
      try { return await fn(item); } catch (e) { return { error: String(e) }; }
    })();
    results.push(p);
    executing.add(p);
    p.finally(() => executing.delete(p));
    if (executing.size >= concurrency) {
      await Promise.race(executing);
    }
  }
  return Promise.all(results);
}

app.get("/tcp/check", requireApiKey, async (req, res) => {
  const host = (req.query.host || "").toString().trim();
  const port = Number(req.query.port || 0);
  const timeoutMs = Number(req.query.timeout) || DEFAULT_TIMEOUT_MS;

  if (!host || !port) return res.status(400).json({ ok: false, error: "missing host or port" });
  const allowed = await hostAllowedAsync(host);
  if (!allowed) return res.status(403).json({ ok: false, error: "host not allowed by server policy" });
  if (port < 1 || port > 65535) return res.status(400).json({ ok: false, error: "port out of range" });

  const result = await checkTcpPort(host, port, timeoutMs);
  res.json({ ok: true, result });
});

app.post("/tcp/scan-range", requireApiKey, async (req, res) => {
  const { host, start, end } = req.body || {};
  const timeoutMs = Number(req.body?.timeout) || DEFAULT_TIMEOUT_MS;
  let concurrency = Number(req.body?.concurrency) || Math.min(MAX_CONCURRENCY, 20);

  if (!host || !Number.isInteger(start) || !Number.isInteger(end)) {
    return res.status(400).json({ ok: false, error: "body must include host, start, end (integers)" });
  }

  const allowed = await hostAllowedAsync(host);
  if (!allowed) return res.status(403).json({ ok: false, error: "host not allowed by server policy" });

  const s = Math.max(1, Math.min(65535, start));
  const e = Math.max(1, Math.min(65535, end));
  const min = Math.min(s, e);
  const max = Math.max(s, e);
  const count = max - min + 1;
  if (count > MAX_PORT_RANGE) {
    return res.status(400).json({ ok: false, error: `range too large (${count} ports); max allowed ${MAX_PORT_RANGE}` });
  }
  concurrency = Math.max(1, Math.min(MAX_CONCURRENCY, concurrency));
  const ports = [];
  for (let p = min; p <= max; p++) ports.push(p);

  const results = await mapWithConcurrency(ports, (port) => checkTcpPort(host, port, timeoutMs), concurrency);

  res.json({ ok: true, host, scanned_count: results.length, results });
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "safe_host_port_checker.html"));
});

const PORT = Number(process.env.PORT) || 3000;
app.listen(PORT, () => console.log(`Safe port checker (LAN-enabled) running on http://localhost:${PORT}`));
