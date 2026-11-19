// NetDiag remote access relay - Cloudflare Worker + one Durable Object.
//
// Browser --HTTPS--> Worker --> Durable Object "home" --WebSocket--> ESP32-S3 (outbound from home)
// The board replays each request against its own web server and streams the exact response back,
// so the remote page is the same page you see at home.
//
// Secrets (set by the GitHub deploy workflow):
//   DEVICE_KEY       the key shown on the board's "Firmware & system" page
//   REMOTE_PASSWORD  the password for this website (12+ characters)
import { DurableObject } from "cloudflare:workers";

const REQUEST_TIMEOUT_MS = 30000;
const MAX_REQUEST_BODY = 32 * 1024;
const MAX_RESPONSE = 2 * 1024 * 1024;
const SESSION_HOURS = 12;
const MAX_FAILS = 5;
const LOCK_MINUTES = 15;
const enc = new TextEncoder();
const dec = new TextDecoder();

export default {
  async fetch(request, env) {
    if (!env.DEVICE_KEY || env.DEVICE_KEY.length < 32 || !env.REMOTE_PASSWORD || env.REMOTE_PASSWORD.length < 12)
      return page(500, "Not set up", "Set the NETDIAG_DEVICE_KEY and NETDIAG_REMOTE_PASSWORD (12+ characters) secrets in GitHub, then run the deploy again.");
    const url = new URL(request.url);
    if (url.protocol !== "https:") return Response.redirect("https://" + url.host + url.pathname + url.search, 301);
    const hub = env.HUB.get(env.HUB.idFromName("home"));
    return hub.fetch(request);
  },
};

export class Hub extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.pending = new Map();
    this.ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS fails (ip TEXT PRIMARY KEY, n INTEGER, until INTEGER)");
  }

  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (path === "/_device") return this.deviceConnect(request);
    if (path === "/favicon.ico") return new Response(null, { status: 204 });
    if (path === "/_login") return this.login(request, url);
    if (path === "/_logout")
      return new Response(null, { status: 303, headers: { Location: "/_login", "Set-Cookie": cookie("", 0), ...SECURITY } });
    if (!(await this.validSession(request))) {
      if (request.method === "GET") return redirect("/_login?next=" + encodeURIComponent(path + url.search));
      return redirect("/_login");
    }
    if (path === "/_status") return this.status();
    return this.relay(request, url);
  }

  // ---------------------------------------------------------------- device side
  async deviceConnect(request) {
    if (request.headers.get("Upgrade") !== "websocket") return new Response("Expected WebSocket", { status: 426 });
    const auth = request.headers.get("Authorization") || "";
    if (!auth.startsWith("Bearer ") || !(await safeEqual(auth.slice(7), this.env.DEVICE_KEY)))
      return new Response("Unauthorized", { status: 401 });
    for (const old of this.ctx.getWebSockets()) {
      try { old.close(1000, "replaced by a new connection"); } catch {}
    }
    const pair = new WebSocketPair();
    this.ctx.acceptWebSocket(pair[1]);
    this.ctx.storage.put({ since: Date.now(), fw: (request.headers.get("X-NetDiag-FW") || "?").slice(0, 16) });
    return new Response(null, { status: 101, webSocket: pair[0] });
  }

  device() {
    const all = this.ctx.getWebSockets();
    return all.length ? all[all.length - 1] : null;
  }

  async webSocketMessage(ws, message) {
    if (typeof message === "string") return;
    const b = new Uint8Array(message);
    if (b.length < 9) return;
    const type = String.fromCharCode(b[0]);
    const id = dec.decode(b.subarray(1, 9));
    const p = this.pending.get(id);
    if (!p) return; // late answer after a timeout, or a duplicate: ignore
    const data = b.subarray(9);
    if (type === "H") {
      const lines = dec.decode(data).split("\n");
      p.status = parseInt(lines[0], 10) || 502;
      for (const l of lines.slice(1)) {
        const i = l.indexOf(":");
        if (i > 0) p.headers.push([l.slice(0, i).trim(), l.slice(i + 1).trim()]);
      }
    } else if (type === "B") {
      p.size += data.length;
      if (p.size > MAX_RESPONSE) return this.finish(id, page(502, "Too large", "The page from the board was too large."));
      p.chunks.push(data.slice());
    } else if (type === "E") {
      this.finish(id, buildResponse(p));
    }
  }

  async webSocketClose(ws, code, reason) {
    try { ws.close(code, "bye"); } catch {}
    await this.ctx.storage.put("lastSeen", Date.now());
    if (!this.device()) for (const id of [...this.pending.keys()]) this.finish(id, offline(Date.now()));
  }

  async webSocketError(ws) {
    await this.webSocketClose(ws, 1011, "error");
  }

  finish(id, response) {
    const p = this.pending.get(id);
    if (!p) return;
    this.pending.delete(id);
    clearTimeout(p.timer);
    p.resolve(response);
  }

  // ---------------------------------------------------------------- browser side
  async relay(request, url) {
    const ws = this.device();
    if (!ws) return offline(await this.ctx.storage.get("lastSeen"));
    const method = request.method === "HEAD" ? "HEAD" : request.method;
    if (!["GET", "POST", "HEAD"].includes(method)) return page(405, "Not allowed", "Only GET and POST are supported.");
    let body = new Uint8Array(0);
    if (method === "POST") {
      body = new Uint8Array(await request.arrayBuffer());
      if (body.length > MAX_REQUEST_BODY) return page(413, "Too large", "Firmware files can only be uploaded on the home network.");
    }
    const clean = (v) => (v || "").replace(/[\r\n]/g, "").slice(0, 512);
    const head = enc.encode(
      `${method}\n${clean(url.pathname + url.search)}\n${clean(request.headers.get("Authorization"))}\n${clean(request.headers.get("Content-Type"))}\n`
    );
    const id = randomId();
    const frame = new Uint8Array(9 + head.length + body.length);
    frame[0] = 81; // 'Q'
    frame.set(enc.encode(id), 1);
    frame.set(head, 9);
    frame.set(body, 9 + head.length);

    const result = new Promise((resolve) => {
      const timer = setTimeout(
        () => this.finish(id, page(504, "No answer", "The board did not answer in time. It may be busy scanning - try again.")),
        REQUEST_TIMEOUT_MS
      );
      this.pending.set(id, { resolve, timer, status: 502, headers: [], chunks: [], size: 0 });
    });
    try {
      ws.send(frame);
    } catch {
      this.finish(id, offline(Date.now()));
    }
    return result;
  }

  async status() {
    const [since, fw, lastSeen] = await Promise.all(["since", "fw", "lastSeen"].map((k) => this.ctx.storage.get(k)));
    return new Response(JSON.stringify({ online: !!this.device(), since, fw, lastSeen }), {
      headers: { "Content-Type": "application/json", ...SECURITY },
    });
  }

  // ---------------------------------------------------------------- login
  async login(request, url) {
    const next = safeNext(url.searchParams.get("next"));
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const now = Date.now();
    const row = this.ctx.storage.sql.exec("SELECT n, until FROM fails WHERE ip = ?", ip).toArray()[0];
    if (row && row.until > now) {
      const mins = Math.ceil((row.until - now) / 60000);
      return loginPage(next, `Too many wrong passwords. Try again in ${mins} minute${mins > 1 ? "s" : ""}.`, 429);
    }
    if (request.method !== "POST") return loginPage(next, "");
    const form = await request.formData();
    const ok = await safeEqual(String(form.get("password") || ""), this.env.REMOTE_PASSWORD);
    if (!ok) {
      const n = (row ? row.n : 0) + 1;
      const until = n >= MAX_FAILS ? now + LOCK_MINUTES * 60000 : 0;
      this.ctx.storage.sql.exec(
        "INSERT INTO fails (ip, n, until) VALUES (?, ?, ?) ON CONFLICT(ip) DO UPDATE SET n = excluded.n, until = excluded.until",
        ip, n >= MAX_FAILS ? 0 : n, until
      );
      return loginPage(next, "Wrong password.", 401);
    }
    this.ctx.storage.sql.exec("DELETE FROM fails WHERE ip = ?", ip);
    const exp = now + SESSION_HOURS * 3600000;
    const token = `${exp}.${await this.sign(String(exp))}`;
    return new Response(null, { status: 303, headers: { Location: next, "Set-Cookie": cookie(token, SESSION_HOURS * 3600), ...SECURITY } });
  }

  async validSession(request) {
    const m = (request.headers.get("Cookie") || "").match(/(?:^|;\s*)nd_s=([0-9]+)\.([0-9a-f]{64})/);
    if (!m || Number(m[1]) < Date.now()) return false;
    return safeEqual(m[2], await this.sign(m[1]));
  }

  // session signing key is derived from both secrets: changing either one logs everyone out
  async sign(text) {
    const key = await crypto.subtle.importKey(
      "raw", enc.encode(`${this.env.DEVICE_KEY}|session|${this.env.REMOTE_PASSWORD}`),
      { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
    );
    return hex(await crypto.subtle.sign("HMAC", key, enc.encode(text)));
  }
}

// -------------------------------------------------------------------- helpers
const SECURITY = {
  "Cache-Control": "no-store",
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Strict-Transport-Security": "max-age=31536000",
};

const PASS_HEADERS = ["content-type", "location", "www-authenticate", "content-disposition", "refresh"];

function buildResponse(p) {
  const h = new Headers(SECURITY);
  for (const [k, v] of p.headers) {
    const lk = k.toLowerCase();
    if (!PASS_HEADERS.includes(lk)) continue;
    if (lk === "location" && !(v.startsWith("/") && !v.startsWith("//"))) continue; // stay on this site
    try { h.set(k, v); } catch {}
  }
  const body = new Uint8Array(p.size);
  let o = 0;
  for (const c of p.chunks) { body.set(c, o); o += c.length; }
  const nullBody = [101, 204, 205, 304].includes(p.status);
  return new Response(nullBody ? null : body, { status: p.status, headers: h });
}

function cookie(value, maxAge) {
  return `nd_s=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;
}

function redirect(to) {
  return new Response(null, { status: 303, headers: { Location: to, ...SECURITY } });
}

function safeNext(n) {
  return n && n.startsWith("/") && !n.startsWith("//") && !n.startsWith("/_") ? n : "/";
}

function randomId() {
  return hex(crypto.getRandomValues(new Uint8Array(4)));
}

function hex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// constant-time compare of any two strings (hash first so lengths always match)
async function safeEqual(a, b) {
  const [x, y] = await Promise.all([a, b].map((s) => crypto.subtle.digest("SHA-256", enc.encode(s))));
  return crypto.subtle.timingSafeEqual(x, y);
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

const STYLE =
  "body{font-family:sans-serif;margin:0;background:#f4f4f4;display:flex;min-height:100vh;align-items:center;justify-content:center}" +
  ".c{background:#fff;border:1px solid #ccc;border-radius:8px;padding:20px;width:min(340px,90vw)}" +
  "input{width:100%;box-sizing:border-box;padding:10px;margin:8px 0;font-size:16px}" +
  "button{padding:10px 14px;width:100%;font-size:16px;background:#0b2a6b;color:#fff;border:0;border-radius:6px}" +
  ".e{background:#fde2e2;padding:8px;border-radius:4px}";

function page(status, title, text) {
  return new Response(
    `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><style>${STYLE}</style></head>` +
      `<body><div class="c"><h3>NetDiag remote</h3><p><b>${esc(title)}</b></p><p>${esc(text)}</p><p><a href="/">Try again</a></p></div></body></html>`,
    { status, headers: { "Content-Type": "text/html; charset=utf-8", ...SECURITY } }
  );
}

function offline(lastSeen) {
  const when = lastSeen ? ` Last seen ${new Date(lastSeen).toISOString().replace("T", " ").slice(0, 16)} UTC.` : "";
  return page(503, "Board offline", "The board is not connected right now. Check its power and home Wi-Fi." + when);
}

function loginPage(next, error, status = 200) {
  return new Response(
    `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NetDiag remote</title><style>${STYLE}</style></head>` +
      `<body><form class="c" method="post" action="/_login?next=${encodeURIComponent(next)}"><h3>NetDiag remote</h3>` +
      (error ? `<p class="e">${esc(error)}</p>` : "") +
      `<input type="password" name="password" placeholder="Remote password" autocomplete="current-password" required autofocus>` +
      `<button>Sign in</button></form></body></html>`,
    { status, headers: { "Content-Type": "text/html; charset=utf-8", ...SECURITY } }
  );
}
