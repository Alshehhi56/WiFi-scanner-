// Remote access relay - see remote.h.
//
// Wire format on the WebSocket (binary frames, 1 type byte + 8 byte request id + payload):
//   Worker -> board  'Q' id  "METHOD\nPATH\nAUTHORIZATION\nCONTENT-TYPE\n" + body
//   board -> Worker  'H' id  "STATUS\nHeader: value\n..."   (response head)
//                    'B' id  body bytes (up to 4 KB per frame, any number of frames)
//                    'E' id  end of response
#include "remote.h"
#include <WiFi.h>
#include <Preferences.h>
#include "sdkconfig.h"
#include "esp_tls.h"
#include "esp_crt_bundle.h"
#include "esp_random.h"
#include "mbedtls/base64.h"
#include <sys/socket.h>

#if !CONFIG_LWIP_NETIF_LOOPBACK
#error "Remote relay needs lwIP loopback (CONFIG_LWIP_NETIF_LOOPBACK) to reach the local web server"
#endif


static const size_t MAX_IN_FRAME = 40 * 1024;    // request + body from the Worker
static const size_t BODY_CHUNK = 4096;           // response body bytes per frame
static const uint32_t PING_EVERY_MS = 30000;
static const uint32_t DEAD_AFTER_MS = 95000;     // no frames at all -> reconnect
static const uint32_t LOCAL_TIMEOUT_MS = 25000;  // local page must answer within this

static Preferences rprefs;
static SemaphoreHandle_t rmux = nullptr;
static bool rOn = false;
static String rHost, rKey, rState = "Off";
static volatile bool rReconfig = false;
static String rFw = "?";
static esp_tls_t *tls = nullptr;
static int tlsFd = -1;

// ------------------------------------------------------------ settings + status
static void setState(const String &s) {
  xSemaphoreTake(rmux, portMAX_DELAY);
  if (rState != s) Serial.printf("> remote: %s\n", s.c_str());
  rState = s;
  xSemaphoreGive(rmux);
}

String remoteStatus() {
  if (!rmux) return "Off";
  xSemaphoreTake(rmux, portMAX_DELAY);
  String s = rState;
  xSemaphoreGive(rmux);
  return s;
}

bool remoteEnabled() { return rOn; }
static String locked(const String &v) {
  if (!rmux) return v;
  xSemaphoreTake(rmux, portMAX_DELAY);
  String c = v;
  xSemaphoreGive(rmux);
  return c;
}
String remoteHost() { return locked(rHost); }
String remoteKey() { return locked(rKey); }

static String cleanHost(String h) {
  h.trim();
  h.toLowerCase();
  if (h.startsWith("https://")) h = h.substring(8);
  if (h.startsWith("http://")) h = h.substring(7);
  int sl = h.indexOf('/');
  if (sl >= 0) h = h.substring(0, sl);
  String o;
  for (size_t i = 0; i < h.length() && o.length() < 100; i++) {
    char c = h[i];
    if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-') o += c;
  }
  return o;
}

String remoteNewKey() {
  uint8_t raw[32];
  esp_fill_random(raw, sizeof raw);
  unsigned char out[64];
  size_t n = 0;
  mbedtls_base64_encode(out, sizeof out, &n, raw, sizeof raw);
  String k;
  for (size_t i = 0; i < n; i++) {  // base64url, no padding: safe to paste anywhere
    char c = out[i];
    if (c == '+') c = '-';
    else if (c == '/') c = '_';
    else if (c == '=') continue;
    k += c;
  }
  xSemaphoreTake(rmux, portMAX_DELAY);
  rKey = k;
  xSemaphoreGive(rmux);
  rprefs.putString("key", k);
  rReconfig = true;
  return k;
}

static void startTask();

void remoteSet(bool enabled, const String &host) {
  String h = cleanHost(host);
  xSemaphoreTake(rmux, portMAX_DELAY);
  rOn = enabled;
  rHost = h;
  xSemaphoreGive(rmux);
  rprefs.putBool("on", rOn);
  rprefs.putString("host", h);
  if (rOn && rKey.length() < 32) remoteNewKey();
  rReconfig = true;
  if (rOn) startTask();
}

// ------------------------------------------------------------ TLS helpers
static void tlsClose() {
  if (tls) esp_tls_conn_destroy(tls);
  tls = nullptr;
  tlsFd = -1;
}

static bool tlsWriteAll(const uint8_t *p, size_t n) {
  uint32_t t0 = millis();
  while (n) {
    ssize_t w = esp_tls_conn_write(tls, p, n);
    if (w > 0) { p += w; n -= w; continue; }
    if (w == ESP_TLS_ERR_SSL_WANT_WRITE || w == ESP_TLS_ERR_SSL_WANT_READ) {
      if (millis() - t0 > 15000) return false;
      vTaskDelay(pdMS_TO_TICKS(5));
      continue;
    }
    return false;
  }
  return true;
}

// waits up to ms for readable data; true if a read should be attempted
static bool tlsWaitReadable(uint32_t ms) {
  if (esp_tls_get_bytes_avail(tls) > 0) return true;
  fd_set rs;
  FD_ZERO(&rs);
  FD_SET(tlsFd, &rs);
  struct timeval tv = {(time_t)(ms / 1000), (suseconds_t)((ms % 1000) * 1000)};
  return select(tlsFd + 1, &rs, nullptr, nullptr, &tv) > 0;
}

// reads exactly n bytes; -1 on error/close, 0 on timeout before the first byte (if allowIdle)
static int tlsReadExact(uint8_t *p, size_t n, uint32_t ms) {
  size_t got = 0;
  uint32_t t0 = millis();
  while (got < n) {
    if (millis() - t0 > ms) return -1;
    if (!tlsWaitReadable(250)) continue;
    ssize_t r = esp_tls_conn_read(tls, p + got, n - got);
    if (r > 0) { got += r; continue; }
    if (r == ESP_TLS_ERR_SSL_WANT_READ || r == ESP_TLS_ERR_SSL_WANT_WRITE) continue;
    return -1;  // 0 = closed by server, <0 = error
  }
  return (int)got;
}

// ------------------------------------------------------------ WebSocket framing (client side, masked)
static uint8_t *txBuf = nullptr;

static bool wsSend(uint8_t opcode, const uint8_t *a, size_t an, const uint8_t *b = nullptr, size_t bn = 0) {
  size_t n = an + bn;
  uint8_t hdr[14];
  size_t h = 0;
  hdr[h++] = 0x80 | opcode;
  if (n < 126) hdr[h++] = 0x80 | n;
  else if (n < 65536) { hdr[h++] = 0x80 | 126; hdr[h++] = n >> 8; hdr[h++] = n & 0xff; }
  else { hdr[h++] = 0x80 | 127; for (int i = 7; i >= 0; i--) hdr[h++] = (i < 4) ? (n >> (8 * i)) & 0xff : 0; }
  uint8_t mask[4];
  esp_fill_random(mask, 4);
  memcpy(hdr + h, mask, 4);
  h += 4;
  if (!tlsWriteAll(hdr, h)) return false;
  size_t pos = 0;  // mask payload through txBuf in slices
  while (pos < n) {
    size_t m = min((size_t)1024, n - pos);
    for (size_t i = 0; i < m; i++) {
      size_t k = pos + i;
      uint8_t c = k < an ? a[k] : b[k - an];
      txBuf[i] = c ^ mask[k & 3];
    }
    if (!tlsWriteAll(txBuf, m)) return false;
    pos += m;
  }
  return true;
}

static bool sendTyped(char type, const char *id, const uint8_t *p, size_t n) {
  uint8_t pre[9];
  pre[0] = (uint8_t)type;
  memcpy(pre + 1, id, 8);
  if (n == 0) return wsSend(0x2, pre, 9);
  // pre + payload in one frame without copying the payload
  return wsSend(0x2, pre, 9, p, n);
}

// ------------------------------------------------------------ connect + handshake
static String lastErr, cHost, cKey;  // cHost/cKey: snapshot used by the task

static bool wsConnect() {
  tlsClose();
  tls = esp_tls_init();
  if (!tls) { lastErr = "no memory for TLS"; return false; }
  esp_tls_cfg_t cfg = {};
  cfg.crt_bundle_attach = esp_crt_bundle_attach;  // same trusted roots as OTA
  cfg.timeout_ms = 12000;
  if (esp_tls_conn_new_sync(cHost.c_str(), cHost.length(), 443, &cfg, tls) != 1) {
    lastErr = "cannot reach " + cHost + " (DNS, internet or certificate)";
    tlsClose();
    return false;
  }
  esp_tls_get_conn_sockfd(tls, &tlsFd);

  uint8_t nonce[16], b64[32];
  esp_fill_random(nonce, sizeof nonce);
  size_t bn = 0;
  mbedtls_base64_encode(b64, sizeof b64, &bn, nonce, sizeof nonce);
  String req = "GET /_device HTTP/1.1\r\nHost: " + cHost +
               "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " +
               String((const char *)b64).substring(0, bn) + "\r\nAuthorization: Bearer " + cKey +
               "\r\nX-NetDiag-FW: " + rFw + "\r\nUser-Agent: NetDiag\r\n\r\n";
  if (!tlsWriteAll((const uint8_t *)req.c_str(), req.length())) { lastErr = "send failed"; tlsClose(); return false; }

  String resp;  // read the HTTP response head byte by byte (small, once per connection)
  uint8_t c;
  while (resp.length() < 2048 && !resp.endsWith("\r\n\r\n")) {
    if (tlsReadExact(&c, 1, 10000) != 1) { lastErr = "no answer from Worker"; tlsClose(); return false; }
    resp += (char)c;
  }
  if (!resp.startsWith("HTTP/1.1 101")) {
    String line = resp.substring(0, resp.indexOf('\r'));
    if (line.indexOf("401") > 0 || line.indexOf("403") > 0) lastErr = "Worker rejected the device key";
    else lastErr = "Worker answered: " + line;
    tlsClose();
    return false;
  }
  return true;
}

// ------------------------------------------------------------ replay one request locally
static char seen[16][9];
static int seenPos = 0;

static bool alreadySeen(const char *id) {
  for (auto &s : seen)
    if (!memcmp(s, id, 8)) return true;
  memcpy(seen[seenPos], id, 8);
  seen[seenPos][8] = 0;
  seenPos = (seenPos + 1) % 16;
  return false;
}

static bool replyText(const char *id, int status, const String &text) {
  String head = String(status) + "\nContent-Type: text/plain; charset=utf-8\n";
  return sendTyped('H', id, (const uint8_t *)head.c_str(), head.length()) &&
         sendTyped('B', id, (const uint8_t *)text.c_str(), text.length()) && sendTyped('E', id, nullptr, 0);
}

static bool handleRequest(const uint8_t *p, size_t n) {
  if (n < 9) return true;
  char id[9];
  memcpy(id, p + 1, 8);
  id[8] = 0;
  if (alreadySeen(id)) return true;  // duplicate delivery: never run a command twice

  // parse the 4 header lines
  String f[4];
  size_t pos = 9;
  for (int i = 0; i < 4; i++) {
    size_t s = pos;
    while (pos < n && p[pos] != '\n') pos++;
    if (pos >= n) return replyText(id, 400, "Bad relay request");
    f[i] = "";
    f[i].concat((const char *)p + s, pos - s);
    pos++;
  }
  const uint8_t *body = p + pos;
  size_t bodyLen = n - pos;
  String &method = f[0], &path = f[1];
  if (!(method == "GET" || method == "POST" || method == "HEAD") || !path.startsWith("/"))
    return replyText(id, 400, "Bad relay request");
  for (auto &s : f)
    if (s.indexOf('\r') >= 0) return replyText(id, 400, "Bad relay request");
  if (method == "POST" && (path == "/update" || path.startsWith("/update?")))
    return replyText(id, 403, "Uploading a firmware file is only possible on the local network.\n"
                              "Use 'Install update' (from GitHub) instead - it works remotely.");

  WiFiClient c;
  if (!c.connect(IPAddress(127, 0, 0, 1), 80, 3000)) return replyText(id, 502, "Local web server not reachable");
  String rq = method + " " + path + " HTTP/1.1\r\nHost: netdiag.local\r\nConnection: close\r\n";
  if (f[2].length()) rq += "Authorization: " + f[2] + "\r\n";
  if (f[3].length()) rq += "Content-Type: " + f[3] + "\r\n";
  if (method == "POST") rq += "Content-Length: " + String(bodyLen) + "\r\n";
  rq += "\r\n";
  c.write((const uint8_t *)rq.c_str(), rq.length());
  if (bodyLen) c.write(body, bodyLen);

  // response head
  uint32_t t0 = millis();
  c.setTimeout(LOCAL_TIMEOUT_MS / 1000);
  String status = c.readStringUntil('\n');
  int sp = status.indexOf(' ');
  int code = sp > 0 ? status.substring(sp + 1, sp + 4).toInt() : 0;
  if (code < 100) { c.stop(); return replyText(id, 504, "Local page did not answer in time"); }
  String head = String(code) + "\n";
  long clen = -1;
  while (true) {
    String l = c.readStringUntil('\n');
    l.trim();
    if (!l.length()) break;
    int colon = l.indexOf(':');
    if (colon < 1) continue;
    String name = l.substring(0, colon), lname = name;
    lname.toLowerCase();
    if (lname == "content-length") clen = l.substring(colon + 1).toInt();
    if (lname == "content-type" || lname == "location" || lname == "www-authenticate" ||
        lname == "content-disposition" || lname == "refresh")
      head += l + "\n";
    if (millis() - t0 > LOCAL_TIMEOUT_MS) break;
  }
  if (!sendTyped('H', id, (const uint8_t *)head.c_str(), head.length())) { c.stop(); return false; }

  // body, streamed in chunks
  static uint8_t buf[BODY_CHUNK];
  long sent = 0;
  if (method != "HEAD") {
    while (clen < 0 || sent < clen) {
      if (millis() - t0 > LOCAL_TIMEOUT_MS) break;
      int avail = c.available();
      if (avail <= 0) {
        if (!c.connected()) break;
        vTaskDelay(pdMS_TO_TICKS(2));
        continue;
      }
      int r = c.read(buf, min((int)BODY_CHUNK, avail));
      if (r <= 0) continue;
      if (!sendTyped('B', id, buf, r)) { c.stop(); return false; }
      sent += r;
    }
  }
  c.stop();
  return sendTyped('E', id, nullptr, 0);
}

// ------------------------------------------------------------ receive loop
static uint8_t *rxBuf = nullptr;

// one session: returns when the connection is lost or settings changed
static void wsSession() {
  uint32_t lastRx = millis(), lastPing = millis();
  while (!rReconfig && rOn && WiFi.status() == WL_CONNECTED) {
    uint32_t now = millis();
    if (now - lastPing > PING_EVERY_MS) {
      if (!wsSend(0x9, (const uint8_t *)"nd", 2)) { lastErr = "connection lost"; return; }
      lastPing = now;
    }
    if (now - lastRx > DEAD_AFTER_MS) { lastErr = "no reply from Worker"; return; }
    if (!tlsWaitReadable(1000)) continue;

    uint8_t h2[2];
    if (tlsReadExact(h2, 2, 10000) != 2) { lastErr = "connection lost"; return; }
    lastRx = millis();
    uint8_t op = h2[0] & 0x0f;
    bool fin = h2[0] & 0x80, masked = h2[1] & 0x80;
    uint64_t len = h2[1] & 0x7f;
    if (len == 126) {
      uint8_t e[2];
      if (tlsReadExact(e, 2, 10000) != 2) return;
      len = (e[0] << 8) | e[1];
    } else if (len == 127) {
      uint8_t e[8];
      if (tlsReadExact(e, 8, 10000) != 8) return;
      len = 0;
      for (int i = 0; i < 8; i++) len = (len << 8) | e[i];
    }
    uint8_t mk[4] = {0};
    if (masked && tlsReadExact(mk, 4, 10000) != 4) return;
    if (!fin || op == 0 || len > MAX_IN_FRAME) { lastErr = "unexpected frame"; return; }
    if (len && tlsReadExact(rxBuf, len, 20000) != (int)len) { lastErr = "connection lost"; return; }
    if (masked)
      for (uint64_t i = 0; i < len; i++) rxBuf[i] ^= mk[i & 3];

    if (op == 0x9) { if (!wsSend(0xA, rxBuf, len)) return; }    // ping -> pong
    else if (op == 0xA) { /* pong: lastRx already updated */ }
    else if (op == 0x8) { lastErr = "closed by Worker"; return; }
    else if (op == 0x2 && len >= 9 && rxBuf[0] == 'Q') {
      if (!handleRequest(rxBuf, len)) { lastErr = "connection lost while replying"; return; }
    }
  }
}

static void remoteTask(void *) {
  uint32_t backoff = 3000;
  while (true) {
    rReconfig = false;
    xSemaphoreTake(rmux, portMAX_DELAY);
    cHost = rHost;
    cKey = rKey;
    xSemaphoreGive(rmux);
    if (!rOn || !cHost.length() || cKey.length() < 32) {
      setState(rOn ? "Not set up: enter your Worker address" : "Off");
      while (!rReconfig) vTaskDelay(pdMS_TO_TICKS(500));
      continue;
    }
    if (WiFi.status() != WL_CONNECTED) {
      setState("Waiting for home Wi-Fi (local access still works)");
      vTaskDelay(pdMS_TO_TICKS(2000));
      continue;
    }
    setState("Connecting to " + cHost + "...");
    // buffers exist only while a connection is open, so remote access costs no memory when unused
    if (!txBuf) txBuf = (uint8_t *)malloc(1024);
    if (!rxBuf) rxBuf = (uint8_t *)malloc(MAX_IN_FRAME + 1);
    bool mem = txBuf && rxBuf;
    if (!mem) lastErr = "not enough free memory";
    if (mem && wsConnect()) {
      backoff = 3000;
      setState("Connected - reachable at https://" + cHost);
      wsSession();
      // a polite close frame; ignore failures
      if (tls) wsSend(0x8, (const uint8_t *)"\x03\xe8", 2);
      tlsClose();
      free(rxBuf); rxBuf = nullptr;
      free(txBuf); txBuf = nullptr;
      if (rReconfig || !rOn) continue;
    }
    free(rxBuf); rxBuf = nullptr;
    free(txBuf); txBuf = nullptr;
    setState("Offline: " + lastErr + " - retrying in " + String(backoff / 1000) + " s");
    uint32_t until = millis() + backoff;
    while (millis() < until && !rReconfig) vTaskDelay(pdMS_TO_TICKS(250));
    backoff = min(backoff * 2, (uint32_t)60000);
  }
}

void remoteBegin(const char *fwVersion) {
  rFw = fwVersion;
  rmux = xSemaphoreCreateMutex();
  rprefs.begin("remote", false);
  rOn = rprefs.getBool("on", false);
  rHost = rprefs.getString("host", "");
  rKey = rprefs.getString("key", "");
  if (rOn) startTask();  // the task (and its 10 KB stack) only exists once remote access is turned on
}

static void startTask() {
  static bool started = false;
  if (started || !rmux) return;
  started = true;
  xTaskCreatePinnedToCore(remoteTask, "remote", 10240, nullptr, 1, nullptr, 0);
}
