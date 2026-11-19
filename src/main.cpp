/*
 * ESP32-S3 Network Diagnostic Tool - Version 2.0 (Wi-Fi diagnostics)
 * Board: ESP32-S3-N16R8, PlatformIO + Arduino framework, serial 115200.
 *
 * What it does each cycle:
 *   1. Runs several full scans of 2.4 GHz channels 1-13 (UAE regulatory set).
 *   2. Aggregates every BSSID: RSSI average / spread / min / max, how many
 *      scans it appeared in, channel, 20/40 MHz width, security, cipher,
 *      802.11b/g/n support and WPS, all read from the AP's beacon data.
 *   3. Groups BSSIDs that are probably the same physical radio
 *      (main + guest SSIDs on one router).
 *   4. Builds an interference estimate for each channel and analyses it.
 *   5. Prints a report: each finding has a severity, a confidence level
 *      (CONFIRMED / LIKELY / POSSIBLE) and a recommended action, plus how
 *      many cycles it has repeated in (persistent vs temporary).
 *
 * Serial commands (type in the terminal, then press Send / Enter):
 *   help                     show commands
 *   scan                     run a cycle now
 *   home SSID1,SSID2         set YOUR networks (stored in flash, not in code)
 *   home -                   clear your networks
 *   rounds N                 scans per cycle (1-10, default 4)
 *   interval S               seconds between cycles (10-3600, default 60)
 *   raw on|off               show/hide the access point table
 *   json on|off              also print a one-line JSON report
 *   reset                    clear persistence history
 *   status                   show settings
 *
 * Limits (stated in every report): a scan only sees beacons. It cannot
 * measure real airtime use, client traffic, or non-Wi-Fi interference
 * (microwaves, Bluetooth, cameras). Interference scores are estimates.
 */

#include <Arduino.h>
#include <WiFi.h>
#include <Preferences.h>
#include <esp_wifi.h>
#include <vector>
#include <map>
#include <algorithm>
#include <math.h>
#include <stdarg.h>
#include <WebServer.h>
#include <ESPmDNS.h>
#include <esp_system.h>
#include <esp_mac.h>
#include <WiFiUdp.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include "ping/ping_sock.h"
#include "lwip/ip_addr.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/dhcp.h"
#include <Update.h>
#include <esp_ota_ops.h>
#include <esp_partition.h>
#include <esp_https_ota.h>
#include <esp_http_client.h>
#include <esp_crt_bundle.h>
#include <mbedtls/sha256.h>
#include "remote.h"
#include "WiFiProv.h"

#define FW_VERSION "3.9.0"
#define DEFAULT_PASS "netdiag123"  // public default; change it with: pass NEWPASSWORD

static const int MAX_CH = 13;    // channels 1..13 allowed in the UAE
static const int MAX_APS = 80;   // BSSIDs kept per cycle
static const int SCAN_MS_PER_CH = 300;
static const float CCA_DBM = -82.0f;  // Wi-Fi preamble-detect threshold

// ------------------------------------------------------------ helpers
static String fmt(const char *f, ...) {
  char buf[256];
  va_list ap;
  va_start(ap, f);
  vsnprintf(buf, sizeof(buf), f, ap);
  va_end(ap);
  return String(buf);
}

static String macStr(const uint8_t *m) {
  return fmt("%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
}

// Manufacturer from the first 3 MAC bytes (OUI). Small common-vendor table,
// focused on home routers/extenders in the region; "?" when not listed.
struct Oui { uint8_t a, b, c; const char *name; };
static const Oui OUI_TABLE[] = {
  // TP-Link
  {0x50,0xC7,0xBF,"TP-Link"},{0xEC,0x08,0x6B,"TP-Link"},{0x60,0x32,0xB1,"TP-Link"},{0xA4,0x2B,0xB0,"TP-Link"},
  {0x14,0xCC,0x20,"TP-Link"},{0x98,0xDA,0xC4,"TP-Link"},{0x1C,0x61,0xB4,"TP-Link"},{0x54,0xAF,0x97,"TP-Link"},
  // D-Link
  {0x1C,0xBD,0xB9,"D-Link"},{0x84,0xC9,0xB2,"D-Link"},{0xC8,0xD3,0xA3,"D-Link"},{0x78,0x54,0x2E,"D-Link"},
  // Netgear
  {0x9C,0xD3,0x6D,"Netgear"},{0xA0,0x40,0xA0,"Netgear"},{0x3C,0x37,0x86,"Netgear"},{0x20,0xE5,0x2A,"Netgear"},
  // Huawei / Honor
  {0x00,0xE0,0xFC,"Huawei"},{0x48,0x62,0x76,"Huawei"},{0x5C,0x7D,0x5E,"Huawei"},{0xD4,0x6A,0xA8,"Huawei"},
  {0xAC,0xE2,0x15,"Huawei"},{0x10,0x47,0x80,"Huawei"},
  // Tenda / Mercury
  {0xC8,0x3A,0x35,"Tenda"},{0x04,0x95,0xE6,"Tenda"},{0xD8,0x32,0x14,"Tenda"},
  // ASUS
  {0x2C,0xFD,0xA1,"ASUS"},{0x04,0xD4,0xC4,"ASUS"},{0x38,0xD5,0x47,"ASUS"},{0xAC,0x9E,0x17,"ASUS"},
  // Xiaomi
  {0x64,0x09,0x80,"Xiaomi"},{0x28,0x6C,0x07,"Xiaomi"},{0xF0,0xB4,0x29,"Xiaomi"},
  // Zyxel / Sagemcom / Technicolor / Arcadyan (ISP boxes)
  {0x5C,0xE2,0x8C,"Zyxel"},{0xA0,0xE4,0x53,"Zyxel"},{0x44,0xD4,0x37,"Sagemcom"},{0x98,0x2C,0xBE,"Technicolor"},
  {0x7C,0x26,0x64,"Technicolor"},{0x88,0x03,0x55,"Arcadyan"},
  // Ubiquiti, Linksys, Realtek
  {0x24,0xA4,0x3C,"Ubiquiti"},{0xFC,0xEC,0xDA,"Ubiquiti"},{0x48,0xF8,0xB3,"Linksys"},{0x00,0xE0,0x4C,"Realtek"},
  // Espressif (NetDiag itself / ESP devices)
  {0x7C,0xDF,0xA1,"Espressif"},{0x24,0x6F,0x28,"Espressif"},{0x34,0x85,0x18,"Espressif"},{0xF4,0x12,0xFA,"Espressif"},
};
static String vendorFromMac(const uint8_t *m) {
  for (auto &o : OUI_TABLE)
    if (o.a == m[0] && o.b == m[1] && o.c == m[2]) return String(o.name);
  return String("?");
}

// ------------------------------------------------------------ settings
struct Settings {
  String home;          // comma separated list of your own SSIDs
  uint8_t rounds = 4;
  uint16_t intervalS = 60;
  bool raw = true;
  bool json = false;
  String staSsid, staPass;  // your Wi-Fi (stored in flash only)
  String adminPass;         // web login + hotspot password
  bool customPass = false;  // true once you set your own password
  uint8_t apMode = 2;       // hotspot: 0 always on, 1 only when Wi-Fi is lost, 2 off (Bluetooth backup)
} cfg;

// saved Wi-Fi networks (v3.9): the board joins the strongest one in range
struct SavedNet { String ssid, pass; };
static const int MAX_NETS = 5;
std::vector<SavedNet> nets;
std::vector<std::pair<String, int>> seenNets;  // SSIDs from the last scan (best RSSI), for the picker

Preferences prefs;
std::vector<String> homeList;

static void parseHomeList() {
  homeList.clear();
  String s = cfg.home;
  int start = 0;
  while (start <= (int)s.length()) {
    int comma = s.indexOf(',', start);
    if (comma < 0) comma = s.length();
    String item = s.substring(start, comma);
    item.trim();
    if (item.length()) homeList.push_back(item);
    start = comma + 1;
  }
}

static bool isHome(const String &ssid) {
  if (ssid.length() == 0) return false;
  for (auto &h : homeList)
    if (h == ssid) return true;
  return false;
}

static void loadSettings() {
  prefs.begin("netdiag", false);
  cfg.home = prefs.getString("home", "");
  cfg.rounds = prefs.getUChar("rounds", 4);
  cfg.intervalS = prefs.getUShort("interval", 60);
  cfg.raw = prefs.getBool("raw", true);
  cfg.json = prefs.getBool("json", false);
  cfg.staSsid = prefs.getString("stassid", "");
  cfg.staPass = prefs.getString("stapass", "");
  cfg.adminPass = prefs.getString("admin", "");
  cfg.customPass = prefs.getBool("custompw", false);
  cfg.apMode = prefs.getUChar("apmode", 2);
  if (cfg.apMode > 2) cfg.apMode = 2;
  nets.clear();
  for (int i = 0; i < MAX_NETS; i++) {
    String ss = prefs.getString(("n" + String(i) + "s").c_str(), "");
    if (ss.length()) nets.push_back({ss, prefs.getString(("n" + String(i) + "p").c_str(), "")});
  }
  if (nets.empty() && cfg.staSsid.length()) nets.push_back({cfg.staSsid, cfg.staPass});  // migrate v3.8
  if (cfg.rounds < 1 || cfg.rounds > 10) cfg.rounds = 4;
  if (cfg.intervalS < 10 || cfg.intervalS > 3600) cfg.intervalS = 60;
  parseHomeList();
}

static void saveSettings() {
  prefs.putString("home", cfg.home);
  prefs.putUChar("rounds", cfg.rounds);
  prefs.putUShort("interval", cfg.intervalS);
  prefs.putBool("raw", cfg.raw);
  prefs.putBool("json", cfg.json);
  prefs.putString("stassid", cfg.staSsid);
  prefs.putString("stapass", cfg.staPass);
  prefs.putString("admin", cfg.adminPass);
  prefs.putBool("custompw", cfg.customPass);
  prefs.putUChar("apmode", cfg.apMode);
  for (int i = 0; i < MAX_NETS; i++) {
    prefs.putString(("n" + String(i) + "s").c_str(), i < (int)nets.size() ? nets[i].ssid : String(""));
    prefs.putString(("n" + String(i) + "p").c_str(), i < (int)nets.size() ? nets[i].pass : String(""));
  }
}

// adds or updates a network and moves it to the top of the list
static void rememberNet(const String &ssid, const String &pass) {
  for (size_t i = 0; i < nets.size(); i++)
    if (nets[i].ssid == ssid) { nets.erase(nets.begin() + i); break; }
  nets.insert(nets.begin(), {ssid, pass});
  if ((int)nets.size() > MAX_NETS) nets.pop_back();
}

// ------------------------------------------------------------ status LED
#if defined(RGB_BUILTIN)
static void led(uint8_t r, uint8_t g, uint8_t b) {
#if defined(ESP_ARDUINO_VERSION_MAJOR) && ESP_ARDUINO_VERSION_MAJOR >= 3
  rgbLedWrite(RGB_BUILTIN, r, g, b);
#else
  neopixelWrite(RGB_BUILTIN, r, g, b);
#endif
}
#else
static void led(uint8_t, uint8_t, uint8_t) {}
#endif

// ------------------------------------------------------------ scan data
struct ApObs {
  String ssid;
  uint8_t bssid[6] = {0};
  uint8_t ch = 0;
  uint8_t second = 0;  // 0 = 20 MHz, 1 = 40 MHz above, 2 = 40 MHz below
  wifi_auth_mode_t auth = WIFI_AUTH_OPEN;
  wifi_cipher_type_t pair = WIFI_CIPHER_TYPE_NONE;
  bool b = false, g = false, n = false, wps = false;
  bool chChangedInCycle = false;
  int seen = 0;
  float sum = 0, sumSq = 0;
  int minR = 0, maxR = -127;
  int radio = -1;

  float avg() const { return seen ? sum / seen : -127; }
  float sd() const {
    if (seen < 2) return 0;
    float m = avg();
    float v = sumSq / seen - m * m;
    return v > 0 ? sqrtf(v) : 0;
  }
  bool hidden() const { return ssid.length() == 0; }
};

struct Radio {
  std::vector<int> aps;  // indexes into aps
  uint8_t ch = 0;
  uint8_t second = 0;
  float rssi = -127;     // strongest average among its BSSIDs
  bool home = false;
};

std::vector<ApObs> aps;
std::vector<Radio> radios;
int roundsDone = 0;
uint32_t cycleNo = 0;
std::map<String, uint8_t> lastChannel;  // BSSID -> channel seen last cycle

static int findAp(const uint8_t *bssid) {
  for (size_t i = 0; i < aps.size(); i++)
    if (memcmp(aps[i].bssid, bssid, 6) == 0) return (int)i;
  return -1;
}

static bool scanRound() {
  int n = WiFi.scanNetworks(false, true, false, SCAN_MS_PER_CH);
  if (n < 0) {
    Serial.printf("! scan failed (%d)\n", n);
    return false;
  }
  for (int i = 0; i < n; i++) {
    wifi_ap_record_t *r = (wifi_ap_record_t *)WiFi.getScanInfoByIndex(i);
    if (!r) continue;
    int idx = findAp(r->bssid);
    if (idx < 0) {
      if ((int)aps.size() >= MAX_APS) continue;
      ApObs o;
      memcpy(o.bssid, r->bssid, 6);
      o.minR = r->rssi;
      o.ch = r->primary;
      aps.push_back(o);
      idx = aps.size() - 1;
    }
    ApObs &a = aps[idx];
    if (a.seen > 0 && a.ch != r->primary) a.chChangedInCycle = true;
    a.ssid = String((const char *)r->ssid);
    a.ch = r->primary;
    a.second = (r->second == WIFI_SECOND_CHAN_ABOVE) ? 1 : (r->second == WIFI_SECOND_CHAN_BELOW) ? 2 : 0;
    a.auth = r->authmode;
    a.pair = r->pairwise_cipher;
    a.b = r->phy_11b;
    a.g = r->phy_11g;
    a.n = r->phy_11n;
    a.wps = r->wps;
    a.seen++;
    a.sum += r->rssi;
    a.sumSq += (float)r->rssi * r->rssi;
    if (r->rssi < a.minR) a.minR = r->rssi;
    if (r->rssi > a.maxR) a.maxR = r->rssi;
  }
  WiFi.scanDelete();
  roundsDone++;
  return true;
}

// Same physical radio? (main + guest SSID): same channel, MAC bytes 1-4
// identical and last byte close. This is a heuristic (LIKELY, not CONFIRMED).
static bool siblings(const ApObs &x, const ApObs &y) {
  if (x.ch != y.ch) return false;
  for (int k = 1; k <= 4; k++)
    if (x.bssid[k] != y.bssid[k]) return false;
  return abs((int)x.bssid[5] - (int)y.bssid[5]) <= 15;
}

static void groupRadios() {
  radios.clear();
  for (size_t i = 0; i < aps.size(); i++) {
    int found = -1;
    for (size_t r = 0; r < radios.size(); r++)
      if (siblings(aps[i], aps[radios[r].aps[0]])) { found = r; break; }
    if (found < 0) {
      Radio nr;
      nr.ch = aps[i].ch;
      radios.push_back(nr);
      found = radios.size() - 1;
    }
    Radio &R = radios[found];
    R.aps.push_back(i);
    if (aps[i].second) R.second = aps[i].second;
    if (aps[i].avg() > R.rssi) R.rssi = aps[i].avg();
    if (isHome(aps[i].ssid)) R.home = true;
    aps[i].radio = found;
  }
}

// ------------------------------------------------------------ interference model
// Spectral overlap between two 20 MHz channels that are d channels apart
// (5 MHz per channel). 1/6/11 (d=5) do not overlap.
static float overlap20(int d) {
  static const float t[] = {1.0f, 0.75f, 0.5f, 0.25f, 0.05f};
  d = abs(d);
  return d < 5 ? t[d] : 0.0f;
}

// Overlap of a radio (20 or 40 MHz) with a 20 MHz channel `target`.
static float radioOverlap(const Radio &r, int target) {
  float o = overlap20((int)r.ch - target);
  if (r.second) {
    int sec = (r.second == 1) ? r.ch + 4 : r.ch - 4;
    o = std::max(o, overlap20(sec - target));
  }
  return o;
}

// Signal weight: -52 dBm or stronger = 1.0, falls to 0 at -92 dBm.
static float rssiWeight(float rssi) {
  float w = (rssi + 92.0f) / 40.0f;
  return w < 0 ? 0 : (w > 1 ? 1 : w);
}

// Estimated interference load on `target`, ignoring radio `skip`
// and (optionally) all of your own radios.
static float channelLoad(int target, int skip, bool skipHome, int *coCount = nullptr, int *adjCount = nullptr) {
  float load = 0;
  int co = 0, adj = 0;
  for (size_t r = 0; r < radios.size(); r++) {
    if ((int)r == skip) continue;
    if (skipHome && radios[r].home) continue;
    float o = radioOverlap(radios[r], target);
    if (o <= 0) continue;
    load += o * rssiWeight(radios[r].rssi);
    if (radios[r].rssi >= CCA_DBM) {
      if (o >= 0.99f) co++;
      else adj++;
    }
  }
  if (coCount) *coCount = co;
  if (adjCount) *adjCount = adj;
  return load;
}

// ------------------------------------------------------------ findings
enum Sev { SEV_OK = 0, SEV_INFO, SEV_WARN, SEV_CRIT };
enum Conf { CONF_POSSIBLE = 0, CONF_LIKELY, CONF_CONFIRMED };
static const char *SEV_NAME[] = {"OK", "INFO", "WARN", "CRIT"};
static const char *CONF_NAME[] = {"POSSIBLE", "LIKELY", "CONFIRMED"};

struct Finding {
  String id, test, finding, evidence, action;
  Sev sev;
  Conf conf;
};
std::vector<Finding> findings;

struct Persist {
  uint16_t count = 0;
  uint32_t first = 0, last = 0;
};
std::map<String, Persist> history;

static void addF(const String &id, Sev s, Conf c, const String &test, const String &f,
                 const String &ev, const String &act) {
  for (auto &x : findings)
    if (x.id == id) return;  // no duplicates
  Finding x;
  x.id = id; x.sev = s; x.conf = c; x.test = test;
  x.finding = f; x.evidence = ev; x.action = act;
  findings.push_back(x);
}

static const char *authName(wifi_auth_mode_t a) {
  switch (a) {
    case WIFI_AUTH_OPEN: return "OPEN";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA";
    case WIFI_AUTH_WPA2_PSK: return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-ENT";
    case WIFI_AUTH_WPA3_PSK: return "WPA3";
    case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/3";
    default: return "OTHER";
  }
}

static const char *phyName(const ApObs &a) {
  if (a.n) return a.b ? "bgn" : "gn";
  if (a.g) return a.b ? "bg" : "g";
  if (a.b) return "b";
  return "?";
}

static String widthStr(const Radio &r) {
  if (!r.second) return fmt("20 MHz on ch %d", r.ch);
  int sec = (r.second == 1) ? r.ch + 4 : r.ch - 4;
  return fmt("40 MHz on ch %d+%d", r.ch, sec);
}

static bool isStd(int ch) { return ch == 1 || ch == 6 || ch == 11; }

static String upperNoSep(String s) {
  s.toUpperCase();
  String o;
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    if (c != '_' && c != '-' && c != ' ' && c != '.') o += c;
  }
  return o;
}

// Best of 1/6/11 for radio `skip`, ignoring your own radios.
static int bestStdChannel(int skip, float *bestLoad) {
  const int cand[] = {1, 6, 11};
  int best = 1;
  float bl = 1e9;
  for (int c : cand) {
    float l = channelLoad(c, skip, true);
    if (l < bl - 0.001f) { bl = l; best = c; }
  }
  if (bestLoad) *bestLoad = bl;
  return best;
}

static void analyseHomeRadio(int ri) {
  Radio &R = radios[ri];
  // representative AP = the home SSID on this radio
  int ai = R.aps[0];
  for (int k : R.aps)
    if (isHome(aps[k].ssid)) { ai = k; break; }
  ApObs &A = aps[ai];
  String who = A.ssid + " [" + macStr(A.bssid).substring(9) + "]";
  String key = macStr(A.bssid);

  // --- channel plan
  int co = 0, adj = 0;
  float cur = channelLoad(R.ch, ri, true, &co, &adj);
  float bestL;
  int best = bestStdChannel(ri, &bestL);
  String loads = fmt("load ch1=%.2f ch6=%.2f ch11=%.2f, current ch%d=%.2f",
                     channelLoad(1, ri, true), channelLoad(6, ri, true),
                     channelLoad(11, ri, true), R.ch, cur);

  if (!isStd(R.ch)) {
    Sev s = (adj + co) > 0 ? SEV_WARN : SEV_INFO;
    addF("nonstd:" + key, s, CONF_CONFIRMED, "Wi-Fi channel",
         who + " is on channel " + String(R.ch) + ", which partly overlaps 1/6/11 neighbours",
         fmt("%d overlapping radios above %.0f dBm; ", co + adj, CCA_DBM) + loads,
         fmt("Set this access point to channel %d (least busy of 1/6/11)", best));
  } else if (best != R.ch && (cur - bestL) >= 0.5f && bestL <= cur * 0.6f) {
    addF("chan:" + key, SEV_WARN, CONF_LIKELY, "Wi-Fi channel",
         who + fmt(" channel %d is busier than channel %d", R.ch, best),
         fmt("%d co-channel + %d adjacent radios above %.0f dBm; ", co, adj, CCA_DBM) + loads,
         fmt("Change channel %d -> %d, then re-test for several cycles", R.ch, best));
  } else {
    addF("chanok:" + key, SEV_OK, CONF_LIKELY, "Wi-Fi channel",
         who + fmt(" channel %d is a reasonable choice", R.ch),
         fmt("%d co-channel + %d adjacent radios; ", co, adj) + loads,
         "No change needed");
  }

  // --- channel width
  if (R.second) {
    int nb = 0;
    for (size_t r = 0; r < radios.size(); r++) {
      if ((int)r == ri || radios[r].home) continue;
      if (radios[r].rssi < CCA_DBM) continue;
      float o = std::max(radioOverlap(radios[r], R.ch),
                         radioOverlap(radios[r], R.second == 1 ? R.ch + 4 : R.ch - 4));
      if (o > 0) nb++;
    }
    addF("width:" + key, nb >= 2 ? SEV_WARN : SEV_INFO, CONF_CONFIRMED, "Channel width",
         who + " uses " + widthStr(R) + " in the 2.4 GHz band",
         fmt("%d neighbour radios overlap its 40 MHz span", nb),
         nb >= 2 ? "Set 2.4 GHz channel width to 20 MHz (40 MHz covers 2/3 of the band)"
                 : "OK while the band is quiet; use 20 MHz if neighbours appear");
  }

  // --- signal at this location
  if (R.rssi < -80) {
    addF("weak:" + key, SEV_WARN, CONF_CONFIRMED, "Signal strength",
         who + " is very weak where this device is", fmt("avg %.0f dBm", R.rssi),
         "Move the AP/extender closer, or add a wired access point here");
  } else if (R.rssi < -70) {
    addF("fair:" + key, SEV_INFO, CONF_CONFIRMED, "Signal strength",
         who + " signal is only fair here", fmt("avg %.0f dBm (good is above -67)", R.rssi),
         "Expect lower speed here; consider AP placement");
  }

  // --- stability
  if (A.seen >= 3 && A.sd() > 6.0f) {
    addF("unstable:" + key, SEV_WARN, CONF_POSSIBLE, "Signal stability",
         who + " signal fluctuates strongly",
         fmt("std dev %.1f dB, range %d..%d dBm over %d scans", A.sd(), A.minR, A.maxR, A.seen),
         "Check for moving obstructions, AP power changes, or interference; keep the tester still");
  }
  if (roundsDone >= 3 && A.seen < roundsDone * 0.6f) {
    addF("missed:" + key, SEV_WARN, CONF_LIKELY, "Beacon reception",
         who + " was missing from some scans", fmt("seen in %d of %d scans", A.seen, roundsDone),
         "Weak or intermittent coverage at this spot; check AP placement");
  }
  if (A.chChangedInCycle) {
    addF("hop:" + key, SEV_INFO, CONF_CONFIRMED, "Channel stability",
         who + " changed channel during this cycle", "channel differed between scans",
         "Auto-channel is switching; clients briefly disconnect each time. Consider a fixed channel");
  }

  // --- security (from the AP's beacon, so CONFIRMED)
  switch (A.auth) {
    case WIFI_AUTH_OPEN:
      addF("open:" + key, SEV_CRIT, CONF_CONFIRMED, "Security", who + " has no password (open)",
           "auth=OPEN", "Enable WPA2-PSK (AES) or WPA2/WPA3; if this is a guest network, isolate it");
      break;
    case WIFI_AUTH_WEP:
      addF("wep:" + key, SEV_CRIT, CONF_CONFIRMED, "Security", who + " uses WEP (broken in minutes)",
           "auth=WEP", "Switch to WPA2-PSK (AES) or WPA2/WPA3 now");
      break;
    case WIFI_AUTH_WPA_PSK:
      addF("wpa1:" + key, SEV_CRIT, CONF_CONFIRMED, "Security", who + " uses WPA (v1), which is obsolete",
           "auth=WPA", "Switch to WPA2-PSK (AES) or WPA2/WPA3");
      break;
    case WIFI_AUTH_WPA_WPA2_PSK:
      addF("mixed:" + key, SEV_WARN, CONF_CONFIRMED, "Security", who + " allows legacy WPA alongside WPA2",
           "auth=WPA/WPA2", "Set security to WPA2-PSK (AES) only, or WPA2/WPA3");
      break;
    case WIFI_AUTH_WPA2_PSK:
      addF("wpa2:" + key, SEV_INFO, CONF_CONFIRMED, "Security", who + " uses WPA2-PSK",
           "auth=WPA2", "Good. If all devices support it, WPA2/WPA3 transition mode is stronger");
      break;
    default:
      break;
  }
  if (A.pair == WIFI_CIPHER_TYPE_TKIP || A.pair == WIFI_CIPHER_TYPE_TKIP_CCMP) {
    addF("tkip:" + key, SEV_WARN, CONF_CONFIRMED, "Security", who + " has TKIP encryption enabled",
         A.pair == WIFI_CIPHER_TYPE_TKIP ? "cipher=TKIP" : "cipher=TKIP+AES",
         "Use AES (CCMP) only. TKIP is deprecated and limits 802.11n devices to 54 Mbps");
  }
  if (A.wps) {
    addF("wps:" + key, SEV_WARN, CONF_CONFIRMED, "Security", who + " advertises WPS",
         "WPS element present in beacon", "Disable WPS (the PIN method is vulnerable to brute force)");
  }

  // --- other SSIDs on the same radio (usually a guest network)
  for (int k : R.aps) {
    if (k == ai || isHome(aps[k].ssid)) continue;
    ApObs &G = aps[k];
    String gname = G.hidden() ? String("<hidden>") : G.ssid;
    if (G.auth == WIFI_AUTH_OPEN || G.auth == WIFI_AUTH_WEP) {
      addF("guestsec:" + macStr(G.bssid), SEV_WARN, CONF_LIKELY, "Security",
           gname + " (same router as " + A.ssid + ") is " + authName(G.auth),
           "MAC address matches your router; probably its guest network",
           "Add a WPA2 password to the guest network and enable client isolation");
    }
  }

  // --- 802.11 mode
  if (!A.n) {
    addF("legacy:" + key, A.g ? SEV_WARN : SEV_CRIT, CONF_CONFIRMED, "Wireless mode",
         who + " does not advertise 802.11n", fmt("PHY=%s", phyName(A)),
         "Set 2.4 GHz mode to b/g/n (or g/n/ax); legacy b/g caps speed at 54 Mbps");
  }

  // --- your own other APs on the same channel
  for (size_t r = 0; r < radios.size(); r++) {
    if ((int)r == ri || !radios[r].home || radios[r].ch != R.ch) continue;
    String other = aps[radios[r].aps[0]].ssid;
    for (int k : radios[r].aps)
      if (isHome(aps[k].ssid)) { other = aps[k].ssid; break; }
    String a = key, b = macStr(aps[radios[r].aps[0]].bssid);
    String pid = "ownco:" + (a < b ? a + b : b + a);
    addF(pid, SEV_INFO, CONF_LIKELY, "Your access points",
         who + " and " + other + fmt(" share channel %d", R.ch),
         fmt("%.0f dBm and %.0f dBm", R.rssi, radios[r].rssi),
         "Normal for mesh/repeaters (wireless backhaul). If the APs are wired, put them on different channels of 1/6/11");
  }
}

static void analyse() {
  findings.clear();
  groupRadios();

  // ---- your networks
  if (homeList.empty()) {
    addF("nohome", SEV_INFO, CONF_CONFIRMED, "Setup", "Your networks are not set",
         "Channel and security advice is general until you choose your SSIDs",
         "Type:  home YourSSID   (several: home SSID1,SSID2)");
  } else {
    for (auto &h : homeList) {
      int count = 0;
      for (auto &a : aps)
        if (a.ssid == h) count++;
      if (!count)
        addF("missing:" + h, SEV_WARN, CONF_CONFIRMED, "Your networks", h + " was not detected",
             fmt("not seen in %d scans", roundsDone),
             "Check the exact SSID spelling, that it broadcasts on 2.4 GHz, and that it is in range");
    }
    for (size_t r = 0; r < radios.size(); r++)
      if (radios[r].home) analyseHomeRadio(r);
  }

  // ---- SSIDs with several access points, and inconsistent settings
  std::map<String, std::vector<int>> bySsid;
  for (size_t i = 0; i < aps.size(); i++)
    if (!aps[i].hidden()) bySsid[aps[i].ssid].push_back(i);

  for (auto &kv : bySsid) {
    auto &v = kv.second;
    if (v.size() < 2) continue;
    String chans;
    bool authDiff = false, sameRadio = true;
    for (size_t j = 0; j < v.size(); j++) {
      if (j) chans += ",";
      chans += String(aps[v[j]].ch);
      if (aps[v[j]].auth != aps[v[0]].auth) authDiff = true;
      if (aps[v[j]].radio != aps[v[0]].radio) sameRadio = false;
    }
    if (!sameRadio) {
      addF("multi:" + kv.first, SEV_INFO, CONF_CONFIRMED, "Access points",
           kv.first + fmt(" is broadcast by %d access points", (int)v.size()),
           "channels " + chans, "Mesh or extenders. Check they all use the same security and that wired APs are in AP/bridge mode, not router mode");
    }
    if (authDiff) {
      String s;
      for (size_t j = 0; j < v.size(); j++) {
        if (j) s += ",";
        s += authName(aps[v[j]].auth);
      }
      addF("authdiff:" + kv.first, SEV_WARN, CONF_CONFIRMED, "Access points",
           kv.first + " uses different security on different access points", "security " + s,
           "Make every AP for this SSID use identical security; otherwise devices fail to roam or reconnect");
    }
  }

  // ---- extender with a separate SSID (e.g. FirstFloor + FirstFloor_EXT)
  for (auto &a : bySsid) {
    for (auto &b : bySsid) {
      if (a.first == b.first || b.first.length() <= a.first.length()) continue;
      if (!b.first.startsWith(a.first)) continue;
      String suf = upperNoSep(b.first.substring(a.first.length()));
      if (suf.startsWith("EXT") || suf.startsWith("RPT") || suf.startsWith("REPEAT")) {
        String ev = b.second.empty() ? String("name = ") + a.first + " + suffix"
                                      : "made by " + vendorFromMac(aps[b.second[0]].bssid) + ", name = " + a.first + " + suffix";
        addF("extssid:" + b.first, SEV_WARN, CONF_LIKELY, "Access points",
             b.first + " looks like an extender with its own SSID", ev,
             "Separate names stop phones moving between them automatically. Give the extender the same SSID and password, or use mesh / wired AP mode");
      }
    }
  }

  // ---- neighbourhood picture (all radios, including yours)
  int nonStd = 0, strong = 0, hidden = 0, insecure = 0, wide = 0;
  for (auto &R : radios) {
    if (R.home) continue;
    if (R.rssi >= CCA_DBM) strong++;
    if (!isStd(R.ch) && R.rssi >= CCA_DBM) nonStd++;
    if (R.second && R.rssi >= CCA_DBM) wide++;
  }
  for (auto &a : aps) {
    if (a.hidden()) hidden++;
    if (!isHome(a.ssid) && !(a.radio >= 0 && radios[a.radio].home) && (a.auth == WIFI_AUTH_OPEN || a.auth == WIFI_AUTH_WEP)) insecure++;
  }
  if (nonStd)
    addF("nb-nonstd", SEV_INFO, CONF_CONFIRMED, "Neighbour channels",
         fmt("%d neighbour radios sit between 1/6/11", nonStd), "on channels 2-5, 7-10, 12-13",
         "These cause adjacent-channel interference you cannot control; stay on 1, 6 or 11");
  if (wide)
    addF("nb-40", SEV_INFO, CONF_CONFIRMED, "Neighbour channels",
         fmt("%d neighbour radios use 40 MHz in 2.4 GHz", wide), "secondary channel present in beacon",
         "Their span covers more of the band; 20 MHz on your side keeps you clear of more of it");
  if (strong >= 15)
    addF("crowded", SEV_INFO, CONF_LIKELY, "Congestion",
         fmt("Crowded band: %d neighbour radios above %.0f dBm", strong, CCA_DBM), "",
         "Use 5 GHz for devices that support it; keep 2.4 GHz for IoT and range");
  if (hidden)
    addF("hidden", SEV_INFO, CONF_CONFIRMED, "Hidden networks", fmt("%d hidden SSIDs detected", hidden),
         "empty SSID in beacon", "Hiding an SSID adds no security; if one is yours, broadcasting it is fine");
  if (insecure)
    addF("nb-insecure", SEV_INFO, CONF_CONFIRMED, "Security",
         fmt("%d nearby networks are open or WEP", insecure), "",
         "If any of these are yours, add them with 'home' to get advice");

  // remember channels for change detection between cycles
  for (auto &a : aps) {
    String k = macStr(a.bssid);
    auto it = lastChannel.find(k);
    if (it != lastChannel.end() && it->second != a.ch && isHome(a.ssid)) {
      addF("cyclehop:" + k, SEV_INFO, CONF_CONFIRMED, "Channel stability",
           a.ssid + fmt(" moved from channel %d to %d since last cycle", it->second, a.ch), "",
           "Auto-channel switching; fine if rare, disruptive if it repeats");
    }
    lastChannel[k] = a.ch;
  }
  if (lastChannel.size() > 150) lastChannel.clear();

  // ---- persistence across cycles
  for (auto &f : findings) {
    Persist &p = history[f.id];
    if (p.count == 0) p.first = cycleNo;
    p.count++;
    p.last = cycleNo;
  }
  if (history.size() > 200) {
    for (auto it = history.begin(); it != history.end();) {
      if (cycleNo - it->second.last > 10) it = history.erase(it);
      else ++it;
    }
  }

  std::stable_sort(findings.begin(), findings.end(),
                   [](const Finding &a, const Finding &b) {
                     return a.sev != b.sev ? a.sev > b.sev : a.conf > b.conf;
                   });

}

static String persistLabel(const String &id) {
  auto it = history.find(id);
  if (it == history.end()) return "new";
  const Persist &p = it->second;
  uint32_t span = cycleNo - p.first + 1;
  if (span < 2) return "new";
  float ratio = (float)p.count / span;
  String s = (ratio >= 0.7f) ? "persistent" : "intermittent";
  return s + fmt(" %u/%u", p.count, span);
}

// ------------------------------------------------------------ report
static String bar(float v, float maxV, int width) {
  int n = maxV > 0 ? (int)roundf(v / maxV * width) : 0;
  if (n > width) n = width;
  String s;
  for (int i = 0; i < n; i++) s += '#';
  for (int i = n; i < width; i++) s += '.';
  return s;
}

static String jsonEsc(const String &s) {
  String o;
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    if (c == '"' || c == '\\') { o += '\\'; o += c; }
    else if ((uint8_t)c < 0x20) o += ' ';
    else o += c;
  }
  return o;
}

static void writeJson(Print &out);

static void printReport(Print &out) {
  out.println();
  out.println("==================================================");
  out.printf(" NETWORK DIAGNOSTIC v%s   cycle %u\n", FW_VERSION, cycleNo);
  out.printf(" %d scans | %d BSSIDs | %d radios | uptime %lus\n", roundsDone, (int)aps.size(),
                (int)radios.size(), millis() / 1000);
  out.printf(" Your networks: %s\n", cfg.home.length() ? cfg.home.c_str() : "(not set)");
  out.println("==================================================");

  if (cfg.raw) {
    out.println("\n-- ACCESS POINTS (avg dBm, spread, seen) --");
    out.println("CH  W   RSSI  SD SEEN SEC      PHY  VENDOR    SSID");
    std::vector<int> order(aps.size());
    for (size_t i = 0; i < aps.size(); i++) order[i] = i;
    std::sort(order.begin(), order.end(), [](int x, int y) { return aps[x].avg() > aps[y].avg(); });
    for (int i : order) {
      ApObs &a = aps[i];
      out.printf("%2d %s %5.0f %3.0f  %d/%d %-8s %-4s %-9s %s%s %s\n", a.ch,
                    a.second ? "40" : "20", a.avg(), a.sd(), a.seen, roundsDone, authName(a.auth),
                    phyName(a), vendorFromMac(a.bssid).c_str(), isHome(a.ssid) ? "*" : "",
                    a.hidden() ? "<hidden>" : a.ssid.c_str(), macStr(a.bssid).substring(9).c_str());
    }
    out.println("(* = your network, last 3 MAC bytes shown)");
  }

  out.println("\n-- CHANNEL INTERFERENCE ESTIMATE (all radios) --");
  float loads[MAX_CH + 1];
  float mx = 0.01f;
  for (int c = 1; c <= MAX_CH; c++) {
    loads[c] = channelLoad(c, -1, false);
    if (loads[c] > mx) mx = loads[c];
  }
  for (int c = 1; c <= MAX_CH; c++) {
    int prim = 0;
    for (auto &R : radios)
      if (R.ch == c) prim++;
    out.printf("%s%2d %s %5.2f  %d AP\n", isStd(c) ? ">" : " ", c, bar(loads[c], mx, 20).c_str(),
                  loads[c], prim);
  }
  int order3[3] = {1, 6, 11};
  std::sort(order3, order3 + 3, [&](int a, int b) { return loads[a] < loads[b]; });
  out.printf("Least busy of 1/6/11: %d, then %d, then %d\n", order3[0], order3[1], order3[2]);
  out.println("(score = overlap x signal; estimate, not airtime)");

  out.println("\n-- FINDINGS --");
  int nC = 0, nW = 0, nI = 0;
  for (auto &f : findings) {
    if (f.sev == SEV_CRIT) nC++;
    else if (f.sev == SEV_WARN) nW++;
    else if (f.sev == SEV_INFO) nI++;
    out.printf("\n[%s][%s][%s] %s\n", SEV_NAME[f.sev], CONF_NAME[f.conf], persistLabel(f.id).c_str(),
                  f.test.c_str());
    out.printf("  Finding : %s\n", f.finding.c_str());
    if (f.evidence.length()) out.printf("  Evidence: %s\n", f.evidence.c_str());
    out.printf("  Action  : %s\n", f.action.c_str());
  }
  out.printf("\nSUMMARY: %d critical, %d warnings, %d info\n", nC, nW, nI);
  out.println("Note: scan data shows beacons only; it cannot measure real airtime");
  out.println("or non-Wi-Fi interference. CONFIRMED = read from beacons,");
  out.println("LIKELY = strong inference, POSSIBLE = needs more evidence.");
  out.printf("Next cycle in %us. Type 'help' for commands.\n", cfg.intervalS);

  if (cfg.json) {
    out.print("JSON:");
    writeJson(out);
    out.println();
  }

  // LED: red = critical, yellow = warning, green = fine
  if (nC) led(20, 0, 0);
  else if (nW) led(20, 12, 0);
  else led(0, 20, 0);
}


static void writeJson(Print &out) {
  out.printf("{\"fw\":\"%s\",\"cycle\":%u,\"scans\":%d,\"findings\":[", FW_VERSION, cycleNo, roundsDone);
  for (size_t i = 0; i < findings.size(); i++) {
    Finding &f = findings[i];
    out.printf("%s{\"id\":\"%s\",\"sev\":\"%s\",\"conf\":\"%s\",\"test\":\"%s\",\"finding\":\"%s\",\"evidence\":\"%s\",\"action\":\"%s\"}",
               i ? "," : "", jsonEsc(f.id).c_str(), SEV_NAME[f.sev], CONF_NAME[f.conf], jsonEsc(f.test).c_str(),
               jsonEsc(f.finding).c_str(), jsonEsc(f.evidence).c_str(), jsonEsc(f.action).c_str());
  }
  out.print("]}");
}

// ------------------------------------------------------------ report buffer
class StrPrint : public Print {
 public:
  String s;
  size_t write(uint8_t c) override { s += (char)c; return 1; }
  size_t write(const uint8_t *b, size_t n) override {
    for (size_t i = 0; i < n; i++) s += (char)b[i];
    return n;
  }
};
String lastReport = "No report yet - first scan is running.";

// ------------------------------------------------------------ Wi-Fi access
WebServer server(80);
String apName;
bool staWasConnected = false;
unsigned long staRetryAt = 0;



// Hotspot that shares the home internet connection (NAT), so a phone on
// NetDiag-XXXX keeps working internet. DHCP hands out a public DNS server.
#if defined(CONFIG_LWIP_IPV4_NAPT) && CONFIG_LWIP_IPV4_NAPT
#warning "NAPT_PROBE: CONFIG_LWIP_IPV4_NAPT enabled"
#else
#warning "NAPT_PROBE: CONFIG_LWIP_IPV4_NAPT NOT enabled"
#endif
#if defined(CONFIG_LWIP_IP_FORWARD) && CONFIG_LWIP_IP_FORWARD
#warning "NAPT_PROBE: CONFIG_LWIP_IP_FORWARD enabled"
#else
#warning "NAPT_PROBE: CONFIG_LWIP_IP_FORWARD NOT enabled"
#endif
bool naptOk = false;
static void startHotspot() {
  WiFi.softAP(apName.c_str(), cfg.adminPass.c_str());
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0),
                    IPAddress(192, 168, 4, 2), IPAddress(1, 1, 1, 1));
  naptOk = WiFi.AP.enableNAPT(true);
  Serial.printf("> internet sharing (NAT) %s\n", naptOk ? "on" : "FAILED");
}

static void startStation() {
  if (!cfg.staSsid.length() && !nets.empty()) { cfg.staSsid = nets[0].ssid; cfg.staPass = nets[0].pass; }
  if (!cfg.staSsid.length()) return;
  Serial.printf("> joining Wi-Fi '%s' ...\n", cfg.staSsid.c_str());
  WiFi.begin(cfg.staSsid.c_str(), cfg.staPass.c_str());
}

// ------------------------------------------------------------ Wi-Fi manager (v3.9)
// Saved networks, hotspot modes and Bluetooth setup when the Wi-Fi is lost.
extern bool cycleActive;
extern volatile bool testRunning, testRequested, otaBusy;
bool apOn = true;  // the hotspot starts at boot and stays until the first connection
volatile bool bleActive = false, provDone = false;
String provSsid, provPass;
uint32_t bleStart = 0;
bool bleTried = false;
static const uint32_t BLE_WINDOW_MS = 10UL * 60 * 1000;
static const char *AP_MODE_NAMES[] = {"Always on", "Only when Wi-Fi is lost", "Off (Bluetooth backup)"};

static void useNet(const SavedNet &n) {
  cfg.staSsid = n.ssid;
  cfg.staPass = n.pass;
  saveSettings();
  WiFi.disconnect();
  delay(100);
  startStation();
}

static void hotspotOn() {
  if (apOn) return;
  WiFi.mode(WIFI_AP_STA);
  startHotspot();
  apOn = true;
}

static void hotspotOff() {
  if (!apOn) return;
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_STA);
  apOn = false;
  naptOk = false;
  Serial.println("> hotspot off (home Wi-Fi works)");
}

// quick scan: remember what is in range and join the strongest saved network
static void connectBest() {
  int n = WiFi.scanNetworks(false, true);
  if (n < 0) return;
  std::map<String, int> best;
  for (int i = 0; i < n; i++) {
    String ss = WiFi.SSID(i);
    if (!ss.length()) continue;
    int r = WiFi.RSSI(i);
    if (!best.count(ss) || r > best[ss]) best[ss] = r;
  }
  WiFi.scanDelete();
  seenNets.assign(best.begin(), best.end());
  std::sort(seenNets.begin(), seenNets.end(), [](const std::pair<String, int> &a, const std::pair<String, int> &b) { return a.second > b.second; });
  int pick = -1, pickR = -127;
  for (size_t i = 0; i < nets.size(); i++)
    if (best.count(nets[i].ssid) && best[nets[i].ssid] > pickR) { pick = i; pickR = best[nets[i].ssid]; }
  if (pick < 0) { Serial.println("> none of the saved networks is in range"); return; }
  Serial.printf("> strongest saved network: %s (%d dBm)\n", nets[pick].ssid.c_str(), pickR);
  useNet(nets[pick]);
}

#if defined(CONFIG_BLUEDROID_ENABLED) || defined(CONFIG_NIMBLE_ENABLED)
#define HAVE_BLE_PROV 1
static void provEvent(arduino_event_t *e) {
  if (e->event_id == ARDUINO_EVENT_PROV_CRED_RECV) {
    char ss[33] = {0}, pw[65] = {0};
    memcpy(ss, e->event_info.prov_cred_recv.ssid, 32);
    memcpy(pw, e->event_info.prov_cred_recv.password, 64);
    provSsid = ss;
    provPass = pw;
  } else if (e->event_id == ARDUINO_EVENT_PROV_CRED_SUCCESS) {
    provDone = true;
  } else if (e->event_id == ARDUINO_EVENT_PROV_CRED_FAIL) {
    Serial.println("> Bluetooth setup: could not join that network (wrong password or out of range) - try again in the app");
  }
}
#endif

static void bleBegin() {
  bleTried = true;
#ifdef HAVE_BLE_PROV
  String svc = "PROV_" + apName;
  uint8_t uuid[16] = {0xb4, 0xdf, 0x5a, 0x1c, 0x3f, 0x6b, 0xf4, 0xbf, 0xea, 0x4a, 0x82, 0x03, 0x04, 0x90, 0x1a, 0x02};
  Serial.printf("> Bluetooth Wi-Fi setup ON for 10 min: open the 'ESP BLE Provisioning' app, pick %s, code = your NetDiag password\n", svc.c_str());
  bleActive = true;
  bleStart = millis();
  WiFi.onEvent(provEvent);
  WiFiProv.beginProvision(NETWORK_PROV_SCHEME_BLE, NETWORK_PROV_SCHEME_HANDLER_FREE_BLE, NETWORK_PROV_SECURITY_1,
                          cfg.adminPass.c_str(), svc.c_str(), NULL, uuid, true);
#else
  Serial.println("> Bluetooth setup is not available in this build");
#endif
}

static String bleStatus() {
  if (bleActive) return "ON - app 'ESP BLE Provisioning', device PROV_" + apName;
  return cfg.apMode == 0 ? "not used (hotspot always on)" : "standby (starts 3 min after Wi-Fi is lost)";
}

static void wifiMgrTick() {
  static uint32_t last = 0, upSince = 0, downSince = 0, lastTry = 0;
  uint32_t now = millis();
  if (provDone) {  // new network received over Bluetooth and it works: save and restart cleanly
    rememberNet(provSsid, provPass);
    cfg.staSsid = provSsid;
    cfg.staPass = provPass;
    saveSettings();
    Serial.printf("> Bluetooth setup: joined '%s', saved. Restarting...\n", provSsid.c_str());
    delay(1500);
    ESP.restart();
  }
  if (now - last < 1000) return;
  last = now;
  bool up = WiFi.status() == WL_CONNECTED;
  if (up) {
    downSince = 0;
    if (!upSince) upSince = now;
    if (cfg.apMode != 0 && apOn && now - upSince > 30000 && !bleActive) hotspotOff();
    return;
  }
  upSince = 0;
  if (!downSince) downSince = now;
  uint32_t down = now - downSince;
  if (bleActive) {
    if (now - bleStart > BLE_WINDOW_MS) {  // nothing received: restart (hotspot is on again until Wi-Fi connects)
      Serial.println("> Bluetooth setup timed out - restarting");
      delay(500);
      ESP.restart();
    }
    return;
  }
  if (cfg.apMode == 0 || (cfg.apMode == 1 && down > 60000)) hotspotOn();
  bool busy = cycleActive || testRunning || testRequested || otaBusy;
  if (!nets.empty() && down > 15000 && now - lastTry > 30000 && !busy) {
    lastTry = now;
    connectBest();
  }
  if (cfg.apMode != 0 && !bleTried && !busy && down > (nets.empty() ? 10000UL : 180000UL)) bleBegin();
}

static void printAccess() {
  Serial.println("\n-- WI-FI ACCESS --");
  Serial.printf("Hotspot : %s   password: %s\n", apName.c_str(), cfg.adminPass.c_str());
  Serial.printf("Open    : http://%s   (login: admin / same password)\n", WiFi.softAPIP().toString().c_str());
  if (WiFi.status() == WL_CONNECTED)
    Serial.printf("Home LAN: http://%s  or  http://netdiag.local  (via %s)\n",
                  WiFi.localIP().toString().c_str(), cfg.staSsid.c_str());
  else if (cfg.staSsid.length())
    Serial.printf("Home LAN: not connected to '%s' yet\n", cfg.staSsid.c_str());
  else
    Serial.println("Home LAN: not set (use the web page or: wifi SSID|PASSWORD)");
}

// ------------------------------------------------------------ web pages
static String htmlEsc(const String &s) {
  String o;
  o.reserve(s.length() + 64);
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    if (c == '<') o += "&lt;";
    else if (c == '>') o += "&gt;";
    else if (c == '&') o += "&amp;";
    else if (c == '"') o += "&quot;";
    else o += c;
  }
  return o;
}

static bool auth() {
  if (server.authenticate("admin", cfg.adminPass.c_str())) return true;
  server.requestAuthentication(BASIC_AUTH, "NetDiag");
  return false;
}

bool scanRequested = true;  // run first cycle at boot
bool cycleActive = false;
int cycleRound = 0;

static void sendRedirect(const String &msg) {
  server.sendHeader("Location", "/?m=" + msg);
  server.send(303);
}

static void handleRoot() {
  if (!auth()) return;
  String msg = server.arg("m");
  String h;
  h.reserve(lastReport.length() + 3500);
  h += F("<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
         "<title>NetDiag</title><style>body{font-family:sans-serif;margin:8px;background:#f4f4f4}"
         "pre{background:#111;color:#ddd;padding:8px;font-size:11px;white-space:pre-wrap;word-break:break-word}"
         "fieldset{background:#fff;border:1px solid #ccc;border-radius:6px;margin:8px 0}"
         "input{width:95%;padding:6px;margin:3px 0}button{padding:10px 14px;margin:4px 0}"
         ".m{background:#dfd;padding:6px;border-radius:4px}</style></head><body>");
  h += "<h3>NetDiag v" FW_VERSION "</h3>";
  if (msg.length()) h += "<p class='m'>" + htmlEsc(msg) + "</p>";
  h += fmt("<p>Cycle %u %s | ", cycleNo, cycleActive ? "<b>(scanning...)</b>" : "");
  if (WiFi.status() == WL_CONNECTED)
    h += "Home LAN: " + htmlEsc(cfg.staSsid) + " " + WiFi.localIP().toString() + fmt(" (%d dBm)", WiFi.RSSI());
  else
    h += "Home LAN: not connected";
  h += String(" | Hotspot internet sharing: ") + (naptOk ? "ON" : "OFF");
  h += "</p><form method='post' action='/scan'><button>Scan now</button> <a href='/'>Refresh</a> | <a href='/api/report'>JSON</a></form>";
  h += "<p><a href='/test' style='display:inline-block;padding:12px 18px;background:#0b2a6b;color:#fff;border-radius:22px;text-decoration:none'>Test Internet Connection &rarr;</a> <a href='/fixes' style='display:inline-block;padding:12px 18px;background:#1d7a3a;color:#fff;border-radius:22px;text-decoration:none'>Recommended fixes</a> <a href='/router'>Router access</a> <a href='/devices'>Devices</a> &nbsp; <a href='/update'>Firmware &amp; system</a></p>";
  h += "<pre>" + htmlEsc(lastReport) + "</pre>";

  h += "<form method='post' action='/settings'><fieldset><legend>Diagnostics</legend>"
       "Your networks (comma separated)<input name='home' value='" + htmlEsc(cfg.home) + "'>"
       "Scans per cycle (1-10)<input name='rounds' type='number' value='" + String(cfg.rounds) + "'>"
       "Seconds between cycles (10-3600)<input name='interval' type='number' value='" + String(cfg.intervalS) + "'>"
       "<button>Save</button></fieldset></form>";

  h += "<form method='post' action='/wifi'><fieldset id='wifi'><legend>My Wi-Fi networks (2.4 GHz)</legend>";
  if (nets.empty()) h += "<p>No networks saved yet.</p>";
  else {
    h += "<table style='width:100%;font-size:14px'>";
    for (size_t i = 0; i < nets.size(); i++) {
      bool cur = WiFi.status() == WL_CONNECTED && nets[i].ssid == WiFi.SSID();
      String sig;
      for (auto &sn : seenNets)
        if (sn.first == nets[i].ssid) { sig = fmt(" %d dBm", sn.second); break; }
      h += "<tr><td>" + htmlEsc(nets[i].ssid) + (cur ? " <b>&#10003; connected</b>" : "") + "<small>" + sig + "</small></td><td style='text-align:right;white-space:nowrap'>";
      if (!cur) h += "<button name='use' value='" + String(i) + "'>Connect</button> ";
      h += "<button name='del' value='" + String(i) + "'>Remove</button></td></tr>";
    }
    h += "</table>";
  }
  h += "<p><b>Add a network</b> (pick from the scan or type the name)<br>"
       "<input name='ssid' list='nets' autocomplete='off' placeholder='Network name'><datalist id='nets'>";
  for (auto &sn : seenNets) h += "<option value='" + htmlEsc(sn.first) + "'>" + fmt("%d dBm", sn.second) + "</option>";
  h += "</datalist>Password<input name='pass' type='password' autocomplete='new-password' placeholder='Leave empty for open network'>"
       "<button name='a' value='add'>Save &amp; connect</button></p>";
  h += "<p><b>Hotspot " + htmlEsc(apName) + "</b><br><select name='apmode' style='padding:6px'>";
  for (int i = 0; i < 3; i++)
    h += "<option value='" + String(i) + "'" + (cfg.apMode == i ? " selected" : "") + ">" + AP_MODE_NAMES[i] + "</option>";
  h += "</select> <button name='a' value='mode'>Save</button><br><small>Hotspot now: " + String(apOn ? "on" : "off") +
       " | Bluetooth setup: " + htmlEsc(bleStatus()) + "</small></p></fieldset></form>";

  h += "<form method='post' action='/password'><fieldset><legend>Admin / hotspot password</legend>"
       "New password (8+ chars)<input name='p1' type='password'>Repeat<input name='p2' type='password'>"
       "<button>Change</button></fieldset></form>";
  h += "<form method='post' action='/reset'><button>Clear history</button></form></body></html>";
  server.send(200, "text/html", h);
}

static void handleScan() {
  if (!auth()) return;
  scanRequested = true;
  sendRedirect("Scan started - refresh in about 20 seconds");
}

static void handleSettings() {
  if (!auth()) return;
  cfg.home = server.arg("home");
  cfg.home.trim();
  int r = server.arg("rounds").toInt(), iv = server.arg("interval").toInt();
  if (r >= 1 && r <= 10) cfg.rounds = r;
  if (iv >= 10 && iv <= 3600) cfg.intervalS = iv;
  parseHomeList();
  history.clear();
  saveSettings();
  sendRedirect("Saved");
}

static void handleWifi() {
  if (!auth()) return;
  String a = server.arg("a");
  if (server.hasArg("del")) {
    int i = server.arg("del").toInt();
    if (i < 0 || i >= (int)nets.size()) { sendRedirect("Unknown network"); return; }
    String ss = nets[i].ssid;
    nets.erase(nets.begin() + i);
    saveSettings();
    sendRedirect("Removed " + ss);
    return;
  }
  if (server.hasArg("use")) {
    int i = server.arg("use").toInt();
    if (i < 0 || i >= (int)nets.size()) { sendRedirect("Unknown network"); return; }
    SavedNet n = nets[i];
    sendRedirect("Connecting to " + n.ssid + " - refresh in 15 s");
    delay(200);
    useNet(n);
    return;
  }
  if (a == "mode") {
    int m = server.arg("apmode").toInt();
    if (m < 0 || m > 2) m = 2;
    cfg.apMode = m;
    saveSettings();
    if (m == 0) hotspotOn();
    sendRedirect(String("Hotspot: ") + AP_MODE_NAMES[m]);
    return;
  }
  String ss = server.arg("ssid"), pw = server.arg("pass");
  ss.trim();
  if (!ss.length()) { sendRedirect("Network name is empty"); return; }
  if (!pw.length())  // keep the saved password when re-adding a known network without one
    for (auto &n : nets)
      if (n.ssid == ss) { pw = n.pass; break; }
  rememberNet(ss, pw);
  saveSettings();
  sendRedirect("Saved. Connecting to " + ss + " - refresh in 15 s");
  delay(200);
  useNet(nets[0]);
}

static void handlePassword() {
  if (!auth()) return;
  String a = server.arg("p1"), b = server.arg("p2");
  if (a.length() < 8 || a.length() > 63 || a != b) { sendRedirect("Passwords must match and be 8-63 characters"); return; }
  cfg.adminPass = a;
  cfg.customPass = true;
  saveSettings();
  sendRedirect("Password changed. Hotspot restarts - reconnect with the new password");
  delay(300);
  startHotspot();
}

static void handleReset() {
  if (!auth()) return;
  history.clear(); lastChannel.clear(); cycleNo = 0;
  sendRedirect("History cleared");
}

static void handleJson() {
  if (!auth()) return;
  StrPrint p;
  writeJson(p);
  server.send(200, "application/json", p.s);
}

// ============================================================ VERSION 3: CONNECTION TEST
// PlayStation-style step list. Runs in its own task so the web page stays live.
enum StepState : uint8_t { ST_WAIT = 0, ST_RUN, ST_OK, ST_WARN, ST_FAIL, ST_SKIP };
static const char *STEP_STATE[] = {"Waiting", "Testing...", "Successful", "Warning", "Failed", "Skipped"};
static const char *STEP_NAME[] = {"Wi-Fi Connection", "Obtain IP Address", "Router (Gateway)", "DNS",
                                  "Internet Connection", "Internet Latency", "NAT Type",
                                  "Download Speed", "Upload Speed"};
static const int NSTEPS = 9;
struct Step {
  StepState st = ST_WAIT;
  char value[96] = "";
  char note[200] = "";
};
Step steps[NSTEPS];
volatile bool testRunning = false;
volatile bool testRequested = false;
uint32_t testCount = 0;
SemaphoreHandle_t testMux = nullptr;

static void setStep(int i, StepState s, const String &v, const String &n = "") {
  if (testMux) xSemaphoreTake(testMux, portMAX_DELAY);
  steps[i].st = s;
  strlcpy(steps[i].value, v.c_str(), sizeof(steps[i].value));
  strlcpy(steps[i].note, n.c_str(), sizeof(steps[i].note));
  if (testMux) xSemaphoreGive(testMux);
}

// ---- ping (ESP-IDF ping session)
struct PingResult {
  volatile bool done = false;
  uint32_t sent = 0, recv = 0, minMs = 0xFFFFFFFF, maxMs = 0, sumMs = 0;
  float loss() const { return sent ? 100.0f * (sent - recv) / sent : 100.0f; }
  float avg() const { return recv ? (float)sumMs / recv : 0; }
};
static void pingOk(esp_ping_handle_t h, void *a) {
  PingResult *r = (PingResult *)a;
  uint32_t t = 0;
  esp_ping_get_profile(h, ESP_PING_PROF_TIMEGAP, &t, sizeof(t));
  r->recv++;
  r->sumMs += t;
  if (t < r->minMs) r->minMs = t;
  if (t > r->maxMs) r->maxMs = t;
}
static void pingTimeout(esp_ping_handle_t, void *) {}
static void pingEnd(esp_ping_handle_t h, void *a) {
  PingResult *r = (PingResult *)a;
  uint32_t tx = 0;
  esp_ping_get_profile(h, ESP_PING_PROF_REQUEST, &tx, sizeof(tx));
  r->sent = tx;
  r->done = true;
}
static bool doPing(IPAddress ip, int count, PingResult &r) {
  esp_ping_config_t pc = ESP_PING_DEFAULT_CONFIG();
  ip_addr_t t;
  memset(&t, 0, sizeof(t));
  if (!ipaddr_aton(ip.toString().c_str(), &t)) return false;
  pc.target_addr = t;
  pc.count = count;
  pc.interval_ms = 200;
  pc.timeout_ms = 1000;
  esp_ping_callbacks_t cb;
  memset(&cb, 0, sizeof(cb));
  cb.cb_args = &r;
  cb.on_ping_success = pingOk;
  cb.on_ping_timeout = pingTimeout;
  cb.on_ping_end = pingEnd;
  esp_ping_handle_t h;
  if (esp_ping_new_session(&pc, &cb, &h) != ESP_OK) return false;
  esp_ping_start(h);
  unsigned long t0 = millis();
  while (!r.done && millis() - t0 < (unsigned long)count * 1300UL + 3000UL) delay(50);
  esp_ping_stop(h);
  esp_ping_delete_session(h);
  return r.done;
}

// ---- STUN (RFC 5389) to find the public address/port mapping
struct StunRes {
  bool ok = false;
  IPAddress ip;
  uint16_t port = 0;
};
static StunRes stunQuery(WiFiUDP &u, const char *host, uint16_t port) {
  StunRes r;
  IPAddress sip;
  if (!WiFi.hostByName(host, sip)) return r;
  uint8_t req[20] = {0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42};
  for (int i = 8; i < 20; i++) req[i] = esp_random() & 0xFF;
  for (int attempt = 0; attempt < 3 && !r.ok; attempt++) {
    u.beginPacket(sip, port);
    u.write(req, 20);
    u.endPacket();
    unsigned long t0 = millis();
    while (millis() - t0 < 1000 && !r.ok) {
      int n = u.parsePacket();
      if (n < 20) { delay(10); continue; }
      uint8_t b[256];
      int len = u.read(b, sizeof(b));
      if (len < 20 || memcmp(b + 8, req + 8, 12) != 0) continue;
      int end = 20 + ((b[2] << 8) | b[3]);
      if (end > len) end = len;
      int pos = 20;
      while (pos + 4 <= end) {
        uint16_t type = (b[pos] << 8) | b[pos + 1];
        uint16_t alen = (b[pos + 2] << 8) | b[pos + 3];
        int v = pos + 4;
        if (v + alen > end) break;
        if ((type == 0x0020 || type == 0x0001) && alen >= 8 && b[v + 1] == 0x01) {
          uint16_t p = (b[v + 2] << 8) | b[v + 3];
          uint8_t a[4] = {b[v + 4], b[v + 5], b[v + 6], b[v + 7]};
          if (type == 0x0020) {
            p ^= 0x2112;
            a[0] ^= 0x21; a[1] ^= 0x12; a[2] ^= 0xA4; a[3] ^= 0x42;
          }
          r.ip = IPAddress(a[0], a[1], a[2], a[3]);
          r.port = p;
          r.ok = true;
          if (type == 0x0020) break;
        }
        pos = v + ((alen + 3) & ~3);
      }
    }
  }
  return r;
}

// ---- speed tests (Cloudflare speed endpoints). Limited by the ESP32 itself.
static const char *SPEED_HOST = "speed.cloudflare.com";

static float downloadMbps(String &err) {
  WiFiClientSecure c;
  c.setInsecure();  // speed test only; no secrets are sent
  c.setTimeout(10);
  if (!c.connect(SPEED_HOST, 443)) { err = "could not reach speed server"; return -1; }
  c.print("GET /__down?bytes=25000000 HTTP/1.1\r\nHost: speed.cloudflare.com\r\nUser-Agent: NetDiag\r\nConnection: close\r\n\r\n");
  static uint8_t buf[2048];
  size_t total = 0;
  unsigned long start = 0, t0 = millis();
  while (millis() - t0 < 14000) {
    int n = c.read(buf, sizeof(buf));
    if (n > 0) {
      if (!start) start = millis();
      total += n;
      if (millis() - start >= 8000) break;
    } else if (!c.connected()) break;
    else delay(1);
  }
  unsigned long el = start ? millis() - start : 0;
  c.stop();
  if (!start || el < 300) { err = "no data received"; return -1; }
  return total * 8.0f / el / 1000.0f;
}

static float uploadMbps(String &err) {
  WiFiClientSecure c;
  c.setInsecure();
  c.setTimeout(10);
  if (!c.connect(SPEED_HOST, 443)) { err = "could not reach speed server"; return -1; }
  const size_t N = 8000000;
  c.printf("POST /__up HTTP/1.1\r\nHost: speed.cloudflare.com\r\nUser-Agent: NetDiag\r\n"
           "Content-Type: application/octet-stream\r\nContent-Length: %u\r\nConnection: close\r\n\r\n", (unsigned)N);
  static uint8_t buf[1400];
  memset(buf, 'x', sizeof(buf));
  size_t sent = 0;
  unsigned long start = millis();
  while (sent < N && millis() - start < 8000) {
    size_t w = c.write(buf, sizeof(buf));
    if (w == 0) { if (!c.connected()) break; delay(2); continue; }
    sent += w;
  }
  unsigned long el = millis() - start;
  c.stop();
  if (sent < 20000 || el < 300) { err = "upload stalled"; return -1; }
  return sent * 8.0f / el / 1000.0f;
}

static const char *signalWord(int rssi) {
  if (rssi >= -60) return "Excellent";
  if (rssi >= -67) return "Good";
  if (rssi >= -75) return "Fair";
  return "Poor";
}

static void skipFrom(int i, const char *why) {
  for (int k = i; k < NSTEPS; k++) setStep(k, ST_SKIP, "", why);
}


// The DHCP server that handed out the current lease (0.0.0.0 if unknown).
static IPAddress dhcpServerIp() {
  struct netif *nif = netif_default;
  if (!nif) return IPAddress(0, 0, 0, 0);
  struct dhcp *d = netif_dhcp_data(nif);
  if (!d) return IPAddress(0, 0, 0, 0);
  return IPAddress(ip4_addr_get_u32(ip_2_ip4(&d->server_ip_addr)));
}

static void runConnectionTest() {
  for (int i = 0; i < NSTEPS; i++) setStep(i, ST_WAIT, "");
  while (cycleActive) delay(100);  // let a running Wi-Fi scan finish first

  // 1. Wi-Fi
  setStep(0, ST_RUN, "");
  if (WiFi.status() != WL_CONNECTED) {
    setStep(0, ST_FAIL, cfg.staSsid.length() ? "not connected to " + cfg.staSsid : "no Wi-Fi configured",
            "Use 'Join my Wi-Fi' on the main page. If it is set, the signal may be too weak or the password wrong.");
    skipFrom(1, "Needs a Wi-Fi connection");
    return;
  }
  int rssi = WiFi.RSSI();
  String wv = WiFi.SSID() + fmt(" | ch %d | %d dBm %s", WiFi.channel(), rssi, signalWord(rssi));
  if (rssi < -75)
    setStep(0, ST_WARN, wv, "Weak signal causes slow speed and packet loss. Move closer to the router or add an access point.");
  else
    setStep(0, ST_OK, wv);

  // 2. IP address (DHCP)
  setStep(1, ST_RUN, "");
  IPAddress ip = WiFi.localIP(), gw = WiFi.gatewayIP(), mask = WiFi.subnetMask(), dns1 = WiFi.dnsIP(0), dns2 = WiFi.dnsIP(1);
  IPAddress dhcp = dhcpServerIp();
  String iv = ip.toString() + " / " + mask.toString() + " | gw " + gw.toString() + " | DNS " + dns1.toString();
  if (dns2 != IPAddress(0, 0, 0, 0)) iv += ", " + dns2.toString();
  if (dhcp != IPAddress(0, 0, 0, 0)) iv += " | DHCP by " + dhcp.toString();
  if (ip[0] == 169 && ip[1] == 254) {
    setStep(1, ST_FAIL, iv, "Self-assigned address: the DHCP server did not answer. Check the router's DHCP setting.");
    skipFrom(2, "Needs a valid IP address");
    return;
  }
  bool sameNet = ((uint32_t)ip & (uint32_t)mask) == ((uint32_t)gw & (uint32_t)mask);
  // Rogue-DHCP clue: the server that leased us differs from the gateway it told us to use.
  bool rogue = dhcp != IPAddress(0, 0, 0, 0) && gw != IPAddress(0, 0, 0, 0) && dhcp != gw;
  if (gw == IPAddress(0, 0, 0, 0) || !sameNet)
    setStep(1, ST_WARN, iv, "Gateway is missing or outside your subnet - DHCP settings look wrong.");
  else if (rogue)
    setStep(1, ST_WARN, iv, "The DHCP server (" + dhcp.toString() + ") and the gateway (" + gw.toString() +
            ") are different devices. If the gateway can't route (e.g. it's a camera), this lease breaks the internet. "
            "Likely a SECOND DHCP server - turn DHCP off on every device except your main router.");
  else if (dns1 == IPAddress(0, 0, 0, 0))
    setStep(1, ST_WARN, iv, "No DNS server was given by DHCP.");
  else
    setStep(1, ST_OK, iv);

  // 3. Gateway ping
  setStep(2, ST_RUN, "pinging " + gw.toString());
  PingResult pg;
  if (!doPing(gw, 20, pg) || pg.recv == 0) {
    setStep(2, ST_FAIL, gw.toString() + " no reply",
            "Router did not answer ping. Some routers block ping; if the next steps pass, this is harmless.");
  } else {
    String v = fmt("avg %.0f ms (min %u / max %u) | loss %.0f%%", pg.avg(), pg.minMs, pg.maxMs, pg.loss());
    if (pg.loss() > 5 || pg.avg() > 50)
      setStep(2, ST_FAIL, v, "High loss or delay to your own router = Wi-Fi problem (weak signal, interference, or overloaded router).");
    else if (pg.loss() > 0 || pg.avg() > 15 || pg.maxMs > 100)
      setStep(2, ST_WARN, v, "Some loss or jitter on the Wi-Fi link. Check signal strength and channel congestion.");
    else
      setStep(2, ST_OK, v);
  }

  // 4. DNS
  setStep(3, ST_RUN, "resolving google.com");
  IPAddress res;
  unsigned long t0 = millis();
  bool dnsOk = WiFi.hostByName("google.com", res);
  unsigned long dnsMs = millis() - t0;
  if (!dnsOk) {
    setStep(3, ST_FAIL, "google.com could not be resolved",
            "DNS failed. Check the DNS servers in the router (try 1.1.1.1 / 8.8.8.8) or the internet connection.");
  } else {
    String v = fmt("google.com -> %s in %lu ms", res.toString().c_str(), dnsMs);
    v += (dns1 == gw) ? " (via router)" : " (via " + dns1.toString() + ")";
    if (dnsMs > 300) setStep(3, ST_WARN, v, "Slow DNS makes every website start slowly. Try 1.1.1.1 or 8.8.8.8 in the router.");
    else setStep(3, ST_OK, v);
  }

  // 5. Internet connection (HTTP 204 check)
  setStep(4, ST_RUN, "");
  int code = -1;
  {
    HTTPClient http;
    http.setTimeout(6000);
    if (http.begin("http://connectivitycheck.gstatic.com/generate_204")) {
      code = http.GET();
      http.end();
    }
  }
  if (code == 204) setStep(4, ST_OK, "online");
  else if (code > 0) setStep(4, ST_WARN, fmt("unexpected HTTP %d", code), "A login page or filter is intercepting traffic (captive portal / parental control).");
  else {
    setStep(4, ST_FAIL, "no internet", dnsOk ? "Local network works but traffic does not reach the internet. Check the router's WAN / ISP line."
                                             : "No DNS and no internet. Check the router's WAN / ISP connection.");
    skipFrom(5, "Needs internet");
    return;
  }

  // 6. Internet latency
  setStep(5, ST_RUN, "pinging 1.1.1.1");
  PingResult pi;
  if (!doPing(IPAddress(1, 1, 1, 1), 20, pi) || pi.recv == 0) {
    setStep(5, ST_WARN, "1.1.1.1 no ping reply", "Ping may be blocked upstream; web traffic works.");
  } else {
    String v = fmt("1.1.1.1 avg %.0f ms (min %u / max %u) | loss %.0f%%", pi.avg(), pi.minMs, pi.maxMs, pi.loss());
    bool lanOk = pg.recv > 0 && pg.loss() == 0;
    if (pi.loss() > 2 || pi.avg() > 100)
      setStep(5, ST_WARN, v, lanOk ? "Your Wi-Fi is clean, so the loss/delay is beyond your router (ISP or line)."
                                   : "Some of this comes from the Wi-Fi link (see Router step).");
    else
      setStep(5, ST_OK, v);
  }

  // 7. NAT type via two STUN servers
  setStep(6, ST_RUN, "");
  {
    WiFiUDP u;
    u.begin(40000 + (esp_random() % 20000));
    StunRes a = stunQuery(u, "stun.l.google.com", 19302);
    StunRes b = stunQuery(u, "stun.cloudflare.com", 3478);
    u.stop();
    if (!a.ok && !b.ok) {
      setStep(6, ST_FAIL, "Failed (UDP blocked)", "No UDP replies. Online games and calls may fail. Check firewall settings.");
    } else {
      StunRes &m = a.ok ? a : b;
      String v = "public IP " + m.ip.toString();
      if (m.ip == ip) {
        setStep(6, ST_OK, "Type 1 | " + v, "Directly on the internet, no NAT. Make sure a firewall is on.");
      } else if (a.ok && b.ok && a.port != b.port) {
        setStep(6, ST_WARN, "Type 3 (strict) | " + v,
                "Symmetric NAT: online games/voice chat may fail to connect. Enable UPnP, check for double NAT "
                "(two routers), or forward ports.");
      } else if (a.ok && b.ok) {
        setStep(6, ST_OK, "Type 2 | " + v, "Behind a normal router (good for gaming).");
      } else {
        setStep(6, ST_WARN, "Type 2? | " + v, "Only one STUN server answered; result not certain.");
      }
    }
  }

  // 8-9. Speed
  setStep(7, ST_RUN, "downloading for 8 s");
  String err;
  float dl = downloadMbps(err);
  if (dl < 0) setStep(7, ST_FAIL, err);
  else setStep(7, dl < 2 ? ST_WARN : ST_OK, fmt("%.1f Mbps (ESP32 limit ~10-20 Mbps)", dl),
               "Measured by the ESP32's small antenna; your phone/PC will be faster. Low values here usually mean weak signal or a busy channel.");
  setStep(8, ST_RUN, "uploading for 8 s");
  err = "";
  float ul = uploadMbps(err);
  if (ul < 0) setStep(8, ST_FAIL, err);
  else setStep(8, ul < 1 ? ST_WARN : ST_OK, fmt("%.1f Mbps (ESP32 limit)", ul), "Limited by the ESP32 and its signal.");
}

volatile bool fixRequested = false, fixRunning = false;
static void runFixJob();
static void runRouterIdentify();
static void runRouterVerify();
static void lanScan();
static void pollSerial();

static void testTask(void *) {
  for (;;) {
    if (testRequested) {
      testRequested = false;
      testRunning = true;
      testCount++;
      Serial.println("\n> connection test started");
      runConnectionTest();
      testRunning = false;
      Serial.println("\n-- CONNECTION TEST --");
      for (int i = 0; i < NSTEPS; i++) {
        Serial.printf("%-20s %-11s %s\n", STEP_NAME[i], STEP_STATE[steps[i].st], steps[i].value);
        if (steps[i].note[0] && steps[i].st != ST_OK) Serial.printf("   -> %s\n", steps[i].note);
      }
    }
    if (fixRequested) {
      fixRequested = false;
      fixRunning = true;
      runFixJob();
      fixRunning = false;
    }
    delay(100);
  }
}

static void handleTestPage() {
  if (!auth()) return;
  String h;
  h.reserve(5000);
  h += F("<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>");
  if (testRunning || testRequested) h += F("<meta http-equiv='refresh' content='2'>");
  h += F("<title>Test Connection</title><style>"
         "body{font-family:sans-serif;margin:0;background:linear-gradient(#0b2a6b,#061538);color:#fff;min-height:100vh}"
         "h2{font-weight:300;margin:0;padding:16px}.row{border-top:1px solid #ffffff22;padding:12px 16px}"
         ".n{font-size:17px}.s{float:right;font-weight:bold}.v{font-size:12px;color:#c8d3f0;margin-top:4px;word-break:break-word}"
         ".t{font-size:12px;color:#ffd27a;margin-top:4px}.OK{color:#7dffa1}.WARN{color:#ffd27a}.FAIL{color:#ff7d7d}"
         ".RUN{color:#7dc8ff}.WAIT,.SKIP{color:#8a97b8}button{margin:16px;padding:12px 22px;font-size:16px;border-radius:24px;"
         "border:0;background:#fff;color:#0b2a6b}a{color:#9fc3ff;margin-left:16px}</style></head><body>");
  h += F("<h2>Test Internet Connection</h2>");
  static const char *cls[] = {"WAIT", "RUN", "OK", "WARN", "FAIL", "SKIP"};
  if (testMux) xSemaphoreTake(testMux, portMAX_DELAY);
  for (int i = 0; i < NSTEPS; i++) {
    h += "<div class='row'><span class='n'>" + String(STEP_NAME[i]) + "</span><span class='s " + cls[steps[i].st] + "'>" +
         STEP_STATE[steps[i].st] + "</span>";
    if (steps[i].value[0]) h += "<div class='v'>" + htmlEsc(steps[i].value) + "</div>";
    if (steps[i].note[0] && steps[i].st != ST_OK && steps[i].st != ST_WAIT) h += "<div class='t'>" + htmlEsc(steps[i].note) + "</div>";
    h += "</div>";
  }
  if (testMux) xSemaphoreGive(testMux);
  if (testRunning || testRequested) h += F("<p style='padding:0 16px'>Testing... about 45 seconds. This page refreshes itself.</p>");
  else h += F("<form method='post' action='/test'><button>Test Internet Connection</button></form>");
  h += F("<a href='/fixes' style='color:#7dffa1'>Recommended fixes &rarr;</a><br><a href='/'>&larr; Back to Wi-Fi report</a><br><br></body></html>");
  server.send(200, "text/html", h);
}

static void handleTestRun() {
  if (!auth()) return;
  if (!testRunning) testRequested = true;
  server.sendHeader("Location", "/test");
  server.send(303);
}

// ============================================================ OTA FIRMWARE UPDATES (v3.1)
// Two ways to update without USB:
//   1. GitHub: device downloads the newest release published by GitHub Actions,
//      over HTTPS with certificate checking, and verifies size + SHA-256
//      against manifest.json before switching to it.
//   2. Upload: send firmware.bin from the phone's browser (needs your own password).
// Safety: two app slots. New firmware must run 90 s healthy; if it reboots 3 times
// first, the device switches back to the previous slot. Manual rollback button too.
static const char *OTA_MANIFEST_URL =
    "https://github.com/Alshehhi56/WiFi-scanner-/releases/latest/download/manifest.json";
static const unsigned long OTA_HEALTHY_MS = 90000;

extern "C" bool verifyRollbackLater() { return true; }  // we confirm the image ourselves

SemaphoreHandle_t otaMux = nullptr;
String otaStatus = "Idle";
int otaProgress = -1;  // 0-100 while installing
volatile bool otaCheckReq = false, otaInstallReq = false, otaBusy = false;
String otaLatestVer, otaLatestUrl, otaLatestSha;
uint32_t otaLatestSize = 0;
bool otaHealthyDone = false;
bool uploadDenied = false;
String uploadErr;

static void setOta(const String &s, int prog = -1) {
  if (otaMux) xSemaphoreTake(otaMux, portMAX_DELAY);
  otaStatus = s;
  otaProgress = prog;
  if (otaMux) xSemaphoreGive(otaMux);
  Serial.printf("> OTA: %s\n", s.c_str());
}
static String getOta(int *prog = nullptr) {
  if (otaMux) xSemaphoreTake(otaMux, portMAX_DELAY);
  String s = otaStatus;
  if (prog) *prog = otaProgress;
  if (otaMux) xSemaphoreGive(otaMux);
  return s;
}

static long verNum(const String &v) {
  int a = 0, b = 0, c = 0;
  sscanf(v.c_str(), "%d.%d.%d", &a, &b, &c);
  return a * 1000000L + b * 1000L + c;
}

static String jsonField(const String &body, const char *key) {
  String k = String("\"") + key + "\"";
  int i = body.indexOf(k);
  if (i < 0) return "";
  i = body.indexOf(':', i + k.length());
  if (i < 0) return "";
  i++;
  while (i < (int)body.length() && body[i] == ' ') i++;
  if (i < (int)body.length() && body[i] == '"') {
    int e = body.indexOf('"', i + 1);
    return e < 0 ? String("") : body.substring(i + 1, e);
  }
  int e = i;
  while (e < (int)body.length() && body[e] != ',' && body[e] != '}' && body[e] != ' ') e++;
  return body.substring(i, e);
}

static esp_err_t manifestEvt(esp_http_client_event_t *e) {
  String *s = (String *)e->user_data;
  if (!s) return ESP_OK;
  if (e->event_id == HTTP_EVENT_ON_CONNECTED) *s = "";
  if (e->event_id == HTTP_EVENT_ON_DATA && s->length() < 4096)
    for (int i = 0; i < e->data_len; i++) *s += ((const char *)e->data)[i];
  return ESP_OK;
}

static bool otaCheck() {
  if (WiFi.status() != WL_CONNECTED) { setOta("Not connected to your Wi-Fi - join it first"); return false; }
  setOta("Checking GitHub for new firmware...");
  String body;
  esp_http_client_config_t c;
  memset(&c, 0, sizeof(c));
  c.url = OTA_MANIFEST_URL;
  c.crt_bundle_attach = esp_crt_bundle_attach;  // real certificate check
  c.event_handler = manifestEvt;
  c.user_data = &body;
  c.timeout_ms = 15000;
  c.max_redirection_count = 6;
  c.buffer_size = 4096;
  c.buffer_size_tx = 4096;
  esp_http_client_handle_t h = esp_http_client_init(&c);
  if (!h) { setOta("Check failed: HTTP client init"); return false; }
  esp_err_t r = esp_http_client_perform(h);
  int st = esp_http_client_get_status_code(h);
  esp_http_client_cleanup(h);
  if (r != ESP_OK) { setOta(String("Check failed: ") + esp_err_to_name(r)); return false; }
  if (st != 200) { setOta(fmt("Check failed: HTTP %d (no release published yet?)", st)); return false; }
  otaLatestVer = jsonField(body, "version");
  otaLatestUrl = jsonField(body, "url");
  otaLatestSha = jsonField(body, "sha256");
  otaLatestSha.toLowerCase();
  otaLatestSize = jsonField(body, "size").toInt();
  if (!otaLatestVer.length() || !otaLatestUrl.startsWith("https://") || otaLatestSha.length() != 64 || !otaLatestSize) {
    setOta("Check failed: manifest incomplete");
    return false;
  }
  if (verNum(otaLatestVer) > verNum(FW_VERSION))
    setOta("Update available: v" + otaLatestVer + fmt(" (%u KB)", otaLatestSize / 1024));
  else
    setOta("Up to date (latest is v" + otaLatestVer + ")");
  return true;
}

static void markPendingAndRestart(const String &newVer) {
  const esp_partition_t *run = esp_ota_get_running_partition();
  prefs.putString("otaprev", run ? run->label : "");
  prefs.putString("otaprevver", FW_VERSION);
  prefs.putString("otanewver", newVer);
  prefs.putBool("otapend", true);
  prefs.putUChar("otatries", 0);
  setOta("Installed v" + newVer + " - restarting...");
  delay(1500);
  ESP.restart();
}

static bool sha256Partition(const esp_partition_t *p, uint32_t len, String &hex) {
  static uint8_t buf[1024];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  for (uint32_t off = 0; off < len; off += sizeof(buf)) {
    uint32_t n = std::min<uint32_t>(sizeof(buf), len - off);
    if (esp_partition_read(p, off, buf, n) != ESP_OK) { mbedtls_sha256_free(&ctx); return false; }
    mbedtls_sha256_update(&ctx, buf, n);
  }
  uint8_t out[32];
  mbedtls_sha256_finish(&ctx, out);
  mbedtls_sha256_free(&ctx);
  hex = "";
  for (int i = 0; i < 32; i++) hex += fmt("%02x", out[i]);
  return true;
}

static void otaInstall() {
  if (!otaCheck()) return;
  if (verNum(otaLatestVer) <= verNum(FW_VERSION)) return;
  while (cycleActive || testRunning) delay(100);
  setOta("Downloading v" + otaLatestVer + "...", 0);
  esp_http_client_config_t hc;
  memset(&hc, 0, sizeof(hc));
  hc.url = otaLatestUrl.c_str();
  hc.crt_bundle_attach = esp_crt_bundle_attach;
  hc.timeout_ms = 20000;
  hc.max_redirection_count = 6;
  hc.buffer_size = 4096;
  hc.buffer_size_tx = 4096;
  hc.keep_alive_enable = true;
  esp_https_ota_config_t oc;
  memset(&oc, 0, sizeof(oc));
  oc.http_config = &hc;
  esp_https_ota_handle_t h = nullptr;
  esp_err_t r = esp_https_ota_begin(&oc, &h);
  if (r != ESP_OK) { setOta(String("Download failed to start: ") + esp_err_to_name(r)); return; }
  while ((r = esp_https_ota_perform(h)) == ESP_ERR_HTTPS_OTA_IN_PROGRESS) {
    int got = esp_https_ota_get_image_len_read(h);
    int pct = otaLatestSize ? (int)(100.0f * got / otaLatestSize) : 0;
    static int lastPct = -1;
    if (pct / 10 != lastPct / 10) { lastPct = pct; setOta("Downloading v" + otaLatestVer + fmt("... %d%%", pct), pct); }
  }
  if (r != ESP_OK || !esp_https_ota_is_complete_data_received(h)) {
    esp_https_ota_abort(h);
    setOta(String("Download failed: ") + esp_err_to_name(r) + " - still on v" FW_VERSION);
    return;
  }
  uint32_t len = esp_https_ota_get_image_len_read(h);
  if (len != otaLatestSize) {
    esp_https_ota_abort(h);
    setOta(fmt("Rejected: size %u, expected %u - still on v" FW_VERSION, len, otaLatestSize));
    return;
  }
  setOta("Verifying SHA-256...", 100);
  String hex;
  const esp_partition_t *dst = esp_ota_get_next_update_partition(NULL);
  if (!dst || !sha256Partition(dst, len, hex) || hex != otaLatestSha) {
    esp_https_ota_abort(h);
    setOta("Rejected: SHA-256 mismatch - still on v" FW_VERSION);
    return;
  }
  r = esp_https_ota_finish(h);  // validates the image and selects it for next boot
  if (r != ESP_OK) { setOta(String("Rejected by image check: ") + esp_err_to_name(r)); return; }
  markPendingAndRestart(otaLatestVer);
}

static void otaTask(void *) {
  for (;;) {
    if (otaCheckReq || otaInstallReq) {
      bool inst = otaInstallReq;
      otaCheckReq = otaInstallReq = false;
      otaBusy = true;
      if (inst) otaInstall();
      else otaCheck();
      otaBusy = false;
    }
    delay(200);
  }
}

// Called early in setup(): count boots of a freshly installed image; roll back after 3 failures.
static void otaBootCheck() {
  String msg = prefs.getString("otamsg", "");
  if (msg.length()) setOta(msg);
  if (!prefs.getBool("otapend", false)) return;
  uint8_t t = prefs.getUChar("otatries", 0) + 1;
  prefs.putUChar("otatries", t);
  Serial.printf("> new firmware v%s, boot attempt %u/3\n", FW_VERSION, t);
  if (t <= 3) return;
  String prev = prefs.getString("otaprev", "");
  const esp_partition_t *p = esp_partition_find_first(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_ANY, prev.c_str());
  prefs.putBool("otapend", false);
  if (p && esp_ota_set_boot_partition(p) == ESP_OK) {
    prefs.putString("otamsg", "Rolled back to v" + prefs.getString("otaprevver", "?") + ": new firmware failed to start 3 times");
    Serial.println("> rolling back to previous firmware");
    delay(500);
    ESP.restart();
  }
}

// Called from loop(): after 90 s of normal running, accept the new image.
static void otaHealthTick() {
  if (otaHealthyDone || millis() < OTA_HEALTHY_MS) return;
  otaHealthyDone = true;
  esp_ota_mark_app_valid_cancel_rollback();
  if (prefs.getBool("otapend", false)) {
    prefs.putBool("otapend", false);
    prefs.putUChar("otatries", 0);
    String m = "Updated to v" FW_VERSION " (previous v" + prefs.getString("otaprevver", "?") + " kept for rollback)";
    prefs.putString("otamsg", m);
    setOta(m);
  }
}

static bool canRollback(String &info) {
  const esp_partition_t *other = esp_ota_get_next_update_partition(NULL);
  String prev = prefs.getString("otaprev", "");
  esp_app_desc_t d;
  if (!other || prev != other->label || esp_ota_get_partition_description(other, &d) != ESP_OK) {
    info = "No previous firmware recorded";
    return false;
  }
  info = String("v") + prefs.getString("otaprevver", "?") + " in slot " + other->label;
  return true;
}

// ---- web: /update
static String remoteFieldset();

static void handleUpdatePage() {
  if (!auth()) return;
  int prog = -1;
  String st = getOta(&prog);
  const esp_partition_t *run = esp_ota_get_running_partition();
  String rbInfo;
  bool rb = canRollback(rbInfo);
  String h;
  h.reserve(5000);
  h += F("<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>");
  if (otaBusy || otaCheckReq || otaInstallReq) h += F("<meta http-equiv='refresh' content='3'>");
  h += F("<title>Firmware</title><style>body{font-family:sans-serif;margin:8px;background:#f4f4f4}"
         "fieldset{background:#fff;border:1px solid #ccc;border-radius:6px;margin:8px 0}td{padding:2px 6px;font-size:13px}"
         "button{padding:10px 14px;margin:4px 0}.s{background:#e8f0ff;padding:8px;border-radius:4px}"
         ".w{background:#fff3cd;padding:8px;border-radius:4px}</style></head><body>");
  h += "<h3>Firmware &amp; System</h3><p class='s'><b>Status:</b> " + htmlEsc(st);
  if (prog >= 0) h += fmt(" <progress max='100' value='%d'></progress>", prog);
  h += "</p>";

  h += "<form method='post' action='/ota'><fieldset><legend>Update from GitHub</legend>"
       "Running <b>v" FW_VERSION "</b>. Downloads the newest release from your repository over HTTPS, "
       "checks size and SHA-256, then restarts.<br>"
       "<button name='a' value='check'>Check for update</button> "
       "<button name='a' value='install'>Install update</button></fieldset></form>";

  if (!cfg.customPass)
    h += "<p class='w'>Upload and rollback are locked while the default password is in use. "
         "Set your own password on the main page first.</p>";
  h += "<form method='post' action='/update' enctype='multipart/form-data'><fieldset><legend>Upload firmware file</legend>"
       "Choose <b>firmware.bin</b> (not merged-firmware.bin).<br><input type='file' name='fw' accept='.bin'><br>"
       "<button>Upload &amp; install</button></fieldset></form>";
  h += "<form method='post' action='/rollback'><fieldset><legend>Roll back</legend>" + htmlEsc(rbInfo) + "<br>";
  if (rb) h += "<label><input type='checkbox' name='yes' value='1'> I want to go back</label><br><button>Roll back &amp; restart</button>";
  h += "</fieldset></form>";

  h += remoteFieldset();
  h += "<fieldset><legend>System</legend><table>";
  h += "<tr><td>Firmware</td><td>v" FW_VERSION " built " __DATE__ " " __TIME__ "</td></tr>";
  h += fmt("<tr><td>Chip</td><td>%s rev %d, %d cores, %lu MHz</td></tr>", ESP.getChipModel(), ESP.getChipRevision(),
           ESP.getChipCores(), (unsigned long)ESP.getCpuFreqMHz());
  h += fmt("<tr><td>Flash</td><td>%lu MB</td></tr>", (unsigned long)(ESP.getFlashChipSize() >> 20));
  h += fmt("<tr><td>PSRAM</td><td>%lu KB %s</td></tr>", (unsigned long)(ESP.getPsramSize() >> 10),
           ESP.getPsramSize() ? "" : "(not enabled in build)");
  h += fmt("<tr><td>Free heap</td><td>%lu KB (min %lu KB)</td></tr>", (unsigned long)(ESP.getFreeHeap() >> 10),
           (unsigned long)(ESP.getMinFreeHeap() >> 10));
  h += fmt("<tr><td>App size</td><td>%lu KB of %lu KB slot</td></tr>", (unsigned long)(ESP.getSketchSize() >> 10),
           (unsigned long)((ESP.getSketchSize() + ESP.getFreeSketchSpace()) >> 10));
  h += String("<tr><td>Running slot</td><td>") + (run ? run->label : "?") + "</td></tr>";
  h += fmt("<tr><td>Uptime</td><td>%lu s</td></tr>", millis() / 1000);
  h += "</table><br><b>Partitions</b><table>";
  esp_partition_iterator_t it = esp_partition_find(ESP_PARTITION_TYPE_ANY, ESP_PARTITION_SUBTYPE_ANY, NULL);
  while (it) {
    const esp_partition_t *p = esp_partition_get(it);
    h += fmt("<tr><td>%s</td><td>0x%06lx</td><td>%lu KB</td></tr>", p->label, (unsigned long)p->address,
             (unsigned long)(p->size >> 10));
    it = esp_partition_next(it);
  }
  esp_partition_iterator_release(it);
  h += "</table></fieldset><a href='/'>&larr; Back</a></body></html>";
  server.send(200, "text/html", h);
}

// ------------------------------------------------------------ remote access settings (v3.9)
// Requests relayed from the Cloudflare Worker arrive from 127.0.0.1.
static bool viaRemote() { return server.client().remoteIP() == IPAddress(127, 0, 0, 1); }

static String remoteFieldset() {
  String m = server.arg("rm");
  String h = "<form method='post' action='/remote'><fieldset id='remote'><legend>Remote access (Cloudflare)</legend>";
  if (m.length()) h += "<p class='w'>" + htmlEsc(m) + "</p>";
  h += "<p class='s'><b>Status:</b> " + htmlEsc(remoteStatus()) + "</p>";
  if (viaRemote()) {
    h += "You are connected remotely. These settings can only be changed on your home network.</fieldset></form>";
    return h;
  }
  h += String("<label><input type='checkbox' name='on' value='1'") + (remoteEnabled() ? " checked" : "") +
       " style='width:auto'> Enable remote access</label><br>"
       "Worker address<br><input name='host' style='width:95%;padding:6px' placeholder='netdiag-remote.yourname.workers.dev' value='" +
       htmlEsc(remoteHost()) + "'><br>";
  if (remoteKey().length())
    h += "Device key (save it in GitHub as secret <b>NETDIAG_DEVICE_KEY</b>):<br><code style='word-break:break-all'>" +
         htmlEsc(remoteKey()) + "</code><br>";
  h += "<button name='a' value='save'>Save</button> <button name='a' value='newkey'>New device key</button>"
       "</fieldset></form>";
  return h;
}

static void handleRemote() {
  if (!auth()) return;
  String a = server.arg("a"), m;
  if (viaRemote()) m = "Remote access settings can only be changed on your home network.";
  else if (a == "newkey") { remoteNewKey(); m = "New key made. Update NETDIAG_DEVICE_KEY in GitHub, then run the deploy again."; }
  else {
    bool on = server.arg("on") == "1";
    if (on && !cfg.customPass) m = "Set your own password on the main page first. The default password is public.";
    else { remoteSet(on, server.arg("host")); m = on ? "Saved. Connecting..." : "Remote access turned off."; }
  }
  server.sendHeader("Location", "/update?rm=" + m + "#remote");
  server.send(303);
}

static void handleOtaAction() {
  if (!auth()) return;
  String a = server.arg("a");
  if (otaBusy) { server.sendHeader("Location", "/update"); server.send(303); return; }
  if (a == "install") otaInstallReq = true;
  else otaCheckReq = true;
  server.sendHeader("Location", "/update");
  server.send(303);
}

static void handleUploadData() {
  HTTPUpload &up = server.upload();
  if (up.status == UPLOAD_FILE_START) {
    uploadDenied = !server.authenticate("admin", cfg.adminPass.c_str()) || !cfg.customPass || otaBusy;
    uploadErr = "";
    if (uploadDenied) return;
    if (up.filename.indexOf("merged") >= 0) { uploadErr = "Use firmware.bin, not merged-firmware.bin"; return; }
    otaBusy = true;
    setOta("Receiving " + up.filename + "...");
    if (!Update.begin(UPDATE_SIZE_UNKNOWN, U_FLASH)) uploadErr = String("Update.begin: ") + Update.errorString();
  } else if (up.status == UPLOAD_FILE_WRITE) {
    if (uploadDenied || uploadErr.length()) return;
    if (Update.write(up.buf, up.currentSize) != up.currentSize) uploadErr = String("write: ") + Update.errorString();
  } else if (up.status == UPLOAD_FILE_END) {
    if (uploadDenied || uploadErr.length()) { Update.abort(); return; }
    if (!Update.end(true)) uploadErr = String("verify: ") + Update.errorString();  // checks image + its SHA-256
  } else if (up.status == UPLOAD_FILE_ABORTED) {
    Update.abort();
    uploadErr = "upload aborted";
  }
}

static void handleUploadDone() {
  if (!auth()) return;
  if (uploadDenied) {
    server.send(403, "text/plain", cfg.customPass ? "Busy, try again" : "Set your own password first (main page).");
    return;
  }
  if (uploadErr.length()) {
    otaBusy = false;
    setOta("Upload rejected: " + uploadErr + " - still on v" FW_VERSION);
    server.sendHeader("Location", "/update");
    server.send(303);
    return;
  }
  server.send(200, "text/html", "<meta http-equiv='refresh' content='25;url=/update'>Installed. Restarting... page reloads in 25 s.");
  delay(300);
  markPendingAndRestart("uploaded");
}

static void handleRollback() {
  if (!auth()) return;
  String info;
  if (!cfg.customPass) { server.send(403, "text/plain", "Set your own password first (main page)."); return; }
  if (server.arg("yes") != "1" || !canRollback(info)) { server.sendHeader("Location", "/update"); server.send(303); return; }
  const esp_partition_t *other = esp_ota_get_next_update_partition(NULL);
  if (esp_ota_set_boot_partition(other) != ESP_OK) { setOta("Rollback failed: image not valid"); server.sendHeader("Location", "/update"); server.send(303); return; }
  prefs.putBool("otapend", false);
  prefs.putString("otamsg", "Rolled back by you from v" FW_VERSION);
  server.send(200, "text/html", "<meta http-equiv='refresh' content='25;url=/update'>Rolling back. Restarting...");
  delay(500);
  ESP.restart();
}

static void handleInfo() {
  if (!auth()) return;
  const esp_partition_t *run = esp_ota_get_running_partition();
  String j = "{\"fw\":\"" FW_VERSION "\",\"slot\":\"" + String(run ? run->label : "?") + "\"";
  j += fmt(",\"uptime_s\":%lu,\"heap\":%lu,\"rssi\":%d", millis() / 1000, (unsigned long)ESP.getFreeHeap(),
           WiFi.status() == WL_CONNECTED ? WiFi.RSSI() : 0);
  j += ",\"ip\":\"" + WiFi.localIP().toString() + "\",\"ota\":\"" + jsonEsc(getOta()) + "\"}";
  server.send(200, "application/json", j);
}

// ============================================================ FIX CENTER (v3.2)
// Every recommendation becomes a fix card:
//  AUTO   - the board fixes it itself (one click), shows progress, then re-checks.
//  GUIDED - router-side change; step-by-step instructions + one-click verify
//           (rescan or retest) that confirms whether the problem is gone.
struct FixItem {
  String id, title, why, how;
  Sev sev;
  bool autoFix;
};

static const int FIX_LINES = 10;
struct FixLine {
  StepState st;
  char text[140];
};
FixLine fixLines[FIX_LINES];
int fixLineCount = 0;
String fixTitle, fixResult, fixJobId;
StepState fixResultState = ST_WAIT;
String fixPendingId;

static void fixReset(const String &title) {
  if (testMux) xSemaphoreTake(testMux, portMAX_DELAY);
  fixLineCount = 0;
  fixTitle = title;
  fixResult = "";
  fixResultState = ST_RUN;
  if (testMux) xSemaphoreGive(testMux);
}
static void fixLine(StepState st, const String &t) {
  if (testMux) xSemaphoreTake(testMux, portMAX_DELAY);
  if (fixLineCount < FIX_LINES) {
    fixLines[fixLineCount].st = st;
    strlcpy(fixLines[fixLineCount].text, t.c_str(), sizeof(fixLines[0].text));
    fixLineCount++;
  }
  if (testMux) xSemaphoreGive(testMux);
  Serial.printf("  [fix] %s %s\n", STEP_STATE[st], t.c_str());
}
static void fixUpdate(StepState st, const String &t) {  // change the last line
  if (testMux) xSemaphoreTake(testMux, portMAX_DELAY);
  if (fixLineCount > 0) {
    fixLines[fixLineCount - 1].st = st;
    strlcpy(fixLines[fixLineCount - 1].text, t.c_str(), sizeof(fixLines[0].text));
  }
  if (testMux) xSemaphoreGive(testMux);
}
static void fixDone(StepState st, const String &r) {
  if (testMux) xSemaphoreTake(testMux, portMAX_DELAY);
  fixResultState = st;
  fixResult = r;
  if (testMux) xSemaphoreGive(testMux);
  Serial.printf("  [fix] RESULT: %s\n", r.c_str());
}

static bool findingPresent(const String &id) {
  for (auto &f : findings)
    if (f.id == id) return true;
  return false;
}

// Run a fresh Wi-Fi scan cycle and wait for it to finish.
static bool rescanAndWait() {
  uint32_t target = cycleNo + (cycleActive ? 2 : 1);
  scanRequested = true;
  unsigned long t0 = millis();
  while ((cycleNo < target || cycleActive) && millis() - t0 < 120000) delay(200);
  return cycleNo >= target && !cycleActive;
}

static bool waitConnected(unsigned long ms) {
  unsigned long t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < ms) delay(200);
  return WiFi.status() == WL_CONNECTED;
}

static void verifyByTest(int stepIdx) {
  fixLine(ST_RUN, "Re-running the connection test...");
  testRunning = true;
  runConnectionTest();
  testRunning = false;
  StepState s = steps[stepIdx].st;
  fixUpdate(s == ST_OK ? ST_OK : s, String(STEP_NAME[stepIdx]) + ": " + STEP_STATE[s] + " - " + steps[stepIdx].value);
  if (s == ST_OK) fixDone(ST_OK, "Fixed - " + String(STEP_NAME[stepIdx]) + " now passes.");
  else fixDone(s == ST_FAIL ? ST_FAIL : ST_WARN, "Not fixed yet. " + String(steps[stepIdx].note));
}

static void autoReconnect() {
  if (!cfg.staSsid.length()) { fixLine(ST_FAIL, "No home Wi-Fi saved"); fixDone(ST_FAIL, "Enter your Wi-Fi on the main page first."); return; }
  fixLine(ST_RUN, "Disconnecting from " + cfg.staSsid);
  WiFi.disconnect();
  delay(800);
  fixUpdate(ST_OK, "Disconnected");
  fixLine(ST_RUN, "Connecting and requesting a new IP (DHCP)...");
  startStation();
  if (!waitConnected(25000)) { fixUpdate(ST_FAIL, "Could not connect"); fixDone(ST_FAIL, "Not fixed: check the password and signal (move closer to the router)."); return; }
  fixUpdate(ST_OK, "Connected: " + WiFi.localIP().toString() + fmt(" at %d dBm", WiFi.RSSI()));
  naptOk = WiFi.AP.enableNAPT(true);
  verifyByTest(2);
}

static void autoRoam() {
  fixLine(ST_RUN, "Looking for a stronger access point for " + cfg.staSsid);
  int cur = WiFi.RSSI();
  uint8_t curB[6];
  memcpy(curB, WiFi.BSSID() ? WiFi.BSSID() : (const uint8_t *)"\0\0\0\0\0\0", 6);
  int best = -1;
  for (size_t i = 0; i < aps.size(); i++) {
    if (aps[i].ssid != cfg.staSsid || memcmp(aps[i].bssid, curB, 6) == 0) continue;
    if (best < 0 || aps[i].avg() > aps[best].avg()) best = i;
  }
  if (best < 0 || aps[best].avg() < cur + 6) {
    fixUpdate(ST_WARN, fmt("No access point clearly stronger than the current one (%d dBm)", cur));
    fixDone(ST_WARN, "Nothing to switch to. Move the board closer, or follow the guided channel / width fixes.");
    return;
  }
  ApObs &b = aps[best];
  fixUpdate(ST_OK, fmt("Found %s on ch %d at %.0f dBm (now %d dBm)", macStr(b.bssid).c_str(), b.ch, b.avg(), cur));
  fixLine(ST_RUN, "Switching to it...");
  WiFi.disconnect();
  delay(500);
  WiFi.begin(cfg.staSsid.c_str(), cfg.staPass.c_str(), b.ch, b.bssid);
  if (!waitConnected(25000)) {
    fixUpdate(ST_FAIL, "Switch failed - returning to normal connection");
    startStation();
    waitConnected(20000);
    fixDone(ST_FAIL, "Not fixed: the stronger access point did not accept the connection.");
    return;
  }
  fixUpdate(ST_OK, fmt("Now on %s at %d dBm", WiFi.BSSIDstr().c_str(), WiFi.RSSI()));
  naptOk = WiFi.AP.enableNAPT(true);
  verifyByTest(2);
}

static void autoNapt() {
  fixLine(ST_RUN, "Turning on hotspot internet sharing...");
  if (WiFi.status() != WL_CONNECTED) { fixUpdate(ST_FAIL, "Board is not connected to your Wi-Fi"); fixDone(ST_FAIL, "Connect the board to your Wi-Fi first."); return; }
  startHotspot();
  delay(1000);
  if (naptOk) { fixUpdate(ST_OK, "Sharing is ON"); fixDone(ST_OK, "Fixed - reconnect your phone to the hotspot."); }
  else { fixUpdate(ST_FAIL, "Sharing could not start"); fixDone(ST_FAIL, "Not fixed - send me the serial log."); }
}

static void autoOta() {
  fixLine(ST_RUN, "Starting firmware update...");
  otaInstallReq = true;
  unsigned long t0 = millis();
  delay(500);
  while ((otaBusy || otaInstallReq) && millis() - t0 < 240000) {
    fixUpdate(ST_RUN, getOta());
    delay(500);
  }
  fixUpdate(ST_WARN, getOta());
  fixDone(ST_WARN, getOta());
}

static void guidedVerifyScan(const String &findingId) {
  fixLine(ST_RUN, "Scanning Wi-Fi again to check your change...");
  if (!rescanAndWait()) { fixUpdate(ST_FAIL, "Scan did not finish"); fixDone(ST_FAIL, "Try again."); return; }
  fixUpdate(ST_OK, fmt("Scan complete (cycle %u)", cycleNo));
  if (findingPresent(findingId)) {
    fixLine(ST_WARN, "The problem is still detected");
    fixDone(ST_WARN, "Not fixed yet. Check the setting was saved; routers can take 1-2 minutes to apply it.");
  } else {
    fixLine(ST_OK, "The problem is no longer detected");
    fixDone(ST_OK, "Fixed - confirmed by a new scan.");
  }
}

static void runFixJob() {
  String id = fixPendingId;
  fixJobId = id;
  if (id == "auto:reconnect") { fixReset("Reconnect & renew IP address"); autoReconnect(); }
  else if (id == "auto:roam") { fixReset("Switch to a stronger access point"); autoRoam(); }
  else if (id == "auto:napt") { fixReset("Turn on hotspot internet sharing"); autoNapt(); }
  else if (id == "auto:ota") { fixReset("Install firmware update"); autoOta(); }
  else if (id.startsWith("test:")) { int i = id.substring(5).toInt(); fixReset(String("Verify: ") + STEP_NAME[i]); verifyByTest(i); }
  else if (id == "router:identify") { runRouterIdentify(); }
  else if (id == "router:verify") { runRouterVerify(); }
  else if (id == "lan:scan") { lanScan(); }
  else if (id.startsWith("scan:")) { fixReset("Verify fix"); guidedVerifyScan(id.substring(5)); }
  else { fixReset("Unknown fix"); fixDone(ST_FAIL, "Unknown fix id"); }
}

// ---- build the list of recommended fixes from all current results
static String routerSteps(const String &setting) {
  String gw = WiFi.status() == WL_CONNECTED ? WiFi.gatewayIP().toString() : String("192.168.1.1");
  return "<ol><li>Open your router page: <a href='http://" + gw + "' target='_blank'>http://" + gw + "</a> and log in "
         "(admin password is often on the router's label).</li><li>Go to <b>Wireless / Wi-Fi &rarr; 2.4 GHz</b>.</li><li>" +
         setting + "</li><li>Tap <b>Save / Apply</b>. Wi-Fi drops for ~30 s.</li><li>Come back and tap <b>I've done it - verify</b>.</li></ol>";
}

static void buildFixes(std::vector<FixItem> &out) {
  out.clear();
  auto add = [&](const String &id, Sev s, const String &t, const String &why, const String &how, bool a) {
    FixItem f; f.id = id; f.sev = s; f.title = t; f.why = why; f.how = how; f.autoFix = a; out.push_back(f);
  };
  bool up = WiFi.status() == WL_CONNECTED;

  // board / connection
  if (cfg.staSsid.length() && !up)
    add("auto:reconnect", SEV_CRIT, "Reconnect to " + cfg.staSsid, "The board is not connected to your Wi-Fi.", "", true);
  if (up && !naptOk)
    add("auto:napt", SEV_WARN, "Share internet through the hotspot", "Phones on NetDiag have no internet.", "", true);
  if (up && WiFi.RSSI() < -75) {
    bool better = false;
    for (auto &a : aps)
      if (a.ssid == cfg.staSsid && a.avg() >= WiFi.RSSI() + 6 && (!WiFi.BSSID() || memcmp(a.bssid, WiFi.BSSID(), 6))) better = true;
    if (better) add("auto:roam", SEV_WARN, "Switch to a stronger access point", fmt("Board signal is %d dBm; a stronger AP with the same name is nearby.", WiFi.RSSI()), "", true);
  }
  if (otaLatestVer.length() && verNum(otaLatestVer) > verNum(FW_VERSION))
    add("auto:ota", SEV_INFO, "Install firmware v" + otaLatestVer, "A newer version is available.", "", true);
  if (!cfg.customPass)
    add("guide:pass", SEV_WARN, "Set your own NetDiag password", "The default password is public in the GitHub code.",
        "<ol><li>Open the <a href='/'>main page</a>.</li><li>Scroll to <b>Admin / hotspot password</b>.</li><li>Enter a new password twice and tap <b>Change</b>.</li></ol>", false);

  // connection-test results
  if (testCount) {
    for (int i = 0; i < NSTEPS; i++) {
      if (steps[i].st != ST_WARN && steps[i].st != ST_FAIL) continue;
      Sev s = steps[i].st == ST_FAIL ? SEV_CRIT : SEV_WARN;
      String how;
      if (i == 0 || i == 2) how = "<ol><li>Try the automatic <b>Reconnect</b> fix, or move the board closer to the router.</li>"
                                  "<li>Apply the channel / 20 MHz fixes below if listed.</li><li>Tap verify.</li></ol>";
      else if (i == 3) how = routerSteps("Find <b>DNS</b> (often under Internet/WAN or DHCP) and set <b>1.1.1.1</b> and <b>8.8.8.8</b>.");
      else if (i == 4 || i == 5) how = "<ol><li>Restart the router (power off 30 s).</li><li>If it continues, contact your ISP with this result.</li><li>Tap verify.</li></ol>";
      else if (i == 6) how = routerSteps("Find <b>UPnP</b> (often under Advanced/NAT) and enable it. If you have two routers, set one to <b>bridge/AP mode</b>.");
      else how = "<ol><li>Move the board closer to the router and tap verify.</li></ol>";
      add("test:" + String(i), s, String(STEP_NAME[i]) + ": " + STEP_STATE[steps[i].st], String(steps[i].value) + ". " + steps[i].note, how, false);
      if ((i == 0 || i == 1 || i == 2) && cfg.staSsid.length())
        add("auto:reconnect", s, "Reconnect & renew IP address", "Often clears a stuck or poor connection.", "", true);
    }
  }

  // Wi-Fi scan findings (warnings and critical)
  for (auto &f : findings) {
    if (f.sev < SEV_WARN && f.id != "nohome") continue;
    String how;
    String id = f.id;
    if (id.startsWith("nonstd:") || id.startsWith("chan:")) {
      int ch = 0;
      int p = f.action.indexOf("channel ");
      if (id.startsWith("chan:")) p = f.action.indexOf("-> ");
      if (p >= 0) ch = f.action.substring(p + (id.startsWith("chan:") ? 3 : 8)).toInt();
      how = routerSteps(fmt("Set <b>Channel</b> to <b>%d</b> (not Auto).", ch));
    } else if (id.startsWith("width:")) how = routerSteps("Set <b>Channel width / Bandwidth</b> to <b>20 MHz</b>.");
    else if (id.startsWith("open:") || id.startsWith("wep:") || id.startsWith("wpa1:") || id.startsWith("mixed:") || id.startsWith("tkip:"))
      how = routerSteps("Set <b>Security</b> to <b>WPA2-PSK</b> (or WPA2/WPA3) and <b>Encryption</b> to <b>AES</b>.");
    else if (id.startsWith("wps:")) how = routerSteps("Find <b>WPS</b> and set it to <b>Disabled</b>.");
    else if (id.startsWith("legacy:")) how = routerSteps("Set <b>Mode</b> to <b>802.11 b/g/n</b> (or b/g/n/ax).");
    else if (id.startsWith("guestsec:")) how = routerSteps("Open <b>Guest network</b>: set a WPA2 password and enable <b>client isolation</b>.");
    else if (id.startsWith("extssid:") || id.startsWith("authdiff:"))
      how = "<ol><li>Open the extender's settings page (see its label or app).</li><li>Set the same <b>network name, password and security</b> as the main router.</li><li>Save, wait 1 minute, tap verify.</li></ol>";
    else if (id == "nohome") how = "<ol><li>On the <a href='/'>main page</a>, enter your network names under <b>Your networks</b> and tap Save.</li></ol>";
    else how = "<ol><li>" + htmlEsc(f.action) + "</li><li>Tap verify.</li></ol>";
    add("scan:" + id, f.sev, f.test + ": " + f.finding, f.evidence, how, false);
  }

  // de-duplicate (reconnect can be added twice) and sort by severity
  std::vector<FixItem> uniq;
  for (auto &f : out) {
    bool dup = false;
    for (auto &u : uniq) if (u.id == f.id) dup = true;
    if (!dup) uniq.push_back(f);
  }
  std::stable_sort(uniq.begin(), uniq.end(), [](const FixItem &a, const FixItem &b) { return a.sev > b.sev; });
  out = uniq;
}

static const char *FIX_CSS =
    "<style>body{font-family:sans-serif;margin:0;background:linear-gradient(#0b2a6b,#061538);color:#fff;min-height:100vh}"
    "h2{font-weight:300;margin:0;padding:16px}.c{background:#ffffff12;margin:10px;padding:12px;border-radius:10px}"
    ".t{font-size:16px}.w{font-size:12px;color:#c8d3f0;margin:6px 0}.b{display:inline-block;font-size:11px;padding:2px 8px;"
    "border-radius:10px;margin-right:6px}.CRIT{background:#ff7d7d;color:#300}.WARN{background:#ffd27a;color:#330}"
    ".INFO{background:#7dc8ff;color:#023}button{padding:10px 18px;border-radius:20px;border:0;font-size:15px;margin-top:6px}"
    ".go{background:#7dffa1;color:#032}.v{background:#fff;color:#0b2a6b}details{font-size:13px;color:#dde}a{color:#9fc3ff}"
    "ol{padding-left:20px}.row{border-top:1px solid #ffffff22;padding:10px 16px;font-size:14px}.s{float:right;font-weight:bold}"
    ".OK{color:#7dffa1}.RUN{color:#7dc8ff}.FAIL{color:#ff7d7d}.WARNs{color:#ffd27a}</style>";

static void handleFixesPage() {
  if (!auth()) return;
  std::vector<FixItem> list;
  buildFixes(list);
  String h;
  h.reserve(8000);
  h += F("<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Fixes</title>");
  h += FIX_CSS;
  h += "</head><body><h2>Recommended Fixes</h2>";
  if (testRunning || fixRunning) h += "<p class='c'>A test or fix is running - <a href='/fix'>see progress</a></p>";
  if (!testCount) h += "<p class='c'>Tip: run <a href='/test'>Test Internet Connection</a> first to include connection fixes.</p>";
  if (list.empty()) h += "<p class='c'>No problems to fix right now.</p>";
  for (auto &f : list) {
    const char *sv = f.sev == SEV_CRIT ? "CRIT" : f.sev == SEV_WARN ? "WARN" : "INFO";
    h += "<div class='c'><span class='b " + String(sv) + "'>" + (f.sev == SEV_CRIT ? "Critical" : f.sev == SEV_WARN ? "Warning" : "Info") +
         "</span><span class='b' style='background:#ffffff22'>" + (f.autoFix ? "Automatic" : "Guided") + "</span>";
    h += "<div class='t'>" + htmlEsc(f.title) + "</div><div class='w'>" + htmlEsc(f.why) + "</div>";
    h += "<form method='post' action='/fix'><input type='hidden' name='id' value='" + htmlEsc(f.id) + "'>";
    if (f.autoFix) h += "<button class='go'>Fix now</button>";
    else if (f.id.startsWith("guide:")) h += "";
    else {
      h += "<details><summary>Show me how</summary>" + f.how + "</details><button class='v'>I've done it - verify</button>";
    }
    if (f.id.startsWith("guide:")) h += "<details open><summary>How</summary>" + f.how + "</details>";
    h += "</form></div>";
  }
  h += "<p style='padding:0 16px'><a href='/'>&larr; Main page</a> &nbsp; <a href='/test'>Connection test</a></p></body></html>";
  server.send(200, "text/html", h);
}

static void handleFixRun() {
  if (!auth()) return;
  String id = server.arg("id");
  if (!fixRunning && !testRunning && !fixRequested && id.length()) {
    fixPendingId = id;
    fixReset("Starting...");
    fixRequested = true;
  }
  server.sendHeader("Location", "/fix");
  server.send(303);
}

static void handleFixProgress() {
  if (!auth()) return;
  String h;
  h.reserve(4000);
  bool running = fixRunning || fixRequested;
  h += F("<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>");
  if (running) h += F("<meta http-equiv='refresh' content='2'>");
  h += "<title>Fixing</title>";
  h += FIX_CSS;
  h += "</head><body>";
  if (testMux) xSemaphoreTake(testMux, portMAX_DELAY);
  h += "<h2>" + htmlEsc(fixTitle.length() ? fixTitle : String("No fix started")) + "</h2>";
  static const char *cls[] = {"", "RUN", "OK", "WARNs", "FAIL", ""};
  for (int i = 0; i < fixLineCount; i++)
    h += "<div class='row'><span class='s " + String(cls[fixLines[i].st]) + "'>" + STEP_STATE[fixLines[i].st] + "</span>" +
         htmlEsc(fixLines[i].text) + "</div>";
  if (running) h += "<p style='padding:0 16px'>Working... this page updates itself.</p>";
  else if (fixResult.length()) {
    const char *c = fixResultState == ST_OK ? "OK" : fixResultState == ST_FAIL ? "FAIL" : "WARNs";
    h += "<div class='c'><div class='t " + String(c) + "'>" + (fixResultState == ST_OK ? "&#10004; " : "&#9888; ") + htmlEsc(fixResult) + "</div></div>";
  }
  if (testMux) xSemaphoreGive(testMux);
  h += "<p style='padding:0 16px'><a href='/fixes'>&larr; All fixes</a> &nbsp; <a href='/'>Main page</a></p></body></html>";
  server.send(200, "text/html", h);
}

// ============================================================ ROUTER ACCESS (v3.3)
// Talks only to YOUR OWN router (the gateway reached through your Wi-Fi).
// Step 1: identify brand + login type by reading the gateway page.
// Step 2: check whether the router still uses a public factory-default login
//         (a security finding in itself). This tries only the small set of
//         well-known factory defaults for HTTP Basic auth - not a password list.
// Step 3: if that fails, you enter the router's admin user/password; it is
//         stored on the board's flash only, never in GitHub.
// Reading/identifying only. Changing router settings is model-specific and will
// always ask for confirmation (added per router model later).

struct RouterCred { const char *user; const char *pass; };
// Public factory defaults, for "is your router still on its default login?".
static const RouterCred FACTORY_DEFAULTS[] = {
    {"admin", "admin"}, {"admin", "password"}, {"admin", ""}, {"admin", "1234"}, {"user", "user"},
};
static const int NDEFAULTS = sizeof(FACTORY_DEFAULTS) / sizeof(FACTORY_DEFAULTS[0]);

static String guessBrand(const String &server, const String &body) {
  String s = server + " " + body;
  s.toLowerCase();
  struct { const char *k; const char *name; } T[] = {
      {"tp-link", "TP-Link"}, {"tplink", "TP-Link"}, {"archer", "TP-Link"}, {"d-link", "D-Link"},
      {"dlink", "D-Link"}, {"netgear", "Netgear"}, {"huawei", "Huawei"}, {"asus", "ASUS"},
      {"tenda", "Tenda"}, {"linksys", "Linksys"}, {"zyxel", "Zyxel"}, {"mikrotik", "MikroTik"},
      {"routeros", "MikroTik"}, {"openwrt", "OpenWrt"}, {"ubiquiti", "Ubiquiti"}, {"unifi", "Ubiquiti"},
      {"fritz", "AVM FRITZ!Box"}, {"technicolor", "Technicolor"}, {"sagemcom", "Sagemcom"},
      {"etisalat", "e& (Etisalat)"}, {"du ", "du"},
  };
  for (auto &t : T)
    if (s.indexOf(t.k) >= 0) return t.name;
  return "Unknown";
}

// GET gateway path; returns HTTP status, fills server header + a little body.
// Which device to manage: a saved router IP if set, else the gateway.
static String routerHost() {
  String h = prefs.getString("rhost", "");
  h.trim();
  if (h.length()) return h;
  return WiFi.status() == WL_CONNECTED ? WiFi.gatewayIP().toString() : String("192.168.1.1");
}

static int gwGet(const String &path, const char *user, const char *pass, String &server, String &body) {
  WiFiClient wc;
  HTTPClient http;
  String url = "http://" + routerHost() + path;
  if (!http.begin(wc, url)) return -1;
  http.setTimeout(6000);
  http.setConnectTimeout(6000);
  const char *hdrs[] = {"Server", "WWW-Authenticate"};
  http.collectHeaders(hdrs, 2);
  if (user) http.setAuthorization(user, pass ? pass : "");
  int code = http.GET();
  if (code > 0) {
    server = http.header("Server");
    if (!server.length()) server = http.header("WWW-Authenticate");
    WiFiClient *st = http.getStreamPtr();
    unsigned long t0 = millis();
    while (body.length() < 2500 && millis() - t0 < 3000) {
      if (st->available()) body += (char)st->read();
      else if (!st->connected()) break;
      else delay(2);
    }
  }
  http.end();
  return code;
}

static void runRouterIdentify() {
  fixReset("Identify router & check access");
  if (WiFi.status() != WL_CONNECTED) { fixDone(ST_FAIL, "Connect the board to your Wi-Fi first."); return; }
  String gw = routerHost();
  fixLine(ST_RUN, "Contacting the router at " + gw + " ...");
  String server, body;
  int code = gwGet("/", nullptr, nullptr, server, body);
  if (code <= 0) {
    fixUpdate(ST_FAIL, "No HTTP reply from " + gw);
    fixDone(ST_WARN, "The router may use HTTPS or a non-standard page. Open http://" + gw + " yourself and tell me the brand.");
    return;
  }
  String brand = guessBrand(server, body);
  fixUpdate(ST_OK, "Reached router. Brand: " + brand + (server.length() ? " (" + server + ")" : ""));
  prefs.putString("rbrand", brand);

  bool basic = (code == 401);
  bool form = (!basic && (body.indexOf("password") >= 0 || body.indexOf("Password") >= 0 || body.indexOf("login") >= 0));

  if (basic) {
    fixLine(ST_RUN, "Checking whether the router still uses a factory-default password...");
    int hit = -1;
    for (int i = 0; i < NDEFAULTS; i++) {
      String s2, b2;
      int c2 = gwGet("/", FACTORY_DEFAULTS[i].user, FACTORY_DEFAULTS[i].pass, s2, b2);
      if (c2 > 0 && c2 != 401) { hit = i; break; }
      delay(300);
    }
    if (hit >= 0) {
      prefs.putString("ruser", FACTORY_DEFAULTS[hit].user);
      prefs.putString("rpass", FACTORY_DEFAULTS[hit].pass);
      prefs.putBool("rok", true);
      fixUpdate(ST_WARN, fmt("Logged in with factory default: %s / %s", FACTORY_DEFAULTS[hit].user,
                             strlen(FACTORY_DEFAULTS[hit].pass) ? FACTORY_DEFAULTS[hit].pass : "(blank)"));
      fixDone(ST_WARN, "SECURITY RISK: your router still uses its factory login, so anyone nearby can get in. "
                       "Change the router admin password now. Access is configured for NetDiag in the meantime.");
    } else {
      prefs.putBool("rok", false);
      fixUpdate(ST_OK, "Good - the router is NOT on a factory-default password.");
      fixDone(ST_WARN, "NetDiag could not log in automatically. Enter your router admin password below so it can manage the router.");
    }
  } else if (form) {
    prefs.putBool("rok", false);
    fixLine(ST_WARN, brand + " uses a web login form, not a simple login box.");
    fixDone(ST_WARN, "Automatic login for this type needs a model adapter for " + brand +
                         ". Enter your router password below and I'll add support for this model next.");
  } else {
    fixDone(ST_WARN, fmt("Router page returned HTTP %d. Enter your router password below, or tell me the brand.", code));
  }
}

static void runRouterVerify() {
  fixReset("Verify router login");
  String u = prefs.getString("ruser", ""), p = prefs.getString("rpass", "");
  if (!u.length()) { fixDone(ST_FAIL, "No router username saved."); return; }
  if (WiFi.status() != WL_CONNECTED) { fixDone(ST_FAIL, "Connect the board to your Wi-Fi first."); return; }
  fixLine(ST_RUN, "Logging in to the router as " + u + " ...");
  String s, b;
  int code = gwGet("/", u.c_str(), p.c_str(), s, b);
  if (code > 0 && code != 401) {
    prefs.putBool("rok", true);
    fixUpdate(ST_OK, fmt("Login accepted (HTTP %d)", code));
    fixDone(ST_OK, "Router access is configured. NetDiag can now read router pages (management features come next, per model).");
  } else {
    prefs.putBool("rok", false);
    fixUpdate(ST_FAIL, code == 401 ? "Rejected (wrong username or password)" : fmt("No login (HTTP %d)", code));
    fixDone(ST_FAIL, "Check the router admin username and password and try again. They are on the router's label if unchanged.");
  }
}

static void handleRouterPage() {
  if (!auth()) return;
  String gwReal = WiFi.status() == WL_CONNECTED ? WiFi.gatewayIP().toString() : String("not connected");
  String gw = routerHost();
  String brand = prefs.getString("rbrand", "");
  String u = prefs.getString("ruser", "");
  bool rok = prefs.getBool("rok", false);
  String h;
  h.reserve(4000);
  h += F("<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Router Access</title>");
  h += FIX_CSS;
  h += "</head><body><h2>Router Access</h2>";
  h += "<div class='c'><div class='w'>Managing router at: <b>" + htmlEsc(gw) + "</b><br>This network's gateway: " + htmlEsc(gwReal) + "</div>";
  h += "<form method='post' action='/router/creds'><div class='w'>Router IP to manage (type 192.168.1.1 for the main router):</div>"
       "<input name='host' value='" + htmlEsc(gw) + "' style='width:60%;padding:6px'> <button class='v'>Set</button></form>";
  h += "<div class='w'>";
  if (brand.length()) h += "<br>Detected brand: <b>" + htmlEsc(brand) + "</b>";
  h += "<br>Access: <b>" + String(rok ? "configured" : (u.length() ? "login saved, not verified" : "not set up")) + "</b></div>";
  if (WiFi.status() != WL_CONNECTED)
    h += "<div class='w'>Connect the board to your Wi-Fi (main page) before setting up router access.</div>";
  h += "<form method='post' action='/fix'><input type='hidden' name='id' value='router:identify'>"
       "<button class='go'>Identify &amp; check access</button></form>";
  h += "<div class='w'>Tries your router's factory-default login (a security check). If it fails, enter your own password below.</div></div>";

  if (!cfg.customPass)
    h += "<div class='c' style='background:#ffd27a22'>Set your own NetDiag password on the main page before saving a router login.</div>";
  h += "<div class='c'><form method='post' action='/router/creds'><div class='t'>Router admin login</div>"
       "<div class='w'>Stored on the board only, never in GitHub.</div>"
       "Username<br><input name='u' value='" + htmlEsc(u) + "' style='width:90%;padding:6px'><br>"
       "Password<br><input name='p' type='password' placeholder='(unchanged if empty)' style='width:90%;padding:6px'><br>"
       "<button class='v'>Save &amp; verify login</button></form></div>";
  h += "<p style='padding:0 16px'><a href='/fixes'>&larr; Fixes</a> &nbsp; <a href='/'>Main page</a></p></body></html>";
  server.send(200, "text/html", h);
}


// Capture a router page's raw code (for building a model adapter). Reads the
// user's OWN router with the saved login. Shows status, key headers and body.
static String gwCapture(const String &path, int &code, String &hdr) {
  WiFiClient wc;
  HTTPClient http;
  String url = "http://" + routerHost() + path;
  code = -1;
  hdr = "";
  if (!http.begin(wc, url)) return "";
  http.setTimeout(9000);
  http.setConnectTimeout(6000);
  const char *hs[] = {"Server", "Set-Cookie", "WWW-Authenticate", "Location", "Content-Type"};
  http.collectHeaders(hs, 5);
  String u = prefs.getString("ruser", ""), pw = prefs.getString("rpass", "");
  if (u.length()) http.setAuthorization(u.c_str(), pw.c_str());
  code = http.GET();
  String body;
  if (code > 0) {
    for (int i = 0; i < 5; i++)
      if (http.header(hs[i]).length()) hdr += String(hs[i]) + ": " + http.header(hs[i]) + "\n";
    WiFiClient *st = http.getStreamPtr();
    unsigned long t0 = millis();
    while (body.length() < 14000 && millis() - t0 < 7000) {
      if (st->available()) body += (char)st->read();
      else if (!st->connected()) break;
      else delay(2);
    }
  }
  http.end();
  return body;
}

static void handleRouterCapture() {
  if (!auth()) return;
  if (server.arg("host").length()) { String rh = server.arg("host"); rh.trim(); prefs.putString("rhost", rh); }
  String path = server.arg("path");
  path.trim();
  if (!path.length()) path = "/login.html";
  if (path[0] != '/') path = "/" + path;
  String h;
  h.reserve(16000);
  h += F("<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Capture</title>");
  h += FIX_CSS;
  h += "<style>textarea{width:95%;height:40vh;font-family:monospace;font-size:11px}</style></head><body>";
  h += "<h2>Router page capture</h2>";
  h += "<form method='get' action='/router/capture' style='padding:0 16px'>Router IP:<br>"
       "<input name='host' value='" + htmlEsc(routerHost()) + "' style='width:70%;padding:6px'><br>Path:<br>"
       "<input name='path' value='" + htmlEsc(path) + "' style='width:70%;padding:6px'> <button class='go'>Fetch</button></form>";
  if (WiFi.status() != WL_CONNECTED) { h += "<p class='c'>Connect the board to your Wi-Fi first.</p>"; }
  else {
    int code = -1;
    String hdr;
    String body = gwCapture(path, code, hdr);
    h += "<div class='c'>HTTP status: <b>" + String(code) + "</b><br><pre style='white-space:pre-wrap'>" + htmlEsc(hdr) + "</pre></div>";
    h += "<p style='padding:0 16px'>Select all and copy this to Claude:</p>";
    h += "<div style='padding:0 16px'><textarea readonly>" + htmlEsc(body) + "</textarea></div>";
    h += "<p style='padding:8px 16px;font-size:12px;color:#c8d3f0'>" + String(body.length()) +
         " bytes shown (truncated at ~14 KB). Useful paths: /login.html, then the Wi-Fi settings page once logged in.</p>";
  }
  h += "<p style='padding:0 16px'><a href='/router'>&larr; Router access</a></p></body></html>";
  server.send(200, "text/html", h);
}

static void handleRouterCreds() {
  if (!auth()) return;
  if (!cfg.customPass) { server.send(403, "text/plain", "Set your own NetDiag password first (main page)."); return; }
  if (server.arg("host").length()) { String rh = server.arg("host"); rh.trim(); prefs.putString("rhost", rh); prefs.putString("rbrand", ""); }
  String u = server.arg("u"), p = server.arg("p");
  u.trim();
  if (!u.length()) { server.sendHeader("Location", "/router"); server.send(303); return; }
  prefs.putString("ruser", u);
  if (p.length() || server.arg("p").length()) prefs.putString("rpass", p);
  prefs.putBool("rok", false);
  if (!fixRunning && !fixRequested) { fixPendingId = "router:verify"; fixReset("Verify router login"); fixRequested = true; }
  server.sendHeader("Location", "/fix");
  server.send(303);
}
// ============================================================ LAN DEVICE SCAN (v3.5)
// Finds devices on your network, identifies maker (MAC) and type (open ports),
// flags the printer and a possible second DHCP/router. Read-only.
struct Dev {
  IPAddress ip;
  uint8_t mac[6] = {0};
  bool hasMac = false;
  uint16_t ports = 0;  // bitmask of PORT_LIST indices
  String kind;
};
static const uint16_t PORT_LIST[] = {80, 443, 9100, 631, 515, 22, 445, 53};
static const int NPORTS = sizeof(PORT_LIST) / sizeof(PORT_LIST[0]);
std::vector<Dev> devices;
uint32_t lanScanCount = 0;

static int findDev(const IPAddress &ip) {
  for (size_t i = 0; i < devices.size(); i++)
    if (devices[i].ip == ip) return (int)i;
  return -1;
}

// Collect current ARP table entries into the device list.
static void readArpTable() {
  for (size_t i = 0; i < 16; i++) {
    ip4_addr_t *ipaddr = nullptr;
    struct netif *nif = nullptr;
    struct eth_addr *eth = nullptr;
    if (etharp_get_entry(i, &ipaddr, &nif, &eth) && ipaddr && eth) {
      IPAddress ip(ip4_addr_get_u32(ipaddr));
      int d = findDev(ip);
      if (d < 0) { Dev nd; nd.ip = ip; devices.push_back(nd); d = devices.size() - 1; }
      memcpy(devices[d].mac, eth->addr, 6);
      devices[d].hasMac = true;
    }
  }
}

static String portName(int idx) {
  switch (PORT_LIST[idx]) {
    case 80: case 8080: return "web";
    case 443: return "https";
    case 9100: return "raw-print";
    case 631: return "ipp-print";
    case 515: return "lpr-print";
    case 22: return "ssh";
    case 445: return "smb";
    case 554: return "rtsp";
    case 53: return "dns";
  }
  return "";
}

static String classify(const Dev &d, const IPAddress &gw) {
  bool print = (d.ports & (1 << 2)) || (d.ports & (1 << 3)) || (d.ports & (1 << 4));  // 9100/631/515
  bool web = (d.ports & 1) || (d.ports & 2);                                          // 80/443
  if (print) return "Printer";
  if (d.ip == gw) return "Router (gateway)";
  if (d.ports & (1 << 6)) return "PC / NAS (file share)";   // 445
  if ((d.ports & (1 << 7)) && web) return "Router / AP";    // 53 + web
  if (d.ports & (1 << 5)) return "Linux / NAS (SSH)";       // 22
  if (web) return "Device with web page";
  return "Device";
}

static void lanScan() {
  fixReset("Scanning your network for devices");
  if (WiFi.status() != WL_CONNECTED) { fixDone(ST_FAIL, "Connect the board to your Wi-Fi first."); return; }
  devices.clear();
  lanScanCount++;
  IPAddress ip = WiFi.localIP(), gw = WiFi.gatewayIP(), mask = WiFi.subnetMask();
  uint32_t net = (uint32_t)ip & (uint32_t)mask;
  struct netif *nif = netif_default;
  if (!nif) { fixDone(ST_FAIL, "Network interface not ready - try again in a few seconds."); return; }
  fixLine(ST_RUN, "Pinging addresses 1-254 on " + IPAddress(net).toString() + "/24 ...");

  // ARP-sweep in small batches so entries stay in the (small) ARP table while read.
  for (int base = 1; base <= 254; base += 6) {
    for (int k = 0; k < 6 && base + k <= 254; k++) {
      IPAddress t(net | htonl(base + k));
      if (t == ip) continue;
      ip4_addr_t a;
      a.addr = (uint32_t)t;
      if (nif) etharp_request(nif, &a);
    }
    delay(180);
    readArpTable();
    if ((base / 6) % 8 == 0) fixUpdate(ST_RUN, fmt("Pinging... %d/254, %d devices so far", base, (int)devices.size()));
    pollSerial();
  }
  readArpTable();
  fixUpdate(ST_OK, fmt("Found %d devices. Checking what each one is...", (int)devices.size()));

  // Fingerprint by probing a few common ports on each live device.
  // Short timeouts and frequent yields so the web server/hotspot stay alive.
  if (devices.size() > 80) devices.resize(80);
  int done = 0;
  for (auto &d : devices) {
    for (int p = 0; p < NPORTS; p++) {
      WiFiClient c;
      if (c.connect(d.ip, PORT_LIST[p], 180)) { d.ports |= (1 << p); c.stop(); }
      delay(5);  // yield so loop() can serve the page
    }
    d.kind = classify(d, gw);
    if (++done % 3 == 0) fixUpdate(ST_RUN, fmt("Identifying... %d/%d", done, (int)devices.size()));
    pollSerial();
    delay(10);
  }

  // Summary
  int printers = 0, dhcpish = 0;
  String printerIp;
  for (auto &d : devices) {
    if (d.kind == "Printer") { printers++; printerIp = d.ip.toString(); }
    if (d.ip != gw && (d.ports & (1 << 7))) dhcpish++;  // another host answering DNS: maybe a 2nd router
  }
  std::sort(devices.begin(), devices.end(), [](const Dev &a, const Dev &b) { return (uint32_t)a.ip < (uint32_t)b.ip; });

  String msg = fmt("%d devices found. ", (int)devices.size());
  if (printers) msg += "Printer at " + printerIp + " - add it to your phone by this IP. ";
  else msg += "No printer detected (it may be off, or only reachable on another network). ";
  if (dhcpish) msg += fmt("%d other device(s) answer DNS - possible second router; keep ONE DHCP (bridge the others).", dhcpish);
  fixLine(printers ? ST_OK : ST_WARN, msg);
  fixDone(printers ? ST_OK : ST_WARN, msg);
}

static void handleDevicesPage() {
  if (!auth()) return;
  IPAddress gw = WiFi.gatewayIP();
  String h;
  h.reserve(6000);
  h += F("<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Devices</title>");
  h += FIX_CSS;
  h += "<style>table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:6px;border-top:1px solid #ffffff22;text-align:left}</style>";
  h += "</head><body><h2>Devices on your network</h2>";
  h += "<form method='post' action='/fix'><input type='hidden' name='id' value='lan:scan'><div style='padding:0 16px'>"
       "<button class='go'>Scan now</button></div></form>";
  if (!lanScanCount) h += "<p style='padding:0 16px'>Tap Scan to list every device, its maker and type.</p>";
  else {
    h += "<table><tr><th>IP</th><th>Maker</th><th>Type</th><th>Services</th></tr>";
    for (auto &d : devices) {
      String svc;
      for (int p = 0; p < NPORTS; p++)
        if (d.ports & (1 << p)) { if (svc.length()) svc += " "; svc += portName(p); }
      String v = d.hasMac ? vendorFromMac(d.mac) : String("?");
      h += "<tr><td>" + d.ip.toString() + (d.ip == gw ? " *" : "") + "</td><td>" + htmlEsc(v) + "</td><td>" +
           htmlEsc(d.kind) + "</td><td>" + htmlEsc(svc) + "</td></tr>";
    }
    h += "</table><p style='padding:8px 16px;font-size:12px;color:#c8d3f0'>* = your router. A scan may miss sleeping devices; scan twice to be sure. "
         "To print, add a device of type Printer to your phone by its IP address.</p>";
  }
  h += "<p style='padding:0 16px'><a href='/fixes'>&larr; Fixes</a> &nbsp; <a href='/'>Main page</a></p></body></html>";
  server.send(200, "text/html", h);
}

static void startWeb() {
  server.on("/", HTTP_GET, handleRoot);
  server.on("/scan", HTTP_POST, handleScan);
  server.on("/settings", HTTP_POST, handleSettings);
  server.on("/wifi", HTTP_POST, handleWifi);
  server.on("/password", HTTP_POST, handlePassword);
  server.on("/reset", HTTP_POST, handleReset);
  server.on("/api/report", HTTP_GET, handleJson);
  server.on("/test", HTTP_GET, handleTestPage);
  server.on("/test", HTTP_POST, handleTestRun);
  server.on("/update", HTTP_GET, handleUpdatePage);
  server.on("/update", HTTP_POST, handleUploadDone, handleUploadData);
  server.on("/ota", HTTP_POST, handleOtaAction);
  server.on("/rollback", HTTP_POST, handleRollback);
  server.on("/api/info", HTTP_GET, handleInfo);
  server.on("/fixes", HTTP_GET, handleFixesPage);
  server.on("/fix", HTTP_POST, handleFixRun);
  server.on("/fix", HTTP_GET, handleFixProgress);
  server.on("/router", HTTP_GET, handleRouterPage);
  server.on("/router/creds", HTTP_POST, handleRouterCreds);
  server.on("/router/capture", HTTP_GET, handleRouterCapture);
  server.on("/devices", HTTP_GET, handleDevicesPage);
  server.on("/remote", HTTP_POST, handleRemote);
  server.onNotFound([]() { server.send(404, "text/plain", "Not found"); });
  server.begin();
}

// ------------------------------------------------------------ serial commands
static void printHelp() {
  Serial.println("\nCommands:");
  Serial.println("  scan               run a diagnostic cycle now");
  Serial.println("  home SSID1,SSID2   set your networks (saved in flash)");
  Serial.println("  home -             clear your networks");
  Serial.println("  rounds N           scans per cycle (1-10)");
  Serial.println("  interval S         seconds between cycles (10-3600)");
  Serial.println("  raw on|off         access point table");
  Serial.println("  json on|off        machine-readable report");
  Serial.println("  wifi               show hotspot / web access details");
  Serial.println("  wifi SSID|PASSWORD save a network and join it (up to 5 saved)");
  Serial.println("  wifi -             forget all saved networks");
  Serial.println("  wifi ble           start Bluetooth Wi-Fi setup now");
  Serial.println("  pass NEWPASSWORD   set hotspot + web password (8+ chars)");
  Serial.println("  reset              clear persistence history");
  Serial.println("  test               run the internet connection test");
  Serial.println("  ota                check GitHub for new firmware");
  Serial.println("  ota install        download and install it");
  Serial.println("  remote             remote access status and device key");
  Serial.println("  remote on|off      turn remote access on or off");
  Serial.println("  remote host NAME   set the Worker address");
  Serial.println("  remote newkey      make a new device key");
  Serial.println("  status             show settings");
}

static void printStatus() {
  Serial.printf("\nfw %s | home=%s | rounds=%u | interval=%us | raw=%s | json=%s | cycles=%u\n",
                FW_VERSION, cfg.home.length() ? cfg.home.c_str() : "(none)", cfg.rounds, cfg.intervalS,
                cfg.raw ? "on" : "off", cfg.json ? "on" : "off", cycleNo);
}

String lineBuf;

static void handleCommand(String line) {
  line.trim();
  if (!line.length()) return;
  int sp = line.indexOf(' ');
  String cmd = sp < 0 ? line : line.substring(0, sp);
  String arg = sp < 0 ? String("") : line.substring(sp + 1);
  cmd.toLowerCase();
  arg.trim();

  if (cmd == "help") printHelp();
  else if (cmd == "status") printStatus();
  else if (cmd == "scan") { scanRequested = true; Serial.println("> cycle queued"); }
  else if (cmd == "home") {
    cfg.home = (arg == "-") ? String("") : arg;
    parseHomeList();
    saveSettings();
    Serial.printf("> your networks: %s\n", cfg.home.length() ? cfg.home.c_str() : "(none)");
    history.clear();
  } else if (cmd == "rounds") {
    int v = arg.toInt();
    if (v >= 1 && v <= 10) { cfg.rounds = v; saveSettings(); Serial.printf("> rounds=%d\n", v); }
    else Serial.println("> rounds must be 1-10");
  } else if (cmd == "interval") {
    int v = arg.toInt();
    if (v >= 10 && v <= 3600) { cfg.intervalS = v; saveSettings(); Serial.printf("> interval=%ds\n", v); }
    else Serial.println("> interval must be 10-3600");
  } else if (cmd == "raw") { cfg.raw = (arg == "on"); saveSettings(); Serial.printf("> raw %s\n", cfg.raw ? "on" : "off"); }
  else if (cmd == "json") { cfg.json = (arg == "on"); saveSettings(); Serial.printf("> json %s\n", cfg.json ? "on" : "off"); }
  else if (cmd == "reset") { history.clear(); lastChannel.clear(); cycleNo = 0; Serial.println("> history cleared"); }
  else if (cmd == "ota") { if (arg == "install") otaInstallReq = true; else otaCheckReq = true; }
  else if (cmd == "test") { if (!testRunning) testRequested = true; Serial.println("> connection test queued"); }
  else if (cmd == "pass") {
    if (arg.length() < 8 || arg.length() > 63 || arg.indexOf(' ') >= 0) {
      Serial.println("> use: pass NEWPASSWORD  (8-63 characters, no spaces)");
      return;
    }
    cfg.adminPass = arg;
    cfg.customPass = true;
    saveSettings();
    startHotspot();
    Serial.println("> password changed; hotspot restarted");
    printAccess();
  }
  else if (cmd == "wifi") {
    if (!arg.length()) printAccess();
    else if (arg == "-") { cfg.staSsid = ""; cfg.staPass = ""; nets.clear(); saveSettings(); WiFi.disconnect(false, true); Serial.println("> all saved networks forgotten"); }
    else if (arg == "ble") { if (bleActive) Serial.println("> Bluetooth setup already on"); else bleBegin(); }
    else {
      int bar = arg.indexOf('|');
      if (bar < 1) { Serial.println("> use: wifi SSID|PASSWORD"); return; }
      rememberNet(arg.substring(0, bar), arg.substring(bar + 1));
      useNet(nets[0]);
      Serial.printf("> saved (%d networks). Joining %s\n", (int)nets.size(), nets[0].ssid.c_str());
    }
  }
  else if (cmd == "remote") {
    if (arg == "on" && !cfg.customPass) Serial.println("> set your own password first: pass NEWPASSWORD");
    else if (arg == "on" || arg == "off") remoteSet(arg == "on", remoteHost());
    else if (arg.startsWith("host ")) remoteSet(remoteEnabled(), arg.substring(5));
    else if (arg == "newkey") remoteNewKey();
    Serial.printf("> remote: %s | host=%s\n> status: %s\n> device key: %s\n", remoteEnabled() ? "on" : "off",
                  remoteHost().length() ? remoteHost().c_str() : "(none)", remoteStatus().c_str(),
                  remoteKey().length() ? remoteKey().c_str() : "(none yet)");
  }
  else Serial.println("> unknown command, type 'help'");
}

static void pollSerial() {
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\n' || c == '\r') {
      if (lineBuf.length()) handleCommand(lineBuf);
      lineBuf = "";
    } else if (lineBuf.length() < 160) {
      lineBuf += c;
    }
  }
}

// ------------------------------------------------------------ main
// One scan per loop() pass so the web page stays responsive between scans.
static void stepCycle() {
  if (!cycleActive) {
    cycleNo++;
    aps.clear();
    roundsDone = 0;
    cycleRound = 0;
    cycleActive = true;
    led(0, 0, 20);  // blue while scanning
    Serial.printf("\n> cycle %u: %u scans of channels 1-%d ...\n", cycleNo, cfg.rounds, MAX_CH);
    return;
  }
  if (scanRound()) cycleRound++;
  else { static int fails = 0; if (++fails % 3 == 0) cycleRound++; }  // don't get stuck
  Serial.printf("  scan %d/%u: %d BSSIDs so far\n", cycleRound, cfg.rounds, (int)aps.size());
  if (cycleRound >= cfg.rounds) {
    analyse();
    StrPrint rp;
    printReport(rp);
    lastReport = rp.s;
    {
      std::map<String, int> best;
      for (auto &a : aps)
        if (a.ssid.length() && (!best.count(a.ssid) || a.avg() > best[a.ssid])) best[a.ssid] = (int)a.avg();
      seenNets.assign(best.begin(), best.end());
      std::sort(seenNets.begin(), seenNets.end(), [](const std::pair<String, int> &x, const std::pair<String, int> &y) { return x.second > y.second; });
    }
    Serial.print(lastReport);
    printAccess();
    cycleActive = false;
  }
}

unsigned long lastCycle = 0;

void setup() {
  Serial.begin(115200);
  delay(800);
  Serial.printf("\nESP32-S3 Network Diagnostic Tool v%s\n", FW_VERSION);
  loadSettings();
  if (!cfg.customPass || cfg.adminPass.length() < 8) {  // fixed easy default until you change it
    cfg.adminPass = DEFAULT_PASS;
    cfg.customPass = false;
    saveSettings();
  }

  WiFi.mode(WIFI_AP_STA);
  WiFi.setAutoReconnect(true);

  // UAE regulatory domain: channels 1-13
  wifi_country_t country;
  memset(&country, 0, sizeof(country));
  country.cc[0] = 'A'; country.cc[1] = 'E'; country.cc[2] = ' ';
  country.schan = 1;
  country.nchan = MAX_CH;
  country.max_tx_power = 20;
  country.policy = WIFI_COUNTRY_POLICY_MANUAL;
  if (esp_wifi_set_country(&country) != ESP_OK) Serial.println("! could not set country (using default)");

  uint8_t mac[6] = {0};
  esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);  // read from chip eFuse, always valid
  apName = fmt("NetDiag-%02X%02X", mac[4], mac[5]);
  startHotspot();
  startStation();
  testMux = xSemaphoreCreateMutex();
  otaMux = xSemaphoreCreateMutex();
  otaBootCheck();
  xTaskCreatePinnedToCore(otaTask, "ota", 12288, nullptr, 1, nullptr, 1);
  xTaskCreatePinnedToCore(testTask, "nettest", 16384, nullptr, 1, nullptr, 1);
  startWeb();
  if (MDNS.begin("netdiag")) MDNS.addService("http", "tcp", 80);
  remoteBegin(FW_VERSION);

  printStatus();
  printAccess();
  if (homeList.empty()) Serial.println("Tip: set your networks on the web page or type: home YourSSID");
}

void loop() {
  server.handleClient();
  pollSerial();
  otaHealthTick();
  wifiMgrTick();

  bool up = WiFi.status() == WL_CONNECTED;
  if (up != staWasConnected) {
    staWasConnected = up;
    if (up) { naptOk = WiFi.AP.enableNAPT(true); Serial.printf("> internet sharing (NAT) %s\n", naptOk ? "on" : "FAILED"); printAccess(); }
    else Serial.println("> home Wi-Fi disconnected");
  }

  if (cycleActive) {
    stepCycle();
  } else if (testRunning || testRequested || otaBusy || bleActive) {
    // pause Wi-Fi scans while the connection test runs
  } else if (scanRequested || millis() - lastCycle >= (unsigned long)cfg.intervalS * 1000UL) {
    scanRequested = false;
    stepCycle();
    lastCycle = millis();
  }
  delay(5);
}
