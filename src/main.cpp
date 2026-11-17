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

#define FW_VERSION "2.1.1"

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

// ------------------------------------------------------------ settings
struct Settings {
  String home;          // comma separated list of your own SSIDs
  uint8_t rounds = 4;
  uint16_t intervalS = 60;
  bool raw = true;
  bool json = false;
  String staSsid, staPass;  // your Wi-Fi (stored in flash only)
  String adminPass;         // web login + hotspot password
} cfg;

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
        addF("extssid:" + b.first, SEV_WARN, CONF_LIKELY, "Access points",
             b.first + " looks like an extender with its own SSID",
             "name = " + a.first + " + suffix", "Separate names stop phones moving between them automatically. Give the extender the same SSID and password, or use mesh / wired AP mode");
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
    out.println("CH  W   RSSI  SD SEEN SEC      PHY  SSID");
    std::vector<int> order(aps.size());
    for (size_t i = 0; i < aps.size(); i++) order[i] = i;
    std::sort(order.begin(), order.end(), [](int x, int y) { return aps[x].avg() > aps[y].avg(); });
    for (int i : order) {
      ApObs &a = aps[i];
      out.printf("%2d %s %5.0f %3.0f  %d/%d %-8s %-4s %s%s %s\n", a.ch,
                    a.second ? "40" : "20", a.avg(), a.sd(), a.seen, roundsDone, authName(a.auth),
                    phyName(a), isHome(a.ssid) ? "*" : "", a.hidden() ? "<hidden>" : a.ssid.c_str(),
                    macStr(a.bssid).substring(9).c_str());
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

static String randomPass() {
  const char *chars = "abcdefghjkmnpqrstuvwxyz23456789";
  String p;
  for (int i = 0; i < 10; i++) p += chars[esp_random() % 31];
  return p;
}

static void startStation() {
  if (!cfg.staSsid.length()) return;
  Serial.printf("> joining Wi-Fi '%s' ...\n", cfg.staSsid.c_str());
  WiFi.begin(cfg.staSsid.c_str(), cfg.staPass.c_str());
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
         "pre{background:#111;color:#ddd;padding:8px;font-size:11px;overflow-x:auto;white-space:pre}"
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
  h += "</p><form method='post' action='/scan'><button>Scan now</button> <a href='/'>Refresh</a> | <a href='/api/report'>JSON</a></form>";
  h += "<pre>" + htmlEsc(lastReport) + "</pre>";

  h += "<form method='post' action='/settings'><fieldset><legend>Diagnostics</legend>"
       "Your networks (comma separated)<input name='home' value='" + htmlEsc(cfg.home) + "'>"
       "Scans per cycle (1-10)<input name='rounds' type='number' value='" + String(cfg.rounds) + "'>"
       "Seconds between cycles (10-3600)<input name='interval' type='number' value='" + String(cfg.intervalS) + "'>"
       "<button>Save</button></fieldset></form>";

  h += "<form method='post' action='/wifi'><fieldset><legend>Join my Wi-Fi (2.4 GHz)</legend>"
       "SSID<input name='ssid' value='" + htmlEsc(cfg.staSsid) + "'>"
       "Password<input name='pass' type='password' placeholder='(unchanged if empty)'>"
       "<button>Connect</button> <button name='forget' value='1'>Forget</button></fieldset></form>";

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
  if (server.arg("forget") == "1") {
    cfg.staSsid = ""; cfg.staPass = "";
    saveSettings();
    WiFi.disconnect(false, true);
    sendRedirect("Home Wi-Fi forgotten");
    return;
  }
  String ss = server.arg("ssid"), pw = server.arg("pass");
  ss.trim();
  if (!ss.length()) { sendRedirect("SSID is empty"); return; }
  if (ss != cfg.staSsid || pw.length()) cfg.staPass = pw;
  cfg.staSsid = ss;
  saveSettings();
  sendRedirect("Connecting to " + ss + " - check the status line in 15 s");
  delay(200);
  WiFi.disconnect();
  startStation();
}

static void handlePassword() {
  if (!auth()) return;
  String a = server.arg("p1"), b = server.arg("p2");
  if (a.length() < 8 || a.length() > 63 || a != b) { sendRedirect("Passwords must match and be 8-63 characters"); return; }
  cfg.adminPass = a;
  saveSettings();
  sendRedirect("Password changed. Hotspot restarts - reconnect with the new password");
  delay(300);
  WiFi.softAP(apName.c_str(), cfg.adminPass.c_str());
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

static void startWeb() {
  server.on("/", HTTP_GET, handleRoot);
  server.on("/scan", HTTP_POST, handleScan);
  server.on("/settings", HTTP_POST, handleSettings);
  server.on("/wifi", HTTP_POST, handleWifi);
  server.on("/password", HTTP_POST, handlePassword);
  server.on("/reset", HTTP_POST, handleReset);
  server.on("/api/report", HTTP_GET, handleJson);
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
  Serial.println("  wifi SSID|PASSWORD join your Wi-Fi (note the | between)");
  Serial.println("  wifi -             forget your Wi-Fi");
  Serial.println("  pass NEWPASSWORD   set hotspot + web password (8+ chars)");
  Serial.println("  reset              clear persistence history");
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
  else if (cmd == "pass") {
    if (arg.length() < 8 || arg.length() > 63 || arg.indexOf(' ') >= 0) {
      Serial.println("> use: pass NEWPASSWORD  (8-63 characters, no spaces)");
      return;
    }
    cfg.adminPass = arg;
    saveSettings();
    WiFi.softAP(apName.c_str(), cfg.adminPass.c_str());
    Serial.println("> password changed; hotspot restarted");
    printAccess();
  }
  else if (cmd == "wifi") {
    if (!arg.length()) printAccess();
    else if (arg == "-") { cfg.staSsid = ""; cfg.staPass = ""; saveSettings(); WiFi.disconnect(false, true); Serial.println("> Wi-Fi forgotten"); }
    else {
      int bar = arg.indexOf('|');
      if (bar < 1) { Serial.println("> use: wifi SSID|PASSWORD"); return; }
      cfg.staSsid = arg.substring(0, bar);
      cfg.staPass = arg.substring(bar + 1);
      saveSettings();
      WiFi.disconnect();
      startStation();
    }
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
  if (cfg.adminPass.length() < 8) {  // first boot: make a unique password
    cfg.adminPass = randomPass();
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
  WiFi.softAP(apName.c_str(), cfg.adminPass.c_str());
  startStation();
  startWeb();
  if (MDNS.begin("netdiag")) MDNS.addService("http", "tcp", 80);

  printStatus();
  printAccess();
  if (homeList.empty()) Serial.println("Tip: set your networks on the web page or type: home YourSSID");
}

void loop() {
  server.handleClient();
  pollSerial();

  bool up = WiFi.status() == WL_CONNECTED;
  if (up != staWasConnected) {
    staWasConnected = up;
    if (up) printAccess();
    else Serial.println("> home Wi-Fi disconnected");
  }

  if (cycleActive) {
    stepCycle();
  } else if (scanRequested || millis() - lastCycle >= (unsigned long)cfg.intervalS * 1000UL) {
    scanRequested = false;
    stepCycle();
    lastCycle = millis();
  }
  delay(5);
}
