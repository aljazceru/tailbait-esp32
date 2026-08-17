/**
 * TailBait-ESP32 — port of the TailBait anti-stalking detection core
 * to the LILYGO TTGO T-Display v1.1 (ESP32, ST7789 135x240).
 *
 * Ports the essential logic of the Android app (tailbait/):
 *   - BLE scanning with tracker fingerprinting (service UUIDs, Apple Find My,
 *     iBeacon) — from TrackerServiceDetector / ManufacturerDataParser
 *   - multi-place detection: device seen at >= 3 distinct "places"
 *   - threat score (0..1) with the same 7 weighted factors as
 *     ThreatScoreCalculator.calculateEnhanced()
 *   - companion-device suppression (own phone filter)
 *   - whitelist (buttons + serial), Find My "separated from owner" bonus
 *   - Find My MAC-rotation resistance via payload pubkey fingerprint
 *
 * WiFi expansion (new on ESP32):
 *   - location = fingerprint of surrounding AP BSSIDs (Jaccard similarity),
 *     replacing GPS — "place" instead of lat/lon meters
 *   - promiscuous sniffing tracks WiFi-side devices (phones etc.) by probe
 *     requests / station frames, with randomized-MAC flagging and a "shadow"
 *     identity from directed-probe SSIDs (ShadowAnalyzer analog)
 *
 * Radio is time-sliced: BLE scan -> WiFi promiscuous sniff -> AP scan.
 *
 * Serial console (115200): JSON event lines out; commands in:
 *   help | devices | places | alerts | wl | wl add <mac> | wl clear | wipe
 */

#include <Arduino.h>
#include <Preferences.h>
#include <esp_wifi.h>
#include "esp_wifi_types.h"
#include <NimBLEDevice.h>
#include <Adafruit_GFX.h>
#include <Adafruit_ST7789.h>

// ============================ config ============================
#define TFT_MOSI 19
#define TFT_SCLK 18
#define TFT_CS    5
#define TFT_DC   16
#define TFT_RST  23
#define TFT_BL    4
#define BTN_L     0   // BOOT button (left)
#define BTN_R    35   // right button

enum Phase : uint8_t { PH_BLE = 0, PH_SNIFF, PH_PLACE, PH_ANALYZE, PH_COUNT };
const uint32_t PHASE_MS[PH_COUNT] = { 12000, 8000, 0 /*blocking*/, 0 };

static const size_t MAX_DEVICES   = 48;
static const size_t MAX_PLACES    = 10;
static const size_t MAX_STATS     = 8;
static const size_t MAX_FP_APS    = 8;
static const size_t MAX_WHITELIST = 16;

static const uint32_t HOUR_MS = 3600UL * 1000;
static const uint32_t DAY_MS  = 24 * HOUR_MS;

// detection thresholds (mirroring DetectionAlgorithm defaults)
static const uint8_t  MIN_PLACES       = 3;     // alertThresholdCount
static const float    MIN_THREAT_ALERT = 0.5f;  // MIN_THREAT_SCORE_FOR_ALERT
static const float    PLACE_SIM_NEW    = 0.90f; // Jaccard below => new place
// (demo value: strict place identity for static bench testing;
//  use 0.35 for real mobile use — environments drift)
static const int16_t  COMPANION_RSSI   = -50;   // isCompanionDevice()
static const float    COMPANION_COVER  = 0.8f;
static const uint8_t  COMPANION_MIN_PL = 5;

// threat weights — ThreatScoreCalculator.calculateEnhanced()
static const float W_MOVEMENT = 0.25f, W_LOCCOUNT = 0.18f, W_DEVTYPE = 0.15f,
                   W_SIGNAL = 0.12f, W_PLACEDIST = 0.12f, W_CONSIST = 0.10f,
                   W_TIMESPAN = 0.08f;

// ============================ data model ============================
enum DevKind : uint8_t { K_BLE = 0, K_WIFI_STA, K_WIFI_SHADOW };

struct PlaceStat {
  bool     live;
  uint8_t  place;
  uint32_t firstMs, lastMs;
  int8_t   bestRssi;
};

struct Device {
  bool     used;
  uint8_t  key[7];             // MAC(6)+kind, or 'F','M'+pubkey fingerprint
  char     label[17];
  uint8_t  kind;
  bool     isTracker;
  bool     findMySeparated;
  bool     randomizedMac;
  int8_t   highestRssi;
  uint32_t firstSeenMs, lastSeenMs;
  uint16_t hits;
  float    lastScore;
  bool     alerted;
  bool     whitelisted;
  PlaceStat stats[MAX_STATS];
};

struct Place {
  bool     used;
  uint32_t firstMs, lastMs;
  uint8_t  macs[MAX_FP_APS][6];
  int8_t   rssi[MAX_FP_APS];
  uint8_t  nAps;
  uint32_t visits;
};

static Device devices[MAX_DEVICES];
static Place  places[MAX_PLACES];
static uint8_t whitelist[MAX_WHITELIST][6];
static size_t  wlCount = 0;
static uint32_t nBleSeen = 0, nWifiSeen = 0, cycleCount = 0;

// ============================ globals ============================
Adafruit_ST7789 tft(TFT_CS, TFT_DC, TFT_MOSI, TFT_SCLK, TFT_RST);
enum Screen : uint8_t { SCR_STATUS = 0, SCR_ALERTS, SCR_COUNT };
static uint8_t curScreen = SCR_STATUS;
static uint32_t lastDraw = 0;

static Phase phase = PH_BLE;
static uint32_t phaseStart = 0;
static bool wifiUp = false, bleUp = false;
static int8_t  curPlace = -1;          // most recent place fingerprint
static uint32_t lastPlaceMs = 0;

Preferences prefs;

struct AlertRow { Device* dev; float score; };
static AlertRow alertRows[6];
static uint8_t alertCount = 0;

// ============================ helpers ============================
static void hexMac(const uint8_t* m, char* out, size_t n) {
  snprintf(out, n, "%02X:%02X:%02X:%02X:%02X:%02X",
           m[0], m[1], m[2], m[3], m[4], m[5]);
}
static bool macEq(const uint8_t* a, const uint8_t* b) {
  return memcmp(a, b, 6) == 0;
}
static void jout(const String& s) { Serial.println(s); }
static float clamp01(float v) { return v < 0 ? 0 : (v > 1 ? 1 : v); }

// ============================ places ============================
static float placeSimilarity(const Place& a, const Place& b) {
  if (!a.nAps || !b.nAps) return 0;
  uint8_t inter = 0;
  for (uint8_t i = 0; i < a.nAps; i++)
    for (uint8_t j = 0; j < b.nAps; j++)
      if (macEq(a.macs[i], b.macs[j])) { inter++; break; }
  return (float)inter / (uint8_t)(a.nAps + b.nAps - inter);  // Jaccard
}

static int8_t findOrCreatePlace(const uint8_t macs[][6], const int8_t* rssi, uint8_t n) {
  Place tmp = {};
  tmp.nAps = n;
  memcpy(tmp.macs, macs, n * 6);
  memcpy(tmp.rssi, rssi, n);
  float bestSim = 0; int8_t bestIdx = -1;
  for (uint8_t i = 0; i < MAX_PLACES; i++) {
    if (!places[i].used) continue;
    float s = placeSimilarity(places[i], tmp);
    if (s > bestSim) { bestSim = s; bestIdx = i; }
  }
  if (bestSim >= PLACE_SIM_NEW) return bestIdx;
  int8_t slot = -1;
  for (uint8_t i = 0; i < MAX_PLACES; i++)
    if (!places[i].used) { slot = i; break; }
  if (slot < 0) {
    uint32_t oldest = UINT32_MAX;
    for (uint8_t i = 0; i < MAX_PLACES; i++)
      if (places[i].lastMs < oldest) { oldest = places[i].lastMs; slot = i; }
  }
  Place& p = places[slot];
  p.used = true;
  p.nAps = n;
  memcpy(p.macs, macs, n * 6);
  memcpy(p.rssi, rssi, n);
  p.visits = 1;
  p.firstMs = p.lastMs = millis();
  char top1[18]; hexMac(macs[0], top1, sizeof(top1));
  jout("{\"ev\":\"place_new\",\"id\":" + String(slot) + ",\"aps\":" + String(n) +
       ",\"top\":\"" + top1 + "\"}");
  return slot;
}

static uint8_t countPlaces() {
  uint8_t n = 0;
  for (auto& p : places) n += p.used;
  return n;
}

// ============================ devices ============================
static Device* findDevice(const uint8_t* key7, bool create) {
  for (auto& d : devices)
    if (d.used && memcmp(d.key, key7, 7) == 0) return &d;
  if (!create) return nullptr;
  for (auto& d : devices) {
    if (d.used) continue;
    memset(&d, 0, sizeof(d));
    memcpy(d.key, key7, 7);
    d.used = true;
    d.highestRssi = -128;
    d.kind = key7[6];
    return &d;
  }
  return nullptr;
}

static void recordSighting(const uint8_t* key7, const char* label, int8_t rssi,
                           int8_t placeIdx, bool isTracker, bool separated,
                           bool randMac, uint8_t kind) {
  Device* d = findDevice(key7, true);
  if (!d) return;
  strncpy(d->label, label, sizeof(d->label) - 1);
  d->isTracker |= isTracker;
  d->findMySeparated |= separated;
  d->randomizedMac |= randMac;
  d->kind = kind;
  uint32_t t = millis();
  if (!d->firstSeenMs) d->firstSeenMs = t;
  d->lastSeenMs = t;
  d->hits++;
  if (rssi > d->highestRssi) d->highestRssi = rssi;
  if (!d->whitelisted) {
    for (size_t i = 0; i < wlCount; i++)
      if (macEq(whitelist[i], key7)) { d->whitelisted = true; break; }
  }
  if (d->whitelisted || placeIdx < 0) return;
  PlaceStat* ps = nullptr;
  for (auto& s : d->stats)
    if (s.live && s.place == placeIdx) { ps = &s; break; }
  if (!ps)
    for (auto& s : d->stats)
      if (!s.live) { ps = &s; memset(ps, 0, sizeof(*ps)); ps->live = true;
                     ps->place = placeIdx; ps->bestRssi = -128; break; }
  if (!ps) {
    ps = &d->stats[0];
    for (auto& s : d->stats) if (s.lastMs < ps->lastMs) ps = &s;
    memset(ps, 0, sizeof(*ps));
    ps->live = true; ps->place = placeIdx; ps->bestRssi = -128;
  }
  ps->lastMs = t;
  if (rssi > ps->bestRssi) ps->bestRssi = rssi;
}

static uint8_t devicePlaceCount(const Device& d) {
  bool seen[MAX_PLACES] = {};
  for (auto& s : d.stats) if (s.live) seen[s.place] = true;
  uint8_t n = 0;
  for (uint8_t i = 0; i < MAX_PLACES; i++) n += seen[i];
  return n;
}

// companion filter — DetectionAlgorithm.isCompanionDevice()
static bool isCompanion(const Device& d) {
  uint8_t userPlaces = countPlaces();
  if (userPlaces < COMPANION_MIN_PL) return false;
  if (d.highestRssi < COMPANION_RSSI) return false;
  return (float)devicePlaceCount(d) / userPlaces >= COMPANION_COVER;
}

// signal strength factor — SignalStrength.fromRssi().threatWeight
static float signalScore(int8_t rssi) {
  if (rssi >= -35) return 1.0f;    // VERY_STRONG
  if (rssi >= -50) return 0.75f;   // STRONG
  if (rssi >= -65) return 0.5f;    // MEDIUM
  if (rssi >= -80) return 0.25f;   // WEAK
  return 0.1f;                     // VERY_WEAK
}

// device type factor — calculateEnhancedDeviceTypeScore()
static float deviceTypeScore(const Device& d) {
  float base;
  if (d.isTracker) base = 1.0f;
  else if (d.kind == K_WIFI_STA || d.kind == K_WIFI_SHADOW) base = 0.8f;  // phones
  else base = 0.3f;
  float score = base * 0.7f;
  if (d.findMySeparated) score += d.isTracker ? 0.3f : 0.15f;
  else if (d.randomizedMac) score += 0.1f;
  return clamp01(score);
}

static void recordTimes(const Device& d, uint32_t& spanMs, uint32_t& avgGapMs) {
  uint32_t ts[MAX_STATS]; uint8_t n = 0;
  for (auto& s : d.stats)
    if (s.live) ts[n++] = s.lastMs;
  if (n < 2) { spanMs = 0; avgGapMs = UINT32_MAX; return; }
  for (uint8_t i = 0; i < n; i++)
    for (uint8_t j = i + 1; j < n; j++)
      if (ts[j] < ts[i]) { uint32_t t = ts[i]; ts[i] = ts[j]; ts[j] = t; }
  spanMs = ts[n - 1] - ts[0];
  uint32_t sum = 0;
  for (uint8_t i = 0; i + 1 < n; i++) sum += ts[i + 1] - ts[i];
  avgGapMs = sum / (n - 1);
}

// avg pairwise fingerprint dissimilarity — the "distance" analog
static float placeDistanceScore(const Device& d) {
  float sum = 0; uint8_t pairs = 0;
  for (uint8_t i = 0; i < MAX_STATS; i++) {
    if (!d.stats[i].live) continue;
    for (uint8_t j = i + 1; j < MAX_STATS; j++) {
      if (!d.stats[j].live) continue;
      if (!places[d.stats[i].place].used || !places[d.stats[j].place].used) continue;
      sum += 1.0f - placeSimilarity(places[d.stats[i].place], places[d.stats[j].place]);
      pairs++;
    }
  }
  return pairs ? sum / pairs : 0;
}

// main score — port of ThreatScoreCalculator.calculateEnhanced()
static float threatScore(const Device& d, float& movementOut) {
  uint8_t pl = devicePlaceCount(d);
  uint8_t userPlaces = countPlaces();
  movementOut = userPlaces ? clamp01((float)pl / userPlaces) : 0;

  uint32_t spanMs, avgGapMs;
  recordTimes(d, spanMs, avgGapMs);

  float s = 0;
  s += movementOut * W_MOVEMENT;
  s += clamp01(pl / 6.0f) * W_LOCCOUNT;
  s += deviceTypeScore(d) * W_DEVTYPE;
  s += signalScore(d.highestRssi) * W_SIGNAL;
  s += placeDistanceScore(d) * W_PLACEDIST;
  float consist = avgGapMs == UINT32_MAX ? 0.13f
                  : avgGapMs < HOUR_MS ? 1.0f
                  : avgGapMs < 6 * HOUR_MS ? 0.67f
                  : avgGapMs < DAY_MS ? 0.33f : 0.13f;
  s += consist * W_CONSIST;
  float timeS = spanMs < HOUR_MS ? 0.25f : spanMs < DAY_MS ? 0.75f : 1.0f;
  s += timeS * W_TIMESPAN;
  return clamp01(s);
}

// ============================ BLE scanner ============================
struct SvcEntry { uint16_t uuid; const char* name; bool tracker; };
static const SvcEntry SVC_TABLE[] = {
  {0xFD5A, "SmartTag", true}, {0xFD6F, "FindMy", true},
  {0xFEED, "Tile", true},     {0xFE8C, "Chipolo", true},
  {0xFE8D, "Pebblebee", true},{0xFE8E, "Cube", true},
  {0xFE9F, "eufy", true},     {0xFEA0, "JioTag", true},
  {0xFE2C, "GoogleFMDN", true},
};
static const size_t SVC_N = sizeof(SVC_TABLE) / sizeof(SVC_TABLE[0]);

class ScanCallbacks : public NimBLEScanCallbacks {
  void onScanEnd(const NimBLEScanResults& r, int reason) override {
    jout("{\"ev\":\"ble_end\",\"n\":" + String(r.getCount()) +
         ",\"reason\":" + String(reason) + "}");
  }
  void onResult(const NimBLEAdvertisedDevice* adv) override {
    int8_t rssi = adv->getRSSI();
    uint8_t key[7];
    memcpy(key, adv->getAddress().getVal(), 6);
    key[6] = K_BLE;

    char label[17] = "";
    std::string nm = adv->getName();
    if (!nm.empty()) strncpy(label, nm.c_str(), 16);

    bool isTracker = false, separated = false;
    const char* type = "";
    uint8_t fmKey[7];
    bool useFmKey = false;

    if (adv->haveServiceUUID()) {
      uint8_t n = min<uint8_t>(adv->getServiceUUIDCount(), 8);
      for (uint8_t i = 0; i < n; i++) {
        NimBLEUUID got = adv->getServiceUUID(i);
        for (size_t k = 0; k < SVC_N; k++)
          if (got == NimBLEUUID(SVC_TABLE[k].uuid)) {
            type = SVC_TABLE[k].name;
            if (!label[0]) strncpy(label, type, 16);
            if (SVC_TABLE[k].tracker) isTracker = true;
            break;
          }
      }
    }

    if (adv->haveManufacturerData()) {           // ManufacturerDataParser
      std::string md = adv->getManufacturerData();
      if (md.size() >= 2) {
        uint16_t cid = (uint8_t)md[0] | ((uint8_t)md[1] << 8);
        if (cid == 0x004C && md.size() >= 4) {   // Apple
          uint8_t typ = (uint8_t)md[2];
          if (typ == 0x12) {                     // Find My OFFLINE finding
            separated = (uint8_t)md[3] & 0x04;   // SEPARATED_FROM_OWNER_MASK
            isTracker = true;
            type = "AirTag/FM";
            if (!label[0]) strncpy(label, type, 16);
            if (md.size() >= 10) {               // pubkey fingerprint key
              fmKey[0] = 'F'; fmKey[1] = 'M';
              memcpy(fmKey + 2, md.data() + 4, 5);
              useFmKey = true;
            }
          } else if (typ == 0x02 && (uint8_t)md[3] == 0x15) {
            type = "iBeacon";
            if (!label[0]) strncpy(label, type, 16);
          }
        }
      }
    }

    char macS[18];
    hexMac(useFmKey ? fmKey + 2 : key, macS, sizeof(macS));
    const char* shown = label[0] ? label : macS;
    if (!label[0]) strncpy(label, macS, 16);

    if (useFmKey) {
      fmKey[6] = 'F';
      recordSighting(fmKey, shown, rssi, curPlace, isTracker, separated, false, K_BLE);
    } else {
      recordSighting(key, shown, rssi, curPlace, isTracker, separated, false, K_BLE);
    }
    nBleSeen++;

    jout("{\"ev\":\"ble\",\"id\":\"" + String(shown) + "\",\"mac\":\"" + String(macS) +
         "\",\"rssi\":" + String(rssi) +
         (type[0] ? ",\"type\":\"" + String(type) + "\"" : "") +
         (separated ? ",\"separated\":true" : "") + "}");
  }
};

// ============================ WiFi side ============================
static bool sniffing = false;

static void wifiBegin() {
  if (wifiUp) return;
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_STA);
  esp_wifi_start();
  wifiUp = true;
}

static void wifiEnd() {
  if (!wifiUp) return;
  esp_wifi_stop();
  esp_wifi_deinit();
  wifiUp = false;
}

static uint16_t hashBuf(const uint8_t* s, uint8_t len) {
  uint16_t h = 5381;
  for (uint8_t i = 0; i < len; i++) h = (uint16_t)((h * 33) ^ s[i]);
  return h;
}

static void recordWifiDev(const uint8_t* tx, int8_t rssi, bool isProbe) {
  // directed probe SSID => shadow identity (survives MAC rotation)
  if (isProbe) return;  // SSID handled by caller when present
  uint8_t key[7]; memcpy(key, tx, 6); key[6] = K_WIFI_STA;
  bool randMac = tx[0] & 0x40;
  char macS[18]; hexMac(tx, macS, sizeof(macS));
  recordSighting(key, macS, rssi, curPlace, false, false, randMac, K_WIFI_STA);
  nWifiSeen++;
  if (nWifiSeen % 16 == 1)
    jout("{\"ev\":\"wifi\",\"mac\":\"" + String(macS) + "\",\"rssi\":" + String(rssi) +
         (randMac ? ",\"randmac\":true" : "") + "}");
}

// promiscuous callback (plain function, uses globals)
static void snifferCb(void* buf, wifi_promiscuous_pkt_type_t /*type*/) {
  const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
  const uint8_t* f = pkt->payload;
  uint16_t flen = pkt->rx_ctrl.sig_len;
  if (flen < 28 || flen > 600) return;
  uint8_t fcType = (f[0] & 0x0C) >> 2;
  uint8_t fcSub  = (f[0] & 0xF0) >> 4;
  uint8_t toDS = f[1] & 0x01, fromDS = f[1] & 0x02;
  const uint8_t* tx = f + 10;                       // addr2 = transmitter
  int8_t rssi = (int8_t)pkt->rx_ctrl.rssi;

  bool isProbe = (fcType == 0 && fcSub == 4);
  bool isStaData = (fcType == 2 && toDS && !fromDS); // client -> AP
  if (!isProbe && !isStaData) return;

  if (isProbe && flen > 28 && f[24] == 0x00) {   // SSID IE in probe req
    uint8_t sl = f[25];
    if (sl > 0 && sl <= 16) {
      uint16_t h = hashBuf(f + 26, sl);
      uint8_t key[7] = { (uint8_t)(h >> 8), (uint8_t)h, 'S', 'H', 'D', 'W', K_WIFI_SHADOW };
      char ssid[17] = {};
      memcpy(ssid, f + 26, sl);
      char lbl[17]; snprintf(lbl, sizeof(lbl), "w:%.14s", ssid);
      recordSighting(key, lbl, rssi, curPlace, false, false, false, K_WIFI_SHADOW);
      nWifiSeen++;
      jout("{\"ev\":\"wifi_shadow\",\"ssid\":\"" + String(ssid) +
           "\",\"rssi\":" + String(rssi) + "}");
      return;
    }
  }
  recordWifiDev(tx, rssi, false);
}

static void wifiSniff(uint32_t durMs) {
  wifiBegin();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&snifferCb);
  wifi_promiscuous_filter_t filt = {};
  filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
  esp_wifi_set_promiscuous_filter(&filt);
  sniffing = true;
  uint32_t t0 = millis();
  while (millis() - t0 < durMs) delay(50);
  sniffing = false;
  esp_wifi_set_promiscuous(false);
}

// AP scan -> place fingerprint
static void updatePlace() {
  wifiBegin();
  wifi_scan_config_t sc = {};
  sc.scan_time.active.min = 0;
  sc.scan_time.active.max = 0;
  sc.scan_time.passive = 120;               // ms per channel
  esp_err_t err = esp_wifi_scan_start(&sc, true);   // blocking
  if (err != ESP_OK) { jout("{\"ev\":\"scan_err\",\"code\":" + String(err) + "}"); return; }
  uint16_t n = 0;
  esp_wifi_scan_get_ap_num(&n);
  if (!n) return;
  static wifi_ap_record_t recs[20];
  uint16_t got = min<uint16_t>(n, 20);
  esp_wifi_scan_get_ap_records(&got, recs);
  esp_wifi_clear_ap_list();

  // insertion-sort top-8 by RSSI into fingerprint
  uint8_t fm[MAX_FP_APS][6];
  int8_t  fr[MAX_FP_APS];
  uint8_t fn = 0;
  for (uint16_t i = 0; i < got; i++) {
    int8_t r = recs[i].rssi;
    if (fn < MAX_FP_APS) {
      memcpy(fm[fn], recs[i].bssid, 6); fr[fn] = r; fn++;
      for (int8_t k = fn - 1; k > 0 && fr[k] > fr[k - 1]; k--) {
        uint8_t tm[6]; memcpy(tm, fm[k], 6); memcpy(fm[k], fm[k-1], 6); memcpy(fm[k-1], tm, 6);
        int8_t tr = fr[k]; fr[k] = fr[k-1]; fr[k-1] = tr;
      }
    } else if (r > fr[MAX_FP_APS - 1]) {
      memcpy(fm[MAX_FP_APS - 1], recs[i].bssid, 6); fr[MAX_FP_APS - 1] = r;
      for (int8_t k = MAX_FP_APS - 1; k > 0 && fr[k] > fr[k - 1]; k--) {
        uint8_t tm[6]; memcpy(tm, fm[k], 6); memcpy(fm[k], fm[k-1], 6); memcpy(fm[k-1], tm, 6);
        int8_t tr = fr[k]; fr[k] = fr[k-1]; fr[k-1] = tr;
      }
    }
  }
  if (fn < 2) return;                        // not enough context
  int8_t p = findOrCreatePlace(fm, fr, fn);
  if (p == curPlace) {
    places[p].lastMs = millis();
    places[p].visits++;
  }
  curPlace = p;
  lastPlaceMs = millis();
  jout("{\"ev\":\"place\",\"id\":" + String(curPlace) + ",\"aps\":" + String(fn) + "}");
}

// ============================ analysis / alerts ============================
static void analyze() {
  alertCount = 0;
  for (auto& d : devices) {
    if (!d.used || d.whitelisted) continue;
    uint8_t pl = devicePlaceCount(d);
    if (pl < MIN_PLACES) { d.lastScore = 0; continue; }
    if (isCompanion(d)) continue;
    float mv;
    float score = threatScore(d, mv);
    bool reAlert = d.alerted && score > d.lastScore + 0.1f;
    d.lastScore = score;
    if (score >= MIN_THREAT_ALERT) {
      // insert into sorted top rows
      uint8_t idx = alertCount < 6 ? alertCount++ : 5;
      while (idx > 0 && alertRows[idx - 1].score < score) {
        if (idx < 5) alertRows[idx] = alertRows[idx - 1];
        else alertCount = 5;
        idx--;
      }
      alertRows[idx].dev = &d;
      alertRows[idx].score = score;
      if (alertCount > 6) alertCount = 6;
      if (!d.alerted || reAlert) {
        d.alerted = true;
        jout("{\"ev\":\"ALERT\",\"id\":\"" + String(d.label) +
             "\",\"score\":" + String(score, 2) +
             ",\"places\":" + String(pl) +
             (d.isTracker ? ",\"tracker\":true" : "") +
             (d.findMySeparated ? ",\"separated\":true" : "") + "}");
      }
    }
  }
}

// ============================ whitelist (NVS) ============================
static void wlLoad() {
  prefs.begin("tailbait", true);
  wlCount = prefs.getBytesLength("wl") / 6;
  if (wlCount > MAX_WHITELIST) wlCount = MAX_WHITELIST;
  if (wlCount) prefs.getBytes("wl", whitelist, wlCount * 6);
  prefs.end();
}
static void wlSave() {
  prefs.begin("tailbait", false);
  prefs.putBytes("wl", whitelist, wlCount * 6);
  prefs.end();
}
static bool wlAdd(const uint8_t* mac) {
  if (wlCount >= MAX_WHITELIST) return false;
  memcpy(whitelist[wlCount++], mac, 6);
  wlSave();
  for (auto& d : devices)
    if (d.used && macEq(d.key, mac)) d.whitelisted = true;
  return true;
}
static void wlClear() {
  wlCount = 0;
  wlSave();
  for (auto& d : devices) d.whitelisted = false;
}

// ============================ UI ============================
static uint16_t threatColor(float s) {
  if (s >= 0.9) return 0xF800;   // red    CRITICAL
  if (s >= 0.75) return 0xFD20;  // orange HIGH
  if (s >= 0.6)  return 0xFFE0;  // yellow MEDIUM
  return 0x07E0;                 // green  LOW
}
static const char* threatName(float s) {
  if (s >= 0.9) return "CRIT";
  if (s >= 0.75) return "HIGH";
  if (s >= 0.6) return "MED";
  return "LOW";
}

static void drawUI(bool force) {
  if (!force && millis() - lastDraw < 1000) return;
  lastDraw = millis();
  static const char* PHASE_NAME[PH_COUNT] = { "BLE", "WiFi", "Place", "Eval" };
  tft.fillScreen(0x0000);

  // header
  tft.fillRect(0, 0, 240, 18, 0x019F /*blue-ish*/);
  tft.setTextColor(0xFFFF); tft.setTextSize(1);
  tft.setCursor(4, 6);
  if (curScreen == SCR_STATUS) {
    tft.printf("TB %s  P%d  B%lu W%lu  c%lu",
               PHASE_NAME[phase], countPlaces(), nBleSeen, nWifiSeen, cycleCount);
  } else {
    tft.printf("ALERTS  (%d)   L:page R:wl", alertCount);
  }

  if (curScreen == SCR_STATUS) {
    int y = 24;
    tft.setTextColor(0xC618); tft.setTextSize(1);
    tft.setCursor(0, y);
    tft.printf("phase:%s  place:%d  wl:%d", PHASE_NAME[phase],
               curPlace >= 0 ? curPlace : -1, (int)wlCount);
    y += 14;
    tft.printf("dev:%d  ble:%lu  wifi:%lu", [&]{
      uint8_t n = 0; for (auto& d : devices) n += d.used; return n; }(),
      nBleSeen, nWifiSeen);
    y += 14;
    // top places with AP counts
    for (uint8_t i = 0; i < MAX_PLACES && y < 135 - 10; i++) {
      if (!places[i].used) continue;
      char b[18]; hexMac(places[i].macs[0], b, sizeof(b));
      tft.setTextColor(curPlace == i ? 0x07E0 : 0x8410);
      tft.setCursor(0, y);
      tft.printf("P%d %dAP %lu  %s", i, places[i].nAps, places[i].visits, b);
      y += 11;
    }
  } else {
    int y = 22;
    if (!alertCount) {
      tft.setTextColor(0x07E0); tft.setTextSize(2);
      tft.setCursor(10, 50); tft.print("no alerts");
    }
    for (uint8_t i = 0; i < alertCount && y < 121; i++) {
      Device* d = alertRows[i].dev;
      float s = alertRows[i].score;
      uint16_t col = threatColor(s);
      tft.fillRect(0, y, 240, 19, i == 0 ? 0x2104 : 0x0000);
      tft.setTextColor(col); tft.setTextSize(1);
      tft.setCursor(2, y + 2);
      tft.printf("%.10s %s", d->label, threatName(s));
      tft.setCursor(2, y + 11);
      tft.printf("pl:%d rssi:%d %s", devicePlaceCount(*d), d->highestRssi,
                 d->isTracker ? "TRK" : "");
      // score bar
      uint8_t bw = (uint8_t)(s * 90);
      tft.drawRect(148, y + 5, 90, 9, 0x8410);
      tft.fillRect(149, y + 6, bw, 7, col);
      y += 20;
    }
    tft.setTextColor(0x8410); tft.setTextSize(1);
    tft.setCursor(0, 126);
    tft.printf("score>=0.5 & %d+ places  L/R:buttons", MIN_PLACES);
  }
}

// ============================ serial console ============================
static void cmdDevices() {
  jout("-- devices (" + String([&]{
    uint8_t n = 0; for (auto& d : devices) n += d.used; return n; }()) + ") --");
  for (auto& d : devices) {
    if (!d.used) continue;
    char macS[18]; hexMac(d.key, macS, sizeof(macS));
    jout(String(d.label) + " mac=" + macS + " kind=" +
         (d.kind == K_BLE ? "ble" : d.kind == K_WIFI_STA ? "wifi" : "shadow") +
         " places=" + String(devicePlaceCount(d)) +
         " rssi=" + String(d.highestRssi) + " hits=" + String(d.hits) +
         " score=" + String(d.lastScore, 2) +
         (d.whitelisted ? " WL" : "") +
         (d.isTracker ? " TRK" : "") +
         (d.findMySeparated ? " SEP!" : ""));
  }
}
static void cmdPlaces() {
  jout("-- places (" + String(countPlaces()) + ") --");
  for (uint8_t i = 0; i < MAX_PLACES; i++) {
    if (!places[i].used) continue;
    char b[18]; hexMac(places[i].macs[0], b, sizeof(b));
    jout("P" + String(i) + " aps=" + String(places[i].nAps) +
         " visits=" + String(places[i].visits) + " top=" + b);
  }
}
// ---- simulation: inject a synthetic "stalker" seen at N synthetic places ----
static void cmdSimTracker(const String& arg) {
  bool tracker = arg.startsWith("tracker");
  String macS = arg.substring(tracker ? 8 : (arg.startsWith("phone") ? 6 : 0));
  macS.trim(); macS.replace(":", "");
  uint8_t mac[6];
  if (macS.length() != 12 || sscanf(macS.c_str(), "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
         &mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]) != 6) {
    jout("usage: sim [tracker|phone] Aabbccddeeff"); return;
  }
  const uint8_t NPL = 3;                        // 3 distinct places
  int8_t made[NPL];
  for (uint8_t p = 0; p < NPL; p++) {
    uint8_t fm[MAX_FP_APS][6]; int8_t fr[MAX_FP_APS];
    for (uint8_t i = 0; i < MAX_FP_APS; i++) {   // unique fake APs per place
      fm[i][0]=0x02; fm[i][1]=0xDE; fm[i][2]=0xAD;
      fm[i][3]=(uint8_t)(0xB0 | p); fm[i][4]=i; fm[i][5]=(uint8_t)(0x50+p*0x11+i);
      fr[i] = (int8_t)(-40 - i * 3);
    }
    made[p] = findOrCreatePlace(fm, fr, MAX_FP_APS);
  }
  uint8_t key[7]; memcpy(key, mac, 6); key[6] = K_BLE;
  uint32_t t = millis();
  for (uint8_t p = 0; p < NPL; p++) {           // sightings 90/50/10 min ago
    int8_t pi = made[p];
    Device* d = findDevice(key, true);
    if (!d) { jout("device table full"); return; }
    strncpy(d->label, tracker ? "SimAirTag" : "SimPhone", 16);
    d->kind = K_BLE; d->isTracker = tracker; d->findMySeparated = tracker;
    d->randomizedMac = !tracker;
    d->highestRssi = -45;
    if (!d->firstSeenMs) d->firstSeenMs = t - 90UL*60000;
    d->lastSeenMs = t - 10UL*60000; d->hits += 5;
    PlaceStat* ps = nullptr;
    for (auto& s : d->stats) if (!s.live) { ps = &s; break; }
    if (!ps) { jout("stats full"); return; }
    memset(ps, 0, sizeof(*ps));
    ps->live = true; ps->place = pi;
    ps->firstMs = t - (uint32_t)(90 - p*40)*60000UL;
    ps->lastMs  = t - (uint32_t)(90 - p*40 - 20)*60000UL;
    ps->bestRssi = -45 - p * 3;
  }
  jout("{\"ev\":\"sim\",\"mac\":\"" + macS + "\",\"places\":3}");
  analyze();
  curScreen = SCR_ALERTS;
  drawUI(true);
}

static void handleCmd(const String& line) {
  String s = line; s.trim();
  if (s == "help")
    jout("cmds: devices | places | alerts | sim [tracker|phone] <MAC> | wl | wl add <MAC> | wl clear | wipe");
  else if (s.startsWith("sim")) cmdSimTracker(s.substring(4));
  else if (s == "devices") cmdDevices();
  else if (s == "places") cmdPlaces();
  else if (s == "alerts") analyze();
  else if (s == "wl") {
    jout("whitelist (" + String(wlCount) + "):");
    for (size_t i = 0; i < wlCount; i++) {
      char b[18]; hexMac(whitelist[i], b, sizeof(b));
      jout("  " + String(b));
    }
  } else if (s.startsWith("wl add ")) {
    uint8_t mac[6]; unsigned v[6];
    String m = s.substring(7); m.replace(':', ' ');
    if (sscanf(m.c_str(), "%x %x %x %x %x %x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) == 6) {
      for (int i = 0; i < 6; i++) mac[i] = v[i];
      char b[18]; hexMac(mac, b, sizeof(b));
      jout(String(wlAdd(mac) ? "added " : "full: ") + b);
    } else jout("format: wl add AA:BB:CC:DD:EE:FF");
  } else if (s == "wl clear") { wlClear(); jout("whitelist cleared"); }
  else if (s == "wipe") {
    memset(devices, 0, sizeof(devices));
    memset(places, 0, sizeof(places));
    curPlace = -1; nBleSeen = nWifiSeen = 0; alertCount = 0;
    jout("data wiped");
  } else if (s.length()) jout("unknown cmd (help)");
}

// ============================ setup / loop ============================
static void enterBle() {
  if (!bleUp) {
    bool ok = NimBLEDevice::init("");
    jout("{\"ev\":\"ble_init\",\"ok\":" + String(ok ? 1 : 0) + "}");
    if (!ok) return;
    NimBLEScan* pScan = NimBLEDevice::getScan();
    pScan->setScanCallbacks(new ScanCallbacks(), false);
    pScan->setActiveScan(true);
    pScan->setMaxResults(0);
    bleUp = true;
  }
  bool ok = NimBLEDevice::getScan()->start(PHASE_MS[PH_BLE] / 1000, false, false);
  jout("{\"ev\":\"ble_start\",\"ok\":" + String(ok ? 1 : 0) + "}");
}

static void exitBle() {
  if (!bleUp) return;
  NimBLEDevice::getScan()->stop();
  NimBLEDevice::deinit(true);
  bleUp = false;
}

void setup() {
  Serial.begin(115200);
  pinMode(TFT_BL, OUTPUT); digitalWrite(TFT_BL, HIGH);
  pinMode(BTN_L, INPUT_PULLUP);
  pinMode(BTN_R, INPUT_PULLUP);

  tft.init(135, 240);
  tft.setRotation(1);
  tft.fillScreen(0x0000);
  tft.setTextColor(0xFFFF); tft.setTextSize(2);
  tft.setCursor(10, 40); tft.print("TailBait-ESP32");
  tft.setTextSize(1);
  tft.setCursor(10, 70); tft.print("BLE + WiFi stalking detector");

  wlLoad();
  // first place fingerprint before first detections
  updatePlace();
  jout("{\"ev\":\"boot\",\"place\":" + String(curPlace) + "}");
  phase = PH_BLE; phaseStart = millis();
  enterBle();
  drawUI(true);
}

static bool btnL() { return digitalRead(BTN_L) == LOW; }
static bool btnR() { return digitalRead(BTN_R) == LOW; }

static void buttons() {
  static uint32_t lT = 0, rT = 0, bothT = 0;
  static bool lWas = false, rWas = false, bothWas = false;
  bool l = btnL(), r = btnR(), both = l && r;
  if (both && !bothWas) bothT = millis();
  if (!both && bothWas && millis() - bothT > 1500) {
    wlClear(); jout("{\"ev\":\"wl_cleared\"}"); drawUI(true);
  }
  if (l && !r && !lWas) lT = millis();
  if (!l && lWas && !r && millis() - lT < 1500) {
    curScreen = (curScreen + 1) % SCR_COUNT; drawUI(true);
  }
  if (r && !l && !rWas) rT = millis();
  if (!r && rWas && !l && millis() - rT < 1500) {
    if (curScreen == SCR_ALERTS && alertCount && alertRows[0].dev) {
      if (wlAdd(alertRows[0].dev->key)) {
        char b[18]; hexMac(alertRows[0].dev->key, b, sizeof(b));
        jout("{\"ev\":\"wl_add\",\"mac\":\"" + String(b) + "\"}");
        alertRows[0].dev->lastScore = 0;
      }
      analyze(); drawUI(true);
    }
  }
  lWas = l; rWas = r; bothWas = both;
}

void loop() {
  // serial commands
  while (Serial.available()) {
    static String in;
    char c = Serial.read();
    if (c == '\n' || c == '\r') { if (in.length()) { handleCmd(in); in = ""; } }
    else if (in.length() < 96) in += c;
  }

  buttons();

  switch (phase) {
    case PH_BLE:
      if (millis() - phaseStart >= PHASE_MS[PH_BLE]) {
        exitBle();
        phase = PH_SNIFF; phaseStart = millis();
      }
      break;
    case PH_SNIFF:
      if (!sniffing) wifiSniff(PHASE_MS[PH_SNIFF]);
      if (millis() - phaseStart >= PHASE_MS[PH_SNIFF]) {
        phase = PH_PLACE; phaseStart = millis();
      }
      break;
    case PH_PLACE:
      updatePlace();
      phase = PH_ANALYZE; phaseStart = millis();
      break;
    case PH_ANALYZE:
      wifiEnd();
      analyze();
      cycleCount++;
      phase = PH_BLE; phaseStart = millis();
      enterBle();
      break;
    default: phase = PH_BLE;
  }

  drawUI(false);
}
