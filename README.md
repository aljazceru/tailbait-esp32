# TailBait-ESP32

A port of the [TailBait](../tailbait/) anti-stalking detection core to the
LILYGO TTGO T-Display v1.1 (ESP32, ST7789 135x240, CH9102F).

## What it does

Continuously watches for devices around you — **both BLE and WiFi** — and
alerts when one keeps showing up across many distinct *places*.

## Mapping from the Android app

| TailBait (Android)                | This port                                        |
|-----------------------------------|--------------------------------------------------|
| GPS locations (lat/lon, Haversine)| Place = fingerprint of nearby AP BSSIDs (Jaccard) |
| ≥3 distinct locations, ≥100 m     | ≥3 distinct places (Jaccard < 0.90)              |
| ThreatScoreCalculator (7 factors) | same weights, fingerprint-dissimilarity as "distance" |
| Apple Find My parsing (0x12, status 0x04 = separated) | same, + pubkey fingerprint key (survives MAC rotation) |
| Tracker service UUIDs (FD5A/FEED/…) | same table                                   |
| Companion-device filter (80% coverage, RSSI ≥ −50) | same                              |
| Whitelist (UI)                    | whitelist via buttons + serial, stored in NVS    |
| ShadowAnalyzer (MAC-rotation-resistant identity) | directed-probe SSID hash shadow identities |
| DetectionWorker every 15 min      | analysis at the end of every radio cycle (~25 s) |
| Notifications                     | display ALERTS page + JSON events on serial      |

## WiFi expansion (new)

The ESP32's promiscuous mode adds what the phone app can't do:

- **WiFi device tracking**: probe requests and station frames give a
  per-device MAC + RSSI trail, flagged when the MAC is randomized
  (locally-administered bit).
- **Shadow identities**: directed probes leak the SSIDs a phone has saved —
  a stable, rotation-proof identity (analog of the app's ShadowAnalyzer).

## Radio scheduling

The single radio is time-sliced: BLE scan (12 s) → promiscuous WiFi sniff
(8 s) → AP scan for the place fingerprint (~2 s) → analyze → repeat.

## Usage

Serial console at 115200 (JSON events out, commands in):

    help | devices | places | alerts
    sim tracker AA:BB:CC:DD:EE:01   # inject synthetic stalker (demo/test)
    sim phone  AA:BB:CC:DD:EE:02
    wl | wl add AA:BB:CC:DD:EE:FF | wl clear
    wipe

Buttons: **LEFT** cycles pages (status/alerts), **RIGHT** on the alerts page
whitelists the top device, **hold both** clears the whitelist.

## Tuning

- `PLACE_SIM_NEW` — Jaccard threshold for "new place". `0.90` = strict
  (bench testing); use ~`0.35` for real mobile use where environments drift.
- `MIN_PLACES`, `MIN_THREAT_ALERT` — as in the app (3, 0.5).
- `MAX_*` — memory budget for the device/place tables (RAM is plentiful).

## Verified live

- BLE scan: sees real devices (Govee light, laptop BlueZ advertisement)
- Find My "separated" AirTag fingerprinting via injected advertisement data
- WiFi tracking: neighbors' phones, randomized-MAC flag
- Shadow identities from directed probes
- Multi-place rotation via hotspot BSSID switching → real ALERT fired
- End-to-end scoring: `sim tracker` → score 0.64 `tracker:true separated:true`

## Limitations vs the phone app

- No GPS: "distance between places" is fingerprint dissimilarity, not meters
- No background cloud of scan data: 48-device / 10-place working set in RAM
- BLE and WiFi cannot run simultaneously (time-sliced, ~20 s cadence)
