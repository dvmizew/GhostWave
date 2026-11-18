/**
 * @file types.h
 * @brief GhostWave Shared Telemetry Structures
 *
 * Shared data structures for FreeRTOS spectrum telemetry and RF asset data.
 */

#ifndef GHOSTWAVE_TYPES_H
#define GHOSTWAVE_TYPES_H

#include <stdint.h>
#include "config.h"

#define MAX_DISCOVERED_APS  8
#define MAX_DISCOVERED_BLE  8

struct WifiApRecord {
    char    ssid[24];
    uint8_t bssid[6];
    uint8_t channel;
    int8_t  rssi;
};

struct BleDeviceRecord {
    char   name[20];
    char   addr[18];
    int8_t rssi;
};

/**
 * @brief Shared FreeRTOS Telemetry Structure transferred across cores.
 */
struct SpectrumSnapshot {
    uint32_t timestampMs;                                   // Uptime timestamp at end of sweep
    uint16_t sweepDurationMs;                               // Elapsed duration of full sweep cycle
    uint16_t seq;                                           // Monotonically increasing sweep sequence
    uint8_t  fmRssi[GHOSTWAVE_FM_BINS];                     // 64 bins, ADC signal level 0 to 15
    uint16_t wifiPkts[GHOSTWAVE_WIFI_CHANNELS];             // Management & data packets per channel
    int8_t   wifiMaxRssi[GHOSTWAVE_WIFI_CHANNELS];          // Peak RSSI in dBm (-128 if no traffic)
    uint16_t bleDevices;                                    // Active advertising BLE devices observed
    int8_t   bleMaxRssi;                                    // Peak BLE RSSI observed in dBm (-128 if none)
    uint8_t  apCount;                                       // Number of beacon APs discovered in this sweep
    WifiApRecord apList[MAX_DISCOVERED_APS];                // Discovered Wi-Fi networks (SSID, BSSID, Ch, RSSI)
    uint8_t  bleCount;                                      // Number of unique BLE devices discovered
    BleDeviceRecord bleList[MAX_DISCOVERED_BLE];            // Discovered BLE devices (Name, MAC, RSSI)
};

#endif // GHOSTWAVE_TYPES_H
