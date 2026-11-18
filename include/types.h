/**
 * @file types.h
 * @brief GhostWave Shared Telemetry Structures
 *
 * Thread-safe FreeRTOS spectrum telemetry data structures.
 */

#ifndef GHOSTWAVE_TYPES_H
#define GHOSTWAVE_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include "config.h"

/**
 * @brief Thread-safe FreeRTOS Telemetry Structure transferred across cores.
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
};

#endif // GHOSTWAVE_TYPES_H
