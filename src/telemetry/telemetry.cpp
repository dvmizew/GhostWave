/**
 * @file telemetry.cpp
 * @brief Zero-Heap Static JSON Serializer Implementation
 */

#include "telemetry/telemetry.h"
#include <stdio.h>

// Static buffer for serial streaming (zero heap churn)
static char s_json_buffer[TELEMETRY_BUFFER_SIZE];

size_t Telemetry::formatJson(const SpectrumSnapshot &snapshot, char *outBuffer, size_t maxLen) {
    if (outBuffer == nullptr || maxLen < 64) {
        return 0;
    }

    int offset = snprintf(outBuffer, maxLen,
        "{\"node\":\"ghostwave\",\"seq\":%u,\"uptime_ms\":%lu,\"sweep_ms\":%u,\"ble_devs\":%u,\"ble_rssi\":%d,\"fm\":[",
        snapshot.seq, static_cast<unsigned long>(snapshot.timestampMs),
        snapshot.sweepDurationMs, snapshot.bleDevices, snapshot.bleMaxRssi);

    if (offset < 0 || static_cast<size_t>(offset) >= maxLen) {
        return 0;
    }

    for (int i = 0; i < GHOSTWAVE_FM_BINS && offset < static_cast<int>(maxLen) - 100; i++) {
        int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset),
                               (i == 0) ? "%u" : ",%u", snapshot.fmRssi[i]);
        if (written < 0 || static_cast<size_t>(offset + written) >= maxLen) {
            break;
        }
        offset += written;
    }

    if (offset < static_cast<int>(maxLen) - 60) {
        int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset), "],\"wifi_pkts\":[");
        if (written > 0 && static_cast<size_t>(offset + written) < maxLen) {
            offset += written;
        }
    }

    for (int i = 0; i < GHOSTWAVE_WIFI_CHANNELS && offset < static_cast<int>(maxLen) - 60; i++) {
        int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset),
                               (i == 0) ? "%u" : ",%u", snapshot.wifiPkts[i]);
        if (written < 0 || static_cast<size_t>(offset + written) >= maxLen) {
            break;
        }
        offset += written;
    }

    if (offset < static_cast<int>(maxLen) - 20) {
        int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset), "],\"wifi_rssi\":[");
        if (written > 0 && static_cast<size_t>(offset + written) < maxLen) {
            offset += written;
        }
    }

    for (int i = 0; i < GHOSTWAVE_WIFI_CHANNELS && offset < static_cast<int>(maxLen) - 20; i++) {
        int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset),
                               (i == 0) ? "%d" : ",%d", snapshot.wifiMaxRssi[i]);
        if (written < 0 || static_cast<size_t>(offset + written) >= maxLen) {
            break;
        }
        offset += written;
    }

    if (offset < static_cast<int>(maxLen) - 3) {
        int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset), "]}\n");
        if (written > 0 && static_cast<size_t>(offset + written) < maxLen) {
            offset += written;
        }
    }

    return (offset > 0 && static_cast<size_t>(offset) < maxLen) ? static_cast<size_t>(offset) : 0;
}

size_t Telemetry::streamJson(Print &output, const SpectrumSnapshot &snapshot) {
    size_t len = formatJson(snapshot, s_json_buffer, sizeof(s_json_buffer));
    if (len > 0) {
        output.write(reinterpret_cast<const uint8_t *>(s_json_buffer), len);
    }
    return len;
}
