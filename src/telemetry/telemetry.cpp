/**
 * @file telemetry.cpp
 * @brief Zero-Heap Static JSON Serializer
 */

#include "telemetry/telemetry.h"
#include <stdio.h>
#include <string.h>

// Static buffer for serial streaming
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

    // 1. FM Spectrum RSSI Bins (64 values)
    for (int i = 0; i < GHOSTWAVE_FM_BINS && offset < static_cast<int>(maxLen) - 200; i++) {
        int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset),
                               (i == 0) ? "%u" : ",%u", snapshot.fmRssi[i]);
        if (written < 0 || static_cast<size_t>(offset + written) >= maxLen) {
            break;
        }
        offset += written;
    }

    // 2. Wi-Fi Packet Counts (13 channels)
    if (offset < static_cast<int>(maxLen) - 180) {
        int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset), "],\"wifi_pkts\":[");
        if (written > 0 && static_cast<size_t>(offset + written) < maxLen) {
            offset += written;
        }
    }

    for (int i = 0; i < GHOSTWAVE_WIFI_CHANNELS && offset < static_cast<int>(maxLen) - 150; i++) {
        int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset),
                               (i == 0) ? "%u" : ",%u", snapshot.wifiPkts[i]);
        if (written < 0 || static_cast<size_t>(offset + written) >= maxLen) {
            break;
        }
        offset += written;
    }

    // 3. Wi-Fi Peak RSSI (13 channels)
    if (offset < static_cast<int>(maxLen) - 120) {
        int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset), "],\"wifi_rssi\":[");
        if (written > 0 && static_cast<size_t>(offset + written) < maxLen) {
            offset += written;
        }
    }

    for (int i = 0; i < GHOSTWAVE_WIFI_CHANNELS && offset < static_cast<int>(maxLen) - 100; i++) {
        int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset),
                               (i == 0) ? "%d" : ",%d", snapshot.wifiMaxRssi[i]);
        if (written < 0 || static_cast<size_t>(offset + written) >= maxLen) {
            break;
        }
        offset += written;
    }

    // 4. Discovered Wi-Fi APs
    if (offset < static_cast<int>(maxLen) - 80) {
        int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset), "],\"aps\":[");
        if (written > 0 && static_cast<size_t>(offset + written) < maxLen) {
            offset += written;
        }
    }

    for (uint8_t i = 0; i < snapshot.apCount && i < MAX_DISCOVERED_APS && offset < static_cast<int>(maxLen) - 120; i++) {
        const WifiApRecord &ap = snapshot.apList[i];
        char cleanSsid[24] = {0};
        for (size_t s = 0; s < sizeof(cleanSsid) - 1 && ap.ssid[s] != '\0'; s++) {
            char c = ap.ssid[s];
            cleanSsid[s] = (c == '"' || c == '\\') ? '.' : c;
        }
        int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset),
            "%s{\"ssid\":\"%s\",\"bssid\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"ch\":%u,\"rssi\":%d}",
            (i == 0) ? "" : ",",
            cleanSsid,
            ap.bssid[0], ap.bssid[1], ap.bssid[2], ap.bssid[3], ap.bssid[4], ap.bssid[5],
            ap.channel, ap.rssi);
        if (written < 0 || static_cast<size_t>(offset + written) >= maxLen) {
            break;
        }
        offset += written;
    }

    // 5. Discovered BLE Devices
    if (offset < static_cast<int>(maxLen) - 60) {
        int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset), "],\"bles\":[");
        if (written > 0 && static_cast<size_t>(offset + written) < maxLen) {
            offset += written;
        }
    }

    for (uint8_t i = 0; i < snapshot.bleCount && i < MAX_DISCOVERED_BLE && offset < static_cast<int>(maxLen) - 80; i++) {
        const BleDeviceRecord &ble = snapshot.bleList[i];
        char cleanName[20] = {0};
        for (size_t s = 0; s < sizeof(cleanName) - 1 && ble.name[s] != '\0'; s++) {
            char c = ble.name[s];
            cleanName[s] = (c == '"' || c == '\\') ? '.' : c;
        }
        int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset),
            "%s{\"name\":\"%s\",\"addr\":\"%s\",\"rssi\":%d}",
            (i == 0) ? "" : ",",
            cleanName,
            ble.addr,
            ble.rssi);
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
