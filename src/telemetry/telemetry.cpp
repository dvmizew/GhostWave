/**
 * @file telemetry.cpp
 * @brief Static JSON Serializer
 */

#include "telemetry/telemetry.h"
#include <stdio.h>
#include <string.h>

static char s_json_buffer[TELEMETRY_BUFFER_SIZE];

static const char *getAuthModeStr(uint8_t auth) {
    switch (auth) {
        case AUTH_WEP:  return "WEP";
        case AUTH_WPA:  return "WPA";
        case AUTH_WPA2: return "WPA2";
        case AUTH_WPA3: return "WPA3";
        case AUTH_OPEN:
        default:        return "OPEN";
    }
}

static void sanitizeJsonStr(const char *src, char *dst, size_t dstSize) {
    size_t s = 0;
    for (; s + 1 < dstSize && src[s] != '\0'; s++) {
        char c = src[s];
        dst[s] = (c >= 32 && c <= 126 && c != '"' && c != '\\') ? c : '.';
    }
    dst[s] = '\0';
}

size_t Telemetry::formatJson(const SpectrumSnapshot &snapshot, char *outBuffer, size_t maxLen) {
    if (outBuffer == nullptr || maxLen < 64) {
        return 0;
    }

    if (snapshot.opMode == OP_MODE_TUNER) {
        int written = snprintf(outBuffer, maxLen,
            "{\"node\":\"ghostwave\",\"mode\":\"tuner\",\"seq\":%u,\"freq\":%.1f,\"lev\":%u,\"stereo\":%s,\"if_cnt\":%u,\"if_lock\":%s,\"mute\":%s,\"mono\":%s}\n",
            snapshot.seq,
            snapshot.tunerFreq,
            snapshot.tunerLevel,
            snapshot.tunerStereo ? "true" : "false",
            snapshot.tunerIfCount,
            snapshot.tunerIfLock ? "true" : "false",
            snapshot.tunerMute ? "true" : "false",
            snapshot.tunerMono ? "true" : "false");
        return (written > 0 && static_cast<size_t>(written) < maxLen) ? static_cast<size_t>(written) : 0;
    }

    if (snapshot.opMode == OP_MODE_BUG_HUNTER) {
        int offset = snprintf(outBuffer, maxLen,
            "{\"node\":\"ghostwave\",\"mode\":\"bug_hunter\",\"seq\":%u,\"sweep_ms\":%u,\"noise\":%u,\"threat\":%u,\"targets\":[",
            snapshot.seq,
            snapshot.sweepDurationMs,
            snapshot.bugNoiseFloor,
            snapshot.bugThreatLevel);

        if (offset < 0 || static_cast<size_t>(offset) >= maxLen) {
            return 0;
        }

        for (uint8_t i = 0; i < snapshot.bugCount && i < MAX_BUG_TARGETS && offset < static_cast<int>(maxLen) - 80; i++) {
            const BugTargetRecord &b = snapshot.bugList[i];
            int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset),
                "%s{\"freq\":%.1f,\"lev\":%u,\"delta\":%u,\"if_cnt\":%u,\"valid_if\":%s}",
                (i == 0) ? "" : ",",
                b.freqMHz,
                b.level,
                b.deltaAboveNoise,
                b.ifCount,
                b.validIf ? "true" : "false");
            if (written < 0 || static_cast<size_t>(offset + written) >= maxLen) {
                break;
            }
            offset += written;
        }

        if (offset <= static_cast<int>(maxLen) - 4) {
            int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset), "]}\n");
            if (written > 0 && static_cast<size_t>(offset + written) < maxLen) {
                offset += written;
            }
        }

        return (offset > 0 && static_cast<size_t>(offset) < maxLen) ? static_cast<size_t>(offset) : 0;
    }

    int offset = snprintf(outBuffer, maxLen,
        "{\"node\":\"ghostwave\",\"mode\":\"sweep\",\"seq\":%u,\"uptime_ms\":%lu,\"sweep_ms\":%u,\"tea_err\":%u,\"ble_devs\":%u,\"ble_rssi\":%d,\"deauth_pkts\":%u,\"deauth_ch\":%u,\"lock_ch\":%u,\"fm\":[",
        snapshot.seq, static_cast<unsigned long>(snapshot.timestampMs),
        snapshot.sweepDurationMs, snapshot.teaError, snapshot.bleDevices, snapshot.bleMaxRssi,
        snapshot.wifiDeauthPkts, snapshot.wifiDeauthChannel, snapshot.wifiLockChannel);

    if (offset < 0 || static_cast<size_t>(offset) >= maxLen) {
        return 0;
    }

    // 1. FM Spectrum RSSI Bins (128 values)
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

    // 3b. Wi-Fi Hardware Noise Floor (13 channels)
    if (offset < static_cast<int>(maxLen) - 120) {
        int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset), "],\"wifi_noise\":[");
        if (written > 0 && static_cast<size_t>(offset + written) < maxLen) {
            offset += written;
        }
    }

    for (int i = 0; i < GHOSTWAVE_WIFI_CHANNELS && offset < static_cast<int>(maxLen) - 100; i++) {
        int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset),
                               (i == 0) ? "%d" : ",%d", snapshot.wifiNoiseFloor[i]);
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

    for (uint8_t i = 0; i < snapshot.apCount && i < MAX_DISCOVERED_APS && static_cast<size_t>(offset) + 256 < maxLen; i++) {
        const WifiApRecord &ap = snapshot.apList[i];
        char cleanSsid[33];
        char cleanWps[24];
        sanitizeJsonStr(ap.ssid, cleanSsid, sizeof(cleanSsid));
        sanitizeJsonStr(ap.wpsModel, cleanWps, sizeof(cleanWps));
        int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset),
            "%s{\"ssid\":\"%s\",\"bssid\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"ch\":%u,\"rssi\":%d,\"auth\":\"%s\",\"sta\":%u,\"wifi\":%u,\"mlo\":%s,\"util\":%d,\"caps\":%u,\"mesh\":%u,\"cc\":\"%s\",\"txp\":%d,\"wps\":\"%s\"}",
            (i == 0) ? "" : ",",
            cleanSsid,
            ap.bssid[0], ap.bssid[1], ap.bssid[2], ap.bssid[3], ap.bssid[4], ap.bssid[5],
            ap.channel, ap.rssi, getAuthModeStr(ap.authMode), ap.staCount,
            ap.wifiStd,
            ap.mlo ? "true" : "false",
            (ap.channelUtil == 0xFF) ? -1 : static_cast<int>(ap.channelUtil),
            ap.caps,
            ap.mesh,
            ap.country,
            ap.maxTxPower,
            cleanWps);
        if (written < 0 || static_cast<size_t>(offset + written) + 4 >= maxLen) {
            break;
        }
        offset += written;
    }

    // 5. Associated Wi-Fi Clients (Connected STAs only)
    if (static_cast<size_t>(offset) + 80 < maxLen) {
        int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset), "],\"clients\":[");
        if (written > 0 && static_cast<size_t>(offset + written) + 4 < maxLen) {
            offset += written;
        }
    }

    for (uint8_t i = 0; i < snapshot.clientCount && i < MAX_DISCOVERED_CLIENTS && static_cast<size_t>(offset) + 210 < maxLen; i++) {
        const WifiClientRecord &cli = snapshot.clientList[i];
        int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset),
            "%s{\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"bssid\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"ch\":%u,\"rssi\":%d,\"tx\":%u,\"rx\":%u,\"txb\":%lu,\"rxb\":%lu,\"rty\":%u,\"phy\":%u,\"mcs\":%u,\"rate\":%u,\"wifi\":%u,\"flg\":%u,\"eap\":%u}",
            (i == 0) ? "" : ",",
            cli.mac[0], cli.mac[1], cli.mac[2], cli.mac[3], cli.mac[4], cli.mac[5],
            cli.bssid[0], cli.bssid[1], cli.bssid[2], cli.bssid[3], cli.bssid[4], cli.bssid[5],
            cli.channel, cli.rssi,
            cli.txPkts, cli.rxPkts,
            static_cast<unsigned long>(cli.txBytes), static_cast<unsigned long>(cli.rxBytes),
            cli.retryPkts, cli.phyMode, cli.mcs, cli.maxRateMbps, cli.wifiStd, cli.flags, cli.eapolMask);
        if (written < 0 || static_cast<size_t>(offset + written) + 4 >= maxLen) {
            break;
        }
        offset += written;
    }

    // 5b. Directed Wi-Fi Probe Requests (strictly separate from associated clients)
    if (static_cast<size_t>(offset) + 60 < maxLen) {
        int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset), "],\"probes\":[");
        if (written > 0 && static_cast<size_t>(offset + written) + 4 < maxLen) {
            offset += written;
        }
    }

    for (uint8_t i = 0; i < snapshot.probeCount && i < MAX_DISCOVERED_PROBES && static_cast<size_t>(offset) + 110 < maxLen; i++) {
        const WifiProbeRecord &pr = snapshot.probeList[i];
        char cleanSsid[33];
        sanitizeJsonStr(pr.ssid, cleanSsid, sizeof(cleanSsid));
        int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset),
            "%s{\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"ssid\":\"%s\",\"rssi\":%d,\"ch\":%u}",
            (i == 0) ? "" : ",",
            pr.mac[0], pr.mac[1], pr.mac[2], pr.mac[3], pr.mac[4], pr.mac[5],
            cleanSsid, pr.rssi, pr.channel);
        if (written < 0 || static_cast<size_t>(offset + written) + 4 >= maxLen) {
            break;
        }
        offset += written;
    }

    // 6. Discovered BLE Devices
    if (static_cast<size_t>(offset) + 60 < maxLen) {
        int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset), "],\"bles\":[");
        if (written > 0 && static_cast<size_t>(offset + written) + 4 < maxLen) {
            offset += written;
        }
    }

    for (uint8_t i = 0; i < snapshot.bleCount && i < MAX_DISCOVERED_BLE && static_cast<size_t>(offset) + 80 < maxLen; i++) {
        const BleDeviceRecord &ble = snapshot.bleList[i];
        char cleanName[20];
        sanitizeJsonStr(ble.name, cleanName, sizeof(cleanName));
        int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset),
            "%s{\"name\":\"%s\",\"addr\":\"%s\",\"rssi\":%d}",
            (i == 0) ? "" : ",",
            cleanName,
            ble.addr,
            ble.rssi);
        if (written < 0 || static_cast<size_t>(offset + written) + 4 >= maxLen) {
            break;
        }
        offset += written;
    }

    // 7. Discovered Active FM Stations
    if (static_cast<size_t>(offset) + 60 < maxLen) {
        int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset), "],\"stations\":[");
        if (written > 0 && static_cast<size_t>(offset + written) + 4 < maxLen) {
            offset += written;
        }
    }

    for (uint8_t i = 0; i < snapshot.stationCount && i < MAX_DISCOVERED_STATIONS && static_cast<size_t>(offset) + 80 < maxLen; i++) {
        const FmStationRecord &st = snapshot.stationList[i];
        int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset),
            "%s{\"freq\":%.1f,\"lev\":%u,\"stereo\":%s,\"if_cnt\":%u,\"if_lock\":%s}",
            (i == 0) ? "" : ",",
            st.freqMHz,
            st.level,
            st.stereo ? "true" : "false",
            st.ifCount,
            st.validIf ? "true" : "false");
        if (written < 0 || static_cast<size_t>(offset + written) + 4 >= maxLen) {
            break;
        }
        offset += written;
    }

    if (static_cast<size_t>(offset) + 4 <= maxLen) {
        int written = snprintf(outBuffer + offset, maxLen - static_cast<size_t>(offset), "]}\n");
        if (written > 0 && static_cast<size_t>(offset + written) < maxLen) {
            return static_cast<size_t>(offset + written);
        }
    }

    return 0;
}

size_t Telemetry::streamJson(Print &output, const SpectrumSnapshot &snapshot) {
    size_t len = formatJson(snapshot, s_json_buffer, sizeof(s_json_buffer));
    if (len > 0) {
        output.write(reinterpret_cast<const uint8_t *>(s_json_buffer), len);
    }
    return len;
}
