/**
 * @file wifi_sniffer.cpp
 * @brief Wi-Fi Promiscuous Sniffer
 */

#include "rf/wifi_sniffer.h"
#include <Arduino.h>
#include <WiFi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <string.h>
#include <esp_timer.h>

static portMUX_TYPE s_wifi_mux = portMUX_INITIALIZER_UNLOCKED;

static volatile uint8_t  s_current_channel = 1;
static volatile uint16_t s_wifi_pkts_temp[GHOSTWAVE_WIFI_CHANNELS] = {0};
static volatile int8_t   s_wifi_rssi_temp[GHOSTWAVE_WIFI_CHANNELS] = {0};
static volatile int8_t   s_wifi_noise_temp[GHOSTWAVE_WIFI_CHANNELS] = {0};
static volatile uint16_t s_wifi_deauth_temp[GHOSTWAVE_WIFI_CHANNELS] = {0};

typedef struct {
    uint16_t frame_ctrl;
    uint16_t duration_id;
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6]; // BSSID
    uint16_t seq_ctrl;
} __attribute__((packed)) wifi_mgmt_hdr_t;

struct WifiApEntry {
    WifiApRecord record;
    uint32_t     lastSeenMs;
};

struct WifiClientEntry {
    WifiClientRecord record;
    uint32_t         lastSeenMs;
};

struct WifiProbeEntry {
    WifiProbeRecord record;
    uint32_t        lastSeenMs;
};

static WifiApEntry     s_ap_records[MAX_DISCOVERED_APS];
static uint8_t         s_ap_count = 0;

static WifiClientEntry s_client_records[MAX_DISCOVERED_CLIENTS];
static uint8_t         s_client_count = 0;

static WifiProbeEntry  s_probe_records[MAX_DISCOVERED_PROBES];
static uint8_t         s_probe_count = 0;

static inline uint32_t getNowMs() {
    return static_cast<uint32_t>(esp_timer_get_time() / 1000);
}

static inline int8_t findApIndexByBssid(const uint8_t *bssid) {
    for (uint8_t i = 0; i < s_ap_count; i++) {
        if (memcmp(s_ap_records[i].record.bssid, bssid, 6) == 0) {
            return static_cast<int8_t>(i);
        }
    }
    return -1;
}

static inline bool isKnownAp(const uint8_t *mac) {
    return findApIndexByBssid(mac) >= 0;
}

static inline bool isValidUnicastMac(const uint8_t *mac) {
    return (mac != nullptr) &&
           ((mac[0] & 0x01) == 0) &&
           ((mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]) != 0);
}

static inline void parseSsidIe(const uint8_t *data, uint8_t elen, char *outBuf) {
    uint8_t copyLen = (elen > 32) ? 32 : elen;
    bool allZero = true;
    for (uint8_t i = 0; i < copyLen; i++) {
        if (data[i] != 0) {
            allZero = false;
            break;
        }
    }
    if (allZero) return;
    for (uint8_t i = 0; i < copyLen; i++) {
        char c = static_cast<char>(data[i]);
        outBuf[i] = (c >= 32 && c <= 126) ? c : '?';
    }
    outBuf[copyLen] = '\0';
}

static inline void parseWpsIe(const uint8_t *data, uint16_t len, uint8_t &caps, char *wpsModel, size_t modelSize) {
    uint8_t bestPriority = 0;
    uint16_t pos = 0;
    while (pos + 4 <= len) {
        uint16_t attrId  = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
        uint16_t attrLen = (static_cast<uint16_t>(data[pos + 2]) << 8) | data[pos + 3];
        pos += 4;
        if (pos + attrLen > len) break;

        if (attrId == 0x1057 && attrLen >= 1 && data[pos] == 1) {
            caps |= WIFI_AP_CAP_WPS_LOCK;
        } else if (attrLen > 0 && (attrId == 0x1023 || attrId == 0x1011 || attrId == 0x1021)) {
            uint8_t prio = (attrId == 0x1023) ? 3 : ((attrId == 0x1011) ? 2 : 1);
            if (prio > bestPriority && modelSize > 1) {
                char tmp[24];
                size_t maxCopy = (modelSize < sizeof(tmp)) ? (modelSize - 1) : (sizeof(tmp) - 1);
                size_t copyLen = (attrLen < maxCopy) ? attrLen : maxCopy;
                size_t outLen = 0;
                for (size_t i = 0; i < copyLen; i++) {
                    char c = static_cast<char>(data[pos + i]);
                    if (c >= 32 && c <= 126) {
                        tmp[outLen++] = c;
                    }
                }
                while (outLen > 0 && tmp[outLen - 1] == ' ') outLen--;
                if (outLen > 0) {
                    memcpy(wpsModel, tmp, outLen);
                    wpsModel[outLen] = '\0';
                    bestPriority = prio;
                }
            }
        }
        pos += attrLen;
    }
}

static inline uint8_t parseEapolKeyMsg(const uint8_t *payload, uint16_t len, uint16_t fc, bool isQos) {
    uint16_t hdrLen = 24 + (isQos ? 2 : 0) + ((isQos && ((fc & 0x8000) != 0)) ? 4 : 0);
    if (len < hdrLen + 15) return 0; // 8B LLC/SNAP + 7B EAPOL-Key header

    const uint8_t *llc = payload + hdrLen;
    if (llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03 ||
        llc[3] != 0x00 || llc[4] != 0x00 || llc[5] != 0x00 ||
        llc[6] != 0x88 || llc[7] != 0x8E) {
        return 0;
    }

    const uint8_t *eapol = llc + 8;
    if (eapol[1] != 0x03 || (eapol[4] != 0x02 && eapol[4] != 0xFE)) return 0;

    uint16_t keyInfo = (static_cast<uint16_t>(eapol[5]) << 8) | eapol[6];
    if ((keyInfo & 0x0008) == 0 || (keyInfo & 0x0C00) != 0) return 0; // Pairwise only; ignore Error/Request

    bool inst = (keyInfo & 0x0040) != 0;
    bool ack  = (keyInfo & 0x0080) != 0;
    bool mic  = (keyInfo & 0x0100) != 0;
    bool sec  = (keyInfo & 0x0200) != 0;

    if (ack && !mic && !inst && !sec) return 0x01; // M1
    if (!ack && mic && !inst && !sec) return 0x02; // M2
    if (ack && mic && inst && (sec || eapol[4] == 0xFE)) return 0x04; // M3 (RSN: Secure=1, WPA1: Secure=0)
    if (!ack && mic && !inst && sec)  return 0x08; // M4
    return 0;
}

static inline uint8_t computePhyRateMbps(const wifi_pkt_rx_ctrl_t &rx) {
    if (rx.sig_mode == 1) { // HT (802.11n) 1SS MCS 0..7
        static const uint8_t kHt20Lgi[8] = {7, 13, 20, 26, 39, 52, 59, 65};
        static const uint8_t kHt20Sgi[8] = {7, 14, 22, 29, 43, 58, 65, 72};
        static const uint8_t kHt40Lgi[8] = {14, 27, 41, 54, 81, 108, 122, 135};
        static const uint8_t kHt40Sgi[8] = {15, 30, 45, 60, 90, 120, 135, 150};
        uint8_t mcsIdx = rx.mcs & 0x07;
        if (rx.cwb) {
            return rx.sgi ? kHt40Sgi[mcsIdx] : kHt40Lgi[mcsIdx];
        }
        return rx.sgi ? kHt20Sgi[mcsIdx] : kHt20Lgi[mcsIdx];
    }
    if (rx.sig_mode == 0) { // Legacy 802.11b/g
        switch (rx.rate) {
            case 0x00: return 1;
            case 0x01: case 0x05: return 2;
            case 0x02: case 0x06: return 6;  // 5.5 Mbps rounded
            case 0x03: case 0x07: return 11;
            case 0x0B: return 6;
            case 0x0F: return 9;
            case 0x0A: return 12;
            case 0x0E: return 18;
            case 0x09: return 24;
            case 0x0D: return 36;
            case 0x08: return 48;
            case 0x0C: return 54;
            default: return 0;
        }
    }
    return 0;
}

// Upserts an associated Wi-Fi client inside s_wifi_mux critical section
static inline void upsertAssociatedClient(
    const uint8_t *clientMac,
    const uint8_t *apMac,
    uint8_t ch,
    int8_t rssi,
    bool isClientTx,
    const wifi_pkt_rx_ctrl_t &rx,
    uint16_t l2Bytes,
    bool isRetry,
    bool hasPwrMgt,
    bool pwrSave,
    bool isEncrypted,
    bool isQos,
    uint8_t observedStd,
    uint8_t extraFlags,
    uint8_t eapolBit,
    uint32_t nowMs)
{
    if (isKnownAp(clientMac)) return;

    uint8_t idx = MAX_DISCOVERED_CLIENTS;
    for (uint8_t i = 0; i < s_client_count; i++) {
        if (memcmp(s_client_records[i].record.mac, clientMac, 6) == 0) {
            idx = i;
            break;
        }
    }

    if (idx == MAX_DISCOVERED_CLIENTS) {
        if (s_client_count < MAX_DISCOVERED_CLIENTS) {
            idx = s_client_count++;
        } else {
            idx = 0;
            uint32_t oldestTime = s_client_records[0].lastSeenMs;
            for (uint8_t i = 1; i < MAX_DISCOVERED_CLIENTS; i++) {
                if (s_client_records[i].lastSeenMs < oldestTime) {
                    oldestTime = s_client_records[i].lastSeenMs;
                    idx = i;
                }
            }
        }
        memset(&s_client_records[idx].record, 0, sizeof(WifiClientRecord));
    }

    WifiClientRecord &rec = s_client_records[idx].record;
    // Initialize new slot or reset per-link stats when client roams to a different BSSID
    if (memcmp(rec.bssid, apMac, 6) != 0) {
        uint8_t keepStd = rec.wifiStd;
        memset(&rec, 0, sizeof(WifiClientRecord));
        memcpy(rec.mac, clientMac, 6);
        memcpy(rec.bssid, apMac, 6);
        rec.rssi = -128;
        rec.flags = ((clientMac[0] & 0x02) != 0) ? WIFI_CLI_FLAG_RANDOM_MAC : 0;
        rec.wifiStd = keepStd;
    }

    int8_t apIdx = findApIndexByBssid(apMac);
    bool isOffChannelBleed = (apIdx >= 0 && s_ap_records[apIdx].record.channel >= 1 &&
                              s_ap_records[apIdx].record.channel <= GHOSTWAVE_WIFI_CHANNELS &&
                              s_ap_records[apIdx].record.channel != ch);

    if (!isOffChannelBleed) {
        rec.channel = ch;
    } else if (rec.channel == 0) {
        rec.channel = s_ap_records[apIdx].record.channel;
    }
    s_client_records[idx].lastSeenMs = nowMs;

    if (isClientTx) {
        if (!isOffChannelBleed || !(rec.flags & WIFI_CLI_FLAG_TX_RSSI)) {
            rec.rssi = rssi;
            rec.flags |= WIFI_CLI_FLAG_TX_RSSI;
        }
        // Keep phyMode, mcs, and maxRateMbps atomically consistent from the peak-rate frame
        uint8_t rateMbps = computePhyRateMbps(rx);
        if (rateMbps > rec.maxRateMbps || (rateMbps == rec.maxRateMbps && rx.sig_mode > rec.phyMode)) {
            rec.maxRateMbps = rateMbps;
            rec.phyMode = rx.sig_mode;
            rec.mcs = (rx.sig_mode == 1) ? (rx.mcs & 0x07) : 0;
        }
        if (rx.sig_mode == 1) {
            if (rx.cwb) rec.flags |= WIFI_CLI_FLAG_40MHZ;
            if (rx.sgi) rec.flags |= WIFI_CLI_FLAG_SGI;
            if (observedStd < 4) observedStd = 4;
        }
        // Note: Do NOT infer Wi-Fi 1 (802.11b/g) from sig_mode == 0; Wi-Fi 6/7 devices
        // routinely transmit 1 Mbps Null/QoS-Null power-save frames.
        if (hasPwrMgt) {
            if (pwrSave) rec.flags |= WIFI_CLI_FLAG_PWRSAVE;
            else rec.flags &= ~WIFI_CLI_FLAG_PWRSAVE;
        }
        if (rec.txPkts < 65535) rec.txPkts++;
        rec.txBytes += l2Bytes;
        if (isRetry && rec.retryPkts < 65535) rec.retryPkts++;
    } else {
        // AP -> Client: never overwrite true Client TX RSSI; refresh downlink RSSI on-channel
        if (!(rec.flags & WIFI_CLI_FLAG_TX_RSSI) && (!isOffChannelBleed || rec.rssi <= -128)) {
            rec.rssi = rssi;
        }
        if (rec.rxPkts < 65535) rec.rxPkts++;
        rec.rxBytes += l2Bytes;
    }

    if (isEncrypted) rec.flags |= WIFI_CLI_FLAG_ENCRYPTED;
    if (isQos)       rec.flags |= WIFI_CLI_FLAG_QOS;
    rec.flags |= extraFlags;
    rec.eapolMask |= eapolBit;

    if (observedStd > rec.wifiStd) {
        rec.wifiStd = observedStd;
    }
}

void WifiSniffer::promiscuousCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type == WIFI_PKT_MGMT || type == WIFI_PKT_DATA) {
        const wifi_promiscuous_pkt_t *pkt = reinterpret_cast<const wifi_promiscuous_pkt_t *>(buf);
        if (pkt->rx_ctrl.rx_state != 0) {
            return; // Drop frames with FCS/PHY errors to prevent phantom MACs
        }
        int8_t rssi = pkt->rx_ctrl.rssi;
        int8_t noise = pkt->rx_ctrl.noise_floor;
        uint8_t rxCh = pkt->rx_ctrl.channel;
        uint8_t ch = (rxCh >= 1 && rxCh <= GHOSTWAVE_WIFI_CHANNELS) ? rxCh : s_current_channel;

        if (ch >= 1 && ch <= GHOSTWAVE_WIFI_CHANNELS) {
            portENTER_CRITICAL(&s_wifi_mux);
            s_wifi_pkts_temp[ch - 1] = s_wifi_pkts_temp[ch - 1] + 1;
            if (rssi > s_wifi_rssi_temp[ch - 1]) {
                s_wifi_rssi_temp[ch - 1] = rssi;
            }
            if (noise != 0) {
                s_wifi_noise_temp[ch - 1] = noise;
            }
            portEXIT_CRITICAL(&s_wifi_mux);
        }

        uint32_t nowMs = getNowMs();

        // 1. Management Frames
        if (type == WIFI_PKT_MGMT && pkt->rx_ctrl.sig_len >= sizeof(wifi_mgmt_hdr_t) + 4) {
            const uint8_t *payload = pkt->payload;
            const wifi_mgmt_hdr_t *hdr = reinterpret_cast<const wifi_mgmt_hdr_t *>(payload);
            uint8_t subtype = (hdr->frame_ctrl >> 4) & 0x0F;
            uint16_t len = (pkt->rx_ctrl.sig_len > 4) ? (pkt->rx_ctrl.sig_len - 4) : pkt->rx_ctrl.sig_len;

            // 1a. Deauth & Disassociation frames (Subtype 12 = Deauth, 10 = Disassoc)
            if (subtype == 12 || subtype == 10) {
                if (ch >= 1 && ch <= GHOSTWAVE_WIFI_CHANNELS) {
                    portENTER_CRITICAL(&s_wifi_mux);
                    s_wifi_deauth_temp[ch - 1] = s_wifi_deauth_temp[ch - 1] + 1;
                    portEXIT_CRITICAL(&s_wifi_mux);
                }
            }
            // 1b. Client Association / Reassociation Request (0, 2) & Authentication (11)
            // Strictly ignores unassociated Probe Requests (subtype 4)
            else if (subtype == 0 || subtype == 2 || subtype == 11) {
                const uint8_t *clientMac = nullptr;
                const uint8_t *apMac = nullptr;
                bool isClientTx = false;

                if ((subtype == 0 || subtype == 2) && memcmp(hdr->addr1, hdr->addr3, 6) == 0) {
                    clientMac = hdr->addr2;
                    apMac = hdr->addr1;
                    isClientTx = true;
                } else if (subtype == 11) {
                    // Auth is bidirectional: BSSID is always in addr3
                    if (memcmp(hdr->addr1, hdr->addr3, 6) == 0) {
                        clientMac = hdr->addr2;
                        apMac = hdr->addr1;
                        isClientTx = true;
                    } else if (memcmp(hdr->addr2, hdr->addr3, 6) == 0) {
                        clientMac = hdr->addr1;
                        apMac = hdr->addr2;
                        isClientTx = false;
                    }
                }

                if (isValidUnicastMac(clientMac) && isValidUnicastMac(apMac)) {
                    uint8_t cliStd = 0;
                    uint8_t extraFlags = 0;
                    char assocSsid[33] = {0};

                    if (subtype == 0 || subtype == 2) {
                        // Assoc Req IEs start at 28 (24B hdr + 2B cap + 2B listen);
                        // Reassoc Req IEs start at 34 (+ 6B current AP MAC)
                        uint16_t pos = (subtype == 0) ? 28 : 34;
                        while (pos + 1 < len) {
                            uint8_t id = payload[pos];
                            uint8_t elen = payload[pos + 1];
                            if (pos + 2 + elen > len) break;

                            if (id == 0 && elen > 0 && assocSsid[0] == '\0') { // Hidden SSID uncloaking
                                parseSsidIe(&payload[pos + 2], elen, assocSsid);
                            } else if (id == 45 && elen >= 2) { // HT Capabilities -> Wi-Fi 4
                                if (cliStd < 4) cliStd = 4;
                                uint16_t htCap = payload[pos + 2] | (static_cast<uint16_t>(payload[pos + 3]) << 8);
                                if (htCap & 0x0002) extraFlags |= WIFI_CLI_FLAG_40MHZ;
                                if (htCap & 0x0060) extraFlags |= WIFI_CLI_FLAG_SGI;
                            } else if (id == 191) { // VHT Capabilities -> Wi-Fi 5
                                if (cliStd < 5) cliStd = 5;
                            } else if (id == 255 && elen >= 1) {
                                uint8_t extId = payload[pos + 2];
                                if (extId == 35 && cliStd < 6) { // HE Capabilities -> Wi-Fi 6
                                    cliStd = 6;
                                } else if (extId == 108 || extId == 107) { // EHT / Multi-Link -> Wi-Fi 7
                                    cliStd = 7;
                                }
                            }
                            pos += 2 + elen;
                        }
                    }

                    bool isRetry = ((hdr->frame_ctrl >> 11) & 0x01) != 0;
                    bool pwrSave = ((hdr->frame_ctrl >> 12) & 0x01) != 0;
                    portENTER_CRITICAL(&s_wifi_mux);
                    if (assocSsid[0] != '\0') {
                        int8_t apIdx = findApIndexByBssid(apMac);
                        if (apIdx >= 0 && s_ap_records[apIdx].record.ssid[0] == '\0') {
                            strncpy(s_ap_records[apIdx].record.ssid, assocSsid, sizeof(s_ap_records[apIdx].record.ssid) - 1);
                            s_ap_records[apIdx].record.ssid[sizeof(s_ap_records[apIdx].record.ssid) - 1] = '\0';
                        }
                    }
                    upsertAssociatedClient(
                        clientMac, apMac, ch, rssi,
                        isClientTx, pkt->rx_ctrl, len, isRetry,
                        isClientTx, pwrSave, false, false, cliStd, extraFlags, 0, nowMs);
                    portEXIT_CRITICAL(&s_wifi_mux);
                }
            }
            // 1b-2. Directed Probe Requests (Subtype 4) -> separate table, never mixed with clients
            else if (subtype == 4 && isValidUnicastMac(hdr->addr2)) {
                char probeSsid[33] = {0};
                uint16_t pos = 24;
                while (pos + 1 < len) {
                    uint8_t id = payload[pos];
                    uint8_t elen = payload[pos + 1];
                    if (pos + 2 + elen > len) break;
                    if (id == 0 && elen > 0) {
                        parseSsidIe(&payload[pos + 2], elen, probeSsid);
                        break;
                    }
                    pos += 2 + elen;
                }
                if (probeSsid[0] != '\0') {
                    portENTER_CRITICAL(&s_wifi_mux);
                    if (!isKnownAp(hdr->addr2)) {
                        uint8_t idx = MAX_DISCOVERED_PROBES;
                        for (uint8_t i = 0; i < s_probe_count; i++) {
                            if (memcmp(s_probe_records[i].record.mac, hdr->addr2, 6) == 0 &&
                                strcmp(s_probe_records[i].record.ssid, probeSsid) == 0) {
                                idx = i;
                                break;
                            }
                        }
                        if (idx == MAX_DISCOVERED_PROBES) {
                            if (s_probe_count < MAX_DISCOVERED_PROBES) {
                                idx = s_probe_count++;
                            } else {
                                idx = 0;
                                uint32_t oldest = s_probe_records[0].lastSeenMs;
                                for (uint8_t i = 1; i < MAX_DISCOVERED_PROBES; i++) {
                                    if (s_probe_records[i].lastSeenMs < oldest) {
                                        oldest = s_probe_records[i].lastSeenMs;
                                        idx = i;
                                    }
                                }
                            }
                            memcpy(s_probe_records[idx].record.mac, hdr->addr2, 6);
                            strncpy(s_probe_records[idx].record.ssid, probeSsid, sizeof(s_probe_records[idx].record.ssid) - 1);
                            s_probe_records[idx].record.ssid[sizeof(s_probe_records[idx].record.ssid) - 1] = '\0';
                        }
                        s_probe_records[idx].record.rssi = rssi;
                        s_probe_records[idx].record.channel = ch;
                        s_probe_records[idx].lastSeenMs = nowMs;
                    }
                    portEXIT_CRITICAL(&s_wifi_mux);
                }
            }
            // 1c. Beacon (Subtype 8) & Probe Response (Subtype 5)
            else if (subtype == 8 || subtype == 5) {
                if (len >= sizeof(wifi_mgmt_hdr_t) + 12) {
                    uint16_t cap = payload[34] | (static_cast<uint16_t>(payload[35]) << 8);
                    bool privacy = (cap & 0x0010) != 0;
                    uint8_t auth = privacy ? AUTH_WEP : AUTH_OPEN;

                    char ssidBuf[33] = {0};
                    uint16_t pos = 36;
                    uint8_t realCh = ch;
                    uint16_t staCount = 0;
                    uint8_t channelUtil = 0xFF;
                    uint8_t caps = 0;
                    uint8_t mesh = 0;
                    char country[3] = {0};
                    int8_t maxTxPower = 0;
                    char wpsModel[24] = {0};
                    bool hasBssLoad = false;
                    bool isHt = false;
                    bool isVht = false;
                    bool isHe = false;
                    bool isEht = false;
                    bool isMlo = false;

                    struct RnrMldEntry {
                        uint8_t mldId;
                        uint8_t linkId;
                        bool    disabled;
                    };
                    RnrMldEntry rnrMldEntries[8];
                    uint8_t rnrMldCount = 0;

                    bool hasBasicMle = false;
                    uint8_t ownLinkId = 0xFF;
                    uint8_t ownApMldId = 0;
                    uint8_t maxSimulLinks = 0;
                    bool hasPartnerProfile = false;

                    while (pos + 1 < len) {
                        uint8_t id = payload[pos];
                        uint8_t elen = payload[pos + 1];
                        if (pos + 2 + elen > len) break;

                        if (id == 0 && elen > 0 && ssidBuf[0] == '\0') { // SSID
                            parseSsidIe(&payload[pos + 2], elen, ssidBuf);
                        } else if (id == 7 && elen >= 6) { // Country IE (ISO code + max TX power)
                            char c0 = static_cast<char>(payload[pos + 2]);
                            char c1 = static_cast<char>(payload[pos + 3]);
                            if (c0 >= 'A' && c0 <= 'Z' && c1 >= 'A' && c1 <= 'Z') {
                                country[0] = c0;
                                country[1] = c1;
                                country[2] = '\0';
                            }
                            uint16_t tPos = pos + 5;
                            uint16_t tEnd = pos + 2 + elen;
                            while (tPos + 3 <= tEnd) {
                                uint8_t firstCh = payload[tPos];
                                uint8_t numCh = payload[tPos + 1];
                                int8_t txp = static_cast<int8_t>(payload[tPos + 2]);
                                if (firstCh >= 1 && firstCh <= 14 && numCh >= 1 && txp > 0 && txp <= 40) {
                                    if (maxTxPower == 0 || (realCh >= firstCh && realCh < firstCh + numCh)) {
                                        maxTxPower = txp;
                                    }
                                }
                                tPos += 3;
                            }
                        } else if (id == 11 && elen >= 2) { // QBSS Load: Station Count + Channel Utilization
                            staCount = payload[pos + 2] | (static_cast<uint16_t>(payload[pos + 3]) << 8);
                            hasBssLoad = true;
                            if (elen >= 3) {
                                channelUtil = static_cast<uint8_t>((static_cast<uint16_t>(payload[pos + 4]) * 100U + 127U) / 255U);
                            }
                        } else if (id == 3 && elen >= 1) { // DS Parameter Set: primary channel (1..14)
                            uint8_t c = payload[pos + 2];
                            if (c >= 1 && c <= 14) {
                                realCh = c;
                            }
                        } else if (id == 45 || id == 61) { // HT Capabilities (45) / HT Operation (61) -> Wi-Fi 4
                            isHt = true;
                            if (id == 61 && elen >= 1) {
                                if (realCh == ch) {
                                    uint8_t c = payload[pos + 2];
                                    if (c >= 1 && c <= 14) {
                                        realCh = c;
                                    }
                                }
                                if (elen >= 2) {
                                    uint8_t htInfo1 = payload[pos + 3];
                                    uint8_t secOff = htInfo1 & 0x03;
                                    if (((htInfo1 & 0x04) != 0) && (secOff == 1 || secOff == 3)) {
                                        caps |= WIFI_AP_CAP_40MHZ;
                                    }
                                }
                            }
                        } else if (id == 54 && elen >= 3) { // Mobility Domain -> 802.11r
                            caps |= WIFI_AP_CAP_11R;
                        } else if (id == 70 && elen >= 5) { // RRM Enabled Capabilities -> 802.11k
                            caps |= WIFI_AP_CAP_11K;
                        } else if (id == 113 && elen == 7) { // IEEE 802.11s Mesh Configuration
                            mesh |= WIFI_AP_MESH_11S;
                        } else if (id == 114) { // IEEE 802.11s Mesh ID
                            mesh |= WIFI_AP_MESH_11S;
                            if (elen > 0 && ssidBuf[0] == '\0') {
                                parseSsidIe(&payload[pos + 2], elen, ssidBuf);
                            }
                        } else if (id == 127 && elen >= 3) { // Extended Capabilities -> 802.11v (bit 19)
                            if ((payload[pos + 4] & 0x08) != 0) {
                                caps |= WIFI_AP_CAP_11V;
                            }
                        } else if (id == 191 || id == 192) { // VHT Capabilities (191) / VHT Operation (192) -> Wi-Fi 5
                            isVht = true;
                        } else if (id == 255 && elen >= 1) { // Extension Element
                            uint8_t extId = payload[pos + 2];
                            if (extId == 35 || extId == 36) { // HE Capabilities (35) / HE Operation (36) -> Wi-Fi 6
                                isHe = true;
                            } else if (extId == 108 || extId == 106) { // EHT Capabilities (108) / EHT Operation (106) -> Wi-Fi 7
                                isEht = true;
                            } else if (extId == 107 && elen >= 4) { // Multi-Link Element (107) -> IEEE 802.11be §9.4.2.322
                                isEht = true;
                                uint16_t elemEnd = pos + 2 + elen;
                                uint16_t mlControl = payload[pos + 3] | (static_cast<uint16_t>(payload[pos + 4]) << 8);
                                uint8_t mlType = mlControl & 0x07;
                                if (mlType == 0) { // Basic Multi-Link element
                                    uint16_t ciStart = pos + 5;
                                    uint8_t commonInfoLen = payload[ciStart];
                                    // Common Info len includes itself (1B) + MLD MAC (6B) => minimum 7 bytes
                                    if (commonInfoLen >= 7 && (ciStart + commonInfoLen) <= elemEnd) {
                                        hasBasicMle = true;
                                        uint8_t ciOff = 7; // past len (1) + mld_addr (6)

                                        if ((mlControl & 0x0010) != 0 && ciOff + 1 <= commonInfoLen) { // Link ID Info Present
                                            ownLinkId = payload[ciStart + ciOff] & 0x0F;
                                            ciOff += 1;
                                        }
                                        if ((mlControl & 0x0020) != 0 && ciOff + 1 <= commonInfoLen) { // BSS Param Change Count
                                            ciOff += 1;
                                        }
                                        if ((mlControl & 0x0040) != 0 && ciOff + 2 <= commonInfoLen) { // Medium Sync Delay Info
                                            ciOff += 2;
                                        }
                                        if ((mlControl & 0x0080) != 0 && ciOff + 2 <= commonInfoLen) { // EML Capabilities
                                            ciOff += 2;
                                        }
                                        if ((mlControl & 0x0100) != 0 && ciOff + 2 <= commonInfoLen) { // MLD Capabilities & Operations
                                            uint16_t mldCap = payload[ciStart + ciOff] | (static_cast<uint16_t>(payload[ciStart + ciOff + 1]) << 8);
                                            maxSimulLinks = mldCap & 0x000F; // value + 1 = max simultaneous links (0 = single-link)
                                            ciOff += 2;
                                        }
                                        if ((mlControl & 0x0200) != 0 && ciOff + 1 <= commonInfoLen) { // AP MLD ID
                                            ownApMldId = payload[ciStart + ciOff];
                                        }

                                        // Check Link Info field for Per-STA Profile subelements (subId == 0)
                                        uint16_t subPos = ciStart + commonInfoLen;
                                        while (subPos + 2 <= elemEnd) {
                                            uint8_t subId = payload[subPos];
                                            uint8_t subLen = payload[subPos + 1];
                                            if (subPos + 2 + subLen > elemEnd) break;
                                            if (subId == 0) {
                                                hasPartnerProfile = true;
                                                break;
                                            }
                                            subPos += 2 + subLen;
                                        }
                                    }
                                }
                            }
                        } else if (id == 201 && elen >= 4) { // Reduced Neighbor Report (RNR) -> IEEE 802.11be
                            uint16_t rnrPos = pos + 2;
                            uint16_t rnrEnd = pos + 2 + elen;
                            while (rnrPos + 4 <= rnrEnd) {
                                uint8_t tbttHdr = payload[rnrPos];
                                uint8_t tbttLen = payload[rnrPos + 1];
                                uint8_t tbttType = tbttHdr & 0x03;
                                uint8_t count = ((tbttHdr & 0xF0) >> 4) + 1;
                                uint16_t infoLen = 4 + (static_cast<uint16_t>(count) * tbttLen);
                                if (rnrPos + infoLen > rnrEnd) break;
                                // MLD Parameters (3 bytes) are appended at offset 13 when tbttType == 0 && tbttLen >= 16
                                if (tbttType == 0 && tbttLen >= 16) {
                                    uint16_t entryPos = rnrPos + 4;
                                    for (uint8_t k = 0; k < count && rnrMldCount < 8; k++) {
                                        const uint8_t *mldParams = &payload[entryPos + 13];
                                        rnrMldEntries[rnrMldCount].mldId = mldParams[0];
                                        rnrMldEntries[rnrMldCount].linkId = mldParams[1] & 0x0F;
                                        rnrMldEntries[rnrMldCount].disabled = (mldParams[2] & 0x20) != 0;
                                        rnrMldCount++;
                                        entryPos += tbttLen;
                                    }
                                }
                                rnrPos += infoLen;
                            }
                        } else if (id == 48 && elen >= 8) { // RSN IE (WPA2 / WPA3 / PMF / 11r)
                            auth = AUTH_WPA2;
                            uint32_t elemEnd = static_cast<uint32_t>(pos) + 2U + elen;
                            uint16_t pairwiseCount = payload[pos + 8] | (static_cast<uint16_t>(payload[pos + 9]) << 8);
                            uint32_t akmOffset = static_cast<uint32_t>(pos) + 10U + (static_cast<uint32_t>(pairwiseCount) * 4U);
                            if (akmOffset + 2U <= elemEnd) {
                                uint16_t akmCount = payload[akmOffset] | (static_cast<uint16_t>(payload[akmOffset + 1]) << 8);
                                uint32_t suitesStart = akmOffset + 2U;
                                for (uint16_t k = 0; k < akmCount && (suitesStart + (static_cast<uint32_t>(k) * 4U) + 4U) <= elemEnd; k++) {
                                    uint32_t sOff = suitesStart + (static_cast<uint32_t>(k) * 4U);
                                    if (payload[sOff] == 0x00 &&
                                        payload[sOff + 1] == 0x0F &&
                                        payload[sOff + 2] == 0xAC) {
                                        uint8_t suiteType = payload[sOff + 3];
                                        // 8=SAE, 9=FT-SAE, 12=Suite-B-192, 24=SAE-EXT-KEY
                                        if (suiteType == 8 || suiteType == 9 || suiteType == 12 || suiteType == 24) {
                                            auth = AUTH_WPA3;
                                        }
                                        // 3=FT-802.1X, 4=FT-PSK, 9=FT-SAE
                                        if (suiteType == 3 || suiteType == 4 || suiteType == 9) {
                                            caps |= WIFI_AP_CAP_11R;
                                        }
                                    }
                                }
                                uint32_t rsnCapOff = suitesStart + (static_cast<uint32_t>(akmCount) * 4U);
                                if (rsnCapOff + 2U <= elemEnd) {
                                    uint16_t rsnCap = payload[rsnCapOff] | (static_cast<uint16_t>(payload[rsnCapOff + 1]) << 8);
                                    if (rsnCap & 0x0080) caps |= WIFI_AP_CAP_PMF_CAP; // MFPC (bit 7)
                                    if (rsnCap & 0x0040) caps |= WIFI_AP_CAP_PMF_REQ; // MFPR (bit 6)
                                }
                            }
                        } else if (id == 221 && elen >= 4) { // Vendor Specific (WPA1, WPS, WFA EasyMesh/Multi-AP)
                            if (payload[pos + 2] == 0x00 &&
                                payload[pos + 3] == 0x50 &&
                                payload[pos + 4] == 0xF2) {
                                uint8_t vType = payload[pos + 5];
                                if (vType == 0x01 && auth < AUTH_WPA2) {
                                    auth = AUTH_WPA;
                                } else if (vType == 0x04) {
                                    caps |= WIFI_AP_CAP_WPS;
                                    if (elen > 4) {
                                        parseWpsIe(&payload[pos + 6], static_cast<uint16_t>(elen - 4), caps, wpsModel, sizeof(wpsModel));
                                    }
                                }
                            } else if (payload[pos + 2] == 0x50 &&
                                       payload[pos + 3] == 0x6F &&
                                       payload[pos + 4] == 0x9A &&
                                       payload[pos + 5] == 0x1B) { // Wi-Fi Alliance Multi-AP (EasyMesh)
                                mesh |= WIFI_AP_MESH_EASYMESH;
                                uint16_t subPos = pos + 6;
                                uint16_t elemEnd = pos + 2 + elen;
                                while (subPos + 2 <= elemEnd) {
                                    uint8_t subId = payload[subPos];
                                    uint8_t subLen = payload[subPos + 1];
                                    subPos += 2;
                                    if (subPos + subLen > elemEnd) break;
                                    if (subId == 0x06 && subLen >= 1) { // Multi-AP Extension subelement
                                        uint8_t ext = payload[subPos];
                                        if (ext & 0x20) mesh |= WIFI_AP_MESH_FRONTHAUL;
                                        if (ext & 0x40) mesh |= WIFI_AP_MESH_BACKHAUL;
                                        if (ext & 0x80) mesh |= WIFI_AP_MESH_BSTA;
                                    }
                                    subPos += subLen;
                                }
                            }
                        }
                        pos += 2 + elen;
                    }

                    bool hasRnrPartnerLink = false;
                    if (hasBasicMle && ownLinkId < 15) {
                        for (uint8_t r = 0; r < rnrMldCount; r++) {
                            if (!rnrMldEntries[r].disabled &&
                                rnrMldEntries[r].mldId == ownApMldId &&
                                rnrMldEntries[r].linkId != ownLinkId) {
                                hasRnrPartnerLink = true;
                                break;
                            }
                        }
                    }
                    isMlo = hasBasicMle && (ownLinkId < 15) &&
                            (maxSimulLinks >= 1 || hasPartnerProfile || hasRnrPartnerLink);

                    uint8_t wifiStd = 0;
                    if (isEht || isMlo) {
                        wifiStd = 7;
                    } else if (isHe) {
                        wifiStd = 6;
                    } else if (isVht) {
                        wifiStd = 5;
                    } else if (isHt) {
                        wifiStd = 4;
                    } else {
                        wifiStd = 1;
                    }

                    if ((ssidBuf[0] != '\0' || subtype == 8) && isValidUnicastMac(hdr->addr3)) {
                        portENTER_CRITICAL(&s_wifi_mux);
                        int8_t apIdx = findApIndexByBssid(hdr->addr3);
                        if (apIdx >= 0) {
                            WifiApEntry &entry = s_ap_records[apIdx];
                            // Avoid adjacent-channel bleed-through corrupting on-channel RSSI
                            if (ch == realCh || entry.record.rssi <= -128) {
                                entry.record.rssi = rssi;
                            }
                            entry.record.channel = realCh;
                            if (subtype == 8 || auth > entry.record.authMode) {
                                entry.record.authMode = auth;
                            }
                            if (hasBssLoad) entry.record.staCount = staCount;
                            if (channelUtil != 0xFF) entry.record.channelUtil = channelUtil;
                            entry.record.caps = (subtype == 8)
                                ? static_cast<uint8_t>(caps | (entry.record.caps & (WIFI_AP_CAP_WPS | WIFI_AP_CAP_WPS_LOCK)))
                                : static_cast<uint8_t>(entry.record.caps | caps);
                            entry.record.mesh = (subtype == 8) ? mesh : static_cast<uint8_t>(entry.record.mesh | mesh);
                            if (country[0] != '\0') {
                                entry.record.country[0] = country[0];
                                entry.record.country[1] = country[1];
                                entry.record.country[2] = '\0';
                            }
                            if (maxTxPower > 0) entry.record.maxTxPower = maxTxPower;
                            if (wpsModel[0] != '\0') {
                                strncpy(entry.record.wpsModel, wpsModel, sizeof(entry.record.wpsModel) - 1);
                                entry.record.wpsModel[sizeof(entry.record.wpsModel) - 1] = '\0';
                            }
                            if (wifiStd > entry.record.wifiStd) {
                                entry.record.wifiStd = wifiStd;
                            }
                            if (subtype == 8 || isMlo) {
                                entry.record.mlo = isMlo;
                            }
                            entry.lastSeenMs = nowMs;
                            if (entry.record.ssid[0] == '\0' && ssidBuf[0] != '\0') {
                                strncpy(entry.record.ssid, ssidBuf, sizeof(entry.record.ssid) - 1);
                                entry.record.ssid[sizeof(entry.record.ssid) - 1] = '\0';
                            }
                        } else {
                            uint8_t idx = 0;
                            if (s_ap_count < MAX_DISCOVERED_APS) {
                                idx = s_ap_count++;
                            } else {
                                uint32_t oldestTime = s_ap_records[0].lastSeenMs;
                                for (uint8_t i = 1; i < MAX_DISCOVERED_APS; i++) {
                                    if (s_ap_records[i].lastSeenMs < oldestTime) {
                                        oldestTime = s_ap_records[i].lastSeenMs;
                                        idx = i;
                                    }
                                }
                            }
                            memset(&s_ap_records[idx].record, 0, sizeof(WifiApRecord));
                            strncpy(s_ap_records[idx].record.ssid, ssidBuf, sizeof(s_ap_records[0].record.ssid) - 1);
                            s_ap_records[idx].record.ssid[sizeof(s_ap_records[0].record.ssid) - 1] = '\0';
                            memcpy(s_ap_records[idx].record.bssid, hdr->addr3, 6);
                            s_ap_records[idx].record.channel = realCh;
                            s_ap_records[idx].record.rssi = rssi;
                            s_ap_records[idx].record.authMode = auth;
                            s_ap_records[idx].record.staCount = staCount;
                            s_ap_records[idx].record.wifiStd = wifiStd;
                            s_ap_records[idx].record.mlo = isMlo;
                            s_ap_records[idx].record.channelUtil = channelUtil;
                            s_ap_records[idx].record.caps = caps;
                            s_ap_records[idx].record.mesh = mesh;
                            if (country[0] != '\0') {
                                s_ap_records[idx].record.country[0] = country[0];
                                s_ap_records[idx].record.country[1] = country[1];
                                s_ap_records[idx].record.country[2] = '\0';
                            }
                            s_ap_records[idx].record.maxTxPower = maxTxPower;
                            if (wpsModel[0] != '\0') {
                                strncpy(s_ap_records[idx].record.wpsModel, wpsModel, sizeof(s_ap_records[0].record.wpsModel) - 1);
                                s_ap_records[idx].record.wpsModel[sizeof(s_ap_records[0].record.wpsModel) - 1] = '\0';
                            }
                            s_ap_records[idx].lastSeenMs = nowMs;
                        }
                        portEXIT_CRITICAL(&s_wifi_mux);
                    }
                }
            }
        }

        // 2. Associated Client Detection from Data Frames (Infrastructure BSS only)
        else if (type == WIFI_PKT_DATA && pkt->rx_ctrl.sig_len >= sizeof(wifi_mgmt_hdr_t) + 4) {
            const uint8_t *payload = pkt->payload;
            const wifi_mgmt_hdr_t *hdr = reinterpret_cast<const wifi_mgmt_hdr_t *>(payload);

            uint16_t fc = hdr->frame_ctrl;
            uint8_t subtype = (fc >> 4) & 0x0F;
            uint8_t toDs = (fc >> 8) & 0x01;
            uint8_t fromDs = (fc >> 9) & 0x01;

            const uint8_t *clientMac = nullptr;
            const uint8_t *apMac = nullptr;
            bool isClientTx = false;

            if (toDs == 1 && fromDs == 0) {
                // Client -> AP (Infrastructure uplink)
                clientMac = hdr->addr2;
                apMac = hdr->addr1;
                isClientTx = true;
            } else if (toDs == 0 && fromDs == 1) {
                // AP -> Client (Infrastructure downlink)
                clientMac = hdr->addr1;
                apMac = hdr->addr2;
                isClientTx = false;
            }
            // Drop ToDS=0,FromDS=0 (IBSS/unassociated) and ToDS=1,FromDS=1 (WDS AP-to-AP)

            if (isValidUnicastMac(clientMac) && isValidUnicastMac(apMac)) {
                uint16_t l2Bytes = pkt->rx_ctrl.sig_len - 4;
                bool isRetry = ((fc >> 11) & 0x01) != 0;
                bool pwrSave = ((fc >> 12) & 0x01) != 0;
                bool isNullData = (subtype & 0x04) != 0; // Subtype 4 (Null) or 12 (QoS Null)
                bool isEncrypted = (!isNullData) && (((fc >> 14) & 0x01) != 0);
                bool isQos = (subtype & 0x08) != 0;      // Subtype 8 (QoS Data) or 12 (QoS Null)
                uint8_t eapolBit = (!isNullData && !isEncrypted) ? parseEapolKeyMsg(payload, l2Bytes, fc, isQos) : 0;

                portENTER_CRITICAL(&s_wifi_mux);
                upsertAssociatedClient(
                    clientMac, apMac, ch, rssi,
                    isClientTx, pkt->rx_ctrl, l2Bytes, isRetry,
                    isClientTx, pwrSave, isEncrypted, isQos, 0, 0, eapolBit, nowMs);
                portEXIT_CRITICAL(&s_wifi_mux);
            }
        }
    }
}

void WifiSniffer::init() {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT |
                       WIFI_PROMIS_FILTER_MASK_DATA |
                       WIFI_PROMIS_FILTER_MASK_DATA_MPDU |
                       WIFI_PROMIS_FILTER_MASK_DATA_AMPDU
    };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(promiscuousCallback);
}

void WifiSniffer::start() {
    esp_wifi_set_promiscuous(true);
}

void WifiSniffer::stop() {
    esp_wifi_set_promiscuous(false);
}

void WifiSniffer::setChannel(uint8_t channel) {
    if (channel >= 1 && channel <= GHOSTWAVE_WIFI_CHANNELS) {
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        s_current_channel = channel;
    }
}

void WifiSniffer::resetChannelStats(uint8_t channel) {
    if (channel >= 1 && channel <= GHOSTWAVE_WIFI_CHANNELS) {
        portENTER_CRITICAL(&s_wifi_mux);
        s_wifi_pkts_temp[channel - 1] = 0;
        s_wifi_rssi_temp[channel - 1] = -128;
        if (s_wifi_noise_temp[channel - 1] == 0) {
            s_wifi_noise_temp[channel - 1] = -95;
        }
        portEXIT_CRITICAL(&s_wifi_mux);
    }
}

void WifiSniffer::getChannelStats(uint8_t channel, uint16_t &outPkts, int8_t &outMaxRssi, int8_t &outNoiseFloor) {
    if (channel >= 1 && channel <= GHOSTWAVE_WIFI_CHANNELS) {
        portENTER_CRITICAL(&s_wifi_mux);
        outPkts = s_wifi_pkts_temp[channel - 1];
        outMaxRssi = s_wifi_rssi_temp[channel - 1];
        outNoiseFloor = s_wifi_noise_temp[channel - 1];
        portEXIT_CRITICAL(&s_wifi_mux);
    }
}

void WifiSniffer::sweepChannels(uint16_t *outPkts, int8_t *outMaxRssi, int8_t *outNoiseFloor,
                                WifiApRecord *outAps, uint8_t &outApCount,
                                WifiClientRecord *outClients, uint8_t &outClientCount,
                                WifiProbeRecord *outProbes, uint8_t &outProbeCount,
                                uint16_t &outDeauthCount, uint8_t &outDeauthChannel,
                                uint32_t dwellMs, uint8_t lockChannel) {
    portENTER_CRITICAL(&s_wifi_mux);
    for (uint8_t i = 0; i < GHOSTWAVE_WIFI_CHANNELS; i++) {
        s_wifi_deauth_temp[i] = 0;
    }
    portEXIT_CRITICAL(&s_wifi_mux);

    start();

    if (lockChannel >= 1 && lockChannel <= GHOSTWAVE_WIFI_CHANNELS) {
        if (outPkts != nullptr && outMaxRssi != nullptr) {
            for (uint8_t i = 0; i < GHOSTWAVE_WIFI_CHANNELS; i++) {
                outPkts[i] = 0;
                outMaxRssi[i] = -128;
                if (outNoiseFloor != nullptr) outNoiseFloor[i] = -95;
            }
        }
        setChannel(lockChannel);
        resetChannelStats(lockChannel);
        vTaskDelay(pdMS_TO_TICKS(dwellMs * GHOSTWAVE_WIFI_CHANNELS));
        if (outPkts != nullptr && outMaxRssi != nullptr) {
            int8_t dummyNoise = -95;
            getChannelStats(lockChannel, outPkts[lockChannel - 1], outMaxRssi[lockChannel - 1],
                            outNoiseFloor != nullptr ? outNoiseFloor[lockChannel - 1] : dummyNoise);
        }
    } else {
        for (uint8_t ch = 1; ch <= GHOSTWAVE_WIFI_CHANNELS; ch++) {
            setChannel(ch);
            resetChannelStats(ch);

            vTaskDelay(pdMS_TO_TICKS(dwellMs));

            if (outPkts != nullptr && outMaxRssi != nullptr) {
                int8_t dummyNoise = -95;
                getChannelStats(ch, outPkts[ch - 1], outMaxRssi[ch - 1],
                                outNoiseFloor != nullptr ? outNoiseFloor[ch - 1] : dummyNoise);
            }
        }
    }

    stop();

    uint32_t nowMs = getNowMs();

    portENTER_CRITICAL(&s_wifi_mux);

    // Prune stale APs (inactive for > 60 seconds)
    uint8_t apWriteIdx = 0;
    for (uint8_t i = 0; i < s_ap_count; i++) {
        if ((nowMs - s_ap_records[i].lastSeenMs) < 60000) {
            if (apWriteIdx != i) {
                s_ap_records[apWriteIdx] = s_ap_records[i];
            }
            apWriteIdx++;
        }
    }
    s_ap_count = apWriteIdx;

    if (outAps != nullptr) {
        outApCount = s_ap_count;
        for (uint8_t i = 0; i < s_ap_count; i++) {
            outAps[i] = s_ap_records[i].record;
        }
    }

    // Prune stale Clients (inactive for > 45 seconds) and scrub any AP BSSID mistakenly inserted
    uint8_t cliWriteIdx = 0;
    for (uint8_t i = 0; i < s_client_count; i++) {
        if ((nowMs - s_client_records[i].lastSeenMs) < 45000 && !isKnownAp(s_client_records[i].record.mac)) {
            if (cliWriteIdx != i) {
                s_client_records[cliWriteIdx] = s_client_records[i];
            }
            cliWriteIdx++;
        }
    }
    s_client_count = cliWriteIdx;

    // Post-sweep enrichment: align client channel with its exact AP channel
    for (uint8_t i = 0; i < s_client_count; i++) {
        int8_t bestApIdx = findApIndexByBssid(s_client_records[i].record.bssid);
        if (bestApIdx >= 0 && s_ap_records[bestApIdx].record.channel >= 1 && s_ap_records[bestApIdx].record.channel <= 14) {
            s_client_records[i].record.channel = s_ap_records[bestApIdx].record.channel;
        }
    }

    if (outClients != nullptr) {
        outClientCount = s_client_count;
        for (uint8_t i = 0; i < s_client_count; i++) {
            outClients[i] = s_client_records[i].record;
        }
    }

    // Prune stale Probe Requests (inactive for > 60 seconds)
    uint8_t probeWriteIdx = 0;
    for (uint8_t i = 0; i < s_probe_count; i++) {
        if ((nowMs - s_probe_records[i].lastSeenMs) < 60000 && !isKnownAp(s_probe_records[i].record.mac)) {
            if (probeWriteIdx != i) {
                s_probe_records[probeWriteIdx] = s_probe_records[i];
            }
            probeWriteIdx++;
        }
    }
    s_probe_count = probeWriteIdx;

    if (outProbes != nullptr) {
        outProbeCount = s_probe_count;
        for (uint8_t i = 0; i < s_probe_count; i++) {
            outProbes[i] = s_probe_records[i].record;
        }
    }

    uint16_t totalDeauth = 0;
    uint8_t maxDeauthCh = 0;
    uint16_t maxDeauthPkts = 0;
    for (uint8_t i = 0; i < GHOSTWAVE_WIFI_CHANNELS; i++) {
        totalDeauth += s_wifi_deauth_temp[i];
        if (s_wifi_deauth_temp[i] > maxDeauthPkts) {
            maxDeauthPkts = s_wifi_deauth_temp[i];
            maxDeauthCh = i + 1;
        }
    }
    outDeauthCount = totalDeauth;
    outDeauthChannel = (totalDeauth > 0) ? maxDeauthCh : 0;

    portEXIT_CRITICAL(&s_wifi_mux);
}
