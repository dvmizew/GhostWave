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

static WifiApEntry     s_ap_records[MAX_DISCOVERED_APS];
static uint8_t         s_ap_count = 0;

static WifiClientEntry s_client_records[MAX_DISCOVERED_CLIENTS];
static uint8_t         s_client_count = 0;

static inline uint32_t getNowMs() {
    return static_cast<uint32_t>(esp_timer_get_time() / 1000);
}

static inline bool isKnownAp(const uint8_t *mac) {
    for (uint8_t i = 0; i < s_ap_count; i++) {
        if (memcmp(s_ap_records[i].record.bssid, mac, 6) == 0) {
            return true;
        }
    }
    return false;
}

void IRAM_ATTR WifiSniffer::promiscuousCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type == WIFI_PKT_MGMT || type == WIFI_PKT_DATA) {
        const wifi_promiscuous_pkt_t *pkt = reinterpret_cast<const wifi_promiscuous_pkt_t *>(buf);
        int8_t rssi = pkt->rx_ctrl.rssi;
        int8_t noise = pkt->rx_ctrl.noise_floor;
        uint8_t ch = s_current_channel;

        if (ch >= 1 && ch <= GHOSTWAVE_WIFI_CHANNELS) {
            portENTER_CRITICAL_ISR(&s_wifi_mux);
            s_wifi_pkts_temp[ch - 1] = s_wifi_pkts_temp[ch - 1] + 1;
            if (rssi > s_wifi_rssi_temp[ch - 1]) {
                s_wifi_rssi_temp[ch - 1] = rssi;
            }
            if (noise != 0) {
                s_wifi_noise_temp[ch - 1] = noise;
            }
            portEXIT_CRITICAL_ISR(&s_wifi_mux);
        }

        uint32_t nowMs = getNowMs();

        // 1. Management Frames
        if (type == WIFI_PKT_MGMT && pkt->rx_ctrl.sig_len >= sizeof(wifi_mgmt_hdr_t)) {
            const uint8_t *payload = pkt->payload;
            const wifi_mgmt_hdr_t *hdr = reinterpret_cast<const wifi_mgmt_hdr_t *>(payload);
            uint8_t subtype = (hdr->frame_ctrl >> 4) & 0x0F;
            uint16_t len = (pkt->rx_ctrl.sig_len > 4) ? (pkt->rx_ctrl.sig_len - 4) : pkt->rx_ctrl.sig_len;

            // 1a. Deauth & Disassociation frames (Subtype 12 = Deauth, 10 = Disassoc)
            if (subtype == 12 || subtype == 10) {
                if (ch >= 1 && ch <= GHOSTWAVE_WIFI_CHANNELS) {
                    portENTER_CRITICAL_ISR(&s_wifi_mux);
                    s_wifi_deauth_temp[ch - 1] = s_wifi_deauth_temp[ch - 1] + 1;
                    portEXIT_CRITICAL_ISR(&s_wifi_mux);
                }
            }
            // 1b. Client Management Frames: Probe Request (4), Assoc Request (0), Reassoc Request (2)
            else if (subtype == 4 || subtype == 0 || subtype == 2) {
                if ((hdr->addr2[0] & 0x01) == 0 &&
                    (hdr->addr2[0] | hdr->addr2[1] | hdr->addr2[2] | hdr->addr2[3] | hdr->addr2[4] | hdr->addr2[5]) != 0) {
                    char probedSsid[33] = {0};
                    uint16_t pos = (subtype == 4) ? 24 : 28; // Probe Req IEs begin at 24, Assoc Req IEs at 28
                    const uint8_t *assocAp = (subtype == 0 || subtype == 2) ? hdr->addr1 : nullptr;

                    while (pos + 1 < len) {
                        uint8_t id = payload[pos];
                        uint8_t elen = payload[pos + 1];
                        if (pos + 2 + elen > len) break;

                        if (id == 0) { // SSID
                            uint8_t copyLen = elen;
                            if (copyLen > 32) copyLen = 32;
                            for (uint8_t i = 0; i < copyLen; i++) {
                                char c = static_cast<char>(payload[pos + 2 + i]);
                                probedSsid[i] = (c >= 32 && c <= 126) ? c : '?';
                            }
                            probedSsid[copyLen] = '\0';
                            break;
                        }
                        pos += 2 + elen;
                    }

                    portENTER_CRITICAL_ISR(&s_wifi_mux);
                    if (!isKnownAp(hdr->addr2)) {
                        bool found = false;
                        for (uint8_t i = 0; i < s_client_count; i++) {
                            if (memcmp(s_client_records[i].record.mac, hdr->addr2, 6) == 0) {
                                found = true;
                                s_client_records[i].record.rssi = rssi;
                                s_client_records[i].record.channel = ch;
                                s_client_records[i].lastSeenMs = nowMs;
                                if (assocAp != nullptr) {
                                    memcpy(s_client_records[i].record.bssid, assocAp, 6);
                                }
                                if (probedSsid[0] != '\0' && s_client_records[i].record.probedSsid[0] == '\0') {
                                    strncpy(s_client_records[i].record.probedSsid, probedSsid, sizeof(s_client_records[0].record.probedSsid) - 1);
                                    s_client_records[i].record.probedSsid[sizeof(s_client_records[0].record.probedSsid) - 1] = '\0';
                                }
                                break;
                            }
                        }
                        if (!found && s_client_count < MAX_DISCOVERED_CLIENTS) {
                            memcpy(s_client_records[s_client_count].record.mac, hdr->addr2, 6);
                            if (assocAp != nullptr) {
                                memcpy(s_client_records[s_client_count].record.bssid, assocAp, 6);
                            } else {
                                memset(s_client_records[s_client_count].record.bssid, 0, 6);
                            }
                            strncpy(s_client_records[s_client_count].record.probedSsid, probedSsid, sizeof(s_client_records[0].record.probedSsid) - 1);
                            s_client_records[s_client_count].record.probedSsid[sizeof(s_client_records[0].record.probedSsid) - 1] = '\0';
                            s_client_records[s_client_count].record.channel = ch;
                            s_client_records[s_client_count].record.rssi = rssi;
                            s_client_records[s_client_count].lastSeenMs = nowMs;
                            s_client_count++;
                        } else if (!found && s_client_count >= MAX_DISCOVERED_CLIENTS) {
                            // Replace oldest entry
                            uint8_t oldestIdx = 0;
                            uint32_t oldestTime = s_client_records[0].lastSeenMs;
                            for (uint8_t i = 1; i < MAX_DISCOVERED_CLIENTS; i++) {
                                if (s_client_records[i].lastSeenMs < oldestTime) {
                                    oldestTime = s_client_records[i].lastSeenMs;
                                    oldestIdx = i;
                                }
                            }
                            memcpy(s_client_records[oldestIdx].record.mac, hdr->addr2, 6);
                            if (assocAp != nullptr) {
                                memcpy(s_client_records[oldestIdx].record.bssid, assocAp, 6);
                            } else {
                                memset(s_client_records[oldestIdx].record.bssid, 0, 6);
                            }
                            strncpy(s_client_records[oldestIdx].record.probedSsid, probedSsid, sizeof(s_client_records[0].record.probedSsid) - 1);
                            s_client_records[oldestIdx].record.probedSsid[sizeof(s_client_records[0].record.probedSsid) - 1] = '\0';
                            s_client_records[oldestIdx].record.channel = ch;
                            s_client_records[oldestIdx].record.rssi = rssi;
                            s_client_records[oldestIdx].lastSeenMs = nowMs;
                        }
                    }
                    portEXIT_CRITICAL_ISR(&s_wifi_mux);
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

                    while (pos + 1 < len) {
                        uint8_t id = payload[pos];
                        uint8_t elen = payload[pos + 1];
                        if (pos + 2 + elen > len) break;

                        if (id == 0 && ssidBuf[0] == '\0') { // SSID
                            uint8_t copyLen = elen;
                            if (copyLen > 32) copyLen = 32;
                            for (uint8_t i = 0; i < copyLen; i++) {
                                char c = static_cast<char>(payload[pos + 2 + i]);
                                ssidBuf[i] = (c >= 32 && c <= 126) ? c : '?';
                            }
                            ssidBuf[copyLen] = '\0';
                        } else if (id == 3 && elen >= 1) { // DS Parameter Set: primary channel (1..14)
                            uint8_t c = payload[pos + 2];
                            if (c >= 1 && c <= 14) {
                                realCh = c;
                            }
                        } else if (id == 61 && elen >= 1 && realCh == ch) { // HT Operation: primary channel
                            uint8_t c = payload[pos + 2];
                            if (c >= 1 && c <= 14) {
                                realCh = c;
                            }
                        } else if (id == 48 && elen >= 8) { // RSN IE (WPA2 / WPA3)
                            auth = AUTH_WPA2;
                            uint16_t pairwiseCount = payload[pos + 8] | (static_cast<uint16_t>(payload[pos + 9]) << 8);
                            uint16_t akmOffset = pos + 10 + (pairwiseCount * 4);
                            if (akmOffset + 2 <= pos + 2 + elen) {
                                uint16_t akmCount = payload[akmOffset] | (static_cast<uint16_t>(payload[akmOffset + 1]) << 8);
                                uint16_t suitesStart = akmOffset + 2;
                                for (uint16_t k = 0; k < akmCount && (suitesStart + (k * 4) + 4) <= (pos + 2 + elen); k++) {
                                    if (payload[suitesStart + (k * 4)] == 0x00 &&
                                        payload[suitesStart + (k * 4) + 1] == 0x0F &&
                                        payload[suitesStart + (k * 4) + 2] == 0xAC) {
                                        uint8_t suiteType = payload[suitesStart + (k * 4) + 3];
                                        if (suiteType == 8 || suiteType == 24) {
                                            auth = AUTH_WPA3;
                                            break;
                                        }
                                    }
                                }
                            }
                        } else if (id == 221 && elen >= 4 && auth < AUTH_WPA2) { // Vendor Specific (WPA1)
                            if (payload[pos + 2] == 0x00 &&
                                payload[pos + 3] == 0x50 &&
                                payload[pos + 4] == 0xF2 &&
                                payload[pos + 5] == 0x01) {
                                auth = AUTH_WPA;
                            }
                        }
                        pos += 2 + elen;
                    }

                    if (ssidBuf[0] != '\0' || subtype == 8) {
                        portENTER_CRITICAL_ISR(&s_wifi_mux);
                        bool found = false;
                        for (uint8_t i = 0; i < s_ap_count; i++) {
                            if (memcmp(s_ap_records[i].record.bssid, hdr->addr3, 6) == 0) {
                                found = true;
                                s_ap_records[i].record.rssi = rssi;
                                s_ap_records[i].record.channel = realCh;
                                s_ap_records[i].record.authMode = auth;
                                s_ap_records[i].lastSeenMs = nowMs;
                                if (s_ap_records[i].record.ssid[0] == '\0' && ssidBuf[0] != '\0') {
                                    strncpy(s_ap_records[i].record.ssid, ssidBuf, sizeof(s_ap_records[0].record.ssid) - 1);
                                    s_ap_records[i].record.ssid[sizeof(s_ap_records[0].record.ssid) - 1] = '\0';
                                }
                                break;
                            }
                        }
                        if (!found && s_ap_count < MAX_DISCOVERED_APS) {
                            strncpy(s_ap_records[s_ap_count].record.ssid, ssidBuf, sizeof(s_ap_records[0].record.ssid) - 1);
                            s_ap_records[s_ap_count].record.ssid[sizeof(s_ap_records[0].record.ssid) - 1] = '\0';
                            memcpy(s_ap_records[s_ap_count].record.bssid, hdr->addr3, 6);
                            s_ap_records[s_ap_count].record.channel = realCh;
                            s_ap_records[s_ap_count].record.rssi = rssi;
                            s_ap_records[s_ap_count].record.authMode = auth;
                            s_ap_records[s_ap_count].lastSeenMs = nowMs;
                            s_ap_count++;
                        } else if (!found && s_ap_count >= MAX_DISCOVERED_APS) {
                            uint8_t oldestIdx = 0;
                            uint32_t oldestTime = s_ap_records[0].lastSeenMs;
                            for (uint8_t i = 1; i < MAX_DISCOVERED_APS; i++) {
                                if (s_ap_records[i].lastSeenMs < oldestTime) {
                                    oldestTime = s_ap_records[i].lastSeenMs;
                                    oldestIdx = i;
                                }
                            }
                            strncpy(s_ap_records[oldestIdx].record.ssid, ssidBuf, sizeof(s_ap_records[0].record.ssid) - 1);
                            s_ap_records[oldestIdx].record.ssid[sizeof(s_ap_records[0].record.ssid) - 1] = '\0';
                            memcpy(s_ap_records[oldestIdx].record.bssid, hdr->addr3, 6);
                            s_ap_records[oldestIdx].record.channel = realCh;
                            s_ap_records[oldestIdx].record.rssi = rssi;
                            s_ap_records[oldestIdx].record.authMode = auth;
                            s_ap_records[oldestIdx].lastSeenMs = nowMs;
                        }
                        portEXIT_CRITICAL_ISR(&s_wifi_mux);
                    }
                }
            }
        }

        // 2. Active Client Detection from Data Frames
        else if (type == WIFI_PKT_DATA && pkt->rx_ctrl.sig_len >= sizeof(wifi_mgmt_hdr_t)) {
            const uint8_t *payload = pkt->payload;
            const wifi_mgmt_hdr_t *hdr = reinterpret_cast<const wifi_mgmt_hdr_t *>(payload);

            uint8_t toDs = (hdr->frame_ctrl >> 8) & 0x01;
            uint8_t fromDs = (hdr->frame_ctrl >> 9) & 0x01;

            const uint8_t *clientMac = nullptr;
            const uint8_t *apMac = nullptr;

            if (toDs == 1 && fromDs == 0) {
                // Client transmitting to AP
                clientMac = hdr->addr2;
                apMac = hdr->addr1;
            } else if (toDs == 0 && fromDs == 1) {
                // AP transmitting to Client
                clientMac = hdr->addr1;
                apMac = hdr->addr2;
            } else if (toDs == 0 && fromDs == 0) {
                // Direct / keepalive / null: addr2 is source, addr3 is BSSID
                clientMac = hdr->addr2;
                if ((hdr->addr3[0] & 0x01) == 0 &&
                    (hdr->addr3[0] | hdr->addr3[1] | hdr->addr3[2] | hdr->addr3[3] | hdr->addr3[4] | hdr->addr3[5]) != 0) {
                    apMac = hdr->addr3;
                }
            }

            if (clientMac != nullptr &&
                (clientMac[0] & 0x01) == 0 &&
                (clientMac[0] | clientMac[1] | clientMac[2] | clientMac[3] | clientMac[4] | clientMac[5]) != 0) {

                portENTER_CRITICAL_ISR(&s_wifi_mux);
                if (!isKnownAp(clientMac)) {
                    bool found = false;
                    for (uint8_t i = 0; i < s_client_count; i++) {
                        if (memcmp(s_client_records[i].record.mac, clientMac, 6) == 0) {
                            found = true;
                            s_client_records[i].record.rssi = rssi;
                            s_client_records[i].record.channel = ch;
                            s_client_records[i].lastSeenMs = nowMs;
                            if (apMac != nullptr) {
                                memcpy(s_client_records[i].record.bssid, apMac, 6);
                            }
                            // If AP is known, enrich probedSsid if empty
                            if (s_client_records[i].record.probedSsid[0] == '\0' && apMac != nullptr) {
                                for (uint8_t a = 0; a < s_ap_count; a++) {
                                    if (memcmp(s_ap_records[a].record.bssid, apMac, 6) == 0 && s_ap_records[a].record.ssid[0] != '\0') {
                                        strncpy(s_client_records[i].record.probedSsid, s_ap_records[a].record.ssid, sizeof(s_client_records[0].record.probedSsid) - 1);
                                        s_client_records[i].record.probedSsid[sizeof(s_client_records[0].record.probedSsid) - 1] = '\0';
                                        break;
                                    }
                                }
                            }
                            break;
                        }
                    }

                    if (!found) {
                        char connSsid[33] = {0};
                        if (apMac != nullptr) {
                            for (uint8_t a = 0; a < s_ap_count; a++) {
                                if (memcmp(s_ap_records[a].record.bssid, apMac, 6) == 0 && s_ap_records[a].record.ssid[0] != '\0') {
                                    strncpy(connSsid, s_ap_records[a].record.ssid, sizeof(connSsid) - 1);
                                    connSsid[sizeof(connSsid) - 1] = '\0';
                                    break;
                                }
                            }
                        }

                        if (s_client_count < MAX_DISCOVERED_CLIENTS) {
                            memcpy(s_client_records[s_client_count].record.mac, clientMac, 6);
                            if (apMac != nullptr) {
                                memcpy(s_client_records[s_client_count].record.bssid, apMac, 6);
                            } else {
                                memset(s_client_records[s_client_count].record.bssid, 0, 6);
                            }
                            strncpy(s_client_records[s_client_count].record.probedSsid, connSsid, sizeof(s_client_records[0].record.probedSsid) - 1);
                            s_client_records[s_client_count].record.probedSsid[sizeof(s_client_records[0].record.probedSsid) - 1] = '\0';
                            s_client_records[s_client_count].record.channel = ch;
                            s_client_records[s_client_count].record.rssi = rssi;
                            s_client_records[s_client_count].lastSeenMs = nowMs;
                            s_client_count++;
                        } else {
                            // Replace oldest entry
                            uint8_t oldestIdx = 0;
                            uint32_t oldestTime = s_client_records[0].lastSeenMs;
                            for (uint8_t i = 1; i < MAX_DISCOVERED_CLIENTS; i++) {
                                if (s_client_records[i].lastSeenMs < oldestTime) {
                                    oldestTime = s_client_records[i].lastSeenMs;
                                    oldestIdx = i;
                                }
                            }
                            memcpy(s_client_records[oldestIdx].record.mac, clientMac, 6);
                            if (apMac != nullptr) {
                                memcpy(s_client_records[oldestIdx].record.bssid, apMac, 6);
                            } else {
                                memset(s_client_records[oldestIdx].record.bssid, 0, 6);
                            }
                            strncpy(s_client_records[oldestIdx].record.probedSsid, connSsid, sizeof(s_client_records[0].record.probedSsid) - 1);
                            s_client_records[oldestIdx].record.probedSsid[sizeof(s_client_records[0].record.probedSsid) - 1] = '\0';
                            s_client_records[oldestIdx].record.channel = ch;
                            s_client_records[oldestIdx].record.rssi = rssi;
                            s_client_records[oldestIdx].lastSeenMs = nowMs;
                        }
                    }
                }
                portEXIT_CRITICAL_ISR(&s_wifi_mux);
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
        s_current_channel = channel;
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
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
                                uint16_t &outDeauthCount, uint8_t &outDeauthChannel,
                                uint32_t dwellMs) {
    portENTER_CRITICAL(&s_wifi_mux);
    for (uint8_t i = 0; i < GHOSTWAVE_WIFI_CHANNELS; i++) {
        s_wifi_deauth_temp[i] = 0;
    }
    portEXIT_CRITICAL(&s_wifi_mux);

    start();

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

    // Prune stale Clients (inactive for > 45 seconds)
    uint8_t cliWriteIdx = 0;
    for (uint8_t i = 0; i < s_client_count; i++) {
        if ((nowMs - s_client_records[i].lastSeenMs) < 45000) {
            if (cliWriteIdx != i) {
                s_client_records[cliWriteIdx] = s_client_records[i];
            }
            cliWriteIdx++;
        }
    }
    s_client_count = cliWriteIdx;

    // Post-sweep enrichment: link clients with AP SSIDs and channels via BSSID / MLO match
    for (uint8_t i = 0; i < s_client_count; i++) {
        const uint8_t *b = s_client_records[i].record.bssid;
        bool hasBssid = (b[0] | b[1] | b[2] | b[3] | b[4] | b[5]) != 0;
        if (hasBssid) {
            for (uint8_t a = 0; a < s_ap_count; a++) {
                // Exact 6-byte BSSID match OR 5-byte MLO affiliated-link match
                bool match = (memcmp(s_ap_records[a].record.bssid, b, 6) == 0);
                if (!match && memcmp(s_ap_records[a].record.bssid + 1, b + 1, 5) == 0) {
                    match = true;
                }
                if (match) {
                    if (s_client_records[i].record.probedSsid[0] == '\0' && s_ap_records[a].record.ssid[0] != '\0') {
                        strncpy(s_client_records[i].record.probedSsid, s_ap_records[a].record.ssid, sizeof(s_client_records[0].record.probedSsid) - 1);
                        s_client_records[i].record.probedSsid[sizeof(s_client_records[0].record.probedSsid) - 1] = '\0';
                    }
                    if (s_ap_records[a].record.channel >= 1 && s_ap_records[a].record.channel <= 14) {
                        s_client_records[i].record.channel = s_ap_records[a].record.channel;
                    }
                    break;
                }
            }
        }
    }

    if (outClients != nullptr) {
        outClientCount = s_client_count;
        for (uint8_t i = 0; i < s_client_count; i++) {
            outClients[i] = s_client_records[i].record;
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
