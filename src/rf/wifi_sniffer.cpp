/**
 * @file wifi_sniffer.cpp
 * @brief Promiscuous 802.11 Sniffer & Beacon Parser
 */

#include "rf/wifi_sniffer.h"
#include <Arduino.h>
#include <WiFi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <string.h>

static portMUX_TYPE s_wifi_mux = portMUX_INITIALIZER_UNLOCKED;

static volatile uint8_t  s_current_channel = 1;
static volatile uint16_t s_wifi_pkts_temp[GHOSTWAVE_WIFI_CHANNELS] = {0};
static volatile int8_t   s_wifi_rssi_temp[GHOSTWAVE_WIFI_CHANNELS] = {0};

typedef struct {
    uint16_t frame_ctrl;
    uint16_t duration_id;
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6]; // BSSID
    uint16_t seq_ctrl;
} __attribute__((packed)) wifi_mgmt_hdr_t;

static WifiApRecord s_ap_temp[MAX_DISCOVERED_APS];
static uint8_t      s_ap_count_temp = 0;

void IRAM_ATTR WifiSniffer::promiscuousCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type == WIFI_PKT_MGMT || type == WIFI_PKT_DATA) {
        const wifi_promiscuous_pkt_t *pkt = reinterpret_cast<const wifi_promiscuous_pkt_t *>(buf);
        int8_t rssi = pkt->rx_ctrl.rssi;
        uint8_t ch = s_current_channel;

        if (ch >= 1 && ch <= GHOSTWAVE_WIFI_CHANNELS) {
            portENTER_CRITICAL_ISR(&s_wifi_mux);
            s_wifi_pkts_temp[ch - 1] = s_wifi_pkts_temp[ch - 1] + 1;
            if (rssi > s_wifi_rssi_temp[ch - 1]) {
                s_wifi_rssi_temp[ch - 1] = rssi;
            }
            portEXIT_CRITICAL_ISR(&s_wifi_mux);
        }

        // Parse Beacon management frames (subtype 8)
        if (type == WIFI_PKT_MGMT && pkt->rx_ctrl.sig_len >= sizeof(wifi_mgmt_hdr_t) + 12) {
            const uint8_t *payload = pkt->payload;
            const wifi_mgmt_hdr_t *hdr = reinterpret_cast<const wifi_mgmt_hdr_t *>(payload);
            uint8_t subtype = (hdr->frame_ctrl >> 4) & 0x0F;

            if (subtype == 8) { // Beacon frame
                // Information Elements (IEs) begin at offset 36
                uint16_t len = pkt->rx_ctrl.sig_len;
                uint16_t pos = 36;
                char ssidBuf[24] = {0};

                while (pos + 1 < len) {
                    uint8_t id = payload[pos];
                    uint8_t elen = payload[pos + 1];
                    if (pos + 2 + elen > len) break;

                    if (id == 0) { // SSID Element ID
                        uint8_t copyLen = (elen < 23) ? elen : 23;
                        for (uint8_t i = 0; i < copyLen; i++) {
                            char c = static_cast<char>(payload[pos + 2 + i]);
                            ssidBuf[i] = (c >= 32 && c <= 126) ? c : '?';
                        }
                        ssidBuf[copyLen] = '\0';
                        break;
                    }
                    pos += 2 + elen;
                }

                if (ssidBuf[0] != '\0') {
                    portENTER_CRITICAL_ISR(&s_wifi_mux);
                    // Check if already in temp AP list by BSSID
                    bool found = false;
                    for (uint8_t i = 0; i < s_ap_count_temp; i++) {
                        if (memcmp(s_ap_temp[i].bssid, hdr->addr3, 6) == 0) {
                            found = true;
                            s_ap_temp[i].rssi = rssi;
                            break;
                        }
                    }
                    if (!found && s_ap_count_temp < MAX_DISCOVERED_APS) {
                        strncpy(s_ap_temp[s_ap_count_temp].ssid, ssidBuf, sizeof(s_ap_temp[0].ssid) - 1);
                        s_ap_temp[s_ap_count_temp].ssid[sizeof(s_ap_temp[0].ssid) - 1] = '\0';
                        memcpy(s_ap_temp[s_ap_count_temp].bssid, hdr->addr3, 6);
                        s_ap_temp[s_ap_count_temp].channel = ch;
                        s_ap_temp[s_ap_count_temp].rssi = rssi;
                        s_ap_count_temp++;
                    }
                    portEXIT_CRITICAL_ISR(&s_wifi_mux);
                }
            }
        }
    }
}

void WifiSniffer::init() {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
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
        portEXIT_CRITICAL(&s_wifi_mux);
    }
}

void WifiSniffer::getChannelStats(uint8_t channel, uint16_t &outPkts, int8_t &outMaxRssi) {
    if (channel >= 1 && channel <= GHOSTWAVE_WIFI_CHANNELS) {
        portENTER_CRITICAL(&s_wifi_mux);
        outPkts = s_wifi_pkts_temp[channel - 1];
        outMaxRssi = s_wifi_rssi_temp[channel - 1];
        portEXIT_CRITICAL(&s_wifi_mux);
    }
}

void WifiSniffer::sweepChannels(uint16_t *outPkts, int8_t *outMaxRssi,
                              WifiApRecord *outAps, uint8_t &outApCount,
                              uint32_t dwellMs) {
    portENTER_CRITICAL(&s_wifi_mux);
    s_ap_count_temp = 0;
    portEXIT_CRITICAL(&s_wifi_mux);

    start();

    for (uint8_t ch = 1; ch <= GHOSTWAVE_WIFI_CHANNELS; ch++) {
        setChannel(ch);
        resetChannelStats(ch);

        vTaskDelay(pdMS_TO_TICKS(dwellMs));

        if (outPkts != nullptr && outMaxRssi != nullptr) {
            getChannelStats(ch, outPkts[ch - 1], outMaxRssi[ch - 1]);
        }
    }

    stop();

    if (outAps != nullptr) {
        portENTER_CRITICAL(&s_wifi_mux);
        outApCount = s_ap_count_temp;
        memcpy(outAps, s_ap_temp, sizeof(WifiApRecord) * s_ap_count_temp);
        portEXIT_CRITICAL(&s_wifi_mux);
    }
}
