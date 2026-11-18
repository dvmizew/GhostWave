/**
 * @file wifi_sniffer.cpp
 * @brief Promiscuous 802.11 Sniffer & Channel Hopper Implementation
 */

#include "rf/wifi_sniffer.h"
#include <Arduino.h>
#include <WiFi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

static portMUX_TYPE s_wifi_mux = portMUX_INITIALIZER_UNLOCKED;

static volatile uint8_t  s_current_channel = 1;
static volatile uint16_t s_wifi_pkts_temp[GHOSTWAVE_WIFI_CHANNELS] = {0};
static volatile int8_t   s_wifi_rssi_temp[GHOSTWAVE_WIFI_CHANNELS] = {0};

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

void WifiSniffer::sweepChannels(uint16_t *outPkts, int8_t *outMaxRssi, uint32_t dwellMs) {
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
}
