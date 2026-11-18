/**
 * @file wifi_sniffer.h
 * @brief 802.11 Promiscuous Sniffer & Channel Hopping Subsystem
 *
 * Captures 802.11 management/data frame counts and parses Access Point Beacons.
 */

#ifndef GHOSTWAVE_RF_WIFI_SNIFFER_H
#define GHOSTWAVE_RF_WIFI_SNIFFER_H

#include <stdint.h>
#include <esp_wifi.h>
#include "config.h"
#include "types.h"

class WifiSniffer {
public:
    static void init();
    static void start();
    static void stop();
    static void setChannel(uint8_t channel);
    static void resetChannelStats(uint8_t channel);
    static void getChannelStats(uint8_t channel, uint16_t &outPkts, int8_t &outMaxRssi);

    /**
     * @brief Sweeps all channels (1..13), collecting packet stats and discovered Beacon APs.
     * @param outPkts Array of size GHOSTWAVE_WIFI_CHANNELS for packet counts
     * @param outMaxRssi Array of size GHOSTWAVE_WIFI_CHANNELS for peak RSSI
     * @param outAps Destination array for discovered AP records (up to MAX_DISCOVERED_APS)
     * @param outApCount Reference storing the number of APs found
     * @param dwellMs Time spent dwelling on each channel in milliseconds
     */
    static void sweepChannels(uint16_t *outPkts, int8_t *outMaxRssi,
                              WifiApRecord *outAps, uint8_t &outApCount,
                              uint32_t dwellMs = WIFI_CHANNEL_DWELL_MS);

private:
    static void IRAM_ATTR promiscuousCallback(void *buf, wifi_promiscuous_pkt_type_t type);
};

#endif // GHOSTWAVE_RF_WIFI_SNIFFER_H
