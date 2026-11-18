/**
 * @file wifi_sniffer.h
 * @brief 802.11 Promiscuous Sniffer & Channel Hopping Subsystem
 *
 * Captures 802.11 management and data frame counts and peak RSSI across channels 1..13.
 */

#ifndef GHOSTWAVE_RF_WIFI_SNIFFER_H
#define GHOSTWAVE_RF_WIFI_SNIFFER_H

#include <stdint.h>
#include <esp_wifi.h>
#include "config.h"

class WifiSniffer {
public:
    /**
     * @brief Configures station mode and registers the promiscuous RX callback.
     */
    static void init();

    /**
     * @brief Enables Wi-Fi promiscuous mode.
     */
    static void start();

    /**
     * @brief Disables Wi-Fi promiscuous mode.
     */
    static void stop();

    /**
     * @brief Tunes hardware radio to specified Wi-Fi channel (1..13).
     * @param channel Primary channel number (1 to 13)
     */
    static void setChannel(uint8_t channel);

    /**
     * @brief Resets accumulator counters for the specified channel under spinlock.
     * @param channel Channel number (1 to 13)
     */
    static void resetChannelStats(uint8_t channel);

    /**
     * @brief Retrieves accumulated packet count and peak RSSI for a channel under spinlock.
     * @param channel Channel number (1 to 13)
     * @param outPkts Output packet count reference
     * @param outMaxRssi Output peak RSSI reference
     */
    static void getChannelStats(uint8_t channel, uint16_t &outPkts, int8_t &outMaxRssi);

    /**
     * @brief Sweeps all channels (1..13) with dwell delay, collecting frame stats.
     * @param outPkts Array of size GHOSTWAVE_WIFI_CHANNELS for packet counts
     * @param outMaxRssi Array of size GHOSTWAVE_WIFI_CHANNELS for peak RSSI
     * @param dwellMs Time spent dwelling on each channel in milliseconds
     */
    static void sweepChannels(uint16_t *outPkts, int8_t *outMaxRssi, uint32_t dwellMs = WIFI_CHANNEL_DWELL_MS);

private:
    static void IRAM_ATTR promiscuousCallback(void *buf, wifi_promiscuous_pkt_type_t type);
};

#endif // GHOSTWAVE_RF_WIFI_SNIFFER_H
