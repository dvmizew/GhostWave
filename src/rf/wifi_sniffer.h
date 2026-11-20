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
    static void getChannelStats(uint8_t channel, uint16_t &outPkts, int8_t &outMaxRssi, int8_t &outNoiseFloor);

    static void sweepChannels(uint16_t *outPkts, int8_t *outMaxRssi, int8_t *outNoiseFloor,
                              WifiApRecord *outAps, uint8_t &outApCount,
                              WifiClientRecord *outClients, uint8_t &outClientCount,
                              uint16_t &outDeauthCount, uint8_t &outDeauthChannel,
                              uint32_t dwellMs = WIFI_CHANNEL_DWELL_MS);

private:
    static void promiscuousCallback(void *buf, wifi_promiscuous_pkt_type_t type);
};

#endif // GHOSTWAVE_RF_WIFI_SNIFFER_H
