/**
 * @file ble_scanner.h
 * @brief NimBLE Passive Scanner Subsystem
 */

#ifndef GHOSTWAVE_RF_BLE_SCANNER_H
#define GHOSTWAVE_RF_BLE_SCANNER_H

#include <stdint.h>

class BleScanner {
public:
    /**
     * @brief Initializes NimBLE passive scan configuration. Zero heap storage.
     */
    static void init();

    /**
     * @brief Performs a passive BLE scan for the specified window duration.
     * @param windowMs Scan duration in milliseconds
     * @param outDevices Output count of advertising devices discovered
     * @param outMaxRssi Output highest RSSI observed in dBm (-128 if none)
     */
    static void scan(uint32_t windowMs, uint16_t &outDevices, int8_t &outMaxRssi);
};

#endif // GHOSTWAVE_RF_BLE_SCANNER_H
