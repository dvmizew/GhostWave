/**
 * @file ble_scanner.h
 * @brief NimBLE Passive Scanner Subsystem
 */

#ifndef GHOSTWAVE_RF_BLE_SCANNER_H
#define GHOSTWAVE_RF_BLE_SCANNER_H

#include <stdint.h>
#include "types.h"

class BleScanner {
public:
    /**
     * @brief Initializes NimBLE passive scan configuration
     */
    static void init();

    /**
     * @brief Performs a passive BLE scan for the specified window duration.
     * @param windowMs Scan duration in milliseconds
     * @param outDevices Output count of advertising devices discovered
     * @param outMaxRssi Output highest RSSI observed in dBm (-128 if none)
     * @param outBleList Output array of discovered BLE devices (up to MAX_DISCOVERED_BLE)
     * @param outBleCount Output reference storing count of discovered BLE devices
     */
    static void scan(uint32_t windowMs, uint16_t &outDevices, int8_t &outMaxRssi,
                     BleDeviceRecord *outBleList = nullptr, uint8_t *outBleCount = nullptr);
};

#endif // GHOSTWAVE_RF_BLE_SCANNER_H
