#ifndef GHOSTWAVE_RF_BLE_SCANNER_H
#define GHOSTWAVE_RF_BLE_SCANNER_H

#include <stdint.h>
#include "types.h"

class BleScanner {
public:
    static void init();
    static void scan(uint32_t windowMs, uint16_t &outDevices, int8_t &outMaxRssi,
                     BleDeviceRecord *outBleList = nullptr, uint8_t *outBleCount = nullptr);
};

#endif // GHOSTWAVE_RF_BLE_SCANNER_H
