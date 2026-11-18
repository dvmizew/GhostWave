#ifndef GHOSTWAVE_DRIVERS_TEA5767_H
#define GHOSTWAVE_DRIVERS_TEA5767_H

#include <stdint.h>
#include <Wire.h>
#include "config.h"

class TEA5767Driver {
public:
    explicit TEA5767Driver(TwoWire &wire = Wire1, uint8_t i2cAddr = TEA5767_I2C_ADDR);
    void init();

    // High-Side LO Injection formula: PLL = 4 * (f_RF + 225 kHz) / 32.768 kHz
    uint8_t readLevel(float freqMHz);
    void sweep(uint8_t *outRssi);

private:
    TwoWire &m_wire;
    uint8_t  m_i2cAddr;
};

#endif // GHOSTWAVE_DRIVERS_TEA5767_H
