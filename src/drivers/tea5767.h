/**
 * @file tea5767.h
 * @brief Raw 5-byte I2C Register Driver for Philips TEA5767 FM Receiver
 *
 * Direct hardware register control via TwoWire (Wire1). No wrapper libraries.
 */

#ifndef GHOSTWAVE_DRIVERS_TEA5767_H
#define GHOSTWAVE_DRIVERS_TEA5767_H

#include <stdint.h>
#include <Wire.h>
#include "config.h"

class TEA5767Driver {
public:
    /**
     * @brief Construct a new TEA5767Driver object.
     * @param wire Reference to TwoWire interface (defaults to Wire1)
     * @param i2cAddr 7-bit I2C address (defaults to 0x60)
     */
    explicit TEA5767Driver(TwoWire &wire = Wire1, uint8_t i2cAddr = TEA5767_I2C_ADDR);

    /**
     * @brief Initializes the dedicated hardware I2C bus on GPIO 32/33.
     */
    void init();

    /**
     * @brief Tunes TEA5767 to a target frequency in MHz and reads ADC signal level.
     *
     * Frequency formula (High-Side LO Injection, 32.768 kHz crystal):
     *   PLL = 4 * (f_RF + 225 kHz) / 32.768 kHz
     *
     * @param freqMHz Target frequency in MHz (87.5 to 108.0)
     * @return uint8_t ADC signal level (0 to 15)
     */
    uint8_t readLevel(float freqMHz);

    /**
     * @brief Sweeps across all configured FM bins and stores levels.
     * @param outRssi Destination array of size GHOSTWAVE_FM_BINS
     */
    void sweep(uint8_t *outRssi);

private:
    TwoWire &m_wire;
    uint8_t  m_i2cAddr;
};

#endif // GHOSTWAVE_DRIVERS_TEA5767_H
