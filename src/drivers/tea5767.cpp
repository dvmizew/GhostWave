/**
 * @file tea5767.cpp
 * @brief Raw 5-byte I2C Register Driver Implementation for Philips TEA5767
 */

#include "drivers/tea5767.h"
#include <Arduino.h>

TEA5767Driver::TEA5767Driver(TwoWire &wire, uint8_t i2cAddr)
    : m_wire(wire), m_i2cAddr(i2cAddr) {
}

void TEA5767Driver::init() {
    m_wire.begin(TEA_SDA_PIN, TEA_SCL_PIN, I2C_STANDARD_CLOCK);
}

uint8_t TEA5767Driver::readLevel(float freqMHz) {
    // High-Side LO Injection formula (32.768 kHz reference crystal):
    // PLL = 4 * (f_RF + 225 kHz) / 32.768 kHz
    uint32_t pll = static_cast<uint32_t>((freqMHz * 1000000.0f + 225000.0f) * 4.0f / 32768.0f + 0.5f);

    uint8_t txBuf[5];
    txBuf[0] = static_cast<uint8_t>(0x80 | ((pll >> 8) & 0x3F)); // MUTE=1 (silent fast sweep), Search=0, PLL[13:8]
    txBuf[1] = static_cast<uint8_t>(pll & 0xFF);                 // PLL[7:0]
    txBuf[2] = 0x18;                                             // SUD=0, SSL=00, HLSI=1 (High side), MS=1 (Force Mono for RF DX)
    txBuf[3] = 0x10;                                             // XTAL=1 (32.768kHz crystal), Europe/US band
    txBuf[4] = 0x00;                                             // PLLE=0, DTC=0

    m_wire.beginTransmission(m_i2cAddr);
    m_wire.write(txBuf, sizeof(txBuf));
    if (m_wire.endTransmission() != 0) {
        return 0; // Bus communication error / NACK
    }

    // Allow PLL synthesizer to settle (~2.5ms settle delay)
    delayMicroseconds(TEA5767_SETTLE_DELAY_US);

    // Read 5 status response bytes
    uint8_t readCount = m_wire.requestFrom(static_cast<uint8_t>(m_i2cAddr), static_cast<uint8_t>(5));
    if (readCount != 5) {
        return 0;
    }

    uint8_t rxBuf[5] = {0};
    for (size_t i = 0; i < 5; i++) {
        rxBuf[i] = static_cast<uint8_t>(m_wire.read());
    }

    // Byte 4: bits 7..4 = LEV[3:0] (ADC signal level 0..15)
    uint8_t level = static_cast<uint8_t>((rxBuf[3] >> 4) & 0x0F);
    return level;
}

void TEA5767Driver::sweep(uint8_t *outRssi) {
    if (outRssi == nullptr) {
        return;
    }

    for (int i = 0; i < GHOSTWAVE_FM_BINS; i++) {
        float freq = GHOSTWAVE_FM_FREQ_START +
            (static_cast<float>(i) * (GHOSTWAVE_FM_FREQ_SPAN / static_cast<float>(GHOSTWAVE_FM_BINS - 1)));
        outRssi[i] = readLevel(freq);
    }
}
