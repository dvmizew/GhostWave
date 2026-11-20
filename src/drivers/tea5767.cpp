/**
 * @file tea5767.cpp
 * @brief Raw 5-byte I2C Register Driver for Philips TEA5767
 */

#include "drivers/tea5767.h"
#include <Arduino.h>

TEA5767Driver::TEA5767Driver(TwoWire &wire, uint8_t i2cAddr)
    : m_wire(wire), m_i2cAddr(i2cAddr), m_lastError(0),
      m_currentFreq(GHOSTWAVE_FM_FREQ_START), m_isMuted(false), m_isMono(false),
      m_softMute(true), m_hcc(true), m_snc(true), m_sweepCursor(0) {
    memset(m_bandRssi, 0, sizeof(m_bandRssi));
    memset(m_bandIf, 0, sizeof(m_bandIf));
    memset(m_bandStereo, 0, sizeof(m_bandStereo));
}

static void recoverI2cBus(int sdaPin, int sclPin) {
    pinMode(sdaPin, INPUT_PULLUP);
    pinMode(sclPin, OUTPUT);
    for (int i = 0; i < 9; i++) {
        digitalWrite(sclPin, LOW);
        delayMicroseconds(10);
        digitalWrite(sclPin, HIGH);
        delayMicroseconds(10);
    }
    pinMode(sdaPin, OUTPUT);
    digitalWrite(sdaPin, LOW);
    delayMicroseconds(10);
    digitalWrite(sclPin, HIGH);
    delayMicroseconds(10);
    digitalWrite(sdaPin, HIGH);
    delayMicroseconds(10);
}

bool TEA5767Driver::init() {
    recoverI2cBus(TEA_SDA_PIN, TEA_SCL_PIN);
    pinMode(TEA_SDA_PIN, INPUT_PULLUP);
    pinMode(TEA_SCL_PIN, INPUT_PULLUP);
    m_wire.begin(TEA_SDA_PIN, TEA_SCL_PIN, I2C_STANDARD_CLOCK);
    m_wire.setTimeOut(25); // Never allow a flaky I2C slave to hang Core 1

    m_wire.beginTransmission(m_i2cAddr);
    m_lastError = m_wire.endTransmission();
    return (m_lastError == 0);
}

bool TEA5767Driver::tune(float freqMHz, bool mute, bool mono,
                         bool softMute, bool hcc, bool snc) {
    m_currentFreq = freqMHz;
    m_isMuted = mute;
    m_isMono = mono;
    m_softMute = softMute;
    m_hcc = hcc;
    m_snc = snc;

    uint32_t pll = static_cast<uint32_t>((freqMHz * 1000000.0f + 225000.0f) * 4.0f / 32768.0f + 0.5f);

    uint8_t bl = (freqMHz < 87.5f) ? 0x20 : 0x00; // BL=1 (Japan FM: 76-91 MHz), BL=0 (Europe/US: 87.5-108 MHz)

    uint8_t txBuf[5];
    txBuf[0] = (mute ? 0x80 : 0x00) | static_cast<uint8_t>((pll >> 8) & 0x3F);
    txBuf[1] = static_cast<uint8_t>(pll & 0xFF);
    txBuf[2] = 0xB0 | (mono ? 0x08 : 0x00); // SUD=1, SSL=01, HLSI=1, MS=mono
    txBuf[3] = 0x10 | bl | (softMute ? 0x08 : 0x00) | (hcc ? 0x04 : 0x00) | (snc ? 0x02 : 0x00);
    txBuf[4] = 0x00; // DTC=0 (50us Europe de-emphasis)

    m_wire.beginTransmission(m_i2cAddr);
    m_wire.write(txBuf, sizeof(txBuf));
    m_lastError = m_wire.endTransmission();
    return (m_lastError == 0);
}

void TEA5767Driver::setMute(bool mute) {
    tune(m_currentFreq, mute, m_isMono, m_softMute, m_hcc, m_snc);
}

void TEA5767Driver::setMono(bool mono) {
    tune(m_currentFreq, m_isMuted, mono, m_softMute, m_hcc, m_snc);
}

void TEA5767Driver::setDsp(bool softMute, bool hcc, bool snc) {
    tune(m_currentFreq, m_isMuted, m_isMono, softMute, hcc, snc);
}

FmReading TEA5767Driver::readCurrentStatus() {
    FmReading r = {};
    uint8_t readCount = m_wire.requestFrom(static_cast<uint8_t>(m_i2cAddr), static_cast<uint8_t>(5));
    if (readCount != 5) {
        m_lastError = 5;
        return r;
    }

    uint8_t rxBuf[5] = {0};
    for (size_t i = 0; i < 5; i++) {
        rxBuf[i] = static_cast<uint8_t>(m_wire.read());
    }

    r.ready = (rxBuf[0] & 0x80) != 0;
    r.bandLimit = (rxBuf[0] & 0x40) != 0;
    r.stereo = (rxBuf[2] & 0x80) != 0;
    r.ifCount = static_cast<uint8_t>(rxBuf[2] & 0x7F);
    r.validIf = (r.ifCount >= 0x31 && r.ifCount <= 0x3E);
    r.level = static_cast<uint8_t>((rxBuf[3] >> 4) & 0x0F);
    return r;
}

bool TEA5767Driver::seek(bool seekUp, float &outFoundFreq) {
    uint32_t pll = static_cast<uint32_t>((m_currentFreq * 1000000.0f + 225000.0f) * 4.0f / 32768.0f + 0.5f);
    uint8_t bl = (m_currentFreq < 87.5f) ? 0x20 : 0x00;

    uint8_t txBuf[5];
    txBuf[0] = 0x40 | static_cast<uint8_t>((pll >> 8) & 0x3F); // SM=1 (Search Mode)
    txBuf[1] = static_cast<uint8_t>(pll & 0xFF);
    txBuf[2] = (seekUp ? 0x80 : 0x00) | 0x20 | 0x10; // SUD, SSL=01, HLSI=1
    txBuf[3] = 0x10 | bl | (m_softMute ? 0x08 : 0x00) | (m_hcc ? 0x04 : 0x00) | (m_snc ? 0x02 : 0x00);
    txBuf[4] = 0x00;

    m_wire.beginTransmission(m_i2cAddr);
    m_wire.write(txBuf, sizeof(txBuf));
    if (m_wire.endTransmission() != 0) {
        return false;
    }

    uint32_t startMs = millis();
    while (millis() - startMs < 600) {
        delay(20);
        uint8_t count = m_wire.requestFrom(static_cast<uint8_t>(m_i2cAddr), static_cast<uint8_t>(5));
        if (count != 5) continue;

        uint8_t rx[5];
        for (int i = 0; i < 5; i++) rx[i] = m_wire.read();

        bool ready = (rx[0] & 0x80) != 0;
        bool bandLimit = (rx[0] & 0x40) != 0;

        if (ready || bandLimit) {
            uint16_t foundPll = ((rx[0] & 0x3F) << 8) | rx[1];
            float foundFreq = (static_cast<float>(foundPll) * 32768.0f / 4.0f - 225000.0f) / 1000000.0f;
            if (foundFreq >= GHOSTWAVE_FM_FREQ_START && foundFreq <= (GHOSTWAVE_FM_FREQ_START + GHOSTWAVE_FM_FREQ_SPAN)) {
                outFoundFreq = foundFreq;
            } else {
                outFoundFreq = m_currentFreq;
            }
            tune(outFoundFreq, m_isMuted, m_isMono, m_softMute, m_hcc, m_snc);
            return true;
        }
    }

    tune(m_currentFreq, m_isMuted, m_isMono, m_softMute, m_hcc, m_snc);
    return false;
}

FmReading TEA5767Driver::readReading(float freqMHz, bool highSide, uint32_t settleUs) {
    FmReading r = {};
    // High-Side (HLSI=1): PLL = 4 * (f_RF + 225 kHz) / 32.768 kHz
    // Low-Side  (HLSI=0): PLL = 4 * (f_RF - 225 kHz) / 32.768 kHz
    float ifOffsetHz = highSide ? 225000.0f : -225000.0f;
    uint32_t pll = static_cast<uint32_t>((freqMHz * 1000000.0f + ifOffsetHz) * 4.0f / 32768.0f + 0.5f);
    uint8_t bl = (freqMHz < 87.5f) ? 0x20 : 0x00;

    uint8_t txBuf[5];
    txBuf[0] = 0x80 | static_cast<uint8_t>((pll >> 8) & 0x3F); // MUTE=1 during sweep/probe to prevent audio static
    txBuf[1] = static_cast<uint8_t>(pll & 0xFF);
    txBuf[2] = 0xA0 | (highSide ? 0x10 : 0x00);                // SUD=1, SSL=01, HLSI=highSide, Stereo ON
    txBuf[3] = 0x10 | bl;                                      // XTAL=1 (32.768 kHz crystal), BL=1/0
    txBuf[4] = 0x00;                                           // Normal operation, Standby=0

    m_wire.beginTransmission(m_i2cAddr);
    m_wire.write(txBuf, sizeof(txBuf));
    uint8_t err = m_wire.endTransmission();
    m_lastError = err;
    if (err != 0) {
        return r; // Bus communication error / NACK
    }

    // Allow PLL synthesizer and AGC/IF stage to settle on frequency
    delayMicroseconds(settleUs);

    uint8_t readCount = m_wire.requestFrom(static_cast<uint8_t>(m_i2cAddr), static_cast<uint8_t>(5));
    if (readCount != 5) {
        m_lastError = 5; // Read error
        return r;
    }

    uint8_t rxBuf[5] = {0};
    for (size_t i = 0; i < 5; i++) {
        rxBuf[i] = static_cast<uint8_t>(m_wire.read());
    }

    // Byte 1 (rxBuf[0]): bit 7 = RF (Ready Flag), bit 6 = BLF (Band Limit Flag)
    r.ready = (rxBuf[0] & 0x80) != 0;
    r.bandLimit = (rxBuf[0] & 0x40) != 0;

    // Byte 3 (rxBuf[2]): bit 7 = STEREO, bits 6..0 = IF[6:0] (Intermediate Frequency counter)
    r.stereo = (rxBuf[2] & 0x80) != 0;
    r.ifCount = static_cast<uint8_t>(rxBuf[2] & 0x7F);
    // TEA5767 datasheet: 0x31 (49) to 0x3E (62) indicates valid 225 kHz IF lock
    r.validIf = (r.ifCount >= 0x31 && r.ifCount <= 0x3E);

    // Byte 4 (rxBuf[3]): bits 7..4 = LEV[3:0] (ADC signal level 0..15)
    r.level = static_cast<uint8_t>((rxBuf[3] >> 4) & 0x0F);
    return r;
}

uint8_t TEA5767Driver::readLevel(float freqMHz) {
    return readReading(freqMHz).level;
}

void TEA5767Driver::sweep(uint8_t *outRssi, FmStationRecord *outStations,
                         uint8_t *outStationCount, uint8_t maxStations) {
    if (outRssi == nullptr) {
        return;
    }

    // Progressive chunked sweep: 16 bins x 30ms (~480ms/cycle) gives full TEA5767 PLL + 27ms IF/ADC settle
    constexpr uint8_t kBinsPerCycle = 16;
    for (uint8_t step = 0; step < kBinsPerCycle; step++) {
        uint8_t i = m_sweepCursor;
        m_sweepCursor = (m_sweepCursor + 1) % GHOSTWAVE_FM_BINS;

        float freq = GHOSTWAVE_FM_FREQ_START +
            (static_cast<float>(i) * (GHOSTWAVE_FM_FREQ_SPAN / static_cast<float>(GHOSTWAVE_FM_BINS - 1)));
        FmReading r = readReading(freq, true, TEA5767_SETTLE_DELAY_US);
        if (m_lastError != 0) {
            memset(outRssi, 0, GHOSTWAVE_FM_BINS);
            if (outStationCount != nullptr) {
                *outStationCount = 0;
            }
            return;
        }
        m_bandRssi[i] = r.level;
        m_bandIf[i] = r.ifCount;
        if (r.stereo) {
            m_bandStereo[i / 8] |= static_cast<uint8_t>(1 << (i % 8));
        } else {
            m_bandStereo[i / 8] &= static_cast<uint8_t>(~(1 << (i % 8)));
        }
    }

    memcpy(outRssi, m_bandRssi, GHOSTWAVE_FM_BINS);

    uint8_t minLev = 15;
    for (int i = 0; i < GHOSTWAVE_FM_BINS; i++) {
        if (m_bandRssi[i] > 0 && m_bandRssi[i] < minLev) {
            minLev = m_bandRssi[i];
        }
    }
    if (minLev == 15) minLev = 0;

    // Peak detection from settled band cache (strict local max above floor + valid 225 kHz IF lock)
    if (outStations != nullptr && outStationCount != nullptr && maxStations > 0) {
        uint8_t count = 0;
        uint8_t threshold = (minLev + 2 > FM_STATION_MIN_LEVEL) ? static_cast<uint8_t>(minLev + 2) : FM_STATION_MIN_LEVEL;

        for (int i = 0; i < GHOSTWAVE_FM_BINS && count < maxStations; i++) {
            uint8_t lev = m_bandRssi[i];
            if (lev < threshold) {
                continue;
            }

            uint8_t left  = (i > 0) ? m_bandRssi[i - 1] : 0;
            uint8_t right = (i < GHOSTWAVE_FM_BINS - 1) ? m_bandRssi[i + 1] : 0;
            bool isLocalPeak = (lev >= left && lev >= right) && (lev > left || lev > right);
            if (!isLocalPeak) {
                continue;
            }

            uint8_t ifc = m_bandIf[i];
            bool validIf = (ifc >= 0x31 && ifc <= 0x3E);
            if (!validIf) {
                continue;
            }

            float freq = GHOSTWAVE_FM_FREQ_START +
                (static_cast<float>(i) * (GHOSTWAVE_FM_FREQ_SPAN / static_cast<float>(GHOSTWAVE_FM_BINS - 1)));
            float snappedFreq = static_cast<float>(static_cast<int>(freq * 10.0f + 0.5f)) / 10.0f;

            outStations[count].freqMHz = snappedFreq;
            outStations[count].level = lev;
            outStations[count].stereo = (m_bandStereo[i / 8] & (1 << (i % 8))) != 0;
            outStations[count].ifCount = ifc;
            outStations[count].validIf = true;
            count++;
        }
        *outStationCount = count;
    }
}
