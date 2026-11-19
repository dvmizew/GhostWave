#ifndef GHOSTWAVE_DRIVERS_TEA5767_H
#define GHOSTWAVE_DRIVERS_TEA5767_H

#include <stdint.h>
#include <Wire.h>
#include "config.h"
#include "types.h"

struct FmReading {
    uint8_t level;
    uint8_t ifCount;
    bool    stereo;
    bool    validIf;
    bool    ready;
    bool    bandLimit;
};

class TEA5767Driver {
public:
    explicit TEA5767Driver(TwoWire &wire = Wire1, uint8_t i2cAddr = TEA5767_I2C_ADDR);

    bool init();

    // High-Side LO Injection: PLL = 4 * (f_RF + 225 kHz) / 32.768 kHz
    bool      tune(float freqMHz, bool mute = false, bool mono = false,
                   bool softMute = true, bool hcc = true, bool snc = true);
    void      setMute(bool mute);
    void      setMono(bool mono);
    bool      seek(bool seekUp, float &outFoundFreq);

    FmReading readReading(float freqMHz);
    FmReading readCurrentStatus();
    uint8_t   readLevel(float freqMHz);

    // 64-bin sweep with peak-detection for active stations
    void sweep(uint8_t *outRssi, FmStationRecord *outStations = nullptr,
               uint8_t *outStationCount = nullptr, uint8_t maxStations = 0);

    uint8_t getLastError() const { return m_lastError; }
    float   getCurrentFrequency() const { return m_currentFreq; }
    bool    isMuted() const { return m_isMuted; }
    bool    isMono() const { return m_isMono; }

private:
    TwoWire &m_wire;
    uint8_t  m_i2cAddr;
    uint8_t  m_lastError;
    float    m_currentFreq;
    bool     m_isMuted;
    bool     m_isMono;
    bool     m_softMute;
    bool     m_hcc;
    bool     m_snc;
};

#endif // GHOSTWAVE_DRIVERS_TEA5767_H
