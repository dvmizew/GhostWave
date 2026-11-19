#ifndef GHOSTWAVE_TYPES_H
#define GHOSTWAVE_TYPES_H

#include <stdint.h>
#include "config.h"

#define MAX_DISCOVERED_APS      8
#define MAX_DISCOVERED_BLE      8
#define MAX_DISCOVERED_STATIONS 8

enum SystemOpMode : uint8_t {
    OP_MODE_SWEEP      = 0,
    OP_MODE_TUNER      = 1,
    OP_MODE_BUG_HUNTER = 2
};

#define MAX_BUG_TARGETS 4

struct BugTargetRecord {
    float   freqMHz;
    uint8_t level;
    uint8_t deltaAboveNoise;
    uint8_t ifCount;
    bool    validIf;
};

struct FmStationRecord {
    float   freqMHz;
    uint8_t level;
    uint8_t ifCount;
    bool    stereo;
    bool    validIf;
};

struct WifiApRecord {
    char    ssid[24];
    uint8_t bssid[6];
    uint8_t channel;
    int8_t  rssi;
};

struct BleDeviceRecord {
    char   name[20];
    char   addr[18];
    int8_t rssi;
};

struct SpectrumSnapshot {
    uint32_t timestampMs;
    uint16_t sweepDurationMs;
    uint16_t seq;
    uint8_t  teaError;                                      // 0 = OK, 2 = I2C NACK (no device), 5 = Read err
    uint8_t  fmRssi[GHOSTWAVE_FM_BINS];                     // 64 bins, ADC signal level 0 to 15
    uint16_t wifiPkts[GHOSTWAVE_WIFI_CHANNELS];             // Management & data packets per channel
    int8_t   wifiMaxRssi[GHOSTWAVE_WIFI_CHANNELS];          // Peak RSSI in dBm (-128 if no traffic)
    uint16_t bleDevices;                                    // Active advertising BLE devices observed
    int8_t   bleMaxRssi;                                    // Peak BLE RSSI observed in dBm (-128 if none)
    uint8_t  apCount;                                       // Number of beacon APs discovered in this sweep
    WifiApRecord apList[MAX_DISCOVERED_APS];                // Discovered Wi-Fi networks (SSID, BSSID, Ch, RSSI)
    uint8_t  bleCount;                                      // Number of unique BLE devices discovered
    BleDeviceRecord bleList[MAX_DISCOVERED_BLE];            // Discovered BLE devices (Name, MAC, RSSI)
    uint8_t  stationCount;                                  // Number of active FM carriers detected
    FmStationRecord stationList[MAX_DISCOVERED_STATIONS];   // Discovered FM stations (Freq, Level, Stereo)

    // Interactive Tuner Status (Active in OP_MODE_TUNER)
    uint8_t  opMode;                                        // OP_MODE_SWEEP, OP_MODE_TUNER, or OP_MODE_BUG_HUNTER
    float    tunerFreq;                                     // Active tuned frequency in MHz
    uint8_t  tunerLevel;                                    // Tuned station ADC level (0-15)
    uint8_t  tunerIfCount;                                  // Tuned station IF counter
    bool     tunerStereo;                                   // Tuned station stereo pilot detected
    bool     tunerIfLock;                                   // Tuned station 225 kHz IF lock
    bool     tunerMute;                                     // Tuner audio muted
    bool     tunerMono;                                     // Tuner force mono

    // RF Bug Hunter Status (Active in OP_MODE_BUG_HUNTER)
    uint8_t         bugNoiseFloor;                          // Ambient RF baseline level
    uint8_t         bugThreatLevel;                         // 0 = Clear, 1 = Suspicious, 2 = Critical
    uint8_t         bugCount;                               // Number of detected suspicious bug transmitters
    BugTargetRecord bugList[MAX_BUG_TARGETS];               // Suspect transmitter records
};

#endif // GHOSTWAVE_TYPES_H
