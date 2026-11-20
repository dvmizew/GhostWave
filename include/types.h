#ifndef GHOSTWAVE_TYPES_H
#define GHOSTWAVE_TYPES_H

#include <stdint.h>
#include "config.h"

#define MAX_DISCOVERED_APS      16
#define MAX_DISCOVERED_BLE      8
#define MAX_DISCOVERED_STATIONS 8

enum WifiAuthMode : uint8_t {
    AUTH_OPEN = 0,
    AUTH_WEP  = 1,
    AUTH_WPA  = 2,
    AUTH_WPA2 = 3,
    AUTH_WPA3 = 4
};

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
    char     ssid[33];                                       // Up to 32 characters + null terminator (IEEE 802.11 standard)
    uint8_t  bssid[6];
    uint8_t  channel;
    int8_t   rssi;
    uint8_t  authMode;                                       // WifiAuthMode (0=Open, 1=WEP, 2=WPA, 3=WPA2, 4=WPA3)
    uint16_t staCount;                                       // QBSS BSS Load client station count (if reported by AP)
    uint8_t  wifiStd;                                        // Generation: 1=Legacy b/g, 4=Wi-Fi 4, 5=Wi-Fi 5, 6=Wi-Fi 6, 7=Wi-Fi 7
    bool     mlo;                                            // Multi-Link Operation (MLO) flag
};

// Bitmask flags for WifiClientRecord::flags
#define WIFI_CLI_FLAG_ENCRYPTED   0x01  // Protected (WPA/WPA2/WPA3) data frame seen
#define WIFI_CLI_FLAG_QOS         0x02  // QoS / WMM Data frame seen
#define WIFI_CLI_FLAG_PWRSAVE     0x04  // Client currently in 802.11 Power Save (Sleep)
#define WIFI_CLI_FLAG_TX_RSSI     0x08  // RSSI measured directly from Client TX (ToDS=1)
#define WIFI_CLI_FLAG_40MHZ       0x10  // 40 MHz channel bandwidth observed or advertised
#define WIFI_CLI_FLAG_SGI         0x20  // Short Guard Interval observed or advertised
#define WIFI_CLI_FLAG_RANDOM_MAC  0x40  // Locally Administered (Randomized / Private) MAC

struct WifiClientRecord {
    uint8_t  mac[6];                                        // Client STA MAC
    uint8_t  bssid[6];                                      // Associated AP BSSID (always non-zero)
    uint8_t  channel;
    int8_t   rssi;                                          // True Client TX RSSI (-128 until TX_RSSI seen)
    uint8_t  wifiStd;                                       // Observed client Wi-Fi gen (0=unknown, 4=n, 5=ac, 6=ax, 7=be)
    uint8_t  phyMode;                                       // rx_ctrl.sig_mode (0=11b/g, 1=HT/11n)
    uint8_t  mcs;                                           // HT MCS index 0..7 (valid when phyMode==1)
    uint8_t  maxRateMbps;                                   // Peak observed client TX PHY rate in Mbps (0=unknown)
    uint8_t  flags;                                         // Bitmask of WIFI_CLI_FLAG_*
    uint16_t txPkts;                                        // Frames transmitted by client (ToDS=1)
    uint16_t rxPkts;                                        // Frames received by client (FromDS=1)
    uint16_t retryPkts;                                     // Client TX retransmitted frames (Retry bit set)
    uint32_t txBytes;                                       // L2 bytes transmitted by client (sig_len - 4)
    uint32_t rxBytes;                                       // L2 bytes received by client (sig_len - 4)
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
    uint8_t  fmRssi[GHOSTWAVE_FM_BINS];                     // 128 bins, ADC signal level 0 to 15
    uint16_t wifiPkts[GHOSTWAVE_WIFI_CHANNELS];             // Management & data packets per channel
    int8_t   wifiMaxRssi[GHOSTWAVE_WIFI_CHANNELS];          // Peak RSSI in dBm (-128 if no traffic)
    int8_t   wifiNoiseFloor[GHOSTWAVE_WIFI_CHANNELS];       // Hardware RF noise floor in dBm per channel
    uint16_t wifiDeauthPkts;                                // Deauth / disassoc frames detected in this sweep
    uint8_t  wifiDeauthChannel;                             // Channel of detected deauth activity (0 if none)
    uint16_t bleDevices;                                    // Active advertising BLE devices observed
    int8_t   bleMaxRssi;                                    // Peak BLE RSSI observed in dBm (-128 if none)
    uint8_t  apCount;                                       // Number of beacon APs discovered in this sweep
    WifiApRecord apList[MAX_DISCOVERED_APS];                // Discovered Wi-Fi networks (SSID, BSSID, Ch, RSSI, Auth)
    uint8_t  clientCount;                                   // Number of client devices discovered in this sweep
    WifiClientRecord clientList[MAX_DISCOVERED_CLIENTS];    // Associated Wi-Fi clients
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
