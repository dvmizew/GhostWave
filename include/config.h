/**
 * @file config.h
 * @brief Hardware Configuration & Constants
 */

#ifndef GHOSTWAVE_CONFIG_H
#define GHOSTWAVE_CONFIG_H

// HARDWARE PIN DEFINITIONS
// TEA5767 FM Receiver (Hardware I2C1 - Wire1)
#define TEA_SDA_PIN             27
#define TEA_SCL_PIN             26

// SERIAL & BUS TIMINGS
#define SERIAL_BAUD_RATE        921600
#define I2C_STANDARD_CLOCK      100000   // 100 kHz Standard-Mode

// Static buffer size for telemetry JSON framing
#define TELEMETRY_BUFFER_SIZE   12288

#define MAX_DISCOVERED_CLIENTS  12
#define MAX_DISCOVERED_PROBES   8

// RF SCANNER CONFIGURATION & CONSTANTS
#define GHOSTWAVE_FM_BINS       103      // 103 frequency steps (200 kHz across 87.5 - 108.0 MHz)
#define GHOSTWAVE_FM_FREQ_START 87.5f    // EU/US FM broadcast band start in MHz
#define GHOSTWAVE_FM_FREQ_SPAN  20.5f    // 108.0 MHz - 87.5 MHz (20.5 MHz span)
#define TEA5767_I2C_ADDR        0x60     // Philips TEA5767 7-bit I2C address
#define TEA5767_SETTLE_DELAY_US 30000    // 30ms PLL + 27ms IF/ADC settle (Philips TEA5767 AN10133)
#define FM_STATION_MIN_LEVEL    5        // Minimum ADC level (0-15) for peak station detection

#define GHOSTWAVE_WIFI_CHANNELS 13       // 2.4 GHz 802.11 b/g/n channels 1 to 13
#define WIFI_CHANNEL_DWELL_MS   25       // Sniffer dwell per channel (13 * 25ms = 325ms)
#define BLE_SCAN_WINDOW_MS      120      // Active BLE scan window per cycle (3 x 40ms channels 37/38/39)

// FREERTOS TASK ALLOCATION
#define RF_TASK_STACK_SIZE      8192     // Core 1: Wi-Fi sniffer + NimBLE stack
#define RF_TASK_PRIORITY        2
#define RF_TASK_CORE            1

#define TELEMETRY_TASK_STACK_SIZE 4096   // Core 0: Event-driven Serial JSON streamer
#define TELEMETRY_TASK_PRIORITY   1
#define TELEMETRY_TASK_CORE       0

#endif // GHOSTWAVE_CONFIG_H
