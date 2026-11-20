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
#define TELEMETRY_BUFFER_SIZE   10240

#define MAX_DISCOVERED_CLIENTS  12
#define MAX_DISCOVERED_PROBES   8

// RF SCANNER CONFIGURATION & CONSTANTS
#define GHOSTWAVE_FM_BINS       128      // 128 frequency steps (Fine Scan)
#define GHOSTWAVE_FM_FREQ_START 76.0f    // FM sweep start in MHz (Japan + World band)
#define GHOSTWAVE_FM_FREQ_SPAN  32.0f    // 108.0 MHz - 76.0 MHz (32.0 MHz span)
#define TEA5767_I2C_ADDR        0x60     // Philips TEA5767 7-bit I2C address
#define TEA5767_SETTLE_DELAY_US 2000     // 2.0ms PLL lock window for fine steps
#define FM_STATION_MIN_LEVEL    5        // Minimum ADC level (0-15) for peak station detection

#define GHOSTWAVE_WIFI_CHANNELS 13       // 2.4 GHz 802.11 b/g/n channels 1 to 13
#define WIFI_CHANNEL_DWELL_MS   25       // Sniffer dwell per channel (13 * 25ms = 325ms)
#define BLE_SCAN_WINDOW_MS      80       // Passive BLE scan window per cycle

// FREERTOS TASK ALLOCATION
#define RF_TASK_STACK_SIZE      8192     // Core 1: Wi-Fi sniffer + NimBLE stack
#define RF_TASK_PRIORITY        2
#define RF_TASK_CORE            1

#define TELEMETRY_TASK_STACK_SIZE 4096   // Core 0: Event-driven Serial JSON streamer
#define TELEMETRY_TASK_PRIORITY   1
#define TELEMETRY_TASK_CORE       0

#endif // GHOSTWAVE_CONFIG_H
