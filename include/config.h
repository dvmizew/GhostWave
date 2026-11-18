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
#define TELEMETRY_BUFFER_SIZE   2048

// RF SCANNER CONFIGURATION & CONSTANTS
#define GHOSTWAVE_FM_BINS       64       // 64 frequency steps across FM band
#define GHOSTWAVE_FM_FREQ_START 87.5f    // FM sweep start in MHz
#define GHOSTWAVE_FM_FREQ_SPAN  20.5f    // 108.0 MHz - 87.5 MHz
#define TEA5767_I2C_ADDR        0x60     // Philips TEA5767 7-bit I2C address
#define TEA5767_SETTLE_DELAY_US 5000     // Settle delay after tuning (5ms PLL lock window)

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
