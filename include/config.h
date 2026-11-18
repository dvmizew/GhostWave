/**
 * @file config.h
 *
 * Hardware pin definitions, bus timings, baud rates, and RF sweep constants.
 */

#ifndef GHOSTWAVE_CONFIG_H
#define GHOSTWAVE_CONFIG_H
// HARDWARE PIN DEFINITIONS (Single 38-Pin ESP32-WROOM-32)
// SSD1306 OLED (128x64, Hardware I2C0 via Wire)
#define OLED_SDA_PIN            21
#define OLED_SCL_PIN            22

// TEA5767 FM Receiver
#define TEA_SDA_PIN             32
#define TEA_SCL_PIN             33

// Mode Toggle Button (INPUT_PULLUP to GND)
#define BTN_MODE_PIN            4

// SERIAL & BUS TIMINGS
#define SERIAL_BAUD_RATE        921600

// Hardware I2C Standard Clock Rate (400 kHz Fast-Mode)
#define I2C_STANDARD_CLOCK      400000

// Display target refresh interval (~30 FPS)
#define UI_REFRESH_INTERVAL_MS  33

// Mode toggle pushbutton debounce duration
#define BTN_DEBOUNCE_MS         250

// Static buffer size for telemetry JSON framing
#define TELEMETRY_BUFFER_SIZE   1280

// RF SCANNER CONFIGURATION & CONSTANTS
#define GHOSTWAVE_FM_BINS       64       // 64 frequency steps across FM band
#define GHOSTWAVE_FM_FREQ_START 87.5f    // FM sweep start in MHz
#define GHOSTWAVE_FM_FREQ_SPAN  20.5f    // 108.0 MHz - 87.5 MHz
#define TEA5767_I2C_ADDR        0x60     // Philips TEA5767 7-bit I2C address
#define TEA5767_SETTLE_DELAY_US 2500     // Settle delay after tuning (~2.5ms)

#define GHOSTWAVE_WIFI_CHANNELS 13       // 2.4 GHz 802.11 b/g/n channels 1 to 13
#define WIFI_CHANNEL_DWELL_MS   25       // Sniffer dwell per channel (13 * 25ms = 325ms)
#define BLE_SCAN_WINDOW_MS      80       // Passive BLE scan window per cycle

// ============================================================================
// FREERTOS TASK ALLOCATION
// ============================================================================
#define RF_TASK_STACK_SIZE      8192     // Sufficient for Wi-Fi sniffer + NimBLE stack
#define RF_TASK_PRIORITY        2
#define RF_TASK_CORE            1

#define UI_TASK_STACK_SIZE      6144     // Sufficient for U8g2 full-buffer rendering
#define UI_TASK_PRIORITY        1
#define UI_TASK_CORE            0

#endif // GHOSTWAVE_CONFIG_H
