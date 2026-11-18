/**
 * @file main.cpp
 * @brief GhostWave Single-Node RF Spectrum Analyzer & Congestion Monitor
 * Entry point: Hardware initialization & dual-core FreeRTOS task dispatch.
 */

#include <Arduino.h>
#include <Wire.h>
#include "config.h"
#include "types.h"
#include "rf/rf_scanner.h"
#include "ui/ui_manager.h"

// Synchronization primitives & double-buffer shared snapshot
static SemaphoreHandle_t s_snapshot_mutex = nullptr;
static SpectrumSnapshot  s_shared_snapshot = {};
static volatile bool     s_new_data_available = false;

void setup() {
    pinMode(BTN_MODE_PIN, INPUT_PULLUP);

    Serial.begin(SERIAL_BAUD_RATE);

    s_snapshot_mutex = xSemaphoreCreateMutex();

    // I2C0 for SSD1306 OLED
    Wire.begin(OLED_SDA_PIN, OLED_SCL_PIN, I2C_STANDARD_CLOCK);

    Serial.println("{\"status\":\"GhostWave Single-Node Online\",\"baud\":921600}");

    // Spawn Core 1 RF Scanner (probes TEA5767 + Wi-Fi Promiscuous + NimBLE Scan)
    rf_scanner_start(s_snapshot_mutex, &s_shared_snapshot, &s_new_data_available);

    // Spawn Core 0 UI & Telemetry (U8g2 30 FPS OLED + Serial JSON Stream)
    ui_manager_start(s_snapshot_mutex, &s_shared_snapshot, &s_new_data_available);
}

void loop() {
    vTaskDelay(pdMS_TO_TICKS(1000));
}
