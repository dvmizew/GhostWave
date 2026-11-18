/**
 * @file rf_scanner.cpp
 * @brief Core 1 RF Scanner
 */

#include "rf/rf_scanner.h"
#include "config.h"
#include "drivers/tea5767.h"
#include "rf/wifi_sniffer.h"
#include "rf/ble_scanner.h"
#include <Arduino.h>
#include <string.h>

static RFScannerContext s_rf_ctx;
static TEA5767Driver    s_tea5767(Wire1);

BaseType_t rf_scanner_start(SemaphoreHandle_t snapshotMutex, SpectrumSnapshot *sharedSnapshot, volatile bool *newDataFlag) {
    s_rf_ctx.snapshotMutex = snapshotMutex;
    s_rf_ctx.sharedSnapshot = sharedSnapshot;
    s_rf_ctx.newDataFlag = newDataFlag;

    s_tea5767.init();
    WifiSniffer::init();
    BleScanner::init();

    return xTaskCreatePinnedToCore(
        Task_RF_Scanner,
        "GW_RF_Scanner",
        RF_TASK_STACK_SIZE,
        &s_rf_ctx,
        RF_TASK_PRIORITY,
        nullptr,
        RF_TASK_CORE
    );
}

void Task_RF_Scanner(void *param) {
    RFScannerContext *ctx = static_cast<RFScannerContext *>(param);
    static SpectrumSnapshot localSnapshot;
    uint16_t sequence = 0;

    while (true) {
        uint32_t sweepStartMs = millis();
        localSnapshot.seq = ++sequence;
        localSnapshot.timestampMs = sweepStartMs;

        // 1. FAST FM BROADCAST SWEEP (87.5 - 108.0 MHz, 64 Bins on Wire1 GPIO 32/33)
        s_tea5767.sweep(localSnapshot.fmRssi);

        // 2. WI-FI PROMISCUOUS CHANNEL HOPPING (Channels 1 - 13)
        WifiSniffer::sweepChannels(localSnapshot.wifiPkts, localSnapshot.wifiMaxRssi, WIFI_CHANNEL_DWELL_MS);

        // delay between Wi-Fi and BLE on the shared 2.4 GHz RF transceiver
        vTaskDelay(pdMS_TO_TICKS(5));

        // 3. PASSIVE BLE SCAN WINDOW (NimBLE-Arduino)
        BleScanner::scan(BLE_SCAN_WINDOW_MS, localSnapshot.bleDevices, localSnapshot.bleMaxRssi);

        localSnapshot.sweepDurationMs = static_cast<uint16_t>(millis() - sweepStartMs);

        // 4. ATOMIC SNAPSHOT TRANSFER TO CORE 0
        if (ctx != nullptr && ctx->snapshotMutex != nullptr &&
            xSemaphoreTake(ctx->snapshotMutex, pdMS_TO_TICKS(10)) == pdTRUE) {
            memcpy(ctx->sharedSnapshot, &localSnapshot, sizeof(SpectrumSnapshot));
            if (ctx->newDataFlag != nullptr) {
                *(ctx->newDataFlag) = true;
            }
            xSemaphoreGive(ctx->snapshotMutex);
        }

        vTaskDelay(pdMS_TO_TICKS(5));
    }
}
