/**
 * @file ui_manager.cpp
 * @brief Core 0 UI and Telemetry Orchestrator Implementation
 */

#include "ui/ui_manager.h"
#include "drivers/display.h"
#include "telemetry/telemetry.h"
#include <Arduino.h>
#include <string.h>

static UIManagerContext s_ui_ctx;
static DisplayDriver    s_display;

BaseType_t ui_manager_start(SemaphoreHandle_t snapshotMutex, SpectrumSnapshot *sharedSnapshot, volatile bool *newDataFlag) {
    s_ui_ctx.snapshotMutex = snapshotMutex;
    s_ui_ctx.sharedSnapshot = sharedSnapshot;
    s_ui_ctx.newDataFlag = newDataFlag;

    return xTaskCreatePinnedToCore(
        Task_UI_And_Telemetry,
        "GW_UI_Telem",
        UI_TASK_STACK_SIZE,
        &s_ui_ctx,
        UI_TASK_PRIORITY,
        nullptr,
        UI_TASK_CORE
    );
}

void Task_UI_And_Telemetry(void *param) {
    UIManagerContext *ctx = static_cast<UIManagerContext *>(param);
    static SpectrumSnapshot localSnapshot;
    DisplayMode currentMode = DisplayMode::FM_SPECTRUM;
    int lastBtnState = HIGH;
    uint32_t lastDebounceMs = 0;

    s_display.init();

    while (true) {
        // Handle mode toggle button with debouncing
        int btn = digitalRead(BTN_MODE_PIN);
        if (btn == LOW && lastBtnState == HIGH && (millis() - lastDebounceMs > BTN_DEBOUNCE_MS)) {
            currentMode = (currentMode == DisplayMode::FM_SPECTRUM)
                ? DisplayMode::WIFI_BLE_HISTOGRAM
                : DisplayMode::FM_SPECTRUM;
            lastDebounceMs = millis();
        }
        lastBtnState = btn;

        // Fetch latest RF snapshot safely
        bool freshData = false;
        if (ctx != nullptr && ctx->snapshotMutex != nullptr &&
            xSemaphoreTake(ctx->snapshotMutex, pdMS_TO_TICKS(5)) == pdTRUE) {
            memcpy(&localSnapshot, ctx->sharedSnapshot, sizeof(SpectrumSnapshot));
            if (ctx->newDataFlag != nullptr) {
                freshData = *(ctx->newDataFlag);
                *(ctx->newDataFlag) = false;
            }
            xSemaphoreGive(ctx->snapshotMutex);
        }

        // 1. STREAM TELEMETRY TO SERIAL (921600 Baud JSON)
        if (freshData) {
            Telemetry::streamJson(Serial, localSnapshot);
        }

        // 2. RENDER ACTIVE VIEW ON SSD1306 (U8g2 Full Buffer)
        s_display.clear();
        s_display.render(localSnapshot, currentMode);
        s_display.sendBuffer();

        // Target ~30 FPS refresh rate
        vTaskDelay(pdMS_TO_TICKS(UI_REFRESH_INTERVAL_MS));
    }
}
