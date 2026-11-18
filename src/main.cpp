#include <Arduino.h>
#include "config.h"
#include "types.h"
#include "rf/rf_scanner.h"
#include "telemetry/telemetry.h"

static SemaphoreHandle_t s_snapshot_mutex = nullptr;
static SpectrumSnapshot  s_shared_snapshot = {};
static TaskHandle_t      s_telemetry_task_handle = nullptr;

static void Task_Telemetry(void *param) {
    (void)param;
    static SpectrumSnapshot localSnapshot;

    while (true) {
        // Blocks indefinitely until Core 1 signals fresh telemetry
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);

        if (xSemaphoreTake(s_snapshot_mutex, pdMS_TO_TICKS(10)) == pdTRUE) {
            memcpy(&localSnapshot, &s_shared_snapshot, sizeof(SpectrumSnapshot));
            xSemaphoreGive(s_snapshot_mutex);

            Telemetry::streamJson(Serial, localSnapshot);
        }
    }
}

void setup() {
    Serial.begin(SERIAL_BAUD_RATE);

    s_snapshot_mutex = xSemaphoreCreateMutex();

    Serial.println("{\"status\":\"GhostWave Headless Online\",\"baud\":921600}");

    // Core 0: Telemetry task waits on notification from Core 1
    xTaskCreatePinnedToCore(
        Task_Telemetry,
        "GW_Telem",
        TELEMETRY_TASK_STACK_SIZE,
        nullptr,
        TELEMETRY_TASK_PRIORITY,
        &s_telemetry_task_handle,
        TELEMETRY_TASK_CORE
    );

    // Core 1: RF Scanner task performs sweeps and notifies Core 0
    rf_scanner_start(s_snapshot_mutex, &s_shared_snapshot, s_telemetry_task_handle);
}

void loop() {
    vTaskDelay(pdMS_TO_TICKS(5000));
}
