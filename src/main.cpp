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
    if (s_snapshot_mutex == nullptr) {
        Serial.println("{\"error\":\"Failed to create snapshot mutex\"}");
        return;
    }

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

static void handleSerialCommand(const char *cmd) {
    if (strncmp(cmd, "TUNE ", 5) == 0) {
        float f = atof(cmd + 5);
        if (f >= GHOSTWAVE_FM_FREQ_START && f <= (GHOSTWAVE_FM_FREQ_START + GHOSTWAVE_FM_FREQ_SPAN)) {
            rf_scanner_tune(f);
        }
    } else if (strcmp(cmd, "SWEEP") == 0) {
        rf_scanner_set_mode(OP_MODE_SWEEP);
    } else if (strncmp(cmd, "MUTE ", 5) == 0) {
        bool m = (cmd[5] == '1');
        rf_scanner_set_mute(m);
    } else if (strncmp(cmd, "MONO ", 5) == 0) {
        bool m = (cmd[5] == '1');
        rf_scanner_set_mono(m);
    } else if (strcmp(cmd, "SEEK_UP") == 0) {
        rf_scanner_seek(true);
    } else if (strcmp(cmd, "SEEK_DOWN") == 0) {
        rf_scanner_seek(false);
    } else if (strcmp(cmd, "BUG_HUNTER") == 0) {
        rf_scanner_set_mode(OP_MODE_BUG_HUNTER);
    } else if (strncmp(cmd, "BUG_SENS ", 9) == 0) {
        uint8_t s = static_cast<uint8_t>(atoi(cmd + 9));
        if (s >= 3 && s <= 15) {
            rf_scanner_set_bug_sensitivity(s);
        }
    }
}

void loop() {
    static char cmdBuf[32];
    static size_t cmdLen = 0;

    while (Serial.available()) {
        char c = static_cast<char>(Serial.read());
        if (c == '\n' || c == '\r') {
            if (cmdLen > 0) {
                cmdBuf[cmdLen] = '\0';
                handleSerialCommand(cmdBuf);
                cmdLen = 0;
            }
        } else if (cmdLen < sizeof(cmdBuf) - 1) {
            cmdBuf[cmdLen++] = c;
        }
    }

    vTaskDelay(pdMS_TO_TICKS(20));
}
