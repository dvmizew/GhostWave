/**
 * @file rf_scanner.cpp
 * @brief Core 1 RF Scanner Task Implementation
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

static volatile SystemOpMode s_current_mode   = OP_MODE_SWEEP;
static volatile float        s_req_tune_freq  = 0.0f;
static volatile bool         s_tune_pending   = false;
static volatile bool         s_seek_pending   = false;
static volatile bool         s_seek_direction = true;

void rf_scanner_set_mode(SystemOpMode mode) {
    s_current_mode = mode;
}

void rf_scanner_tune(float freqMHz) {
    s_req_tune_freq = freqMHz;
    s_tune_pending = true;
    s_current_mode = OP_MODE_TUNER;
}

void rf_scanner_set_mute(bool mute) {
    s_tea5767.setMute(mute);
}

void rf_scanner_set_mono(bool mono) {
    s_tea5767.setMono(mono);
}

void rf_scanner_seek(bool seekUp) {
    s_seek_direction = seekUp;
    s_seek_pending = true;
    s_current_mode = OP_MODE_TUNER;
}

static volatile uint8_t s_bug_sensitivity = 7;

void rf_scanner_set_bug_sensitivity(uint8_t minLevel) {
    s_bug_sensitivity = minLevel;
}

SystemOpMode rf_scanner_get_mode() {
    return s_current_mode;
}

BaseType_t rf_scanner_start(SemaphoreHandle_t snapshotMutex, SpectrumSnapshot *sharedSnapshot, TaskHandle_t notifyTaskHandle) {
    s_rf_ctx.snapshotMutex = snapshotMutex;
    s_rf_ctx.sharedSnapshot = sharedSnapshot;
    s_rf_ctx.notifyTaskHandle = notifyTaskHandle;

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
        if (s_tune_pending) {
            s_tea5767.tune(s_req_tune_freq, false, false);
            s_tune_pending = false;
        }

        if (s_seek_pending) {
            float found = 0.0f;
            s_tea5767.seek(s_seek_direction, found);
            s_seek_pending = false;
        }

        if (s_current_mode == OP_MODE_TUNER) {
            uint32_t tunerStartMs = millis();
            localSnapshot.seq = ++sequence;
            localSnapshot.timestampMs = tunerStartMs;
            localSnapshot.opMode = OP_MODE_TUNER;
            localSnapshot.tunerFreq = s_tea5767.getCurrentFrequency();

            FmReading r = s_tea5767.readCurrentStatus();
            localSnapshot.teaError = s_tea5767.getLastError();
            localSnapshot.tunerLevel = r.level;
            localSnapshot.tunerStereo = r.stereo;
            localSnapshot.tunerIfCount = r.ifCount;
            localSnapshot.tunerIfLock = r.validIf;
            localSnapshot.tunerMute = s_tea5767.isMuted();
            localSnapshot.tunerMono = s_tea5767.isMono();
            localSnapshot.sweepDurationMs = static_cast<uint16_t>(millis() - tunerStartMs);

            if (ctx != nullptr && ctx->snapshotMutex != nullptr &&
                xSemaphoreTake(ctx->snapshotMutex, pdMS_TO_TICKS(10)) == pdTRUE) {
                memcpy(ctx->sharedSnapshot, &localSnapshot, sizeof(SpectrumSnapshot));
                xSemaphoreGive(ctx->snapshotMutex);

                if (ctx->notifyTaskHandle != nullptr) {
                    xTaskNotifyGive(ctx->notifyTaskHandle);
                }
            }

            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        if (s_current_mode == OP_MODE_BUG_HUNTER) {
            uint32_t bugStartMs = millis();
            localSnapshot.seq = ++sequence;
            localSnapshot.timestampMs = bugStartMs;
            localSnapshot.opMode = OP_MODE_BUG_HUNTER;

            // 1. Fast sweep across entire 76.0 - 108.0 MHz band
            localSnapshot.stationCount = 0;
            s_tea5767.sweep(localSnapshot.fmRssi, localSnapshot.stationList,
                            &localSnapshot.stationCount, MAX_DISCOVERED_STATIONS);
            localSnapshot.teaError = s_tea5767.getLastError();

            // 2. Measure dynamic ambient RF noise floor
            uint8_t minLev = 15;
            uint32_t sumLev = 0;
            for (int i = 0; i < GHOSTWAVE_FM_BINS; i++) {
                uint8_t lev = localSnapshot.fmRssi[i];
                if (lev < minLev) minLev = lev;
                sumLev += lev;
            }
            uint8_t avgLev = static_cast<uint8_t>(sumLev / GHOSTWAVE_FM_BINS);
            uint8_t noiseFloor = (minLev + avgLev) / 2;
            localSnapshot.bugNoiseFloor = noiseFloor;

            // 3. Isolate suspect bug transmitters:
            // - Analog bugs are strictly MONO (no 19 kHz pilot multiplexer)
            // - Near-field signal spike: level >= s_bug_sensitivity AND delta >= 3 above noise
            uint8_t bugCount = 0;
            uint8_t maxThreat = 0;

            for (uint8_t i = 0; i < localSnapshot.stationCount && bugCount < MAX_BUG_TARGETS; i++) {
                const FmStationRecord &st = localSnapshot.stationList[i];
                if (!st.stereo && st.level >= s_bug_sensitivity && st.level >= (noiseFloor + 3)) {
                    uint8_t delta = static_cast<uint8_t>(st.level - noiseFloor);
                    localSnapshot.bugList[bugCount].freqMHz = st.freqMHz;
                    localSnapshot.bugList[bugCount].level = st.level;
                    localSnapshot.bugList[bugCount].deltaAboveNoise = delta;
                    localSnapshot.bugList[bugCount].ifCount = st.ifCount;
                    localSnapshot.bugList[bugCount].validIf = st.validIf;
                    bugCount++;

                    if (st.level >= 11) {
                        maxThreat = 2; // Critical: Proximity transmitter detected!
                    } else if (maxThreat < 1) {
                        maxThreat = 1; // Suspicious carrier
                    }
                }
            }

            localSnapshot.bugCount = bugCount;
            localSnapshot.bugThreatLevel = maxThreat;
            localSnapshot.sweepDurationMs = static_cast<uint16_t>(millis() - bugStartMs);

            if (ctx != nullptr && ctx->snapshotMutex != nullptr &&
                xSemaphoreTake(ctx->snapshotMutex, pdMS_TO_TICKS(10)) == pdTRUE) {
                memcpy(ctx->sharedSnapshot, &localSnapshot, sizeof(SpectrumSnapshot));
                xSemaphoreGive(ctx->snapshotMutex);

                if (ctx->notifyTaskHandle != nullptr) {
                    xTaskNotifyGive(ctx->notifyTaskHandle);
                }
            }

            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }

        // --- SPECTRUM SWEEP MODE ---
        uint32_t sweepStartMs = millis();
        localSnapshot.seq = ++sequence;
        localSnapshot.timestampMs = sweepStartMs;
        localSnapshot.opMode = OP_MODE_SWEEP;

        // 1. FAST FM BROADCAST SWEEP (87.5 - 108.0 MHz, 64 Bins on Wire1)
        localSnapshot.stationCount = 0;
        s_tea5767.sweep(localSnapshot.fmRssi, localSnapshot.stationList,
                        &localSnapshot.stationCount, MAX_DISCOVERED_STATIONS);
        localSnapshot.teaError = s_tea5767.getLastError();

        // 2. WI-FI PROMISCUOUS CHANNEL HOPPING (Channels 1 - 13)
        WifiSniffer::sweepChannels(localSnapshot.wifiPkts, localSnapshot.wifiMaxRssi,
                                   localSnapshot.apList, localSnapshot.apCount,
                                   WIFI_CHANNEL_DWELL_MS);

        // Brief delay between Wi-Fi and BLE on the shared 2.4 GHz RF transceiver
        vTaskDelay(pdMS_TO_TICKS(5));

        // 3. PASSIVE BLE SCAN WINDOW (NimBLE-Arduino)
        BleScanner::scan(BLE_SCAN_WINDOW_MS, localSnapshot.bleDevices, localSnapshot.bleMaxRssi,
                         localSnapshot.bleList, &localSnapshot.bleCount);

        localSnapshot.sweepDurationMs = static_cast<uint16_t>(millis() - sweepStartMs);

        // 4. ATOMIC SNAPSHOT TRANSFER & CORE 0 NOTIFICATION
        if (ctx != nullptr && ctx->snapshotMutex != nullptr &&
            xSemaphoreTake(ctx->snapshotMutex, pdMS_TO_TICKS(10)) == pdTRUE) {
            memcpy(ctx->sharedSnapshot, &localSnapshot, sizeof(SpectrumSnapshot));
            xSemaphoreGive(ctx->snapshotMutex);

            if (ctx->notifyTaskHandle != nullptr) {
                xTaskNotifyGive(ctx->notifyTaskHandle);
            }
        }

        vTaskDelay(pdMS_TO_TICKS(5));
    }
}
