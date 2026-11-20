#ifndef GHOSTWAVE_RF_RF_SCANNER_H
#define GHOSTWAVE_RF_RF_SCANNER_H

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#include "types.h"

struct RFScannerContext {
    SemaphoreHandle_t snapshotMutex;
    SpectrumSnapshot *sharedSnapshot;
    TaskHandle_t      notifyTaskHandle;
};

BaseType_t rf_scanner_start(SemaphoreHandle_t snapshotMutex, SpectrumSnapshot *sharedSnapshot, TaskHandle_t notifyTaskHandle);
void Task_RF_Scanner(void *param);

void         rf_scanner_set_mode(SystemOpMode mode);
void         rf_scanner_tune(float freqMHz);
void         rf_scanner_set_mute(bool mute);
void         rf_scanner_set_mono(bool mono);
void         rf_scanner_set_dsp(bool softMute, bool hcc, bool snc);
void         rf_scanner_set_fm_enabled(bool enabled);
void         rf_scanner_seek(bool seekUp);
void         rf_scanner_set_bug_sensitivity(uint8_t minLevel);
void         rf_scanner_set_wifi_lock(uint8_t channel);
SystemOpMode rf_scanner_get_mode();

#endif // GHOSTWAVE_RF_RF_SCANNER_H
