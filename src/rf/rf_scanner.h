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

#endif // GHOSTWAVE_RF_RF_SCANNER_H
