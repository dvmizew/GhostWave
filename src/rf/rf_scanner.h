/**
 * @file rf_scanner.h
 * @brief Core 1 RF Scanner Task
 *
 */

#ifndef GHOSTWAVE_RF_RF_SCANNER_H
#define GHOSTWAVE_RF_RF_SCANNER_H

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include "types.h"

struct RFScannerContext {
    SemaphoreHandle_t snapshotMutex;
    SpectrumSnapshot *sharedSnapshot;
    volatile bool    *newDataFlag;
};

/**
 * @brief Initializes RF peripherals and spawns Core 1 scanner task.
 * @param snapshotMutex FreeRTOS mutex protecting shared snapshot
 * @param sharedSnapshot Pointer to shared snapshot double buffer
 * @param newDataFlag Pointer to fresh data flag
 * @return BaseType_t pdPASS if created successfully
 */
BaseType_t rf_scanner_start(SemaphoreHandle_t snapshotMutex, SpectrumSnapshot *sharedSnapshot, volatile bool *newDataFlag);

/**
 * @brief Core 1 task loop.
 * @param param Pointer to RFScannerContext
 */
void Task_RF_Scanner(void *param);

#endif // GHOSTWAVE_RF_RF_SCANNER_H
