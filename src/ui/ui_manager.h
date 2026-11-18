/**
 * @file ui_manager.h
 * @brief Core 0 UI and Telemetry Orchestrator Task
 *
 * Drives SSD1306 OLED rendering at ~30 FPS, debounces the view toggle button,
 * and streams JSON telemetry over USB Serial at 921600 baud.
 */

#ifndef GHOSTWAVE_UI_UI_MANAGER_H
#define GHOSTWAVE_UI_UI_MANAGER_H

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include "types.h"

struct UIManagerContext {
    SemaphoreHandle_t snapshotMutex;
    SpectrumSnapshot *sharedSnapshot;
    volatile bool    *newDataFlag;
};

/**
 * @brief Initializes UI subsystem and spawns Core 0 task.
 * @param snapshotMutex FreeRTOS mutex protecting shared snapshot
 * @param sharedSnapshot Pointer to shared snapshot double buffer
 * @param newDataFlag Pointer to fresh data flag
 * @return BaseType_t pdPASS if created successfully
 */
BaseType_t ui_manager_start(SemaphoreHandle_t snapshotMutex, SpectrumSnapshot *sharedSnapshot, volatile bool *newDataFlag);

/**
 * @brief Core 0 task loop.
 * @param param Pointer to UIManagerContext
 */
void Task_UI_And_Telemetry(void *param);

#endif // GHOSTWAVE_UI_UI_MANAGER_H
