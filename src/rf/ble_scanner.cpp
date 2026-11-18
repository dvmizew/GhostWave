/**
 * @file ble_scanner.cpp
 * @brief NimBLE Passive Scanner
 */

#include "rf/ble_scanner.h"
#include <Arduino.h>
#include <NimBLEDevice.h>
#include <freertos/FreeRTOS.h>

static portMUX_TYPE s_ble_mux = portMUX_INITIALIZER_UNLOCKED;

static volatile uint16_t s_ble_devices_temp = 0;
static volatile int8_t   s_ble_max_rssi_temp = -128;

class GhostWaveBLECallbacks : public NimBLEScanCallbacks {
    void onDiscovered(const NimBLEAdvertisedDevice *advertisedDevice) override {
        if (advertisedDevice == nullptr) {
            return;
        }
        portENTER_CRITICAL(&s_ble_mux);
        s_ble_devices_temp = s_ble_devices_temp + 1;
        int8_t rssi = static_cast<int8_t>(advertisedDevice->getRSSI());
        if (rssi > s_ble_max_rssi_temp) {
            s_ble_max_rssi_temp = rssi;
        }
        portEXIT_CRITICAL(&s_ble_mux);
    }
};

static GhostWaveBLECallbacks s_ble_callbacks;

void BleScanner::init() {
    NimBLEDevice::init("");
    NimBLEScan *pBLEScan = NimBLEDevice::getScan();
    pBLEScan->setScanCallbacks(&s_ble_callbacks, false);
    pBLEScan->setActiveScan(false); // Passive scan
    pBLEScan->setMaxResults(0);     // Zero heap storage; event-driven only
}

void BleScanner::scan(uint32_t windowMs, uint16_t &outDevices, int8_t &outMaxRssi) {
    portENTER_CRITICAL(&s_ble_mux);
    s_ble_devices_temp = 0;
    s_ble_max_rssi_temp = -128;
    portEXIT_CRITICAL(&s_ble_mux);

    NimBLEScan *pBLEScan = NimBLEDevice::getScan();
    pBLEScan->getResults(windowMs, false);

    portENTER_CRITICAL(&s_ble_mux);
    outDevices = s_ble_devices_temp;
    outMaxRssi = s_ble_max_rssi_temp;
    portEXIT_CRITICAL(&s_ble_mux);
}
