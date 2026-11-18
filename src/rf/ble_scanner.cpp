/**
 * @file ble_scanner.cpp
 * @brief NimBLE Passive Scanner
 */

#include "rf/ble_scanner.h"
#include <Arduino.h>
#include <NimBLEDevice.h>
#include <freertos/FreeRTOS.h>
#include <string.h>

static portMUX_TYPE s_ble_mux = portMUX_INITIALIZER_UNLOCKED;

static volatile uint16_t s_ble_devices_temp = 0;
static volatile int8_t   s_ble_max_rssi_temp = -128;

static BleDeviceRecord s_discovered_ble_temp[MAX_DISCOVERED_BLE];
static uint8_t         s_discovered_count_temp = 0;

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

        std::string addrStr = advertisedDevice->getAddress().toString();
        bool found = false;
        for (uint8_t i = 0; i < s_discovered_count_temp; i++) {
            if (strncmp(s_discovered_ble_temp[i].addr, addrStr.c_str(), sizeof(s_discovered_ble_temp[0].addr)) == 0) {
                found = true;
                s_discovered_ble_temp[i].rssi = rssi;
                break;
            }
        }
        if (!found && s_discovered_count_temp < MAX_DISCOVERED_BLE) {
            BleDeviceRecord &rec = s_discovered_ble_temp[s_discovered_count_temp];
            strncpy(rec.addr, addrStr.c_str(), sizeof(rec.addr) - 1);
            rec.addr[sizeof(rec.addr) - 1] = '\0';

            std::string nameStr = advertisedDevice->getName();
            if (nameStr.empty()) {
                strncpy(rec.name, "[BLE Beacon]", sizeof(rec.name) - 1);
            } else {
                strncpy(rec.name, nameStr.c_str(), sizeof(rec.name) - 1);
            }
            rec.name[sizeof(rec.name) - 1] = '\0';
            rec.rssi = rssi;
            s_discovered_count_temp++;
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
    pBLEScan->setMaxResults(0);
}

void BleScanner::scan(uint32_t windowMs, uint16_t &outDevices, int8_t &outMaxRssi,
                      BleDeviceRecord *outBleList, uint8_t *outBleCount) {
    portENTER_CRITICAL(&s_ble_mux);
    s_ble_devices_temp = 0;
    s_ble_max_rssi_temp = -128;
    s_discovered_count_temp = 0;
    portEXIT_CRITICAL(&s_ble_mux);

    NimBLEScan *pBLEScan = NimBLEDevice::getScan();
    pBLEScan->getResults(windowMs, false);

    portENTER_CRITICAL(&s_ble_mux);
    outDevices = s_ble_devices_temp;
    outMaxRssi = s_ble_max_rssi_temp;
    if (outBleCount != nullptr) {
        *outBleCount = s_discovered_count_temp;
    }
    if (outBleList != nullptr && s_discovered_count_temp > 0) {
        memcpy(outBleList, s_discovered_ble_temp, sizeof(BleDeviceRecord) * s_discovered_count_temp);
    }
    portEXIT_CRITICAL(&s_ble_mux);
}
