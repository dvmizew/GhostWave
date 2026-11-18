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

static void extractBleName(const NimBLEAdvertisedDevice *dev, char *outName, size_t maxLen) {
    if (outName == nullptr || maxLen == 0) return;
    outName[0] = '\0';

    const std::vector<uint8_t> &payload = dev->getPayload();
    size_t len = payload.size();
    size_t pos = 0;

    while (pos + 1 < len) {
        uint8_t fieldLen = payload[pos];
        if (fieldLen == 0 || pos + 1 + fieldLen > len) {
            break;
        }
        uint8_t fieldType = payload[pos + 1];
        if (fieldType == 0x09 || fieldType == 0x08) { // Complete (0x09) or Shortened (0x08) Local Name
            uint8_t valLen = fieldLen - 1;
            uint8_t copyLen = (valLen < maxLen - 1) ? valLen : static_cast<uint8_t>(maxLen - 1);
            for (uint8_t i = 0; i < copyLen; i++) {
                char c = static_cast<char>(payload[pos + 2 + i]);
                outName[i] = (c >= 32 && c <= 126 && c != '"' && c != '\\') ? c : '?';
            }
            outName[copyLen] = '\0';
            return;
        }
        pos += 1 + fieldLen;
    }

    strncpy(outName, "[BLE Beacon]", maxLen - 1);
    outName[maxLen - 1] = '\0';
}

class GhostWaveBLECallbacks : public NimBLEScanCallbacks {
    void onDiscovered(const NimBLEAdvertisedDevice *advertisedDevice) override {
        if (advertisedDevice == nullptr) {
            return;
        }

        // Zero-heap attribute extraction using stack buffers
        int8_t rssi = static_cast<int8_t>(advertisedDevice->getRSSI());
        const uint8_t *val = advertisedDevice->getAddress().getVal();
        char addrBuf[18];
        snprintf(addrBuf, sizeof(addrBuf), "%02x:%02x:%02x:%02x:%02x:%02x",
                 val[5], val[4], val[3], val[2], val[1], val[0]);

        char nameBuf[sizeof(s_discovered_ble_temp[0].name)];
        extractBleName(advertisedDevice, nameBuf, sizeof(nameBuf));

        portENTER_CRITICAL(&s_ble_mux);
        s_ble_devices_temp = s_ble_devices_temp + 1;
        if (rssi > s_ble_max_rssi_temp) {
            s_ble_max_rssi_temp = rssi;
        }

        bool found = false;
        for (uint8_t i = 0; i < s_discovered_count_temp; i++) {
            if (strncmp(s_discovered_ble_temp[i].addr, addrBuf, sizeof(s_discovered_ble_temp[0].addr)) == 0) {
                found = true;
                s_discovered_ble_temp[i].rssi = rssi;
                break;
            }
        }
        if (!found && s_discovered_count_temp < MAX_DISCOVERED_BLE) {
            BleDeviceRecord &rec = s_discovered_ble_temp[s_discovered_count_temp];
            strncpy(rec.addr, addrBuf, sizeof(rec.addr) - 1);
            rec.addr[sizeof(rec.addr) - 1] = '\0';

            strncpy(rec.name, nameBuf, sizeof(rec.name) - 1);
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
    pBLEScan->setActiveScan(false);
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
