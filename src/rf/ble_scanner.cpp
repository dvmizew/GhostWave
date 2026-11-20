/**
 * @file ble_scanner.cpp
 * @brief NimBLE Active Scanner & Zero-Heap AD Parser
 */

#include "rf/ble_scanner.h"
#include <Arduino.h>
#include <NimBLEDevice.h>
#include <freertos/FreeRTOS.h>
#include <string.h>

static portMUX_TYPE s_ble_mux = portMUX_INITIALIZER_UNLOCKED;

static volatile int8_t  s_ble_max_rssi_temp = -128;
static BleDeviceRecord  s_discovered_ble_temp[MAX_DISCOVERED_BLE];
static uint8_t          s_discovered_count_temp = 0;

static inline bool isPriorityBleService(uint16_t uuid) {
    return uuid == 0xFD5A || // Samsung SmartTag / SmartThings Find
           uuid == 0xFEED || // Tile Tracker
           uuid == 0xFE2C || // Google Fast Pair
           uuid == 0xFEAA || // Eddystone
           uuid == 0xFCB2 || // Apple Find My / DULT
           uuid == 0xFD44 || // Apple Find My
           uuid == 0xFE95 || // Xiaomi MiBeacon
           uuid == 0xFCD2;   // BTHome
}

static void parseBleAdvSlice(const uint8_t *data, size_t len, BleDeviceRecord &rec,
                             bool &hasCompleteName, bool &hasPrioritySvc) {
    size_t pos = 0;

    while (pos + 1 < len) {
        uint8_t fieldLen = data[pos];
        if (fieldLen == 0 || pos + 1 + fieldLen > len) {
            break;
        }
        uint8_t fieldType = data[pos + 1];
        const uint8_t *val = data + pos + 2;
        uint8_t valLen = fieldLen - 1;

        if (fieldType == 0x01 && valLen >= 1) { // AD Flags
            if ((val[0] & 0x04) == 0) { // Bit 2 = BR/EDR Not Supported
                rec.flags |= BLE_FLAG_DUAL_MODE;
            }
        } else if ((fieldType == 0x09 || (fieldType == 0x08 && !hasCompleteName)) && valLen > 0) {
            size_t copyLen = (valLen < sizeof(rec.name) - 1) ? valLen : (sizeof(rec.name) - 1);
            size_t outLen = 0;
            for (size_t i = 0; i < copyLen; i++) {
                char c = static_cast<char>(val[i]);
                if (c >= 32 && c <= 126 && c != '"' && c != '\\') {
                    rec.name[outLen++] = c;
                }
            }
            while (outLen > 0 && rec.name[outLen - 1] == ' ') outLen--;
            rec.name[outLen] = '\0';
            if (fieldType == 0x09 && outLen > 0) hasCompleteName = true;
        } else if (fieldType == 0x0A && valLen >= 1) { // TX Power Level
            rec.txPower = static_cast<int8_t>(val[0]);
            rec.flags |= BLE_FLAG_HAS_TXPOWER;
        } else if (fieldType == 0x19 && valLen >= 2) { // GAP Appearance
            rec.appearance = static_cast<uint16_t>(val[0]) | (static_cast<uint16_t>(val[1]) << 8);
        } else if ((fieldType == 0x02 || fieldType == 0x03) && valLen >= 2) { // 16-bit Service UUID list
            for (uint8_t i = 0; i + 1 < valLen; i += 2) {
                uint16_t uuid = static_cast<uint16_t>(val[i]) | (static_cast<uint16_t>(val[i + 1]) << 8);
                if (uuid == 0) continue;
                if (isPriorityBleService(uuid)) {
                    rec.serviceUuid = uuid;
                    hasPrioritySvc = true;
                    break;
                }
                if (rec.serviceUuid == 0) rec.serviceUuid = uuid;
            }
        } else if (fieldType == 0x16 && valLen >= 2) { // Service Data - 16-bit UUID
            uint16_t uuid = static_cast<uint16_t>(val[0]) | (static_cast<uint16_t>(val[1]) << 8);
            if (uuid != 0 && (!hasPrioritySvc || isPriorityBleService(uuid))) {
                if (isPriorityBleService(uuid)) {
                    rec.serviceUuid = uuid;
                    hasPrioritySvc = true;
                } else if (rec.serviceUuid == 0) {
                    rec.serviceUuid = uuid;
                }
            }
        } else if (fieldType == 0xFF && valLen >= 2) { // Manufacturer Specific Data
            rec.companyId = static_cast<uint16_t>(val[0]) | (static_cast<uint16_t>(val[1]) << 8);
            rec.flags |= BLE_FLAG_HAS_MFG;
            rec.mfgSubtype = (valLen >= 3) ? val[2] : 0;
        }

        pos += 1 + fieldLen;
    }
}

static void parseBleAdvPayload(const uint8_t *data, size_t len, size_t advLen, BleDeviceRecord &rec) {
    bool hasCompleteName = false;
    bool hasPrioritySvc = false;
    size_t firstLen = (advLen > 0 && advLen < len) ? advLen : len;
    parseBleAdvSlice(data, firstLen, rec, hasCompleteName, hasPrioritySvc);
    if (firstLen < len) {
        parseBleAdvSlice(data + firstLen, len - firstLen, rec, hasCompleteName, hasPrioritySvc);
    }
}

class GhostWaveBLECallbacks : public NimBLEScanCallbacks {
    void onResult(const NimBLEAdvertisedDevice *advertisedDevice) override {
        if (advertisedDevice == nullptr) {
            return;
        }

        BleDeviceRecord parsed;
        memset(&parsed, 0, sizeof(parsed));
        parsed.rssi = advertisedDevice->getRSSI();

        const NimBLEAddress addr = advertisedDevice->getAddress();
        const uint8_t *val = addr.getVal();
        for (uint8_t i = 0; i < 6; i++) {
            parsed.addr[i] = val[5 - i]; // Convert LE controller bytes to MSB-first display order
        }

        if (addr.isPublic()) {
            parsed.addrType = 0;
        } else if (addr.isStatic()) {
            parsed.addrType = 1;
        } else if (addr.isRpa()) {
            parsed.addrType = 2;
        } else {
            parsed.addrType = 3;
        }

        if (advertisedDevice->isConnectable()) {
            parsed.flags |= BLE_FLAG_CONNECTABLE;
        }

        const std::vector<uint8_t> &payload = advertisedDevice->getPayload();
        if (!payload.empty()) {
            parseBleAdvPayload(payload.data(), payload.size(), advertisedDevice->getAdvLength(), parsed);
        }

        portENTER_CRITICAL(&s_ble_mux);
        if (parsed.rssi > s_ble_max_rssi_temp) {
            s_ble_max_rssi_temp = parsed.rssi;
        }

        int8_t matchIdx = -1;
        for (uint8_t i = 0; i < s_discovered_count_temp; i++) {
            if (memcmp(s_discovered_ble_temp[i].addr, parsed.addr, 6) == 0) {
                matchIdx = static_cast<int8_t>(i);
                break;
            }
        }

        if (matchIdx >= 0) {
            BleDeviceRecord &dst = s_discovered_ble_temp[matchIdx];
            dst.rssi = parsed.rssi;
            dst.addrType = parsed.addrType;
            dst.flags |= parsed.flags;
            if (parsed.name[0] != '\0') {
                strncpy(dst.name, parsed.name, sizeof(dst.name) - 1);
                dst.name[sizeof(dst.name) - 1] = '\0';
            }
            if (parsed.flags & BLE_FLAG_HAS_TXPOWER) dst.txPower = parsed.txPower;
            if (parsed.flags & BLE_FLAG_HAS_MFG) {
                dst.companyId = parsed.companyId;
                dst.mfgSubtype = parsed.mfgSubtype;
            }
            if (parsed.serviceUuid != 0 && (dst.serviceUuid == 0 || isPriorityBleService(parsed.serviceUuid))) {
                dst.serviceUuid = parsed.serviceUuid;
            }
            if (parsed.appearance != 0) dst.appearance = parsed.appearance;
        } else if (s_discovered_count_temp < MAX_DISCOVERED_BLE) {
            s_discovered_ble_temp[s_discovered_count_temp++] = parsed;
        } else {
            // Evict weakest-RSSI slot when new device is stronger
            uint8_t weakIdx = 0;
            int8_t weakRssi = s_discovered_ble_temp[0].rssi;
            for (uint8_t i = 1; i < MAX_DISCOVERED_BLE; i++) {
                if (s_discovered_ble_temp[i].rssi < weakRssi) {
                    weakRssi = s_discovered_ble_temp[i].rssi;
                    weakIdx = i;
                }
            }
            if (parsed.rssi > weakRssi) {
                s_discovered_ble_temp[weakIdx] = parsed;
            }
        }
        portEXIT_CRITICAL(&s_ble_mux);
    }
};

static GhostWaveBLECallbacks s_ble_callbacks;

void BleScanner::init() {
    NimBLEDevice::init("");
    NimBLEScan *pBLEScan = NimBLEDevice::getScan();
    pBLEScan->setScanCallbacks(&s_ble_callbacks, false);
    pBLEScan->setActiveScan(true);
    pBLEScan->setInterval(40);
    pBLEScan->setWindow(40);
    pBLEScan->setMaxResults(0);
}

void BleScanner::scan(uint32_t windowMs, uint16_t &outDevices, int8_t &outMaxRssi,
                      BleDeviceRecord *outBleList, uint8_t *outBleCount) {
    portENTER_CRITICAL(&s_ble_mux);
    s_ble_max_rssi_temp = -128;
    s_discovered_count_temp = 0;
    portEXIT_CRITICAL(&s_ble_mux);

    NimBLEScan *pBLEScan = NimBLEDevice::getScan();
    if (pBLEScan->isScanning()) {
        pBLEScan->stop();
    }
    // Non-blocking start + bounded wait (avoids NimBLEScan::getResults BLE_NPL_TIME_FOREVER deadlock under Wi-Fi coex)
    if (pBLEScan->start(windowMs, false)) {
        vTaskDelay(pdMS_TO_TICKS(windowMs + 25));
        if (pBLEScan->isScanning()) {
            pBLEScan->stop();
        }
    }

    portENTER_CRITICAL(&s_ble_mux);
    outDevices = s_discovered_count_temp;
    outMaxRssi = s_ble_max_rssi_temp;
    if (outBleCount != nullptr) {
        *outBleCount = s_discovered_count_temp;
    }
    if (outBleList != nullptr && s_discovered_count_temp > 0) {
        memcpy(outBleList, s_discovered_ble_temp, sizeof(BleDeviceRecord) * s_discovered_count_temp);
    }
    portEXIT_CRITICAL(&s_ble_mux);
}
