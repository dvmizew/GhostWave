# GhostWave

High-speed, zero-bloat RF Spectrum Analyzer & Protocol Sniffer for a single ESP32-WROOM-32.

- **FM Radio DXing:** 87.5 – 108.0 MHz (64 bins via Philips TEA5767 on Hardware I2C1).
- **Wi-Fi 2.4 GHz Congestion:** Channels 1 to 13 promiscuous sniffer with 802.11 Beacon frame parser (SSID, BSSID, Channel, RSSI).
- **Bluetooth LE Radar:** Passive advertising sniffer (NimBLE-Arduino) with proximity estimation.
- **WebSerial Dashboard:** Real-time 3-tab browser interface at 921600 baud with waterfall spectrogram and live sorting tables.

---

## Hardware Wiring (4 Wires Only)

| TEA5767 Pin | ESP32 Pin | Function |
| :--- | :--- | :--- |
| **VCC** | **3V3** (or 5V if board has onboard LDO) | Power |
| **GND** | **GND** | Common Ground |
| **SDA** | **GPIO 32** | Hardware I2C1 (`Wire1`) Data |
| **SCL** | **GPIO 33** | Hardware I2C1 (`Wire1`) Clock |

---

## Build & Flash (PlatformIO)

```bash
# Build firmware
pio run

# Flash to ESP32
pio run -t upload

# Open serial monitor
pio device monitor -b 921600
```

---

## WebSerial Dashboard

1. Open `dashboard/index.html` in Google Chrome, Microsoft Edge, or Opera.
2. Select **921600 Baud** and click **Connect**.
3. Pick your ESP32 serial port.
