# GhostWave

ESP32 RF spectrum analyzer and protocol sniffer. Sweeps the FM broadcast band (87.5–108.0 MHz) via a TEA5767 tuner, sniffs 802.11 b/g/n Wi-Fi traffic and beacon frames, and captures Bluetooth LE advertisements. Streams formatted JSON telemetry over serial at 921600 baud to a WebSerial dashboard.

Firmware is written in C++ for FreeRTOS with static memory allocation and zero heap usage in the hot loop.

---

## Hardware & Wiring

Requires an ESP32-WROOM-32 development board and a TEA5767 FM tuner module.

| TEA5767 Pin | ESP32 Pin | Bus / Function | Notes |
| :--- | :--- | :--- | :--- |
| **VCC** | **3V3** or **5V** | Power | Use 5V if module has onboard 3.3V LDO |
| **GND** | **GND** | Ground | Common ground |
| **SDA** | **GPIO 27** | I2C1 Data (`Wire1`) | Bidirectional pin with pull-up |
| **SCL** | **GPIO 26** | I2C1 Clock (`Wire1`) | Bidirectional pin with pull-up |


---

## Firmware Build & Flash

Built using PlatformIO.

```bash
# Build firmware
pio run

# Flash to connected ESP32
pio run -t upload

# Monitor serial output (921600 baud)
pio device monitor -b 921600
```

---

## WebSerial Dashboard

The dashboard is a self-contained web app located at `dashboard/index.html`. It uses the Web Serial API (supported on Chrome, Edge, Brave, and Opera).

1. Open `dashboard/index.html` in your browser.
2. Select **921600 Baud**.
3. Click **Connect** and select the serial port for your ESP32.

### Dashboard Views
- **Radio (FM):** 64-bin spectrum trace (87.5–108.0 MHz), waterfall spectrogram, and detected carrier peak list.
- **Wi-Fi:** 2.4 GHz channel density histogram (Channels 1–13) and table of discovered APs (SSID, BSSID, Channel, RSSI dBm).
- **Bluetooth LE:** Proximity radar categories (<1m, 1–3m, >3m) and table of discovered BLE devices with signal strength.

---

## Serial Telemetry Format

Each sweep cycle (~550 ms) outputs a single-line JSON string followed by `\n`:

```json
{
  "node": "ghostwave",
  "seq": 142,
  "uptime_ms": 78200,
  "sweep_ms": 568,
  "ble_devs": 4,
  "ble_rssi": -62,
  "fm": [1, 2, 4, 12, 11, 3, 1, 0, 0],
  "wifi_pkts": [18, 4, 0, 0, 2, 42, 5, 0, 1, 0, 31, 0, 0],
  "wifi_rssi": [-68, -82, -128, -128, -89, -52, -76, -128, -85, -128, -58, -128, -128],
  "aps": [
    {"ssid": "Office_5G", "bssid": "64:70:02:ab:cd:ef", "ch": 6, "rssi": -52}
  ],
  "bles": [
    {"name": "SmartBand", "addr": "e4:5f:01:44:55:66", "rssi": -64}
  ]
}
```

### Fields
- `seq`: Monotonic sweep counter.
- `sweep_ms`: Elapsed time for the full cycle (FM + Wi-Fi dwell + BLE window).
- `fm`: Array of 64 signal levels (0–15) mapped from 87.5 to 108.0 MHz.
- `wifi_pkts`: Management and data packet counts per channel (1 to 13).
- `wifi_rssi`: Peak RSSI in dBm per channel (-128 if no traffic observed).
- `aps`: Discovered 802.11 beacon access points.
- `bles`: Discovered BLE advertisers.

---

## Troubleshooting

- **Port Busy / Access Denied:** Close any active terminal serial monitors (`pio device monitor`, screen, PuTTY) before clicking Connect in the browser.
- **Linux Serial Permissions:** If the browser cannot open `/dev/ttyUSB0`, grant dialout permissions:
  ```bash
  sudo usermod -a -G dialout $USER
  ```
  Then log out and log back in.
- **Flat FM Spectrum (All Zeros):** Check that SDA/SCL are wired to GPIO 27 and 26, and ensure an antenna or wire is plugged into the TEA5767 3.5mm jack.
