# GhostWave

ESP32 RF spectrum analyzer and protocol sniffer. Sweeps the FM broadcast band (76.0–108.0 MHz) via a TEA5767 tuner, sniffs 802.11 b/g/n Wi-Fi traffic and beacon frames, and captures Bluetooth LE advertisements. Streams formatted JSON telemetry over serial at 921600 baud to a WebSerial dashboard.

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
- **Radio (FM):** 128-bin spectrum trace (76.0–108.0 MHz, 250 kHz resolution), waterfall spectrogram, detected carrier peak list, and an **Interactive FM Tuner** (allows direct listening via the 3.5mm headphone jack, slider tuning, hardware seek, mute, and mono toggles).
- **Wi-Fi:** 2.4 GHz channel density histogram (Channels 1–13) and table of discovered APs (SSID, BSSID, Channel, RSSI dBm).
- **Bluetooth LE:** Proximity radar categories (<1m, 1–3m, >3m) and table of discovered BLE devices with signal strength.

### Interactive Serial Commands
You can control GhostWave in real time from the dashboard UI or via serial terminal:
- `TUNE <freq>` — Tune to a specific frequency (e.g. `TUNE 98.3`), unmute audio, and enter live listen mode.
- `SWEEP` — Resume continuous RF spectrum analyzer sweep mode.
- `BUG_HUNTER` — Enter dedicated RF Bug Hunter mode (detects clandestine near-field analog surveillance transmitters).
- `BUG_SENS <val>` — Set bug detection sensitivity threshold (signal level 3–15, default: 7).
- `MUTE <1|0>` — Mute or unmute audio output on the 3.5mm jack.
- `MONO <1|0>` — Force mono (reduces noise on weak signals) or auto-stereo.
- `SEEK_UP` / `SEEK_DOWN` — Hardware autonomous search for next station.

---

## RF Bug Hunter Mode
The Bug Hunter mode is physically separated from normal Spectrum Sweep and Live Tuner modes to prevent operational confusion and avoid RF self-interference from ESP32 2.4 GHz transmissions:
- Fast 128-bin sweep dedicated strictly to surveillance frequencies (76.0–108.0 MHz).
- Dynamic RF ambient noise floor calculation.
- Discriminates near-field analog bugs: surveillance transmitters use raw analog FM without 19 kHz stereo multiplexers (strictly `mono`), saturate the near field ($>1/r^2$), and spike significantly above ambient noise.
- Automated Threat Level Assessment:
  - **Level 0 (ALL CLEAR)**: Ambient noise only.
  - **Level 1 (ELEVATED)**: Suspicious mono carrier detected above threshold.
  - **Level 2 (CRITICAL ALERT)**: Near-field saturating transmitter detected ($Level \ge 11$).
- One-click **Listen / Verify** feature to instantly tune and listen into the carrier through headphones.

---

## Serial Telemetry Format

Each sweep cycle (~550 ms) outputs a single-line JSON string followed by `\n`:

```json
{
  "node": "ghostwave",
  "seq": 142,
  "uptime_ms": 78200,
  "sweep_ms": 568,
  "tea_err": 0,
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
  ],
  "stations": [
    {"freq": 98.3, "lev": 12, "stereo": true, "if_cnt": 55, "if_lock": true}
  ]
}
```

### Fields
- `seq`: Monotonic sweep counter.
- `sweep_ms`: Elapsed time for the full cycle (FM + Wi-Fi dwell + BLE window).
- `tea_err`: TEA5767 I2C status code (`0` = OK, `2` = I2C NACK, `5` = Read error).
- `fm`: Array of 128 signal levels (0–15) mapped from 76.0 to 108.0 MHz (Fine Scan).
- `wifi_pkts`: Management and data packet counts per channel (1 to 13).
- `wifi_rssi`: Peak RSSI in dBm per channel (-128 if no traffic observed).
- `aps`: Discovered 802.11 beacon access points.
- `bles`: Discovered BLE advertisers.
- `stations`: Active FM carrier peaks with hardware stereo flag (`stereo`), 7-bit IF counter (`if_cnt`), and 225 kHz intermediate frequency lock status (`if_lock`).

---

## Troubleshooting

- **Port Busy / Access Denied:** Close any active terminal serial monitors (`pio device monitor`, screen, PuTTY) before clicking Connect in the browser.
- **Linux Serial Permissions:** If the browser cannot open `/dev/ttyUSB0`, grant dialout permissions:
  ```bash
  sudo usermod -a -G dialout $USER
  ```
  Then log out and log back in.
- **Flat FM Spectrum (All Zeros):** Check that SDA/SCL are wired to GPIO 27 and 26, and ensure an antenna or wire is plugged into the TEA5767 3.5mm jack.
