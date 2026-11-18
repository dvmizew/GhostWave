/**
 * @file display.cpp
 * @brief U8g2 SSD1306 Rendering Routines Implementation
 */

#include "drivers/display.h"
#include <stdio.h>

DisplayDriver::DisplayDriver()
    : m_u8g2(U8G2_R0, /* reset= */ U8X8_PIN_NONE, OLED_SCL_PIN, OLED_SDA_PIN) {
}

void DisplayDriver::init() {
    m_u8g2.begin();
    m_u8g2.setBusClock(I2C_STANDARD_CLOCK);
}

void DisplayDriver::clear() {
    m_u8g2.clearBuffer();
}

void DisplayDriver::renderFmView(const SpectrumSnapshot &snapshot) {
    uint8_t peakBin = 0;
    uint8_t peakRssi = 0;
    for (uint8_t i = 0; i < GHOSTWAVE_FM_BINS; i++) {
        if (snapshot.fmRssi[i] > peakRssi) {
            peakRssi = snapshot.fmRssi[i];
            peakBin = i;
        }
    }

    m_u8g2.setFont(u8g2_font_5x7_tr);
    m_u8g2.drawStr(0, 7, "GHOSTWAVE FM-DX");

    if (peakRssi > 0) {
        char peakStr[16];
        float peakFreq = GHOSTWAVE_FM_FREQ_START +
            (static_cast<float>(peakBin) * (GHOSTWAVE_FM_FREQ_SPAN / static_cast<float>(GHOSTWAVE_FM_BINS - 1)));
        snprintf(peakStr, sizeof(peakStr), "%5.1fM:%02u", peakFreq, peakRssi);
        m_u8g2.drawStr(72, 7, peakStr);
    } else {
        m_u8g2.drawStr(80, 7, "SCANNING");
    }

    m_u8g2.drawHLine(0, 9, 128);

    const int graphBaseY = 54;
    const int maxBarH = 42;

    for (int i = 0; i < GHOSTWAVE_FM_BINS; i++) {
        int barH = (snapshot.fmRssi[i] * maxBarH) / 15;
        if (barH > 0) {
            m_u8g2.drawVLine(i * 2, graphBaseY - barH, barH);
            m_u8g2.drawVLine(i * 2 + 1, graphBaseY - barH, barH);
        }
    }

    // Peak marker indicator
    if (peakRssi > 0) {
        int peakX = peakBin * 2;
        int peakY = graphBaseY - ((peakRssi * maxBarH) / 15) - 3;
        if (peakY < 11) {
            peakY = 11;
        }
        m_u8g2.drawBox(peakX, peakY, 2, 2);
    }

    m_u8g2.drawHLine(0, 55, 128);
    m_u8g2.drawStr(0, 64, "87.5");
    m_u8g2.drawStr(56, 64, "98.0");
    m_u8g2.drawStr(103, 64, "108.0");
}

void DisplayDriver::renderWifiView(const SpectrumSnapshot &snapshot) {
    m_u8g2.setFont(u8g2_font_5x7_tr);
    char bleHdr[24];
    snprintf(bleHdr, sizeof(bleHdr), "2.4G CH1-13|BLE:%u", snapshot.bleDevices);
    m_u8g2.drawStr(0, 7, bleHdr);
    m_u8g2.drawHLine(0, 9, 128);

    const int barWidth = 6;
    const int barStartX = 6;
    const int barSpacing = 9;
    const int maxWifiH = 40;
    const int wifiBaseY = 52;

    for (int ch = 0; ch < GHOSTWAVE_WIFI_CHANNELS; ch++) {
        int x = barStartX + (ch * barSpacing);

        uint16_t pkts = snapshot.wifiPkts[ch];
        int barH = (pkts > 100) ? maxWifiH : ((pkts * maxWifiH) / 100);

        if (barH > 0) {
            m_u8g2.drawBox(x, wifiBaseY - barH, barWidth, barH);
        } else {
            m_u8g2.drawHLine(x, wifiBaseY, barWidth);
        }

        // Highlight primary non-overlapping channels (1, 6, 11)
        if (ch == 0 || ch == 5 || ch == 10) {
            m_u8g2.drawPixel(x + 2, wifiBaseY - maxWifiH - 2);
        }
    }

    m_u8g2.drawHLine(0, 54, 128);
    m_u8g2.drawStr(7, 63, "1");
    m_u8g2.drawStr(52, 63, "6");
    m_u8g2.drawStr(97, 63, "11");
    m_u8g2.drawStr(115, 63, "13");
}

void DisplayDriver::render(const SpectrumSnapshot &snapshot, DisplayMode mode) {
    if (mode == DisplayMode::FM_SPECTRUM) {
        renderFmView(snapshot);
    } else {
        renderWifiView(snapshot);
    }
}

void DisplayDriver::sendBuffer() {
    m_u8g2.sendBuffer();
}
