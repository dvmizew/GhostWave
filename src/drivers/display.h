/**
 * @file display.h
 * @brief U8g2 SSD1306 Display Driver and RF Visualizer
 */

#ifndef GHOSTWAVE_DRIVERS_DISPLAY_H
#define GHOSTWAVE_DRIVERS_DISPLAY_H

#include <stdint.h>
#include <U8g2lib.h>
#include "types.h"
#include "config.h"

enum class DisplayMode : uint8_t {
    FM_SPECTRUM = 0,
    WIFI_BLE_HISTOGRAM = 1
};

class DisplayDriver {
public:
    DisplayDriver();

    /**
     * @brief Initializes the OLED display and configures I2C bus clock.
     */
    void init();

    /**
     * @brief Clears the internal graphics buffer.
     */
    void clear();

    /**
     * @brief Renders the FM Broadcast DX Spectrum view (87.5 - 108.0 MHz).
     * @param snapshot Latest spectrum snapshot
     */
    void renderFmView(const SpectrumSnapshot &snapshot);

    /**
     * @brief Renders the 2.4 GHz Wi-Fi & BLE Congestion Histogram.
     * @param snapshot Latest spectrum snapshot
     */
    void renderWifiView(const SpectrumSnapshot &snapshot);

    /**
     * @brief Renders the active view according to selected DisplayMode.
     * @param snapshot Latest spectrum snapshot
     * @param mode Active display view
     */
    void render(const SpectrumSnapshot &snapshot, DisplayMode mode);

    /**
     * @brief Flushes the internal graphics buffer to the SSD1306 display.
     */
    void sendBuffer();

private:
    U8G2_SSD1306_128X64_NONAME_F_HW_I2C m_u8g2;
};

#endif // GHOSTWAVE_DRIVERS_DISPLAY_H
