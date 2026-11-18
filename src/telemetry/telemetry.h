/**
 * @file telemetry.h
 * @brief Zero-Heap Static JSON Serializer
 *
 * Formats SpectrumSnapshot instances into compact, single-line JSON records
 * for 921600 baud serial transmission without dynamic memory allocation.
 */

#ifndef GHOSTWAVE_TELEMETRY_TELEMETRY_H
#define GHOSTWAVE_TELEMETRY_TELEMETRY_H

#include <stdint.h>
#include <stddef.h>
#include <Print.h>
#include "types.h"
#include "config.h"

class Telemetry {
public:
    /**
     * @brief Formats a SpectrumSnapshot into a JSON string in outBuffer.
     * Zero heap allocation.
     * @param snapshot Snapshot data to format
     * @param outBuffer Destination character buffer
     * @param maxLen Capacity of outBuffer
     * @return Number of characters written (excluding null terminator), or 0 on error
     */
    static size_t formatJson(const SpectrumSnapshot &snapshot, char *outBuffer, size_t maxLen);

    /**
     * @brief Serializes snapshot to internal static buffer and writes to output stream.
     * @param output Print stream (e.g. Serial)
     * @param snapshot Snapshot data
     * @return Number of bytes written
     */
    static size_t streamJson(Print &output, const SpectrumSnapshot &snapshot);
};

#endif // GHOSTWAVE_TELEMETRY_TELEMETRY_H
