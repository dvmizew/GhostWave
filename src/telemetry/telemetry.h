#ifndef GHOSTWAVE_TELEMETRY_TELEMETRY_H
#define GHOSTWAVE_TELEMETRY_TELEMETRY_H

#include <stddef.h>
#include <Print.h>
#include "types.h"

class Telemetry {
public:
    static size_t formatJson(const SpectrumSnapshot &snapshot, char *outBuffer, size_t maxLen);
    static size_t streamJson(Print &output, const SpectrumSnapshot &snapshot);
};

#endif // GHOSTWAVE_TELEMETRY_TELEMETRY_H
