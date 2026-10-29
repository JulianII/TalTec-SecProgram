#pragma once

#include <cstdint>
#include <string>

namespace pwm {

class Clipboard {
public:
    static constexpr unsigned int cleanupDelaySeconds = 15;

    static std::uint32_t copyToClipboard(const std::string& text);
    static void scheduleClearAfterDelay(std::uint32_t expectedSequenceNumber);
    static int runCleanupProcess();
    static void clearClipboard();
    static std::string getClipboardText();
};

} // namespace pwm
