#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include "secure_memory.hpp"

namespace pwm {

class Clipboard {
public:
    static constexpr unsigned int cleanupDelaySeconds = 15;

    static std::uint32_t copyToClipboard(std::string_view text);
    static void scheduleClearAfterDelay(std::uint32_t expectedSequenceNumber);
    static int runCleanupProcess();
    static void clearClipboard();
    static SecureString getClipboardText();
};

} // namespace pwm
