#pragma once

#include <string>

namespace pwm {

class Clipboard {
public:
    static void copyToClipboard(const std::string& text);
    static void clearClipboard();
    static std::string getClipboardText();
};

} // namespace pwm
