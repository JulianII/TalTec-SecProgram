#pragma once

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string_view>

namespace pwm {

inline void logEvent(std::string_view level, std::string_view event) {
    const auto now = std::chrono::system_clock::now();
    const std::time_t timestamp = std::chrono::system_clock::to_time_t(now);
    std::tm utc{};
#ifdef _WIN32
    gmtime_s(&utc, &timestamp);
#else
    gmtime_r(&timestamp, &utc);
#endif

    std::ostringstream line;
    line << "{\"timestamp\":\"" << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ")
         << "\",\"level\":\"" << level << "\",\"event\":\"" << event << "\"}";
    std::clog << line.str() << '\n';
    std::clog.flush();
}

}  // namespace pwm
