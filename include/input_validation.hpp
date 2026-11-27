#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

namespace pwm {

inline constexpr size_t maxAccountNameBytes = 256;
inline constexpr size_t maxPersistedAccountNameBytes = 4096;
inline constexpr size_t maxSecretBytes = 4096;

inline bool isValidUtf8(std::string_view value) noexcept {
    size_t i = 0;
    while (i < value.size()) {
        const unsigned char first = static_cast<unsigned char>(value[i]);
        if (first < 0x80) {
            ++i;
            continue;
        }

        size_t continuationCount = 0;
        uint32_t codePoint = 0;
        if (first >= 0xc2 && first <= 0xdf) {
            continuationCount = 1;
            codePoint = first & 0x1f;
        } else if (first >= 0xe0 && first <= 0xef) {
            continuationCount = 2;
            codePoint = first & 0x0f;
        } else if (first >= 0xf0 && first <= 0xf4) {
            continuationCount = 3;
            codePoint = first & 0x07;
        } else {
            return false;
        }

        if (value.size() - i <= continuationCount) {
            return false;
        }
        for (size_t j = 1; j <= continuationCount; ++j) {
            const unsigned char next = static_cast<unsigned char>(value[i + j]);
            if ((next & 0xc0) != 0x80) {
                return false;
            }
            codePoint = (codePoint << 6) | (next & 0x3f);
        }

        if ((continuationCount == 2 && codePoint < 0x800) ||
            (continuationCount == 3 && codePoint < 0x10000) ||
            (codePoint >= 0xd800 && codePoint <= 0xdfff) ||
            codePoint > 0x10ffff) {
            return false;
        }
        i += continuationCount + 1;
    }
    return true;
}

inline void validateAccountName(
    std::string_view value,
    size_t maximumBytes = maxAccountNameBytes) {
    if (value.empty()) {
        throw std::invalid_argument("Account name cannot be empty");
    }
    if (value.size() > maximumBytes) {
        throw std::invalid_argument("Account name exceeds the maximum length");
    }
    if (value.front() == ' ' || value.back() == ' ') {
        throw std::invalid_argument("Account name cannot start or end with a space");
    }
    if (!isValidUtf8(value)) {
        throw std::invalid_argument("Account name must be valid UTF-8");
    }

    size_t i = 0;
    while (i < value.size()) {
        const unsigned char first = static_cast<unsigned char>(value[i]);
        uint32_t codePoint = first;
        size_t width = 1;
        if (first >= 0xc2 && first <= 0xdf) {
            codePoint = first & 0x1f;
            width = 2;
        } else if (first >= 0xe0 && first <= 0xef) {
            codePoint = first & 0x0f;
            width = 3;
        } else if (first >= 0xf0) {
            codePoint = first & 0x07;
            width = 4;
        }
        for (size_t j = 1; j < width; ++j) {
            codePoint = (codePoint << 6) |
                (static_cast<unsigned char>(value[i + j]) & 0x3f);
        }

        const bool control = codePoint < 0x20 ||
            (codePoint >= 0x7f && codePoint <= 0x9f) ||
            codePoint == 0x2028 || codePoint == 0x2029 ||
            (codePoint >= 0x202a && codePoint <= 0x202e) ||
            (codePoint >= 0x2066 && codePoint <= 0x2069);
        if (control) {
            throw std::invalid_argument("Account name contains a control character");
        }
        i += width;
    }
}

inline void validateSecret(std::string_view value, const char* fieldName) {
    if (value.empty()) {
        throw std::invalid_argument(std::string(fieldName) + " cannot be empty");
    }
    if (value.size() > maxSecretBytes) {
        throw std::invalid_argument(std::string(fieldName) + " exceeds the maximum length");
    }
    if (value.find('\0') != std::string_view::npos) {
        throw std::invalid_argument(std::string(fieldName) + " contains a null byte");
    }
}

}  // namespace pwm
