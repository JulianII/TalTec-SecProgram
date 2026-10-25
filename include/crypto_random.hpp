#pragma once

#include <cstddef>
#include <climits>
#include <stdexcept>
#include <vector>
#include <openssl/rand.h>

namespace pwm::crypto {

inline std::vector<unsigned char> randomBytes(size_t size) {
    if (size > static_cast<size_t>(INT_MAX)) {
        throw std::runtime_error("Requested random byte count is too large");
    }

    std::vector<unsigned char> bytes(size);
    if (size != 0 && RAND_bytes(bytes.data(), static_cast<int>(size)) != 1) {
        throw std::runtime_error("Cryptographic random number generation failed");
    }
    return bytes;
}

}  // namespace pwm::crypto
