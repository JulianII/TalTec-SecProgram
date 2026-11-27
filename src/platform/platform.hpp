// platform.hpp
#pragma once

#include <string>
#include "secure_memory.hpp"

namespace platform {
    pwm::SecureString readHiddenPassword();
    std::string getUserDataDirectory();
}