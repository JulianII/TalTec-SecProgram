#include "platform.hpp"

#include <stdexcept>
#include <unistd.h>
#include <termios.h>
#include <cstdlib>

#include "input_validation.hpp"

namespace platform {
    pwm::SecureString readHiddenPassword() {
        struct termios oldt, newt;
        if (tcgetattr(STDIN_FILENO, &oldt) != 0) {
            throw std::runtime_error("Could not access terminal settings.");
        }
        newt = oldt;
        newt.c_lflag &= ~ECHO;
        
        if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0) {
            throw std::runtime_error("Could not disable terminal echo.");
        }
        
        pwm::SecureString password;
        bool restored = false;
        try {
            while (true) {
                char character = 0;
                if (::read(STDIN_FILENO, &character, 1) != 1) {
                    throw std::runtime_error("Could not read master password from terminal.");
                }
                if (character == '\n') {
                    break;
                }
                if (password.size() == pwm::maxSecretBytes) {
                    while (::read(STDIN_FILENO, &character, 1) == 1 &&
                           character != '\n') {}
                    throw std::runtime_error("Password exceeds the maximum length.");
                }
                password.append(character);
            }
            if (tcsetattr(STDIN_FILENO, TCSANOW, &oldt) != 0) {
                throw std::runtime_error("Could not restore terminal settings.");
            }
            restored = true;
        } catch (...) {
            if (!restored && tcsetattr(STDIN_FILENO, TCSANOW, &oldt) != 0) {
                throw std::runtime_error("Could not restore terminal settings.");
            }
            throw;
        }
        
        return password;
    }

    std::string getUserDataDirectory() {
        const char* home = getenv("HOME");
        if (!home) {
            throw std::runtime_error("Could not determine home directory.");
        }
        return std::string(home) + "/.local/share/pwm";
    }
}
