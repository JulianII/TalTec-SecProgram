#include "platform.hpp"

#include <iostream>
#include <string>
#include <stdexcept>
#include <unistd.h>
#include <termios.h>
#include <cstdlib>

namespace platform {
    std::string readHiddenPassword() {
        struct termios oldt, newt;
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~ECHO;
        
        if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0) {
            throw std::runtime_error("Could not disable terminal echo.");
        }
        
        std::string password;
        try {
            std::getline(std::cin, password);
        } catch (...) {
            tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
            throw;
        }
        
        if (tcsetattr(STDIN_FILENO, TCSANOW, &oldt) != 0) {
            throw std::runtime_error("Could not restore terminal settings.");
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
