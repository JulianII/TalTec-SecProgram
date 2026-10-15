#include "platform.hpp"

#include <iostream>
#include <windows.h>
#include <shlobj.h>

#include <stdexcept>
#include <string>

namespace platform {
    std::string readHiddenPassword() {
        HANDLE console = GetStdHandle(STD_INPUT_HANDLE);
        DWORD originalMode = 0;

        if (console == INVALID_HANDLE_VALUE ||
            console == NULL ||
            !GetConsoleMode(console, &originalMode)) {
            throw std::runtime_error("Could not access terminal input.");
        }

        DWORD hiddenMode = originalMode & ~ENABLE_ECHO_INPUT;

        if (!SetConsoleMode(console, hiddenMode)) {
            throw std::runtime_error("Could not disable terminal echo.");
        }

        std::string password = "";
        
        try {
            std::getline(std::cin, password);
        } catch (...) {
            SetConsoleMode(console, originalMode);
            throw;
        }

        if (!SetConsoleMode(console, originalMode)) {
            throw std::runtime_error("Could not restore terminal settings.");
        }

        return password;
    }

    std::string getUserDataDirectory() {
        wchar_t* path = nullptr;
        if (SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &path) != S_OK) {
            throw std::runtime_error("Could not determine local application data directory.");
        }
        
        std::wstring wpath(path);
        CoTaskMemFree(path);
        
        // Convert wide string to UTF-8
        int size = WideCharToMultiByte(CP_UTF8, 0, wpath.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (size == 0) {
            throw std::runtime_error("Could not convert path to UTF-8.");
        }
        
        std::string result(size, 0);
        WideCharToMultiByte(CP_UTF8, 0, wpath.c_str(), -1, &result[0], size, nullptr, nullptr);
        
        // Remove trailing null if present
        if (!result.empty() && result.back() == '\0') {
            result.pop_back();
        }
        
        return result + "\\pwm";
    }
}
