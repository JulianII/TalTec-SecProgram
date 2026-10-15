#include "clipboard.hpp"
#include <windows.h>
#include <stdexcept>
#include <string>

namespace pwm {

void Clipboard::copyToClipboard(const std::string& text) {
    if (!OpenClipboard(nullptr)) {
        throw std::runtime_error("Could not open clipboard");
    }
    
    // Clear existing clipboard content
    EmptyClipboard();
    
    // Allocate global memory for the text
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
    if (!hMem) {
        CloseClipboard();
        throw std::runtime_error("Could not allocate memory for clipboard");
    }
    
    // Copy the text to the global memory
    char* pMem = static_cast<char*>(GlobalLock(hMem));
    if (!pMem) {
        GlobalFree(hMem);
        CloseClipboard();
        throw std::runtime_error("Could not lock global memory");
    }
    
    std::copy(text.begin(), text.end(), pMem);
    pMem[text.size()] = '\0';
    
    GlobalUnlock(hMem);
    
    // Set the clipboard data
    if (!SetClipboardData(CF_TEXT, hMem)) {
        GlobalFree(hMem);
        CloseClipboard();
        throw std::runtime_error("Could not set clipboard data");
    }
    
    CloseClipboard();
}

void Clipboard::clearClipboard() {
    if (!OpenClipboard(nullptr)) {
        return; // Silently fail if we can't open clipboard
    }
    
    EmptyClipboard();
    CloseClipboard();
}

std::string Clipboard::getClipboardText() {
    if (!OpenClipboard(nullptr)) {
        throw std::runtime_error("Could not open clipboard");
    }
    
    HANDLE hData = GetClipboardData(CF_TEXT);
    if (!hData) {
        CloseClipboard();
        return "";
    }
    
    char* pData = static_cast<char*>(GlobalLock(hData));
    if (!pData) {
        CloseClipboard();
        return "";
    }
    
    std::string text(pData);
    GlobalUnlock(hData);
    CloseClipboard();
    
    return text;
}

} // namespace pwm
