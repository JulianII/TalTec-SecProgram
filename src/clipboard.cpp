#include "clipboard.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>
#include "input_validation.hpp"
#include <windows.h>
#include <stdexcept>
#include <string>

namespace pwm {
namespace {

constexpr DWORD clipboardRetryCount = 10;
constexpr DWORD clipboardRetryDelayMilliseconds = 100;
constexpr size_t maxClipboardAllocationSize = maxSecretBytes + 4096;

std::runtime_error windowsError(const char* operation) {
    return std::runtime_error(
        std::string(operation) + " (Windows error " +
        std::to_string(GetLastError()) + ")");
}

void writePipeData(HANDLE pipe, const void* data, DWORD size) {
    const auto* bytes = static_cast<const unsigned char*>(data);
    DWORD writtenTotal = 0;
    while (writtenTotal < size) {
        DWORD written = 0;
        if (!WriteFile(pipe, bytes + writtenTotal, size - writtenTotal, &written, nullptr) ||
            written == 0) {
            throw windowsError("Could not send clipboard cleanup data");
        }
        writtenTotal += written;
    }
}

bool readPipeData(HANDLE pipe, void* data, DWORD size) {
    auto* bytes = static_cast<unsigned char*>(data);
    DWORD readTotal = 0;
    while (readTotal < size) {
        DWORD bytesRead = 0;
        if (!ReadFile(pipe, bytes + readTotal, size - readTotal, &bytesRead, nullptr) ||
            bytesRead == 0) {
            return false;
        }
        readTotal += bytesRead;
    }
    return true;
}

bool clearClipboardIfUnchanged(std::uint32_t expectedSequenceNumber) {
    bool opened = false;
    for (DWORD attempt = 0; attempt < clipboardRetryCount; ++attempt) {
        if (OpenClipboard(nullptr)) {
            opened = true;
            break;
        }
        Sleep(clipboardRetryDelayMilliseconds);
    }
    if (!opened) {
        throw windowsError("Could not open clipboard for cleanup");
    }

    const bool shouldClear =
        GetClipboardSequenceNumber() == expectedSequenceNumber;

    if (shouldClear && !EmptyClipboard()) {
        CloseClipboard();
        throw windowsError("Could not clear clipboard");
    }
    if (!CloseClipboard()) {
        throw windowsError("Could not close clipboard after cleanup");
    }
    return shouldClear;
}

void showCleanupFailure() {
    MessageBoxW(
        nullptr,
        L"PWM could not clear the clipboard. Please clear it manually if needed.",
        L"PWM clipboard cleanup",
        MB_OK | MB_ICONWARNING | MB_SETFOREGROUND);
}

} // namespace

std::uint32_t Clipboard::copyToClipboard(std::string_view text) {
    if (text.size() > maxSecretBytes) {
        throw std::runtime_error("Clipboard text exceeds the maximum supported length");
    }
    if (text.find('\0') != std::string_view::npos) {
        throw std::runtime_error("Clipboard text contains a null byte");
    }
    if (!OpenClipboard(nullptr)) {
        throw std::runtime_error("Could not open clipboard");
    }
    
    // Clear existing clipboard content
    if (!EmptyClipboard()) {
        CloseClipboard();
        throw windowsError("Could not clear existing clipboard content");
    }
    
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
        char* failedData = static_cast<char*>(GlobalLock(hMem));
        if (failedData) {
            SecureZeroMemory(failedData, text.size() + 1);
            GlobalUnlock(hMem);
        }
        GlobalFree(hMem);
        CloseClipboard();
        throw std::runtime_error("Could not set clipboard data");
    }

    const std::uint32_t sequenceNumber = GetClipboardSequenceNumber();
    if (!CloseClipboard()) {
        throw windowsError("Could not close clipboard after copying text");
    }
    return sequenceNumber;
}

void Clipboard::scheduleClearAfterDelay(std::uint32_t expectedSequenceNumber) {
    if (expectedSequenceNumber == 0) {
        throw std::runtime_error("Could not determine clipboard version for cleanup");
    }

    SECURITY_ATTRIBUTES securityAttributes{};
    securityAttributes.nLength = sizeof(securityAttributes);
    securityAttributes.bInheritHandle = TRUE;

    HANDLE readPipe = nullptr;
    HANDLE writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &securityAttributes, 0)) {
        throw windowsError("Could not create clipboard cleanup pipe");
    }
    if (!SetHandleInformation(writePipe, HANDLE_FLAG_INHERIT, 0)) {
        CloseHandle(readPipe);
        CloseHandle(writePipe);
        throw windowsError("Could not configure clipboard cleanup pipe");
    }

    HANDLE nullOutput = CreateFileW(
        L"NUL", GENERIC_WRITE, FILE_SHARE_WRITE, &securityAttributes,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (nullOutput == INVALID_HANDLE_VALUE) {
        CloseHandle(readPipe);
        CloseHandle(writePipe);
        throw windowsError("Could not prepare clipboard cleanup process");
    }

    std::vector<wchar_t> executablePath(32768);
    const DWORD pathLength = GetModuleFileNameW(
        nullptr, executablePath.data(), static_cast<DWORD>(executablePath.size()));
    if (pathLength == 0 || pathLength >= executablePath.size()) {
        CloseHandle(readPipe);
        CloseHandle(writePipe);
        CloseHandle(nullOutput);
        throw windowsError("Could not locate PWM executable for clipboard cleanup");
    }
    executablePath.resize(pathLength);

    std::wstring commandLine = L"\"" + std::wstring(executablePath.begin(), executablePath.end()) +
        L"\" --internal-clear-clipboard";
    std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
    mutableCommandLine.push_back(L'\0');
    executablePath.push_back(L'\0');

    SIZE_T attributeListSize = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeListSize);
    std::vector<unsigned char> attributeListStorage(attributeListSize);
    auto* attributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
        attributeListStorage.data());
    if (!InitializeProcThreadAttributeList(attributeList, 1, 0, &attributeListSize)) {
        CloseHandle(readPipe);
        CloseHandle(writePipe);
        CloseHandle(nullOutput);
        throw windowsError("Could not initialize clipboard cleanup process");
    }

    HANDLE inheritedHandles[] = {readPipe, nullOutput};
    if (!UpdateProcThreadAttribute(
            attributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inheritedHandles, sizeof(inheritedHandles), nullptr, nullptr)) {
        DeleteProcThreadAttributeList(attributeList);
        CloseHandle(readPipe);
        CloseHandle(writePipe);
        CloseHandle(nullOutput);
        throw windowsError("Could not configure clipboard cleanup process handles");
    }

    STARTUPINFOEXW startupInfo{};
    startupInfo.StartupInfo.cb = sizeof(startupInfo);
    startupInfo.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startupInfo.StartupInfo.hStdInput = readPipe;
    startupInfo.StartupInfo.hStdOutput = nullOutput;
    startupInfo.StartupInfo.hStdError = nullOutput;
    startupInfo.lpAttributeList = attributeList;

    PROCESS_INFORMATION processInfo{};
    const BOOL created = CreateProcessW(
        executablePath.data(), mutableCommandLine.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
        &startupInfo.StartupInfo, &processInfo);
    DeleteProcThreadAttributeList(attributeList);
    CloseHandle(readPipe);
    CloseHandle(nullOutput);

    if (!created) {
        CloseHandle(writePipe);
        throw windowsError("Could not start clipboard cleanup process");
    }
    CloseHandle(processInfo.hThread);
    CloseHandle(processInfo.hProcess);

    try {
        writePipeData(writePipe, &expectedSequenceNumber, sizeof(expectedSequenceNumber));
    } catch (...) {
        CloseHandle(writePipe);
        throw;
    }
    CloseHandle(writePipe);
}

int Clipboard::runCleanupProcess() {
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    if (input == INVALID_HANDLE_VALUE || GetFileType(input) != FILE_TYPE_PIPE) {
        return 1;
    }

    std::uint32_t expectedSequenceNumber = 0;
    if (!readPipeData(input, &expectedSequenceNumber, sizeof(expectedSequenceNumber)) ||
        expectedSequenceNumber == 0) {
        return 1;
    }

    Sleep(cleanupDelaySeconds * 1000);

    try {
        clearClipboardIfUnchanged(expectedSequenceNumber);
        return 0;
    } catch (const std::exception&) {
        showCleanupFailure();
        return 1;
    }
}

void Clipboard::clearClipboard() {
    if (!OpenClipboard(nullptr)) {
        throw windowsError("Could not open clipboard");
    }
    
    if (!EmptyClipboard()) {
        CloseClipboard();
        throw windowsError("Could not clear clipboard");
    }
    if (!CloseClipboard()) {
        throw windowsError("Could not close clipboard");
    }
}

SecureString Clipboard::getClipboardText() {
    if (!OpenClipboard(nullptr)) {
        throw std::runtime_error("Could not open clipboard");
    }
    
    HANDLE hData = GetClipboardData(CF_TEXT);
    if (!hData) {
        CloseClipboard();
        throw std::runtime_error("Clipboard does not contain text");
    }
    
    const SIZE_T allocationSize = GlobalSize(hData);
    if (allocationSize == 0 || allocationSize > maxClipboardAllocationSize) {
        CloseClipboard();
        throw std::runtime_error("Clipboard text exceeds the maximum supported length");
    }

    char* pData = static_cast<char*>(GlobalLock(hData));
    if (!pData) {
        CloseClipboard();
        throw std::runtime_error("Could not access clipboard text");
    }
    
    const auto* terminator = static_cast<const char*>(
        std::memchr(pData, '\0', allocationSize));
    if (!terminator) {
        GlobalUnlock(hData);
        CloseClipboard();
        throw std::runtime_error("Clipboard text is not terminated");
    }
    if (static_cast<size_t>(terminator - pData) > maxSecretBytes) {
        GlobalUnlock(hData);
        CloseClipboard();
        throw std::runtime_error("Clipboard text exceeds the maximum supported length");
    }

    SecureString text;
    try {
        text = SecureString{std::string_view(
            pData, static_cast<size_t>(terminator - pData))};
    } catch (...) {
        GlobalUnlock(hData);
        CloseClipboard();
        throw;
    }
    GlobalUnlock(hData);
    if (!CloseClipboard()) {
        throw windowsError("Could not close clipboard");
    }
    
    return text;
}

} // namespace pwm
