#pragma once

#include <stdexcept>
#include <string>
#include <windows.h> // Required for DWORD, FormatMessage etc.

// Helper function to get Win32 error message
inline std::string GetWin32ErrorString(DWORD errorCode) {
    if (errorCode == 0) return "No error.";
    LPSTR buffer = nullptr;
    DWORD size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&buffer,
        0,
        NULL);

    std::string message(buffer, size);
    LocalFree(buffer);

    // Remove trailing newline characters which FormatMessage often adds
    while (!message.empty() && (message.back() == '\r' || message.back() == '\n')) {
        message.pop_back();
    }
    return message;
}

class PipeException : public std::runtime_error {
private:
    DWORD errorCode;
    std::string errorMessage;

public:
    PipeException(const std::string& message, DWORD error = GetLastError())
        : std::runtime_error(message + " (Win32 Error " + std::to_string(error) + ": " + GetWin32ErrorString(error) + ")"),
        errorCode(error),
        errorMessage(GetWin32ErrorString(error))
    { }

    DWORD GetErrorCode() const noexcept {
        return errorCode;
    }

    const char* GetWin32ErrorMessage() const noexcept {
        return errorMessage.c_str();
    }
};