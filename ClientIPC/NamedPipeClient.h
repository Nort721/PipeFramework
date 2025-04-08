#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <stdexcept>
#include "PipeException.h"
#include "CryptoHelper.h"

class NamedPipeClient {
private:
    std::wstring pipeName;
    HANDLE hPipe = INVALID_HANDLE_VALUE;
    bool isAuthenticated = false; // Track authentication status

    static constexpr DWORD BUFFER_SIZE = 4096;
    static constexpr char const* AUTH_NONCE_PREFIX = "NONCE ";
    static constexpr char const* AUTH_RESPONSE_PREFIX = "AUTH ";
    static constexpr char const* AUTH_OK = "AUTH_OK";
    static constexpr char const* AUTH_FAIL = "AUTH_FAIL"; // Not expected from server normally


     // Internal raw send/receive used during handshake
    void RawSend(const std::string& message) {
        if (hPipe == INVALID_HANDLE_VALUE) throw std::logic_error("Pipe not open for send.");
        DWORD bytesWritten = 0;
        BOOL success = WriteFile(hPipe, message.c_str(), static_cast<DWORD>(message.length()), &bytesWritten, NULL);
        if (!success || bytesWritten != message.length()) {
            throw PipeException("Handshake failed: Cannot write to pipe");
        }
    }

    std::string RawReceive() {
        if (hPipe == INVALID_HANDLE_VALUE) throw std::logic_error("Pipe not open for receive.");
        std::vector<char> buffer(BUFFER_SIZE);
        DWORD bytesRead = 0;
        BOOL success = ReadFile(hPipe, buffer.data(), BUFFER_SIZE, &bytesRead, NULL);

        if (!success || bytesRead == 0) {
            DWORD error = GetLastError();
            if (error == ERROR_BROKEN_PIPE) {
                throw PipeException("Handshake failed: Pipe broken or server disconnected", error);
            }
            else {
                throw PipeException("Handshake failed: Cannot read from pipe", error);
            }
        }
        return std::string(buffer.data(), bytesRead);
    }

    // Performs the client side of the authentication handshake
    void Authenticate(const std::string& password) {
        try {
            // 1. Receive nonce from server
            std::string nonceMsg = RawReceive();
            if (nonceMsg.rfind(AUTH_NONCE_PREFIX, 0) != 0) {
                throw PipeException("Authentication failed: Invalid nonce message from server", 0);
            }
            std::string nonceHex = nonceMsg.substr(strlen(AUTH_NONCE_PREFIX));
            std::vector<BYTE> nonce = HexToBytes(nonceHex);

            // 2. Compute hash = SHA256(password + nonce)
            std::vector<BYTE> hash = ComputeSHA256(password, nonce);
            std::string hashHex = BytesToHex(hash);

            // 3. Send hash back to server
            RawSend(std::string(AUTH_RESPONSE_PREFIX) + hashHex);

            // 4. Wait for AUTH_OK
            std::string serverResponse = RawReceive();
            if (serverResponse == AUTH_OK) {
                isAuthenticated = true; // Success!
                OutputDebugStringA("Client authenticated successfully.\n");
            }
            else {
                // Server sent AUTH_FAIL or unexpected message
                isAuthenticated = false;
                throw PipeException("Authentication failed: Server rejected credentials or sent invalid response.", 0);
            }

        }
        catch (const PipeException& e) {
            // Authentication failed, ensure handle is closed if appropriate
            if (hPipe != INVALID_HANDLE_VALUE) {
                CloseHandle(hPipe);
                hPipe = INVALID_HANDLE_VALUE;
            }
            isAuthenticated = false;
            throw; // Re-throw original exception
        }
        catch (const std::exception& e) {
            // Other errors (e.g., crypto helper)
            if (hPipe != INVALID_HANDLE_VALUE) {
                CloseHandle(hPipe);
                hPipe = INVALID_HANDLE_VALUE;
            }
            isAuthenticated = false;
            throw PipeException(std::string("Authentication handshake failed: ") + e.what(), 0);
        }
    }


public:
    // Constructor: Connects and authenticates
    explicit NamedPipeClient(const std::wstring& name, const std::string& password) : pipeName(name) {
        int retries = 5;
        DWORD error = 0;
        while (retries-- > 0) {
            hPipe = CreateFileW(
                pipeName.c_str(), GENERIC_READ | GENERIC_WRITE,
                0, NULL, OPEN_EXISTING, 0, NULL);

            if (hPipe != INVALID_HANDLE_VALUE) break; // Success

            error = GetLastError();
            if (error != ERROR_PIPE_BUSY) break; // Different error, stop retrying

            if (!WaitNamedPipeW(pipeName.c_str(), 1000)) { // Wait 1 second
                error = GetLastError(); // Update error if wait failed
                break; // Stop retrying if wait failed
            }
        }

        if (hPipe == INVALID_HANDLE_VALUE) {
            throw PipeException("Could not open pipe", error);
        }

        // Set message mode
        DWORD dwMode = PIPE_READMODE_MESSAGE;
        BOOL success = SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL);
        if (!success) {
            error = GetLastError(); // Capture error before closing handle
            CloseHandle(hPipe);
            hPipe = INVALID_HANDLE_VALUE;
            throw PipeException("Failed to set pipe mode", error);
        }

        // Now perform authentication
        Authenticate(password); // This will throw on failure and close the handle
    }

    ~NamedPipeClient() {
        if (hPipe != INVALID_HANDLE_VALUE) {
            CloseHandle(hPipe);
        }
    }

    // Send/Receive methods now check isAuthenticated flag
    void SendMessageToServer(const std::string& message) {
        if (!isAuthenticated || hPipe == INVALID_HANDLE_VALUE) {
            throw std::logic_error("Cannot send message: Client not authenticated or pipe closed.");
        }
        // Use RawSend for consistency
        RawSend(message);
    }

    std::string ReceiveMessageFromServer() {
        if (!isAuthenticated || hPipe == INVALID_HANDLE_VALUE) {
            throw std::logic_error("Cannot receive message: Client not authenticated or pipe closed.");
        }
        try {
            return RawReceive();
        }
        catch (const PipeException& e) {
            // If pipe breaks during normal communication, update state
            if (e.GetErrorCode() == ERROR_BROKEN_PIPE) {
                isAuthenticated = false; // Mark as not authenticated/connected
                if (hPipe != INVALID_HANDLE_VALUE) { // Defensive check
                    CloseHandle(hPipe); // Close broken handle
                    hPipe = INVALID_HANDLE_VALUE;
                }
            }
            throw; // Re-throw
        }
    }

    // Prevent copying/assignment (delete or implement properly if needed)
    NamedPipeClient(const NamedPipeClient&) = delete;
    NamedPipeClient& operator=(const NamedPipeClient&) = delete;
    // Move constructor/assignment (optional, implement if needed)
    NamedPipeClient(NamedPipeClient&&) = default;
    NamedPipeClient& operator=(NamedPipeClient&&) = default;
};