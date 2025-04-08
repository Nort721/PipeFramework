#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <stdexcept>
#include <memory> // For unique_ptr
#include "PipeException.h"
#include "SecurityHelper.h"
#include "CryptoHelper.h"

class NamedPipeServer {
private:
    std::wstring pipeName;
    HANDLE hPipe = INVALID_HANDLE_VALUE;
    unique_local_ptr pSecurityDescriptor;
    SECURITY_ATTRIBUTES sa;
    bool isClientConnectedAndAuthenticated = false; // Renamed for clarity
    std::string storedPassword; // !! STORE HASHED PASSWORD IN PRODUCTION !!

    static constexpr DWORD BUFFER_SIZE = 4096;
    static constexpr char const* AUTH_NONCE_PREFIX = "NONCE ";
    static constexpr char const* AUTH_RESPONSE_PREFIX = "AUTH ";
    static constexpr char const* AUTH_OK = "AUTH_OK";
    static constexpr char const* AUTH_FAIL = "AUTH_FAIL";

    void InitializeSecurityAttributes() {
        // ... (same as before)
        pSecurityDescriptor = CreateCurrentUserSecurityDescriptor();
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.lpSecurityDescriptor = pSecurityDescriptor.get();
        sa.bInheritHandle = FALSE;
    }

    // Internal raw send/receive used during handshake
    void RawSend(const std::string& message) {
        DWORD bytesWritten = 0;
        BOOL success = WriteFile(hPipe, message.c_str(), static_cast<DWORD>(message.length()), &bytesWritten, NULL);
        if (!success || bytesWritten != message.length()) {
            throw PipeException("Handshake failed: Cannot write to pipe");
        }
    }

    std::string RawReceive() {
        std::vector<char> buffer(BUFFER_SIZE);
        DWORD bytesRead = 0;
        BOOL success = ReadFile(hPipe, buffer.data(), BUFFER_SIZE, &bytesRead, NULL);

        if (!success || bytesRead == 0) { // Also treat 0 bytes read as failure during handshake
            DWORD error = GetLastError();
            if (error == ERROR_BROKEN_PIPE) {
                throw PipeException("Handshake failed: Pipe broken or client disconnected", error);
            }
            else {
                throw PipeException("Handshake failed: Cannot read from pipe", error);
            }
        }
        return std::string(buffer.data(), bytesRead);
    }


    // Performs the challenge-response authentication handshake
    bool AuthenticateClient() {
        try {
            // 1. Generate and send nonce (challenge)
            std::vector<BYTE> nonce = GenerateNonce();
            std::string nonceHex = BytesToHex(nonce);
            RawSend(std::string(AUTH_NONCE_PREFIX) + nonceHex);

            // 2. Receive client's response (hashed password + nonce)
            std::string clientResponse = RawReceive();
            if (clientResponse.rfind(AUTH_RESPONSE_PREFIX, 0) != 0) {
                RawSend(AUTH_FAIL); // Invalid format
                return false;
            }
            std::string clientHashHex = clientResponse.substr(strlen(AUTH_RESPONSE_PREFIX));
            std::vector<BYTE> clientHash = HexToBytes(clientHashHex);


            // 3. Compute expected hash
            // !! IMPORTANT: In production, 'storedPassword' should actually be the password,
            //    and you'd compare the received hash against a securely pre-computed hash
            //    of the password. Here, we compute the hash on the fly using the plaintext
            //    password for demonstration. NEVER store plaintext passwords.
            std::vector<BYTE> expectedHash = ComputeSHA256(storedPassword, nonce);

            // 4. Compare hashes and send result
            if (clientHash == expectedHash) {
                RawSend(AUTH_OK);
                return true; // Authentication successful
            }
            else {
                RawSend(AUTH_FAIL);
                return false; // Authentication failed
            }
        }
        catch (const std::exception& e) {
            // Log the error - e.g., using OutputDebugStringA or a logging library
            std::string errorMsg = "Authentication handshake error: ";
            errorMsg += e.what();
            OutputDebugStringA(errorMsg.c_str());
            // Attempt to notify client of failure if possible, otherwise just return false
            try { RawSend(AUTH_FAIL); }
            catch (...) {}
            return false;
        }
    }


public:
    // Constructor: Takes pipe name and the password required for authentication
    // !! In Production: Pass a securely retrieved password hash, not plaintext !!
    explicit NamedPipeServer(const std::wstring& name, std::string requiredPassword)
        : pipeName(name), storedPassword(std::move(requiredPassword)) // Store the password
    {
        InitializeSecurityAttributes();

        hPipe = CreateNamedPipeW(
            pipeName.c_str(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE, // Use FIRST_PIPE_INSTANCE if you only want one server instance
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, // Max instances = 1 for simplicity with FIRST_PIPE_INSTANCE
            BUFFER_SIZE, BUFFER_SIZE,
            0, &sa);

        if (hPipe == INVALID_HANDLE_VALUE) {
            // Allow ERROR_ACCESS_DENIED if pipe already exists due to FIRST_PIPE_INSTANCE
            if (GetLastError() == ERROR_ACCESS_DENIED && !(FILE_FLAG_FIRST_PIPE_INSTANCE & PIPE_ACCESS_DUPLEX)) {
                // Another instance might be running. Depending on requirements, either
                // fail here, or try connecting as a client to see if it's active, etc.
                // For this example, we'll throw.
                throw PipeException("Pipe already exists (or access denied). Ensure only one server instance.", GetLastError());
            }
            throw PipeException("Failed to create named pipe");
        }
    }

    ~NamedPipeServer() {
        DisconnectClient(); // Ensure client is disconnected
        if (hPipe != INVALID_HANDLE_VALUE) {
            CloseHandle(hPipe);
        }
    }

    void WaitForClientConnection() {
        if (isClientConnectedAndAuthenticated) {
            DisconnectClient();
        }

        BOOL connected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

        if (!connected) {
            DWORD error = GetLastError();
            // Don't close the handle here if ConnectNamedPipe fails,
            // it needs to stay open for the next connection attempt.
            // Only close if creation failed initially.
            throw PipeException("Failed waiting for client connection", error);
        }

        // Client connected, now perform authentication handshake
        if (AuthenticateClient()) {
            isClientConnectedAndAuthenticated = true; // Authentication successful
             // Optional: Log success
            OutputDebugStringA("Client connected and authenticated.\n");
        }
        else {
            isClientConnectedAndAuthenticated = false;
            OutputDebugStringA("Client authentication failed. Disconnecting.\n");
            DisconnectNamedPipe(hPipe); // Disconnect unauthenticated client
            // Optionally throw or just return (caller needs to check if connected)
            // Let's throw to indicate connection attempt failed overall
            throw PipeException("Client authentication failed", 0); // Use 0 or custom error
        }
    }

    // Sends message only if client is authenticated
    void SendMessageToClient(const std::string& message) {
        if (!isClientConnectedAndAuthenticated) {
            throw std::logic_error("Cannot send message: No authenticated client connected.");
        }
        // Use RawSend for consistency, or reimplement checks here
        RawSend(message);
    }

    // Receives message only if client is authenticated
    std::string ReceiveMessageFromClient() {
        if (!isClientConnectedAndAuthenticated) {
            throw std::logic_error("Cannot receive message: No authenticated client connected.");
        }
        try {
            return RawReceive();
        }
        catch (const PipeException& e) {
            // If pipe breaks during normal communication, update state
            if (e.GetErrorCode() == ERROR_BROKEN_PIPE) {
                isClientConnectedAndAuthenticated = false;
            }
            throw; // Re-throw the exception
        }
    }

    // Disconnects client and resets authentication state
    void DisconnectClient() {
        if (hPipe != INVALID_HANDLE_VALUE && isClientConnectedAndAuthenticated) {
            // isClientConnectedAndAuthenticated check ensures we only call DisconnectNamedPipe
            // if we successfully connected AND authenticated previously.
            if (!DisconnectNamedPipe(hPipe)) {
                // Log warning or minor error
                OutputDebugStringA(("Warning: DisconnectNamedPipe failed with error " + std::to_string(GetLastError()) + "\n").c_str());
            }
        }
        // Always reset the flag regardless of DisconnectNamedPipe success
        isClientConnectedAndAuthenticated = false;
    }

    // Prevent copying/assignment (delete or implement properly if needed)
    NamedPipeServer(const NamedPipeServer&) = delete;
    NamedPipeServer& operator=(const NamedPipeServer&) = delete;
    // Move constructor/assignment (optional, implement if needed)
    NamedPipeServer(NamedPipeServer&&) = default;
    NamedPipeServer& operator=(NamedPipeServer&&) = default;
};