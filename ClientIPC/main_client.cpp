#include <iostream>
#include <string>
#include <stdexcept>
#include <thread>
#include <chrono>

#include "NamedPipeClient.h" // Includes other necessary headers transitively

int main() {
    const std::wstring pipeName = L"\\\\.\\pipe\\MySecureAuthPipe";
    const std::string clientPassword = "SuperSecretPassword123!"; // Must match server's password

    try {
        std::cout << "Connecting to pipe server (" << std::string(pipeName.begin(), pipeName.end()) << ") and authenticating..." << std::endl;
        // Pass the password to the client constructor for authentication
        NamedPipeClient client(pipeName, clientPassword);
        std::cout << "Connected and authenticated successfully." << std::endl;

        // Communication loop
        for (int i = 1; i <= 3; ++i) {
            std::string msg = "Authenticated hello from client, message " + std::to_string(i);
            std::cout << "Client Sending: " << msg << std::endl;
            client.SendMessageToServer(msg);

            std::cout << "Waiting for reply from server..." << std::endl;
            std::string reply = client.ReceiveMessageFromServer();
            std::cout << "Client Received: " << reply << std::endl;

            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

        // Send quit message
        std::cout << "Client Sending: quit" << std::endl;
        client.SendMessageToServer("quit");

        std::cout << "Waiting for final reply from server..." << std::endl;
        std::string finalReply = client.ReceiveMessageFromServer();
        std::cout << "Client Received: " << finalReply << std::endl;


    }
    catch (const PipeException& e) {
        std::cerr << "Client pipe communication or authentication error: " << e.what() << std::endl;
        if (e.GetErrorCode() == ERROR_BROKEN_PIPE) {
            std::cout << "Server disconnected unexpectedly." << std::endl;
        }
        else if (std::string(e.what()).find("Authentication failed") != std::string::npos) {
            std::cout << "Authentication failed. Please check the password." << std::endl;
        }
        else {
            std::cout << "A pipe error occurred." << std::endl;
        }
        return 1;
    }
    catch (const std::exception& e) {
        std::cerr << "An unexpected client error occurred: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "Client finished successfully." << std::endl;
    return 0;
}