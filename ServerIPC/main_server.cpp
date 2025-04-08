#include <iostream>
#include <string>
#include <stdexcept>
#include <thread>
#include <chrono>

#include "NamedPipeServer.h" // Includes other necessary headers transitively

int main() {
    const std::wstring pipeName = L"\\\\.\\pipe\\MySecureAuthPipe";
    // !!! IMPORTANT SECURITY WARNING !!!
    // Hardcoding passwords is very insecure. In a real application:
    // 1. Store a securely generated HASH of the password, not the password itself.
    // 2. Load the hash from a secure configuration store, not the code.
    // 3. The 'AuthenticateClient' method should compare hashes, not compute on the fly.
    const std::string serverPassword = "SuperSecretPassword123!"; // Example password

    try {
        std::cout << "Starting pipe server (" << std::string(pipeName.begin(), pipeName.end()) << ")..." << std::endl;
        // Pass the required password to the server constructor
        NamedPipeServer server(pipeName, serverPassword);
        std::cout << "Server created. Waiting for authenticated client connection..." << std::endl;

        while (true) {
            try {
                server.WaitForClientConnection(); // Now includes authentication
                std::cout << "Client connected and authenticated." << std::endl;

                // Communication loop (only runs if authenticated)
                while (true) { // Inner loop for messages from one client
                    std::cout << "Waiting for message from client..." << std::endl;
                    std::string receivedMsg = server.ReceiveMessageFromClient();
                    std::cout << "Server Received: " << receivedMsg << std::endl;

                    if (receivedMsg == "quit") {
                        std::cout << "Client requested quit. Sending goodbye and disconnecting." << std::endl;
                        server.SendMessageToClient("Goodbye from server!");
                        break; // Exit inner loop, will disconnect below
                    }

                    std::string reply = "Server received authenticated msg: " + receivedMsg;
                    std::cout << "Sending reply: " << reply << std::endl;
                    server.SendMessageToClient(reply);
                }
            }
            catch (const PipeException& e) {
                std::cerr << "Pipe communication or authentication error: " << e.what() << std::endl;
                if (e.GetErrorCode() == ERROR_BROKEN_PIPE) {
                    std::cout << "Client disconnected." << std::endl;
                }
                else if (e.what() == std::string("Client authentication failed")) {
                    std::cout << "Authentication failed. Waiting for new connection." << std::endl;
                    // Server already disconnected the client in this case.
                }
                else {
                    std::cerr << "A pipe error occurred. Waiting for new connection." << std::endl;
                }
                // Fall through to disconnect and wait for the next client connection attempt
            }
            catch (const std::exception& e) {
                // Catch other potential errors during communication
                std::cerr << "Unexpected error during client handling: " << e.what() << std::endl;
            }

            // Ensure client is disconnected before waiting for the next one
            server.DisconnectClient();
            std::cout << "Client session ended. Waiting for next connection..." << std::endl;
        }

    }
    catch (const PipeException& e) {
        std::cerr << "Server failed to initialize: " << e.what() << std::endl;
        return 1;
    }
    catch (const std::exception& e) {
        std::cerr << "An unexpected server error occurred: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "Server shutting down." << std::endl; // Should not be reached in this loop
    return 0;
}