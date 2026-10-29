#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <cstring>
#include <csignal>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Global atomic flag to control execution of sending and receiving loops
std::atomic<bool> is_running{true};

// Function executed in a separate std::thread to continuously receive incoming messages
void receive_messages(int sock_fd) {
    char buffer[4096];
    while (is_running) {
        std::memset(buffer, 0, sizeof(buffer));
        ssize_t bytes_received = recv(sock_fd, buffer, sizeof(buffer) - 1, 0);

        if (bytes_received > 0) {
            // Display incoming message and restore the input prompt
            std::cout << "\n[Server]: " << buffer << "\n[Client]: " << std::flush;
        } else if (bytes_received == 0) {
            // Peer closed connection gracefully
            if (is_running) {
                std::cout << "\n[Info] Server has disconnected." << std::endl;
                std::cout << "[Info] Press Enter to exit..." << std::endl;
            }
            is_running = false;
            break;
        } else {
            // Read error or socket was closed locally
            if (is_running) {
                std::cerr << "\n[Error] Socket read error occurred." << std::endl;
                std::cout << "[Info] Press Enter to exit..." << std::endl;
            }
            is_running = false;
            break;
        }
    }
}

int main(int argc, char* argv[]) {
    // Ignore SIGPIPE to avoid crashing when writing to a closed/broken socket
    signal(SIGPIPE, SIG_IGN);

    std::string server_ip = "127.0.0.1";
    int port = 8080;

    // Optional CLI arguments: ./client [ip] [port]
    if (argc >= 2) {
        server_ip = argv[1];
    }
    if (argc >= 3) {
        try {
            port = std::stoi(argv[2]);
        } catch (...) {
            std::cerr << "Invalid port argument. Using default port 8080.\n";
            port = 8080;
        }
    }

    // 1. Create client socket (IPv4, TCP stream)
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("Failed to create socket");
        return 1;
    }

    // 2. Configure server address structure
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    // Convert IP address from text to binary format
    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address or address not supported: " << server_ip << std::endl;
        close(sock_fd);
        return 1;
    }

    std::cout << "========================================\n";
    std::cout << "         Two-Way Chat Client            \n";
    std::cout << "========================================\n";
    std::cout << "Connecting to server at " << server_ip << ":" << port << "...\n";

    // 3. Connect to server
    if (connect(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection to server failed");
        close(sock_fd);
        return 1;
    }

    std::cout << "[Connected] Successfully connected to server!\n";
    std::cout << "[Info] Type your message and hit Enter to send.\n";
    std::cout << "[Info] Type '/exit' to end the chat session.\n";
    std::cout << "----------------------------------------\n";
    std::cout << "[Client]: " << std::flush;

    // Start background thread for concurrent message reception
    std::thread receiver_thread(receive_messages, sock_fd);

    // Main thread handles outgoing messages entered by user
    std::string message;
    while (is_running && std::getline(std::cin, message)) {
        if (!is_running) {
            break;
        }

        // Check if user requested to terminate session
        if (message == "/exit") {
            std::cout << "[Info] Closing session...\n";
            is_running = false;
            break;
        }

        // Avoid sending empty strings
        if (message.empty()) {
            std::cout << "[Client]: " << std::flush;
            continue;
        }

        // Send message to server
        ssize_t bytes_sent = send(sock_fd, message.c_str(), message.length(), MSG_NOSIGNAL);
        if (bytes_sent < 0) {
            std::cerr << "[Error] Failed to send message.\n";
            is_running = false;
            break;
        }

        std::cout << "[Client]: " << std::flush;
    }

    // Cleanup resources
    is_running = false;

    // Shutdown connection to unblock recv() in the receiver thread if it's still blocking
    shutdown(sock_fd, SHUT_RDWR);
    close(sock_fd);

    // Wait for the receiver thread to terminate
    if (receiver_thread.joinable()) {
        receiver_thread.join();
    }

    std::cout << "\n[Info] Client shut down cleanly.\n";
    return 0;
}
