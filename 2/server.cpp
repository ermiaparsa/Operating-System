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
void receive_messages(int client_fd) {
    char buffer[4096];
    while (is_running) {
        std::memset(buffer, 0, sizeof(buffer));
        ssize_t bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);

        if (bytes_received > 0) {
            // Display incoming message and restore the input prompt
            std::cout << "\n[Client]: " << buffer << "\n[Server]: " << std::flush;
        } else if (bytes_received == 0) {
            // Peer closed connection gracefully
            if (is_running) {
                std::cout << "\n[Info] Client has disconnected." << std::endl;
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

    int port = 8080;
    if (argc >= 2) {
        try {
            port = std::stoi(argv[1]);
        } catch (...) {
            std::cerr << "Invalid port argument. Using default port 8080.\n";
            port = 8080;
        }
    }

    // 1. Create socket (IPv4, TCP stream)
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Failed to create socket");
        return 1;
    }

    // Set SO_REUSEADDR option so port can be re-bound immediately upon restart
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEADDR failed");
        close(server_fd);
        return 1;
    }

    // 2. Configure server address structure
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Bind to all available local network interfaces
    server_addr.sin_port = htons(port);

    // 3. Bind socket to the specified IP and port
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        return 1;
    }

    // 4. Listen for incoming connections (backlog queue of 1)
    if (listen(server_fd, 1) < 0) {
        perror("Listen failed");
        close(server_fd);
        return 1;
    }

    std::cout << "========================================\n";
    std::cout << "         Two-Way Chat Server            \n";
    std::cout << "========================================\n";
    std::cout << "Listening on port " << port << "...\n";
    std::cout << "Waiting for a client to connect...\n";

    // 5. Accept client connection
    sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd < 0) {
        perror("Accept failed");
        close(server_fd);
        return 1;
    }

    // Convert client IP from binary to readable string
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    int client_port = ntohs(client_addr.sin_port);

    std::cout << "[Connected] Client connected from " << client_ip << ":" << client_port << "\n";
    std::cout << "[Info] Type your message and hit Enter to send.\n";
    std::cout << "[Info] Type '/exit' to end the chat session.\n";
    std::cout << "----------------------------------------\n";
    std::cout << "[Server]: " << std::flush;

    // Start background thread for concurrent message reception
    std::thread receiver_thread(receive_messages, client_fd);

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
            std::cout << "[Server]: " << std::flush;
            continue;
        }

        // Send message to client
        ssize_t bytes_sent = send(client_fd, message.c_str(), message.length(), MSG_NOSIGNAL);
        if (bytes_sent < 0) {
            std::cerr << "[Error] Failed to send message.\n";
            is_running = false;
            break;
        }

        std::cout << "[Server]: " << std::flush;
    }

    // Cleanup resources
    is_running = false;

    // Shutdown connection to unblock recv() in the receiver thread if it's still blocking
    shutdown(client_fd, SHUT_RDWR);
    close(client_fd);
    close(server_fd);

    // Wait for the receiver thread to terminate
    if (receiver_thread.joinable()) {
        receiver_thread.join();
    }

    std::cout << "\n[Info] Server shut down cleanly.\n";
    return 0;
}
