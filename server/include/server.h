#pragma once

#include <memory>
#include <filesystem>
#include <stdexcept>
#include <coroutine>
#include <span>
#include <optional>
#include <cstdint>
#include <vector>

namespace co_uring_http {

// Game context structure for parsing client packets
struct game_context {
    std::uint32_t packet_type;
    std::uint32_t player_id;
    std::uint64_t timestamp;
    std::vector<std::uint8_t> payload;
};

// Forward declarations
class socket_server;
class socket_client;
class http_request;
class http_parser;
class thread_pool;
template<typename T> class task;

// Exception classes
class server_error : public std::runtime_error {
public:
    explicit server_error(const std::string& msg);
};

class client_error : public std::runtime_error {
public:
    explicit client_error(const std::string& msg);
};

// Worker class that handles client connections
class worker {
public:
    worker();
    ~worker() = default;

    // Initialize the worker (sets up io_uring, binds socket, etc.)
    auto init() -> void;
    
    // Accept clients in a loop
    [[nodiscard]] auto accept_client() -> task<>;
    
    // Handle a single client connection
    [[nodiscard]] auto handle_client(socket_client socket_client) const -> task<>;

private:
    // Parse game context from received buffer
    [[nodiscard]] auto parse_game_context(
        const std::span<std::uint_least8_t>& buffer) const -> std::optional<game_context>;
    
    // Process a game context packet
    [[nodiscard]] auto process_game_context(
        const socket_client& client,
        const game_context& context) const -> task<>;
    
    // Process a single HTTP request (legacy)
    [[nodiscard]] auto process_http_request(
        const socket_client& client,
        const http_request& request) const -> task<>;

    std::unique_ptr<socket_server> socket_server_;
};

// Main HTTP server class
class http_server {
public:
    http_server();
    ~http_server() = default;
    
    // Start the server and listen for connections
    auto listen() -> void;

private:
    // Start a single worker thread
    [[nodiscard]] auto start_worker(int worker_id) -> task<>;
    
    thread_pool thread_pool_;
};

} // namespace co_uring_http