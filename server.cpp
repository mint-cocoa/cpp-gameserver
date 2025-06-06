#include "server.h"
#include "server/include/message.h"
#include <iostream>
#include <filesystem>
#include <format>
#include <ranges>
#include <vector>
#include <thread>


#define LOG_ERROR(msg) std::cerr << "[ERROR] " << msg << std::endl
#define LOG_INFO(msg) std::cout << "[INFO] " << msg << std::endl
#define LOG_DEBUG(msg) std::cout << "[DEBUG] " << msg << std::endl
#define LOG_WARN(msg) std::cout << "[WARN] " << msg << std::endl



// Exception class implementations
server_error::server_error(const std::string& msg) 
    : std::runtime_error(msg) {}

client_error::client_error(const std::string& msg) 
    : std::runtime_error(msg) {}

// Worker class implementation
worker::worker() {
    LOG_INFO("Worker instance created");
}

auto worker::init() -> void {
    try {
        LOG_INFO("Initializing worker...");
        
        // Initialize io_uring context
        IoUring::getInstance().queue_init();
        LOG_DEBUG("io_uring queue initialized");
        
        // Register buffer ring
        IoUring::getInstance().register_buf_ring();
        LOG_DEBUG("Buffer ring registered");
        
        // Bind and listen
        socket_server_ = std::make_unique<socket_server>(bind());
        LOG_INFO("Socket bound successfully");
        
        socket_server_->listen();
        LOG_INFO("Server listening for connections");
        
        // Start accepting clients
        spawn(accept_client());
        LOG_INFO("Worker initialization completed");
        
    } catch (const std::exception& e) {
        LOG_ERROR("Worker initialization failed: " + std::string(e.what()));
        throw server_error("Failed to initialize worker: " + std::string(e.what()));
    }
}

auto worker::accept_client() -> task<> {
    LOG_INFO("Starting client acceptance loop");
    
    while (true) {
        try {
            auto client = co_await socket_server_->accept();
            LOG_INFO("New client connection accepted");
            spawn(handle_client(std::move(client)));
            
        } catch (const std::exception& e) {
            LOG_ERROR("Failed to accept client: " + std::string(e.what()));
            // Continue accepting other clients
            continue;
        }
    }
}

auto worker::handle_client(socket_client socket_client) const -> task<> {
    LOG_INFO("Handling new client connection");
    
    try {
        while (true) {
            // Receive data from client
            auto [recv_buf_id, recv_buf_size] = co_await socket_client.recv();
            
            if (recv_buf_size == 0) {
                LOG_INFO("Client disconnected (received 0 bytes)");
                break;
            }
            
            LOG_DEBUG("Received " + std::to_string(recv_buf_size) + " bytes from client");
            
            // Get buffer from ring
            const std::span<std::uint_least8_t> recv_buf =
                buf_ring::get_instance()
                    .borrow_buf(recv_buf_id)
                    .subspan(0, recv_buf_size);
            
            // Parse game context packet
            auto parse_result = parse_game_context(recv_buf);
            
            if (parse_result.has_value()) {
                const game_context& context = *parse_result;
                LOG_INFO("Game packet received - Type: " + std::to_string(context.packet_type) + 
                        ", Player ID: " + std::to_string(context.player_id));
                
                // Process game context
                co_await process_game_context(socket_client, context);
            }
            
            // Return buffer to pool
            buf_ring::get_instance().return_buf(recv_buf_id);
        }
        
    } catch (const client_error& e) {
        LOG_WARN("Client error: " + std::string(e.what()));
    } catch (const std::exception& e) {
        LOG_ERROR("Error handling client: " + std::string(e.what()));
    }
    
    LOG_INFO("Client handler completed");
}

auto worker::parse_game_context(
    const std::span<std::uint_least8_t>& buffer) const -> std::optional<game_context> {
    
    game_packet_parser parser;
    auto result = parser.parse_packet(buffer);
    
    if (result.has_value()) {
        const auto& context = *result;
        LOG_DEBUG("Parsed game context - Type: " + std::to_string(context.packet_type) + 
                  ", Player: " + std::to_string(context.player_id) + 
                  ", Payload size: " + std::to_string(context.payload.size()));
    } else {
        LOG_WARN("Failed to parse game packet - Buffer size: " + std::to_string(buffer.size()) + " bytes");
    }
    
    return result;
}

auto worker::process_game_context(
    const socket_client& client,
    const game_context& context) const -> task<> {
    
    try {
        LOG_INFO("Processing game context - Type: " + std::to_string(context.packet_type) + 
                 " from Player: " + std::to_string(context.player_id));
        
        // Simple response based on packet type
        std::vector<std::uint8_t> response_data;
        
        switch (context.packet_type) {
            case 1: // Login packet
                LOG_INFO("Processing login request for player " + std::to_string(context.player_id));
                // Create login response
                response_data = {0x01, 0x00, 0x00, 0x00}; // Success response
                break;
                
            case 2: // Game state update
                LOG_DEBUG("Processing game state update from player " + std::to_string(context.player_id));
                // Echo back the update
                response_data = {0x02, 0x00, 0x00, 0x00}; // Acknowledgment
                break;
                
            case 3: // Heartbeat
                LOG_DEBUG("Heartbeat from player " + std::to_string(context.player_id));
                // Send heartbeat response
                response_data = {0x03, 0x00, 0x00, 0x00}; // Heartbeat ack
                break;
                
            default:
                LOG_WARN("Unknown packet type: " + std::to_string(context.packet_type));
                // Send error response
                response_data = {0xFF, 0x00, 0x00, 0x00}; // Error response
                break;
        }
        
        // Send response to client
        if (!response_data.empty()) {
            auto bytes_sent = co_await client.send({response_data.data(), response_data.size()});
            LOG_DEBUG("Sent response: " + std::to_string(bytes_sent) + " bytes");
        }
        
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to process game context: " + std::string(e.what()));
        throw client_error("Game context processing failed");
    }
}

auto worker::process_http_request(
    const socket_client& client,
    const http_request& request) const -> task<> {
    
    try {
        const std::filesystem::path file_path = 
            std::filesystem::relative(request.url, "/");
        
        LOG_DEBUG("Requested file path: " + file_path.string());
        
        http_response response;
        response.version = request.version;
        
        if (std::filesystem::exists(file_path) && 
            std::filesystem::is_regular_file(file_path)) {
            
            // File exists - send 200 OK
            response.status = "200";
            response.status_text = "OK";
            
            const auto file_size = std::filesystem::file_size(file_path);
            response.headers.emplace_back("content-length", 
                                        std::format("{}", file_size));
            
            LOG_INFO("Serving file: " + file_path.string() + 
                    " (" + std::to_string(file_size) + " bytes)");
            
            // Send response headers
            const std::string header_data = std::format("{}", response);
            auto bytes_sent = co_await client.send(
                {reinterpret_cast<const std::uint_least8_t*>(header_data.data()),
                 header_data.size()});
            
            LOG_DEBUG("Sent response headers: " + std::to_string(bytes_sent) + " bytes");
            
            // Open and send file
            try {
                const file f = open(file_path.c_str());
                co_await splice(f, client, file_size);
                LOG_INFO("File transfer completed: " + file_path.string());
                
            } catch (const std::exception& e) {
                LOG_ERROR("Failed to send file content: " + std::string(e.what()));
                throw client_error("File transfer failed");
            }
            
        } else {
            // File not found - send 404
            response.status = "404";
            response.status_text = "Not Found";
            response.headers.emplace_back("content-length", "0");
            
            LOG_WARN("File not found: " + file_path.string());
            
            const std::string header_data = std::format("{}", response);
            co_await client.send(
                {reinterpret_cast<const std::uint_least8_t*>(header_data.data()),
                 header_data.size()});
        }
        
    } catch (const std::filesystem::filesystem_error& e) {
        LOG_ERROR("Filesystem error: " + std::string(e.what()));
        throw client_error("Failed to access requested resource");
    }
}

// HTTP server class implementation
export http_server::http_server() 
    : thread_pool_(std::thread::hardware_concurrency()) {
    LOG_INFO("HTTP server created with " + 
            std::to_string(thread_pool_.size()) + " worker threads");
}

export auto http_server::listen() -> void {
    LOG_INFO("Starting HTTP server...");
    
    try {
        auto worker_list = std::views::iota(0) |
                          std::views::take(thread_pool_.size()) |
                          std::views::transform([this](int worker_id) -> task<> {
                              return start_worker(worker_id);
                          }) |
                          std::ranges::to<std::vector<task<>>>();
        
        LOG_INFO("Spawning " + std::to_string(worker_list.size()) + " workers");
        
        // Spawn all workers
        std::ranges::for_each(worker_list, spawn<task<>&>);
        
        LOG_INFO("All workers spawned, waiting for completion...");
        
        // Wait for all workers
        std::ranges::for_each(worker_list, wait<task<>&>);
        
    } catch (const std::exception& e) {
        LOG_ERROR("Server failed: " + std::string(e.what()));
        throw server_error("HTTP server failed: " + std::string(e.what()));
    }
}

auto http_server::start_worker(int worker_id) -> task<> {
    try {
        co_await thread_pool_.schedule();
        
        LOG_INFO("Worker " + std::to_string(worker_id) + " started on thread");
        
        worker worker_instance;
        worker_instance.init();
        
        LOG_INFO("Worker " + std::to_string(worker_id) + " entering event loop");
        io_uring_context::get_instance().event_loop();
        
        LOG_INFO("Worker " + std::to_string(worker_id) + " completed");
        
    } catch (const std::exception& e) {
        LOG_ERROR("Worker " + std::to_string(worker_id) + 
                 " failed: " + std::string(e.what()));
        throw;
    }
}

} // namespace co_uring_http