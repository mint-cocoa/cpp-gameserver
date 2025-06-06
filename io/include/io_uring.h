#pragma once

#include <liburing.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <cstdint>
#include <memory>
#include <vector>
#include <span>
#include <expected>

namespace co_uring_http {

class SqeData {
public:
    void* coroutine = nullptr;
    std::int32_t cqe_res = 0;
    std::uint32_t cqe_flags = 0;
};

class IoUring {
public:
    static constexpr std::uint32_t IO_URING_QUEUE_SIZE = 4096;
    static constexpr std::uint32_t BUF_RING_SIZE = 1024;
    static constexpr std::uint32_t BUF_SIZE = 8192;
    static constexpr std::uint32_t BUF_GROUP_ID = 1;

    static IoUringContext& getInstance() noexcept;
    
    ~IoUringContext() noexcept;

    std::expected<void, std::uint16_t> queueInit() noexcept;
    
    void eventLoop() noexcept;
    
    std::expected<std::uint32_t, std::uint16_t> submitAndWait(std::uint32_t wait_nr) noexcept;
    
    void submitMultishotAcceptRequest(SqeData* sqe_data, std::uint32_t raw_fd,
                                     sockaddr* client_addr, socklen_t* client_len) noexcept;
    
    void submitRecvRequest(SqeData* sqe_data, std::uint32_t raw_fd) noexcept;
    
    void submitSendRequest(SqeData* sqe_data, std::uint32_t raw_fd,
                          std::span<const std::uint8_t> buf) noexcept;
    
    void submitSpliceRequest(SqeData* sqe_data, std::uint32_t raw_fd_in,
                            std::uint32_t raw_fd_out, std::uint32_t len) noexcept;
    
    void submitCancelRequest(SqeData* sqe_data) noexcept;
    
    std::expected<void, std::uint16_t> setupBufRing(
        io_uring_buf_ring* buf_ring,
        const std::vector<std::vector<std::uint8_t>>& buf_list) noexcept;
    
    void addBuf(io_uring_buf_ring* buf_ring,
               std::span<std::uint8_t> buf,
               std::uint32_t buf_id) noexcept;

private:
    IoUringContext() = default;
    IoUringContext(const IoUringContext&) = delete;
    IoUringContext& operator=(const IoUringContext&) = delete;
    
    std::expected<void, std::uint16_t> decodeVoid(int result) noexcept;
    std::expected<std::uint32_t, std::uint16_t> decode(int result) noexcept;
    void unwrap(std::expected<std::uint32_t, std::uint16_t> result) noexcept;

    io_uring io_uring_;
};

} // namespace co_uring_http 