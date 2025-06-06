#include "include/IoUring.h"
#include "Logger.h"
#include <coroutine>
#include <cstring>
#include <stdexcept>
#include <algorithm>

namespace co_uring {

class sqe_data {
public:
  void *coroutine = nullptr;
  std::int_least32_t cqe_res = 0;
  std::uint_least32_t cqe_flags = 0;
}

IoUring& IoUring::getInstance() noexcept {
    thread_local IoUring instance;
    return instance;
}

IoUring::~IoUring() {io_uring_queue_exit(&io_uring_);}


IoUring::queueInit() {
    int result = io_uring_queue_init(IO_URING_QUEUE_SIZE, &io_uring_, 0);
    if (result < 0) {
        LOG_ERROR("Failed to initialize io_uring queue: ", strerror(-result));
        return std::unexpected(static_cast<std::uint16_t>(-result));
    }
    
    LOG_INFO("IoUring queue initialized with size: ", IO_URING_QUEUE_SIZE);
    return {};
}

void IoUring::eventLoop() {
    LOG_INFO("Starting io_uring event loop");
    while (true) {
        auto result = submitAndWait(1);
        if (!result) {
            LOG_ERROR("Failed to submit and wait: ", result.error());
            continue;
        }

        std::uint32_t head = 0;
        io_uring_cqe* cqe = nullptr;
        
        io_uring_for_each_cqe(&io_uring_, head, cqe) {
            auto* sqe_data = reinterpret_cast<SqeData*>(io_uring_cqe_get_data(cqe));
            
            if (sqe_data) {
                sqe_data->cqe_res = cqe->res;
                sqe_data->cqe_flags = cqe->flags;
                
                void* coroutine_address = sqe_data->coroutine;
                io_uring_cqe_seen(&io_uring_, cqe);
                
                if (coroutine_address != nullptr) {
                    std::coroutine_handle<>::from_address(coroutine_address).resume();
                }
            } else {
                io_uring_cqe_seen(&io_uring_, cqe);
            }
        }
    }
}

IoUring::submitAndWait(std::uint32_t wait_nr) {
    int result = io_uring_submit_and_wait(&io_uring_, wait_nr);
    if (result < 0) {
        LOG_ERROR("Failed to submit and wait: ", strerror(-result));
        return std::unexpected(static_cast<std::uint16_t>(-result));
    }
    
    return static_cast<std::uint32_t>(result);
}

void IoUring::submitMultishotAcceptRequest(SqeData* sqe_data, std::uint32_t raw_fd,
                                                  sockaddr* client_addr, socklen_t* client_len) {
    io_uring_sqe* sqe = io_uring_get_sqe(&io_uring_);
    if (!sqe) {
        LOG_ERROR("Failed to get SQE for multishot accept");
        return;
    }
    
    io_uring_prep_multishot_accept(sqe, raw_fd, client_addr, client_len, 0);
    io_uring_sqe_set_data(sqe, sqe_data);
    
    LOG_DEBUG("Submitted multishot accept request for fd: ", raw_fd);
}

void IoUring::submitRecvRequest(SqeData* sqe_data, std::uint32_t raw_fd)  {
    io_uring_sqe* sqe = io_uring_get_sqe(&io_uring_);
    if (!sqe) {
        LOG_ERROR("Failed to get SQE for recv");
        return;
    }
    
    io_uring_prep_recv(sqe, raw_fd, nullptr, BUF_SIZE, 0);
    io_uring_sqe_set_flags(sqe, IOSQE_BUFFER_SELECT);
    io_uring_sqe_set_data(sqe, sqe_data);
    sqe->buf_group = BUF_GROUP_ID;
    
    LOG_DEBUG("Submitted recv request for fd: ", raw_fd);
}

void IoUring::submitSendRequest(SqeData* sqe_data, std::uint32_t raw_fd,
                                      std::span<const std::uint8_t> buf) {
    io_uring_sqe* sqe = io_uring_get_sqe(&io_uring_);
    if (!sqe) {
        LOG_ERROR("Failed to get SQE for send");
        return;
    }
    
    io_uring_prep_send(sqe, raw_fd, buf.data(), buf.size(), 0);
    io_uring_sqe_set_data(sqe, sqe_data);
    
    LOG_DEBUG("Submitted send request for fd: ", raw_fd, " size: ", buf.size());
}

void IoUring::submitSpliceRequest(SqeData* sqe_data, std::uint32_t raw_fd_in,
                                        std::uint32_t raw_fd_out, std::uint32_t len){
    io_uring_sqe* sqe = io_uring_get_sqe(&io_uring_);
    if (!sqe) {
        LOG_ERROR("Failed to get SQE for splice");
        return;
    }
    
    io_uring_prep_splice(sqe, raw_fd_in, -1, raw_fd_out, -1, len, SPLICE_F_MORE);
    io_uring_sqe_set_data(sqe, sqe_data);
    
    LOG_DEBUG("Submitted splice request from fd: ", raw_fd_in, " to fd: ", raw_fd_out, " len: ", len);
}

void IoUring::submitCancelRequest(SqeData* sqe_data){
    io_uring_sqe* sqe = io_uring_get_sqe(&io_uring_);
    if (!sqe) {
        LOG_ERROR("Failed to get SQE for cancel");
        return;
    }
    
    io_uring_prep_cancel(sqe, sqe_data, 0);
    
    LOG_DEBUG("Submitted cancel request");
}

std::expected<void, std::uint16_t> IoUringContext::setupBufRing(
    io_uring_buf_ring* buf_ring,
    const std::vector<std::vector<std::uint8_t>>& buf_list) noexcept {
    
    if (!buf_ring) {
        LOG_ERROR("Null buffer ring pointer");
        return std::unexpected(EINVAL);
    }
    
    if (buf_list.size() != BUF_RING_SIZE) {
        LOG_ERROR("Buffer list size mismatch. Expected: ", BUF_RING_SIZE, " Got: ", buf_list.size());
        return std::unexpected(EINVAL);
    }
    
    // Register buffer ring with io_uring
    io_uring_buf_reg reg{};
    reg.ring_addr = reinterpret_cast<std::uint64_t>(buf_ring);
    reg.ring_entries = BUF_RING_SIZE;
    reg.bgid = BUF_GROUP_ID;
    
    int result = io_uring_register_buf_ring(&io_uring_, &reg, 0);
    if (result < 0) {
        LOG_ERROR("Failed to register buffer ring: ", strerror(-result));
        return std::unexpected(static_cast<std::uint16_t>(-result));
    }
    
    // Initialize buffer ring
    io_uring_buf_ring_init(buf_ring);
    
    // Add all buffers to the ring
    const std::uint32_t mask = io_uring_buf_ring_mask(BUF_RING_SIZE);
    for (std::uint32_t buf_id = 0; buf_id < BUF_RING_SIZE; ++buf_id) {
        if (buf_list[buf_id].size() != BUF_SIZE) {
            LOG_ERROR("Buffer ", buf_id, " size mismatch. Expected: ", BUF_SIZE, " Got: ", buf_list[buf_id].size());
            io_uring_unregister_buf_ring(&io_uring_, BUF_GROUP_ID);
            return std::unexpected(EINVAL);
        }
        
        io_uring_buf_ring_add(buf_ring, 
                             const_cast<void*>(static_cast<const void*>(buf_list[buf_id].data())),
                             buf_list[buf_id].size(), 
                             buf_id, 
                             mask, 
                             buf_id);
    }
    
    // Submit all buffers
    io_uring_buf_ring_advance(buf_ring, BUF_RING_SIZE);
    
    LOG_INFO("Buffer ring setup completed with ", BUF_RING_SIZE, " buffers");
    return {};
}

void IoUringContext::addBuf(io_uring_buf_ring* buf_ring,
                           std::span<std::uint8_t> buf,
                           std::uint32_t buf_id) noexcept {
    if (!buf_ring) {
        LOG_ERROR("Null buffer ring pointer");
        return;
    }
    
    if (buf.empty()) {
        LOG_ERROR("Empty buffer span");
        return;
    }
    
    const std::uint32_t mask = io_uring_buf_ring_mask(BUF_RING_SIZE);
    io_uring_buf_ring_add(buf_ring, buf.data(), buf.size(), buf_id, mask, buf_id);
    io_uring_buf_ring_advance(buf_ring, 1);
    
    LOG_DEBUG("Added buffer ", buf_id, " to ring, size: ", buf.size());
}

std::expected<void, std::uint16_t> IoUringContext::decodeVoid(int result) noexcept {
    if (result < 0) {
        return std::unexpected(static_cast<std::uint16_t>(-result));
    }
    return {};
}

std::expected<std::uint32_t, std::uint16_t> IoUringContext::decode(int result) noexcept {
    if (result < 0) {
        return std::unexpected(static_cast<std::uint16_t>(-result));
    }
    return static_cast<std::uint32_t>(result);
}

void IoUringContext::unwrap(std::expected<std::uint32_t, std::uint16_t> result) noexcept {
    if (!result) {
        LOG_ERROR("Unwrap failed with error: ", result.error());
    }
}

} // namespace co_uring_http 