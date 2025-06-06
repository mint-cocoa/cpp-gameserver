#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <optional>
#include <span>
#include <array>
#include <chrono>
#include <cstring>

namespace co_uring_http {

// 게임 패킷 타입 정의
enum class packet_type : std::uint32_t {
    LOGIN = 1,
    GAME_STATE_UPDATE = 2,
    HEARTBEAT = 3,
    PLAYER_MOVE = 4,
    PLAYER_ATTACK = 5,
    CHAT_MESSAGE = 6,
    DISCONNECT = 7,
    ERROR_RESPONSE = 0xFF
};

// 게임 컨텍스트 구조체
struct game_context {
    std::uint32_t packet_type;
    std::uint32_t player_id;
    std::uint64_t timestamp;
    std::vector<std::uint8_t> payload;
    
    game_context() = default;
    game_context(std::uint32_t type, std::uint32_t id, std::uint64_t ts)
        : packet_type(type), player_id(id), timestamp(ts) {}
};

// 플레이어 위치 정보
struct player_position {
    float x, y, z;
    float rotation;
};

// 채팅 메시지 구조체
struct chat_message {
    std::uint32_t sender_id;
    std::string message;
    std::uint64_t timestamp;
};

// 로그인 요청 구조체
struct login_request {
    std::string username;
    std::string password;
    std::uint32_t client_version;
};

// 로그인 응답 구조체
struct login_response {
    bool success;
    std::uint32_t player_id;
    std::string session_token;
    std::string error_message;
};

// 게임 패킷 파서 클래스
class game_packet_parser {
public:
    // 바이너리 패킷을 파싱하여 게임 컨텍스트로 변환
    std::optional<game_context> parse_packet(const std::span<std::uint_least8_t>& buffer) const noexcept;
    
    // 게임 컨텍스트를 바이너리 패킷으로 직렬화
    std::vector<std::uint8_t> serialize_packet(const game_context& context) const noexcept;
    
    // 페이로드에서 플레이어 위치 정보 추출
    std::optional<player_position> extract_player_position(const std::vector<std::uint8_t>& payload) const noexcept;
    
    // 페이로드에서 채팅 메시지 추출
    std::optional<chat_message> extract_chat_message(const std::vector<std::uint8_t>& payload) const noexcept;
    
    // 페이로드에서 로그인 요청 추출
    std::optional<login_request> extract_login_request(const std::vector<std::uint8_t>& payload) const noexcept;
    
    // 로그인 응답을 페이로드로 직렬화
    std::vector<std::uint8_t> serialize_login_response(const login_response& response) const noexcept;
    
    // 플레이어 위치를 페이로드로 직렬화
    std::vector<std::uint8_t> serialize_player_position(const player_position& position) const noexcept;
    
    // 채팅 메시지를 페이로드로 직렬화
    std::vector<std::uint8_t> serialize_chat_message(const chat_message& message) const noexcept;

private:
    // 리틀 엔디안으로 32비트 정수 읽기
    std::uint32_t read_uint32_le(const std::uint8_t* data) const noexcept {
        return static_cast<std::uint32_t>(data[0]) |
               (static_cast<std::uint32_t>(data[1]) << 8) |
               (static_cast<std::uint32_t>(data[2]) << 16) |
               (static_cast<std::uint32_t>(data[3]) << 24);
    }
    
    // 리틀 엔디안으로 64비트 정수 읽기
    std::uint64_t read_uint64_le(const std::uint8_t* data) const noexcept {
        return static_cast<std::uint64_t>(data[0]) |
               (static_cast<std::uint64_t>(data[1]) << 8) |
               (static_cast<std::uint64_t>(data[2]) << 16) |
               (static_cast<std::uint64_t>(data[3]) << 24) |
               (static_cast<std::uint64_t>(data[4]) << 32) |
               (static_cast<std::uint64_t>(data[5]) << 40) |
               (static_cast<std::uint64_t>(data[6]) << 48) |
               (static_cast<std::uint64_t>(data[7]) << 56);
    }
    
    // 리틀 엔디안으로 32비트 정수 쓰기
    void write_uint32_le(std::uint8_t* data, std::uint32_t value) const noexcept {
        data[0] = static_cast<std::uint8_t>(value & 0xFF);
        data[1] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
        data[2] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
        data[3] = static_cast<std::uint8_t>((value >> 24) & 0xFF);
    }
    
    // 리틀 엔디안으로 64비트 정수 쓰기
    void write_uint64_le(std::uint8_t* data, std::uint64_t value) const noexcept {
        data[0] = static_cast<std::uint8_t>(value & 0xFF);
        data[1] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
        data[2] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
        data[3] = static_cast<std::uint8_t>((value >> 24) & 0xFF);
        data[4] = static_cast<std::uint8_t>((value >> 32) & 0xFF);
        data[5] = static_cast<std::uint8_t>((value >> 40) & 0xFF);
        data[6] = static_cast<std::uint8_t>((value >> 48) & 0xFF);
        data[7] = static_cast<std::uint8_t>((value >> 56) & 0xFF);
    }
    
    // float를 바이트 배열로 변환
    std::array<std::uint8_t, 4> float_to_bytes(float value) const noexcept {
        std::array<std::uint8_t, 4> bytes;
        std::memcpy(bytes.data(), &value, sizeof(float));
        return bytes;
    }
    
    // 바이트 배열을 float로 변환
    float bytes_to_float(const std::uint8_t* data) const noexcept {
        float value;
        std::memcpy(&value, data, sizeof(float));
        return value;
    }
};

// 게임 패킷 빌더 클래스
class game_packet_builder {
public:
    // 로그인 패킷 생성
    static game_context create_login_packet(std::uint32_t player_id, 
                                          const login_request& request);
    
    // 위치 업데이트 패킷 생성
    static game_context create_position_packet(std::uint32_t player_id, 
                                             const player_position& position);
    
    // 채팅 패킷 생성
    static game_context create_chat_packet(std::uint32_t player_id, 
                                         const chat_message& message);
    
    // 하트비트 패킷 생성
    static game_context create_heartbeat_packet(std::uint32_t player_id);
    
    // 에러 응답 패킷 생성
    static game_context create_error_packet(std::uint32_t player_id, 
                                          const std::string& error_msg);

private:
    static std::uint64_t get_current_timestamp() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
};

} // namespace co_uring_http
