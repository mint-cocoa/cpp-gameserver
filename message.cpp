#include "server/include/message.h"
#include <iostream>

namespace co_uring_http {

// game_packet_parser 구현

std::optional<game_context> game_packet_parser::parse_packet(
    const std::span<std::uint_least8_t>& buffer) const noexcept {
    
    // 최소 패킷 크기 검사 (packet_type + player_id + timestamp = 16 bytes)
    if (buffer.size() < 16) {
        return std::nullopt;
    }
    
    game_context context;
    const auto* data = buffer.data();
    
    // 패킷 헤더 파싱 (리틀 엔디안 형식)
    context.packet_type = read_uint32_le(data);
    context.player_id = read_uint32_le(data + 4);
    context.timestamp = read_uint64_le(data + 8);
    
    // 페이로드 추출 (나머지 바이트)
    if (buffer.size() > 16) {
        context.payload.assign(data + 16, data + buffer.size());
    }
    
    return context;
}

std::vector<std::uint8_t> game_packet_parser::serialize_packet(
    const game_context& context) const noexcept {
    
    std::vector<std::uint8_t> packet(16 + context.payload.size());
    
    // 헤더 직렬화
    write_uint32_le(packet.data(), context.packet_type);
    write_uint32_le(packet.data() + 4, context.player_id);
    write_uint64_le(packet.data() + 8, context.timestamp);
    
    // 페이로드 복사
    if (!context.payload.empty()) {
        std::copy(context.payload.begin(), context.payload.end(), 
                  packet.begin() + 16);
    }
    
    return packet;
}

std::optional<player_position> game_packet_parser::extract_player_position(
    const std::vector<std::uint8_t>& payload) const noexcept {
    
    if (payload.size() < 16) { // 4 floats * 4 bytes each
        return std::nullopt;
    }
    
    player_position pos;
    pos.x = bytes_to_float(payload.data());
    pos.y = bytes_to_float(payload.data() + 4);
    pos.z = bytes_to_float(payload.data() + 8);
    pos.rotation = bytes_to_float(payload.data() + 12);
    
    return pos;
}

std::optional<chat_message> game_packet_parser::extract_chat_message(
    const std::vector<std::uint8_t>& payload) const noexcept {
    
    if (payload.size() < 12) { // sender_id(4) + timestamp(8) + 최소 메시지 크기
        return std::nullopt;
    }
    
    chat_message msg;
    msg.sender_id = read_uint32_le(payload.data());
    msg.timestamp = read_uint64_le(payload.data() + 4);
    
    // 메시지 길이 읽기
    if (payload.size() < 16) {
        return std::nullopt;
    }
    std::uint32_t msg_length = read_uint32_le(payload.data() + 12);
    
    if (payload.size() < 16 + msg_length) {
        return std::nullopt;
    }
    
    msg.message = std::string(reinterpret_cast<const char*>(payload.data() + 16), 
                             msg_length);
    
    return msg;
}

std::optional<login_request> game_packet_parser::extract_login_request(
    const std::vector<std::uint8_t>& payload) const noexcept {
    
    if (payload.size() < 12) { // 최소 크기: username_len(4) + password_len(4) + version(4)
        return std::nullopt;
    }
    
    login_request req;
    std::size_t offset = 0;
    
    // 사용자명 길이와 내용
    std::uint32_t username_len = read_uint32_le(payload.data() + offset);
    offset += 4;
    
    if (payload.size() < offset + username_len + 8) {
        return std::nullopt;
    }
    
    req.username = std::string(reinterpret_cast<const char*>(payload.data() + offset), 
                              username_len);
    offset += username_len;
    
    // 비밀번호 길이와 내용
    std::uint32_t password_len = read_uint32_le(payload.data() + offset);
    offset += 4;
    
    if (payload.size() < offset + password_len + 4) {
        return std::nullopt;
    }
    
    req.password = std::string(reinterpret_cast<const char*>(payload.data() + offset), 
                              password_len);
    offset += password_len;
    
    // 클라이언트 버전
    req.client_version = read_uint32_le(payload.data() + offset);
    
    return req;
}

std::vector<std::uint8_t> game_packet_parser::serialize_login_response(
    const login_response& response) const noexcept {
    
    std::vector<std::uint8_t> payload;
    
    // 성공 여부 (1 byte)
    payload.push_back(response.success ? 1 : 0);
    
    // 플레이어 ID (4 bytes)
    std::array<std::uint8_t, 4> player_id_bytes;
    write_uint32_le(player_id_bytes.data(), response.player_id);
    payload.insert(payload.end(), player_id_bytes.begin(), player_id_bytes.end());
    
    // 세션 토큰 길이와 내용
    std::array<std::uint8_t, 4> token_len_bytes;
    write_uint32_le(token_len_bytes.data(), static_cast<std::uint32_t>(response.session_token.size()));
    payload.insert(payload.end(), token_len_bytes.begin(), token_len_bytes.end());
    payload.insert(payload.end(), response.session_token.begin(), response.session_token.end());
    
    // 에러 메시지 길이와 내용
    std::array<std::uint8_t, 4> error_len_bytes;
    write_uint32_le(error_len_bytes.data(), static_cast<std::uint32_t>(response.error_message.size()));
    payload.insert(payload.end(), error_len_bytes.begin(), error_len_bytes.end());
    payload.insert(payload.end(), response.error_message.begin(), response.error_message.end());
    
    return payload;
}

std::vector<std::uint8_t> game_packet_parser::serialize_player_position(
    const player_position& position) const noexcept {
    
    std::vector<std::uint8_t> payload(16);
    
    auto x_bytes = float_to_bytes(position.x);
    auto y_bytes = float_to_bytes(position.y);
    auto z_bytes = float_to_bytes(position.z);
    auto rot_bytes = float_to_bytes(position.rotation);
    
    std::copy(x_bytes.begin(), x_bytes.end(), payload.begin());
    std::copy(y_bytes.begin(), y_bytes.end(), payload.begin() + 4);
    std::copy(z_bytes.begin(), z_bytes.end(), payload.begin() + 8);
    std::copy(rot_bytes.begin(), rot_bytes.end(), payload.begin() + 12);
    
    return payload;
}

std::vector<std::uint8_t> game_packet_parser::serialize_chat_message(
    const chat_message& message) const noexcept {
    
    std::vector<std::uint8_t> payload;
    
    // 발신자 ID (4 bytes)
    std::array<std::uint8_t, 4> sender_bytes;
    write_uint32_le(sender_bytes.data(), message.sender_id);
    payload.insert(payload.end(), sender_bytes.begin(), sender_bytes.end());
    
    // 타임스탬프 (8 bytes)
    std::array<std::uint8_t, 8> timestamp_bytes;
    write_uint64_le(timestamp_bytes.data(), message.timestamp);
    payload.insert(payload.end(), timestamp_bytes.begin(), timestamp_bytes.end());
    
    // 메시지 길이 (4 bytes)
    std::array<std::uint8_t, 4> msg_len_bytes;
    write_uint32_le(msg_len_bytes.data(), static_cast<std::uint32_t>(message.message.size()));
    payload.insert(payload.end(), msg_len_bytes.begin(), msg_len_bytes.end());
    
    // 메시지 내용
    payload.insert(payload.end(), message.message.begin(), message.message.end());
    
    return payload;
}

// game_packet_builder 구현

game_context game_packet_builder::create_login_packet(
    std::uint32_t player_id, const login_request& request) {
    
    game_context context(static_cast<std::uint32_t>(packet_type::LOGIN), 
                        player_id, get_current_timestamp());
    
    // 로그인 요청을 페이로드로 직렬화
    std::vector<std::uint8_t> payload;
    
    // 사용자명 길이와 내용
    std::array<std::uint8_t, 4> username_len_bytes;
    game_packet_parser parser;
    parser.write_uint32_le(username_len_bytes.data(), static_cast<std::uint32_t>(request.username.size()));
    payload.insert(payload.end(), username_len_bytes.begin(), username_len_bytes.end());
    payload.insert(payload.end(), request.username.begin(), request.username.end());
    
    // 비밀번호 길이와 내용
    std::array<std::uint8_t, 4> password_len_bytes;
    parser.write_uint32_le(password_len_bytes.data(), static_cast<std::uint32_t>(request.password.size()));
    payload.insert(payload.end(), password_len_bytes.begin(), password_len_bytes.end());
    payload.insert(payload.end(), request.password.begin(), request.password.end());
    
    // 클라이언트 버전
    std::array<std::uint8_t, 4> version_bytes;
    parser.write_uint32_le(version_bytes.data(), request.client_version);
    payload.insert(payload.end(), version_bytes.begin(), version_bytes.end());
    
    context.payload = std::move(payload);
    return context;
}

game_context game_packet_builder::create_position_packet(
    std::uint32_t player_id, const player_position& position) {
    
    game_context context(static_cast<std::uint32_t>(packet_type::PLAYER_MOVE), 
                        player_id, get_current_timestamp());
    
    game_packet_parser parser;
    context.payload = parser.serialize_player_position(position);
    
    return context;
}

game_context game_packet_builder::create_chat_packet(
    std::uint32_t player_id, const chat_message& message) {
    
    game_context context(static_cast<std::uint32_t>(packet_type::CHAT_MESSAGE), 
                        player_id, get_current_timestamp());
    
    game_packet_parser parser;
    context.payload = parser.serialize_chat_message(message);
    
    return context;
}

game_context game_packet_builder::create_heartbeat_packet(std::uint32_t player_id) {
    return game_context(static_cast<std::uint32_t>(packet_type::HEARTBEAT), 
                       player_id, get_current_timestamp());
}

game_context game_packet_builder::create_error_packet(
    std::uint32_t player_id, const std::string& error_msg) {
    
    game_context context(static_cast<std::uint32_t>(packet_type::ERROR_RESPONSE), 
                        player_id, get_current_timestamp());
    
    // 에러 메시지를 페이로드로 직렬화
    std::vector<std::uint8_t> payload;
    
    // 메시지 길이
    std::array<std::uint8_t, 4> msg_len_bytes;
    game_packet_parser parser;
    parser.write_uint32_le(msg_len_bytes.data(), static_cast<std::uint32_t>(error_msg.size()));
    payload.insert(payload.end(), msg_len_bytes.begin(), msg_len_bytes.end());
    
    // 메시지 내용
    payload.insert(payload.end(), error_msg.begin(), error_msg.end());
    
    context.payload = std::move(payload);
    return context;
}

} // namespace co_uring_http
