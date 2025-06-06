# C++ Game Server

고성능 게임 서버 구현체로, io_uring을 사용한 비동기 네트워킹과 바이너리 패킷 처리 시스템을 제공합니다.

## 🚀 주요 특징

- **고성능 비동기 I/O**: Linux io_uring을 활용한 효율적인 네트워크 처리
- **게임 패킷 시스템**: 바이너리 패킷 파싱 및 직렬화 지원
- **타입 안전성**: 강타입 열거형을 사용한 패킷 타입 관리
- **확장 가능한 구조**: 새로운 패킷 타입과 게임 로직 쉽게 추가 가능

## 📁 프로젝트 구조

```
gameserver/
├── io/                          # 네트워킹 및 I/O 관련 모듈
│   ├── include/
│   │   ├── buffer_ring.h       # 버퍼 링 관리
│   │   ├── io_uring.h          # io_uring 래퍼
│   │   └── socket.h            # 소켓 추상화
│   ├── buffer_ring.cpp
│   ├── io_uring.cpp
│   └── socket.cpp
├── server/                      # 서버 핵심 로직
│   └── include/
│       ├── message.h           # 게임 패킷 정의
│       └── server.h            # 서버 클래스 정의
├── message.cpp                  # 패킷 파서/빌더 구현
└── server.cpp                   # 메인 서버 구현
```

## 🎮 지원 패킷 타입

- **LOGIN**: 플레이어 로그인 처리
- **GAME_STATE_UPDATE**: 게임 상태 업데이트
- **HEARTBEAT**: 연결 상태 확인
- **PLAYER_MOVE**: 플레이어 위치 업데이트
- **PLAYER_ATTACK**: 플레이어 공격 액션
- **CHAT_MESSAGE**: 채팅 메시지
- **DISCONNECT**: 연결 해제
- **ERROR_RESPONSE**: 에러 응답

## 📦 패킷 구조

모든 게임 패킷은 다음과 같은 헤더 구조를 가집니다:

```
| Packet Type (4 bytes) | Player ID (4 bytes) | Timestamp (8 bytes) | Payload (Variable) |
```

## 🛠️ 빌드 요구사항

- **C++20** 이상
- **Linux** (io_uring 지원)
- **liburing** 라이브러리

## 💡 사용 예시

### 패킷 파싱
```cpp
game_packet_parser parser;
auto context = parser.parse_packet(buffer);
if (context.has_value()) {
    // 패킷 처리 로직
}
```

### 패킷 생성
```cpp
login_request req{"username", "password", 1};
auto packet = game_packet_builder::create_login_packet(player_id, req);
```

## 🔧 개발 상태

현재 개발 중인 프로젝트입니다. 주요 구성 요소들이 구현되어 있지만 추가적인 테스트와 최적화가 필요합니다.

## 📄 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다. 