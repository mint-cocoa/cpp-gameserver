# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a high-performance game server written in modern C++ that uses Linux's io_uring for asynchronous I/O operations. The server is designed to handle many concurrent game client connections with minimal overhead.

## Architecture

The codebase consists of three main components:

1. **I/O Subsystem** (`io/`): Provides C++ wrappers around io_uring for high-performance async I/O
   - Uses coroutines for clean async code
   - Implements zero-copy operations with buffer rings
   - Multishot operations for efficient connection handling

2. **Message Protocol** (`message.cpp`, `server/include/message.h`): Binary protocol for game packets
   - Fixed 16-byte header: packet_type (4) + player_id (4) + timestamp (8)
   - Variable-length payload
   - Packet types: LOGIN, GAME_STATE_UPDATE, HEARTBEAT, PLAYER_MOVE, PLAYER_ATTACK, CHAT_MESSAGE, DISCONNECT, ERROR_RESPONSE

3. **Server Core** (`server.cpp`, `server/include/server.h`): Multi-threaded game server
   - Thread pool architecture with hardware_concurrency threads
   - Each worker handles multiple clients using coroutines
   - Namespace: `co_uring_http` (historical - evolved from HTTP server)

## Build Instructions

**Note**: No build system files currently exist in the repository. To compile this project, you'll need:

- C++20 compatible compiler (GCC 11+ or Clang 13+)
- liburing development headers
- Linux system (io_uring is Linux-specific)

Suggested compilation command pattern:
```bash
g++ -std=c++20 -O3 -pthread -luring -o gameserver server.cpp message.cpp io/*.cpp
```

## Development Notes

- The project uses advanced C++20 features: coroutines, concepts, ranges, std::expected
- Platform: Linux-only due to io_uring dependency
- Performance-critical: Uses zero-copy I/O, multishot operations, and careful memory management
- Empty header files (`socket.h`, `buffer_ring.h`) suggest ongoing development
- Korean comments in some files indicate international development team

## Testing

No test framework is currently set up. When adding tests, consider testing:
- Message serialization/deserialization
- Concurrent connection handling
- io_uring operation completions
- Error handling paths