//
//  httplib-ws.h
//
//  Copyright (c) 2025 Florian Albrechtskirchinger. All rights reserved.
//  MIT License
//

#ifndef CPPHTTPLIB_HTTPLIB_WS_H
#define CPPHTTPLIB_HTTPLIB_WS_H

/*
 * Configuration
 */

#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
#error CPPHTTPLIB_OPENSSL_SUPPORT is required
#endif

/*
 * Headers
 */

#include "httplib.h"

/*
 * Declaration
 */

namespace httplib {

// See https://www.iana.org/assignments/websocket/websocket.xhtml
enum class WSCloseCode {
  NormalClosure_1000 = 1000,
  GoingAway_1001 = 1001,
  ProtocolError_1002 = 1002,
  UnsupportedData_1003 = 1003,
  // Reserved = 1004,
  NoStatusRcvd_1005 = 1005,    // internal
  AbnormalClosure_1006 = 1006, // internal
  InvalidFramePayloadData_1007 = 1007,
  PolicyViolation_1008 = 1008,
  MessageTooBig_1009 = 1009,
  MandatoryExtension_1010 = 1010,
  InternalError_1011 = 1011,
  ServiceRestart_1012 = 1012,
  TryAgainLater_1013 = 1013,
  BadGateway_1014 = 1014,
  TLSHandshake_1015 = 1015, // internal
};

const char *close_reason(WSCloseCode close_code);

std::string to_string(WSCloseCode close_code);

// ----------------------------------------------------------------------------

/*
 * Implementation that will be part of the .cc file if split into .h + .cc.
 */

inline const char *close_reason(WSCloseCode close_code) {
  switch (close_code) {
  case WSCloseCode::NormalClosure_1000: return "Normal Closure";
  case WSCloseCode::GoingAway_1001: return "Going Away";
  case WSCloseCode::ProtocolError_1002: return "ProtocolErrory";
  case WSCloseCode::UnsupportedData_1003: return "UnsupportedData";
  // Reserved 1004
  case WSCloseCode::NoStatusRcvd_1005: return "No Status Rcvd (Internal)";
  case WSCloseCode::AbnormalClosure_1006: return "Abnormal Closure (Internal)";
  case WSCloseCode::InvalidFramePayloadData_1007:
    return "Invalid Frame Payload Data";
  case WSCloseCode::PolicyViolation_1008: return "Policy Violation";
  case WSCloseCode::MessageTooBig_1009: return "Message Too Big";
  case WSCloseCode::MandatoryExtension_1010: return "Mandatory Extension";
  default:
  case WSCloseCode::InternalError_1011: return "Internal Error";
  case WSCloseCode::ServiceRestart_1012: return "Service Restart";
  case WSCloseCode::TryAgainLater_1013: return "Try Again Later";
  case WSCloseCode::BadGateway_1014: return "Bad Gateway";
  case WSCloseCode::TLSHandshake_1015: return "TLS Handshake (Internal)";
  }
}

inline std::string to_string(WSCloseCode close_code) {
  return close_reason(close_code);
}

namespace detail {

inline namespace ws {

namespace WSProto {

enum Mask : uint8_t {
  Header0_IsFinal /*         */ = 0b10000000,
  Header0_Reserved /*        */ = 0b01110000,
  Header0_OpCode /*          */ = 0b00001111,
  Header0_OpCode_IsControl /**/ = 0b00001000,
  Header1_IsMasked /*        */ = 0b10000000,
  Header1_PayloadLength /*   */ = 0b01111111,
};

enum OpCode : uint8_t {
  OpCode_None = 0x00,
  OpCode_Continuation = 0x00,
  OpCode_Text = 0x01,
  OpCode_Binary = 0x02,
  OpCode_Close = 0x08,
  OpCode_Ping = 0x09,
  OpCode_Pong = 0x0a,
};

} // namespace WSProto

using WSFrameHeader = uint8_t[2];

} // namespace ws

inline bool pipe(socket_t fds[2]) {
  fds[0] = fds[1] = INVALID_SOCKET;

#if defined(__linux__) && defined(_GNU_SOURCE)
  if (::pipe2(fds, O_CLOEXEC | O_NONBLOCK) < 0) { return false; }
#elif !defined(_WIN32)
  if (::pipe(fds) < 0) { return false; }
  if (::fcntl(fds[0], F_SETFD, FD_CLOEXEC) < 0) { return false; }
  if (::fcntl(fds[0], F_SETFL, O_NONBLOCK) < 0) { return false; }
  if (::fcntl(fds[1], F_SETFD, FD_CLOEXEC) < 0) { return false; }
  if (::fcntl(fds[1], F_SETFL, O_NONBLOCK) < 0) { return false; }
#else
  return false;
#endif

  return true;
}

inline bool socketpair_inet(socket_t socks[2]) {
  socks[0] = socks[1] = INVALID_SOCKET;

  socket_t lsock = INVALID_SOCKET, ssock = INVALID_SOCKET,
           csock = INVALID_SOCKET;

  auto se = scope_exit([&]() {
    if (lsock != INVALID_SOCKET) { close_socket(lsock); }
    if (ssock != INVALID_SOCKET) { close_socket(ssock); }
    if (csock != INVALID_SOCKET) { close_socket(csock); }
  });

  lsock = ::socket(AF_INET, SOCK_STREAM, 0);
  csock = ::socket(AF_INET, SOCK_STREAM, 0);
  if (lsock == INVALID_SOCKET || csock == INVALID_SOCKET) { return false; }

  int opt = 1;
  if (::setsockopt(lsock, SOL_SOCKET,
#if defined(_WIN32) || !defined(SO_REUSEPORT)
                   SO_REUSEADDR,
#else
                   SO_REUSEPORT,
#endif
                   &opt, sizeof(opt))) {
    return false;
  }

  struct sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;

  if (::bind(lsock, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr))) {
    return false;
  }
  if (::listen(lsock, 1)) { return false; }

  socklen_t addrlen = sizeof(addr);
  if (::getsockname(lsock, reinterpret_cast<struct sockaddr *>(&addr),
                    &addrlen)) {
    return false;
  }
  if (::connect(csock, reinterpret_cast<struct sockaddr *>(&addr),
                sizeof(addr))) {
    return false;
  }
  ssock = ::accept(lsock, NULL, NULL);

  // Pedantic check against CVEs like CVE-2024-3219
  auto auth_connection = [](socket_t sock, socket_t peer) -> bool {
    struct sockaddr_in sock_addr, peer_addr;
    socklen_t sock_addrlen = sizeof(sock_addr),
              peer_addrlen = sizeof(peer_addr);

    if (::getsockname(sock, reinterpret_cast<struct sockaddr *>(&sock_addr),
                      &sock_addrlen)) {
      return false;
    }
    if (::getpeername(peer, reinterpret_cast<struct sockaddr *>(&peer_addr),
                      &peer_addrlen)) {
      return false;
    }

    if (sock_addrlen != peer_addrlen) { return false; }
    return std::memcmp(&sock_addr, &peer_addr, sock_addrlen) == 0;
  };

  if (!auth_connection(ssock, csock) || !auth_connection(csock, ssock)) {
    return false;
  }

  set_nonblocking(ssock, true);
  set_nonblocking(csock, true);
  socks[0] = csock;
  socks[1] = ssock;
  ssock = csock = INVALID_SOCKET; // Prevent closing on scope exit

  return true;
}

class NotifyHandle {
public:
  NotifyHandle();
  NotifyHandle(const NotifyHandle &) = delete;
  NotifyHandle(NotifyHandle &&) noexcept;
  ~NotifyHandle();

  NotifyHandle &operator=(const NotifyHandle &) = delete;
  NotifyHandle &operator=(NotifyHandle &&) noexcept;

  bool is_valid() const;

  socket_t fd() const;

  bool notify() const;
  bool clear() const;

  void destroy();

private:
  socket_t fds_[2];
};

// NotifyHandle implementation
inline NotifyHandle::NotifyHandle() {
#ifdef _WIN32
  socketpair_inet(fds_);
#else
  pipe(fds_);
#endif
}

inline NotifyHandle::NotifyHandle(NotifyHandle &&other) noexcept {
  std::memcpy(fds_, other.fds_, sizeof(fds_));
  other.fds_[0] = other.fds_[1] = INVALID_SOCKET;
}

inline NotifyHandle::~NotifyHandle() { destroy(); }

inline NotifyHandle &NotifyHandle::operator=(NotifyHandle &&other) noexcept {
  if (this != &other) {
    destroy();
    std::memcpy(fds_, other.fds_, sizeof(fds_));
    other.fds_[0] = other.fds_[1] = INVALID_SOCKET;
  }
  return *this;
}

inline bool NotifyHandle::is_valid() const {
  return fds_[0] != INVALID_SOCKET && fds_[1] != INVALID_SOCKET;
}

inline int NotifyHandle::fd() const { return fds_[0]; }

inline bool NotifyHandle::notify() const {
  const char buf[1]{};
#ifdef _WIN32
  return send_socket(fds_[1], buf, sizeof(buf)) == sizeof(buf);
#else
  return ::write(fds_[1], buf, sizeof(buf)) == sizeof(buf);
#endif
}

inline bool NotifyHandle::clear() const {
  char buf[1]{};
#ifdef _WIN32
  return read_socket(fds_[0], buf, sizeof(buf)) == sizeof(buf);
#else
  return ::read(fds_[0], buf, sizeof(buf)) == sizeof(buf);
#endif
}

inline void NotifyHandle::destroy() {
#ifdef _WIN32
  if (fds_[0] != INVALID_SOCKET) { close_socket(fds_[0]); }
  if (fds_[1] != INVALID_SOCKET) { close_socket(fds_[1]); }
#else
  if (fds_[0] != INVALID_SOCKET) { ::close(fds_[0]); }
  if (fds_[1] != INVALID_SOCKET) { ::close(fds_[1]); }
#endif

  fds_[0] = fds_[1] = INVALID_SOCKET;
}

inline namespace ws {

enum class WSReadResult {
  Error,
  Again,
  Stop,
};

using WSFrameHeader = uint8_t[2];

} // namespace ws

enum class WSReadState {
  NewFrame,
  NewFrameResume, // Resume fragmented message after having reveived a control
                  // frame
  NewFrameContinuation,
  Header,
  PayloadLength16,
  PayloadLength64,
  Mask,
  Payload,
};

struct WSFrame {
  WSReadState read_state;
  WSFrameHeader header;
  uint8_t opcode;
  bool is_final;
  bool is_masked;
  bool is_complete;
  uint8_t mask[4];
  uint64_t payload_length;
  std::string payload;
};

class WSReader {
public:
  WSReader(Stream &strm, bool expect_masked);

  WSReadResult read(bool readable);

  WSCloseCode close_code() const;

  WSFrame &current_frame();

  bool is_closing_await_recv() const;
  void is_closing_await_recv(bool is_closing);

  bool is_closing_await_send() const;
  void is_closing_await_send(bool is_closing);

private:
  bool read_next_bytes(bool readable, char *buf_ptr);
  bool handle_payload_length();

  Stream *strm_;
  WSFrame storage_[2]{};
  WSFrame *frame_;  // Two frames to support control frames
  WSFrame *frame2_; // in the middle of fragmented messages

  char buffer_[sizeof(uint64_t)];

  size_t read_offset_;
  size_t read_length_;
  size_t saved_read_offset_; // Used to save payload length/offset
  size_t saved_read_length_; // when reading mask before payload

  WSCloseCode close_code_ = WSCloseCode::NoStatusRcvd_1005;
  bool expect_masked_;
  bool read_complete_;
  bool is_closing_await_recv_ = false; // Whether we sent a close frame and
                                       // are waiting for our peer to respond
  bool is_closing_await_send_ = false; // Whether we received a close frame
                                       // and still have to respond
};

// WSReader implementation
WSReader::WSReader(Stream &strm, bool expect_masked)
    : strm_(&strm), frame_(&storage_[0]), frame2_(&storage_[1]),
      expect_masked_(expect_masked) {}

WSReadResult WSReader::read(bool readable) {
  using namespace ws;

  switch (frame_->read_state) {
  case WSReadState::NewFrame:
  case WSReadState::NewFrameResume:
    if (frame_->read_state == WSReadState::NewFrame) {
      frame_->opcode = WSProto::OpCode_None;
      frame_->is_complete = false;
      frame_->payload.clear();
    } else {
      // A fragmented message was interrupted by a control frame
      // Reset opcode on current/control frame, keep opcode on new frame for
      // continuation
      frame_->opcode = WSProto::OpCode_None;
      std::swap(frame_, frame2_);
    }
    // Fallthrough
  case WSReadState::NewFrameContinuation:
    read_offset_ = 0;
    read_length_ = sizeof(frame_->header);
  // Fallthrough
  case WSReadState::Header:
    if (!read_next_bytes(readable, buffer_)) { return WSReadResult::Error; }
    if (read_complete_) {
      WSFrameHeader header;
      std::memcpy(header, buffer_, sizeof(header));

      // Reserved bits MUST be zero
      if (header[0] & WSProto::Header0_Reserved) {
        close_code_ = WSCloseCode::ProtocolError_1002;
        return WSReadResult::Error;
      }

      // Is this a control frame interrupting a fragmented message?
      if (frame_->opcode != WSProto::OpCode_None &&
          header[0] & WSProto::Header0_OpCode_IsControl) {
        // Keep current opcode for continuation, reset opcode on new frame
        std::swap(frame_, frame2_);
        frame_->opcode = WSProto::OpCode_None;
      }

      std::memcpy(frame_->header, header, sizeof(header));
      frame_->is_final = frame_->header[0] & WSProto::Header0_IsFinal;

      // Validate opcode
      uint8_t opcode = frame_->header[0] & WSProto::Header0_OpCode;
      if (opcode == WSProto::OpCode_Continuation) {
        if (frame_->opcode == WSProto::OpCode_Continuation) {
          // Nothing to continue
          close_code_ = WSCloseCode::ProtocolError_1002;
          return WSReadResult::Error;
        }
      } else {
        frame_->opcode = opcode;
      }

      frame_->is_masked = frame_->header[1] & WSProto::Header1_IsMasked;
      frame_->payload_length =
          frame_->header[1] & WSProto::Header1_PayloadLength;

      // Control frames MUST NOT be fragmented
      if (frame_->opcode & WSProto::Header0_OpCode_IsControl &&
          !frame_->is_final) {
        close_code_ = WSCloseCode::ProtocolError_1002;
        return WSReadResult::Error;
      }

      // Frames from server to client MUST NOT be masked
      if (frame_->is_masked != expect_masked_) {
        close_code_ = WSCloseCode::ProtocolError_1002;
        return WSReadResult::Error;
      }

      // Select next state
      read_offset_ = 0;
      if (frame_->payload_length == 126) {
        read_length_ = sizeof(uint16_t);
        frame_->read_state = WSReadState::PayloadLength16;
      } else if (frame_->payload_length == 127) {
        read_length_ = sizeof(uint64_t);
        frame_->read_state = WSReadState::PayloadLength64;
      } else if (!handle_payload_length()) {
        return WSReadResult::Error;
      }
    }
    break;
  case WSReadState::PayloadLength16:
    if (!read_next_bytes(readable, buffer_)) { return WSReadResult::Error; }
    if (read_complete_) {
      uint16_t payload_length;
      std::memcpy(&payload_length, buffer_, sizeof(payload_length));
      frame_->payload_length = ::ntohs(payload_length);
      if (!handle_payload_length()) { return WSReadResult::Error; }
    }
    break;
  case WSReadState::PayloadLength64:
    if (!read_next_bytes(readable, buffer_)) { return WSReadResult::Error; }
    if (read_complete_) {
      frame_->payload_length = std::accumulate(
          buffer_, buffer_ + sizeof(frame_->payload_length),
          static_cast<uint64_t>(0), [](uint64_t len, char b) {
            return (len << 8) | static_cast<uint64_t>(static_cast<uint8_t>(b));
          });
      if (!handle_payload_length()) { return WSReadResult::Error; }
    }
    break;
  case WSReadState::Mask:
    if (!read_next_bytes(readable, buffer_)) { return WSReadResult::Error; }
    if (read_complete_) {
      std::memcpy(frame_->mask, buffer_, sizeof(frame_->mask));
      // Select next state
      read_offset_ = saved_read_offset_;
      read_length_ = saved_read_length_;
      frame_->read_state = WSReadState::Payload;
    }
    break;
  case WSReadState::Payload:
    if (!read_next_bytes(readable, &frame_->payload[0])) {
      return WSReadResult::Error;
    }
    if (read_complete_) {
      // Select next state
      if (frame_->is_final) {
        frame_->is_complete = true;

        // Did a control frame interrupt a fragmented message?
        if (frame_->opcode & WSProto::Header0_OpCode_IsControl &&
            frame2_->opcode != WSProto::OpCode_None) {
          frame_->read_state = WSReadState::NewFrameResume;
        } else {
          frame_->read_state = WSReadState::NewFrame;
        }
      } else {
        frame_->read_state = WSReadState::NewFrameContinuation;
      }
    }
    break;
  default:
    assert(false); // Should never happen
    return WSReadResult::Error;
  }

  // If a read was fully satisfied, but didn't yield a complete message, try
  // reading again
  return (read_complete_ && !frame_->is_complete) ? WSReadResult::Again
                                                  : WSReadResult::Stop;
}

inline WSCloseCode WSReader::close_code() const { return close_code_; }

inline WSFrame &WSReader::current_frame() { return *frame_; }

inline bool WSReader::is_closing_await_recv() const {
  return is_closing_await_recv_;
}

inline void WSReader::is_closing_await_recv(bool is_closing) {
  is_closing_await_recv_ = is_closing;
}

inline bool WSReader::is_closing_await_send() const {
  return is_closing_await_send_;
}

inline void WSReader::is_closing_await_send(bool is_closing) {
  is_closing_await_send_ = is_closing;
}

inline bool WSReader::read_next_bytes(bool readable, char *buf_ptr) {
  size_t read_length =
      readable ? read_length_
               : (std::min)(read_length_, strm_->nonblocking_read_size());
  ssize_t n = strm_->read(buf_ptr + read_offset_, read_length);
  if (n <= 0) { // Read failed
    close_code_ = WSCloseCode::AbnormalClosure_1006;
    return false;
  }

  read_offset_ += n;
  read_length_ -= n;
  read_complete_ = read_length_ == 0;

  return true;
}

inline bool WSReader::handle_payload_length() {
  size_t total_length =
      frame_->payload.size() + static_cast<size_t>(frame_->payload_length);
  if ((frame_->payload_length & (1ULL << 63)) || // MSB MUST be zero
      frame_->payload_length > (std::numeric_limits<size_t>::max)() ||
      total_length < frame_->payload.size() || // Check overflow
      total_length > frame_->payload.max_size() ||
      frame_->payload_length > CPPHTTPLIB_PAYLOAD_MAX_LENGTH) {
    close_code_ = WSCloseCode::MessageTooBig_1009;
    return false;
  }

  // Select next state
  saved_read_offset_ = frame_->payload.size();
  saved_read_length_ = static_cast<size_t>(frame_->payload_length);
  frame_->payload.resize(total_length);
  if (frame_->is_masked) {
    read_offset_ = 0;
    read_length_ = sizeof(frame_->mask);
    frame_->read_state = WSReadState::Mask;
  } else {
    read_offset_ = saved_read_offset_;
    read_length_ = saved_read_length_;
    frame_->read_state = WSReadState::Payload;
  }

  return true;
}

} // namespace detail

// ----------------------------------------------------------------------------

} // namespace httplib

#endif // CPPHTTPLIB_HTTPLIB_WS_H
