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

#include <queue>
#include <type_traits>

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

enum class WSMessageType {
  Text,
  Binary,
  Ping,
  Pong,
};

using WSMessageHandler =
    std::function<void(std::string msg, WSMessageType msg_type)>;

using WSSubprotocols = std::vector<std::string>;

enum class WSPingAction {
  Ignore,
  AutoReply = 0b01,   // Echo data back as Pong
  CallHandler = 0b10, // Call message handler
  AutoReplyAndCallHandler = AutoReply | CallHandler,
};

enum class WSPongAction {
  Ignore,
  MatchOrClose, // Must match Ping or connection is closed
  CallHandler,  // Call message handler
};

namespace detail {

class NotifyHandle;

inline namespace ws {

struct WSMessage {
  uint16_t cookie;
  uint8_t opcode;
  std::string payload;
};

} // namespace ws

template <bool IsServer> class WSConnectionBase {
public:
  WSConnectionBase() = default;
  WSConnectionBase(const WSConnectionBase &) = delete;
  WSConnectionBase(WSConnectionBase &&) = default;

  bool close(WSCloseCode close_code = WSCloseCode::NormalClosure_1000);
  bool close(WSCloseCode close_code, const char *reason_ptr);
  bool close(WSCloseCode close_code, const char *reason_ptr, size_t reason_len);

  void wait_closed();

  bool send(const char *ptr, size_t size, WSMessageType msg_type);
  bool send(const char *ptr, WSMessageType msg_type = WSMessageType::Text);
  bool send(const std::string &msg, WSMessageType msg_type);
  bool send(std::string &&msg, WSMessageType msg_type);

  bool subprotocol_negotiated() const;
  const std::string &subprotocol() const;

  WSCloseCode close_code() const;
  const std::string &close_reason() const;

  void set_ping_action(WSPingAction action);
  void set_pong_action(WSPongAction action);

protected:
  enum class ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Failed,
  };

  void set_subprotocol(const std::string &subprotocol);

  bool enqueue_msg(detail::WSMessage &&msg, bool wait_proc);

  bool process_websocket(Stream &strm, WSMessageHandler message_handler);
  bool process_websocket_main(Stream &strm,
                              const WSMessageHandler &message_handler);

  std::mutex mutex_;
  std::condition_variable cond_;

  std::queue<detail::WSMessage> msg_queue_;

  std::string subprotocol_;
  mutable std::string close_reason_;

  const detail::NotifyHandle *notify_handle_ = nullptr;

  ConnectionState conn_state_ = ConnectionState::Disconnected;

  WSCloseCode close_code_ = WSCloseCode::NoStatusRcvd_1005;

  WSPingAction ping_action_ = WSPingAction::AutoReply;
  WSPongAction pong_action_ =
      IsServer ? WSPongAction::MatchOrClose : WSPongAction::Ignore;

  // Messages are assigned a cookie to track when they've been processed
  uint16_t msg_cookie_next_ = 0;   // Next cookie value
  uint16_t msg_cookie_result_ = 0; // Result for condition variable

  bool subprotocol_negotiated_ = false;
  bool stop_requested_ = false;
  bool msg_proc_result_ = false; // Cookie'd msg processed OK?

#ifndef NDEBUG
  // Users obtain an unconnected connection object. To prevent hard-to-diagnose
  // issues, enforce calling wait_until_ready() in debug builds
  bool wait_until_ready_called_ = false;
#endif
};

} // namespace detail

class WebSocketClient : public detail::WSConnectionBase<false> {
public:
  // Universal interface
  explicit WebSocketClient(const std::string &scheme_host_port);

  explicit WebSocketClient(const std::string &scheme_host_port,
                           const std::string &client_cert_path,
                           const std::string &client_key_path);

  // WS only interface
  explicit WebSocketClient(const std::string &host, int port);

  explicit WebSocketClient(const std::string &host, int port,
                           const std::string &client_cert_path,
                           const std::string &client_key_path);

  WebSocketClient(WebSocketClient &&) = default;
  WebSocketClient &operator=(WebSocketClient &&) = default;

  ~WebSocketClient();

  bool is_valid() const;

  bool connect(const std::string &path, WSMessageHandler message_handler);
  bool connect(const std::string &path, const Headers &headers,
               const WSSubprotocols &subprotocols,
               WSMessageHandler message_handler);

private:
  bool validate_response(const Response &res, const std::string &ws_key,
                         const WSSubprotocols &subprotocols);

  std::unique_ptr<ClientImpl> cli_;

  std::thread thread_;

  bool is_ssl_ = false;
};

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

template <typename Enum,
          typename std::enable_if<std::is_enum<Enum>::value, int>::type = 0>
bool bitset_is_set(Enum a, Enum b) {
  using T = typename std::underlying_type<Enum>::type;
  return static_cast<T>(a) & static_cast<T>(b);
}

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

template <typename T, size_t N,
          typename std::enable_if<sizeof(T) == 1, int>::type = 0>
inline void apply_mask(const T (&mask)[N], std::string &data) {
  size_t i = 0;
  std::transform(data.begin(), data.end(), data.begin(),
                 [&](char c) mutable -> char { return c ^ mask[i++ % N]; });
}

inline bool write_msg(Stream &strm, WSMessage &msg, bool mask_payload) {
  using namespace ws;

  size_t write_offset = 0;
  WSFrameHeader header;
  uint8_t mask[4]{};
  char buf[sizeof(header) + sizeof(uint64_t) + sizeof(mask)];

  header[0] = WSProto::Header0_IsFinal | msg.opcode;
  header[1] = mask_payload ? WSProto::Header1_IsMasked : 0;
  write_offset = sizeof(header);

  // Write payload length and, if required, extended payload length in network
  // byte order
  if (msg.payload.size() <= 125) {
    header[1] |= static_cast<uint8_t>(msg.payload.size());
  } else if (msg.payload.size() <= std::numeric_limits<uint16_t>::max()) {
    header[1] |= 126;
    uint16_t payload_length = static_cast<uint16_t>(msg.payload.size());
    for (unsigned i = 0; i < sizeof(payload_length); ++i) {
      buf[write_offset + sizeof(payload_length) - i - 1] =
          static_cast<char>(payload_length & 0xff);
      payload_length >>= 8;
    }
    write_offset += sizeof(payload_length);
  } else {
    header[1] |= 127;
    uint64_t payload_length = static_cast<uint64_t>(msg.payload.size());

    if (payload_length & (1ULL << 63)) { return false; }

    for (unsigned i = 0; i < sizeof(payload_length); ++i) {
      buf[write_offset + sizeof(payload_length) - i - 1] =
          static_cast<char>(payload_length & 0xff);
      payload_length >>= 8;
    }
    write_offset += sizeof(payload_length);
  }

  // Copy header, payload length, and maybe mask
  std::memcpy(buf, header, sizeof(header));
  if (mask_payload) {
    random_bytes(reinterpret_cast<char *>(mask), sizeof(mask), false);
    std::memcpy(buf + write_offset, mask, sizeof(mask));
    write_offset += sizeof(mask);
  }
  assert(write_offset <= sizeof(buf));
  // Send it
  if (!write_data(strm, buf, write_offset)) {
    // TODO Report errors like these to the user ... somehow ...
    // WebSocketClient::error()?
    return false;
  }

  // Mask payload if requested and send it
  if (mask_payload) { apply_mask(mask, msg.payload); }
  return write_data(strm, msg.payload.data(), msg.payload.size());
}

inline std::string make_ws_accept(const std::string &ws_key) {
  constexpr const char *ws_accept_magic =
      "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  auto context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>(
      EVP_MD_CTX_new(), EVP_MD_CTX_free);

  unsigned int hash_length = 0;
  unsigned char hash[EVP_MAX_MD_SIZE];

  EVP_DigestInit_ex(context.get(), EVP_sha1(), nullptr);
  EVP_DigestUpdate(context.get(), ws_key.c_str(), ws_key.size());
  EVP_DigestUpdate(context.get(), ws_accept_magic,
                   std::strlen(ws_accept_magic));
  EVP_DigestFinal_ex(context.get(), hash, &hash_length);

  return base64_encode(std::string(hash, hash + hash_length));
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

// WSConnectionBase implementation
template <bool IsServer>
inline bool WSConnectionBase<IsServer>::close(WSCloseCode close_code) {
  return close(close_code, httplib::close_reason(close_code));
}

template <bool IsServer>
inline bool WSConnectionBase<IsServer>::close(WSCloseCode close_code,
                                              const char *reason_ptr) {
  if (reason_ptr) {
    return close(close_code, reason_ptr, std::strlen(reason_ptr));
  } else {
    return close(close_code, nullptr, 0);
  }
}

template <bool IsServer>
inline bool WSConnectionBase<IsServer>::close(WSCloseCode close_code,
                                              const char *reason_ptr,
                                              size_t reason_len) {
  using namespace detail::ws;

  uint16_t temp = ::htons(static_cast<uint16_t>(close_code));
  WSMessage msg;
  msg.opcode = WSProto::OpCode_Close;
  msg.payload.resize(sizeof(temp) + reason_len);
  std::memcpy(&msg.payload[0], &temp, sizeof(temp));
  if (reason_ptr) {
    std::memcpy(&msg.payload[sizeof(temp)], reason_ptr, reason_len);
  }
  return enqueue_msg(std::move(msg), true);
}

template <bool IsServer> inline void WSConnectionBase<IsServer>::wait_closed() {
  std::unique_lock<std::mutex> lock(mutex_);
  cond_.wait(lock,
             [&] { return conn_state_ == ConnectionState::Disconnected; });
}

template <bool IsServer>
inline bool WSConnectionBase<IsServer>::send(const char *ptr, size_t size,
                                             WSMessageType msg_type) {
  using namespace detail::ws;

  WSMessage msg;
  msg.opcode = msg_type == WSMessageType::Text ? WSProto::OpCode_Text
                                               : WSProto::OpCode_Binary;
  msg.payload.assign(ptr, size);
  return enqueue_msg(std::move(msg), true);
}

template <bool IsServer>
inline bool WSConnectionBase<IsServer>::send(const char *ptr,
                                             WSMessageType msg_type) {
  return send(ptr, std::strlen(ptr), msg_type);
}

template <bool IsServer>
inline bool WSConnectionBase<IsServer>::send(const std::string &msg,
                                             WSMessageType msg_type) {
  using namespace detail::ws;

  WSMessage ws_msg;
  ws_msg.opcode = msg_type == WSMessageType::Text ? WSProto::OpCode_Text
                                                  : WSProto::OpCode_Binary;
  ws_msg.payload = msg;
  return enqueue_msg(std::move(ws_msg), true);
}

template <bool IsServer>
inline bool WSConnectionBase<IsServer>::send(std::string &&msg,
                                             WSMessageType msg_type) {
  using namespace detail::ws;

  WSMessage ws_msg;
  ws_msg.opcode = msg_type == WSMessageType::Text ? WSProto::OpCode_Text
                                                  : WSProto::OpCode_Binary;
  ws_msg.payload = std::move(msg);
  return enqueue_msg(std::move(ws_msg), true);
}

template <bool IsServer>
inline bool WSConnectionBase<IsServer>::subprotocol_negotiated() const {
  return subprotocol_negotiated_;
}

template <bool IsServer>
inline const std::string &WSConnectionBase<IsServer>::subprotocol() const {
  return subprotocol_;
}

template <bool IsServer>
inline WSCloseCode WSConnectionBase<IsServer>::close_code() const {
  return close_code_;
}

template <bool IsServer>
inline const std::string &WSConnectionBase<IsServer>::close_reason() const {
  if (close_reason_.empty()) {
    close_reason_ = httplib::close_reason(close_code_);
  }
  return close_reason_;
}

template <bool IsServer>
inline void WSConnectionBase<IsServer>::set_ping_action(WSPingAction action) {
  ping_action_ = action;
}

template <bool IsServer>
inline void WSConnectionBase<IsServer>::set_pong_action(WSPongAction action) {
  pong_action_ = action;
}

template <bool IsServer>
inline void
WSConnectionBase<IsServer>::set_subprotocol(const std::string &subprotocol) {
  subprotocol_ = subprotocol;
  subprotocol_negotiated_ = true;
}

template <bool IsServer>
inline bool WSConnectionBase<IsServer>::enqueue_msg(detail::WSMessage &&msg,
                                                    bool wait_proc) {
  std::unique_lock<std::mutex> lock(mutex_);

  assert(!IsServer || (IsServer && wait_until_ready_called_));
  if (notify_handle_ == nullptr) { return false; }

  // Set cookie
  uint16_t cookie = 0;
  if (wait_proc) {
    msg_cookie_next_ += 1;
    if (msg_cookie_next_ == 0) { msg_cookie_next_ = 1; }
    cookie = msg_cookie_next_;
  }
  msg.cookie = cookie;

  msg_queue_.push(std::move(msg));
  notify_handle_->notify();
  if (wait_proc) {
    // TODO Dead-lock check in debug mode
    cond_.wait(lock, [&] {
      return msg_cookie_result_ == cookie ||
             conn_state_ != ConnectionState::Connected;
    });
    msg_cookie_result_ = 0;
    if (conn_state_ != ConnectionState::Connected) {
      // Clear queue
      if (!msg_queue_.empty()) { std::queue<WSMessage>().swap(msg_queue_); }
      return false;
    }
    return msg_proc_result_;
  }
  return true;
}

template <bool IsServer>
inline bool WSConnectionBase<IsServer>::process_websocket(
    Stream &strm, WSMessageHandler message_handler) {
  NotifyHandle notify_handle{};
  if (!notify_handle.is_valid()) { return false; }

  {
    std::lock_guard<std::mutex> guard(mutex_);
    notify_handle_ = &notify_handle;
    conn_state_ = ConnectionState::Connected;
  }
  cond_.notify_all();
  bool ret = process_websocket_main(strm, message_handler);
  {
    std::lock_guard<std::mutex> guard(mutex_);
    conn_state_ = ConnectionState::Disconnected;
    notify_handle_ = nullptr;
  }
  cond_.notify_all();

  return ret;
}

template <bool IsServer>
inline bool WSConnectionBase<IsServer>::process_websocket_main(
    Stream &strm, const WSMessageHandler &message_handler) {
  using namespace ws;

  bool readable, readable_buffered, notified = false;
  WSReader reader(strm, IsServer);
  WSMessage msg;
  bool proc_msg = false;

  auto stream_is_readable_or_notified = [&]() -> bool {
    return select_read(strm.socket(), notify_handle_->fd(),
                       static_cast<time_t>(-1), 0, readable, notified) > 0;
  };
  auto check_notified = [&]() {
    notified = select_read(notify_handle_->fd(), 0, 0) > 0;
  };
  auto dispatch_msg = [&](std::string &msg, WSMessageType msg_type) {
    // TODO This is just a crude hack to prevent dead-locks
    // Users should be able to choose between different dispatch options:
    // - same thread (can dead-lock, but users may wish to hand off to their own
    //   thread pool, etc.)
    // - internal thread pool
    std::thread(
        [&](std::string &&msg, WSMessageType msg_type) {
          message_handler(std::move(msg), msg_type);
        },
        std::move(msg), msg_type)
        .detach();
  };
  auto close_internal = [&](WSCloseCode close_code,
                            const char *reason_ptr = nullptr, size_t len = 0) {
    const char *reason =
        reason_ptr ? reason_ptr : httplib::close_reason(close_code);
    auto reason_len = reason_ptr ? len : std::strlen(reason);
    uint16_t temp = ::htons(static_cast<uint16_t>(close_code));
    WSMessage msg;
    msg.opcode = WSProto::OpCode_Close;
    msg.payload.resize(sizeof(temp) + reason_len);
    std::memcpy(&msg.payload[0], &temp, sizeof(temp));
    std::memcpy(&msg.payload[sizeof(temp)], reason, reason_len);
    enqueue_msg(std::move(msg), false);
  };

  std::unique_lock<std::mutex> lock(mutex_, std::defer_lock);
  while (true) {
    // Check if there's anything to read, or if we've been notified, unless the
    // connection is closing
    if (!reader.is_closing_await_send()) {
      readable = false;
      readable_buffered = strm.nonblocking_read_size() > 0;
      if (readable_buffered) {
        // Reading from the buffer; ensure we don't fall behind on notifications
        check_notified();
      } else if (!stream_is_readable_or_notified()) {
        continue; // Timed out
      }
      if (notified) {
        notify_handle_->clear();
        assert(!lock);
        lock.lock();
        if (stop_requested_) { return true; }
        // Release or continue holding the lock depending on whether we're going
        // to read or process messages next
        if (proc_msg) { lock.unlock(); }
      }

      // Alternate between reading and processing messages
      // not notified => always read
      // notified and proc_msg because we just processed one => read
      // notified and not proc_msg because we just read => process messages
      if ((!notified || (notified && proc_msg)) &&
          (readable || readable_buffered)) {
        WSReadResult result;
        do {
          result = reader.read(readable);
          if (result == WSReadResult::Error) {
            // frame failed validation; proper close code should have been set
            assert(reader.close_code() != WSCloseCode::NoStatusRcvd_1005);
            if (reader.close_code() != WSCloseCode::AbnormalClosure_1006) {
              reader.is_closing_await_recv(true);
              close_internal(reader.close_code());
            } else {
              // Connection closed abnormally; nothing left to do
              return false;
            }
          }
        } while (result == WSReadResult::Again);
        auto &frame = reader.current_frame();
        if (frame.is_complete) { // Complete frame read
          if (IsServer) { apply_mask(frame.mask, frame.payload); }
          switch (frame.opcode) {
          case WSProto::OpCode_Text:
          case WSProto::OpCode_Binary:
            dispatch_msg(frame.payload, frame.opcode == WSProto::OpCode_Text
                                            ? WSMessageType::Text
                                            : WSMessageType::Binary);
            break;
          case WSProto::OpCode_Close:
            if (reader.is_closing_await_recv()) {
              // Server responded to our close frame; we're done
              // TODO Record close code and reason
              return true;
            } else {
              const char *reason = nullptr;
              size_t len = 0;
              uint16_t temp;
              WSCloseCode close_code = WSCloseCode::NormalClosure_1000;
              if (frame.payload.size() >= sizeof(temp)) {
                std::memcpy(&temp, &frame.payload[0], sizeof(temp));
                close_code = static_cast<WSCloseCode>(::ntohs(temp));
                if (frame.payload.size() > sizeof(temp)) {
                  reason = &frame.payload[sizeof(temp)];
                  len = frame.payload.size() - sizeof(temp);
                }
              }
              reader.is_closing_await_send(true);
              close_internal(close_code, reason, len);
            }
            break;
          case WSProto::OpCode_Ping:
            if (bitset_is_set(ping_action_, WSPingAction::CallHandler)) {
              // Note that callee can modify the application data, before it
              // is sent back, if AutoReply is enabled
              dispatch_msg(frame.payload, WSMessageType::Ping);
            }
            if (bitset_is_set(ping_action_, WSPingAction::AutoReply)) {
              WSMessage pong;
              pong.opcode = WSProto::OpCode_Pong;
              pong.payload = std::move(frame.payload);
              enqueue_msg(std::move(pong), false);
            }
            break;
          case WSProto::OpCode_Pong:
            // TODO Implement pong action
            break;
          default:
            reader.is_closing_await_send(true);
            close_internal(WSCloseCode::ProtocolError_1002);
            break;
          }
        }
      }

      if (!notified) {
        proc_msg = false;
        continue;
      }
    }

    // Process message queue
    {
      assert(!proc_msg || (proc_msg && !lock));
      if (!lock) { lock.lock(); }
      proc_msg = !msg_queue_.empty();
      if (proc_msg) {
        msg = std::move(msg_queue_.front());
        msg_queue_.pop();
      }
      lock.unlock();
    }

    if (proc_msg) {
      if (msg.opcode == WSProto::OpCode_Close &&
          !reader.is_closing_await_send()) {
        // We're about to initiate a close; wait for the server to respond
        // if the close was initiated by the user, this hasn't been set yet
        reader.is_closing_await_recv(true);
      }

      uint16_t cookie = msg.cookie;
      bool ret = write_msg(strm, msg, !IsServer);
      {
        // Report result back to caller
        lock.lock();
        msg_cookie_result_ = cookie;
        msg_proc_result_ = ret;
        lock.unlock();
      }
      cond_.notify_all();
      if (!ret) { return false; }

      if (msg.opcode == WSProto::OpCode_Close &&
          reader.is_closing_await_send()) {
        // Closing handshake complete (initiated by remote)
        return true;
      }
    } else if (reader.is_closing_await_send()) {
      // This case should not happen; i.e., waiting to send a close frame, but
      // the send queue is empty
      assert(false);
      return false;
    }
  }

  // We should never reach here
  assert(false);
  return false;
}

} // namespace detail

// WebSocket client implementation
inline WebSocketClient::WebSocketClient(const std::string &scheme_host_port)
    : WebSocketClient(scheme_host_port, std::string(), std::string()) {}

inline WebSocketClient::WebSocketClient(const std::string &scheme_host_port,
                                        const std::string &client_cert_path,
                                        const std::string &client_key_path) {
  const static std::regex re(
      R"((?:([a-z]+):\/\/)?(?:\[([a-fA-F\d:]+)\]|([^:/?#]+))(?::(\d+))?)");

  std::smatch m;
  if (std::regex_match(scheme_host_port, m, re)) {
    auto scheme = m[1].str();

    if (!scheme.empty() && (scheme != "ws" && scheme != "wss")) {
#ifndef CPPHTTPLIB_NO_EXCEPTIONS
      std::string msg = "'" + scheme + "' scheme is not supported.";
      throw std::invalid_argument(msg);
#endif
      return;
    }

    is_ssl_ = scheme == "wss";

    auto host = m[2].str();
    if (host.empty()) { host = m[3].str(); }

    auto port_str = m[4].str();
    auto port = !port_str.empty() ? std::stoi(port_str) : (is_ssl_ ? 443 : 80);

    if (is_ssl_) {
      cli_ = detail::make_unique<SSLClient>(host, port, client_cert_path,
                                            client_key_path);
    } else {
      cli_ = detail::make_unique<ClientImpl>(host, port, client_cert_path,
                                             client_key_path);
    }
  } else {
    cli_ = detail::make_unique<ClientImpl>(scheme_host_port, 80,
                                           client_cert_path, client_key_path);
  }
}

inline WebSocketClient::WebSocketClient(const std::string &host, int port)
    : cli_(detail::make_unique<ClientImpl>(host, port)) {}

inline WebSocketClient::WebSocketClient(const std::string &host, int port,
                                        const std::string &client_cert_path,
                                        const std::string &client_key_path)
    : cli_(detail::make_unique<ClientImpl>(host, port, client_cert_path,
                                           client_key_path)) {}

inline WebSocketClient::~WebSocketClient() {
  if (thread_.joinable()) {
    {
      std::lock_guard<std::mutex> guard(mutex_);
      if (notify_handle_ != nullptr) {
        stop_requested_ = true;
        notify_handle_->notify();
      }
    }
    thread_.join();
  }
}

inline bool WebSocketClient::is_valid() const {
  return cli_ != nullptr && cli_->is_valid();
}

inline bool WebSocketClient::connect(const std::string &path,
                                     WSMessageHandler message_handler) {
  return connect(path, Headers{}, WSSubprotocols{}, std::move(message_handler));
}

inline bool WebSocketClient::connect(const std::string &path,
                                     const Headers &headers,
                                     const WSSubprotocols &subprotocols,
                                     WSMessageHandler message_handler) {
  {
    std::lock_guard<std::mutex> guard(mutex_);
    if (!(conn_state_ == ConnectionState::Disconnected ||
          conn_state_ == ConnectionState::Failed)) {
      return false;
    }
    conn_state_ = ConnectionState::Connecting;
    // No need to notify here
  }

  // Don't send stale messages
  if (!msg_queue_.empty()) { std::queue<detail::WSMessage>().swap(msg_queue_); }

  auto ws_key = detail::base64_encode(detail::random_string(16));

  Request req;
  req.method = "GET";
  req.path = path;
  req.headers = headers;
  req.headers.emplace("Connection", "upgrade");
  req.headers.emplace("Upgrade", "websocket");
  req.headers.emplace("Sec-WebSocket-Version", "13");
  req.headers.emplace("Sec-WebSocket-Key", ws_key);

  if (!subprotocols.empty()) {
    std::stringstream ss;
    for (size_t i = 0, last = subprotocols.size() - 1; i <= last; ++i) {
      ss << subprotocols[i];
      if (i != last) { ss << ", "; }
    }
    req.headers.emplace("Sec-WebSocket-Protocol", ss.str());
  }

  req.response_handler = [&, this](const Response &res) {
    return validate_response(res, ws_key, subprotocols);
  };

  req.stream_handler = [&, this](Stream &strm) -> bool {
    return process_websocket(strm, std::move(message_handler));
  };

  thread_ = std::thread([&, this]() {
    Response res;
    Error error;
    // On success, our stream_handler will be called, which updates state and
    // notifies; on failure, we'll update state and notify here
    if (!cli_->send(req, res, error)) {
      {
        std::lock_guard<std::mutex> guard(mutex_);
        conn_state_ = ConnectionState::Failed;
      }
      cond_.notify_all();
    }
  });

  {
    std::unique_lock<std::mutex> lock(mutex_);
    cond_.wait(lock,
               [&] { return conn_state_ != ConnectionState::Connecting; });
    if (conn_state_ == ConnectionState::Failed) {
      return false;
    } else if (conn_state_ == ConnectionState::Connected) {
      return true;
    } else {
      // At this point, we should either be connected or have failed to connect
      assert(false);
    }
  }

  return false;
}

inline bool
WebSocketClient::validate_response(const Response &res,
                                   const std::string &ws_key,
                                   const WSSubprotocols &subprotocols) {
  if (res.status != StatusCode::SwitchingProtocol_101) { return false; }

  // TODO Rewrite once utility functions for proper handling become available
  // I.e., this ignores field repetitions and comma-separated values
  if (!res.has_header("Connection") ||
      !detail::case_ignore::equal(res.get_header_value("Connection"),
                                  "upgrade")) {
    return false;
  }
  if (!res.has_header("Upgrade") ||
      !detail::case_ignore::equal(res.get_header_value("Upgrade"),
                                  "websocket")) {
    return false;
  }
  if (res.has_header("Sec-WebSocket-Version") &&
      res.get_header_value("Sec-WebSocket-Version") != "13") {
    return false;
  }

  // We requested no extensions
  if (res.has_header("Sec-WebSocket-Extensions")) { return false; }

  if (!res.has_header("Sec-WebSocket-Accept")) { return false; }
  auto ws_accept = res.get_header_value("Sec-WebSocket-Accept");
  auto ws_accept_expected = detail::make_ws_accept(ws_key);
  if (ws_accept != ws_accept_expected) { return false; }

  if (res.has_header("Sec-WebSocket-Protocol")) {
    // Server MUST send at most ONE protocol field
    if (res.get_header_value_count("Sec-WebSocket-Protocol") > 1) {
      return false;
    }

    const auto &subprotocol = res.get_header_value("Sec-WebSocket-Protocol");
    if (std::find(subprotocols.begin(), subprotocols.end(), subprotocol) ==
        subprotocols.end()) {
      return false;
    }
    set_subprotocol(subprotocol);
  }

  return true;
}

// ----------------------------------------------------------------------------

} // namespace httplib

#endif // CPPHTTPLIB_HTTPLIB_WS_H
