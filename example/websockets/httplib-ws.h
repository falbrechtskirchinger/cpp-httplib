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



// ----------------------------------------------------------------------------

/*
 * Implementation that will be part of the .cc file if split into .h + .cc.
 */

namespace detail {

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

} // namespace detail

// ----------------------------------------------------------------------------

} // namespace httplib

#endif // CPPHTTPLIB_HTTPLIB_WS_H
