// Netify Agent
// Copyright (C) 2015-2025 eGloo Incorporated
// <http://www.egloo.ca>
//
// This program is free software: you can redistribute it
// and/or modify it under the terms of the GNU General
// Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be
// useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE.  See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public
// License along with this program.  If not, see
// <http://www.gnu.org/licenses/>.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <memory>

#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define __FAVOR_BSD
#include <netinet/in.h>
#include <netinet/ip.h>
#undef __FAVOR_BSD

#include "nd-util.hpp"
#include "nd-socket.hpp"

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 104
#endif

using namespace std;

#define _ND_SOCKET_PROC_NET_UNIX "/proc/net/unix"

ndSocketLocal::ndSocketLocal(ndSocket *base, const string &node)
  : base(base), valid(false) {
    // nd_dprintf("%s\n", __PRETTY_FUNCTION__);
    base->sa = make_unique<struct sockaddr_storage>();
    struct sockaddr_un *sa_un = (struct sockaddr_un *)base->sa.get();

    base->node = node;
    base->sa_size = sizeof(struct sockaddr_un);

    memset(sa_un, 0, sizeof(struct sockaddr_un));

    sa_un->sun_family = base->family = AF_LOCAL;
    strncpy(sa_un->sun_path, base->node.c_str(), UNIX_PATH_MAX);

    int rc;

    if ((rc = IsValid()) != 0) {
        throw ndException("%s: invalid node: %s\n",
          __PRETTY_FUNCTION__, node.c_str());
    }

    valid = true;

    base->Create();
}

ndSocketLocal::~ndSocketLocal() {
    // nd_dprintf("%s\n", __PRETTY_FUNCTION__);
    if (valid && base->type == ndSOCKET_TYPE_SERVER)
        unlink(base->node.c_str());
}

#ifdef __FreeBSD__
int ndSocketLocal::IsValid(void) {
    // TODO: Need a "BSD-way" to achieve the same...
    int rc = unlink(base->node.c_str());
    if (rc != 0 && errno != ENOENT) {
        nd_printf(
          "Error while removing stale socket file: %s: "
          "%s\n",
          base->node.c_str(), strerror(errno));
        return rc;
    }
    return 0;
}
#else
int ndSocketLocal::IsValid(void) {
    // nd_dprintf("%s\n", __PRETTY_FUNCTION__);

    struct stat socket_stat;

    if (base->type == ndSOCKET_TYPE_CLIENT) {
        stat(base->node.c_str(), &socket_stat);
        return errno;
    }
    else if (base->type == ndSOCKET_TYPE_SERVER) {
        int rc = 0;
        const long max_path_len = pathconf(base->node.c_str(), _PC_PATH_MAX);
        if (max_path_len == -1) return errno;

        FILE *fh = fopen(_ND_SOCKET_PROC_NET_UNIX, "r");
        if (! fh) return errno;

        unique_ptr<char[]> filename(new char[max_path_len]);

        for (;;) {
            unsigned int a, b, c, d, e, f, g;
            int count = fscanf(fh, "%x: %u %u %u %u %u %u ",
              &a, &b, &c, &d, &e, &f, &g);
            if (count == 0) {
                if (! fgets(filename.get(), max_path_len, fh))
                    break;
                continue;
            }
            else if (count == -1) break;
            else if (! fgets(filename.get(), max_path_len, fh))
                break;
            else if (strncmp(filename.get(), base->node.c_str(),
                       base->node.size()) == 0)
            {
                rc = EADDRINUSE;
                break;
            }
        }

        fclose(fh);

        if (rc != 0) return rc;

        if (stat(base->node.c_str(), &socket_stat) != 0 &&
          errno != ENOENT)
            return errno;

        unlink(base->node.c_str());
    }

    return 0;
}
#endif

ndSocketRemote::ndSocketRemote(ndSocket *base,
  const string &node, const string &service)
  : base(base) {
    // nd_dprintf("%s\n", __PRETTY_FUNCTION__);

    base->node = node;
    base->service = service;

    base->Create();
}

ndSocketRemote::~ndSocketRemote() {
    // nd_dprintf("%s\n", __PRETTY_FUNCTION__);
}

ndSocketClient::ndSocketClient(ndSocket *base)
  : base(base) {
    // nd_dprintf("%s\n", __PRETTY_FUNCTION__);

    base->type = ndSOCKET_TYPE_CLIENT;
}

ndSocketClient::~ndSocketClient() {
}

ndSocket *ndSocketServer::Accept(void) {
    // nd_dprintf("%s\n", __PRETTY_FUNCTION__);
    ndSocket *peer = nullptr;
    int peer_sd = -1;
    socklen_t peer_sa_size = sizeof(struct sockaddr_storage);
    auto peer_sa = make_unique<struct sockaddr_storage>();

    try {
        peer_sd = accept(base->sd, (struct sockaddr *)peer_sa.get(), &peer_sa_size);
        if (peer_sd < 0) {
            throw ndExceptionSystemError(__PRETTY_FUNCTION__,
              "accept");
        }

        if (base->sa_size == sizeof(struct sockaddr_un)) {
            peer = new ndSocket(base->node);

            nd_dprintf("%s: peer: %s\n",
              __PRETTY_FUNCTION__, base->node.c_str());
        }
        else {
            char node[NI_MAXHOST], service[NI_MAXSERV];

            int rc = getnameinfo((struct sockaddr *)peer_sa.get(), peer_sa_size,
              node, NI_MAXHOST, service, NI_MAXSERV,
              NI_NUMERICHOST | NI_NUMERICSERV);

            if (rc != 0) {
                throw ndExceptionSystemErrno(
                  __PRETTY_FUNCTION__, "getnameinfo", rc);
            }

            peer = new ndSocket(node, service);

            nd_dprintf("%s: peer: %s:%s\n",
              __PRETTY_FUNCTION__, node, service);
        }

        peer->sd = peer_sd;
        peer->family = base->family;
        peer->type = ndSOCKET_TYPE_CLIENT;
        peer->state = ndSOCKET_STATE_ACCEPTED;
        peer->sa = std::move(peer_sa);
        peer->sa_size = peer_sa_size;
    }
    catch (runtime_error &e) {
        if (peer != nullptr) {
            delete peer;
            peer = nullptr;
        }
        if (peer_sd >= 0) close(peer_sd);
        throw;
    }

    return peer;
}

ndSocketServer::ndSocketServer(ndSocket *base)
  : base(base) {
    // nd_dprintf("%s\n", __PRETTY_FUNCTION__);
    base->type = ndSOCKET_TYPE_SERVER;
}

ndSocketServer::~ndSocketServer() {
    // nd_dprintf("%s\n", __PRETTY_FUNCTION__);
}

ndSocketClientLocal::ndSocketClientLocal(const string &node)
  : ndSocketClient(this), ndSocketLocal(this, node) {
    // nd_dprintf("%s\n", __PRETTY_FUNCTION__);
}

ndSocketClientLocal::~ndSocketClientLocal() {
    // nd_dprintf("%s\n", __PRETTY_FUNCTION__);
}

ndSocketServerLocal::ndSocketServerLocal(const string &node)
  : ndSocketServer(this), ndSocketLocal(this, node) {
    // nd_dprintf("%s\n", __PRETTY_FUNCTION__);
}

ndSocketServerLocal::~ndSocketServerLocal() {
    // nd_dprintf("%s\n", __PRETTY_FUNCTION__);
}

void ndSocketServerLocal::SetPermissions(mode_t mode) {
    // nd_dprintf("%s\n", __PRETTY_FUNCTION__);
    if (chmod(node.c_str(), mode) < 0)
        throw ndExceptionSystemError(__PRETTY_FUNCTION__, "chmod");
}

ndSocketClientRemote::ndSocketClientRemote(
  const string &node, const string &service)
  : ndSocketClient(this), ndSocketRemote(this, node, service) {
    // nd_dprintf("%s\n", __PRETTY_FUNCTION__);
}

ndSocketClientRemote::~ndSocketClientRemote() {
    // nd_dprintf("%s\n", __PRETTY_FUNCTION__);
}

ndSocketServerRemote::ndSocketServerRemote(
  const string &node, const string &service)
  : ndSocketServer(this), ndSocketRemote(this, node, service) {
    // nd_dprintf("%s\n", __PRETTY_FUNCTION__);
}

ndSocketServerRemote::~ndSocketServerRemote() {
    // nd_dprintf("%s\n", __PRETTY_FUNCTION__);
}

ndSocket::ndSocket()
  : sd(-1), family(AF_UNSPEC), sa_size(0),
    type(ndSOCKET_TYPE_NULL), state(ndSOCKET_STATE_INIT),
    bytes_in(0), bytes_out(0) {
    // nd_dprintf("%s\n", __PRETTY_FUNCTION__);
}

ndSocket::ndSocket(const string &node)
  : sd(-1), family(AF_UNSPEC), sa_size(0),
    node(node), type(ndSOCKET_TYPE_NULL),
    state(ndSOCKET_STATE_INIT), bytes_in(0), bytes_out(0) {
    // nd_dprintf("%s\n", __PRETTY_FUNCTION__);
}

ndSocket::ndSocket(const string &host, const string &service)
  : sd(-1), family(AF_UNSPEC), sa_size(0),
    node(host), service(service), type(ndSOCKET_TYPE_NULL),
    state(ndSOCKET_STATE_INIT), bytes_in(0), bytes_out(0) {
    // nd_dprintf("%s\n", __PRETTY_FUNCTION__);
}

ndSocket::~ndSocket() {
    // nd_dprintf("%s\n", __PRETTY_FUNCTION__);
    if (sd != -1) close(sd);
}

ssize_t ndSocket::Read(uint8_t *buffer, ssize_t length) {
    uint8_t *p = buffer;
    ssize_t bytes_read = 0, bytes_remaining = length;

    // nd_dprintf("%s\n", __PRETTY_FUNCTION__);

    do {
        ssize_t rc = read(sd, p, bytes_remaining);

        if (rc < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                throw ndExceptionSystemError(
                  __PRETTY_FUNCTION__, "read");
            break;
        }

        if (rc == 0) throw ndSocketHangupException("read");

        bytes_read += rc;
        p += rc;
        bytes_remaining -= rc;
        bytes_in += rc;
    }
    while (bytes_remaining > 0);

    return bytes_read;
}

ssize_t ndSocket::Write(const uint8_t *buffer, ssize_t length) {
    const uint8_t *p = buffer;
    ssize_t bytes_wrote = 0, bytes_remaining = length;

    // nd_dprintf("%s\n", __PRETTY_FUNCTION__);

    do {
        ssize_t rc = write(sd, p, bytes_remaining);

        if (rc < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                throw ndExceptionSystemError(
                  __PRETTY_FUNCTION__, "write");
            }
            break;
        }

        if (rc == 0)
            throw ndSocketHangupException("write");

        bytes_wrote += rc;
        p += rc;
        bytes_remaining -= rc;
        bytes_out += rc;
    }
    while (bytes_remaining > 0);

    return bytes_wrote;
}

void ndSocket::SetBlockingMode(bool enable) {
    int flags;

    // nd_dprintf("%s\n", __PRETTY_FUNCTION__);

    if (enable == false) {
        flags = fcntl(sd, F_GETFL);
        if (fcntl(sd, F_SETFL, flags | O_NONBLOCK) < 0) {
            throw ndExceptionSystemError(__PRETTY_FUNCTION__,
              "fcntl(F_SETFL, O_NONBLOCK)");
        }
    }
    else {
        flags = fcntl(sd, F_GETFL);
        flags &= ~O_NONBLOCK;
        if (fcntl(sd, F_SETFL, flags) < 0) {
            throw ndExceptionSystemError(__PRETTY_FUNCTION__,
              "fcntl(F_SETFL, ~O_NONBLOCK)");
        }
    }
}

void ndSocket::Create(void) {
    // nd_dprintf("%s\n", __PRETTY_FUNCTION__);

    if (family == AF_UNSPEC) {
        struct addrinfo hints;
        struct addrinfo *result, *rp;

        memset(&hints, 0, sizeof(struct addrinfo));
#if defined(__FreeBSD__)
        hints.ai_family = AF_UNSPEC;
#else
        hints.ai_family = AF_INET6;
#endif
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_V4MAPPED;
        // hints.ai_flags = AI_V4MAPPED | AI_ALL;
        if (type == ndSOCKET_TYPE_SERVER)
            hints.ai_flags |= AI_PASSIVE;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_canonname = nullptr;
        hints.ai_addr = nullptr;
        hints.ai_next = nullptr;

        int rc;
        const char *_node = (node.length()) ? node.c_str() : nullptr;
        if ((rc = getaddrinfo(_node, service.c_str(),
               &hints, &result)) != 0)
        {
            throw ndException("%s: %s: %s", __PRETTY_FUNCTION__,
              "getaddrinfo", gai_strerror(rc));
        }

        sd = -1;
        for (rp = result; rp != nullptr; rp = rp->ai_next) {
            sd = socket(rp->ai_family,
              rp->ai_socktype | SOCK_NONBLOCK,
              rp->ai_protocol);
            if (sd < 0) {
                nd_printf("%s: socket: %s",
                  __PRETTY_FUNCTION__, strerror(errno));
                continue;
            }

            if (type == ndSOCKET_TYPE_CLIENT) {
                if (connect(sd, rp->ai_addr, rp->ai_addrlen) == 0)
                {
                    nd_printf("%s: connected\n", __PRETTY_FUNCTION__);
                    break;
                }
                else {
                    if (rp->ai_family == AF_INET) {
                        nd_printf("%s: connect v4: %s\n",
                          __PRETTY_FUNCTION__, strerror(errno));
                    }
                    else if (rp->ai_family == AF_INET6) {
                        nd_printf("%s: connect v6: %s\n",
                          __PRETTY_FUNCTION__, strerror(errno));
                    }
                    else {
                        nd_printf("%s: connect: %s\n",
                          __PRETTY_FUNCTION__, strerror(errno));
                    }
                }
            }
            else if (type == ndSOCKET_TYPE_SERVER) {
                int on = 1;
                if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR,
                      (char *)&on, sizeof(on)) != 0)
                {
                    throw ndExceptionSystemError(__PRETTY_FUNCTION__,
                      "setsockopt(SO_REUSEADDR)");
                }

                if (::bind(sd, rp->ai_addr, rp->ai_addrlen) == 0)
                    break;
                else {
                    throw ndExceptionSystemError(
                      __PRETTY_FUNCTION__, "bind");
                }
            }

            close(sd);
            sd = -1;
        }

        if (rp == nullptr) {
            freeaddrinfo(result);
            throw ndException("%s: %s: %s", __PRETTY_FUNCTION__,
              "getaddrinfo", "no addresses found");
        }

        family = rp->ai_family;
        sa_size = rp->ai_addrlen;

        sa = make_unique<struct sockaddr_storage>();
        memcpy(sa.get(), rp->ai_addr, sa_size);

        freeaddrinfo(result);

        if (sd < 0) {
            throw ndException("%s: %s", __PRETTY_FUNCTION__,
              "unable to create socket");
        }

        if (type == ndSOCKET_TYPE_SERVER) {
            if (::listen(sd, SOMAXCONN) != 0) {
                throw ndExceptionSystemError(
                  __PRETTY_FUNCTION__, "listen");
            }
        }
    }
    else if (family == AF_LOCAL) {
        if ((sd = ::socket(family, SOCK_STREAM | SOCK_NONBLOCK, 0)) < 0)
        {
            throw ndExceptionSystemError(__PRETTY_FUNCTION__,
              "socket");
        }

        if (type == ndSOCKET_TYPE_CLIENT) {
            if (::connect(sd, (struct sockaddr *)sa.get(), sa_size) != 0)
            {
                throw ndExceptionSystemError(
                  __PRETTY_FUNCTION__, "connect");
            }
            nd_printf("%s: connected\n", __PRETTY_FUNCTION__);
        }
        else if (type == ndSOCKET_TYPE_SERVER) {
            if (::bind(sd, (struct sockaddr *)sa.get(), sa_size) != 0)
            {
                throw ndExceptionSystemError(
                  __PRETTY_FUNCTION__, "bind");
            }

            if (::listen(sd, SOMAXCONN) != 0) {
                throw ndExceptionSystemError(
                  __PRETTY_FUNCTION__, "listen");
            }
        }
    }

    // nd_dprintf("%s: created\n", __PRETTY_FUNCTION__);
}
