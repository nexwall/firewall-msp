#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include <sys/socket.h>
#include <sys/select.h>

#include <libmnl/libmnl.h>

#include <iostream>

#include "nd-config.hpp"
#include "nd-except.hpp"
#include "nd-netlink.hpp"

using namespace std;

// #define _ND_NETLINK_DEBUG   1

static int ndNetlink_ProcessMessageCallback(
    const struct nlmsghdr *nlh, void *data) {
    ndNetlink *nl = reinterpret_cast<ndNetlink *>(data);
    return nl->ProcessMessage(nlh);
}

ndNetlink::ndNetlink(int bus) : dump(true) {
    socket_buffer.resize(ndGC.netlink_buffer_size.load());

    socket_nl = mnl_socket_open(bus);
    if (socket_nl == nullptr)
        throw ndException("mnl_socket_open: %s", strerror(errno));

    if (ndGC.netlink_socket_buffer_size > 0) {
        int rcvbuf = ndGC.netlink_socket_buffer_size;
        int fd = mnl_socket_get_fd(socket_nl);
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(rcvbuf)) < 0) {
            setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
        }
    }

    if (mnl_socket_bind(socket_nl, 0, MNL_SOCKET_AUTOPID) < 0)
        throw ndException("mnl_socket_bind: %s", strerror(errno));

    port_id = mnl_socket_get_portid(socket_nl);

#ifdef _ND_NETLINK_DEBUG
    nd_dprintf("%s: created netlink socket: port_id: %lu, buffer_size: %lu\n",
        __PRETTY_FUNCTION__, port_id, socket_buffer.size());
#endif
}

ndNetlink::ndNetlink(int bus, unsigned int groups) {
    socket_buffer.resize(ndGC.netlink_buffer_size.load());

    socket_nl = mnl_socket_open2(bus, SOCK_NONBLOCK);
    if (socket_nl == nullptr)
        throw ndException("mnl_socket_open: %s", strerror(errno));

    if (ndGC.netlink_socket_buffer_size > 0) {
        int rcvbuf = ndGC.netlink_socket_buffer_size;
        int fd = mnl_socket_get_fd(socket_nl);
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(rcvbuf)) < 0) {
            setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
        }
    }

    if (mnl_socket_bind(socket_nl, groups, MNL_SOCKET_AUTOPID) < 0)
        throw ndException("mnl_socket_bind: %s", strerror(errno));

#ifdef _ND_NETLINK_DEBUG
    nd_dprintf("%s: created netlink socket: port_id: %lu, buffer_size: %lu\n",
        __PRETTY_FUNCTION__, mnl_socket_get_portid(socket_nl),
        socket_buffer.size());
#endif
}

ndNetlink::~ndNetlink() {
    if (socket_nl != nullptr) {
        mnl_socket_close(socket_nl);
        socket_nl = nullptr;
    }
}

int ndNetlink::GetDescriptor(void) {
    if (socket_nl != nullptr)
        return mnl_socket_get_fd(socket_nl);
    return -1;
}

bool ndNetlink::Recv(void)
{
    int rc = MNL_CB_ERROR;

    do {
        ssize_t bytes = mnl_socket_recvfrom(
            socket_nl, socket_buffer.data(), socket_buffer.size());
#if _ND_NETLINK_DEBUG
        if (dump) {
            nd_dprintf("%s: recv %ld byte(s), seq_id: %u, port_id: %u\n",
                __PRETTY_FUNCTION__, bytes, seq_id, port_id);
        }
#endif
        if (bytes < 0) {
            if (!dump) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    rc = MNL_CB_OK;
                    break;
                }

                if (errno == ENOSPC) {
                    nd_printf(
                      "Netlink: messages dropped: "
                      "  The Netlink buffer_size is too small.\n",
                      strerror(errno));
                }
                else if (errno == ENOBUFS) {
                    if (ndGC.netlink_max_buffer_size == 0 ||
                        ndGC.netlink_max_buffer_size >
                          ndGC.netlink_buffer_size.load()) {

                        ndGC.netlink_buffer_size
                          += ND_NETLINK_BUFFER_INCREMENT;

                        socket_buffer.resize(
                          ndGC.netlink_buffer_size.load());

                        nd_dprintf(
                          "mnl_socket_recvfrom: %s, resized to: %lu\n",
                          strerror(errno), socket_buffer.size());
                    }
                    else {
                        nd_printf(
                          "Netlink: %s, messages dropped."
                          "  Consider increasing buffer_size or setting "
                          "max_buffer_size > buffer_size.\n",
                          strerror(errno), socket_buffer.size());
                    }

                    rc = MNL_CB_OK;
                    continue;
                }
            }

            throw ndException("mnl_socket_recvfrom: %s", strerror(errno));
        }
#if _ND_NETLINK_DEBUG
        nd_dprintf("%s: read %ld byte(s), seq_id: %u, port_id: %u\n",
            __PRETTY_FUNCTION__, bytes,
            dump ? seq_id : 0, dump ? port_id : 0);
#endif
        rc = mnl_cb_run(
            socket_buffer.data(), (size_t)bytes,
            dump ? seq_id : 0, dump ? port_id : 0,
            ndNetlink_ProcessMessageCallback,
            static_cast<void *>(this));

    } while (rc == MNL_CB_OK);

    return (rc == MNL_CB_OK || rc == MNL_CB_STOP);
}

bool ndNetlink::Send(nlmsghdr *nlh)
{
    if (dump) {
        nlh->nlmsg_seq = seq_id = time(nullptr);
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    }

    ssize_t bytes = mnl_socket_sendto(socket_nl, nlh, nlh->nlmsg_len);
#if _ND_NETLINK_DEBUG
    if (dump) {
        nd_dprintf("%s: send %ld byte(s), seq_id: %u, port_id: %u\n",
            __PRETTY_FUNCTION__, bytes, seq_id, port_id);
    }
#endif
    if (bytes < 0)
        throw ndException("mnl_socket_sendto: %s", strerror(errno));

    return (bytes > 0);
}
