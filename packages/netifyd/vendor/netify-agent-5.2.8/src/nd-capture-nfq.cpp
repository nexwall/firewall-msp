// Netify Agent
// Copyright (C) 2015-2024 eGloo Incorporated
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

#include <libmnl/libmnl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <net/if.h>

#ifndef NF_ACCEPT
#define NF_ACCEPT 1
#endif
#ifndef NF_REPEAT
#define NF_REPEAT 4
#endif

#if defined(HAVE_PCAP_DLT_H)
#include <pcap/dlt.h>
#elif defined(_ND_PCAP_DLT_IN_BPF_H)
#include <pcap/bpf.h>
#else
#include "pcap-compat/dlt.h"
#endif

#include "nd-capture-nfq.hpp"
#include "nd-except.hpp"

// #define _ND_LOG_WARNINGS 1
// #define _ND_LOG_DEBUG 1

#ifndef HAVE_NFQ_NLMSG_PUT
// XXX: To support libnetfilter_queue < 1.0.4, supply our own nfq_nlmsg_put().
static struct nlmsghdr *nfq_nlmsg_put(char *buffer, int type, uint32_t queue_id) {
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buffer);
    nlh->nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | type;
    nlh->nlmsg_flags = NLM_F_REQUEST;

    struct nfgenmsg *nfg = static_cast<struct nfgenmsg *>(
        mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg))
    );
    nfg->nfgen_family = AF_UNSPEC;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = htons(queue_id);

    return nlh;
}
#endif

#ifdef _ND_LOG_DEBUG
static void ndCaptureNFQueue_PrintAttrs(const char *tag, struct nlattr **attr) {
    for (unsigned i = 0; i < NFQA_MAX; i++) {
        if (attr[i] == nullptr) continue;

        switch (i) {
        case NFQA_UNSPEC:
            nd_dprintf("%s: NFQA_UNSPEC\n", tag);
            break;
        case NFQA_PACKET_HDR:
            nd_dprintf("%s: NFQA_PACKET_HDR\n", tag);
            break;
        case NFQA_VERDICT_HDR:
            nd_dprintf("%s: NFQA_VERDICT_HDR\n", tag);
            break;
        case NFQA_MARK:
            nd_dprintf("%s: NFQA_MARK\n", tag);
            break;
        case NFQA_TIMESTAMP:
            nd_dprintf("%s: NFQA_TIMESTAMP\n", tag);
            break;
        case NFQA_IFINDEX_INDEV:
            nd_dprintf("%s: NFQA_IFINDEX_INDEV\n", tag);
            break;
        case NFQA_IFINDEX_OUTDEV:
            nd_dprintf("%s: NFQA_IFINDEX_OUTDEV\n", tag);
            break;
        case NFQA_IFINDEX_PHYSINDEV:
            nd_dprintf("%s: NFQA_IFINDEX_PHYSINDEV\n", tag);
            break;
        case NFQA_IFINDEX_PHYSOUTDEV:
            nd_dprintf("%s: NFQA_IFINDEX_PHYSOUTDEV\n", tag);
            break;
        case NFQA_HWADDR:
            nd_dprintf("%s: NFQA_HWADDR\n", tag);
            break;
        case NFQA_PAYLOAD:
            nd_dprintf("%s: NFQA_PAYLOAD\n", tag);
            break;
        case NFQA_CT:
            nd_dprintf("%s: NFQA_CT\n", tag);
            break;
        case NFQA_CT_INFO:
            nd_dprintf("%s: NFQA_CT_INFO\n", tag);
            break;
        case NFQA_CAP_LEN:
            nd_dprintf("%s: NFQA_CAP_LEN\n", tag);
            break;
        default:
            nd_dprintf("%s: NFQA_???: %u\n", tag, i);
            break;
        }
    }
}
#endif

static int ndCaptureNFQueue_SetVerdict(
    const struct nlmsghdr *nlh, ndCaptureNFQueue *nfq,
    struct nfqnl_msg_packet_hdr *pkt_hdr) {

    struct nfgenmsg *nfg = static_cast<struct nfgenmsg *>(
      mnl_nlmsg_get_payload(nlh));

    uint8_t buffer[ND_NETLINK_BUFFER_SOCKET_SIZE];
    struct nlmsghdr *nlh_verdict = nfq_nlmsg_put(
      (char *)buffer, NFQNL_MSG_VERDICT, ntohs(nfg->res_id));

    if (nfq->mark_verdict) {
        nfq_nlmsg_verdict_put_mark(nlh_verdict, htonl(
          nfq->mark | (nfq->mark_verdict & nfq->mark_mask)));
    }

    nfq_nlmsg_verdict_put(nlh_verdict,
      htonl(pkt_hdr->packet_id), nfq->verdict);

    if (mnl_socket_sendto(nfq->GetSocket(), nlh_verdict,
          nlh_verdict->nlmsg_len) < 0)
    {
        nd_printf("%s: Error setting verdict: %s\n",
          nfq->GetTag().c_str(), strerror(errno));
        return MNL_CB_ERROR;
    }

    return MNL_CB_OK;
}

static int ndCaptureNFQueue_Callback(
  const struct nlmsghdr *nlh, void *user) {
    ndCaptureNFQueue *nfq = static_cast<ndCaptureNFQueue *>(user);
    const char *tag = nfq->GetTag().c_str();

    struct nlattr *attr[NFQA_MAX + 1] = {};
    if (nfq_nlmsg_parse(nlh, attr) < 0) {
        nd_printf("%s: Error parsing attributes: %s\n", tag,
          strerror(errno));
        return MNL_CB_ERROR;
    }

    if (attr[NFQA_PACKET_HDR] == nullptr) {
        nd_printf("%s: No packet header metadata set.\n", tag);
        return MNL_CB_ERROR;
    }

    struct nfqnl_msg_packet_hdr *pkt_hdr = nullptr;
    pkt_hdr = static_cast<struct nfqnl_msg_packet_hdr *>(
      mnl_attr_get_payload(attr[NFQA_PACKET_HDR]));

    switch (ntohs(pkt_hdr->hw_protocol)) {
    case ETHERTYPE_IP:
    case ETHERTYPE_IPV6:
        break;
    default:
#ifdef _ND_LOG_WARNINGS
        nd_dprintf("%s: unsupported packet protocol: 0x%04x\n",
            tag, ntohs(pkt_hdr->hw_protocol));
#endif
        return ndCaptureNFQueue_SetVerdict(nlh, nfq, pkt_hdr);
    }

    if (attr[NFQA_PAYLOAD] == nullptr) {
        nd_printf("%s: No packet payload set.\n", tag);
        return ndCaptureNFQueue_SetVerdict(nlh, nfq, pkt_hdr);
    }

    struct nfqnl_msg_packet_timestamp *pkt_ts = nullptr;
    if (attr[NFQA_TIMESTAMP] != nullptr) {
        pkt_ts = static_cast<struct nfqnl_msg_packet_timestamp *>(
          mnl_attr_get_payload(attr[NFQA_TIMESTAMP]));
    }

    struct timeval pkt_tv;
    if (pkt_ts != nullptr && (pkt_ts->sec != 0 || pkt_ts->usec != 0)) {
        pkt_tv.tv_sec = __be64_to_cpu(pkt_ts->sec);
        pkt_tv.tv_usec = __be64_to_cpu(pkt_ts->usec);
    }
    else {
#ifdef _ND_LOG_WARNINGS
        nd_dprintf("%s: WARNING: no packet timestamp.\n", tag);
#endif
        gettimeofday(&pkt_tv, nullptr);
    }

    if (attr[NFQA_MARK] != nullptr)
        nfq->mark = ntohl(mnl_attr_get_u32(attr[NFQA_MARK]));

    uint32_t ifidx_in = 0;
    if (attr[NFQA_IFINDEX_PHYSINDEV] != nullptr)
        ifidx_in = ntohl(mnl_attr_get_u32(attr[NFQA_IFINDEX_PHYSINDEV]));
    else if (attr[NFQA_IFINDEX_INDEV] != nullptr)
        ifidx_in = ntohl(mnl_attr_get_u32(attr[NFQA_IFINDEX_INDEV]));
    uint32_t ifidx_out = 0;
    if (attr[NFQA_IFINDEX_PHYSOUTDEV] != nullptr)
        ifidx_out = ntohl(mnl_attr_get_u32(attr[NFQA_IFINDEX_PHYSOUTDEV]));
    else if (attr[NFQA_IFINDEX_OUTDEV] != nullptr)
        ifidx_out = ntohl(mnl_attr_get_u32(attr[NFQA_IFINDEX_OUTDEV]));

#ifdef _ND_LOG_DEBUG
    if (ifidx_in > 0) {
        char ifname[IFNAMSIZ] = { '\0' };
        if_indextoname(ifidx_in, ifname);
        nd_dprintf("%s: -->: %s\n", tag, ifname);
    }
    if (ifidx_out > 0) {
        char ifname[IFNAMSIZ] = { '\0' };
        if_indextoname(ifidx_out, ifname);
        nd_dprintf("%s: <--: %s\n", tag, ifname);
    }
#endif

    const uint16_t pkt_caplen = mnl_attr_get_payload_len(
      attr[NFQA_PAYLOAD]);
    void *payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]);

#ifdef _ND_LOG_DEBUG
    uint32_t skbinfo = attr[NFQA_SKB_INFO] ?
      ntohl(mnl_attr_get_u32(attr[NFQA_SKB_INFO])) :
      0;
    if (skbinfo & NFQA_SKB_GSO)
        nd_dprintf("%s: GSO packet.\n", tag);
#endif

    constexpr size_t hdr_eth_size = sizeof(struct ether_header);
    const uint16_t pkt_len = (attr[NFQA_CAP_LEN]) ?
      ntohl(mnl_attr_get_u32(attr[NFQA_CAP_LEN])) :
      pkt_caplen;

    // One-and-only packet copy...
    uint8_t *pkt_data = new uint8_t[hdr_eth_size + pkt_caplen];
    memcpy(pkt_data + hdr_eth_size, payload, pkt_caplen);

    // Initialize Ethernet header...
    struct ether_header *hdr_eth = (struct ether_header *)pkt_data;
    memset(hdr_eth, 0, hdr_eth_size);
    hdr_eth->ether_type = pkt_hdr->hw_protocol;

    // If we have a HW address, use it as source MAC...
    struct nfqnl_msg_packet_hw *pkt_hwaddr = nullptr;
    if (attr[NFQA_HWADDR] != nullptr) {
        pkt_hwaddr = static_cast<struct nfqnl_msg_packet_hw *>(
          mnl_attr_get_payload(attr[NFQA_HWADDR]));
    }

    ndFlags<ndPacket::StatusFlags> pkt_status = ndPacket::StatusFlags::OK;

    if (pkt_hwaddr != nullptr) {
        pkt_status |= ndPacket::StatusFlags::NFQ_HWADDR_SRC;
        memcpy(&hdr_eth->ether_shost[0],
          &pkt_hwaddr->hw_addr[0], ETH_ALEN);
    }
    else if (ifidx_in > 0) {
        // ...otheriwse attempt to look-up MAC for input interface.
        ndAddr addr;
        if (nfq->ndi.addr_lookup.LookupLinkAddress(ifidx_in, addr)
            && addr.IsEthernet()) {
            pkt_status |= ndPacket::StatusFlags::NFQ_HWADDR_SRC;
            memcpy(&hdr_eth->ether_shost[0],
                addr.GetAddress(), ETH_ALEN);
        }
    }

    // Set initial destination MAC using output interface, if available.
    if (ifidx_out > 0) {
        ndAddr addr;
        if (nfq->ndi.addr_lookup.LookupLinkAddress(ifidx_out, addr)
            && addr.IsEthernet()) {
            pkt_status |= ndPacket::StatusFlags::NFQ_HWADDR_DST;
            memcpy(&hdr_eth->ether_dhost[0],
                addr.GetAddress(), ETH_ALEN);
        }
    }

    int ifidx_logical = -1;
#if defined(_ND_ENABLE_INTERFACE_METADATA)
    if (ndGC.mark_to_ifindex_enable && nfq->mark) {
        ifidx_logical = (nfq->mark >> ndGC.mark_to_ifindex_mark_shift) &
          ((1U << ndGC.mark_to_ifindex_mark_mask) - 1);
    }
#endif
    // Filtered?
    if (nfq->filter.bf_insns && bpf_filter(
        nfq->filter.bf_insns, pkt_data,
        hdr_eth_size + pkt_len,
        hdr_eth_size + pkt_caplen) == 0) {
        delete [] pkt_data;
    }
    else {
        // Create and push packet
        ndPacket *pkt = new ndPacket(pkt_status,
          static_cast<uint16_t>(hdr_eth_size + pkt_len),
          static_cast<uint16_t>(hdr_eth_size + pkt_caplen),
          pkt_data, pkt_tv,
          ifidx_logical,
          ifidx_in,
          ifidx_out);

        nfq->PushPacket(pkt);
    }

    return ndCaptureNFQueue_SetVerdict(nlh, nfq, pkt_hdr);
}

ndCaptureNFQueue::ndCaptureNFQueue(int16_t cpu,
  ndInterface::Ptr &iface, const ndDetectionThreads &threads_dpi,
  unsigned instance_id, ndDNSHintCache *dhc, uint8_t private_addr)
  : ndCaptureThread(ndCaptureType::NFQ, cpu, iface,
      threads_dpi, dhc, private_addr),
    nl(nullptr), port_id(0),
    buffer_size(0xffff + (ND_NETLINK_BUFFER_SOCKET_SIZE / 2)),
    buffer(nullptr), dropped(0) {
    dl_type = DLT_EN10MB;

    queue_id = iface->config_nfq.queue_id + instance_id;

    const char *verdict_tag = "unknown";
    switch (iface->config_nfq.verdict) {
    case ndNFQVerdict::ACCEPT:
        verdict = NF_ACCEPT;
        verdict_tag = "NF_ACCEPT";
        break;
    case ndNFQVerdict::REPEAT:
        verdict = NF_REPEAT;
        verdict_tag = "NF_REPEAT";
        break;
    }

    mark_verdict = iface->config_nfq.mark;
    mark_mask = iface->config_nfq.mask;

    nl = mnl_socket_open(NETLINK_NETFILTER);

    if (nl == nullptr) {
        throw ndExceptionSystemError(__PRETTY_FUNCTION__,
          "mnl_socket_open");
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        throw ndExceptionSystemError(__PRETTY_FUNCTION__,
          "mnl_socket_bind");
    }

    port_id = mnl_socket_get_portid(nl);

    buffer = new uint8_t[buffer_size];

    struct nlmsghdr *nlh;

    nlh = nfq_nlmsg_put((char *)buffer, NFQNL_MSG_CONFIG, queue_id);
    nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);
    nfq_nlmsg_cfg_put_cmd(nlh, AF_INET6, NFQNL_CFG_CMD_BIND);

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        throw ndExceptionSystemError(__PRETTY_FUNCTION__,
          "mnl_socket_sendto");
    }

    nlh = nfq_nlmsg_put((char *)buffer, NFQNL_MSG_CONFIG, queue_id);
    nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, ndGC.max_capture_length);

    long flags = NFQA_CFG_F_FAIL_OPEN |
        NFQA_CFG_F_CONNTRACK | NFQA_CFG_F_GSO;
    mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(flags));
    mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(flags));

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        throw ndExceptionSystemError(__PRETTY_FUNCTION__,
          "mnl_socket_sendto");
    }

    // int enable = 1;
    // mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &enable,
    // sizeof(int));

    nd_dprintf(
      "%s: NFQ capture thread created on queue #%u, thread #%u, "
      "counters: %s, buffer size: %lu, verdict: %s, mark: 0x%08x/0x%08x\n",
      tag.c_str(),
      iface->config_nfq.queue_id, instance_id,
      (iface->config_nfq.conntrack_counters) ? "enabled" : "disabled",
      buffer_size, verdict_tag, mark_verdict, mark_mask);
}

ndCaptureNFQueue::~ndCaptureNFQueue() {
    Join();

    if (nl != nullptr) mnl_socket_close(nl);
    if (buffer != nullptr) delete[] buffer;

    pcap_freecode(&filter);

    nd_dprintf("%s: NFQ capture thread destroyed.\n", tag.c_str());
}

void *ndCaptureNFQueue::Entry(void) {
    int rc = 0;
    struct timeval tv;
    int fd = mnl_socket_get_fd(nl);
    fd_set fds_read;

    capture_state = State::ONLINE;

    auto it_filter = ndGC.interface_filters.find(tag);

    if (it_filter != ndGC.interface_filters.end())
        CompileFilter(it_filter->second, filter);

    nd_dprintf("%s: NFQ capture started on CPU: %lu\n",
      tag.c_str(), cpu >= 0 ? cpu : 0);

    while (! ShouldTerminate()) {
        FD_ZERO(&fds_read);
        FD_SET(fd, &fds_read);

        memset(&tv, 0, sizeof(struct timeval));
        tv.tv_sec = 1;

        rc = select(fd + 1, &fds_read, nullptr, nullptr, &tv);

        if (rc == -1) {
            throw ndExceptionSystemError(__PRETTY_FUNCTION__,
              "select");
        }

        if (rc == 0 || ! FD_ISSET(fd, &fds_read)) continue;

        ssize_t bytes = mnl_socket_recvfrom(nl, (char *)buffer, buffer_size);
#ifdef _ND_LOG_DEBUG
        nd_dprintf("%s: NFQUEUE: mnl_socket_recvfrom: %d (%s)\n",
            tag.c_str(), bytes, (bytes == -1) ? strerror(errno) : "No error");
#endif
        if (bytes == -1) {
            if (errno == ENOBUFS) {
                dropped++;
                continue;
            }
            else {
                nd_printf(
                  "%s: Error receiving NFQUEUE data: %s\n",
                  tag.c_str(), strerror(errno));
                break;
            }
        }

        rc = mnl_cb_run((char *)buffer, (size_t)bytes, 0, port_id,
          ndCaptureNFQueue_Callback, static_cast<void *>(this));

        if (rc != MNL_CB_OK) {
            nd_printf(
              "%s: Error processing NFQUEUE data: %s [%d]\n",
              tag.c_str(), strerror(errno), rc);

            capture_state = State::OFFLINE;

            throw ndExceptionSystemError(__PRETTY_FUNCTION__,
              "mnl_cb_run");
        }

        if (pkt_queue.size()) {
            Lock();

            try {
                for (auto &pkt : pkt_queue) {
                    if (ProcessPacket(pkt) != nullptr)
                        delete pkt;
                }
            }
            catch (...) {
                Unlock();
                capture_state = State::OFFLINE;
                throw;
            }

            Unlock();

            pkt_queue.clear();
        }
    }

    capture_state = State::OFFLINE;

    nd_dprintf("%s: NFQ capture ended on CPU: %lu\n",
      tag.c_str(), cpu >= 0 ? cpu : 0);

    return nullptr;
}

void ndCaptureNFQueue::GetCaptureStats(ndPacketStats &stats) {
    stats.pkt.capture_dropped = dropped;

    dropped = 0;

    ndCaptureThread::GetCaptureStats(stats);
}
