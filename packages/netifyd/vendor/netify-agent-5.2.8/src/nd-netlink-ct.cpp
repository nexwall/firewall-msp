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

#include <algorithm>
#include <array>
#include <sstream>
#include <string>

#include <libmnl/libmnl.h>

#include "nd-except.hpp"
#include "nd-instance.hpp"
#include "nd-netlink-ct.hpp"

// Enable Conntrack debug logging
//#define _ND_DEBUG_LOG   1

using namespace std;

constexpr const char *TAG = { "netlink-ct" };

static int ndNetlinkConntrack_attr_parse(
    const struct nlattr *attr, void *data) {
    const struct nlattr **tb = static_cast<const struct nlattr **>(data);
    int type = mnl_attr_get_type(attr);

    if (mnl_attr_type_valid(attr, CTA_MAX) < 0)
        return MNL_CB_OK;

    switch(type) {
    case CTA_ID:
    case CTA_MARK:
        if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
            nd_dprintf("%s: invalid attribute type, expected: %s\n",
                TAG, "U32");
            return MNL_CB_ERROR;
        }
        break;
    case CTA_COUNTERS_ORIG:
    case CTA_COUNTERS_REPLY:
    case CTA_TUPLE_ORIG:
    case CTA_TUPLE_REPLY:
        if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
            nd_dprintf("%s: invalid attribute type, expected: %s\n",
                TAG, "TUPLE");
            return MNL_CB_ERROR;
        }
        break;
    }

    tb[type] = attr;

    return MNL_CB_OK;
}

static int ndNetlinkConntrack_attr_parse_tuple(
    const struct nlattr *attr, void *data) {
    const struct nlattr **tb = static_cast<const struct nlattr **>(data);
    int type = mnl_attr_get_type(attr);

    if (mnl_attr_type_valid(attr, CTA_TUPLE_MAX) < 0)
        return MNL_CB_OK;

    switch(type) {
    case CTA_TUPLE_IP:
        if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
            nd_dprintf("%s: invalid attribute type, expected: %s\n",
                TAG, "NESTED");
            return MNL_CB_ERROR;
        }
        break;
    case CTA_TUPLE_PROTO:
        if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
            nd_dprintf("%s: invalid attribute type, expected: %s\n",
                TAG, "NESTED");
            return MNL_CB_ERROR;
        }
        break;
    }

    tb[type] = attr;

    return MNL_CB_OK;
}

static int ndNetlinkConntrack_attr_parse_ip(
    const struct nlattr *attr, void *data) {
    const struct nlattr **tb = static_cast<const struct nlattr **>(data);
    int type = mnl_attr_get_type(attr);

    if (mnl_attr_type_valid(attr, CTA_IP_MAX) < 0)
        return MNL_CB_OK;

    switch(type) {
    case CTA_IP_V4_SRC:
    case CTA_IP_V4_DST:
        if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
            nd_dprintf("%s: invalid attribute type, expected: %s\n",
                TAG, "U32");
            return MNL_CB_ERROR;
        }
        break;
    case CTA_IP_V6_SRC:
    case CTA_IP_V6_DST:
        if (mnl_attr_validate2(attr,
            MNL_TYPE_BINARY, sizeof(struct in6_addr)) < 0) {
            nd_dprintf("%s: invalid attribute type, expected: %s\n",
                TAG, "BINARY");
            return MNL_CB_ERROR;
        }
        break;
    }

    tb[type] = attr;

    return MNL_CB_OK;
}

static int ndNetlinkConntrack_attr_parse_proto(
    const struct nlattr *attr, void *data) {
    const struct nlattr **tb = static_cast<const struct nlattr **>(data);
    int type = mnl_attr_get_type(attr);

    if (mnl_attr_type_valid(attr, CTA_PROTO_MAX) < 0)
        return MNL_CB_OK;

    switch(type) {
    case CTA_PROTO_NUM:
        if (mnl_attr_validate(attr, MNL_TYPE_U8) < 0) {
            nd_dprintf("%s: invalid attribute type, expected: %s\n",
                TAG, "U8");
            return MNL_CB_ERROR;
        }
        break;
    case CTA_PROTO_SRC_PORT:
    case CTA_PROTO_DST_PORT:
        if (mnl_attr_validate(attr, MNL_TYPE_U16) < 0) {
            nd_dprintf("%s: invalid attribute type, expected: %s\n",
                TAG, "U16");
            return MNL_CB_ERROR;
        }
        break;
    }

    tb[type] = attr;

    return MNL_CB_OK;
}

static int ndNetlinkConntrack_attr_parse_counters(
    const struct nlattr *attr, void *data) {
    const struct nlattr **tb = static_cast<const struct nlattr **>(data);
    int type = mnl_attr_get_type(attr);

    if (mnl_attr_type_valid(attr, CTA_COUNTERS_MAX) < 0)
        return MNL_CB_OK;

    switch(type) {
    case CTA_COUNTERS_PACKETS:
    case CTA_COUNTERS_BYTES:
        if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0) {
            nd_dprintf("%s: invalid attribute type, expected: %s\n",
                TAG, "U64");
            return MNL_CB_ERROR;
        }
        break;
    }

    tb[type] = attr;

    return MNL_CB_OK;
}

class ndNetlinkConntrackDump : public ndNetlink
{
public:
    ndNetlinkConntrackDump(ndNetlink *parent)
        : ndNetlink(NETLINK_NETFILTER), parent(parent) {
    }

    int ProcessMessage(const struct nlmsghdr *nlh) {
        return parent->ProcessMessage(nlh);
    }

    bool Dump(bool zero_counters = false, sa_family_t family = AF_UNSPEC) {
        struct nlmsghdr *nlh = mnl_nlmsg_put_header(socket_buffer.data());
        nlh->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) |
            (zero_counters ? IPCTNL_MSG_CT_GET_CTRZERO : IPCTNL_MSG_CT_GET);

        struct nfgenmsg *nfh = static_cast<struct nfgenmsg *>(
            mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg))
        );
        nfh->nfgen_family = family;
        nfh->version = NFNETLINK_V0;
        nfh->res_id = 0;

        try {
            if (Send(nlh)) return (Recv());
        }
        catch (exception &e) {
            nd_printf(
                "%s: Exception while dumping CT table: %s\n", TAG, e.what()
            );
        }

        return false;
    }

protected:
    ndNetlink *parent;
};

ndNetlinkConntrackThread::ndNetlinkConntrackThread(void)
    : ndThread(TAG),
    ndNetlink(NETLINK_NETFILTER,
            NF_NETLINK_CONNTRACK_NEW |
            NF_NETLINK_CONNTRACK_UPDATE |
            NF_NETLINK_CONNTRACK_DESTROY) {
}

ndNetlinkConntrackThread::~ndNetlinkConntrackThread() {
    Join();
}

void *ndNetlinkConntrackThread::Entry(void) {
    int rc;
    fd_set fds_read;
    int fd = GetDescriptor();

    while (! ShouldTerminate()) {
        FD_ZERO(&fds_read);
        FD_SET(fd, &fds_read);

        struct timeval tv = { 1, 0 };
        rc = select(fd + 1, &fds_read, nullptr, nullptr, &tv);

        if (rc == -1) {
            throw ndExceptionSystemError("select", errno);
        }

        if (FD_ISSET(fd, &fds_read)) {
            try {
                if (! Recv())
                    nd_printf("%s: Error while reading CT message.\n", TAG);
            }
            catch (exception &e) {
                nd_printf("%s: Exception while reading CT message: %s\n",
                    TAG, e.what());
            }
        }
    }

    nd_dprintf("%s: Exit.\n", TAG);

    return nullptr;
}

int ndNetlinkConntrackThread::ProcessMessage(const struct nlmsghdr *nlh) {
    struct nfgenmsg *nfg = static_cast<struct nfgenmsg *>(
        mnl_nlmsg_get_payload(nlh)
    );
#if 0
    nd_dprintf(
        "%s: NLMSG: %hu, len: %u (%u, %u), flags: 0x%x, seq: %u, pid: %u, family: %hhu\n",
        TAG, nlh->nlmsg_type, nlh->nlmsg_len,
        NLMSG_HDRLEN, NLMSG_LENGTH(nlh->nlmsg_len),
        nlh->nlmsg_flags, nlh->nlmsg_seq, nlh->nlmsg_pid, nfg->nfgen_family);
#endif
    Attrs attrs = { 0 };
    if (mnl_attr_parse(nlh, sizeof(*nfg),
        ndNetlinkConntrack_attr_parse, attrs.data()) != MNL_CB_OK) {
        return MNL_CB_OK;
    }

    nf_conntrack_msg_type type = NFCT_T_UNKNOWN;
    switch(nlh->nlmsg_type & 0xFF) {
    case IPCTNL_MSG_CT_NEW:
        if (nlh->nlmsg_flags & (NLM_F_CREATE | NLM_F_EXCL))
            type = NFCT_T_NEW;
        else
            type = NFCT_T_UPDATE;
        break;
    case IPCTNL_MSG_CT_DELETE:
        type = NFCT_T_DESTROY;
        break;
    default:
        nd_dprintf("%s: unknown type: 0x%04x\n", TAG, type);
        return MNL_CB_OK;
    }

    _ND_NLRT_CHECK_ATTR(TAG, attrs[CTA_ID], MNL_CB_OK);
    _ND_NLRT_CHECK_ATTR(TAG, attrs[CTA_TUPLE_ORIG], MNL_CB_OK);
    _ND_NLRT_CHECK_ATTR(TAG, attrs[CTA_TUPLE_REPLY], MNL_CB_OK);

    uint32_t id = ntohl(mnl_attr_get_u32(attrs[CTA_ID]));

    try {
        switch (type) {
        case NFCT_T_NEW:
            if (! NewFlow(id, attrs)) UpdateFlow(id, attrs);
            break;

        case NFCT_T_UPDATE:
            if (! UpdateFlow(id, attrs)) NewFlow(id, attrs);
            break;

        case NFCT_T_DESTROY:
            DestroyFlow(id);
            break;

        default:
            nd_dprintf("%s: %lu: unhandled CT message type: 0x%04x\n",
                TAG, id, type);
        }
    }
    catch (exception &e) {
        nd_printf("%s: Exception: %s.\n", TAG, e.what());
    }

    return MNL_CB_OK;
}

bool ndNetlinkConntrackThread::NewFlow(uint32_t id, const Attrs &attrs) {
#ifdef _ND_DEBUG_LOG
    nd_dprintf("%s: %lu: new flow.\n", TAG, id);
#endif
    lock_guard<mutex> lg(map_lock);

    auto id_flow = id_flows.find(id);
    if (id_flow != id_flows.end()) {
#ifdef _ND_DEBUG_LOG
        nd_dprintf("%s: %lu: ID found in map.\n", TAG, id);
#endif
        return false;
    }

    shared_ptr<ndConntrackFlow> flow = make_shared<ndConntrackFlow>(id, attrs);

    /* auto orig_digest_flow = */ digest_flows.insert(
        make_pair(
            flow->digest[ndEnumCast(ndConntrackFlow::Origin, ORIG)], flow));

    //if (orig_digest_flow.second == false)
    //    throw ndException("ORIG flow digest exists");

    // XXX: It's OK if this fails on duplicate entries...
    // All non-NAT flows will have the same reply hash.
    digest_flows.insert(
        make_pair(
            flow->digest[ndEnumCast(ndConntrackFlow::Origin, REPLY)], flow));

    auto id_flow_insert = id_flows.insert(make_pair(id, flow));

    if (id_flow_insert.second == false)
        throw ndException("ID flow exists");

    stats.created++;

    return true;
}

bool ndNetlinkConntrackThread::UpdateFlow(uint32_t id, const Attrs &attrs) {
#ifdef _ND_DEBUG_LOG
    nd_dprintf("%s: %lu: update flow\n", TAG, id);
#endif
    lock_guard<mutex> lg(map_lock);

    auto id_flow = id_flows.find(id);
    if (id_flow == id_flows.end()) return false;

    id_flow->second->Update(attrs);

    // TODO: Verify that the hashes haven't changed?

    stats.updated++;

    return true;
}

void ndNetlinkConntrackThread::DestroyFlow(uint32_t id) {
#ifdef _ND_DEBUG_LOG
    nd_dprintf("%s: %lu: destroy flow\n", TAG, id);
#endif
    lock_guard<mutex> lg(map_lock);

    auto id_flow = id_flows.find(id);
    if (id_flow != id_flows.end()) {
        auto digest_flow = digest_flows.find(
            id_flow->second->digest[ndEnumCast(ndConntrackFlow::Origin, ORIG)]
        );
        if (digest_flow != digest_flows.end())
            digest_flows.erase(digest_flow);

        digest_flow = digest_flows.find(
            id_flow->second->digest[ndEnumCast(ndConntrackFlow::Origin, REPLY)]
        );
        if (digest_flow != digest_flows.end())
            digest_flows.erase(digest_flow);

        id_flows.erase(id_flow);

        stats.destroyed++;
    }
}

void ndNetlinkConntrackThread::Dump(bool zero_counters) {
    ndNetlinkConntrackDump ct_dump(this);
    ct_dump.Dump(zero_counters);
}

void ndNetlinkConntrackThread::Sweep(time_t timeout) {
    if (timeout == 0) return;

    lock_guard<mutex> lg(map_lock);
    time_t now = nd_time_monotonic();
    uint32_t purged = 0;

    for (auto it = id_flows.begin(); it != id_flows.end(); ) {
        if (now - it->second->updated_at > timeout) {
            digest_flows.erase(it->second->digest[ndEnumCast(ndConntrackFlow::Origin, ORIG)]);
            digest_flows.erase(it->second->digest[ndEnumCast(ndConntrackFlow::Origin, REPLY)]);
            it = id_flows.erase(it);
            purged++;
        } else {
            ++it;
        }
    }

    if (purged > 0) {
        nd_dprintf(
          "%s: swept %u stale conntrack flows (timeout: %ld seconds).\n",
            TAG, purged, (long)timeout);
        stats.destroyed += purged;
    }
}

void ndNetlinkConntrackThread::UpdateFlow(ndFlow::Ptr &flow) {

    uint8_t hdata[128];
    size_t hoff = 0;

    auto hwrite = [&](const void *data, size_t len) {
        if (hoff + len <= sizeof(hdata)) {
            memcpy(&hdata[hoff], data, len);
            hoff += len;
        }
    };

    sa_family_t family;
    switch (flow->ip_version) {
    case 4: family = AF_INET; break;
    default: family = AF_INET6; break;
    }

    hwrite(&family, sizeof(sa_family_t));
    hwrite(&flow->ip_protocol, sizeof(uint8_t));

    hwrite(flow->lower_addr.GetAddress(), flow->lower_addr.GetAddressSize());
    hwrite(flow->upper_addr.GetAddress(), flow->lower_addr.GetAddressSize());

    uint16_t port = flow->lower_addr.GetPort(false);
    hwrite(&port, sizeof(uint16_t));
    port = flow->upper_addr.GetPort(false);
    hwrite(&port, sizeof(uint16_t));

    ndDigest digest = nd_xxh64(hdata, hoff);

    lock_guard<mutex> lg(map_lock);

    stats.lookups++;
    auto digest_flow = digest_flows.find(digest);

    if (digest_flow != digest_flows.end()) {
        if (! digest_flow->second->reply_addr[
                static_cast<int>(ndConntrackFlow::Direction::SRC)].IsValid() ||
            ! digest_flow->second->reply_addr[
                static_cast<int>(ndConntrackFlow::Direction::DST)].IsValid()) {
            throw ndException("reply SRC or DST invalid");
        }

        stats.matches++;
        auto &ct_flow = *digest_flow->second;

        ct_flow.updated_at = nd_time_monotonic();

        flow->conntrack.id = ct_flow.id;
#ifdef _ND_ENABLE_CONNTRACK_MDATA
        flow->conntrack.mark = ct_flow.mark;
        flow->conntrack.reply_src_addr = digest_flow->second->reply_addr[
            static_cast<int>(ndConntrackFlow::Direction::SRC)];
        flow->conntrack.reply_dst_addr = digest_flow->second->reply_addr[
            static_cast<int>(ndConntrackFlow::Direction::DST)];
#endif
        if (flow->iface->role != ndInterfaceRole::WAN) return;

        flow->flags.ip_nat = (
            ct_flow.orig_addr[static_cast<int>(
                ndConntrackFlow::Direction::SRC)].Compare(
                ct_flow.reply_addr[
                    static_cast<int>(ndConntrackFlow::Direction::DST)])
            != 0 ||
            ct_flow.orig_addr[static_cast<int>(
                ndConntrackFlow::Direction::DST)].Compare(
                ct_flow.reply_addr[
                    static_cast<int>(ndConntrackFlow::Direction::SRC)])
            != 0);
    }
#ifdef _ND_DEBUG_LOG
    else {
        string _digest;
        nd_xxh64_to_string(digest, _digest);
        nd_dprintf("%s: flow not updated, no match: %s\n", TAG, _digest.c_str());
        flow->Print();
    }
#endif
}

#ifdef _ND_ENABLE_CONNTRACK_COUNTERS
bool ndNetlinkConntrackThread::UpdateFlowStats(
    ndFlow::Ptr &flow, const struct timeval &stamp) const {

    if (flow->conntrack.id == 0) {
#ifdef _ND_DEBUG_LOG
        nd_dprintf("%s: id not set.\n", TAG);
#endif
        return false;
    }

    lock_guard<mutex> lg(map_lock);

    auto id_flow = id_flows.find(flow->conntrack.id);
    if (id_flow == id_flows.end()) {
#ifdef _ND_DEBUG_LOG
        nd_dprintf("%s: id not found in map.\n", TAG);
#endif
        return false;
    }

    if (id_flow->second->packets[
            ndEnumCast(ndConntrackFlow::Direction, SRC)] == 0 &&
        id_flow->second->packets[
            ndEnumCast(ndConntrackFlow::Direction, DST)] == 0) {
#ifdef _ND_DEBUG_LOG
        nd_dprintf("%s: no packets.\n", TAG);
#endif
        return false;
    }

    unsigned idx_lower, idx_upper;

    switch (flow->origin) {
    case ndFlow::Origin::LOWER:
        idx_lower = ndEnumCast(ndConntrackFlow::Direction, SRC);
        idx_upper = ndEnumCast(ndConntrackFlow::Direction, DST);
        break;

    case ndFlow::Origin::UPPER:
        idx_lower = ndEnumCast(ndConntrackFlow::Direction, DST);
        idx_upper = ndEnumCast(ndConntrackFlow::Direction, SRC);
        break;
    default:
        nd_dprintf("%s: flow origin unknown.\n", TAG);
        return false;
    }

    uint64_t ts_pkt = ((uint64_t)stamp.tv_sec) * ND_DETECTION_TICKS +
      stamp.tv_usec / (1000000 / ND_DETECTION_TICKS);

    uint64_t current_lower_packets = id_flow->second->packets[idx_lower];
    uint64_t current_lower_bytes = id_flow->second->bytes[idx_lower];
    uint64_t current_upper_packets = id_flow->second->packets[idx_upper];
    uint64_t current_upper_bytes = id_flow->second->bytes[idx_upper];

    uint64_t delta_lower_packets = current_lower_packets >= flow->conntrack.packets[idx_lower] ?
        current_lower_packets - flow->conntrack.packets[idx_lower] : current_lower_packets;
    uint64_t delta_lower_bytes = current_lower_bytes >= flow->conntrack.bytes[idx_lower] ?
        current_lower_bytes - flow->conntrack.bytes[idx_lower] : current_lower_bytes;

    uint64_t delta_upper_packets = current_upper_packets >= flow->conntrack.packets[idx_upper] ?
        current_upper_packets - flow->conntrack.packets[idx_upper] : current_upper_packets;
    uint64_t delta_upper_bytes = current_upper_bytes >= flow->conntrack.bytes[idx_upper] ?
        current_upper_bytes - flow->conntrack.bytes[idx_upper] : current_upper_bytes;

    flow->conntrack.packets[idx_lower] = current_lower_packets;
    flow->conntrack.bytes[idx_lower] = current_lower_bytes;
    flow->conntrack.packets[idx_upper] = current_upper_packets;
    flow->conntrack.bytes[idx_upper] = current_upper_bytes;

    flow->stats.lower_packets = delta_lower_packets;
    flow->stats.lower_bytes = delta_lower_bytes;
    flow->stats.upper_packets = delta_upper_packets;
    flow->stats.upper_bytes = delta_upper_bytes;

    flow->stats.total_packets += delta_lower_packets;
    flow->stats.total_bytes += delta_lower_bytes;
    flow->stats.total_packets += delta_upper_packets;
    flow->stats.total_bytes += delta_upper_bytes;

    bool has_new_packets = (delta_lower_packets > 0 || delta_upper_packets > 0);
    if (has_new_packets) {
        flow->ts_last_seen = ts_pkt;
    }
#ifdef _ND_ENABLE_EXTENDED_STATS
    flow->stats.UpdateRate(true, ts_pkt, delta_lower_bytes);
    flow->stats.UpdateRate(false, ts_pkt, delta_upper_bytes);
#endif
#ifdef _ND_DEBUG_LOG
    nd_dprintf("%s: updated flow counters.\n", TAG);
#endif
    return has_new_packets;
}
#endif // _ND_ENABLE_CONNTRACK_COUNTERS

ndConntrackFlow::ndConntrackFlow(uint32_t id,
    const ndNetlinkConntrackThread::Attrs &attr)
    : id(id) {
    Update(attr);
}

void ndConntrackFlow::Update(const ndNetlinkConntrackThread::Attrs &attr) {
    AttrsTuple tuple_orig = { 0 }, tuple_reply = { 0 };

    if (mnl_attr_parse_nested(attr[CTA_TUPLE_ORIG],
        ndNetlinkConntrack_attr_parse_tuple, tuple_orig.data()) != MNL_CB_OK) {
        throw ndException("origin %s invalid", "CTA_TUPLE_ORIG");
    }
    if (mnl_attr_parse_nested(attr[CTA_TUPLE_REPLY],
        ndNetlinkConntrack_attr_parse_tuple, tuple_reply.data()) != MNL_CB_OK) {
        throw ndException("reply %s invalid", "CTA_TUPLE_REPLY");
    }

    AttrsIP ip_orig = { 0 }, ip_reply = { 0 };

    if (mnl_attr_parse_nested(tuple_orig[CTA_TUPLE_IP],
        ndNetlinkConntrack_attr_parse_ip, ip_orig.data()) != MNL_CB_OK) {
        throw ndException("origin %s invalid", "CTA_TUPLE_IP");
    }
    if (mnl_attr_parse_nested(tuple_reply[CTA_TUPLE_IP],
        ndNetlinkConntrack_attr_parse_ip, ip_reply.data()) != MNL_CB_OK) {
        throw ndException("reply %s invalid", "CTA_TUPLE_IP");
    }

    if (ip_orig[CTA_IP_V4_SRC]) l3_proto = AF_INET;
    else if (ip_orig[CTA_IP_V6_SRC]) l3_proto = AF_INET6;

    switch (l3_proto) {
    case AF_INET:
        _ND_NLEX_CHECK_ATTR(TAG, ip_orig[CTA_IP_V4_SRC]);
        _ND_NLEX_CHECK_ATTR(TAG, ip_orig[CTA_IP_V4_DST]);
        _ND_NLEX_CHECK_ATTR(TAG, ip_reply[CTA_IP_V4_SRC]);
        _ND_NLEX_CHECK_ATTR(TAG, ip_reply[CTA_IP_V4_DST]);

        ndAddr::Create(orig_addr[ndEnumCast(Direction, SRC)],
            static_cast<struct in_addr *>(
                mnl_attr_get_payload(ip_orig[CTA_IP_V4_SRC])
            )
        );
        ndAddr::Create(orig_addr[ndEnumCast(Direction, DST)],
            static_cast<struct in_addr *>(
                mnl_attr_get_payload(ip_orig[CTA_IP_V4_DST])
            )
        );

        ndAddr::Create(reply_addr[ndEnumCast(Direction, SRC)],
            static_cast<struct in_addr *>(
                mnl_attr_get_payload(ip_reply[CTA_IP_V4_SRC])
            )
        );
        ndAddr::Create(reply_addr[ndEnumCast(Direction, DST)],
            static_cast<struct in_addr *>(
                mnl_attr_get_payload(ip_reply[CTA_IP_V4_DST])
            )
        );
        break;

    case AF_INET6:
        _ND_NLEX_CHECK_ATTR(TAG, ip_orig[CTA_IP_V6_SRC]);
        _ND_NLEX_CHECK_ATTR(TAG, ip_orig[CTA_IP_V6_DST]);
        _ND_NLEX_CHECK_ATTR(TAG, ip_reply[CTA_IP_V6_SRC]);
        _ND_NLEX_CHECK_ATTR(TAG, ip_reply[CTA_IP_V6_DST]);

        ndAddr::Create(orig_addr[ndEnumCast(Direction, SRC)],
            static_cast<struct in6_addr *>(
                mnl_attr_get_payload(ip_orig[CTA_IP_V6_SRC])
            )
        );
        ndAddr::Create(orig_addr[ndEnumCast(Direction, DST)],
            static_cast<struct in6_addr *>(
                mnl_attr_get_payload(ip_orig[CTA_IP_V6_DST])
            )
        );

        ndAddr::Create(reply_addr[ndEnumCast(Direction, SRC)],
            static_cast<struct in6_addr *>(
                mnl_attr_get_payload(ip_reply[CTA_IP_V6_SRC])
            )
        );
        ndAddr::Create(reply_addr[ndEnumCast(Direction, DST)],
            static_cast<struct in6_addr *>(
                mnl_attr_get_payload(ip_reply[CTA_IP_V6_DST])
            )
        );
        break;

    default:
        throw ndException("un-supported address family: %hhu", l3_proto);
    }

    AttrsProto proto_orig = { 0 }, proto_reply = { 0 };

    if (mnl_attr_parse_nested(tuple_orig[CTA_TUPLE_PROTO],
        ndNetlinkConntrack_attr_parse_proto, proto_orig.data()) != MNL_CB_OK) {
        throw ndException("origin %s invalid", "CTA_TUPLE_PROTO");
    }
    if (mnl_attr_parse_nested(tuple_reply[CTA_TUPLE_PROTO],
        ndNetlinkConntrack_attr_parse_proto, proto_reply.data()) != MNL_CB_OK) {
        throw ndException("reply %s invalid", "CTA_TUPLE_PROTO");
    }

    _ND_NLEX_CHECK_ATTR(TAG, proto_orig[CTA_PROTO_NUM]);
    _ND_NLEX_CHECK_ATTR(TAG, proto_reply[CTA_PROTO_NUM]);

    if (mnl_attr_get_u8(proto_orig[CTA_PROTO_NUM]) !=
        mnl_attr_get_u8(proto_reply[CTA_PROTO_NUM])) {
        nd_dprintf(
            "%s: WARNING: origin protocol doesn't match reply.\n", TAG);
    }

    l4_proto = mnl_attr_get_u8(proto_orig[CTA_PROTO_NUM]);

    if (proto_orig[CTA_PROTO_SRC_PORT]) {
        orig_addr[ndEnumCast(Direction, SRC)].SetPort(
            mnl_attr_get_u16(proto_orig[CTA_PROTO_SRC_PORT])
        );
    }
    if (proto_orig[CTA_PROTO_DST_PORT]) {
        orig_addr[ndEnumCast(Direction, DST)].SetPort(
            mnl_attr_get_u16(proto_orig[CTA_PROTO_DST_PORT])
        );
    }
    if (proto_reply[CTA_PROTO_SRC_PORT]) {
        reply_addr[ndEnumCast(Direction, SRC)].SetPort(
            mnl_attr_get_u16(proto_reply[CTA_PROTO_SRC_PORT])
        );
    }
    if (proto_reply[CTA_PROTO_DST_PORT]) {
        reply_addr[ndEnumCast(Direction, DST)].SetPort(
            mnl_attr_get_u16(proto_reply[CTA_PROTO_DST_PORT])
        );
    }

#ifdef _ND_ENABLE_CONNTRACK_MDATA
    if (attr[CTA_MARK])
        mark = ntohl(mnl_attr_get_u32(attr[CTA_MARK]));
#endif

#ifdef _ND_ENABLE_CONNTRACK_COUNTERS
    if (attr[CTA_COUNTERS_ORIG]) {
        AttrsCounters counters = { 0 };

        if (mnl_attr_parse_nested(attr[CTA_COUNTERS_ORIG],
            ndNetlinkConntrack_attr_parse_counters,
            counters.data()) != MNL_CB_OK) {
            throw ndException("origin %s is invalid", "CTA_COUNTERS_ORIG");
        }

        packets[ndEnumCast(Direction, SRC)] =
            be64toh(mnl_attr_get_u64(counters[CTA_COUNTERS_PACKETS]));
        bytes[ndEnumCast(Direction, SRC)] =
            be64toh(mnl_attr_get_u64(counters[CTA_COUNTERS_BYTES]));
#if 0
        nd_printf(
            "%s: origin packets: %llu, bytes: %llu\n",
            TAG,
            packets[ndEnumCast(Direction, SRC)],
            bytes[ndEnumCast(Direction, SRC)]);
#endif
    }

    if (attr[CTA_COUNTERS_REPLY]) {
        AttrsCounters counters = { 0 };

        if (mnl_attr_parse_nested(attr[CTA_COUNTERS_REPLY],
            ndNetlinkConntrack_attr_parse_counters,
            counters.data()) != MNL_CB_OK) {
            throw ndException("reply %s is invalid", "CTA_COUNTERS_REPLY");
        }

        packets[ndEnumCast(Direction, DST)] =
            be64toh(mnl_attr_get_u64(counters[CTA_COUNTERS_PACKETS]));
        bytes[ndEnumCast(Direction, DST)] =
            be64toh(mnl_attr_get_u64(counters[CTA_COUNTERS_BYTES]));
#if 0
        nd_printf(
            "%s: reply packets: %llu, bytes: %llu\n",
            TAG,
            packets[ndEnumCast(Direction, DST)],
            bytes[ndEnumCast(Direction, DST)]);
#endif
    }
#endif // _ND_ENABLE_CONNTRACK_COUNTERS

    updated_at = nd_time_monotonic();

    Hash();
}

void ndConntrackFlow::Hash(void) {
    for (uint8_t i = 0; i < static_cast<uint8_t>(Origin::MAX); i++) {
        uint8_t hdata[128];
        size_t hoff = 0;

        auto hwrite = [&](const void *data, size_t len) {
            if (hoff + len <= sizeof(hdata)) {
                memcpy(&hdata[hoff], data, len);
                hoff += len;
            }
        };

        hwrite(&l3_proto, sizeof(sa_family_t));
        hwrite(&l4_proto, sizeof(uint8_t));

        const ndAddr *src, *dst;

        if (i == static_cast<uint8_t>(Origin::ORIG)) {
            src = &orig_addr[static_cast<int>(Direction::SRC)];
            dst = &orig_addr[static_cast<int>(Direction::DST)];
        }
        else {
            src = &reply_addr[static_cast<int>(Direction::SRC)];
            dst = &reply_addr[static_cast<int>(Direction::DST)];
        }

        uint16_t port = 0;
        int addr_cmp = src->Compare(*dst);

        if (addr_cmp < 0) {
            hwrite(src->GetAddress(), src->GetAddressSize());
            hwrite(dst->GetAddress(), dst->GetAddressSize());

            port = src->GetPort(false);
            hwrite(&port, sizeof(uint16_t));
            port = dst->GetPort(false);
            hwrite(&port, sizeof(uint16_t));
        }
        else {
            hwrite(dst->GetAddress(), dst->GetAddressSize());
            hwrite(src->GetAddress(), src->GetAddressSize());

            port = dst->GetPort(false);
            hwrite(&port, sizeof(uint16_t));
            port = src->GetPort(false);
            hwrite(&port, sizeof(uint16_t));
        }

        digest[i] = nd_xxh64(hdata, hoff);
#ifdef _ND_DEBUG_LOG
        string _digest;
        nd_xxh64_to_string(digest[i], _digest);
        nd_dprintf("%s: %lu: [%hhu]:%s\n", TAG, id, i, _digest.c_str());
#endif
    }
}

void ndConntrackFlow::Print(void) {
#ifdef _ND_DEBUG_LOG
    ndDebugLogStream dls(ndDebugLogStream::Type::FLOW);

    // ID
    dls << TAG << ": " << setw(8) << id << ": ";

    string d1, d2;
    nd_xxh64_to_string(digest[ndEnumCast(Origin, ORIG)], d1);
    nd_xxh64_to_string(digest[ndEnumCast(Origin, REPLY)], d2);

    dls << d1 << ": " << d2 << ": ";

    // L3 proto
    switch (l3_proto) {
    case AF_INET:
        dls << setfill(' ') << dec << setw(2) << 4;
        break;
    case AF_INET6:
        dls << setfill(' ') << dec << setw(2) << 6;
        break;
    }

    // L4 proto
    dls << ": " << setfill(' ') << dec << setw(2) << (unsigned)l4_proto << ": ";

    // Origin addresses
    dls << orig_addr[static_cast<int>(Direction::SRC)].GetString(
            ndAddr::MakeFlags::PORT) << " --> "
        << orig_addr[static_cast<int>(Direction::DST)].GetString(
            ndAddr::MakeFlags::PORT) << " : "
        << reply_addr[static_cast<int>(Direction::SRC)].GetString(
            ndAddr::MakeFlags::PORT) << " --> "
        << reply_addr[static_cast<int>(Direction::DST)].GetString(
            ndAddr::MakeFlags::PORT) << endl;
#endif // _ND_LOG_DEBUG
}
