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

#pragma once

#include <inttypes.h>

#include <ctime>
#include <memory>
#include <mutex>
#include <unordered_map>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include "nd-addr.hpp"
#include "nd-flow.hpp"
#include "nd-netlink.hpp"
#include "nd-thread.hpp"
#include "nd-util.hpp"

class ndConntrackFlow;

class ndNetlinkConntrackThread : public ndThread, public ndNetlink
{
public:
    ndNetlinkConntrackThread(void);
    virtual ~ndNetlinkConntrackThread();

    virtual void *Entry(void);

    virtual int ProcessMessage(const struct nlmsghdr *nlh);

    void Dump(bool zero_counters = false);
    void Sweep(time_t timeout);

    void UpdateFlow(ndFlow::Ptr &flow);
#if defined(_ND_ENABLE_CONNTRACK_COUNTERS)
    bool UpdateFlowStats(ndFlow::Ptr &flow, const struct timeval &stamp) const;
#endif
    class Stats {
    public:
        uint32_t created = { 0 };
        uint32_t updated = { 0 };
        uint32_t destroyed = { 0 };
        uint32_t lookups = { 0 };
        uint32_t matches = { 0 };
        uint32_t total_ids = { 0 };
        uint32_t total_flows = { 0 };
    };

    void GetStats(Stats &stats) {
        std::lock_guard<std::mutex> lg(map_lock);

        stats = this->stats;
        stats.total_ids = (uint32_t)id_flows.size();
        stats.total_flows = (uint32_t)digest_flows.size();

        this->stats.lookups = this->stats.matches = 0;
        this->stats.created = this->stats.updated = this->stats.destroyed = 0;
    };

    void PrintStats(const Stats &stats) {
        nd_dprintf("%s: created: %" PRIu32 ", updated: %" PRIu32
            ", destroyed: %" PRIu32 ", lookups: %" PRIu32
            ", matches: %" PRIu32 ", total ids: %" PRIu32
            ", total flows: %" PRIu32 "\n", tag.c_str(),
            stats.created, stats.updated, stats.destroyed,
            stats.lookups, stats.matches,
            stats.total_ids, stats.total_flows
        );
    }

    typedef std::array<struct nlattr *, CTA_MAX + 1> Attrs;

protected:
    bool NewFlow(uint32_t id, const Attrs &attrs);
    bool UpdateFlow(uint32_t id, const Attrs &attrs);
    void DestroyFlow(uint32_t id);

    mutable std::mutex map_lock;

    typedef std::unordered_map<uint32_t,
        std::shared_ptr<ndConntrackFlow>> IdFlowMap;
    typedef std::unordered_map<ndDigest,
        std::shared_ptr<ndConntrackFlow>> DigestFlowMap;

    IdFlowMap id_flows;
    DigestFlowMap digest_flows;

    Stats stats;
};

class ndConntrackFlow
{
public:
    enum class Origin : uint8_t { ORIG, REPLY, MAX };
    enum class Direction : uint8_t { SRC, DST, MAX };

    typedef std::pair<ndConntrackFlow *, void *> Attrs;
    typedef std::array<struct nlattr *, CTA_IP_MAX + 1> AttrsIP;
    typedef std::array<struct nlattr *, CTA_PROTO_MAX + 1> AttrsProto;
    typedef std::array<struct nlattr *, CTA_TUPLE_MAX + 1> AttrsTuple;
    typedef std::array<struct nlattr *, CTA_COUNTERS_MAX + 1> AttrsCounters;

    ndConntrackFlow(uint32_t id,
        const ndNetlinkConntrackThread::Attrs &attr);

    void Update(const ndNetlinkConntrackThread::Attrs &attr);

    inline uint32_t GetId(void) { return id; }

    void Print(void);

protected:
    friend class ndNetlinkConntrackThread;

    void Hash(void);

    uint32_t id = { 0 };
#if defined(_ND_ENABLE_CONNTRACK_MDATA)
    uint32_t mark = { 0 };
#endif
    time_t updated_at = { 0 };
    ndDigest digest[2];
    sa_family_t l3_proto = { 0 };
    uint8_t l4_proto = { 0 };
    ndAddr orig_addr[2];
    ndAddr reply_addr[2];
#if defined(_ND_ENABLE_CONNTRACK_COUNTERS)
    uint64_t packets[2] = { 0, 0 };
    uint64_t bytes[2] = { 0, 0 };
#endif
};
