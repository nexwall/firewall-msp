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

#pragma once

#include <string>

#include "nd-flow-parser.hpp"
#include "nd-util.hpp"

template <class T>
using ndDetectionQueue = std::queue<T, ndLeanQueueAdapter<T, 1000u>>;

class ndDetectionQueueEntry
{
public:
    ndDetectionQueueEntry(ndFlow::Ptr &flow,
      const ndPacket *packet,
      const uint8_t *data,
      uint16_t length)
      : flow(flow), packet(packet), data(data), length(length) { }

    ndDetectionQueueEntry(ndFlow::Ptr &flow)
      : flow(flow) { }

    virtual ~ndDetectionQueueEntry() {
        if (packet != nullptr) delete packet;
    }

    ndFlow::Ptr flow;
    const ndPacket *packet = { nullptr };
    const uint8_t *data = { nullptr };
    uint16_t length = { 0 };
};

class ndDetectionThread : public ndThread, public ndInstanceClient
{
public:
    ndDetectionThread(int16_t cpu, const std::string &tag,
#ifdef _ND_ENABLE_NETLINK
      ndNetlinkRouteThread *netlink,
#ifdef _ND_ENABLE_CONNTRACK
      ndNetlinkConntrackThread *thread_conntrack,
#endif
#endif
      ndDNSHintCache *dhc = NULL,
      ndFlowHashCache *fhc = NULL, uint8_t private_addr = 0);

    virtual ~ndDetectionThread();

    // XXX: Not thread-safe!  Lock before calling...
    virtual void Reload(void);

    void QueuePacket(ndFlow::Ptr &flow,
      const ndPacket *packet = nullptr,
      const uint8_t *data = nullptr,
      uint16_t length = 0);

    struct ndpi_detection_module_struct *GetDetectionModule(void) {
        return ndpi;
    }

    virtual void *Entry(void);

protected:
#ifdef _ND_ENABLE_NETLINK
    ndNetlinkRouteThread *thread_netlink;
#ifdef _ND_ENABLE_CONNTRACK
    ndNetlinkConntrackThread *thread_conntrack;
#endif
#endif
    struct ndpi_detection_module_struct *ndpi;

    ndAddr::PrivatePair private_addrs;

    ndDNSHintCache *dhc;
    ndFlowHashCache *fhc;

    std::string flow_digest, flow_digest_mdata;

    ndDetectionQueue<ndDetectionQueueEntry *> pkt_queue;
    pthread_cond_t pkt_queue_cond;
    pthread_mutex_t pkt_queue_cond_mutex;

    ndFlowParser parser;

    ndProto::Id
    ProtocolLookup(uint16_t id, ndDetectionQueueEntry *entry);

    void ProcessPacketQueue(void);
    void ProcessPacket(ndDetectionQueueEntry *entry);
    void ProcessFlow(ndDetectionQueueEntry *entry);
    bool ProcessALPN(ndDetectionQueueEntry *entry,
      bool client = true);
    void ProcessRisks(ndDetectionQueueEntry *entry);

    void SetHostServerName(ndDetectionQueueEntry *entry,
      const char *host_serer_name);
    void SetDetectedProtocol(ndDetectionQueueEntry *entry,
      ndProto::Id id);
    void SetDetectedApplication(ndDetectionQueueEntry *entry,
      ndApp::Id id);

    void DispatchEvent(ndDetectionQueueEntry *entry);

    void DetectionUpdate(ndDetectionQueueEntry *entry);
    void DetectionGuess(ndDetectionQueueEntry *entry);
    void DetectionComplete(ndDetectionQueueEntry *entry);

#ifdef _ND_ENABLE_DEBUG_STATS
    uint64_t flows = { 0 };
    uint64_t pkts = { 0 };
    uint64_t queued_pkts = { 0 };
    uint64_t queued_size = { 0 };
    uint64_t max_queued_pkts = { 0 };
    uint64_t max_queued_size = { 0 };
#endif
};
