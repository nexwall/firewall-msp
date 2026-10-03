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

#include <atomic>
#include <string>

#include <pcap/pcap.h>

#include "nd-except.hpp"
#include "nd-flags.hpp"
#include "nd-instance.hpp"
#include "nd-packet.hpp"
#include "nd-thread.hpp"
#include "nd-util.hpp"

class ndCaptureThread : public ndThread, public ndInstanceClient
{
public:
    ndCaptureThread(ndFlags<ndCaptureType> cs_type, int16_t cpu,
      ndInterface::Ptr &iface, const ndDetectionThreads &threads_dpi,
      ndDNSHintCache *dhc = NULL, uint8_t private_addr = 0);

    virtual ~ndCaptureThread() { }

    virtual void *Entry(void) = 0;

    // XXX: Ensure thread is locked before calling!
    virtual void GetCaptureStats(ndPacketStats &stats) {
        this->stats.AddAndReset(stats);
    }

    enum class State : uint8_t {
        INIT,
        ONLINE,
        OFFLINE,
    };

    inline State GetState(void) const {
        return capture_state.load();
    }

    static void CompileFilter(const std::string &filter,
        struct bpf_program &bpf_filter, pcap_t *pcap = nullptr);

protected:
    int dl_type = { 0 };
    ndFlags<ndCaptureType> cs_type;

    ndInterface::Ptr iface;
    ndFlow flow;

    time_t tv_epoch = { 0 };
    uint64_t ts_pkt_first = { 0 };
    uint64_t ts_pkt_last = { 0 };

    ndAddr::PrivatePair private_addrs;

    ndPacketStats stats;

    ndDNSHintCache *dhc;

    const ndDetectionThreads &threads_dpi;
    int16_t dpi_thread_id;

    typedef const ndPacket *(ndCaptureThread::*ProcessPacketFunc)(ndPacket *);
    ProcessPacketFunc process_packet_func = nullptr;

    template <int DL_TYPE>
    const ndPacket *ProcessPacketImpl(ndPacket *packet);

    const ndPacket *ProcessPacket(ndPacket *packet);

    bool ProcessDNSPacket(ndFlow::Ptr &flow,
      const uint8_t *pkt, uint16_t pkt_len, ndProto::Id proto);

    std::atomic<State> capture_state = { State::INIT };
};
