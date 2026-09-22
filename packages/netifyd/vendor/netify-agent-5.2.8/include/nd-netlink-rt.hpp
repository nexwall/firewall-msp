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

#include <atomic>

#include <linux/rtnetlink.h>

#include "nd-netlink.hpp"
#include "nd-thread.hpp"

class ndNetlinkRouteThread : public ndThread, public ndNetlink
{
public:
    ndNetlinkRouteThread(void);
    virtual ~ndNetlinkRouteThread();

    virtual void *Entry();

    virtual int ProcessMessage(const struct nlmsghdr *nlh);

    void Dump(void);

    class Stats {
    public:
        struct {
            std::atomic<uint32_t> added = { 0 };
            std::atomic<uint32_t> removed = { 0 };
            std::atomic<uint32_t> error = { 0 };
        } addr;
        struct {
            std::atomic<uint32_t> added = { 0 };
            std::atomic<uint32_t> removed = { 0 };
            std::atomic<uint32_t> error = { 0 };
        } net;
        struct {
            std::atomic<uint32_t> added = { 0 };
            std::atomic<uint32_t> removed = { 0 };
            std::atomic<uint32_t> error = { 0 };
        } link;
        struct {
            std::atomic<uint32_t> added = { 0 };
            std::atomic<uint32_t> removed = { 0 };
            std::atomic<uint32_t> error = { 0 };
        } neigh;
    };

    void GetStats(Stats &stats);
    void PrintStats(const Stats &stats) const;

    typedef std::array<struct nlattr *, IFA_MAX + 1> AttrsAddr;
    typedef std::array<struct nlattr *, RTA_MAX + 1> AttrsRoute;
    typedef std::array<struct nlattr *, IFLA_MAX + 1> AttrsLink;
    typedef std::array<struct nlattr *, IFLA_INFO_MAX + 1> AttrsLinkInfo;
    typedef std::array<struct nlattr *, IFLA_VLAN_MAX + 1> AttrsLinkVLAN;
    typedef std::array<struct nlattr *, NDA_MAX + 1> AttrsNeigh;

protected:
    int AddRemoveAddress(const struct nlmsghdr *nlh, bool add = true);
    int AddRemoveNetwork(const struct nlmsghdr *nlh, bool add = true);
    int AddRemoveLink(const struct nlmsghdr *nlh, bool add = true);
    int AddRemoveNeighbor(const struct nlmsghdr *nlh, bool add = true);

#if defined(_ND_ENABLE_INTERFACE_METADATA)
    void UpdateNFTablesMapping(int ifindex, uint32_t mark, bool add);
#if defined(_ND_ENABLE_UBUS)
    std::string GetWirelessSSID(const char* ifname);
#endif // _ND_ENABLE_UBUS
#endif // _ND_ENABLE_INTERFACE_METADATA

    Stats stats;
};
