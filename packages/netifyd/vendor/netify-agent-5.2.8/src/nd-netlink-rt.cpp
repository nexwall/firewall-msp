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
#include <vector>

#include <arpa/inet.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <netinet/in.h>

#include <libmnl/libmnl.h>

#if defined(_ND_ENABLE_INTERFACE_METADATA)
#include <libnftnl/set.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#endif // _ND_ENABLE_INTERFACE_METADATA

#include "nd-except.hpp"
#include "nd-instance.hpp"
#include "nd-netlink-rt.hpp"
#if defined(_ND_ENABLE_INTERFACE_METADATA) && defined(_ND_ENABLE_UBUS)
#include "nd-ubus.hpp"
#endif
#include "nd-util.hpp"

// Enable Conntrack debug logging
// #define _ND_DEBUG_LOG   1

#ifndef IFLA_EXT_MASK
#define IFLA_EXT_MASK 29
#endif

#ifndef AF_BRIDGE
#define AF_BRIDGE 7
#endif

// Manual definitions with unique names to avoid Musl/Kernel conflicts
#ifndef IFLA_BRIDGE_VLAN_INFO
#define IFLA_BRIDGE_VLAN_INFO 2
#endif

#ifndef BRIDGE_VLAN_INFO_PVID
#define BRIDGE_VLAN_INFO_PVID (1 << 1)
#endif

#ifndef RTEXT_FILTER_BRVLAN
#define RTEXT_FILTER_BRVLAN (1 << 1)
#endif

using namespace std;
using json = nlohmann::json;

// We use "nd_" prefix so the compiler never confuses this with system types
struct nd_bridge_vlan_info {
    uint16_t flags;
    uint16_t vid;
};

constexpr const char *TAG = { "netlink-rt" };

#if defined(_ND_ENABLE_INTERFACE_METADATA)
// Netlink error callback to capture the specific errno from the kernel ACK
static int ndNetlinkRoute_nft_error_cb(
  const struct nlmsghdr *nlh, void *data)
{
    if (nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = static_cast<struct nlmsgerr *>(
          mnl_nlmsg_get_payload(nlh));
        if (err->error != 0) {
            *(int *)data = err->error;
        }
    }
    return MNL_CB_OK;
}
#endif

static int ndNetlinkRoute_attr_parse_ifav4(
    const struct nlattr *attr, void *data) {
    const struct nlattr **tb = static_cast<const struct nlattr **>(data);
    int type = mnl_attr_get_type(attr);

    if (mnl_attr_type_valid(attr, IFA_MAX) < 0)
        return MNL_CB_OK;

    switch(type) {
    case IFA_LOCAL:
    case IFA_ADDRESS:
    case IFA_BROADCAST:
        if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
            nd_dprintf("%s: invalid attribute type, expected: %s\n",
                TAG, "U32");
            return MNL_CB_ERROR;
        }
        break;
    }

    tb[type] = attr;

    return MNL_CB_OK;
}

static int ndNetlinkRoute_attr_parse_ifav6(
    const struct nlattr *attr, void *data) {
    const struct nlattr **tb = static_cast<const struct nlattr **>(data);
    int type = mnl_attr_get_type(attr);

    if (mnl_attr_type_valid(attr, IFA_MAX) < 0)
        return MNL_CB_OK;

    switch(type) {
    case IFA_LOCAL:
    case IFA_ADDRESS:
        if (mnl_attr_validate2(
            attr, MNL_TYPE_BINARY, sizeof(struct in6_addr)) < 0) {
            nd_dprintf("%s: invalid attribute type, expected: %s\n",
                TAG, "BINARY");
            return MNL_CB_ERROR;
        }
        break;
    }

    tb[type] = attr;

    return MNL_CB_OK;
}

static int ndNetlinkRoute_attr_parse_rtav4(
    const struct nlattr *attr, void *data) {
    const struct nlattr **tb = static_cast<const struct nlattr **>(data);
    int type = mnl_attr_get_type(attr);

    if (mnl_attr_type_valid(attr, RTA_MAX) < 0)
        return MNL_CB_OK;

    switch(type) {
    case RTA_DST:
    case RTA_OIF:
        if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
            nd_dprintf("%s: invalid attribute type, expected: %s\n",
                TAG, "U32");
            return MNL_CB_ERROR;
        }
        break;
    }

    tb[type] = attr;

    return MNL_CB_OK;
}

static int ndNetlinkRoute_attr_parse_rtav6(
    const struct nlattr *attr, void *data) {
    const struct nlattr **tb = static_cast<const struct nlattr **>(data);
    int type = mnl_attr_get_type(attr);

    if (mnl_attr_type_valid(attr, RTA_MAX) < 0)
        return MNL_CB_OK;

    switch(type) {
    case RTA_DST:
        if (mnl_attr_validate2(
            attr, MNL_TYPE_BINARY, sizeof(struct in6_addr)) < 0) {
            nd_dprintf("%s: invalid attribute type, expected: %s\n",
                TAG, "BINARY");
            return MNL_CB_ERROR;
        }
        break;
    case RTA_OIF:
        if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
            nd_dprintf("%s: invalid attribute type, expected: %s\n",
                TAG, "U32");
            return MNL_CB_ERROR;
        }
        break;
    }

    tb[type] = attr;

    return MNL_CB_OK;
}

static int ndNetlinkRoute_attr_parse_ifla(
    const struct nlattr *attr, void *data) {
    const struct nlattr **tb = static_cast<const struct nlattr **>(data);
    int type = mnl_attr_get_type(attr);

    if (mnl_attr_type_valid(attr, IFLA_MAX) < 0)
        return MNL_CB_OK;

    switch(type) {
    case IFLA_ADDRESS:
        if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0) {
            nd_dprintf("%s: invalid attribute type, expected: %s\n",
                TAG, "BINARY");
            return MNL_CB_ERROR;
        }
        break;

    case IFLA_LINKINFO:
    case IFLA_AF_SPEC:
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

static int ndNetlinkRoute_attr_parse_linkinfo(
    const struct nlattr *attr, void *data) {
    const struct nlattr **tb = static_cast<const struct nlattr **>(data);
    int type = mnl_attr_get_type(attr);

    if (mnl_attr_type_valid(attr, IFLA_INFO_MAX) < 0)
        return MNL_CB_OK;

    switch(type) {
    case IFLA_INFO_KIND:
        if (mnl_attr_validate(attr, MNL_TYPE_NUL_STRING) < 0) {
            nd_dprintf("%s: invalid attribute type, expected: %s\n",
                TAG, "NUL_STRING");
            return MNL_CB_ERROR;
        }
        break;

    case IFLA_INFO_DATA:
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

static int ndNetlinkRoute_attr_parse_vlan(
    const struct nlattr *attr, void *data) {
    const struct nlattr **tb = static_cast<const struct nlattr **>(data);
    int type = mnl_attr_get_type(attr);

    if (mnl_attr_type_valid(attr, IFLA_VLAN_MAX) < 0)
        return MNL_CB_OK;

    switch(type) {
    case IFLA_VLAN_ID:
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

static int ndNetlinkRoute_attr_parse_nda(
    const struct nlattr *attr, void *data) {
    const struct nlattr **tb = static_cast<const struct nlattr **>(data);
    int type = mnl_attr_get_type(attr);

    if (mnl_attr_type_valid(attr, NDA_MAX) < 0)
        return MNL_CB_OK;

    switch(type) {
    case NDA_DST:
    case NDA_LLADDR:
        if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0) {
            nd_dprintf("%s: invalid attribute type, expected: %s\n",
                TAG, "BINARY");
            return MNL_CB_ERROR;
        }
        break;
    }

    tb[type] = attr;

    return MNL_CB_OK;
}

class ndNetlinkRouteDump : public ndNetlink
{
public:
    ndNetlinkRouteDump(ndNetlink *parent)
        : ndNetlink(NETLINK_ROUTE), parent(parent) {
    }

    int ProcessMessage(const struct nlmsghdr *nlh) {
        return parent->ProcessMessage(nlh);
    }

    bool Dump(uint16_t type, sa_family_t family = AF_UNSPEC) {
        struct nlmsghdr *nlh = mnl_nlmsg_put_header(socket_buffer.data());
        nlh->nlmsg_type = type;

        if (type == RTM_GETADDR) {
            struct rtgenmsg *rtgh = static_cast<struct rtgenmsg *>(
                mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtgenmsg))
            );
            rtgh->rtgen_family = family;
        }
        else if (type == RTM_GETROUTE) {
            struct rtmsg *rth = static_cast<struct rtmsg *>(
                mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg))
            );
            rth->rtm_family = family;
        }
        else if (type == RTM_GETLINK) {
            struct ifinfomsg *ifi = static_cast<struct ifinfomsg *>(
                mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg))
            );
            ifi->ifi_family = family;
            // Request Bridge VLAN information (PVIDs, etc)
            mnl_attr_put_u32(nlh, IFLA_EXT_MASK, RTEXT_FILTER_BRVLAN);
        }
        else if (type == RTM_GETNEIGH) {
            struct ndmsg *ndh = static_cast<struct ndmsg *>(
                mnl_nlmsg_put_extra_header(nlh, sizeof(struct ndmsg))
            );
            ndh->ndm_family = family;
        }

        try {
            if (Send(nlh)) return (Recv());
        }
        catch (exception &e) {
            nd_printf("Exception while dumping RT table: %s\n", e.what());
        }

        return false;
    }

protected:
    ndNetlink *parent;
};

ndNetlinkRouteThread::ndNetlinkRouteThread(void)
    : ndThread(TAG),
        ndNetlink(NETLINK_ROUTE,
            RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE |
            RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE |
            RTMGRP_LINK | RTMGRP_NEIGH
        ) { }

ndNetlinkRouteThread::~ndNetlinkRouteThread() {
    Join();
}

void *ndNetlinkRouteThread::Entry(void) {
    int rc;
    fd_set fds_read;
    int fd = GetDescriptor();

    while (! ShouldTerminate()) {
        FD_ZERO(&fds_read);
        FD_SET(fd, &fds_read);

        struct timeval tv = { 1, 0 };
        rc = select(fd + 1, &fds_read, nullptr, nullptr, &tv);

        if (rc == -1) {
            throw ndExceptionSystemError("select", strerror(errno));
        }

        if (FD_ISSET(fd, &fds_read)) {
            try {
                if (! Recv())
                    nd_printf("Error while reading RT message.\n");
            }
            catch (exception &e) {
                nd_printf("Exception while reading RT message: %s\n", e.what());
            }
        }
    }

    nd_dprintf("%s: Exit.\n", tag.c_str());

    return nullptr;
}

int ndNetlinkRouteThread::ProcessMessage(const struct nlmsghdr *nlh) {
#if 0
    struct nfgenmsg *nfg = static_cast<struct nfgenmsg *>(
        mnl_nlmsg_get_payload(nlh)
    );
    nd_dprintf(
        "%s: NLMSG: %hu, len: %u (%u, %u), flags: 0x%x, seq: %u, pid: %u, family: %hhu\n",
        tag.c_str(), nlh->nlmsg_type, nlh->nlmsg_len,
        NLMSG_HDRLEN, NLMSG_LENGTH(nlh->nlmsg_len),
        nlh->nlmsg_flags, nlh->nlmsg_seq, nlh->nlmsg_pid, nfg->nfgen_family);
#endif
    int rc;

    switch (nlh->nlmsg_type) {
    case RTM_NEWADDR:
        if ((rc = AddRemoveAddress(nlh)) < 0) stats.addr.error++;
        else stats.addr.added += rc;
        break;

    case RTM_DELADDR:
        if ((rc = AddRemoveAddress(nlh, false)) < 0) stats.addr.error++;
        else stats.addr.removed += rc;
        break;

    case RTM_NEWROUTE:
        if ((rc = AddRemoveNetwork(nlh)) < 0) stats.net.error++;
        else stats.net.added += rc;
        break;

    case RTM_DELROUTE:
        if ((rc = AddRemoveNetwork(nlh, false)) < 0) stats.net.error++;
        else stats.net.removed += rc;
        break;

    case RTM_NEWLINK:
        if ((rc = AddRemoveLink(nlh)) < 0) stats.link.error++;
        else stats.link.added += rc;
        break;

    case RTM_DELLINK:
        if ((rc = AddRemoveLink(nlh, false)) < 0) stats.link.error++;
        else stats.link.removed += rc;
        break;

    case RTM_NEWNEIGH:
        if ((rc = AddRemoveNeighbor(nlh)) < 0) stats.neigh.error++;
        else stats.neigh.added += rc;
        break;

    case RTM_DELNEIGH:
        if ((rc = AddRemoveNeighbor(nlh, false)) < 0) stats.neigh.error++;
        else stats.neigh.removed += rc;
        break;
    }

    return MNL_CB_OK;
}

void ndNetlinkRouteThread::Dump(void) {
    ndNetlinkRouteDump rt_dump(this);

    rt_dump.Dump(RTM_GETADDR);
    rt_dump.Dump(RTM_GETROUTE);
    rt_dump.Dump(RTM_GETLINK);
#if defined(_ND_ENABLE_INTERFACE_METADATA)
    // Need to make a specific call to Netlink specifing family
    // otherwise kernel does not return the bridge VLAN metadata
    // we're looking for
    if (ndGC.mark_to_ifindex_enable) {
        rt_dump.Dump(RTM_GETLINK, AF_BRIDGE);
    }
#endif
    rt_dump.Dump(RTM_GETNEIGH);
}

void ndNetlinkRouteThread::GetStats(Stats &stats) {
    stats.addr.added = this->stats.addr.added.exchange(0);
    stats.addr.removed = this->stats.addr.removed.exchange(0);
    stats.addr.error = this->stats.addr.error.exchange(0);

    stats.net.added = this->stats.net.added.exchange(0);
    stats.net.removed = this->stats.net.removed.exchange(0);
    stats.net.error = this->stats.net.error.exchange(0);

    stats.link.added = this->stats.link.added.exchange(0);
    stats.link.removed = this->stats.link.removed.exchange(0);
    stats.link.error = this->stats.link.error.exchange(0);

    stats.neigh.added = this->stats.neigh.added.exchange(0);
    stats.neigh.removed = this->stats.neigh.removed.exchange(0);
    stats.neigh.error = this->stats.neigh.error.exchange(0);
}

void ndNetlinkRouteThread::PrintStats(const Stats &stats) const {
    nd_dprintf("%s: addresses added: %lu, removed: %lu, errors: %lu\n",
        tag.c_str(), stats.addr.added.load(),
        stats.addr.removed.load(), stats.addr.error.load()
    );
    nd_dprintf("%s: networks added: %lu, removed: %lu, errors: %lu\n",
        tag.c_str(), stats.net.added.load(),
        stats.net.removed.load(), stats.net.error.load()
    );
    nd_dprintf("%s: links added: %lu, removed: %lu, errors: %lu\n",
        tag.c_str(), stats.link.added.load(),
        stats.link.removed.load(), stats.link.error.load()
    );
    nd_dprintf("%s: neighbors added: %lu, removed: %lu, errors: %lu\n",
        tag.c_str(), stats.neigh.added.load(),
        stats.neigh.removed.load(), stats.neigh.error.load()
    );
}

int ndNetlinkRouteThread::AddRemoveAddress(const struct nlmsghdr *nlh, bool add) {
    int rc = -1;

    const struct ifaddrmsg *ifa = static_cast<const struct ifaddrmsg *>(
        mnl_nlmsg_get_payload(nlh)
    );

    char ifname[IFNAMSIZ] = { '\0' };
    if (if_indextoname(ifa->ifa_index, ifname) == nullptr) {
        nd_dprintf("%s: %s: if_indextoname(%d): %s\n",
            TAG, __PRETTY_FUNCTION__, ifa->ifa_index, strerror(errno));
        return rc;
    }

    AttrsAddr attrs = { 0 };

    switch(ifa->ifa_family) {
    case AF_INET:
        if (mnl_attr_parse(nlh, sizeof(*ifa),
            ndNetlinkRoute_attr_parse_ifav4, attrs.data()) != MNL_CB_OK)
            return rc;
        break;
    case AF_INET6:
        if (mnl_attr_parse(nlh, sizeof(*ifa),
            ndNetlinkRoute_attr_parse_ifav6, attrs.data()) != MNL_CB_OK)
            return rc;
        break;
    default:
        nd_dprintf(
            "%s: unsupported address family: %d\n",
            TAG, ifa->ifa_family
        );
        return rc;
    }

    rc = 0;
    for (unsigned i = 0; i < attrs.size(); i++) {
        ndAddr addr;
        ndAddr::Type type = ndAddr::Type::LOCAL;

        switch(ifa->ifa_family) {
        case AF_INET:
#if 0
            if (i == IFA_LOCAL && attrs[IFA_LOCAL]) {
                ndAddr::Create(addr,
                    static_cast<struct in_addr *>(
                        mnl_attr_get_payload(attrs[IFA_LOCAL])
                    )
                );
            }
#endif
            if (i == IFA_ADDRESS && attrs[IFA_ADDRESS]) {
                ndAddr::Create(addr,
                    static_cast<struct in_addr *>(
                        mnl_attr_get_payload(attrs[IFA_ADDRESS])
                    )
                );
            }
            if (i == IFA_BROADCAST && attrs[IFA_BROADCAST]) {
                type = ndAddr::Type::BROADCAST;
                ndAddr::Create(addr,
                    static_cast<struct in_addr *>(
                        mnl_attr_get_payload(attrs[IFA_BROADCAST])
                    )
                );
            }
            break;

        case AF_INET6:
#if 0
            if (i == IFA_LOCAL && attrs[IFA_LOCAL]) {
                ndAddr::Create(addr,
                    static_cast<struct in6_addr *>(
                        mnl_attr_get_payload(attrs[IFA_LOCAL])
                    )
                );
            }
#endif
            if (i == IFA_ADDRESS && attrs[IFA_ADDRESS]) {
                ndAddr::Create(addr,
                    static_cast<struct in6_addr *>(
                        mnl_attr_get_payload(attrs[IFA_ADDRESS])
                    )
                );
            }
            break;
        }

        if (addr.IsValid()) {
            ndInstance &ndi = ndInstance::GetInstance();
            if (add) {
#ifdef _ND_DEBUG_LOG
                nd_dprintf("%s: adding address: %s: %s\n", TAG, ifname,
                    addr.GetString().c_str()
                );
#endif
                if (ndi.addr_lookup.AddAddress(type, addr, ifname)) rc++;
            }
            else {
#ifdef _ND_DEBUG_LOG
                nd_dprintf("%s: removing address: %s: %s\n", TAG, ifname,
                    addr.GetString().c_str()
                );
#endif
                if (ndi.addr_lookup.RemoveAddress(addr, ifname)) rc++;
            }
        }
    }

    return rc;
}

int ndNetlinkRouteThread::AddRemoveNetwork(const struct nlmsghdr *nlh, bool add) {
    const struct rtmsg *rtm = static_cast<const struct rtmsg *>(
        mnl_nlmsg_get_payload(nlh)
    );

    if (rtm->rtm_type != RTN_UNICAST) return 0;

    AttrsRoute attrs = { 0 };

    switch(rtm->rtm_family) {
    case AF_INET:
        if (mnl_attr_parse(nlh, sizeof(*rtm),
            ndNetlinkRoute_attr_parse_rtav4, attrs.data()) != MNL_CB_OK)
            return -1;
        break;

    case AF_INET6:
        if (mnl_attr_parse(nlh, sizeof(*rtm),
            ndNetlinkRoute_attr_parse_rtav6, attrs.data()) != MNL_CB_OK)
            return -1;
        break;
    default:
        nd_dprintf(
            "%s: unsupported address family: %d\n",
            TAG, rtm->rtm_family
        );
        return 0;
    }

    if (!attrs[RTA_DST] || !attrs[RTA_OIF]) {
        return 0;
    }

    ndAddr addr;
    switch(rtm->rtm_family) {
    case AF_INET:
        ndAddr::Create(addr,
            static_cast<struct in_addr *>(
                mnl_attr_get_payload(attrs[RTA_DST])
            ), rtm->rtm_dst_len
        );
        break;
    case AF_INET6:
        ndAddr::Create(addr,
            static_cast<struct in6_addr *>(
                mnl_attr_get_payload(attrs[RTA_DST])
            ), rtm->rtm_dst_len
        );
        break;
    }

    char ifname[IFNAMSIZ] = { '\0' };
    if (if_indextoname(mnl_attr_get_u32(attrs[RTA_OIF]), ifname) == nullptr) {
        nd_dprintf("%s: %s: if_indextoname(%u): %s\n", TAG, __PRETTY_FUNCTION__,
            mnl_attr_get_u32(attrs[RTA_OIF]), strerror(errno));
        return -1;
    }

    if (addr.IsValid() && ifname[0] != '\0') {
        ndInstance &ndi = ndInstance::GetInstance();
        if (add) {
#ifdef _ND_DEBUG_LOG
            nd_dprintf("%s: adding network: %s: %s\n", TAG, ifname,
                addr.GetString(ndAddr::MakeFlags::PREFIX).c_str());
#endif
            return (ndi.addr_lookup.AddAddress(
              ndAddr::Type::LOCAL, addr, ifname)) ? 1 : 0;
        }
        else {
#ifdef _ND_DEBUG_LOG
            nd_dprintf("%s: removing network: %s: %s\n", TAG, ifname,
                addr.GetString(ndAddr::MakeFlags::PREFIX).c_str());
#endif
            return (ndi.addr_lookup.RemoveAddress(
                addr, ifname)) ? 1 : 0;
        }
    }

    return 0;
}

int ndNetlinkRouteThread::AddRemoveLink(const struct nlmsghdr *nlh, bool add) {
    const struct ifinfomsg *ifi = static_cast<const struct ifinfomsg *>(
        mnl_nlmsg_get_payload(nlh)
    );

    int rc = 0;
    ndInstance &ndi = ndInstance::GetInstance();
    char ifname[IFNAMSIZ] = { '\0' };

    if (add) {
        if (if_indextoname(ifi->ifi_index, ifname) == nullptr) {
            nd_dprintf("%s: %s: if_indextoname(%d): %s\n",
                TAG, __PRETTY_FUNCTION__, ifi->ifi_index, strerror(errno));
            return -1;
        }

        nd_dprintf("%s: RTM_NEWLINK: %s\n", TAG, ifname);

        if (ndi.addr_lookup.AddLinkName(ifi->ifi_index, ifname)) rc = 1;

#if defined(_ND_ENABLE_INTERFACE_METADATA) && defined(_ND_ENABLE_UBUS)
        std::string ssid = this->GetWirelessSSID(ifname);
        if (!ssid.empty()) {
            nd_dprintf("%s: %s SSID: %s\n", TAG, ifname, ssid.c_str());
            ndi.addr_lookup.AddLinkSSID(ifi->ifi_index, ssid);
        }

        if (ndGC.mark_to_ifindex_enable &&
          ndGC.mark_to_ifindex_firewall == "nft") {
            uint32_t mark = (uint32_t)ifi->ifi_index
              << ndGC.mark_to_ifindex_mark_shift;

            this->UpdateNFTablesMapping(ifi->ifi_index, mark, true);
        }
#endif
        AttrsLink attrs = { 0 };

        if (mnl_attr_parse(nlh, sizeof(*ifi),
            ndNetlinkRoute_attr_parse_ifla, attrs.data()) != MNL_CB_OK)
            return -1;

        if (attrs[IFLA_LINKINFO]) {
            AttrsLinkInfo linkinfo_attrs = { 0 };

            if (mnl_attr_parse_nested(attrs[IFLA_LINKINFO],
                ndNetlinkRoute_attr_parse_linkinfo,
                linkinfo_attrs.data()) != MNL_CB_OK) {
                throw ndException("infolink %s invalid", "IFLA_LINKINFO");
            }

            if (linkinfo_attrs[IFLA_INFO_KIND] &&
                linkinfo_attrs[IFLA_INFO_DATA]) {
                const char *kind = mnl_attr_get_str(
                    linkinfo_attrs[IFLA_INFO_KIND]
                );

                if ((int16_t)mnl_attr_get_payload_len(
                    linkinfo_attrs[IFLA_INFO_KIND]) > 0 &&
                    ! strncasecmp(kind, "vlan", 4)) {

                    AttrsLinkVLAN vlan_attrs = { 0 };

                    if (mnl_attr_parse_nested(linkinfo_attrs[IFLA_INFO_DATA],
                        ndNetlinkRoute_attr_parse_vlan,
                        vlan_attrs.data()) != MNL_CB_OK) {
                        throw ndException("vlan %s invalid", "IFLA_INFO_DATA");
                    }

                    if (vlan_attrs[IFLA_VLAN_ID]) {
                        uint16_t pvid = mnl_attr_get_u16(
                            vlan_attrs[IFLA_VLAN_ID]
                        );

                        nd_dprintf("%s: PVID: %hu\n", ifname, pvid);
                        ndi.addr_lookup.AddLinkPVID(ifi->ifi_index, pvid);
                    }
                }
            }
        }
#if defined(_ND_ENABLE_INTERFACE_METADATA)
        if (ndGC.mark_to_ifindex_enable && attrs[IFLA_AF_SPEC]) {
            int rem = mnl_attr_get_payload_len(attrs[IFLA_AF_SPEC]);
            const struct nlattr *af_spec_attr =
                static_cast<const struct nlattr *>(mnl_attr_get_payload(attrs[IFLA_AF_SPEC]));

            while (mnl_attr_ok(af_spec_attr, rem)) {
                uint16_t type = mnl_attr_get_type(af_spec_attr);

                // --- CASE 1: Nested Data (Inside AF_BRIDGE/7 folder) ---
                if (type == AF_BRIDGE) {
                    const struct nlattr *br_attr =
                        static_cast<const struct nlattr *>(mnl_attr_get_payload(af_spec_attr));
                    int br_rem = mnl_attr_get_payload_len(af_spec_attr);

                    while (mnl_attr_ok(br_attr, br_rem)) {
                        if (mnl_attr_get_type(br_attr) == IFLA_BRIDGE_VLAN_INFO) {
                            const char *payload = static_cast<const char *>(mnl_attr_get_payload(br_attr));
                            int vlen = mnl_attr_get_payload_len(br_attr);

                            for (int i = 0; i <= vlen - (int)sizeof(nd_bridge_vlan_info); i += sizeof(nd_bridge_vlan_info)) {
                                const struct nd_bridge_vlan_info *vinfo =
                                    reinterpret_cast<const struct nd_bridge_vlan_info *>(payload + i);

                                if (vinfo->flags & BRIDGE_VLAN_INFO_PVID) {
                                    nd_dprintf("%s: %s PVID (Nested): %hu\n",TAG, ifname, vinfo->vid);
                                    ndi.addr_lookup.AddLinkPVID(ifi->ifi_index, vinfo->vid);
                                    goto next_interface;
                                }
                            }
                        }
                        int b_len = mnl_attr_get_len(br_attr);
                        br_attr = mnl_attr_next(br_attr);
                        br_rem -= MNL_ALIGN(b_len);
                    }
                }
                // --- CASE 2: Direct Data (Type 2 is VLAN Info because header is AF_BRIDGE) ---
                else if (type == IFLA_BRIDGE_VLAN_INFO && ifi->ifi_family == AF_BRIDGE) {
                    const char *payload = static_cast<const char *>(mnl_attr_get_payload(af_spec_attr));
                    int vlen = mnl_attr_get_payload_len(af_spec_attr);

                    for (int i = 0; i <= vlen - (int)sizeof(nd_bridge_vlan_info); i += sizeof(nd_bridge_vlan_info)) {
                        const struct nd_bridge_vlan_info *vinfo =
                            reinterpret_cast<const struct nd_bridge_vlan_info *>(payload + i);

                        if (vinfo->flags & BRIDGE_VLAN_INFO_PVID) {
                            nd_dprintf("%s: %s PVID (Direct): %hu\n", TAG, ifname, vinfo->vid);
                            ndi.addr_lookup.AddLinkPVID(ifi->ifi_index, vinfo->vid);
                            goto next_interface;
                        }
                    }
                }

                int a_len = mnl_attr_get_len(af_spec_attr);
                af_spec_attr = mnl_attr_next(af_spec_attr);
                rem -= MNL_ALIGN(a_len);
            }
        }

        // Label to break out of nested loops once PVID is found
        next_interface:
#endif
        _ND_NLRT_CHECK_ATTR(TAG, attrs[IFLA_ADDRESS], -1);

        ndAddr addr;
        ndAddr::Create(addr,
            static_cast<const uint8_t *>(
                mnl_attr_get_payload(attrs[IFLA_ADDRESS])), ETH_ALEN
        );

#ifdef _ND_DEBUG_LOG
        nd_dprintf("%s: adding link: %u: %s\n", TAG,
            ifi->ifi_index,
            addr.GetString().c_str()
        );
#endif
        if (ndi.addr_lookup.AddLinkAddress(ifi->ifi_index, addr)) rc = 1;
    }
    else {

#ifdef _ND_DEBUG_LOG
        nd_dprintf("%s: removing link: %d\n", TAG,
            ifi->ifi_index
        );
#endif
#if defined(_ND_ENABLE_INTERFACE_METADATA)
        if (ndGC.mark_to_ifindex_enable
          && ndGC.mark_to_ifindex_firewall == "nft")
            this->UpdateNFTablesMapping(ifi->ifi_index, 0, false);
#endif
        if (ndi.addr_lookup.RemoveLinkAddress(ifi->ifi_index)) rc = 1;
        if (ndi.addr_lookup.RemoveLinkName(ifi->ifi_index)) rc = 1;

        ndi.addr_lookup.RemoveLinkPVID(ifi->ifi_index);
#if defined(_ND_ENABLE_INTERFACE_METADATA)
        ndi.addr_lookup.RemoveLinkSSID(ifi->ifi_index);
#endif
    }

    return rc;
}

int ndNetlinkRouteThread::AddRemoveNeighbor(const struct nlmsghdr *nlh, bool add) {
    const struct ndmsg *ndm = static_cast<const struct ndmsg *>(
        mnl_nlmsg_get_payload(nlh)
    );

    AttrsNeigh attrs = { 0 };

    if (mnl_attr_parse(nlh, sizeof(*ndm),
        ndNetlinkRoute_attr_parse_nda, attrs.data()) != MNL_CB_OK)
        return -1;

    if (add)
        _ND_NLRT_CHECK_ATTR(TAG, attrs[NDA_DST], -1);
    _ND_NLRT_CHECK_ATTR(TAG, attrs[NDA_LLADDR], -1);

    ndAddr addr;

    if (add) {
        switch(ndm->ndm_family) {
        case AF_INET:
            ndAddr::Create(addr,
                static_cast<struct in_addr *>(
                    mnl_attr_get_payload(attrs[NDA_DST])
                )
            );
            break;
        case AF_INET6:
            ndAddr::Create(addr,
                static_cast<struct in6_addr *>(
                    mnl_attr_get_payload(attrs[NDA_DST])
                )
            );
            break;

        default:
            nd_dprintf(
                "%s: unsupported address family: %d\n",
                TAG, ndm->ndm_family
            );
            return 0;
        }

        if (! addr.IsValid()) {
            nd_dprintf("%s: %s: invalid IP address.\n",
                TAG, __PRETTY_FUNCTION__);
            return -1;
        }
    }

    ndAddr lladdr;
    ndAddr::Create(lladdr,
        static_cast<const uint8_t *>(
            mnl_attr_get_payload(attrs[NDA_LLADDR])), ETH_ALEN
    );

    if (! lladdr.IsValid()) {
        nd_dprintf("%s: %s: invalid LL address.\n",
            TAG, __PRETTY_FUNCTION__);
        return -1;
    }

#ifdef _ND_DEBUG_LOG
    string state;
    switch(ndm->ndm_state) {
    case NUD_INCOMPLETE:
        state = "incomplete";
        break;
    case NUD_REACHABLE:
        state = "reachable";
        break;
    case NUD_STALE:
        state = "stale";
        break;
    case NUD_DELAY:
        state = "delay";
        break;
    case NUD_PROBE:
        state = "probe";
        break;
    case NUD_FAILED:
        state = "failed";
        break;
    case NUD_NOARP:
        state = "noarp";
        break;
    case NUD_PERMANENT:
        state = "permanent";
        break;
    default:
        state = "unknown: " + to_string(ndm->ndm_state);
        break;
    }
#endif

    bool rc = false;
    ndInstance &ndi = ndInstance::GetInstance();

    if (add) {
#ifdef _ND_DEBUG_LOG
        nd_dprintf("%s: adding neighbor: %s: %s [%s]\n", TAG,
            lladdr.GetString().c_str(),
            addr.GetString().c_str(), state.c_str()
        );
#endif
        rc = ndi.addr_lookup.AddNeighbor(addr, lladdr);
    }
    else {
#ifdef _ND_DEBUG_LOG
        nd_dprintf("%s: removing neighbor: %s [%s]\n", TAG,
            lladdr.GetString().c_str(), state.c_str()
        );
#endif
        rc = ndi.addr_lookup.RemoveNeighbor(lladdr);
    }

    return rc;
}

#if defined(_ND_ENABLE_INTERFACE_METADATA)
void ndNetlinkRouteThread::UpdateNFTablesMapping(
    int ifindex, uint32_t mark, bool add) {

    struct mnl_socket *nl;
    struct nftnl_set *set;
    struct nftnl_set_elem *elem;
    vector<uint8_t> buf;
    buf.resize(ndGC.netlink_buffer_size);
    uint32_t seq = time(NULL);
    int ret;

    set = nftnl_set_alloc();
    if (!set) {
        nd_dprintf("%s: failed to allocate nftnl_set\n", TAG);
        return;
    }

    // Bit of a TODO - we don't support anything but nftables for now
    nftnl_set_set_str(
      set, NFTNL_SET_TABLE, ndGC.mark_to_ifindex_nft_table.c_str());
    nftnl_set_set_str(
      set, NFTNL_SET_NAME, ndGC.mark_to_ifindex_nft_set.c_str());
    nftnl_set_set_u32(set, NFTNL_SET_FAMILY, NFPROTO_BRIDGE);

    elem = nftnl_set_elem_alloc();
    if (!elem) {
        nftnl_set_free(set);
        nd_dprintf("%s: failed to allocate nftnl_set_elem\n", TAG);
        return;
    }

    nftnl_set_elem_set(elem, NFTNL_SET_ELEM_KEY, &ifindex, sizeof(ifindex));
    if (add) {
        nftnl_set_elem_set(elem, NFTNL_SET_ELEM_DATA, &mark, sizeof(mark));
    }
    nftnl_set_elem_add(set, elem);

    nl = mnl_socket_open(NETLINK_NETFILTER);
    if (!nl) {
        nd_dprintf("%s: failed to open netlink socket\n", TAG);
        nftnl_set_free(set);
        return;
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        nd_dprintf("%s: failed to bind netlink socket\n", TAG);
        mnl_socket_close(nl);
        nftnl_set_free(set);
        return;
    }

    struct nlmsghdr *nlh;
    struct nfgenmsg *nfg;
    int offset = 0;

    // Batch Begin
    nlh = mnl_nlmsg_put_header(buf.data());
    nlh->nlmsg_type = NFNL_MSG_BATCH_BEGIN;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = seq++;

    nfg = (struct nfgenmsg *)mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
    nfg->nfgen_family = NFPROTO_UNSPEC;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = NFNL_SUBSYS_NFTABLES;
    offset += nlh->nlmsg_len;

    // Add/Delete Set Element
    uint16_t msg_type = add ? NFT_MSG_NEWSETELEM : NFT_MSG_DELSETELEM;
    uint16_t msg_flags = NLM_F_REQUEST | NLM_F_ACK;
    if (add) {
        msg_flags |= NLM_F_CREATE;
    }

    nlh = nftnl_nlmsg_build_hdr(
      (char *)buf.data() + offset, msg_type,
      NFPROTO_BRIDGE, msg_flags, seq++);
    nftnl_set_elems_nlmsg_build_payload(nlh, set);
    offset += nlh->nlmsg_len;

    // Batch End
    nlh = mnl_nlmsg_put_header(buf.data() + offset);
    nlh->nlmsg_type = NFNL_MSG_BATCH_END;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = seq++;

    nfg = (struct nfgenmsg *)mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
    nfg->nfgen_family = NFPROTO_UNSPEC;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = NFNL_SUBSYS_NFTABLES;
    offset += nlh->nlmsg_len;

    if (mnl_socket_sendto(nl, buf.data(), offset) < 0)
        nd_dprintf("%s: failed to send nft message\n", TAG);
    else {
        ret = mnl_socket_recvfrom(nl, buf.data(), buf.size());
        if (ret > 0) {
            int err_code = 0;
            if (mnl_cb_run(buf.data(), ret, 0, mnl_socket_get_portid(nl), ndNetlinkRoute_nft_error_cb, &err_code) < 0) {
                nd_dprintf(
                  "%s: nftables update failed: %s (table: %s, set: %s)\n",
                   TAG, strerror(abs(err_code)),
                   ndGC.mark_to_ifindex_nft_table.c_str(),
                   ndGC.mark_to_ifindex_nft_set.c_str());
            }
        }
    }

    nftnl_set_free(set);
    mnl_socket_close(nl);
}

#if defined(_ND_ENABLE_UBUS)
/*
 * ubus call hostapd.phy0-ap0 get_status
 * {
 *  "status": "ENABLED",
 *  "bssid": "02:00:00:00:00:00",
 *  "ssid": "SimulatedAP",
 *  "freq": 5180,
 *  "channel": 36,
 *  "op_class": 128,
 *  "beacon_interval": 100,
 *  "bss_color": -1,
 *  "phy": "phy0",
 *  "rrm": {
 *      "neighbor_report_tx": 0
 *  },
 *  "wnm": {
 *      "bss_transition_query_rx": 0,
 *      "bss_transition_request_tx": 0,
 *      "bss_transition_response_rx": 0
 *  },
 *  "airtime": {
 *      "time": 120,
 *      "time_busy": 15,
 *      "utilization": 31
 *  },
 *  "dfs": {
 *      "cac_seconds": 0,
 *      "cac_active": false,
 *      "cac_seconds_left": 0
 *  }
 * }
 * */
string ndNetlinkRouteThread::GetWirelessSSID(const char *ifname) {
    string ssid;

    std::string base_path = "/sys/class/net/" + std::string(ifname);
    if (access((base_path + "/phy80211").c_str(), F_OK) != 0 &&
        access((base_path + "/lower_wlan0/phy80211").c_str(), F_OK) != 0 &&
        access((base_path + "/lower_wlan1/phy80211").c_str(), F_OK) != 0) {
        return ssid;
    }

    json result;
    string ubus_path = "hostapd." + string(ifname);

    ndUbus ubus;

    try {
        ubus.Call(result, ubus_path, "get_status", "", 1);
    }
    catch (...) {
        return ssid;
    }

    try {
        string key = "ssid";
        auto jssid = result.at(key);
        ssid = jssid.get<string>();
    }
    catch (exception &e) {
        nd_dprintf("%s: UBUS result does not contain a valid SSID.\n",
          TAG);
    }

    return ssid;
}
#endif // _ND_ENABLE_UBUS
#endif // _ND_ENABLE_INTERFACE_METADATA
