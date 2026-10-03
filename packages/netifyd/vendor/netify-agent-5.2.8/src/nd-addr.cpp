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

#include <fstream>

#include <ifaddrs.h>
#include <sys/types.h>

#include <radix/radix_tree.hpp>

#include "nd-addr.hpp"
#include "nd-flags.hpp"
#include "nd-instance.hpp"
#include "nd-util.hpp"

using namespace std;

bool ndAddr::Create(ndAddr &a, const string &addr) {
    a.Reset();
    string _addr(addr);

    size_t p;
    if ((p = addr.find_first_of("/")) != string::npos) {
        try {
            a.prefix = (uint8_t)stoul(addr.substr(p + 1),
              nullptr, 10);
        }
        catch (...) {
            nd_dprintf(
              "Invalid IP address prefix length: %s\n",
              addr.substr(p + 1).c_str());
            return false;
        }

        _addr.erase(p);
    }

    if (inet_pton(AF_INET, _addr.c_str(), &a.addr.in.sin_addr) == 1)
    {
        if (a.prefix > _ND_ADDR_BITSv4) {
            nd_dprintf(
              "Invalid IP address prefix length: %hhu\n", a.prefix);
            return false;
        }

        a.addr.ss.ss_family = AF_INET;
        return true;
    }

    if (inet_pton(AF_INET6, _addr.c_str(), &a.addr.in6.sin6_addr) == 1)
    {
        if (a.prefix > _ND_ADDR_BITSv6) {
            nd_dprintf(
              "Invalid IP address prefix length: %hhu\n", a.prefix);
            return false;
        }

        a.addr.ss.ss_family = AF_INET6;
        return true;
    }

    switch (addr.size()) {
    case ND_STR_ETHALEN:
    {
        stringstream ss(addr);
        uint8_t octet = 0, hw_addr[ETH_ALEN] = { 0 };

        do {
            if (! ss.good()) break;

            string byte;
            getline(ss, byte, ':');

            try {
                hw_addr[octet] = (uint8_t)stoul(byte, nullptr, 16);
            }
            catch (...) {
                nd_dprintf(
                  "Invalid hardware address, octet #%hhu\n", octet);

                return false;
            }
        }
        while (++octet < ETH_ALEN);

        if (octet == ETH_ALEN)
            return Create(a, hw_addr, ETH_ALEN);
    }
    default: break;
    }

    return false;
}

bool ndAddr::Create(ndAddr &a, const uint8_t *hw_addr, size_t length) {
    a.Reset();
    switch (length) {
    case ETH_ALEN:
#if defined(__linux__)
        a.addr.ss.ss_family = AF_PACKET;
        a.addr.ll.sll_hatype = ARPHRD_ETHER;
        a.addr.ll.sll_halen = ETH_ALEN;
        memcpy(a.addr.ll.sll_addr, hw_addr, ETH_ALEN);
#elif defined(__FreeBSD__)
        a.addr.ss.ss_family = AF_LINK;
        a.addr.dl.sdl_type = ARPHRD_ETHER;
        a.addr.dl.sdl_nlen = 0;
        a.addr.dl.sdl_alen = ETH_ALEN;
        memcpy(a.addr.dl.sdl_data, hw_addr, ETH_ALEN);
#endif
        return true;

    default:
        nd_dprintf("Invalid hardware address size: %lu\n", length);
        return false;
    }

    return false;
}

bool ndAddr::Create(ndAddr &a,
  const struct sockaddr_storage *ss_addr,
  uint8_t prefix) {
    a.Reset();
    switch (ss_addr->ss_family) {
    case AF_INET:
        if (prefix > _ND_ADDR_BITSv4) {
            nd_dprintf(
              "Invalid IP address prefix length: %hhu\n", prefix);
            return false;
        }

        if (prefix) a.prefix = prefix;
        else a.prefix = _ND_ADDR_BITSv4;

        memcpy(&a.addr.in, ss_addr, sizeof(struct sockaddr_in));
        break;

    case AF_INET6:
        if (prefix > _ND_ADDR_BITSv6) {
            nd_dprintf(
              "Invalid IP address prefix length: %hhu\n", prefix);
            return false;
        }

        if (prefix) a.prefix = prefix;
        else a.prefix = _ND_ADDR_BITSv6;

        memcpy(&a.addr.in6, ss_addr, sizeof(struct sockaddr_in6));
        break;

    default:
        nd_dprintf("Unsupported address family: %hu\n",
          ss_addr->ss_family);
        return false;
    }

    return true;
}

bool ndAddr::Create(ndAddr &a,
  const struct sockaddr_in *ss_in, uint8_t prefix) {
    a.Reset();
    if (ss_in->sin_family != AF_INET) {
        nd_dprintf("Unsupported address family: %hu\n",
          ss_in->sin_family);
        return false;
    }

    if (prefix > _ND_ADDR_BITSv4) {
        nd_dprintf(
          "Invalid IP address prefix length: %hhu\n", prefix);
        return false;
    }

    memcpy(&a.addr.in, ss_in, sizeof(struct sockaddr_in));

    if (prefix) a.prefix = prefix;
    else a.prefix = _ND_ADDR_BITSv4;

    return true;
}

bool ndAddr::Create(ndAddr &a,
  const struct sockaddr_in6 *ss_in6, uint8_t prefix) {
    a.Reset();
    if (ss_in6->sin6_family != AF_INET6) {
        nd_dprintf("Unsupported address family: %hu\n",
          ss_in6->sin6_family);
        return false;
    }

    if (prefix > _ND_ADDR_BITSv6) {
        nd_dprintf(
          "Invalid IP address prefix length: %hhu\n", prefix);
        return false;
    }

    memcpy(&a.addr.in6, ss_in6, sizeof(struct sockaddr_in6));

    if (prefix) a.prefix = prefix;
    else a.prefix = _ND_ADDR_BITSv6;

    return true;
}

bool ndAddr::Create(ndAddr &a,
  const struct in_addr *in_addr, uint8_t prefix) {
    a.Reset();
    if (prefix > _ND_ADDR_BITSv4) {
        nd_dprintf(
          "Invalid IP address prefix length: %hhu\n", prefix);
        return false;
    }

    a.addr.in.sin_family = AF_INET;
    a.addr.in.sin_port = 0;
    a.addr.in.sin_addr.s_addr = in_addr->s_addr;

    if (prefix) a.prefix = prefix;
    else a.prefix = _ND_ADDR_BITSv4;

    return true;
}

bool ndAddr::Create(ndAddr &a,
  const struct in6_addr *in6_addr, uint8_t prefix) {
    a.Reset();
    if (prefix > _ND_ADDR_BITSv6) {
        nd_dprintf(
          "Invalid IP address prefix length: %hhu\n", prefix);
        return false;
    }

    a.addr.in6.sin6_family = AF_INET6;
    a.addr.in6.sin6_port = 0;
    memcpy(&a.addr.in6.sin6_addr, in6_addr, sizeof(struct in6_addr));

    if (prefix) a.prefix = prefix;
    else a.prefix = _ND_ADDR_BITSv6;

    return true;
}

const uint8_t *ndAddr::GetAddress(void) const {
    if (! IsValid()) return nullptr;
    if (IsIPv4())
        return reinterpret_cast<const uint8_t *>(&addr.in.sin_addr);
    if (IsIPv6())
        return reinterpret_cast<const uint8_t *>(&addr.in6.sin6_addr);
    if (IsEthernet())
#if defined(__linux__)
        return reinterpret_cast<const uint8_t *>(&addr.ll.sll_addr[0]);
#elif defined(__FreeBSD__)
        return reinterpret_cast<const uint8_t *>(&addr.dl.sdl_data[0]);
#endif
    return nullptr;
}

size_t ndAddr::GetAddressSize(void) const {
    if (! IsValid()) return 0;
    if (IsIPv4()) return sizeof(struct in_addr);
    if (IsIPv6()) return sizeof(struct in6_addr);
    if (IsEthernet()) return ETH_ALEN;

    return 0;
}

uint16_t ndAddr::GetPort(bool byte_swap) const {
    if (! IsValid()) return 0;
    if (IsIPv4())
        return (
          (byte_swap) ? ntohs(addr.in.sin_port) : addr.in.sin_port);
    if (IsIPv6())
        return ((byte_swap) ?
            ntohs(addr.in6.sin6_port) :
            addr.in6.sin6_port);

    return 0;
}

bool ndAddr::SetPort(uint16_t port) {
    if (! IsValid()) return false;
    if (IsIPv4()) {
        addr.in.sin_port = port;
        return true;
    }
    if (IsIPv6()) {
        addr.in6.sin6_port = port;
        return true;
    }

    return false;
}

bool ndAddr::GetNAT64Addr(const ndAddr &addr_nat64, ndAddr &addr_ipv4) {
    if (! addr_nat64.IsNAT64()) return false;

    const struct in_addr ipv4 = {
        .s_addr = addr_nat64.addr.in6.sin6_addr.s6_addr32[3]
    };

    addr_ipv4 = ndAddr(&ipv4);

    return addr_ipv4.IsIPv4();
}

bool ndAddr::MakeString(const ndAddr &a, string &result,
  ndFlags<MakeFlags> flags) {
    if (! a.IsValid()) return false;

    char sa[INET6_ADDRSTRLEN] = { 0 };

    switch (a.addr.ss.ss_family) {
#if defined(__linux__)
    case AF_PACKET:
        switch (a.addr.ll.sll_hatype) {
        case ARPHRD_ETHER:
        {
            char *p = sa;
            for (unsigned i = 0; i < a.addr.ll.sll_halen &&
                 (sa - p) < (INET6_ADDRSTRLEN - 1);
                 i++)
            {
                sprintf(p, "%02hhx", a.addr.ll.sll_addr[i]);
                p += 2;

                if (i < (unsigned)(a.addr.ll.sll_halen - 1) &&
                  (sa - p) < (INET6_ADDRSTRLEN - 1))
                {
                    *p = ':';
                    p++;
                }
            }
        }

            result = sa;

            return true;
        }
        break;
#elif defined(__FreeBSD__)
    case AF_LINK:
        switch (a.addr.dl.sdl_type) {
        case ARPHRD_ETHER:
        {
            char *p = sa;
            for (unsigned i = 0; i < a.addr.dl.sdl_alen &&
                 (sa - p) < (INET6_ADDRSTRLEN - 1);
                 i++)
            {
                sprintf(p, "%02hhx",
                  a.addr.dl.sdl_data[a.addr.dl.sdl_nlen + i]);
                p += 2;

                if (i < (unsigned)(a.addr.dl.sdl_alen - 1) &&
                  (sa - p) < (INET6_ADDRSTRLEN - 1))
                {
                    *p = ':';
                    p++;
                }
            }
        }

            result = sa;

            return true;
        }
        break;
#endif
    case AF_INET:
        if (inet_ntop(AF_INET,
              (const void *)&a.addr.in.sin_addr.s_addr, sa,
              INET_ADDRSTRLEN) == nullptr)
        {
            nd_dprintf(
              "error converting %s address to string: %s",
              "AF_INET", strerror(errno));
            return false;
        }

        result = sa;

        if (ndFlagBoolean(flags, MakeFlags::PREFIX) &&
          (a.prefix > 0 && a.prefix != _ND_ADDR_BITSv4))
            result.append("/" + to_string((size_t)a.prefix));

        if (ndFlagBoolean(flags, MakeFlags::PORT) &&
          a.addr.in.sin_port != 0)
        {
            result.append(
              ":" + to_string(ntohs(a.addr.in.sin_port)));
        }

        return true;

    case AF_INET6:
        if (inet_ntop(AF_INET6,
              (const void *)&a.addr.in6.sin6_addr.s6_addr,
              sa, INET6_ADDRSTRLEN) == nullptr)
        {
            nd_dprintf(
              "error converting %s address to string: %s",
              "AF_INET6", strerror(errno));
            return false;
        }

        if (ndFlagBoolean(flags, MakeFlags::IPV6_URI)) {
            result = "[";
            result.append(sa);
        }
        else
            result.append(sa);

        if (ndFlagBoolean(flags, MakeFlags::IPV6_URI))
            result.append("]");

        if (ndFlagBoolean(flags, MakeFlags::PREFIX) &&
          a.prefix > 0 && a.prefix != _ND_ADDR_BITSv6)
            result.append("/" + to_string((size_t)a.prefix));

        if (ndFlagBoolean(flags, MakeFlags::PORT) &&
          a.addr.in6.sin6_port != 0)
        {
            result.append(
              ":" + to_string(ntohs(a.addr.in6.sin6_port)));
        }

        return true;
    }

    return false;
}

bool ndAddr::operator==(const ndAddr &a) const {
    if (a.addr.ss.ss_family != addr.ss.ss_family)
        return false;
    if (ndFlagBoolean(compare_flags, CompareFlags::PREFIX) &&
      a.prefix != prefix)
        return false;

    switch (addr.ss.ss_family) {
#if defined(__linux__)
    case AF_PACKET:
        if (! ndFlagBoolean(compare_flags, CompareFlags::ADDR))
            return true;
        return (memcmp(&addr.ll, &a.addr.ll,
                  sizeof(struct sockaddr_ll)) == 0);
#elif defined(__FreeBSD__)
    case AF_LINK:
        if (! ndFlagBoolean(compare_flags, CompareFlags::ADDR))
            return true;
        return (memcmp(&addr.dl, &a.addr.dl,
                  sizeof(struct sockaddr_dl)) == 0);
#endif
    case AF_INET:
        if (ndFlagBoolean(compare_flags, CompareFlags::ADDR) &&
          (ndFlagBoolean(compare_flags, CompareFlags::PORT)))
        {
            return (memcmp(&addr.in, &a.addr.in,
                      sizeof(struct sockaddr_in)) == 0);
        }
        if (ndFlagBoolean(compare_flags, CompareFlags::ADDR) &&
          memcmp(&addr.in.sin_addr, &a.addr.in.sin_addr,
            sizeof(struct in_addr)) == 0)
            return true;
        if (ndFlagBoolean(compare_flags, CompareFlags::PORT) &&
          addr.in.sin_port == a.addr.in.sin_port)
            return true;
        break;
    case AF_INET6:
        if (ndFlagBoolean(compare_flags, CompareFlags::ADDR) &&
          (ndFlagBoolean(compare_flags, CompareFlags::PORT)))
        {
            return (memcmp(&addr.in6, &a.addr.in6,
                      sizeof(struct sockaddr_in6)) == 0);
        }
        if (ndFlagBoolean(compare_flags, CompareFlags::ADDR) &&
          memcmp(&addr.in6.sin6_addr,
            &a.addr.in6.sin6_addr,
            sizeof(struct in6_addr)) == 0)
            return true;
        if (ndFlagBoolean(compare_flags, CompareFlags::PORT) &&
          addr.in6.sin6_port == a.addr.in6.sin6_port)
            return true;
        break;
    }
    return false;
}

int ndAddr::Compare(const ndAddr &a) const {
    switch (addr.ss.ss_family) {
#if defined(__linux__)
    case AF_PACKET:
        return memcmp(&addr.ll, &a.addr.ll, sizeof(struct sockaddr_ll));
#elif defined(__FreeBSD__)
    case AF_LINK:
        return memcmp(&addr.dl, &a.addr.dl, sizeof(struct sockaddr_dl));
#endif
    case AF_INET:
        return memcmp(
            &addr.in.sin_addr, &a.addr.in.sin_addr, sizeof(struct in_addr));
    case AF_INET6:
        return memcmp(
            &addr.in6.sin6_addr, &a.addr.in6.sin6_addr, sizeof(struct in6_addr));
        break;
    }
    return 0;
}

ndAddrLookup::ndAddrLookup() {
    // Add private networks
    AddAddress(ndAddr::Type::RESERVED, "127.0.0.0/8");
    AddAddress(ndAddr::Type::RESERVED, "10.0.0.0/8");
    AddAddress(ndAddr::Type::RESERVED, "100.64.0.0/10");
    AddAddress(ndAddr::Type::RESERVED, "172.16.0.0/12");
    AddAddress(ndAddr::Type::RESERVED, "192.168.0.0/16");

    AddAddress(ndAddr::Type::RESERVED, "::1/128");
    AddAddress(ndAddr::Type::RESERVED, "fc00::/7");
    AddAddress(ndAddr::Type::RESERVED, "fd00::/8");
    AddAddress(ndAddr::Type::RESERVED, "fe80::/10");

    // Add multicast networks
    AddAddress(ndAddr::Type::MULTICAST, "224.0.0.0/4");

    AddAddress(ndAddr::Type::MULTICAST, "ff00::/8");

    // Add broadcast addresses
    AddAddress(ndAddr::Type::BROADCAST, "169.254.255.255");
}

bool ndAddrLookup::AddAddress(ndAddr::Type type,
  const ndAddr &addr, const string &ifname) {
    if (! addr.IsValid()) {
        nd_printf("Invalid address: %s\n",
          addr.GetString(ndAddr::MakeFlags::PREFIX).c_str());
        return false;
    }
#ifdef _ND_ENABLE_DEBUG_STATS
    nd_dprintf("%s: %d: %s: %s\n", __func__, type,
      (! ifname.empty()) ? ifname.c_str() : "(global)",
      addr.GetString(ndAddr::MakeFlags::PREFIX).c_str());
#endif
    try {
        if (addr.IsEthernet()) {
            lock_guard<mutex> ul(lock_ether_reserved);

            string mac = addr.GetString(ndAddr::MakeFlags::PREFIX);
            auto it = ether_reserved.find(mac);
            if (it != ether_reserved.end()) {
#ifdef _ND_ENABLE_DEBUG_STATS
                nd_dprintf(
                  "Reserved MAC address exists: %s\n", mac.c_str());
#endif
                return false;
            }
            ether_reserved[mac] = type;
#ifdef _ND_ENABLE_DEBUG_STATS
            nd_dprintf("ether_reserved: %u\n",
              ether_reserved.size());
#endif
            return true;
        }

        if (type == ndAddr::Type::LOCAL && addr.IsNetwork())
            type = ndAddr::Type::LOCALNET;

        if (addr.IsIPv4() && ifname.empty()) {
            ndRadixNetworkEntry<_ND_ADDR_BITSv4> entry;
            if (ndRadixNetworkEntry<_ND_ADDR_BITSv4>::Create(entry, addr))
            {
                lock_guard<mutex> ul(lock_ipv4_reserved);

                ipv4_reserved[entry] = type;
                return true;
            }
        }

        if (addr.IsIPv6() && ifname.empty()) {
            ndRadixNetworkEntry<_ND_ADDR_BITSv6> entry;
            if (ndRadixNetworkEntry<_ND_ADDR_BITSv6>::Create(entry, addr))
            {
                lock_guard<mutex> ul(lock_ipv6_reserved);

                ipv6_reserved[entry] = type;
                return true;
            }
        }

        if (addr.IsIPv4() && ! ifname.empty()) {
            ndRadixNetworkEntry<_ND_ADDR_BITSv4> entry;
            if (ndRadixNetworkEntry<_ND_ADDR_BITSv4>::Create(entry, addr))
            {
                lock_guard<mutex> ul(lock_ipv4_ifaces);

                ipv4_ifaces[ifname][entry] = type;
                return true;
            }
        }

        if (addr.IsIPv6() && ! ifname.empty()) {
            ndRadixNetworkEntry<_ND_ADDR_BITSv6> entry;
            if (ndRadixNetworkEntry<_ND_ADDR_BITSv6>::Create(entry, addr))
            {
                lock_guard<mutex> ul(lock_ipv6_ifaces);

                ipv6_ifaces[ifname][entry] = type;
                return true;
            }
        }
    }
    catch (runtime_error &e) {
        nd_dprintf("Error adding address: %s: %s\n",
          addr.GetString(ndAddr::MakeFlags::PREFIX).c_str(),
          e.what());
    }

    return false;
}

bool ndAddrLookup::RemoveAddress(const ndAddr &addr,
  const string &ifname) {
    if (! addr.IsValid()) {
        nd_printf("Invalid address: %s\n",
          addr.GetString(ndAddr::MakeFlags::PREFIX).c_str());
        return false;
    }
#ifdef _ND_ENABLE_DEBUG_STATS
    nd_dprintf("%s: %s: %s\n", __func__,
      (! ifname.empty()) ? ifname.c_str() : "(global)",
      addr.GetString(ndAddr::MakeFlags::PREFIX).c_str());
#endif
    try {
        if (addr.IsEthernet()) {
            lock_guard<mutex> ul(lock_ether_reserved);

            string mac = addr.GetString(ndAddr::MakeFlags::PREFIX);
            auto it = ether_reserved.find(mac);
            if (it != ether_reserved.end()) {
                ether_reserved.erase(it);
                return true;
            }
            return false;
        }

        if (addr.IsIPv4() && ifname.empty()) {
            ndRadixNetworkEntry<_ND_ADDR_BITSv4> entry;
            if (ndRadixNetworkEntry<_ND_ADDR_BITSv4>::Create(entry, addr))
            {
                lock_guard<mutex> ul(lock_ipv4_reserved);

                return ipv4_reserved.erase(entry);
            }
        }

        if (addr.IsIPv6() && ifname.empty()) {
            ndRadixNetworkEntry<_ND_ADDR_BITSv6> entry;
            if (ndRadixNetworkEntry<_ND_ADDR_BITSv6>::Create(entry, addr))
            {
                lock_guard<mutex> ul(lock_ipv6_reserved);

                return ipv6_reserved.erase(entry);
            }
        }

        if (addr.IsIPv4() && ifname.empty()) {
            ndRadixNetworkEntry<_ND_ADDR_BITSv4> entry;
            if (ndRadixNetworkEntry<_ND_ADDR_BITSv4>::Create(entry, addr))
            {
                lock_guard<mutex> ul(lock_ipv4_ifaces);

                auto it = ipv4_ifaces.find(ifname);
                if (it != ipv4_ifaces.end())
                    return it->second.erase(entry);
                return false;
            }
        }

        if (addr.IsIPv6() && ! ifname.empty()) {
            ndRadixNetworkEntry<_ND_ADDR_BITSv6> entry;
            if (ndRadixNetworkEntry<_ND_ADDR_BITSv6>::Create(entry, addr))
            {
                lock_guard<mutex> ul(lock_ipv6_ifaces);

                auto it = ipv6_ifaces.find(ifname);
                if (it != ipv6_ifaces.end())
                    return it->second.erase(entry);
                return false;
            }
        }
    }
    catch (runtime_error &e) {
        nd_dprintf("Error removing address: %s: %s\n",
          addr.GetString(ndAddr::MakeFlags::PREFIX).c_str(),
          e.what());
    }

    return false;
}

bool ndAddrLookup::AddLinkAddress(
    unsigned index, const ndAddr &addr) {
    if (! (addr.IsValid() && addr.IsEthernet())) return false;

    lock_guard<mutex> ul(lock_link_addrs);

    auto result = link_addrs.insert(make_pair(index, addr));

    return result.second;
}

bool ndAddrLookup::RemoveLinkAddress(unsigned index) {
    lock_guard<mutex> ul(lock_link_addrs);

    auto result = link_addrs.find(index);
    if (result == link_addrs.end()) return false;

    link_addrs.erase(result);

    return true;
}

bool ndAddrLookup::LookupLinkAddress(unsigned index, ndAddr &addr) {
    lock_guard<mutex> ul(lock_link_addrs);

    auto result = link_addrs.find(index);
    if (result == link_addrs.end()) return false;

    addr = result->second;

    return true;
}

bool ndAddrLookup::AddLinkPVID(unsigned index, uint16_t id) {
    lock_guard<mutex> ul(lock_link_pvid);

    auto result = link_pvids.insert(make_pair(index, id));

    return result.second;
}

bool ndAddrLookup::RemoveLinkPVID(unsigned index) {
    lock_guard<mutex> ul(lock_link_pvid);

    auto result = link_pvids.find(index);
    if (result == link_pvids.end()) return false;

    link_pvids.erase(result);

    return true;
}

uint16_t ndAddrLookup::LookupLinkPVID(unsigned index) {
    lock_guard<mutex> ul(lock_link_pvid);

    auto result = link_pvids.find(index);
    if (result == link_pvids.end()) return 0;

    return result->second;
}

bool ndAddrLookup::AddLinkName(
    unsigned index, const string &name) {

    lock_guard<mutex> ul(lock_link_names);

    auto result = link_names.insert(make_pair(index, name));

    return result.second;
}

bool ndAddrLookup::RemoveLinkName(unsigned index) {
    lock_guard<mutex> ul(lock_link_names);

    auto result = link_names.find(index);
    if (result == link_names.end()) return false;

    link_names.erase(result);

    return true;
}

bool ndAddrLookup::LookupLinkName(unsigned index, string &name) {
    lock_guard<mutex> ul(lock_link_names);

    auto result = link_names.find(index);
    if (result == link_names.end()) return false;

    name = result->second;

    return true;
}

bool ndAddrLookup::AddNeighbor(const ndAddr &addr, const ndAddr &lladdr) {
    if (! (addr.IsValid() && lladdr.IsValid())) return false;
    if (! (addr.IsIP() && lladdr.IsEthernet())) return false;

    lock_guard<mutex> ul(lock_neighbors);

    auto result = neighbors.insert(make_pair(addr, lladdr));

    return result.second;
#if 0
    if (result.second) return true;

    if (result.first->second != lladdr) {
        result.first->second = lladdr;
        nd_dprintf("%s: neighbor updated.\n", __PRETTY_FUNCTION__);
        return true;
    }

    nd_dprintf("%s: neighbor already up-to-date.\n", __PRETTY_FUNCTION__);

    return true;
#endif
}

bool ndAddrLookup::RemoveNeighbor(const ndAddr &addr) {
    if (! addr.IsValid()) return false;
    if (! (addr.IsIP() || addr.IsEthernet())) return false;

    lock_guard<mutex> ul(lock_neighbors);

    bool removed = false;

    if (addr.IsIP()) {
        auto result = neighbors.find(addr);
        if (result == neighbors.end()) return false;

        neighbors.erase(result);
        removed = true;
    }
    else {
        for (NeighborMap::iterator i = neighbors.begin();
            i != neighbors.end(); i++) {
            if (i->second != addr) continue;

            neighbors.erase(i);
            removed = true;
            break;
        }
    }

    return removed;
}

bool ndAddrLookup::LookupNeighbor(const ndAddr &addr, ndAddr &lladdr) {
    if (! (addr.IsValid() && addr.IsIP())) return false;

    lock_guard<mutex> ul(lock_neighbors);

    auto result = neighbors.find(addr);
    if (result == neighbors.end()) return false;

    lladdr = result->second;

    return true;
}

bool ndAddrLookup::AddGroupAddress(const string &tag, const ndAddr &addr) {
    if (! addr.IsValid()) return false;
    if (! (addr.IsEthernet() || addr.IsIP())) return false;

    if (addr.IsEthernet() || ! addr.IsNetwork()) {
        lock_guard<recursive_mutex> ul(lock_group_addrs);

        auto group = group_addrs.find(tag);
        if (group == group_addrs.end()) {
            GroupAddrSet addr_set({ addr });
            group_addrs.emplace(tag, addr_set);
            return true;
        }

        auto result = group->second.insert(addr);

        return result.second;
    }

    if (addr.IsIPv4()) {
        lock_guard<recursive_mutex> ul(lock_group_networks4);

        nd_rn4_network *rn4 = nullptr;
        auto group = group_networks4.find(tag);
        if (group == group_networks4.end()) {
            auto [it, inserted] = group_networks4.emplace(tag, make_unique<nd_rn4_network>());
            rn4 = it->second.get();
        }
        else rn4 = group->second.get();

        ndRadixNetworkEntry<_ND_ADDR_BITSv4> entry;
        if (ndRadixNetworkEntry<_ND_ADDR_BITSv4>::Create(entry, addr)) {
            (*rn4)[entry] = true;
            return true;
        }
    }
    else if (addr.IsIPv6()) {
        lock_guard<recursive_mutex> ul(lock_group_networks6);

        nd_rn6_network *rn6 = nullptr;
        auto group = group_networks6.find(tag);
        if (group == group_networks6.end()) {
            auto [it, inserted] = group_networks6.emplace(tag, make_unique<nd_rn6_network>());
            rn6 = it->second.get();
        }
        else rn6 = group->second.get();

        ndRadixNetworkEntry<_ND_ADDR_BITSv6> entry;
        if (ndRadixNetworkEntry<_ND_ADDR_BITSv6>::Create(entry, addr)) {
            (*rn6)[entry] = true;
            return true;
        }
    }

    return false;
}

bool ndAddrLookup::RemoveGroup(const string &tag) {
    unique_lock<recursive_mutex> ul(lock_group_addrs);

    auto group = group_addrs.find(tag);
    if (group != group_addrs.end())
        group_addrs.erase(group);

    ul.unlock();
    ul.release();
    ul = unique_lock<recursive_mutex>{ lock_group_networks4 };

    group_networks4.erase(tag);

    ul.unlock();
    ul.release();
    ul = unique_lock<recursive_mutex>{ lock_group_networks6 };

    group_networks6.erase(tag);

    ul.unlock();
    ul.release();
    ul = unique_lock<recursive_mutex>{ lock_group_filenames };

    auto filename = group_filenames.find(tag);
    if (filename != group_filenames.end()) {
        string path = ndGC.path_addr_groups + "/" + filename->second;
        unlink(path.c_str());
        group_filenames.erase(filename);
    }

    return true;
}

bool ndAddrLookup::RemoveGroupAddress(
  const string &tag, const ndAddr &addr) {
    if (! addr.IsValid()) return false;
    if (! (addr.IsEthernet() || addr.IsIP())) return false;

    if (addr.IsEthernet() || ! addr.IsNetwork()) {
        lock_guard<recursive_mutex> ul(lock_group_addrs);

        auto group = group_addrs.find(tag);
        if (group == group_addrs.end()) return false;

        auto result = group->second.find(addr);
        if (result == group->second.end()) return false;

        group->second.erase(result);

        if (group->second.empty()) group_addrs.erase(group);

        return true;
    }

    if (addr.IsIPv4()) {
        lock_guard<recursive_mutex> ul(lock_group_networks4);

        auto group = group_networks4.find(tag);
        if (group == group_networks4.end()) return false;
        nd_rn4_network *rn4 = group->second.get();

        nd_rn4_network::iterator it;
        ndRadixNetworkEntry<_ND_ADDR_BITSv4> entry;
        if (ndRadixNetworkEntry<_ND_ADDR_BITSv4>::CreateQuery(
              entry, addr)) {
            if ((it = rn4->longest_match(entry)) == rn4->end())
                return false;
        }

        rn4->erase(it);

        return true;
    }

    if (addr.IsIPv6()) {
        lock_guard<recursive_mutex> ul(lock_group_networks6);

        auto group = group_networks6.find(tag);
        if (group == group_networks6.end()) return false;
        nd_rn6_network *rn6 = group->second.get();

        nd_rn6_network::iterator it;
        ndRadixNetworkEntry<_ND_ADDR_BITSv6> entry;

        if (ndRadixNetworkEntry<_ND_ADDR_BITSv6>::CreateQuery(
              entry, addr)) {
            if ((it = rn6->longest_match(entry)) == rn6->end())
                return false;
        }

        rn6->erase(it);

        return true;
    }

    return true;
}

bool ndAddrLookup::LookupGroupAddress(
  const string &tag, const ndAddr &addr) {

    if (! addr.IsValid()) return false;

    if ((addr.IsIP() && ! addr.IsNetwork()) || addr.IsEthernet()) {
        lock_guard<recursive_mutex> ul(lock_group_addrs);

        auto group = group_addrs.find(tag);
        if (group != group_addrs.end()) {
            if (group->second.find(addr) != group->second.end())
                return true;
        }

        if (addr.IsEthernet()) return false;
    }

    if (addr.IsIPv4()) {
        lock_guard<recursive_mutex> ul(lock_group_networks4);

        auto group = group_networks4.find(tag);
        if (group != group_networks4.end()) {
            nd_rn4_network *rn4 = group->second.get();

            ndRadixNetworkEntry<_ND_ADDR_BITSv4> entry;
            if (ndRadixNetworkEntry<_ND_ADDR_BITSv4>::CreateQuery(
                entry, addr)) {
                if (rn4->longest_match(entry) != rn4->end())
                    return true;
            }
        }
    }
    else if (addr.IsIPv6()) {
        lock_guard<recursive_mutex> ul(lock_group_networks6);

        auto group = group_networks6.find(tag);
        if (group != group_networks6.end()) {
            nd_rn6_network *rn6 = group->second.get();

            ndRadixNetworkEntry<_ND_ADDR_BITSv6> entry;
            if (ndRadixNetworkEntry<_ND_ADDR_BITSv6>::CreateQuery(
                entry, addr)) {
                if (rn6->longest_match(entry) != rn6->end())
                    return true;
            }
        }
    }

    return false;
}

bool ndAddrLookup::GetGroupFilename(const string &tag, string &filename) {
    lock_guard<recursive_mutex> ul(lock_group_filenames);

    auto group = group_filenames.find(tag);
    if (group == group_filenames.end()) return false;

    filename = group->second;
    return true;
}

bool ndAddrLookup::SetGroupFilename(const string &tag) {
    lock_guard<recursive_mutex> ul(lock_group_filenames);

    auto group = group_filenames.find(tag);
    if (group != group_filenames.end()) return false;

    string filename = string("10-") + tag + ".conf";
    group_filenames.emplace(tag, filename);

    return true;
}

bool ndAddrLookup::LoadGroupAddress(
  const string &tag, const string &filename) {

    ifstream ifs(filename);
    if (! ifs.is_open()) {
        nd_printf("Error opening group address file: %s: %s\n",
          filename.c_str(), strerror(ENOENT));
        return false;
    }

    unique_lock<recursive_mutex> ul(lock_group_addrs);

    auto group = group_addrs.find(tag);
    if (group != group_addrs.end()) group_addrs.erase(group);

    ul.unlock();
    ul.release();
    ul = unique_lock<recursive_mutex>{ lock_group_networks4 };

    group_networks4.erase(tag);

    ul.unlock();
    ul.release();
    ul = unique_lock<recursive_mutex>{ lock_group_networks6 };

    group_networks6.erase(tag);

    ul.unlock();
    ul.release();

    string line;
    size_t addrs = 0;

    while (getline(ifs, line)) {
        nd_ltrim(line);
        if (line.empty() || line[0] == '#') continue;

        if (AddGroupAddress(tag, ndAddr(line))) addrs++;
    }

    nd_dprintf("%s: Loaded %lu group address(es) from: %s\n",
        tag.c_str(), addrs, filename.c_str());

    return (addrs != 0);
}

bool ndAddrLookup::SaveGroupAddress(
  const string &tag, const string &filename) {

    ofstream ofs(filename, ofstream::trunc);
    if (! ofs.is_open()) {
        nd_printf("Error opening group address file: %s: %s\n",
          filename.c_str(), strerror(ENOENT));
        return false;
    }

    size_t addrs = 0;
    unique_lock<recursive_mutex> ul(lock_group_addrs);

    if (! group_addrs.empty()) {
        auto group = group_addrs.find(tag);
        if (group != group_addrs.end()) {
            for (auto &i : group->second)
                ofs << i.GetString(ndAddr::MakeFlags::PREFIX) << endl;

            addrs += group->second.size();
        }
    }

    ul.unlock();
    ul.release();
    ul = unique_lock<recursive_mutex>{ lock_group_networks4 };

    if (! group_networks4.empty()) {
        auto group = group_networks4.find(tag);
        if (group != group_networks4.end()) {
            nd_rn4_network *rn4 = group->second.get();

            for (auto &it : (*rn4)) {
                string ip;
                if (it.first.GetString(ip, ndAddr::MakeFlags::PREFIX)) {
                    ofs << ip << endl;
                    addrs++;
                }
            }
        }
    }

    ul.unlock();
    ul.release();
    ul = unique_lock<recursive_mutex>{ lock_group_networks6 };

    if (! group_networks6.empty()) {
        auto group = group_networks6.find(tag);
        if (group != group_networks6.end()) {
            nd_rn6_network *rn6 = group->second.get();

            for (auto &it : (*rn6)) {
                string ip;
                if (it.first.GetString(ip, ndAddr::MakeFlags::PREFIX)) {
                    ofs << ip << endl;
                    addrs++;
                }
            }
        }
    }

    nd_dprintf("%s: Saved %lu group address(es) to: %s\n",
        tag.c_str(), addrs, filename.c_str());

    return true;
}

void ndAddrLookup::LoadGroupAddresses(const string &path) {
    lock_guard<recursive_mutex> ul(lock_group_filenames);

    for (auto &i : group_filenames) {
        lock_guard<recursive_mutex> ul_group_addrs(lock_group_addrs);

        auto group = group_addrs.find(i.first);
        if (group != group_addrs.end()) group_addrs.erase(group);
    }

    vector<string> files;
    if (! nd_scan_dotd(path, files) || files.empty())
        return;

    for (auto &i : files) {
        string tag;
        if (! nd_get_dotd_tag(i, tag)) continue;

        if (LoadGroupAddress(tag, path + "/" + i))
            group_filenames.emplace(tag, i);
    }
}

void ndAddrLookup::SaveGroupAddresses(const string &path) {
    lock_guard<recursive_mutex> ul(lock_group_filenames);

    for (auto &i : group_filenames)
        SaveGroupAddress(i.first, path + "/" + i.second);
}

void ndAddrLookup::Classify(ndAddr::Type &type, const ndAddr &addr) {
    if (addr.IsValid())
        type = ndAddr::Type::OTHER;
    else {
        type = ndAddr::Type::ERROR;
        return;
    }

    if (addr.IsEthernet()) {
        for (uint8_t i = 0x01; i <= 0x0f; i += 0x02) {
#if defined(__linux__)
            if ((i & addr.addr.ll.sll_addr[0]) != i)
                continue;
#elif defined(__FreeBSD__)
            if ((i & addr.addr.dl.sdl_data[addr.addr.dl.sdl_nlen]) != i)
                continue;
#endif
            type = ndAddr::Type::MULTICAST;
            return;
        }

#if defined(__linux__)
        uint8_t sll_addr[sizeof(addr.addr.ll.sll_addr)];

        memset(sll_addr, 0xff, addr.addr.ll.sll_halen);
        if (memcmp(addr.addr.ll.sll_addr, sll_addr,
              addr.addr.ll.sll_halen) == 0)
        {
            type = ndAddr::Type::BROADCAST;
            return;
        }

        memset(sll_addr, 0, addr.addr.ll.sll_halen);
        if (memcmp(addr.addr.ll.sll_addr, sll_addr,
              addr.addr.ll.sll_halen) == 0)
        {
            type = ndAddr::Type::NONE;
            return;
        }
#elif defined(__FreeBSD__)
        uint8_t sll_addr[sizeof(addr.addr.dl.sdl_data)];

        memset(sll_addr, 0xff, addr.addr.dl.sdl_alen);
        if (memcmp(&addr.addr.dl.sdl_data[addr.addr.dl.sdl_nlen],
              sll_addr, addr.addr.dl.sdl_alen) == 0)
        {
            type = ndAddr::Type::BROADCAST;
            return;
        }

        memset(sll_addr, 0, addr.addr.dl.sdl_alen);
        if (memcmp(&addr.addr.dl.sdl_data[addr.addr.dl.sdl_nlen],
              sll_addr, addr.addr.dl.sdl_alen) == 0)
        {
            type = ndAddr::Type::NONE;
            return;
        }
#endif
        lock_guard<mutex> ul(lock_ether_reserved);

        if (ether_reserved.size()) {
            auto it = ether_reserved.find(addr.GetString());
            if (it != ether_reserved.end()) {
                type = it->second;
                return;
            }
        }
    }
    else if (addr.IsIPv4()) {
        if (addr.addr.in.sin_addr.s_addr == 0) {
            type = ndAddr::Type::LOCAL;
            return;
        }

        if (addr.addr.in.sin_addr.s_addr == 0xffffffff) {
            type = ndAddr::Type::BROADCAST;
            return;
        }

        lock_guard<mutex> ul_ipv4_ifaces(lock_ipv4_ifaces);

        for (auto &iface : ipv4_ifaces) {
            ndRadixNetworkEntry<_ND_ADDR_BITSv4> entry;
            if (ndRadixNetworkEntry<_ND_ADDR_BITSv4>::CreateQuery(
                  entry, addr))
            {
                RadixAddrType4::iterator it;
                if ((it = iface.second.longest_match(entry)) !=
                  iface.second.end())
                {
                    type = it->second;
                    if (type == ndAddr::Type::LOCALNET &&
                      ! addr.IsNetwork())
                        type = ndAddr::Type::LOCAL;
                    return;
                }
            }
        }

        ndRadixNetworkEntry<_ND_ADDR_BITSv4> entry;
        if (ndRadixNetworkEntry<_ND_ADDR_BITSv4>::CreateQuery(
              entry, addr))
        {
            lock_guard<mutex> ul_ipv4_reserved(lock_ipv4_reserved);

            RadixAddrType4::iterator it;
            if ((it = ipv4_reserved.longest_match(entry)) !=
              ipv4_reserved.end())
            {
                type = it->second;
                if (type == ndAddr::Type::LOCALNET &&
                  ! addr.IsNetwork())
                    type = ndAddr::Type::LOCAL;
                return;
            }
        }
    }
    else if (addr.IsIPv6()) {
        lock_guard<mutex> ul_ipv6_ifaces(lock_ipv6_ifaces);

        for (auto &iface : ipv6_ifaces) {
            ndRadixNetworkEntry<_ND_ADDR_BITSv6> entry;
            if (ndRadixNetworkEntry<_ND_ADDR_BITSv6>::CreateQuery(
                  entry, addr))
            {
                RadixAddrType6::iterator it;
                if ((it = iface.second.longest_match(entry)) !=
                  iface.second.end())
                {
                    type = it->second;
                    if (type == ndAddr::Type::LOCALNET &&
                      ! addr.IsNetwork())
                        type = ndAddr::Type::LOCAL;
                    return;
                }
            }
        }

        ndRadixNetworkEntry<_ND_ADDR_BITSv6> entry;
        if (ndRadixNetworkEntry<_ND_ADDR_BITSv6>::CreateQuery(
              entry, addr))
        {
            lock_guard<mutex> ul_ipv6_reserved(lock_ipv6_reserved);

            RadixAddrType6::iterator it;
            if ((it = ipv6_reserved.longest_match(entry)) !=
              ipv6_reserved.end())
            {
                type = it->second;
                if (type == ndAddr::Type::LOCALNET &&
                  ! addr.IsNetwork())
                    type = ndAddr::Type::LOCAL;
                return;
            }
        }
    }
}

size_t ndAddrLookup::GetInterfaceAddresses(const string &iface,
  set<string> &result, sa_family_t family) {

    if (family == AF_UNSPEC || family == AF_INET) {
        lock_guard<mutex> ul(lock_ipv4_ifaces);

        auto rn = ipv4_ifaces.find(iface);
        if (rn == ipv4_ifaces.end()) return result.size();

        for (auto &it : rn->second) {
            string ip;
            if (it.first.GetString(ip)) result.insert(ip);
        }
    }

    if (family == AF_UNSPEC || family == AF_INET6) {
        lock_guard<mutex> ul(lock_ipv6_ifaces);

        auto rn = ipv6_ifaces.find(iface);
        if (rn == ipv6_ifaces.end()) return result.size();

        for (auto &it : rn->second) {
            string ip;
            if (it.first.GetString(ip)) result.insert(ip);
        }
    }

    return result.size();
}

size_t ndInterface::UpdateAddrs(ndInterface::Interfaces &interfaces) {
    size_t count = 0;

    struct ifaddrs *if_addrs;

    if (getifaddrs(&if_addrs) == 0) {
        for (auto &i : interfaces) {
            i.second->addrs.Clear();
            i.second->UpdateAddrs(if_addrs);
        }

        freeifaddrs(if_addrs);
    }

    return count;
}

size_t ndInterface::UpdateAddrs(const struct ifaddrs *if_addrs) {
    size_t count = 0;
    const struct ifaddrs *ifa_addr = if_addrs;
#if defined(__linux__)
    struct sockaddr_ll *sa_ll;
#elif defined(__FreeBSD__)
    struct sockaddr_dl *sa_dl;
#endif
    const uint8_t *mac_addr = nullptr;

    for (; ifa_addr != NULL; ifa_addr = ifa_addr->ifa_next) {
        if (ifa_addr->ifa_addr == NULL ||
          (ifname != ifa_addr->ifa_name &&
            ifname_peer != ifa_addr->ifa_name))
            continue;

        ndAddr addr;
        uint8_t prefix = 0;
        ndInstance &ndi = ndInstance::GetInstance();

        switch (ifa_addr->ifa_addr->sa_family) {
        case AF_LINK:
#if defined(__linux__)
            sa_ll = (struct sockaddr_ll *)ifa_addr->ifa_addr;
            mac_addr = sa_ll->sll_addr;
#elif defined(__FreeBSD__)
            sa_dl = (struct sockaddr_dl *)ifa_addr->ifa_addr;
            mac_addr = (const uint8_t *)sa_dl->sdl_data +
              sa_dl->sdl_nlen;
#endif
            if (mac_addr != nullptr) {
                ndAddr::Create(addr, mac_addr, ETH_ALEN);
                if (addrs.Push(addr)) count++;
                if (ndGC_USE_GETIFADDRS) {
                    ndi.addr_lookup.AddAddress(
                      ndAddr::Type::LOCAL, addr, ifname);
                }
            }
            break;
        case AF_INET:
            prefix = nd_netmask_to_prefix(
              reinterpret_cast<struct sockaddr_storage *>(
                ifa_addr->ifa_netmask));
            ndAddr::Create(addr,
              reinterpret_cast<const struct sockaddr_in *>(
                ifa_addr->ifa_addr),
              prefix);
            if (addrs.Push(addr)) count++;
            if (ndGC_USE_GETIFADDRS) {
                ndi.addr_lookup.AddAddress(
                  ndAddr::Type::LOCAL, addr, ifname);
            }
            break;
        case AF_INET6:
            prefix = nd_netmask_to_prefix(
              reinterpret_cast<struct sockaddr_storage *>(
                ifa_addr->ifa_netmask));
            ndAddr::Create(addr,
              reinterpret_cast<const struct sockaddr_in6 *>(
                ifa_addr->ifa_addr),
              prefix);
            if (addrs.Push(addr)) count++;
            if (ndGC_USE_GETIFADDRS) {
                ndi.addr_lookup.AddAddress(
                  ndAddr::Type::LOCAL, addr, ifname);
            }
            break;
        default: break;
        }
    }

    return count;
}
#if defined(_ND_ENABLE_INTERFACE_METADATA)

bool ndAddrLookup::AddLinkSSID(unsigned index, const std::string &ssid) {
    std::lock_guard<std::mutex> lock(this->lock_link_ssids);
    this->link_ssids[index] = ssid;
    return true;
}

bool ndAddrLookup::RemoveLinkSSID(unsigned index) {
    std::lock_guard<std::mutex> lock(this->lock_link_ssids);
    return this->link_ssids.erase(index) > 0;
}

bool ndAddrLookup::LookupLinkSSID(unsigned index, std::string &ssid) {
    std::lock_guard<std::mutex> lock(this->lock_link_ssids);
    auto it = this->link_ssids.find(index);
    if (it != this->link_ssids.end()) {
        ssid = it->second;
        return true;
    }
    return false;
}

#endif
