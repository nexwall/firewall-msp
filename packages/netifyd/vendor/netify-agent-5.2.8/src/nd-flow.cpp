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
#include <iomanip>
#include <locale>
#include <mutex>
#include <sstream>

#include "nd-apps.hpp"
#include "nd-flags.hpp"
#include "nd-flow.hpp"
#include "nd-instance.hpp"
#include "nd-risks.hpp"
#include "nd-sha1.h"
#include "nd-util.hpp"

using namespace std;

// Enable lower map debug output
// #define _ND_DEBUG_LOWER_MAP	1

// Enable digest mdata debug output
// #define _ND_DEBUG_DIGEST_MDATA 1

#ifdef _ND_ENABLE_EXTENDED_STATS
void ndFlowStats::UpdateRate(bool lower, uint64_t timestamp,
  uint64_t bytes) {
    const unsigned interval = ndGC.update_interval;

    unsigned index = (unsigned)fmod(
      floor((double)timestamp / (double)1000), (double)interval);

    atomic<float> &rate = lower ? lower_rate : upper_rate;
    vector<uint64_t> &samples =
      lower ? lower_rate_samples : upper_rate_samples;

    samples[index] += bytes;

    uint64_t total = 0;
    unsigned divisor = 0;
    for (unsigned i = 0; i < interval; i++) {
        if (samples[i] == 0) continue;
        total += samples[i];
        divisor++;
    }

    rate = (divisor > 0) ? ((float)total / (float)divisor) : 0.0f;
}
#endif

ndFlow::ndFlow(ndInterface::Ptr &iface)
  : iface(iface), detected_protocol_name("Unknown") {
#if defined(_ND_ENABLE_INTERFACE_METADATA)
     memset(&if_metadata, 0, sizeof(if_metadata));
    if_metadata.local.index = -1;
    if_metadata.local.pvid = -1;
    if_metadata.other.index = -1;
    if_metadata.other.pvid = -1;
#endif
}

ndFlow::ndFlow(const ndFlow &flow)
  : iface(flow.iface), lower_mac(flow.lower_mac),
    upper_mac(flow.upper_mac), lower_addr(flow.lower_addr),
    upper_addr(flow.upper_addr), first_addr_cmp(flow.first_addr_cmp),
    ip_version(flow.ip_version), ip_protocol(flow.ip_protocol),
    vlan_id(flow.vlan_id), ts_first_seen(flow.ts_first_seen),
    ts_last_seen(flow.ts_last_seen.load()),
    tunnel_type(flow.tunnel_type), origin(flow.origin),
    digest_lower(flow.digest_lower), flags{}, tcp{},
#ifdef _ND_ENABLE_CONNTRACK
    conntrack(flow.conntrack),
#endif
#if defined(_ND_ENABLE_INTERFACE_METADATA)
    if_metadata(flow.if_metadata),
#endif
    gtp(flow.gtp), detected_protocol_name("Unknown") {
    digest_mdata.push_back(digest_lower);
    tcp.last_seq = flow.tcp.last_seq.load();
    tcp.fin_ack = flow.tcp.fin_ack.load();
    tcp.lower_next_seq = flow.tcp.lower_next_seq.load();
    tcp.upper_next_seq = flow.tcp.upper_next_seq.load();
}

ndFlow::~ndFlow() {
    Release();
}

void ndFlow::Hash(const string &device, bool hash_mdata,
  const uint8_t *key, size_t key_length) {

    uint8_t hdata[256];
    size_t hoff = 0;

    auto hwrite = [&](const void *data, size_t len) {
        if (hoff + len <= sizeof(hdata)) {
            memcpy(&hdata[hoff], data, len);
            hoff += len;
        }
    };

    hwrite(device.c_str(), device.size());
    hwrite(&ip_version, sizeof(ip_version));
    hwrite(&ip_protocol, sizeof(ip_protocol));
    uint16_t vlan_be = htons(vlan_id);
    hwrite(&vlan_be, sizeof(vlan_be));

    switch (ip_version) {
    case 4:
        hwrite(&lower_addr.addr.in.sin_addr.s_addr, 4);
        hwrite(&upper_addr.addr.in.sin_addr.s_addr, 4);

        if (lower_addr.addr.in.sin_addr.s_addr == 0 &&
          upper_addr.addr.in.sin_addr.s_addr == 0xffffffff)
        {
#if defined(__linux__)
            hwrite(lower_mac.addr.ll.sll_addr, ETH_ALEN);
#elif defined(__FreeBSD__)
            hwrite(LLADDR(&lower_mac.addr.dl), ETH_ALEN);
#endif
        }
        break;
    case 6:
        hwrite(&lower_addr.addr.in6.sin6_addr.s6_addr, 16);
        hwrite(&upper_addr.addr.in6.sin6_addr.s6_addr, 16);
        break;
    }

    uint16_t port = lower_addr.GetPort(false);
    hwrite(&port, sizeof(port));
    port = upper_addr.GetPort(false);
    hwrite(&port, sizeof(port));

    if (hash_mdata) {
        hwrite(&detected_protocol, sizeof(ndProto::Id));
        hwrite(&detected_application, sizeof(ndApp::Id));

        if (! host_server_name.empty()) {
            hwrite(host_server_name.c_str(),
              host_server_name.size());
        }

        if (HasBTInfoHash()) {
            hwrite(bt.info_hash.data(),
              bt.info_hash.size());
        }
    }

    if (key != nullptr && key_length > 0)
        hwrite(key, key_length);

    if (! hash_mdata)
        digest_lower = nd_xxh64(hdata, hoff);
    else {
        ndDigest mdata = nd_xxh64(hdata, hoff);
        PushMetadataDigest(mdata);
    }
}

void ndFlow::Release(void) {
    lock_guard<recursive_mutex> lg(lock);

    if (ndpi_flow != nullptr) {
        ndpi_free_flow(ndpi_flow);
        ndpi_flow = nullptr;
    }
}

ndProto::Id ndFlow::GetMasterProtocol(void) const {
    switch (detected_protocol) {
    case ndProto::Id::HTTPS:
    case ndProto::Id::TLS:
    case ndProto::Id::FTPS:
    case ndProto::Id::FTPS_DATA:
    case ndProto::Id::MAIL_IMAPS:
    case ndProto::Id::MAIL_POPS:
    case ndProto::Id::MAIL_SMTPS:
    case ndProto::Id::MQTTS:
    case ndProto::Id::NNTPS:
    case ndProto::Id::SIPS: return ndProto::Id::TLS;
    case ndProto::Id::HLS:
    case ndProto::Id::HTTP:
    case ndProto::Id::HTTP_CONNECT:
    case ndProto::Id::HTTP_PROXY:
    case ndProto::Id::OOKLA:
    case ndProto::Id::RTSP:
    case ndProto::Id::STEAM:
    case ndProto::Id::TEAMVIEWER:
    case ndProto::Id::XBOX: return ndProto::Id::HTTP;
    case ndProto::Id::DNS:
    case ndProto::Id::MDNS:
    case ndProto::Id::LLMNR: return ndProto::Id::DNS;
    default: break;
    }

    return detected_protocol;
}

bool ndFlow::HasDhcpFingerprint(void) const {
    return (detected_protocol == ndProto::Id::DHCP &&
      ! dhcp.fingerprint.empty());
}

bool ndFlow::HasDhcpClassIdent(void) const {
    return (detected_protocol == ndProto::Id::DHCP &&
      ! dhcp.class_ident.empty());
}

bool ndFlow::HasHttpUserAgent(void) const {
    return (GetMasterProtocol() == ndProto::Id::HTTP &&
      ! http.user_agent.empty());
}

bool ndFlow::HasHttpURL(void) const {
    return (GetMasterProtocol() == ndProto::Id::HTTP &&
      ! http.url.empty());
}

bool ndFlow::HasSSHClientAgent(void) const {
    return (detected_protocol == ndProto::Id::SSH &&
      ! ssh.client_agent.empty());
}

bool ndFlow::HasSSHServerAgent(void) const {
    return (detected_protocol == ndProto::Id::SSH &&
      ! ssh.server_agent.empty());
}

bool ndFlow::HasTLSClientSNI(void) const {
    return ((GetMasterProtocol() == ndProto::Id::TLS ||
              detected_protocol == ndProto::Id::DTLS ||
              detected_protocol == ndProto::Id::QUIC) &&
      host_server_name.empty() == false);
}

bool ndFlow::HasTLSEncryptedCH(void) const {
    return ((GetMasterProtocol() == ndProto::Id::TLS ||
              detected_protocol == ndProto::Id::DTLS ||
              detected_protocol == ndProto::Id::QUIC) &&
      tls.ech.version != 0);
}

bool ndFlow::HasTLSServerCN(void) const {
    return ((GetMasterProtocol() == ndProto::Id::TLS ||
              detected_protocol == ndProto::Id::DTLS ||
              detected_protocol == ndProto::Id::QUIC) &&
      ! tls.server_cn.empty());
}

bool ndFlow::HasTLSIssuerDN(void) const {
    return ((GetMasterProtocol() == ndProto::Id::TLS ||
              detected_protocol == ndProto::Id::DTLS ||
              detected_protocol == ndProto::Id::QUIC) &&
      ! tls.issuer_dn.empty());
}

bool ndFlow::HasTLSSubjectDN(void) const {
    return ((GetMasterProtocol() == ndProto::Id::TLS ||
              detected_protocol == ndProto::Id::DTLS ||
              detected_protocol == ndProto::Id::QUIC) &&
      ! tls.subject_dn.empty());
}

bool ndFlow::HasTLSClientJA4(void) const {
    return ((GetMasterProtocol() == ndProto::Id::TLS ||
              detected_protocol == ndProto::Id::DTLS) &&
      ! tls.client_ja4.empty());
}

bool ndFlow::HasBTInfoHash(void) const {
    return (detected_protocol == ndProto::Id::BITTORRENT &&
      ! bt.info_hash.empty());
}

bool ndFlow::HasSSDPUserAgent(void) const {
    return (GetMasterProtocol() == ndProto::Id::SSDP &&
      ! http.user_agent.empty());
}

bool ndFlow::HasMDNSDomainName(void) const {
    return (detected_protocol == ndProto::Id::MDNS &&
      ! mdns.domain_name.empty());
}

bool ndFlow::HasSTUNAddress(void) const {
    return (stun.mapped.IsValid() || stun.peer.IsValid() ||
      stun.relayed.IsValid() || stun.response.IsValid() || stun.other.IsValid());
}

void ndFlow::Print(ndFlags<PrintFlags> pflags,
  const string &prefix) const {
    bool multiline = false;
    ndDebugLogStream dls(ndDebugLogStream::Type::FLOW);

    lock_guard<recursive_mutex> lg(lock);

    ostringstream os;
    if (! prefix.empty()) os << prefix << ": ";
    os << iface->ifname;
    size_t plen = 4;

    nd_output_lock();

    try {
        dls << os.str() << ": ";

        if (ndFlagBoolean(pflags, PrintFlags::HASHES)) {
            string h1, h2, h3;
            nd_xxh64_to_string(digest_lower, h1);

            auto mdata = digest_mdata.rbegin();
            if (mdata != digest_mdata.rend()) {
                nd_xxh64_to_string(*mdata, h2);
                mdata++;
            } else {
                h2 = "0000000000000000";
            }

            if (mdata != digest_mdata.rend()) {
                nd_xxh64_to_string(*mdata, h3);
            } else {
                h3 = "0000000000000000";
            }

            dls << h1.substr(0, 10) << ":" << h2.substr(0, 10) << ":" << h3.substr(0, 10) << " ";
        }

        dls
          << setfill(' ') << dec
          << ((iface->role == ndInterfaceRole::LAN) ? 'i' : 'e')
          << ((ip_version == 4)    ? '4' :
                 (ip_version == 6) ? '6' :
                                     '-')
          << (flags.detection_init.load() ? 'p' : '-')
          << (flags.detection_complete.load() ? 'c' : '-')
          << (flags.detection_updated.load() ? 'u' : '-')
          << (flags.detection_guessed.load() ? 'g' : '-')
          << (flags.expiring.load() ? 'x' : '-')
          << (flags.expired.load() ? 'X' : '-')
          << (flags.dhc_hit.load() ? 'd' : '-')
          << (flags.fhc_hit.load() ? 'f' : '-')
          << (flags.ip_nat.load() ? 'n' : '-')
          << (risk.risks.empty() ? '-' : 'r')
          << (flags.soft_dissector.load() ? 's' : '-')
          << (flags.app_ip_override.load() ? 'o' : '-')
          << (flags.app_proto_twins.load() ? 't' : '-')
          << (tcp.fin_ack.load() ? 'F' : '-')
          << (ndFlagBoolean(privacy_mask,
                (PrivacyMask::LOWER_MAC | PrivacyMask::LOWER_IP)) ?
                 'v' :
                 ndFlagBoolean(privacy_mask,
                   (PrivacyMask::UPPER_MAC | PrivacyMask::UPPER_IP)) ?
                 'V' :
                 ndFlagBoolean(privacy_mask,
                   (PrivacyMask::LOWER_MAC | PrivacyMask::LOWER_IP |
                     PrivacyMask::UPPER_MAC | PrivacyMask::UPPER_IP)) ?
                 '?' :
                 '-')
          << " ";

        string proto;
        nd_get_ip_protocol_name(ip_protocol, proto);
        dls << proto << " ";

        switch (lower_map) {
        case LowerMap::UNKNOWN: dls << "[U"; break;
        case LowerMap::LOCAL: dls << "[L"; break;
        case LowerMap::OTHER: dls << "[O"; break;
        }

        char ot = '?';
        switch (other_type) {
        case OtherType::UNKNOWN: ot = 'U'; break;
        case OtherType::UNSUPPORTED: ot = 'X'; break;
        case OtherType::LOCAL: ot = 'L'; break;
        case OtherType::MULTICAST: ot = 'M'; break;
        case OtherType::BROADCAST: ot = 'B'; break;
        case OtherType::REMOTE: ot = 'R'; break;
        case OtherType::ERROR: ot = 'E'; break;
        }

        if (lower_map == LowerMap::OTHER) dls << ot;

        dls << "] ";

        if (ndFlagBoolean(pflags, PrintFlags::MACS))
            dls << lower_mac.GetString() << " ";

        dls
          << lower_addr.GetString() << ":"
          << lower_addr.GetPort() << " "
          << ((origin == Origin::LOWER || origin == Origin::UNKNOWN) ? '-' : '<')
          << ((origin == Origin::UNKNOWN) ? '?' : '-')
          << ((origin == Origin::UPPER || origin == Origin::UNKNOWN) ? '-' : '>')
          << " ";

        switch (lower_map) {
        case LowerMap::UNKNOWN: dls << "[U"; break;
        case LowerMap::LOCAL: dls << "[O"; break;
        case LowerMap::OTHER: dls << "[L"; break;
        }

        if (lower_map == LowerMap::LOCAL) dls << ot;

        dls << "] ";

        if (ndFlagBoolean(pflags, PrintFlags::MACS))
            dls << upper_mac.GetString() << " ";

        dls << upper_addr.GetString() << ":"
            << upper_addr.GetPort();

        if (ndFlagBoolean(pflags, PrintFlags::METADATA) &&
          flags.detection_init.load())
        {
            multiline = true;

            dls
              << endl
              << setw(plen) << " "
              << ": " << detected_protocol_name
              << ((! detected_application_name.empty()) ? "." : "")
              << ((! detected_application_name.empty()) ?
                     detected_application_name :
                     "");

            if (!tags.empty()) {
                dls << endl
                    << setw(plen) << " "
                    << ": OVERLAY: " << *tags.begin();
                auto it = tags.begin();
                it++;
                for (; it != tags.end(); ++it) {
                    dls << endl
                        << setw(plen) << " "
                        << "           " << *it;
                }
            }

#ifdef _ND_ENABLE_CONNTRACK
            dls << endl
                << setw(plen) << " " << ":"
                << " CT ID: " << conntrack.id;
#ifdef _ND_ENABLE_CONNTRACK_MDATA
            dls << ":"
                << " MARK: " << conntrack.mark;

            if (vlan_id > 0) {
                dls
                  << endl
                  << setw(plen) << " "
                  << ": VLAN: " << vlan_id;
            }

            if (conntrack.reply_src_addr.IsValid() ||
                conntrack.reply_dst_addr.IsValid()) {
                dls << endl
                    << setw(plen) << " " << ": CT REPLY";
                if (conntrack.reply_src_addr.IsValid()) {
                    dls << " SRC: "
                        << conntrack.reply_src_addr.GetString() << ":"
                        << conntrack.reply_src_addr.GetPort();
                }
                if (conntrack.reply_dst_addr.IsValid()) {
                    dls << " DST: "
                        << conntrack.reply_dst_addr.GetString() << ":"
                        << conntrack.reply_dst_addr.GetPort();
                }
            }
#endif // _ND_ENABLE_CONNTRACK_MDATA
#endif // _ND_ENABLE_CONNTRACK
#ifdef _ND_ENABLE_NFQUEUE
            if (! nfq.src_iface.empty() || ! nfq.dst_iface.empty()) {
                dls << endl
                    << setw(plen) << " "
                    << ": NFQ";
                if (! nfq.src_iface.empty())
                    dls << " SRC: " << nfq.src_iface;
                if (! nfq.dst_iface.empty())
                    dls << " DST: " << nfq.dst_iface;
            }
#endif
#if defined(_ND_ENABLE_INTERFACE_METADATA)
            if (if_metadata.local.index != -1 || if_metadata.other.index != -1) {
                dls << endl << setw(plen) << " " << ": META";

                if (if_metadata.local.index != -1) {
                    dls << " L:[IDX:" << if_metadata.local.index;
                    if (if_metadata.local.name[0] != '\0')
                        dls << " NM:" << if_metadata.local.name;
                    if (if_metadata.local.ssid[0] != '\0')
                        dls << " SSID:" << if_metadata.local.ssid;
                    if (if_metadata.local.pvid != -1)
                        dls << " PVID:" << if_metadata.local.pvid;
                    dls << "]";
                }

                if (if_metadata.other.index != -1) {
                    dls << " O:[IDX:" << if_metadata.other.index;
                    if (if_metadata.other.name[0] != '\0')
                        dls << " NM:" << if_metadata.other.name;
                    if (if_metadata.other.pvid != -1)
                        dls << " PVID:" << if_metadata.other.pvid;
                    dls << "]";
                }
            }
#endif

            if (! dns_host_name.empty() ||
              ! host_server_name.empty())
            {
                dls << endl
                    << setw(plen) << " "
                    << ":";
                if (! dns_host_name.empty())
                    dls << " D: " << dns_host_name;
                if (! host_server_name.empty() &&
                  dns_host_name.compare(host_server_name))
                    dls << " H: " << host_server_name;
            }

            if (HasMDNSDomainName()) {
                dls << endl
                    << setw(plen) << " "
                    << ":";
                dls << " MDNS/DN: " << mdns.domain_name;
            }

            if (HasBTInfoHash()) {
                string digest;
                nd_sha1_to_string(bt.info_hash, digest);

                dls << endl
                    << setw(plen) << " "
                    << ":";
                dls << " BT/HASH: " << digest;
            }

            if (HasDhcpFingerprint() || HasDhcpClassIdent()) {
                dls << endl
                    << setw(plen) << " "
                    << ":";
                if (HasDhcpFingerprint())
                    dls << " DHCP/FP: " << dhcp.fingerprint;
                if (HasDhcpClassIdent())
                    dls << " DHCP/CI: " << dhcp.class_ident;
            }

            if (HasHttpUserAgent() || HasSSDPUserAgent()) {
                dls << endl
                    << setw(plen) << " "
                    << ":";
                dls << " HTTP/UA: " << http.user_agent;
            }

            if (HasHttpURL()) {
                dls << endl
                    << setw(plen) << " "
                    << ":";
                dls << " URL: " << http.url;
            }

            if (HasSSHClientAgent() || HasSSHServerAgent()) {
                dls << endl
                    << setw(plen) << " "
                    << ":";
                if (HasSSHClientAgent())
                    dls << " SSH/CA: " << ssh.client_agent;
                if (HasSSHServerAgent())
                    dls << " SSH/SA: " << ssh.server_agent;
            }

            if (HasSTUNAddress()) {
                if (stun.mapped.IsValid()) {
                    dls << endl
                        << setw(plen) << " "
                        << ":";
                    dls << " STUN/MAPPED: " << stun.mapped.GetString()
                        << ":" << stun.mapped.GetPort();
                }
                if (stun.peer.IsValid()) {
                    dls << endl
                        << setw(plen) << " "
                        << ":";
                    dls << " STUN/PEER: " << stun.peer.GetString()
                        << ":" << stun.peer.GetPort();
                }
                if (stun.relayed.IsValid()) {
                    dls << endl
                        << setw(plen) << " "
                        << ":";
                    dls << " STUN/RELAYED: " << stun.relayed.GetString()
                        << ":" << stun.relayed.GetPort();
                }
                if (stun.response.IsValid()) {
                    dls << endl
                        << setw(plen) << " "
                        << ":";
                    dls << " STUN/RESPONSE: " << stun.response.GetString()
                        << ":" << stun.response.GetPort();
                }
                if (stun.other.IsValid()) {
                    dls << endl
                        << setw(plen) << " "
                        << ":";
                    dls << " STUN/OTHER: " << stun.other.GetString()
                        << ":" << stun.other.GetPort();
                }
            }

            if ((GetMasterProtocol() == ndProto::Id::TLS ||
                  detected_protocol == ndProto::Id::DTLS ||
                  detected_protocol == ndProto::Id::QUIC) &&
              (tls.version || tls.cipher_suite))
            {
                dls << endl
                    << setw(plen) << " "
                    << ": ";
                dls << "V: 0x" << setfill('0') << setw(4) << hex
                    << tls.version << setfill(' ') << dec;

                if (tls.cipher_suite) {
                    dls << " "
                        << "CS: 0x" << setfill('0')
                        << setw(4) << hex << tls.cipher_suite
                        << setfill(' ') << dec;
                }
            }

            if (HasTLSClientSNI() || HasTLSServerCN()) {
                dls << endl
                    << setw(plen) << " "
                    << ":";
                if (HasTLSClientSNI())
                    dls << " TLS/SNI: " << host_server_name;
                if (HasTLSServerCN())
                    dls << " TLS/CN: " << tls.server_cn;
            }

            if (HasTLSEncryptedCH()) {
                dls << endl
                    << setw(plen) << " "
                    << ": TLS/ECH: 0x" << setfill('0')
                    << setw(4) << hex << tls.ech.version
                    << setfill(' ') << dec;
            }

            if (HasTLSIssuerDN() || HasTLSSubjectDN()) {
                dls << endl
                    << setw(plen) << " "
                    << ":";
                if (HasTLSIssuerDN())
                    dls << " TLS/IDN: " << tls.issuer_dn;
                if (HasTLSSubjectDN())
                    dls << " TLS/SDN: " << tls.subject_dn;
            }

            if (HasTLSClientJA4()) {
                dls << endl
                    << setw(plen) << " "
                    << ": JA4: " << tls.client_ja4;
            }

            ndInstance &ndi = ndInstance::GetInstance();

            dls << endl
                << setw(plen) << " "
                << ": CAT/APP: " << ndi.categories.GetTag(
                  ndCategories::Type::APP, category.application)
                << " CAT/PROTO: " << ndi.categories.GetTag(
                  ndCategories::Type::PROTO, category.protocol)
                << " CAT/DOMAIN: " << ndi.categories.GetTag(
                  ndCategories::Type::APP, category.domain)
                << " CAT/NET/LOWER: " << ndi.categories.GetTag(
                  ndCategories::Type::APP, category.lower_net)
                << " CAT/NET/UPPER: " << ndi.categories.GetTag(
                  ndCategories::Type::APP, category.upper_net)
                << " CAT/OVERLAY: " << ndi.categories.GetTag(
                  ndCategories::Type::APP, category.overlay);
        }

        if (ndFlagBoolean(pflags, PrintFlags::RISKS)) {
            if (! risk.risks.empty()) {
                auto r = risk.risks.begin();
                if (r != risk.risks.end()) {
                    dls
                      << endl
                      << setw(plen) << " " << setw(0) << ": RID"
                      << setw(3) << static_cast<unsigned>(*r)
                      << ": " << setw(0) << ndRisk::GetName(*r);
                }
                if (risk.risks.size() > 1) {
                    for (r = next(risk.risks.begin());
                         r != risk.risks.end();
                         r++)
                    {
                        dls
                          << endl
                          << setw(plen) << " " << setw(0)
                          << ": RID" << setw(3)
                          << static_cast<unsigned>(*r) << ": "
                          << setw(0) << ndRisk::GetName(*r);
                    }
                }
            }
        }

        if (ndFlagBoolean(pflags, PrintFlags::STATS)) {
            multiline = true;

            dls << endl
                << setw(plen) << " "
                << ": "
                << "DP: "
                << ndLogFormat(ndLogFormat::Format::BYTES,
                     stats.detection_packets.load());

            if (ndFlagBoolean(pflags, PrintFlags::STATS_FULL))
            {
                dls
                  << " "
                  << "TP: "
                  << ndLogFormat(ndLogFormat::Format::PACKETS,
                       stats.total_packets.load())
                  << " "
                  << "TB: "
                  << ndLogFormat(ndLogFormat::Format::BYTES,
                       stats.total_bytes.load());
            }
        }

        if (multiline) dls << endl;
        dls << endl;
    }
    catch (exception &e) {
        nd_output_unlock();

        nd_dprintf("exception caught printing flow: %s\n",
          e.what());
        return;
    }

    nd_output_unlock();
}

void ndFlow::UpdateLowerMaps(void) {
    if (lower_map == LowerMap::UNKNOWN)
        GetLowerMap(lower_type, upper_type, lower_map, other_type);

    switch (tunnel_type) {
    case TunnelType::GTP:
        if (gtp.lower_map == LowerMap::UNKNOWN) {
            GetLowerMap(gtp.lower_type, gtp.upper_type,
              gtp.lower_map, gtp.other_type);
        }
        break;
    default: break;
    }
}

void ndFlow::GetLowerMap(ndAddr::Type lt, ndAddr::Type ut,
  LowerMap &lm, OtherType &ot) {
    if (lt == ndAddr::Type::ERROR || ut == ndAddr::Type::ERROR) {
        ot = OtherType::ERROR;
    }
    else if (lt == ndAddr::Type::LOCAL && ut == ndAddr::Type::LOCAL) {
        lm = (origin == Origin::LOWER || origin == Origin::UNKNOWN) ?
            LowerMap::LOCAL : LowerMap::OTHER;
        ot = OtherType::LOCAL;
    }
    else if (lt == ndAddr::Type::LOCAL && ut == ndAddr::Type::LOCALNET) {
        lm = (origin == Origin::LOWER || origin == Origin::UNKNOWN) ?
            LowerMap::LOCAL : LowerMap::OTHER;
        ot = OtherType::LOCAL;
    }
    else if (lt == ndAddr::Type::LOCALNET && ut == ndAddr::Type::LOCAL) {
        lm = (origin == Origin::LOWER || origin == Origin::UNKNOWN) ?
            LowerMap::LOCAL : LowerMap::OTHER;
        ot = OtherType::LOCAL;
    }
    else if (lt == ndAddr::Type::RESERVED && ut == ndAddr::Type::LOCALNET) {
        lm = LowerMap::OTHER;
        ot = OtherType::LOCAL;
    }
    else if (lt == ndAddr::Type::LOCALNET && ut == ndAddr::Type::RESERVED) {
        lm = (origin == Origin::LOWER || origin == Origin::UNKNOWN) ?
            LowerMap::LOCAL : LowerMap::OTHER;
        ot = OtherType::LOCAL;
    }
    else if (lt == ndAddr::Type::RESERVED && ut == ndAddr::Type::LOCAL) {
        lm = LowerMap::OTHER;
        ot = OtherType::REMOTE;
    }
    else if (lt == ndAddr::Type::LOCAL && ut == ndAddr::Type::RESERVED) {
        lm = LowerMap::LOCAL;
        ot = OtherType::REMOTE;
    }
    else if (lt == ndAddr::Type::MULTICAST) {
        lm = LowerMap::OTHER;
        ot = OtherType::MULTICAST;
    }
    else if (ut == ndAddr::Type::MULTICAST) {
        lm = LowerMap::LOCAL;
        ot = OtherType::MULTICAST;
    }
    else if (lt == ndAddr::Type::BROADCAST) {
        lm = LowerMap::OTHER;
        ot = OtherType::BROADCAST;
    }
    else if (ut == ndAddr::Type::BROADCAST) {
        lm = LowerMap::LOCAL;
        ot = OtherType::BROADCAST;
    }
    // TODO: Further investigation required!
    // This appears to catch corrupted IPv6 headers.
    // Spend some time to figure out if there are any
    // possible over-matches for different methods of
    // deployment (gateway/port mirror modes).
    else if (ip_version != 6 && lt == ndAddr::Type::RESERVED &&
      ut == ndAddr::Type::RESERVED)
    {
        lm = (origin == Origin::LOWER || origin == Origin::UNKNOWN) ?
            LowerMap::LOCAL : LowerMap::OTHER;
        ot = OtherType::LOCAL;
    }
    else if (lt == ndAddr::Type::LOCALNET && ut == ndAddr::Type::LOCALNET) {
        lm = (origin == Origin::LOWER || origin == Origin::UNKNOWN) ?
            LowerMap::LOCAL : LowerMap::OTHER;
        ot = OtherType::LOCAL;
    }
    else if (lt == ndAddr::Type::OTHER) {
        lm = LowerMap::OTHER;
        ot = OtherType::REMOTE;
    }
    else if (ut == ndAddr::Type::OTHER) {
        lm = LowerMap::LOCAL;
        ot = OtherType::REMOTE;
    }
#if _ND_DEBUG_LOWER_MAP
    const static vector<string> lower_maps = { "lmUNKNOWN",
        "lmLOCAL", "lmOTHER" };
    const static vector<string> other_types = { "otUNKNOWN",
        "otUNSUPPORTED", "otLOCAL", "otMULTICAST",
        "otBROADCAST", "otREMOTE", "otERROR" };
    const static vector<string> at = { "atNONE", "atLOCAL",
        "atLOCALNET", "atRESERVED", "atMULTICAST",
        "atBROADCAST", "atOTHER" };

    if (lm == lmUNKNOWN) {
        nd_dprintf("lower map: %s, other type: %s\n",
          lower_maps[lm].c_str(),
          other_types[ot].c_str());
        nd_dprintf(
          "lower type: %s: %s, upper_type: %s: %s\n",
          lower_addr.GetString().c_str(),
          (lt == ndAddr::Type::ERROR) ? "atERROR" : at[lt].c_str(),
          upper_addr.GetString().c_str(),
          (ut == ndAddr::Type::ERROR) ? "atERROR" : at[ut].c_str());
    }
#endif
}

bool ndFlow::PushMetadataDigest(const ndDigest &digest) {
    for (auto &i : digest_mdata) {
        if (i == digest) return false;
    }

    digest_mdata.push_back(digest);

#ifdef _ND_DEBUG_DIGEST_MDATA
    string lower;
    nd_xxh64_to_string(digest_lower, lower);

    unsigned i = 0;
    for (auto &d : digest_mdata) {
        string mdata;
        nd_xxh64_to_string(d, mdata);
        nd_dprintf("%s: digest mdata[%u]: %s\n",
          lower.c_str(), i++, mdata.c_str());
    }
#endif
    return true;
}
