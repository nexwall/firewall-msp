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
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "nd-addr.hpp"
#include "nd-category.hpp"
#include "nd-config.hpp"
#include "nd-flags.hpp"
#include "nd-protos.hpp"
#include "nd-serializer.hpp"
#include "nd-sha1.h"
#include "nd-types.hpp"
#include "nd-util.hpp"

// TLS SNI hostname/common-name length. Reference: RFC 4366
constexpr size_t ND_FLOW_TLS_CNLEN = 256;

class ndFlowStats
{
public:
    ndFlowStats()
      : lower_bytes(0), upper_bytes(0), total_bytes(0),
        total_lower_bytes(0), total_upper_bytes(0),
        lower_packets(0), upper_packets(0), total_packets(0),
        total_lower_packets(0), total_upper_packets(0),
        detection_packets(0)
#ifdef _ND_ENABLE_EXTENDED_STATS
        ,
        lower_rate_samples(ndGC.update_interval, 0),
        upper_rate_samples(ndGC.update_interval, 0),
        lower_rate(0), upper_rate(0), tcp_seq_errors(0),
        tcp_resets(0), tcp_retrans(0)
#endif
    {
    }

    ndFlowStats(const ndFlowStats &stats)
      : lower_bytes(stats.lower_bytes.load()),
        upper_bytes(stats.upper_bytes.load()),
        total_bytes(stats.total_bytes.load()),
        total_lower_bytes(stats.total_lower_bytes.load()),
        total_upper_bytes(stats.total_upper_bytes.load()),
        lower_packets(stats.lower_packets.load()),
        upper_packets(stats.upper_packets.load()),
        total_packets(stats.total_packets.load()),
        total_lower_packets(stats.total_lower_packets.load()),
        total_upper_packets(stats.total_upper_packets.load()),
        detection_packets(stats.detection_packets.load())
#ifdef _ND_ENABLE_EXTENDED_STATS
        ,
        lower_rate_samples(ndGC.update_interval, 0),
        upper_rate_samples(ndGC.update_interval, 0),
        lower_rate(stats.lower_rate.load()),
        upper_rate(stats.upper_rate.load()),
        tcp_seq_errors(stats.tcp_seq_errors.load()),
        tcp_resets(stats.tcp_resets.load()),
        tcp_retrans(stats.tcp_retrans.load())
#endif
    {
    }

    inline ndFlowStats &operator=(const ndFlowStats &fs) {
        lower_bytes = fs.lower_bytes.load();
        upper_bytes = fs.upper_bytes.load();
        total_bytes = fs.total_bytes.load();
        total_lower_bytes = fs.total_lower_bytes.load();
        total_upper_bytes = fs.total_upper_bytes.load();
        lower_packets = fs.lower_packets.load();
        upper_packets = fs.upper_packets.load();
        total_packets = fs.total_packets.load();
        total_lower_packets = fs.total_lower_packets.load();
        total_upper_packets = fs.total_upper_packets.load();
        detection_packets = fs.detection_packets.load();
#ifdef _ND_ENABLE_EXTENDED_STATS
        lower_rate = fs.lower_rate.load();
        upper_rate = fs.upper_rate.load();
        tcp_seq_errors = fs.tcp_seq_errors.load();
        tcp_resets = fs.tcp_resets.load();
        tcp_retrans = fs.tcp_retrans.load();
#endif
        return *this;
    };

    inline void Reset(void) {
        lower_bytes = 0;
        upper_bytes = 0;
        lower_packets = 0;
        upper_packets = 0;
#ifdef _ND_ENABLE_EXTENDED_STATS
        lower_rate_samples.assign(ndGC.update_interval, 0);
        upper_rate_samples.assign(ndGC.update_interval, 0);
        tcp_seq_errors = 0;
        tcp_resets = 0;
        tcp_retrans = 0;
#endif
    }

    std::atomic<uint64_t> lower_bytes;
    std::atomic<uint64_t> upper_bytes;
    std::atomic<uint64_t> total_bytes;
    std::atomic<uint64_t> total_lower_bytes;
    std::atomic<uint64_t> total_upper_bytes;

    std::atomic<uint32_t> lower_packets;
    std::atomic<uint32_t> upper_packets;
    std::atomic<uint32_t> total_packets;
    std::atomic<uint32_t> total_lower_packets;
    std::atomic<uint32_t> total_upper_packets;

    std::atomic<uint8_t> detection_packets;

#ifdef _ND_ENABLE_EXTENDED_STATS
    std::vector<uint64_t> lower_rate_samples;
    std::vector<uint64_t> upper_rate_samples;
    std::atomic<float> lower_rate;
    std::atomic<float> upper_rate;

    void UpdateRate(bool lower, uint64_t timestamp, uint64_t bytes);

    std::atomic<uint32_t> tcp_seq_errors;
    std::atomic<uint32_t> tcp_resets;
    std::atomic<uint32_t> tcp_retrans;
#endif
};

class ndFlow : public ndSerializer
{
public:
    using Ptr = std::shared_ptr<ndFlow>;

    ndInterface::Ptr iface;

    ndAddr lower_mac;
    ndAddr upper_mac;

    ndAddr lower_addr;
    ndAddr upper_addr;

    ndAddr::Type lower_type = { ndAddr::Type::NONE };
    ndAddr::Type upper_type = { ndAddr::Type::NONE };

    int first_addr_cmp = { 0 };

    uint8_t ip_version = { 0 };
    uint8_t ip_dscp = { 0 };
    uint8_t ip_protocol = { 0 };

    uint16_t vlan_id = { 0 };

    uint64_t ts_first_seen = { 0 };
    std::atomic<uint64_t> ts_last_seen = { 0 };

    enum class LowerMap : uint8_t { UNKNOWN, LOCAL, OTHER };

    LowerMap lower_map = { LowerMap::UNKNOWN };

    enum class OtherType : uint8_t {
        UNKNOWN,
        UNSUPPORTED,
        LOCAL,
        MULTICAST,
        BROADCAST,
        REMOTE,
        ERROR
    };

    OtherType other_type = { OtherType::UNKNOWN };

    enum class TunnelType : uint8_t { NONE, GTP };

    TunnelType tunnel_type = { TunnelType::NONE };

    enum class Origin : uint8_t {
        UNKNOWN,
        LOWER,
        UPPER,
    };

    Origin origin = { Origin::UNKNOWN };

    enum class PrivacyMask : uint8_t {
        NONE = 0,
        LOWER_MAC = (1 << 0),
        UPPER_MAC = (1 << 1),
        UPPER_IP = (1 << 2),
        LOWER_IP = (1 << 3)
    };

    ndFlags<PrivacyMask> privacy_mask = { PrivacyMask::NONE };

    ndDigest digest_lower = 0;

    using DigestVec = std::vector<ndDigest>;
    DigestVec digest_mdata;

    struct {
        std::atomic<bool> detection_complete = { false };
        std::atomic<bool> detection_guessed = { false };
        std::atomic<bool> detection_init = { false };
        std::atomic<bool> detection_updated = { false };
        std::atomic<bool> dhc_hit = { false };
        std::atomic<bool> fhc_hit = { false };
        std::atomic<bool> expiring = { false };
        std::atomic<bool> expiry_broadcast = { false };
        std::atomic<bool> expired = { false };
        std::atomic<bool> ip_nat = { false };
        std::atomic<bool> soft_dissector = { false };
        std::atomic<bool> app_ip_override = { false };
        std::atomic<bool> app_proto_twins = { false };
    } flags;

    struct {
        std::atomic<uint8_t> fin_ack = { 0 };
        std::atomic<uint32_t> last_seq = { 0 };
        std::atomic<uint32_t> lower_next_seq = { 0 };
        std::atomic<uint32_t> upper_next_seq = { 0 };
    } tcp;

#ifdef _ND_ENABLE_CONNTRACK
    struct {
        uint32_t id = { 0 };
#ifdef _ND_ENABLE_CONNTRACK_COUNTERS
        uint64_t packets[2] = { 0, 0 };
        uint64_t bytes[2] = { 0, 0 };
#endif
#ifdef _ND_ENABLE_CONNTRACK_MDATA
        uint32_t mark = { 0 };
        ndAddr reply_src_addr;
        ndAddr reply_dst_addr;
#endif
    } conntrack;
#endif
#if defined(_ND_ENABLE_INTERFACE_METADATA)
    struct if_metadata {
        int index = { -1 };
        int pvid = { -1 };
        std::string name;
        std::string ssid;
    };

    struct {
        if_metadata local;
        if_metadata other;
    } if_metadata;
#endif
#if defined(_ND_ENABLE_NFQUEUE)
    struct {
        int src_ifindex = { -1 };
        int dst_ifindex = { -1 };
        std::string src_iface;
        std::string dst_iface;
    } nfq;
#endif
    struct {
        uint8_t version = { 0xFF };
        uint8_t ip_version = { 0 };
        uint8_t ip_dscp = { 0 };
        uint32_t lower_teid = { 0 };
        uint32_t upper_teid = { 0 };
        ndAddr::Type lower_type = { ndAddr::Type::NONE };
        ndAddr::Type upper_type = { ndAddr::Type::NONE };
        ndAddr lower_addr;
        ndAddr upper_addr;
        LowerMap lower_map = { LowerMap::UNKNOWN };
        OtherType other_type = { OtherType::UNKNOWN };
    } gtp;

    std::string dns_host_name;
    std::string host_server_name;

    ndProto::Id detected_protocol = { ndProto::Id::UNKNOWN };
    std::string detected_protocol_name;
    ndpi_protocol detected_ndpi_protocol = { { 0 } };

    ndApp::Id detected_application = { ndApp::Id::UNKNOWN };
    std::string detected_application_name;

    struct {
        ndCategories::Id application = { ndCategory::UNKNOWN };
        ndCategories::Id protocol = { ndCategory::UNKNOWN };
        ndCategories::Id domain = { ndCategory::UNKNOWN };
        ndCategories::Id upper_net = { ndCategory::UNKNOWN };
        ndCategories::Id lower_net = { ndCategory::UNKNOWN };
        ndCategories::Id overlay = { ndCategory::UNKNOWN };
    } category;

    struct {
        std::string user_agent;
        std::string url;
    } http;

    struct {
        std::string fingerprint;
        std::string class_ident;
    } dhcp;

    struct {
        std::string client_agent;
        std::string server_agent;
    } ssh;

    struct {
        uint16_t version = { 0 };
        uint16_t cipher_suite = { 0 };

        std::string subject_dn;
        std::string issuer_dn;
        std::string server_cn;
        std::string client_ja4;
        std::vector<uint8_t> cert_fingerprint;
        std::vector<std::string> alpn, alpn_server;

        struct {
            uint16_t version = { 0 };
        } ech;

        std::atomic<bool> proc_hello = { false };
        std::atomic<bool> proc_certificate = { false };
    } tls;

    struct {
        bool tls = { false };
    } smtp;

    struct {
        ndDigestDynamic info_hash;
    } bt;

    struct {
        std::string domain_name;
    } mdns;

    struct {
        ndAddr mapped, peer, relayed, response, other;
    } stun;

    struct {
        uint16_t ndpi_score = { 0 };
        uint16_t ndpi_score_client = { 0 };
        uint16_t ndpi_score_server = { 0 };

        using Risks = std::set<ndRisk::Id>;
        Risks risks;
    } risk;

    ndFlowStats stats;

    using Tags = std::set<std::string>;
    Tags tags;

    mutable std::recursive_mutex lock;

    uint8_t dpi_queued = { 0 };
    int16_t dpi_thread_id = { -1 };

    struct ndpi_flow_struct *ndpi_flow = { nullptr };
    mutable ndFlow *lru_prev = { nullptr };
    mutable ndFlow *lru_next = { nullptr };
    uint8_t lru_list = { 0 };


    ndFlow(ndInterface::Ptr &iface);
    ndFlow(const ndFlow &flow);
    virtual ~ndFlow();

    void Hash(const std::string &device, bool hash_mdata = false,
      const uint8_t *key = nullptr, size_t key_length = 0);

    inline void Reset(bool full = false) {
        stats.Reset();
        tcp.last_seq = 0;
        tcp.lower_next_seq = 0;
        tcp.upper_next_seq = 0;
        tcp.fin_ack = 0;
        if (full) vlan_id = 0;
    }

    void Release(void);

    ndProto::Id GetMasterProtocol(void) const;

    bool HasDhcpFingerprint(void) const;
    bool HasDhcpClassIdent(void) const;
    bool HasHttpUserAgent(void) const;
    bool HasHttpURL(void) const;
    bool HasSSHClientAgent(void) const;
    bool HasSSHServerAgent(void) const;
    bool HasTLSClientSNI(void) const;
    bool HasTLSEncryptedCH(void) const;
    bool HasTLSServerCN(void) const;
    bool HasTLSIssuerDN(void) const;
    bool HasTLSSubjectDN(void) const;
    bool HasTLSClientJA4(void) const;
    bool HasBTInfoHash(void) const;
    bool HasSSDPUserAgent(void) const;
    bool HasMDNSDomainName(void) const;
    bool HasSTUNAddress(void) const;

    enum class PrintFlags : uint8_t {
        NONE = 0,
        HASHES = (1 << 0),
        MACS = (1 << 1),
        METADATA = (1 << 2),
        STATS = (1 << 3),
        STATS_FULL = (1 << 4),
        RISKS = (1 << 5),
        ALL = (HASHES | MACS | METADATA | STATS | STATS_FULL | RISKS)
    };

    void Print(ndFlags<PrintFlags> pflags = PrintFlags::METADATA,
      const std::string &prefix = "") const;

    void UpdateLowerMaps(void);
    void GetLowerMap(ndAddr::Type lt, ndAddr::Type ut,
      LowerMap &lm, OtherType &ot);

    enum class EncodeFlags : uint8_t {
        NONE = 0,
        METADATA = (1 << 0),
        TUNNELS = (1 << 1),
        STATS = (1 << 2),
        ALL = (METADATA | TUNNELS | STATS)
    };

    template <class T>
    void Encode(T &output, const ndFlowStats &stats,
      ndFlags<EncodeFlags> encode_flags = EncodeFlags::ALL) const {
        std::lock_guard<std::recursive_mutex> lg(lock);

        std::string _other_type = "unknown";
        std::string _lower_mac = "local_mac",
                    _upper_mac = "other_mac";
        std::string _lower_ip = "local_ip",
                    _upper_ip = "other_ip";
        std::string _lower_gtp_ip = "local_ip",
                    _upper_gtp_ip = "other_ip";
        std::string _lower_port = "local_port",
                    _upper_port = "other_port";
        std::string _lower_gtp_port = "local_port",
                    _upper_gtp_port = "other_port";
        std::string _lower_bytes = "local_bytes",
                    _upper_bytes = "other_bytes";
        std::string _total_lower_bytes = "total_local_bytes",
                    _total_upper_bytes = "total_other_bytes";
        std::string _lower_packets = "local_packets",
                    _upper_packets = "other_packets";
        std::string _total_lower_packets = "total_local_packets",
                    _total_upper_packets = "total_other_packets";
        std::string _lower_net_cat = "local_network";
        std::string _upper_net_cat = "other_network";
#ifdef _ND_ENABLE_EXTENDED_STATS
        std::string _lower_rate = "local_rate";
        std::string _upper_rate = "other_rate";
#endif
        std::string digest;

        if (digest_mdata.empty()) {
            nd_xxh64_to_string(digest_lower, digest);
            serialize(output, { "digest" }, digest);

            std::vector<std::string> digests;
            digests.push_back(digest);
            serialize(output, { "digest_prev" }, digests);
        }
        else {
            auto i = digest_mdata.rbegin();
            nd_xxh64_to_string((*i), digest);
            serialize(output, { "digest" }, digest);

            std::vector<std::string> digests;
            for (auto &i : digest_mdata) {
                nd_xxh64_to_string(i, digest);
                digests.push_back(digest);
            }
            serialize(output, { "digest_prev" }, digests);
        }

        serialize(output, { "last_seen_at" }, ts_last_seen.load());

        switch (lower_map) {
        case LowerMap::LOCAL:
            _lower_mac = "local_mac";
            _lower_ip = "local_ip";
            _lower_port = "local_port";
            _lower_bytes = "local_bytes";
            _total_lower_bytes = "total_local_bytes";
            _lower_packets = "local_packets";
            _total_lower_packets = "total_local_packets";
            _lower_net_cat = "local_network";
            _upper_mac = "other_mac";
            _upper_ip = "other_ip";
            _upper_port = "other_port";
            _upper_bytes = "other_bytes";
            _upper_packets = "other_packets";
            _upper_net_cat = "other_network";
#ifdef _ND_ENABLE_EXTENDED_STATS
            _lower_rate = "local_rate";
            _upper_rate = "other_rate";
#endif
            break;
        case LowerMap::OTHER:
            _lower_mac = "other_mac";
            _lower_ip = "other_ip";
            _lower_port = "other_port";
            _lower_bytes = "other_bytes";
            _total_lower_bytes = "total_other_bytes";
            _lower_packets = "other_packets";
            _total_lower_packets = "total_other_packets";
            _lower_net_cat = "other_network";
            _upper_mac = "local_mac";
            _upper_ip = "local_ip";
            _upper_port = "local_port";
            _upper_bytes = "local_bytes";
            _upper_packets = "local_packets";
            _upper_net_cat = "local_network";
#ifdef _ND_ENABLE_EXTENDED_STATS
            _lower_rate = "other_rate";
            _upper_rate = "local_rate";
#endif
            break;
        default: break;
        }

        switch (other_type) {
        case OtherType::LOCAL: _other_type = "local"; break;
        case OtherType::MULTICAST:
            _other_type = "multicast";
            break;
        case OtherType::BROADCAST:
            _other_type = "broadcast";
            break;
        case OtherType::REMOTE:
            _other_type = "remote";
            break;
        case OtherType::UNSUPPORTED:
            _other_type = "unsupported";
            break;
        case OtherType::ERROR: _other_type = "error"; break;
        default: break;
        }

        if (ndFlagBoolean(encode_flags, EncodeFlags::METADATA))
        {
            serialize(output, { "ip_nat" },
              (bool)flags.ip_nat.load());
            if (ndGC_USE_DHC) {
                serialize(output, { "dhc_hit" },
                  (bool)flags.dhc_hit.load());
            }
            if (ndGC_USE_FHC) {
                serialize(output, { "fhc_hit" },
                  (bool)flags.fhc_hit.load());
            }
            serialize(output, { "soft_dissector" },
              (bool)flags.soft_dissector.load());
            serialize(output, { "app_ip_override" },
              (bool)flags.app_ip_override.load());
            serialize(output, { "app_proto_twins" },
              (bool)flags.app_proto_twins.load());
            serialize(output, { "ip_version" }, (unsigned)ip_version);
            serialize(output, { "ip_dscp" }, (unsigned)ip_dscp);
            serialize(output, { "ip_protocol" },
              (unsigned)ip_protocol);
            serialize(output, { "vlan_id" }, (unsigned)vlan_id);
            serialize(output, { "other_type" }, _other_type);

            switch (origin) {
            case Origin::UPPER:
                serialize(output, { "local_origin" },
                  (_lower_ip == "local_ip") ? false : true);
                break;
            case Origin::LOWER:
            default:
                serialize(output, { "local_origin" },
                  (_lower_ip == "local_ip") ? true : false);
                break;
            }

            // 00-52-14 to 00-52-FF: Unserialized (small
            // allocations)
            serialize(output, { _lower_mac },
              ndFlagBoolean(privacy_mask, PrivacyMask::LOWER_MAC) ?
                "00:52:14:00:00:00" :
                (lower_mac.IsValid()) ?
                lower_mac.GetString() :
                "00:00:00:00:00:00");
            serialize(output, { _upper_mac },
              ndFlagBoolean(privacy_mask, PrivacyMask::UPPER_MAC) ?
                "00:52:ff:00:00:00" :
                (upper_mac.IsValid()) ?
                upper_mac.GetString() :
                "00:00:00:00:00:00");

            if (ndFlagBoolean(privacy_mask, PrivacyMask::LOWER_IP))
            {
                if (ip_version == 4)
                    serialize(output, { _lower_ip },
                      ND_PRIVATE_IPV4 "253");
                else
                    serialize(output, { _lower_ip },
                      ND_PRIVATE_IPV6 "fd");
            }
            else
                serialize(output, { _lower_ip },
                  lower_addr.GetString());

            if (ndFlagBoolean(privacy_mask, PrivacyMask::UPPER_IP))
            {
                if (ip_version == 4)
                    serialize(output, { _upper_ip },
                      ND_PRIVATE_IPV4 "254");
                else
                    serialize(output, { _upper_ip },
                      ND_PRIVATE_IPV6 "fe");
            }
            else
                serialize(output, { _upper_ip },
                  upper_addr.GetString());

            serialize(output, { _lower_port },
              (unsigned)lower_addr.GetPort());
            serialize(output, { _upper_port },
              (unsigned)upper_addr.GetPort());

            serialize(output, { "detected_protocol" },
              (unsigned)detected_protocol);
            serialize(output, { "detected_protocol_name" },
              (detected_protocol_name.empty()) ?
                "Unknown" :
                detected_protocol_name);

            serialize(output, { "detected_application" },
              (unsigned)detected_application);
            serialize(output, { "detected_application_name" },
              (detected_application_name.empty()) ?
                "Unknown" :
                detected_application_name);

            serialize(output, { "detection_guessed" },
              flags.detection_guessed.load());
            serialize(output, { "detection_updated" },
              flags.detection_updated.load());

            serialize(output, { "category", "application" },
              category.application);
            serialize(output, { "category", "protocol" },
              category.protocol);
            serialize(output, { "category", "domain" },
              category.domain);
            serialize(output, { "category", _lower_net_cat },
              category.lower_net);
            serialize(output, { "category", _upper_net_cat },
              category.upper_net);
            serialize(output, { "category", "overlay" },
              category.overlay);

#ifdef _ND_ENABLE_CONNTRACK
            serialize(output, { "conntrack", "id" }, conntrack.id);
#ifdef _ND_ENABLE_CONNTRACK_MDATA
            serialize(output, { "conntrack", "mark" }, conntrack.mark);
            if (conntrack.reply_src_addr.IsValid()) {
                serialize(output, { "conntrack", "reply_src_ip" },
                  conntrack.reply_src_addr.GetString());
                serialize(output, { "conntrack", "reply_src_port" },
                  (unsigned)conntrack.reply_src_addr.GetPort());
            }
            if (conntrack.reply_dst_addr.IsValid()) {
                serialize(output, { "conntrack", "reply_dst_ip" },
                  conntrack.reply_dst_addr.GetString());
                serialize(output, { "conntrack", "reply_dst_port" },
                  (unsigned)conntrack.reply_dst_addr.GetPort());
            }
#endif // _ND_ENABLE_CONNTRACK_MDATA
#endif // _ND_ENABLE_CONNTRACK
#if defined(_ND_ENABLE_INTERFACE_METADATA)
            if (if_metadata.local.index != -1) {
                serialize(output, { "local_if_meta", "index" }, (uint32_t)if_metadata.local.index);

                if (! if_metadata.local.name.empty())
                    serialize(output, { "local_if_meta", "name" }, if_metadata.local.name);

                if (! if_metadata.local.ssid.empty())
                    serialize(output, { "local_if_meta", "ssid" }, if_metadata.local.ssid);

                if (if_metadata.local.pvid != -1)
                    serialize(output, { "local_if_meta", "pvid" }, (uint32_t)if_metadata.local.pvid);
            }

            if (if_metadata.other.index != -1) {
                serialize(output, { "other_if_meta", "index" }, (uint32_t)if_metadata.other.index);

                if (if_metadata.other.name[0] != '\0')
                    serialize(output, { "other_if_meta", "name" }, if_metadata.other.name);

                if (if_metadata.other.pvid != -1)
                    serialize(output, { "other_if_meta", "pvid" }, (uint32_t)if_metadata.other.pvid);
            }
#endif // _ND_ENABLE_INTERFACE_METADATA
#if defined(_ND_ENABLE_NFQUEUE)
            if (! nfq.src_iface.empty()) {
                serialize(output, { "nfq", "src_iface" }, nfq.src_iface);
            }
            if (! nfq.dst_iface.empty()) {
                serialize(output, { "nfq", "dst_iface" }, nfq.dst_iface);
            }
#endif // _ND_ENABLE_NFQUEUE
            if (! dns_host_name.empty())
                serialize(output, { "dns_host_name" }, dns_host_name);

            if (! host_server_name.empty())
                serialize(output, { "host_server_name" },
                  host_server_name);

            if (HasHttpUserAgent() || HasHttpURL()) {
                if (HasHttpUserAgent())
                    serialize(output,
                      { "http", "user_agent" }, http.user_agent);
                if (HasHttpURL())
                    serialize(output, { "http", "url" },
                      http.url);
            }

            if (HasDhcpFingerprint() || HasDhcpClassIdent()) {
                if (HasDhcpFingerprint())
                    serialize(output,
                      { "dhcp", "fingerprint" }, dhcp.fingerprint);

                if (HasDhcpClassIdent())
                    serialize(output,
                      { "dhcp", "class_ident" }, dhcp.class_ident);
            }

            if (HasSSHClientAgent() || HasSSHServerAgent()) {
                if (HasSSHClientAgent())
                    serialize(output, { "ssh", "client" },
                      ssh.client_agent);

                if (HasSSHServerAgent())
                    serialize(output, { "ssh", "server" },
                      ssh.server_agent);
            }

            if (GetMasterProtocol() == ndProto::Id::TLS ||
              detected_protocol == ndProto::Id::QUIC)
            {
                char tohex[7];

                sprintf(tohex, "0x%04hx", tls.version);
                serialize(output, { "ssl", "version" }, tohex);

                sprintf(tohex, "0x%04hx", tls.cipher_suite);
                serialize(output, { "ssl", "cipher_suite" }, tohex);

                if (HasTLSClientSNI())
                    serialize(output,
                      { "ssl", "client_sni" }, host_server_name);

                if (HasTLSEncryptedCH()) {
                    sprintf(tohex, "0x%04hx", tls.ech.version);
                    serialize(output,
                      { "ssl", "encrypted_ch_version" },
                      tohex);
                }

                if (HasTLSServerCN())
                    serialize(output,
                      { "ssl", "server_cn" }, tls.server_cn);

                if (HasTLSIssuerDN())
                    serialize(output,
                      { "ssl", "issuer_dn" }, tls.issuer_dn);

                if (HasTLSSubjectDN())
                    serialize(output,
                      { "ssl", "subject_dn" }, tls.subject_dn);

                if (HasTLSClientJA4())
                    serialize(output,
                      { "ssl", "client_ja4" }, tls.client_ja4);

                if (! tls.cert_fingerprint.empty()) {
                    nd_sha1_to_string(tls.cert_fingerprint, digest);
                    serialize(output,
                      { "ssl", "fingerprint" }, digest);
                }

                if (! tls.alpn.empty())
                    serialize(output, { "ssl", "alpn" }, tls.alpn);
                if (! tls.alpn_server.empty())
                    serialize(output,
                      { "ssl", "alpn_server" }, tls.alpn_server);
            }

            if (HasBTInfoHash()) {
                nd_sha1_to_string(bt.info_hash, digest);
                serialize(output, { "bt", "info_hash" }, digest);
            }

            if (HasSSDPUserAgent()) {
                if (HasSSDPUserAgent()) {
                    serialize(output,
                      { "ssdp", "user_agent" }, http.user_agent);
                }
            }

            if (HasMDNSDomainName()) {
                serialize(output, { "mdns", "answer" },
                  mdns.domain_name);
            }

            if (HasSTUNAddress()) {
                if (stun.mapped.IsValid()) {
                    serialize(output, { "stun", "mapped" },
                      stun.mapped.GetString(ndAddr::MakeFlags::PORT));
                }
                if (stun.peer.IsValid()) {
                    serialize(output, { "stun", "peer" },
                      stun.peer.GetString(ndAddr::MakeFlags::PORT));
                }
                if (stun.relayed.IsValid()) {
                    serialize(output, { "stun", "relayed" },
                      stun.relayed.GetString(ndAddr::MakeFlags::PORT));
                }
                if (stun.response.IsValid()) {
                    serialize(output, { "stun", "response" },
                      stun.response.GetString(ndAddr::MakeFlags::PORT));
                }
                if (stun.other.IsValid()) {
                    serialize(output, { "stun", "other" },
                      stun.other.GetString(ndAddr::MakeFlags::PORT));
                }
            }

            serialize(output, { "first_seen_at" }, ts_first_seen);

            serialize(output, { "risks", "risks" }, risk.risks);
            serialize(output, { "risks", "ndpi_risk_score" },
              risk.ndpi_score);
            serialize(output,
              { "risks", "ndpi_risk_score_client" },
              risk.ndpi_score_client);
            serialize(output,
              { "risks", "ndpi_risk_score_server" },
              risk.ndpi_score_server);

            serialize(output, { "tags" }, tags);
        }

        if (ndFlagBoolean(encode_flags, EncodeFlags::TUNNELS))
        {
            std::string _lower_teid = "local_teid",
                        _upper_teid = "other_teid";

            switch (tunnel_type) {
            case TunnelType::GTP:
                switch (gtp.lower_map) {
                case LowerMap::LOCAL:
                    _lower_ip = "local_ip";
                    _lower_port = "local_port";
                    _lower_teid = "local_teid";
                    _upper_ip = "other_ip";
                    _upper_port = "other_port";
                    _upper_teid = "other_teid";
                    break;
                case LowerMap::OTHER:
                    _lower_ip = "other_ip";
                    _lower_port = "other_port";
                    _lower_teid = "other_teid";
                    _upper_ip = "local_ip";
                    _upper_port = "local_port";
                    _upper_teid = "local_teid";
                    break;
                default: break;
                }

                switch (gtp.other_type) {
                case OtherType::LOCAL:
                    _other_type = "local";
                    break;
                case OtherType::REMOTE:
                    _other_type = "remote";
                    break;
                case OtherType::ERROR:
                    _other_type = "error";
                    break;
                case OtherType::UNSUPPORTED:
                default: _other_type = "unsupported"; break;
                }

                serialize(output, { "gtp", "version" }, gtp.version);
                serialize(output, { "gtp", "ip_version" },
                  gtp.ip_version);
                serialize(output, { "gtp", "ip_dscp" }, gtp.ip_dscp);
                serialize(output, { "gtp", _lower_ip },
                  gtp.lower_addr.GetString());
                serialize(output, { "gtp", _upper_ip },
                  gtp.upper_addr.GetString());
                serialize(output, { "gtp", _lower_port },
                  (unsigned)gtp.lower_addr.GetPort());
                serialize(output, { "gtp", _upper_port },
                  (unsigned)gtp.upper_addr.GetPort());
                serialize(output, { "gtp", _lower_teid },
                  htonl(gtp.lower_teid));
                serialize(output, { "gtp", _upper_teid },
                  htonl(gtp.upper_teid));
                serialize(output, { "gtp", "other_type" },
                  _other_type);

                break;
            default: break;
            }
        }

        if (ndFlagBoolean(encode_flags, EncodeFlags::STATS)) {
            serialize(output, { _lower_bytes },
              stats.lower_bytes.load());
            serialize(output, { _upper_bytes },
              stats.upper_bytes.load());
            serialize(output, { _total_lower_bytes },
              stats.total_lower_bytes.load());
            serialize(output, { _upper_bytes },
              stats.upper_bytes.load());
            serialize(output, { _total_upper_bytes },
              stats.total_upper_bytes.load());
            serialize(output, { _lower_packets },
              stats.lower_packets.load());
            serialize(output, { _total_lower_packets },
              stats.total_lower_packets.load());
            serialize(output, { _upper_packets },
              stats.upper_packets.load());
            serialize(output, { _total_upper_packets },
              stats.total_upper_packets.load());
            serialize(output, { "total_packets" },
              stats.total_packets.load());
            serialize(output, { "total_bytes" },
              stats.total_bytes.load());
            serialize(output, { "detection_packets" },
              stats.detection_packets.load());

#ifdef _ND_ENABLE_EXTENDED_STATS
            serialize(output, { _lower_rate },
              stats.lower_rate.load());
            serialize(output, { _upper_rate },
              stats.upper_rate.load());

            if (ip_protocol == IPPROTO_TCP) {
                serialize(output,
                  { "tcp", "seq_errors" },
                  stats.tcp_seq_errors.load());
                serialize(output, { "tcp", "resets" },
                  stats.tcp_resets.load());
                serialize(output, { "tcp", "retrans" },
                  stats.tcp_retrans.load());
            }
#endif
        }
    }

    bool PushMetadataDigest(const ndDigest &digest);
};
