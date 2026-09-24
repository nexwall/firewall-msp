// Nexwall proc-flow-actions plugin
//
// Copyright (C) 2026 Nexwall. All rights reserved.
// Proprietary - not for redistribution.
//
// DPI-rule enforcement: evaluates classified flows against dpi-config's
// action criteria and writes the matching conntrack labels, which dpi-nft's
// nftables rules then block or QoS-mark on. Written against the public
// plugin ABI (nd-plugin.hpp), the engine's own flow expression parser
// (ndFlowParser) for criteria evaluation, and libnetfilter_conntrack for
// the label writes.
//
// Every enabled action is evaluated independently on each classification
// pass, not first-match-wins: "block" and "analyzed" are not mutually
// exclusive, so a flow can carry both labels at once. Each pass
// authoritatively recomputes the full label state this plugin manages
// (not just newly-matching bits), using ATTR_CONNLABELS_MASK to touch only
// those bits, so a label set by an earlier pass is correctly cleared once
// its rule stops matching, without disturbing labels this plugin doesn't
// own.
//
// DispatchProcessorEvent runs with the plugin manager's lock held, so it
// only evaluates criteria and enqueues the resulting label update; the
// netlink conntrack write happens from Entry(), this plugin's own thread.
// A conntrack entry that no longer exists by the time the write runs is
// treated as a normal, expected outcome of that queueing delay, not an
// error.

#include <arpa/inet.h>
#include <condition_variable>
#include <fstream>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "nd-flow-parser.hpp"
#include "nd-plugin.hpp"

using namespace std;
using ordered_json = nlohmann::ordered_json;

// A label bitfield is a byte array, one bit per label, matching the kernel's
// own xt_connlabel/CTA_LABELS representation (network byte order per byte,
// bit N is byte N/8 bit N%8 - same convention /etc/connlabel.conf's bit
// numbers already use).
static constexpr size_t LABEL_BYTES = 16;  // 128 bits, matches XT_CONNLABEL_MAXBIT+1 headroom

struct PendingUpdate {
    uint8_t l3proto, l4proto;
    // orig tuple, network byte order already
    struct sockaddr_storage src, dst;
    uint16_t port_src, port_dst;
    uint8_t value[LABEL_BYTES];
    uint8_t mask[LABEL_BYTES];
};

class ndPluginNxFlowActions : public ndPluginProcessor
{
public:
    ndPluginNxFlowActions(const string &tag, const ndPlugin::Params &params)
      : ndPluginProcessor(tag, params) {
        if (! GetConfiguration().empty()) LoadConfig(GetConfiguration());
        ct_handle = nfct_open(CONNTRACK, 0);
        if (ct_handle == nullptr)
            nd_printf("nx-proc-flow-actions: nfct_open failed: %s\n", strerror(errno));
    }

    virtual ~ndPluginNxFlowActions() {
        if (ct_handle != nullptr) nfct_close(ct_handle);
    }

    virtual void GetName(string &name) { name = "nx-proc-flow-actions"; }
    virtual void GetVersion(string &version) { version = "1.0.0-nexwall"; }

    virtual void *Entry(void) {
        while (! ShouldTerminate()) {
            PendingUpdate up;
            if (! PopQueue(up)) continue;
            ApplyUpdate(up);
        }
        return nullptr;
    }

    virtual void DispatchProcessorEvent(Event event, ndFlow::Ptr &flow) {
        if (! flow || ! ct_handle) return;
        if (event != Event::DPI_COMPLETE && event != Event::DPI_UPDATE) return;
        if (managed_bits.empty()) return;
        if (! parser) parser = make_unique<ndFlowParser>();

        if (IsExempt(flow, global_exemptions)) return;

        uint8_t value[LABEL_BYTES] = {0};
        uint8_t mask[LABEL_BYTES] = {0};
        // authoritatively recompute state for every bit this plugin manages
        for (int bit : managed_bits) SetBit(mask, bit);

        for (auto &action : actions) {
            if (! action.enabled) continue;
            if (IsExempt(flow, action.exemptions)) continue;

            bool matched = false;
            try {
                matched = parser->Parse(flow, action.criteria);
            }
            catch (exception &e) {
                nd_printf("nx-proc-flow-actions: bad criteria in '%s': %s\n",
                  action.name.c_str(), e.what());
                continue;
            }
            if (! matched) continue;

            for (auto &target_name : action.targets) {
                auto it = targets.find(target_name);
                if (it == targets.end() || ! it->second.enabled) continue;
                for (int bit : it->second.label_bits) SetBit(value, bit);
            }
        }

        PendingUpdate up;
        if (! BuildTuple(flow, up)) return;
        memcpy(up.value, value, LABEL_BYTES);
        memcpy(up.mask, mask, LABEL_BYTES);
        QueueUpdate(up);
    }

private:
    struct Target {
        bool enabled = false;
        vector<int> label_bits;
    };
    struct Action {
        string name;
        bool enabled = false;
        string criteria;
        vector<string> targets;
        vector<string> exemptions;
    };

    map<string, Target> targets;
    vector<Action> actions;  // in config file order (ordered_json)
    vector<string> global_exemptions;
    vector<int> managed_bits;  // every bit any enabled ctlabel target can set

    struct nfct_handle *ct_handle = nullptr;

    mutex queue_lock;
    condition_variable queue_cond;
    vector<PendingUpdate> queue;

    // Constructed lazily rather than in this plugin's own constructor:
    // ndFlowParser inherits ndInstanceClient, whose constructor accesses
    // the agent's own singleton, which is not guaranteed ready at
    // plugin-load time. By the time DispatchProcessorEvent runs, the agent
    // is fully initialized, so construction here is safe.
    unique_ptr<ndFlowParser> parser;

    static void SetBit(uint8_t *bytes, int bit) {
        if (bit < 0 || (size_t)bit >= LABEL_BYTES * 8) return;
        bytes[bit / 8] |= (1 << (bit % 8));
    }

    void LoadConfig(const string &conf_filename) {
        ifstream f(conf_filename);
        if (! f.is_open()) {
            nd_printf("nx-proc-flow-actions: could not open %s\n",
              conf_filename.c_str());
            return;
        }
        ordered_json j;
        try {
            f >> j;
        }
        catch (exception &e) {
            nd_printf("nx-proc-flow-actions: %s: %s\n",
              conf_filename.c_str(), e.what());
            return;
        }

        string connlabel_conf = "/etc/connlabel.conf";
        if (j.contains("target_globals") &&
          j["target_globals"].contains("ctlabel") &&
          j["target_globals"]["ctlabel"].contains("connlabel_conf")) {
            connlabel_conf =
              j["target_globals"]["ctlabel"]["connlabel_conf"].get<string>();
        }
        map<string, int> label_bits = LoadConnlabelConf(connlabel_conf);

        if (j.contains("targets")) {
            for (auto &item : j["targets"].items()) {
                if (item.value().value("target_type", "") != "ctlabel") continue;
                Target t;
                t.enabled = item.value().value("target_enabled", false);
                for (auto &label_name : item.value().value("labels", vector<string>{})) {
                    auto bit_it = label_bits.find(label_name);
                    if (bit_it == label_bits.end()) {
                        nd_printf("nx-proc-flow-actions: target '%s' references "
                          "unknown label '%s' (not in %s)\n",
                          item.key().c_str(), label_name.c_str(),
                          connlabel_conf.c_str());
                        continue;
                    }
                    t.label_bits.push_back(bit_it->second);
                    if (t.enabled) managed_bits.push_back(bit_it->second);
                }
                targets[item.key()] = t;
            }
        }

        if (j.contains("actions")) {
            for (auto &item : j["actions"].items()) {
                Action a;
                a.name = item.key();
                a.enabled = item.value().value("enabled", false);
                a.criteria = item.value().value("criteria", "");
                a.targets = item.value().value("targets", vector<string>{});
                a.exemptions = item.value().value("exemptions", vector<string>{});
                actions.push_back(a);
            }
        }

        global_exemptions = j.value("exemptions", vector<string>{});
    }

    // <bit> <name> per line, standard xt_connlabel/nfct format
    static map<string, int> LoadConnlabelConf(const string &path) {
        map<string, int> result;
        ifstream f(path);
        if (! f.is_open()) {
            nd_printf("nx-proc-flow-actions: could not open %s\n", path.c_str());
            return result;
        }
        string line;
        while (getline(f, line)) {
            size_t p = line.find_first_not_of(" \t");
            if (p == string::npos || line[p] == '#') continue;
            int bit;
            char name[256];
            if (sscanf(line.c_str(), "%d %255s", &bit, name) == 2)
                result[name] = bit;
        }
        return result;
    }

    // Reuses the agent's own IP/CIDR matching (the same code path "local_ip
    // == x.x.x.x/y" criteria already uses) rather than a second, separately
    // written implementation that could behave subtly differently.
    bool IsExempt(ndFlow::Ptr &flow, const vector<string> &exemptions) {
        if (exemptions.empty()) return false;
        string expr = "(";
        for (size_t i = 0; i < exemptions.size(); ++i) {
            if (i) expr += " || ";
            expr += "local_ip == " + exemptions[i] +
              " || other_ip == " + exemptions[i];
        }
        expr += ");";
        try {
            return parser->Parse(flow, expr);
        }
        catch (exception &e) {
            nd_printf("nx-proc-flow-actions: bad exemption entry: %s\n", e.what());
            return false;
        }
    }

    bool BuildTuple(ndFlow::Ptr &flow, PendingUpdate &up) {
        memset(&up, 0, sizeof(up));
        up.l3proto = (flow->ip_version == 6) ? AF_INET6 : AF_INET;
        up.l4proto = flow->ip_protocol;

        const ndAddr &src = flow->lower_addr;
        const ndAddr &dst = flow->upper_addr;
        if (! src.IsValid() || ! dst.IsValid()) return false;

        if (up.l3proto == AF_INET6) {
            auto *s6 = (struct sockaddr_in6 *)&up.src;
            auto *d6 = (struct sockaddr_in6 *)&up.dst;
            s6->sin6_family = AF_INET6;
            d6->sin6_family = AF_INET6;
            s6->sin6_addr = src.addr.in6.sin6_addr;
            d6->sin6_addr = dst.addr.in6.sin6_addr;
        }
        else {
            auto *s4 = (struct sockaddr_in *)&up.src;
            auto *d4 = (struct sockaddr_in *)&up.dst;
            s4->sin_family = AF_INET;
            d4->sin_family = AF_INET;
            s4->sin_addr = src.addr.in.sin_addr;
            d4->sin_addr = dst.addr.in.sin_addr;
        }
        // GetPort(false): raw/network byte order - GetPort()'s default
        // (byte_swap=true) returns host byte order, which conntrack netlink
        // attributes must NOT be set to (found by checking the real header,
        // not assumed).
        up.port_src = src.GetPort(false);
        up.port_dst = dst.GetPort(false);
        return true;
    }

    void QueueUpdate(const PendingUpdate &up) {
        {
            lock_guard<mutex> l(queue_lock);
            queue.push_back(up);
        }
        queue_cond.notify_one();
    }

    bool PopQueue(PendingUpdate &up) {
        unique_lock<mutex> l(queue_lock);
        queue_cond.wait_for(l, chrono::seconds(1),
          [this] { return ! queue.empty() || ShouldTerminate(); });
        if (queue.empty()) return false;
        up = queue.back();
        queue.pop_back();
        return true;
    }

    void ApplyUpdate(const PendingUpdate &up) {
        struct nf_conntrack *ct = nfct_new();
        if (ct == nullptr) {
            nd_printf("nx-proc-flow-actions: nfct_new failed\n");
            return;
        }

        nfct_set_attr_u8(ct, ATTR_ORIG_L3PROTO, up.l3proto);
        nfct_set_attr_u8(ct, ATTR_ORIG_L4PROTO, up.l4proto);
        if (up.l3proto == AF_INET6) {
            auto *s6 = (struct sockaddr_in6 *)&up.src;
            auto *d6 = (struct sockaddr_in6 *)&up.dst;
            nfct_set_attr(ct, ATTR_ORIG_IPV6_SRC, &s6->sin6_addr);
            nfct_set_attr(ct, ATTR_ORIG_IPV6_DST, &d6->sin6_addr);
        }
        else {
            auto *s4 = (struct sockaddr_in *)&up.src;
            auto *d4 = (struct sockaddr_in *)&up.dst;
            nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_SRC, s4->sin_addr.s_addr);
            nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_DST, d4->sin_addr.s_addr);
        }
        nfct_set_attr_u16(ct, ATTR_ORIG_PORT_SRC, up.port_src);
        nfct_set_attr_u16(ct, ATTR_ORIG_PORT_DST, up.port_dst);

        // ATTR_CONNLABELS/_MASK take ownership of a heap-allocated
        // nfct_bitmask object (nfct_destroy() below frees it via
        // nfct_bitmask_destroy()) - they do not copy a raw buffer, despite
        // going through the same nfct_set_attr() call as other attributes.
        struct nfct_bitmask *value_bm = nfct_bitmask_new(LABEL_BYTES * 8 - 1);
        struct nfct_bitmask *mask_bm = nfct_bitmask_new(LABEL_BYTES * 8 - 1);
        if (value_bm != nullptr && mask_bm != nullptr) {
            for (unsigned bit = 0; bit < LABEL_BYTES * 8; ++bit) {
                if (up.value[bit / 8] & (1 << (bit % 8)))
                    nfct_bitmask_set_bit(value_bm, bit);
                if (up.mask[bit / 8] & (1 << (bit % 8)))
                    nfct_bitmask_set_bit(mask_bm, bit);
            }
            nfct_set_attr(ct, ATTR_CONNLABELS, value_bm);
            nfct_set_attr(ct, ATTR_CONNLABELS_MASK, mask_bm);
        }
        else {
            if (value_bm != nullptr) nfct_bitmask_destroy(value_bm);
            if (mask_bm != nullptr) nfct_bitmask_destroy(mask_bm);
        }

        int rc = nfct_query(ct_handle, NFCT_Q_UPDATE, ct);
        if (rc == -1 && errno != ENOENT) {
            // ENOENT means the conntrack entry is already gone (expired,
            // torn down, or NATed away between classification and this
            // update) - an ordinary, expected outcome, not an error.
            nd_dprintf("nx-proc-flow-actions: conntrack update failed: %s\n",
              strerror(errno));
        }
        nfct_destroy(ct);
    }
};

ndPluginInit(ndPluginNxFlowActions)
