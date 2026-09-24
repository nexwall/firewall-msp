// Nexwall proc-flow-actions plugin
//
// Copyright (C) 2026 Nexwall. All rights reserved.
// Proprietary - not for redistribution.
//
// Reimplementation of the real Netify Agent proc-flow-actions plugin
// (internal name confirmed as "proc-nfa" from NethServer/nethsecurity issue
// #1552; proprietary distribution, not buildable against this engine
// version - see msp/DPI_PLAN.md in the internal repo), against the public,
// documented plugin ABI (nd-plugin.hpp), the agent's own built-in flow
// expression parser (ndFlowParser, src/nd-flow-parser.hpp - no expression
// parsing code needed here at all), and libnetfilter_conntrack.
//
// Config contract (netify-proc-flow-actions.json, written by dpi-config,
// original NethSecurity code, unmodified) and the real upstream design this
// mirrors (github.com/NethServer/nethsecurity PR #1520, confirmed against
// live history, not guessed) are documented in msp/DPI_PLAN.md.
//
// Every DPI_COMPLETE/DPI_UPDATE (reprocess_flows in the config), evaluates
// every enabled action's criteria against the flow (skipping it if the flow
// matches that action's own exemptions or the global ones), and - unlike a
// naive "first match wins" design - evaluates ALL actions independently and
// accumulates every matching one's ctlabel targets, because "block" and
// "analyzed" are not mutually exclusive (dpi-config's own "analyzed" action
// is meant to apply alongside whatever else matched). Each evaluation
// authoritatively recomputes the FULL label state for every label this
// plugin manages (not just newly-matching ones), using ATTR_CONNLABELS_MASK
// to touch only those bits - so a label set by an earlier, now-stale
// evaluation gets correctly cleared if its rule no longer matches, without
// disturbing labels this plugin doesn't manage at all.
//
// Threading: DispatchProcessorEvent runs with ndPluginManager's lock held
// (see nx-proc-flows in firewall-msp for the full explanation - same
// lesson, applied from the start here). ndFlowParser::Parse() is pure
// computation, safe to call directly from the callback. The actual netlink
// conntrack update is deferred to Entry(), this plugin's own thread, both
// for that reason and because of NethServer/nethsecurity issue #1552: the
// real proc-nfa plugin crashed in production, in libnetfilter_conntrack -
// keeping the write path on its own thread, simple, and defensively
// checked (never assuming a lookup/update succeeds; a conntrack entry that
// no longer exists is an ordinary, expected outcome of the queueing delay,
// not a bug) is a direct, deliberate response to that precedent, not a
// hypothetical precaution.

#include <arpa/inet.h>
#include <fstream>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <map>
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
                matched = parser.Parse(flow, action.criteria);
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
    ndFlowParser parser;

    mutex queue_lock;
    vector<PendingUpdate> queue;

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
            return parser.Parse(flow, expr);
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
        lock_guard<mutex> l(queue_lock);
        queue.push_back(up);
    }

    bool PopQueue(PendingUpdate &up) {
        lock_guard<mutex> l(queue_lock);
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
        nfct_set_attr_l(ct, ATTR_CONNLABELS, up.value, LABEL_BYTES);
        nfct_set_attr_l(ct, ATTR_CONNLABELS_MASK, up.mask, LABEL_BYTES);

        int rc = nfct_query(ct_handle, NFCT_Q_UPDATE, ct);
        if (rc == -1 && errno != ENOENT) {
            // ENOENT (entry already gone - expired, torn down, NATed away
            // between classification and this update) is an ordinary,
            // expected outcome of the queueing delay, not a bug: see the
            // class comment on NethServer/nethsecurity issue #1552.
            nd_dprintf("nx-proc-flow-actions: conntrack update failed: %s\n",
              strerror(errno));
        }
        nfct_destroy(ct);
    }
};

ndPluginInit(ndPluginNxFlowActions)
