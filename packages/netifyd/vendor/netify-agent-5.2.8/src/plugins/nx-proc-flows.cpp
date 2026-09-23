// Nexwall proc-flows plugin
//
// Copyright (C) 2026 Nexwall
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Reimplementation of the real Netify Agent proc-core plugin (proprietary
// distribution, not buildable against this engine version - see
// msp/DPI_PLAN.md in the internal repo), against the public, documented
// plugin ABI (nd-plugin.hpp) and the agent's own ndFlow::Encode() (used
// throughout the agent's own source for exactly this purpose). Wraps each
// encoded flow in the same {"type","interface","flow":{...}} shape
// ns-flows' own parser already expects (nexwall-monitoring/flows/parser.go),
// and hands it to the sink named in this instance's own JSON config
// ("sinks": {"<name>": {"types": [...]}}), matching how the real plugin
// pair (proc-core + sink-http) was configured.

#include <fstream>
#include <unistd.h>
#include <nlohmann/json.hpp>
#include <string>

#include "nd-plugin.hpp"

using namespace std;

class ndPluginNxProcFlows : public ndPluginProcessor
{
public:
    ndPluginNxProcFlows(const string &tag, const ndPlugin::Params &params)
      : ndPluginProcessor(tag, params) {
        nd_printf("nx-proc-flows: DEBUG constructed, tag=%s, conf=%s\n",
          tag.c_str(), GetConfiguration().c_str());
        if (! GetConfiguration().empty()) LoadSinks(GetConfiguration());
        nd_printf("nx-proc-flows: DEBUG %zu sink channel(s) loaded\n",
          sink_channels.size());
        for (auto &c : sink_channels)
            nd_printf("nx-proc-flows: DEBUG   channel: %s\n", c.c_str());
    }

    virtual void GetName(string &name) { name = "nx-proc-flows"; }
    virtual void GetVersion(string &version) { version = "1.0.0-nexwall"; }

    virtual void *Entry(void) {
        // purely event-driven (DispatchProcessorEvent below), nothing to
        // poll; just wait until the agent asks this thread to terminate.
        while (! ShouldTerminate()) sleep(1);
        return nullptr;
    }

    virtual void DispatchProcessorEvent(Event event, ndFlow::Ptr &flow) {
        nd_printf("nx-proc-flows: DEBUG DispatchProcessorEvent called, "
          "event=%u, flow=%p, channels=%zu\n",
          (unsigned)event, (void *)flow.get(), sink_channels.size());
        if (sink_channels.empty() || ! flow) return;

        switch (event) {
        case Event::DPI_COMPLETE:
            nd_printf("nx-proc-flows: DEBUG DPI_COMPLETE, emitting\n");
            Emit("flow_dpi_complete", flow);
            break;
        case Event::FLOW_EXPIRE:
            nd_printf("nx-proc-flows: DEBUG FLOW_EXPIRE, emitting\n");
            Emit("flow_purge", flow);
            break;
        default: break;
        }
    }

private:
    ndPlugin::Channels sink_channels;

    void LoadSinks(const string &conf_filename) {
        ifstream f(conf_filename);
        if (! f.is_open()) {
            nd_printf("nx-proc-flows: could not open %s\n",
              conf_filename.c_str());
            return;
        }
        try {
            nlohmann::json j;
            f >> j;
            if (! j.contains("sinks")) return;
            // channel names here are the sink plugin instance tags this
            // processor forwards to (matching plugins.d [sink-*] sections);
            // "types" (stream-flows/stream-stats) is accepted but this
            // plugin only ever emits flow events, so it is not filtered on.
            for (auto &item : j["sinks"].items())
                sink_channels.insert(item.key());
        }
        catch (exception &e) {
            nd_printf("nx-proc-flows: %s: %s\n",
              conf_filename.c_str(), e.what());
        }
    }

    void Emit(const char *type, ndFlow::Ptr &flow) {
        nlohmann::json jflow;
        flow->Encode(jflow, flow->stats);

        nlohmann::json jevent;
        jevent["type"] = type;
        jevent["interface"] = flow->iface ?
            flow->iface->ifname : string();
        jevent["flow"] = jflow;

        for (auto &target : sink_channels) {
            nd_printf("nx-proc-flows: DEBUG dispatching to target=%s\n",
              target.c_str());
            try {
                ndPlugin::DispatchSinkPayload(target, {}, jevent,
                  ndPlugin::DispatchFlags::FORMAT_JSON_OBJECT);
                nd_printf("nx-proc-flows: DEBUG dispatch to %s ok\n",
                  target.c_str());
            }
            catch (exception &e) {
                nd_printf("nx-proc-flows: DEBUG dispatch to %s FAILED: %s\n",
                  target.c_str(), e.what());
            }
        }
    }
};

ndPluginInit(ndPluginNxProcFlows)
