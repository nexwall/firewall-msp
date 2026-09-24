// Nexwall proc-flows plugin
//
// Copyright (C) 2026 Nexwall
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Open-source equivalent of the real Netify Agent proc-core plugin, written
// against the public plugin ABI (nd-plugin.hpp) and the engine's own
// ndFlow::Encode(). Wraps each encoded flow in the
// {"type","interface","flow":{...}} shape ns-flows' parser expects and
// hands it to the sink named in this instance's own JSON config.
//
// DispatchProcessorEvent() runs with the plugin manager's lock held, so it
// only encodes and enqueues here; calling DispatchSinkPayload() directly
// from this callback would deadlock, since that call needs the same lock
// on the same thread. The actual dispatch happens from Entry(), this
// plugin's own thread.

#include <condition_variable>
#include <deque>
#include <fstream>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>

#include "nd-plugin.hpp"

using namespace std;

class ndPluginNxProcFlows : public ndPluginProcessor
{
public:
    ndPluginNxProcFlows(const string &tag, const ndPlugin::Params &params)
      : ndPluginProcessor(tag, params) {
        if (! GetConfiguration().empty()) LoadSinks(GetConfiguration());
    }

    virtual void GetName(string &name) { name = "nx-proc-flows"; }
    virtual void GetVersion(string &version) { version = "1.0.0-nexwall"; }

    virtual void *Entry(void) {
        while (! ShouldTerminate()) {
            nlohmann::json jevent;
            if (! PopQueue(jevent)) continue;

            for (auto &target : sink_channels) {
                try {
                    ndPlugin::DispatchSinkPayload(target, {}, jevent,
                      ndPlugin::DispatchFlags::FORMAT_JSON_OBJECT);
                }
                catch (exception &e) {
                    nd_printf("nx-proc-flows: dispatch to %s: %s\n",
                      target.c_str(), e.what());
                }
            }
        }
        return nullptr;
    }

    virtual void DispatchProcessorEvent(Event event, ndFlow::Ptr &flow) {
        if (sink_channels.empty() || ! flow) return;

        switch (event) {
        case Event::DPI_COMPLETE: Queue("flow_dpi_complete", flow); break;
        case Event::FLOW_EXPIRE: Queue("flow_purge", flow); break;
        default: break;
        }
    }

private:
    ndPlugin::Channels sink_channels;
    mutex queue_lock;
    condition_variable queue_cond;
    deque<nlohmann::json> queue;

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

    // Called with ndPluginManager's lock held by the caller - must be fast
    // and must not call back into the plugin manager (see class comment).
    void Queue(const char *type, ndFlow::Ptr &flow) {
        nlohmann::json jflow;
        flow->Encode(jflow, flow->stats);

        nlohmann::json jevent;
        jevent["type"] = type;
        jevent["interface"] = flow->iface ?
            flow->iface->ifname : string();
        jevent["flow"] = jflow;

        {
            lock_guard<mutex> l(queue_lock);
            queue.push_back(std::move(jevent));
        }
        queue_cond.notify_one();
    }

    bool PopQueue(nlohmann::json &jevent) {
        unique_lock<mutex> l(queue_lock);
        queue_cond.wait_for(l, chrono::seconds(1),
          [this] { return ! queue.empty() || ShouldTerminate(); });
        if (queue.empty()) return false;
        jevent = std::move(queue.front());
        queue.pop_front();
        return true;
    }
};

ndPluginInit(ndPluginNxProcFlows)
