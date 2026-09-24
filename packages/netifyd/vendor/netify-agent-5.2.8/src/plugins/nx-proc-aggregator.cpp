// Nexwall proc-aggregator plugin
//
// Copyright (C) 2026 Nexwall. All rights reserved.
// Proprietary - not for redistribution.
//
// Batches per-flow byte/packet counters and POSTs them periodically in the
// {"log_time_end","stats":[...]} shape ns-stats' Go backend expects
// (nexwall-monitoring/stats/stats.go AggregatorPayload/AggregatorEntry) to
// the sink named in this instance's own JSON config. Written against the
// public plugin ABI (nd-plugin.hpp) and the engine's own ndFlow::Encode().
//
// DispatchProcessorEvent runs with the plugin manager's lock held, so it
// only encodes and enqueues here; the actual dispatch happens from Entry(),
// this plugin's own thread, on a timer (log_interval) or when the batch
// reaches batched_rows.

#include <chrono>
#include <condition_variable>
#include <deque>
#include <fstream>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>

#include "nd-plugin.hpp"

using namespace std;

class ndPluginNxProcAggregator : public ndPluginProcessor
{
public:
    ndPluginNxProcAggregator(const string &tag, const ndPlugin::Params &params)
      : ndPluginProcessor(tag, params) {
        if (! GetConfiguration().empty()) LoadConfig(GetConfiguration());
    }

    virtual void GetName(string &name) { name = "nx-proc-aggregator"; }
    virtual void GetVersion(string &version) { version = "1.0.0-nexwall"; }

    virtual void *Entry(void) {
        auto next_flush = chrono::steady_clock::now() +
          chrono::seconds(log_interval);

        while (! ShouldTerminate()) {
            {
                unique_lock<mutex> l(batch_lock);
                batch_cond.wait_until(l, next_flush, [this] {
                    return batch.size() >= batched_rows || ShouldTerminate();
                });
            }
            next_flush = chrono::steady_clock::now() +
              chrono::seconds(log_interval);
            Flush();
        }
        Flush();
        return nullptr;
    }

    virtual void DispatchProcessorEvent(Event event, ndFlow::Ptr &flow) {
        if (sink_channels.empty() || ! flow) return;

        switch (event) {
        case Event::DPI_COMPLETE:
        case Event::DPI_UPDATE:
        case Event::FLOW_EXPIRE:
            QueueEntry(flow);
            break;
        default: break;
        }
    }

private:
    ndPlugin::Channels sink_channels;
    mutex batch_lock;
    condition_variable batch_cond;
    deque<nlohmann::json> batch;
    unsigned batched_rows = 100;
    unsigned log_interval = 10;

    void LoadConfig(const string &conf_filename) {
        ifstream f(conf_filename);
        if (! f.is_open()) {
            nd_printf("nx-proc-aggregator: could not open %s\n",
              conf_filename.c_str());
            return;
        }
        try {
            nlohmann::json j;
            f >> j;
            if (j.contains("batched_rows"))
                batched_rows = j["batched_rows"].get<unsigned>();
            if (j.contains("log_interval"))
                log_interval = j["log_interval"].get<unsigned>();
            if (! j.contains("sinks")) return;
            // same convention as nx-proc-flows: channel names are the sink
            // plugin instance tags this processor forwards to
            for (auto &item : j["sinks"].items())
                sink_channels.insert(item.key());
        }
        catch (exception &e) {
            nd_printf("nx-proc-aggregator: %s: %s\n",
              conf_filename.c_str(), e.what());
        }
    }

    // Called with ndPluginManager's lock held by the caller - must be fast
    // and must not call back into the plugin manager (see class comment).
    void QueueEntry(ndFlow::Ptr &flow) {
        nlohmann::json jflow;
        flow->Encode(jflow, flow->stats);

        // Map to nexwall-monitoring's exact AggregatorEntry JSON field
        // names (stats/stats.go), read directly from its source rather than
        // guessed - most fields share ndFlow::Encode()'s own naming, a few
        // (Detected*, IpProtocol, IpVersion) use Go's CamelCase-derived tags.
        nlohmann::json entry;
        entry["detected_application"] = jflow.value("detected_application", 0);
        entry["detected_application_name"] =
          jflow.value("detected_application_name", "Unknown");
        entry["detected_protocol"] = jflow.value("detected_protocol", 0);
        entry["detected_protocol_name"] =
          jflow.value("detected_protocol_name", "Unknown");
        entry["digests"] = jflow.value("digest_prev", nlohmann::json::array());
        entry["interface"] = flow->iface ? flow->iface->ifname : string();
        entry["ip_protocol"] = jflow.value("ip_protocol", 0);
        entry["ip_version"] = jflow.value("ip_version", 0);
        entry["local_bytes"] = jflow.value("local_bytes", (int64_t)0);
        entry["local_ip"] = jflow.value("local_ip", "");
        entry["local_mac"] = jflow.value("local_mac", "");
        entry["local_origin"] = jflow.value("local_origin", false);
        entry["other_bytes"] = jflow.value("other_bytes", (int64_t)0);
        entry["other_ip"] = jflow.value("other_ip", "");
        entry["other_port"] = jflow.value("other_port", 0);
        entry["other_type"] = jflow.value("other_type", "");
        entry["packets"] = jflow.value("total_packets", 0);

        lock_guard<mutex> l(batch_lock);
        batch.push_back(std::move(entry));
        if (batch.size() >= batched_rows) batch_cond.notify_one();
    }

    void Flush(void) {
        deque<nlohmann::json> pending;
        {
            lock_guard<mutex> l(batch_lock);
            if (batch.empty()) return;
            pending.swap(batch);
        }

        nlohmann::json payload;
        payload["log_time_end"] = (int64_t)time(nullptr);
        payload["stats"] = nlohmann::json::array();
        for (auto &e : pending) payload["stats"].push_back(e);

        for (auto &target : sink_channels) {
            try {
                ndPlugin::DispatchSinkPayload(target, {}, payload,
                  ndPlugin::DispatchFlags::FORMAT_JSON_OBJECT);
            }
            catch (exception &e) {
                nd_printf("nx-proc-aggregator: dispatch to %s: %s\n",
                  target.c_str(), e.what());
            }
        }
    }

};

ndPluginInit(ndPluginNxProcAggregator)
