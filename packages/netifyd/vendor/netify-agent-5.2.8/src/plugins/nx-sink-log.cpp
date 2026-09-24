// Nexwall sink-log plugin
//
// Copyright (C) 2026 Nexwall. All rights reserved.
// Proprietary - not for redistribution.
//
// Receives batched flow stats (the same {"log_time_end","stats":[...]}
// shape nx-proc-aggregator already produces) and writes a nested
// mac -> ip -> app -> protocol -> {download,upload,packets} JSON snapshot to
// a local file, matching the format nethsec.conntrack/ns.talkers (the real
// NethSecurity "top consumers" API) expects from the real plugin's own
// output (/var/run/netifyd/aggregator-stats.json).
//
// "app" keys are the application name string (ns.talkers reads them as-is,
// with no name lookup); "proto" keys are the numeric protocol ID as a
// string (ns.talkers resolves these via netifyd --dump-protos).
// download/upload follow the LAN-perspective convention: download is bytes
// received by the local side (other_bytes), upload is bytes sent by the
// local side (local_bytes) - independent of which side initiated the flow.

#include <fstream>
#include <map>
#include <nlohmann/json.hpp>
#include <string>

#include "nd-plugin.hpp"

using namespace std;

class ndPluginNxSinkLog : public ndPluginSink
{
public:
    ndPluginNxSinkLog(const string &tag, const ndPlugin::Params &params)
      : ndPluginSink(tag, params) {
        if (! GetConfiguration().empty()) LoadConfig(GetConfiguration());
        window_start = time(nullptr);
    }

    virtual void GetName(string &name) { name = "nx-sink-log"; }
    virtual void GetVersion(string &version) { version = "1.0.0-nexwall"; }

    virtual void *Entry(void) {
        while (! ShouldTerminate()) {
            WaitOnPayloadQueue();
            ndPluginSinkPayload::Ptr payload;
            while (PopPayloadQueue(payload)) {
                if (payload) Write(payload);
            }
        }
        return nullptr;
    }

private:
    string log_path = "/var/run/netifyd";
    string log_name = "aggregator-stats";
    bool overwrite = true;
    time_t window_start;

    void LoadConfig(const string &conf_filename) {
        ifstream f(conf_filename);
        if (! f.is_open()) {
            nd_printf("nx-sink-log: could not open %s\n", conf_filename.c_str());
            return;
        }
        try {
            nlohmann::json j;
            f >> j;
            if (j.contains("channels") && j["channels"].contains("stats")) {
                auto &ch = j["channels"]["stats"];
                log_path = ch.value("log_path", log_path);
                log_name = ch.value("log_name", log_name);
                overwrite = ch.value("overwrite", overwrite);
            }
        }
        catch (exception &e) {
            nd_printf("nx-sink-log: %s: %s\n", conf_filename.c_str(), e.what());
        }
    }

    void Write(const ndPluginSinkPayload::Ptr &payload) {
        if (payload->jdata.is_null()) return;
        if (! payload->jdata.contains("stats")) return;

        nlohmann::json out;
        out["log_time_start"] = (int64_t)window_start;
        out["log_time_end"] = payload->jdata.value("log_time_end", (int64_t)time(nullptr));

        for (auto &entry : payload->jdata["stats"]) {
            string mac = entry.value("local_mac", "");
            string ip = entry.value("local_ip", "");
            string app = entry.value("detected_application_name", "Unknown");
            string proto = std::to_string(entry.value("detected_protocol", 0));
            if (mac.empty() || ip.empty()) continue;

            auto &node = out["stats"][mac][ip][app][proto];
            if (! node.is_object()) {
                node = { {"download", 0}, {"upload", 0}, {"packets", 0} };
            }
            node["download"] = node.value("download", (int64_t)0) +
              entry.value("other_bytes", (int64_t)0);
            node["upload"] = node.value("upload", (int64_t)0) +
              entry.value("local_bytes", (int64_t)0);
            node["packets"] = node.value("packets", 0) + entry.value("packets", 0);
        }

        string path = log_path + "/" + log_name + ".json";
        string tmp_path = path + ".tmp";
        ofstream f(tmp_path, ofstream::trunc);
        if (! f.is_open()) {
            nd_printf("nx-sink-log: could not write %s\n", tmp_path.c_str());
            return;
        }
        f << out.dump();
        f.close();
        // atomic replace: ns.talkers reads this file directly, never see a
        // partially-written one
        rename(tmp_path.c_str(), path.c_str());

        window_start = time(nullptr);
    }
};

ndPluginInit(ndPluginNxSinkLog)
