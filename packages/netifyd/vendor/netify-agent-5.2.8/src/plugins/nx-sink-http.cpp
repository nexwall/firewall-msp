// Nexwall sink-http plugin
//
// Copyright (C) 2026 Nexwall
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Reimplementation of the real Netify Agent sink-http plugin (proprietary
// distribution, not buildable against this engine version - see
// msp/DPI_PLAN.md in the internal repo), against the public, documented
// plugin ABI (nd-plugin.hpp). Loaded once per plugins.d [sink-*] section,
// each instance reading its own JSON config file (the same format the real
// plugin used: "channels": { "<name>": { "enable": bool, "url": "..." } }).
// Every queued payload is POSTed, as-is, to every enabled channel whose name
// is in the payload's channel set (or to every enabled channel if the
// payload names none).

#include <cstring>
#include <curl/curl.h>
#include <fstream>
#include <map>
#include <nlohmann/json.hpp>
#include <string>

#include "nd-plugin.hpp"

using namespace std;

class ndPluginNxSinkHTTP : public ndPluginSink
{
public:
    ndPluginNxSinkHTTP(const string &tag, const ndPlugin::Params &params)
      : ndPluginSink(tag, params) {
        if (! GetConfiguration().empty()) LoadChannels(GetConfiguration());
        curl = curl_easy_init();
    }

    virtual ~ndPluginNxSinkHTTP() {
        if (curl != nullptr) curl_easy_cleanup(curl);
    }

    virtual void GetName(string &name) { name = "nx-sink-http"; }
    virtual void GetVersion(string &version) { version = "1.0.0-nexwall"; }

    virtual void *Entry(void) {
        while (! ShouldTerminate()) {
            WaitOnPayloadQueue();
            ndPluginSinkPayload::Ptr payload;
            while (PopPayloadQueue(payload)) {
                if (payload) Post(payload);
            }
        }
        return nullptr;
    }

private:
    struct Channel {
        bool enable;
        string url;
    };

    map<string, Channel> channels;
    CURL *curl;

    void LoadChannels(const string &conf_filename) {
        ifstream f(conf_filename);
        if (! f.is_open()) {
            nd_printf("nx-sink-http: could not open %s\n",
              conf_filename.c_str());
            return;
        }
        try {
            nlohmann::json j;
            f >> j;
            if (! j.contains("channels")) return;
            for (auto &item : j["channels"].items()) {
                Channel c;
                c.enable = item.value().value("enable", false);
                c.url = item.value().value("url", "");
                channels[item.key()] = c;
            }
        }
        catch (exception &e) {
            nd_printf("nx-sink-http: %s: %s\n",
              conf_filename.c_str(), e.what());
        }
    }

    static size_t DiscardBody(char *, size_t size, size_t nmemb, void *) {
        return size * nmemb;
    }

    void PostTo(const string &url, const ndPluginSinkPayload::Ptr &payload) {
        if (curl == nullptr) return;

        string body;
        const void *data;
        long length;

        if (! payload->jdata.is_null()) {
            body = payload->jdata.dump();
            data = body.data();
            length = (long)body.size();
        }
        else {
            data = payload->data;
            length = (long)payload->length;
        }

        curl_easy_reset(curl);
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, length);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, DiscardBody);

        struct curl_slist *headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        CURLcode rc = curl_easy_perform(curl);
        if (rc != CURLE_OK) {
            nd_dprintf("nx-sink-http: %s: %s\n",
              url.c_str(), curl_easy_strerror(rc));
        }
        curl_slist_free_all(headers);
    }

    void Post(const ndPluginSinkPayload::Ptr &payload) {
        bool matched = false;
        for (auto &kv : channels) {
            if (! kv.second.enable) continue;
            if (! payload->channels.empty() &&
              payload->channels.find(kv.first) == payload->channels.end())
                continue;
            PostTo(kv.second.url, payload);
            matched = true;
        }
        if (! matched) {
            for (auto &kv : channels) {
                if (kv.second.enable) PostTo(kv.second.url, payload);
            }
        }
    }
};

ndPluginInit(ndPluginNxSinkHTTP)
