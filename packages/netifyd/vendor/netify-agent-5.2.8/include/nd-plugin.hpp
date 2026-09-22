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

#include <memory>
#include <queue>
#include <set>

#include "nd-config.hpp"
#include "nd-flow.hpp"
#include "nd-flow-map.hpp"
#include "nd-packet.hpp"
#include "nd-serializer.hpp"
#include "nd-thread.hpp"
#include "nd-util.hpp"

class ndInstanceStatus;

constexpr unsigned _ND_PLUGIN_VER = 0x20230309;

#define ndPluginInit(class_name) \
    extern "C" { \
    ndPlugin *ndPluginInit(const string &tag, \
      const ndPlugin::Params &params) { \
        class_name *p = new class_name(tag, params); \
        if (p->GetType() != ndPlugin::Type::PROC && \
          p->GetType() != ndPlugin::Type::SINK) \
        { \
            nd_printf("Invalid plugin type: %s [%u]\n", \
              tag.c_str(), p->GetType()); \
            delete p; \
            return nullptr; \
        } \
        return dynamic_cast<ndPlugin *>(p); \
    } \
    }

class ndPlugin : public ndThread, public ndSerializer
{
public:
    enum class Type : uint8_t {
        BASE,
        PROC,
        SINK,
    };

    using Params = std::map<std::string, std::string>;
    using Channels = std::set<std::string>;

    ndPlugin(Type type, const std::string &tag, const Params &params);
    virtual ~ndPlugin();

    virtual void *Entry(void) = 0;

    virtual void GetLibrary(std::string &library) { library = "-"; }

    virtual void GetName(std::string &name) { name = "-"; }

    virtual void GetVersion(std::string &version) = 0;

    virtual void GetStatus(nlohmann::json &status) { }

    virtual void DisplayStatus(const nlohmann::json &status) { }

    inline const std::string &GetConfiguration(void) {
        return conf_filename;
    }

    enum class Event : uint8_t {
        RELOAD,
        STATUS_UPDATE,
    };

    virtual void
    DispatchEvent(Event event, void *param = nullptr){};

    static const std::map<ndPlugin::Type, std::string> types;

    Type GetType(void) { return type; };

    enum class DispatchFlags : uint8_t {
        NONE = 0,
        FORMAT_JSON = (1 << 0),
        FORMAT_JSON_OBJECT = (1 << 1),
        FORMAT_MSGPACK = (1 << 2),
        FORMAT_MASK = (FORMAT_JSON | FORMAT_JSON_OBJECT | FORMAT_MSGPACK),
        ADD_LF = (1 << 3),
        ADD_HEADER = (1 << 4),
        GZ_DEFLATE = (1 << 5),
    };

    static void DispatchSinkPayload(const std::string &target,
      const ndPlugin::Channels &channels, size_t length,
      const uint8_t *payload,
      ndFlags<ndPlugin::DispatchFlags> flags = DispatchFlags::NONE);

    static void DispatchSinkPayload(const std::string &target,
      const ndPlugin::Channels &channels,
      const std::vector<uint8_t> &payload,
      ndFlags<ndPlugin::DispatchFlags> flags = DispatchFlags::NONE) {
        ndPlugin::DispatchSinkPayload(target, channels,
          payload.size(), payload.data(), flags);
    }

    static void DispatchSinkPayload(const std::string &target,
      const ndPlugin::Channels &channels, const nlohmann::json &j,
      ndFlags<ndPlugin::DispatchFlags> flags = DispatchFlags::NONE);

protected:
    Type type;
    std::string conf_filename;
};

class ndPluginProcessor : public ndPlugin
{
public:
    ndPluginProcessor(const std::string &tag,
      const ndPlugin::Params &params);
    virtual ~ndPluginProcessor();

    enum class Event : uint16_t {
        NONE,

        FLOW_MAP,  // 1: ndFlowMap *
        FLOW_NEW,  // 2: ndFlow::Ptr
        FLOW_EXPIRING,  // 3: ndFlow::Ptr
        FLOW_EXPIRE,  // 4: ndFlow::Ptr
        FLOW_INTEL,  // 5: ndFlow::Ptr, nlohmann::json
        DPI_NEW,  // 6: ndFlow::Ptr
        DPI_UPDATE,  // 7: ndFlow::Ptr
        DPI_COMPLETE,  // 8: ndFlow::Ptr
        INTERFACES,  // 9: ndInterfaces
        PKT_CAPTURE_STATS,  // 10: string, ndPacketStats *
        PKT_GLOBAL_STATS,  // 11: ndPacketStats *
        UPDATE_INIT,  // 12: ndInstanceStatus *
        UPDATE_COMPLETE, // 13

        MAX
    };

    virtual void
    DispatchProcessorEvent(Event event, ndFlowMap *flow_map) { }
    virtual void
    DispatchProcessorEvent(Event event, ndFlow::Ptr &flow) { }
    virtual void
    DispatchProcessorEvent(Event event,
      ndFlow::Ptr &flow, nlohmann::json &jargs) { }
    virtual void DispatchProcessorEvent(Event event,
      ndInterface::Interfaces *interfaces) { }
    virtual void DispatchProcessorEvent(Event event,
      const std::string &iface, ndPacketStats *stats) { }
    virtual void DispatchProcessorEvent(Event event,
      ndPacketStats *stats) { }
    virtual void DispatchProcessorEvent(Event event,
      ndInstanceStatus *status) { }
    virtual void DispatchProcessorEvent(Event event) { }
};

class ndPluginSinkPayload
{
public:
    using Ptr = std::shared_ptr<ndPluginSinkPayload>;

    static Ptr Create(size_t length, const uint8_t *data,
      const ndPlugin::Channels &channels,
      ndFlags<ndPlugin::DispatchFlags> flags = ndPlugin::DispatchFlags::NONE);

    inline static Ptr Create(const Ptr &payload,
      ndFlags<ndPlugin::DispatchFlags> flags = ndPlugin::DispatchFlags::NONE) {
        return Create(payload->length, payload->data,
          payload->channels, flags);
    }

    inline static Ptr Create(const ndPluginSinkPayload *payload,
      ndFlags<ndPlugin::DispatchFlags> flags = ndPlugin::DispatchFlags::NONE) {
        return Create(payload->length, payload->data,
          payload->channels, flags);
    }

    inline static Ptr Create(const nlohmann::json &j,
      const ndPlugin::Channels &channels,
      ndFlags<ndPlugin::DispatchFlags> flags = ndPlugin::DispatchFlags::NONE) {
        if (ndFlagBoolean(flags, ndPlugin::DispatchFlags::FORMAT_JSON_OBJECT)) {
            return std::make_shared<ndPluginSinkPayload>(j, channels, flags);
        }

        std::string output;
        nd_json_to_string(j, output, ndGC_DEBUG);
        return Create(output.size(),
          (const uint8_t *)output.c_str(), channels, flags);
    }

    ndPluginSinkPayload()
      : length(0), data(nullptr),
        flags(ndPlugin::DispatchFlags::NONE) { }

    ndPluginSinkPayload(size_t length, const uint8_t *data,
      const ndPlugin::Channels &channels,
      ndFlags<ndPlugin::DispatchFlags> flags)
      : length(length), data(nullptr), channels(channels),
        flags(flags) {
        this->data = new uint8_t[length];
        memcpy(const_cast<uint8_t *>(this->data), data, length);
    }

    ndPluginSinkPayload(const nlohmann::json &jdata,
      const ndPlugin::Channels &channels,
      ndFlags<ndPlugin::DispatchFlags> flags)
      : length(0), data(nullptr), jdata(jdata), channels(channels),
        flags(flags) { }

    virtual ~ndPluginSinkPayload() {
        if (data) {
            delete[] data;
            data = nullptr;
        }
        length = 0;
    }

    size_t length;
    const uint8_t *data;
    const nlohmann::json jdata;
    ndPlugin::Channels channels;
    ndFlags<ndPlugin::DispatchFlags> flags;
};

constexpr size_t _ND_PLQ_DEFAULT_MAX_SIZE = 2097152;

class ndPluginSink : public ndPlugin
{
public:
    ndPluginSink(const std::string &tag,
      const ndPlugin::Params &params);
    virtual ~ndPluginSink();

    virtual void
    QueuePayload(const ndPluginSinkPayload::Ptr &payload);

protected:
    size_t plq_size;
    size_t plq_size_max;
    std::queue<ndPluginSinkPayload::Ptr> plq_public;
    std::queue<ndPluginSinkPayload::Ptr> plq_private;
    pthread_cond_t plq_cond;
    pthread_mutex_t plq_cond_mutex;

    size_t PullPayloadQueue(void);
    size_t WaitOnPayloadQueue(unsigned timeout = 1);

    bool PopPayloadQueue(ndPluginSinkPayload::Ptr &payload);
};

class ndPluginLoader
{
public:
    ndPluginLoader(const std::string &tag,
      const std::string &so_name, const ndPlugin::Params &params);
    virtual ~ndPluginLoader();

    inline ndPlugin *GetPlugin(void) { return plugin.get(); };
    inline const std::string &GetTag(void) { return tag; };
    inline const std::string &GetObjectName(void) {
        return so_name;
    };

protected:
    std::string tag;
    std::string so_name;
    void *so_handle;
    std::unique_ptr<ndPlugin> plugin;
};

class ndPluginManager : public ndSerializer
{
public:
    virtual ~ndPluginManager() { Destroy(); }

    void Load(ndPlugin::Type type = ndPlugin::Type::BASE,
      bool create = true);

    bool Create(ndPlugin::Type type = ndPlugin::Type::BASE);

    size_t Terminate(ndPlugin::Type type = ndPlugin::Type::BASE);

    void Destroy(ndPlugin::Type type = ndPlugin::Type::BASE);

    size_t Reap(ndPlugin::Type type = ndPlugin::Type::BASE);

    void BroadcastEvent(ndPlugin::Type type,
      ndPlugin::Event event,
      void *param = nullptr);

    void BroadcastSinkPayload(const ndPluginSinkPayload::Ptr &payload);
    bool DispatchSinkPayload(const std::string &target,
      const ndPluginSinkPayload::Ptr &payload);

    void DispatchProcessorEvent(const std::string &target,
      ndPluginProcessor::Event event, ndFlowMap *flow_map);
    void DispatchProcessorEvent(const std::string &target,
      ndPluginProcessor::Event event, ndFlow::Ptr &flow);
    void DispatchProcessorEvent(const std::string &target,
      ndPluginProcessor::Event event, ndFlow::Ptr &flow, nlohmann::json &jargs);
    void DispatchProcessorEvent(const std::string &target,
      ndPluginProcessor::Event event, ndInterface::Interfaces *interfaces);
    void DispatchProcessorEvent(const std::string &target,
      ndPluginProcessor::Event event, const std::string &iface, ndPacketStats *stats);
    void DispatchProcessorEvent(const std::string &target,
      ndPluginProcessor::Event event, ndPacketStats *stats);
    void DispatchProcessorEvent(const std::string &target,
      ndPluginProcessor::Event event, ndInstanceStatus *status);
    void DispatchProcessorEvent(const std::string &target,
      ndPluginProcessor::Event event);

    void BroadcastProcessorEvent(
      ndPluginProcessor::Event event, ndFlowMap *flow_map);
    void BroadcastProcessorEvent(
      ndPluginProcessor::Event event, ndFlow::Ptr &flow);
    void BroadcastProcessorEvent(ndPluginProcessor::Event event,
      ndFlow::Ptr &flow, nlohmann::json &jargs);
    void BroadcastProcessorEvent(ndPluginProcessor::Event event,
      ndInterface::Interfaces *interfaces);
    void BroadcastProcessorEvent(ndPluginProcessor::Event event,
      const std::string &iface, ndPacketStats *stats);
    void BroadcastProcessorEvent(
      ndPluginProcessor::Event event, ndPacketStats *stats);
    void BroadcastProcessorEvent(ndPluginProcessor::Event event,
      ndInstanceStatus *status);
    void BroadcastProcessorEvent(ndPluginProcessor::Event event);

    void Encode(nlohmann::json &output) const;

    void DisplayStatus(const nlohmann::json &status) const;

    void DumpVersions(ndPlugin::Type type = ndPlugin::Type::BASE);

protected:
    std::mutex lock;

    using PluginMap = std::map<std::string, std::unique_ptr<ndPluginLoader>>;

    PluginMap processors;
    PluginMap sinks;
};
