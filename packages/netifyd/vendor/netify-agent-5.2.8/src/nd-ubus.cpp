// Netify Agent 🥷
// Copyright (C) 2025 eGloo Incorporated
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

#include "nd-config.hpp"
#include "nd-except.hpp"
#include "nd-ubus.hpp"
#include "nd-util.hpp"

// #define _LOG_DEBUG 1

using namespace std;

using json = nlohmann::json;

ndUbus *ndUbus::instance = nullptr;
mutex ndUbus::instance_mutex;

static void nd_ubus_call_cb(
    struct ubus_request *req, int type, struct blob_attr *message)
{
    if (! message)
        nd_dprintf("No message data.\n");
    else {
        char *str = blobmsg_format_json(message, true);
        if (str != nullptr) {
            json *j = reinterpret_cast<json *>(req->priv);
#ifdef _LOG_DEBUG
            nd_dprintf("%s\n", str);
#endif
            *j = json::parse(str);
            free(str);
        }
    }
}

static int nd_ubus_receive_cb(
    struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method,
    struct blob_attr *message)
{
    if (! message)
        nd_dprintf("No message data.\n");
    else {
        char *str = blobmsg_format_json(message, true);
        if (str != nullptr) {
            nd_dprintf("%s: %s\n", method, str);
            ndUbus::instance->PushEvent(method, str);
            free(str);
        }
    }

    return 0;
}

static void nd_ubus_sub_remove_cb(
    struct ubus_context *ctx, struct ubus_subscriber *obj, uint32_t id)
{
    ndUbus::instance->Unsubscribe(id);
}

static char *nd_ubus_encode_monitor_data(string &method, struct blob_attr *message)
{
    int i;
    struct blob_attr *tb[UBUS_ATTR_MAX];

    static vector<struct blob_attr_info> policy;
    if (policy.size() == 0) {
        policy.insert(policy.begin(), UBUS_ATTR_MAX, { 0 });
        policy[UBUS_ATTR_DATA] = { .type = BLOB_ATTR_NESTED };
        policy[UBUS_ATTR_METHOD] = { .type = BLOB_ATTR_STRING };
    }

    blob_parse(message, tb, &policy[0], UBUS_ATTR_MAX);

    if (tb[UBUS_ATTR_METHOD] && tb[UBUS_ATTR_DATA] &&
        blobmsg_data_len(tb[UBUS_ATTR_DATA])) {

        method = (const char *)blob_data(tb[UBUS_ATTR_METHOD]);

        char *str = blobmsg_format_json(tb[UBUS_ATTR_DATA], true);

        return str;
    }

    return nullptr;
}

static void nd_ubus_monitor_cb(
    struct ubus_context *ctx, uint32_t seq, struct blob_attr *message)
{
    static vector<struct blob_attr_info> policy_hdr;

    if (policy_hdr.size() == 0) {
        policy_hdr.insert(policy_hdr.begin(), UBUS_MONITOR_MAX, { 0 });
        policy_hdr[UBUS_MONITOR_CLIENT] = { .type = BLOB_ATTR_INT32 };
        policy_hdr[UBUS_MONITOR_PEER] = { .type = BLOB_ATTR_INT32 };
        policy_hdr[UBUS_MONITOR_SEND] = { .type = BLOB_ATTR_INT8 };
        policy_hdr[UBUS_MONITOR_TYPE] = { .type = BLOB_ATTR_INT32 };
        policy_hdr[UBUS_MONITOR_DATA] = { .type = BLOB_ATTR_NESTED };
    }

    static vector<struct blob_attr_info> policy_data;

    if (policy_data.size() == 0) {
        policy_data.insert(policy_data.begin(), UBUS_ATTR_MAX, { 0 });
        policy_data[UBUS_ATTR_OBJPATH] = { .type = BLOB_ATTR_STRING };
    }

    struct blob_attr *ba_hdr[UBUS_MONITOR_MAX];

    blob_parse_untrusted(
        message, blob_raw_len(message), ba_hdr, &policy_hdr[0], UBUS_MONITOR_MAX
    );

    if (! ba_hdr[UBUS_MONITOR_CLIENT] || ! ba_hdr[UBUS_MONITOR_PEER] ||
        ! ba_hdr[UBUS_MONITOR_SEND] || ! ba_hdr[UBUS_MONITOR_TYPE] ||
        ! ba_hdr[UBUS_MONITOR_DATA]) {
        nd_dprintf("Invalid monitor message.\n");
        return;
    }
#if 0
    bool send = blob_get_int32(ba_hdr[UBUS_MONITOR_SEND]);
    uint32_t client = blob_get_int32(ba_hdr[UBUS_MONITOR_CLIENT]);
    uint32_t peer = blob_get_int32(ba_hdr[UBUS_MONITOR_PEER]);
#endif
    uint32_t type = blob_get_int32(ba_hdr[UBUS_MONITOR_TYPE]);
    struct blob_attr *data = ba_hdr[UBUS_MONITOR_DATA];

    if (type == UBUS_MSG_ADD_OBJECT) {

        struct blob_attr *ba_data[UBUS_ATTR_MAX];

        blob_parse(data, ba_data, &policy_data[0], UBUS_ATTR_MAX);

        if (ba_data[UBUS_ATTR_OBJPATH]) {
            try {
                ndUbus::instance->Resubscribe(
                    (const char *)blob_data(ba_data[UBUS_ATTR_OBJPATH])
                );
            }
            catch (ndException &e) {
                nd_printf("Failed to auto-resubscribe: %s\n", e.what());
            }
        }
    }
}

static void nd_ubus_connection_lost_cb(struct ubus_context *ctx)
{
#if 1
    nd_dprintf("TODO: Implement reconnection logic.\n");
#else
#define _ND_UBUS_RECONNECT_ATTEMPTS 10
    for (unsigned i = 0; i < _ND_UBUS_RECONNECT_ATTEMPTS; i++) {
        // TODO: Pass path, if not nullptr.
        if (ubus_reconnect(ubus_socket, nullptr) == UBUS_STATUS_OK)
            break;

        nd_printf(
            "Ubus reconnect failed (attempt #%u of %u)...\n",
            i + 1, _ND_UBUS_RECONNECT_ATTEMPTS
        );
        sleep(1);
    }
#endif
}

ndUbus::ndUbus(const string &path)
    : ctx(nullptr), sub{0}, timeout(0u), path(path)
{
    const char *ubus_socket = nullptr;

    if (path.size())
        ubus_socket = path.c_str();

    ctx = ubus_connect(ubus_socket);
    if (ctx == nullptr)
        throw ndException( "ubus_connect: %s", "Connection failed.");

    ctx->connection_lost = nd_ubus_connection_lost_cb;
}

ndUbus::ndUbus(unsigned timeout, const string &path)
    : ctx(nullptr), sub{0}, timeout(timeout), path(path)
{
    const char *ubus_socket = nullptr;

    if (path.size())
        ubus_socket = path.c_str();

    ctx = ubus_connect(ubus_socket);
    if (ctx == nullptr)
        throw ndException( "ubus_connect: %s", "Connection failed.");

    ctx->monitor_cb = nd_ubus_monitor_cb;
    ctx->connection_lost = nd_ubus_connection_lost_cb;

    int rc;
    sub.cb = nd_ubus_receive_cb;
    sub.remove_cb = nd_ubus_sub_remove_cb;

    rc = ubus_register_subscriber(ctx, &sub);

    if (rc) {
        throw ndException(
            "%s: Failed to register subscriber: %s [%d]",
            path.c_str(), ubus_strerror(rc), rc
        );
    }
}

ndUbus::~ndUbus()
{
    if (ctx) {
        ubus_free(ctx);

        ctx = nullptr;
    }
}

void ndUbus::Call(json &result,
    const string &path, const string &func, const string &args, unsigned ttl)
{
    int rc;
    uint32_t id;

    rc = ubus_lookup_id(ctx, path.c_str(), &id);

    if (rc) {
        throw ndException(
            "%s/%s: Failed to lookup ubus path: %s [%d]",
            path.c_str(), func.c_str(), ubus_strerror(rc), rc
        );
    }

    struct blob_buf buf;
    memset(&buf, 0, sizeof(buf));
    blob_buf_init(&buf, 0);

    if (! args.empty() && ! blobmsg_add_json_from_string(
        &buf, args.c_str())) {
        blob_buf_free(&buf);
        if (ndGC_DEBUG) {
            nd_dprintf("%s/%s: Failed to parse JSON argument(s):\n\"%s\"\n",
                path.c_str(), func.c_str(), args.c_str());
        }
        throw ndException("%s/%s: Failed to parse JSON argument(s)",
            path.c_str(), func.c_str());
    }

    rc = ubus_invoke(
        ctx,
        id,
        func.c_str(),
        buf.head,
        nd_ubus_call_cb,
        (void *)&result,
        (int)(((ttl > 0) ? ttl : timeout) * 1000)
    );

    blob_buf_free(&buf);

    if (rc != UBUS_STATUS_OK) {
        throw ndException(
            "%s/%s: Failed to invoke ubus call: %s [%d]",
                path.c_str(), func.c_str(), ubus_strerror(rc), rc);
    }
}

size_t ndUbus::ParseMessages(void)
{
    lock_guard<mutex> lock(instance_mutex);

    instance = this;
    ubus_handle_event(ctx);

    return events.size();
}

void ndUbus::Subscribe(const string &path)
{
    int rc;
    uint32_t id;
    rc = ubus_lookup_id(ctx, path.c_str(), &id);
    if (rc) {
        throw ndException(
            "Failed to lookup ubus path: %s: %s [%d]",
            path.c_str(), ubus_strerror(rc), rc
        );
    }

    auto it_sub = subscriptions.find(path);

    if (it_sub != subscriptions.end()) {
        if (id == it_sub->second) {
#if 0
            nd_dprintf("Already subscribed to: %s [%u]\n",
                path.c_str(), it_sub->second);
#endif
            return;
        }
        else if (it_sub->second != 0)
            Unsubscribe(path);
    }

    rc = ubus_subscribe(ctx, &sub, id);
    if (rc) {
        throw ndException(
            "Failed to subscribe to path: %s: %s [%d:%u]",
            path.c_str(), ubus_strerror(rc), rc, id
        );
    }

    subscriptions[path] = id;

    nd_dprintf("%s [%u]\n", path.c_str(), id);
}

bool ndUbus::Subscribed(const string &path)
{
    return (
        subscriptions.find(path) != subscriptions.end()
    ) ?  true : false;
}

void ndUbus::Resubscribe(const string &path)
{
    auto it_sub = subscriptions.find(path);

    if (it_sub == subscriptions.end()) return;

    Subscribe(path);
}

void ndUbus::Unsubscribe(uint32_t id)
{
    for (auto &it : subscriptions) {
        if (it.second != id) continue;
        nd_dprintf("%s [%u]\n", it.first.c_str(), id);
        subscriptions[it.first] = 0;
        break;
    }
}

void ndUbus::Unsubscribe(const string &path)
{
    auto it_sub = subscriptions.find(path);

    if (it_sub == subscriptions.end()) {
        nd_dprintf("Not subscribed to: %s\n", path.c_str());
        return;
    }

    if (it_sub->second == 0) return;

    int rc;
    rc = ubus_unsubscribe(ctx, &sub, it_sub->second);
#if _ND_DEBUG_UBUS
    if (rc) {
        nd_dprintf("Failed to unsubscribe from path: %s: %s [%d:%u]\n",
            path.c_str(), ubus_strerror(rc), rc, it_sub->second
        );
    }
#endif
    subscriptions.erase(it_sub);
}

void ndUbus::Monitor(bool enable)
{
    int rc;

    if (enable)
        rc = ubus_monitor_start(ctx);
    else
        rc = ubus_monitor_stop(ctx);

    if (rc) {
        throw ndException(
            "Failed to %s monitor mode: %s [%d]",
            (enable) ? "enable" : "disable",
            ubus_strerror(rc), rc);
    }
}

void ndUbus::PushEvent(const char *method, const char *event)
{
    json j = json::parse(event);

    message_map::iterator i = events.find(method);

    if (i != events.end())
        i->second.push_back(j);
    else {
        pair<string, vector<json>> insert(method, { j });
        events.insert(insert);
    }
}

bool ndUbus::PopEvent(string &method, json &event)
{
    auto i = events.begin();
    if (i == events.end()) return false;

    method = i->first;
    event = i->second.back();
    i->second.pop_back();

    if (i->second.empty()) events.erase(i);

    return true;
}

enum nd_ubus_methods {
    METHOD_PUBLISH,
    METHOD_HOTPLUG
};

enum nd_ubus_publish_policies {
    POLICY_PUBLISH_ARGS,

    POLICY_PUBLISH_MAX
};

static const struct blobmsg_policy nd_ubus_publish_policy[POLICY_PUBLISH_MAX] = {
    [POLICY_PUBLISH_ARGS] = {
        .name = "args",
        .type = BLOBMSG_TYPE_STRING
    },
};

enum nd_ubus_hotplug_policies {
    POLICY_HOTPLUG_ACTION,
    POLICY_HOTPLUG_DEVICE,
    POLICY_HOTPLUG_INTERFACE,

    POLICY_HOTPLUG_MAX
};

static const struct blobmsg_policy nd_ubus_hotplug_policy[POLICY_HOTPLUG_MAX] = {
    [POLICY_HOTPLUG_ACTION] = {
        .name = "action",
        .type = BLOBMSG_TYPE_STRING
    },
    [POLICY_HOTPLUG_DEVICE] = {
        .name = "device",
        .type = BLOBMSG_TYPE_STRING
    },
    [POLICY_HOTPLUG_INTERFACE] = {
        .name = "interface",
        .type = BLOBMSG_TYPE_STRING
    },
};

static blob_buf nd_ubus_blob_buffer = { 0 };

static int nd_ubus_method_cb(
    struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method,
    struct blob_attr *message)
{
    unsigned rc = 1;

    if (strncasecmp(method, "publish", 7) == 0) {
        struct blob_attr *tb[POLICY_PUBLISH_MAX];

        blobmsg_parse(
            nd_ubus_publish_policy,
            POLICY_PUBLISH_MAX, tb, blob_data(message), blob_len(message)
        );

        if (! tb[POLICY_PUBLISH_ARGS])
            return UBUS_STATUS_INVALID_ARGUMENT;

        const char *args = blobmsg_get_string(tb[POLICY_PUBLISH_ARGS]);

        if (args == nullptr)
            return UBUS_STATUS_UNKNOWN_ERROR;

        char *str = blobmsg_format_json(message, true);
        if (str != nullptr) {
            nd_dprintf("%s: %s\n", method, str);
            ndUbus::instance->PushEvent(method, str);
            free(str);
        }

        rc = 0;
    }
    else if (strncasecmp(method, "hotplug", 7) == 0) {
        struct blob_attr *tb[POLICY_HOTPLUG_MAX];

        blobmsg_parse(
            nd_ubus_hotplug_policy,
            POLICY_HOTPLUG_MAX, tb, blob_data(message), blob_len(message)
        );

        if (! tb[POLICY_HOTPLUG_ACTION])
            return UBUS_STATUS_INVALID_ARGUMENT;

        const char *action = blobmsg_get_string(tb[POLICY_HOTPLUG_ACTION]);

        if (action == nullptr)
            return UBUS_STATUS_UNKNOWN_ERROR;

        char *str = blobmsg_format_json(message, true);
        if (str != nullptr) {
            nd_dprintf("%s: %s: %s\n", method, action, str);
            ndUbus::instance->PushEvent(method, str);
            free(str);
        }

        rc = 0;
    }
    else
        nd_dprintf("Unknown method: %s\n", method);

    blob_buf_init(&nd_ubus_blob_buffer, 0);
    blobmsg_add_u32(&nd_ubus_blob_buffer, "result", rc);
    ubus_send_reply(ctx, req, nd_ubus_blob_buffer.head);

    return 0;
}

static const struct ubus_method nd_ubus_server_methods[] = {
    [METHOD_PUBLISH] = {
        .name = "publish",
        .handler = nd_ubus_method_cb,
        .mask = 0,
        .tags = 0,
        .policy = nd_ubus_publish_policy,
        .n_policy = ARRAY_SIZE(nd_ubus_publish_policy)
    },
    [METHOD_HOTPLUG] = {
        .name = "hotplug",
        .handler = nd_ubus_method_cb,
        .mask = 0,
        .tags = 0,
        .policy = nd_ubus_hotplug_policy,
        .n_policy = ARRAY_SIZE(nd_ubus_hotplug_policy)
    },
};

static struct ubus_object_type nd_ubus_server_object_type = {
    .name = PACKAGE_TARNAME,
    .id = 0,
    .methods = nd_ubus_server_methods,
    .n_methods = ARRAY_SIZE(nd_ubus_server_methods)
};

static struct ubus_object nd_ubus_server_object = {
    .avl = { 0 },
    .name = PACKAGE_TARNAME,
    .id = 0,
    .path = nullptr,
    .type = &nd_ubus_server_object_type,
    .subscribe_cb = nullptr,
    .has_subscribers = false,
    .methods = nd_ubus_server_methods,
    .n_methods = ARRAY_SIZE(nd_ubus_server_methods)
};

ndUbusServer::ndUbusServer(const string &path)
    : ndUbus(path)
{
    int rc;
    rc = ubus_add_object(ctx, &nd_ubus_server_object);
    if (rc) {
        throw ndException(
            "%s: Failed to register server object(s): %s [%d]",
            path.c_str(), ubus_strerror(rc), rc
        );
    }
}
