// Netify Agent
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

#pragma once

#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

extern "C" {
    #include <libubus.h>
    #include <libubox/blobmsg.h>
    #include <libubox/blobmsg_json.h>
}

class ndUbus
{
public:
    static ndUbus *instance;
    static std::mutex instance_mutex;

    ndUbus(const std::string &path);
    ndUbus(unsigned timeout = 5, const std::string &path = "");

    virtual ~ndUbus();

    void Call(
        nlohmann::json &result,
        const std::string &path, const std::string &func, const std::string &args = "",
        unsigned ttl = 0
    );

    size_t ParseMessages(void);

    inline int GetDescriptor(void) { return ctx->sock.fd; }

    void Subscribe(const std::string &path);
    bool Subscribed(const std::string &path);
    void Resubscribe(const std::string &path);
    void Unsubscribe(uint32_t id);
    void Unsubscribe(const std::string &path);

    void Monitor(bool enable = true);

    virtual void PushEvent(const char *method, const char *event);
    virtual bool PopEvent(std::string &method, nlohmann::json &event);

protected:
    struct ubus_context *ctx;
    struct ubus_subscriber sub;
    std::unordered_map<std::string, uint32_t> subscriptions;
    std::string path;
    unsigned timeout;
    typedef std::unordered_map<std::string, std::vector<nlohmann::json>> message_map;
    message_map events;
};

class ndUbusServer : public ndUbus
{
public:
    ndUbusServer(const std::string &path = "");
};
