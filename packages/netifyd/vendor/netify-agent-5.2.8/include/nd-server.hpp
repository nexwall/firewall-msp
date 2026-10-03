// Netify Agent
// Copyright (C) 2015-2025 eGloo Incorporated
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
#include <stack>
#include <string>
#include <thread>
#include <unordered_map>

#include <nlohmann/json.hpp>

#include "nd-except.hpp"
#include "nd-socket.hpp"
#include "nd-util.hpp"

class ndServer
{
public:
    enum class CommandCode : uint16_t {
        NONE,
        STATUS,
        RELOAD,
        RESTART,
        GROUP_ADDR_ADD,
        GROUP_ADDR_DEL,
        GROUP_ADDR_FLUSH,
        GROUP_ADDR_LOOKUP,
        GROUP_ADDR_LIST,
        GROUP_ADDR_LOAD,
        GROUP_ADDR_SAVE,
        HANGUP,
    };

    enum class ResponseCode : uint16_t {
        OK = 100,
        ERROR = 500,
        PARSE_ERROR = 501,
        UNIMPLEMENTED = 502,
    };

    static ndServer& Create(void);
    static void Destroy(void);

    ndServer(const ndServer &) = delete;
    ndServer &operator=(const ndServer &) = delete;

    static inline ndServer &GetInstance() {
        if (instance == nullptr) {
            throw ndException("%s: instance not found",
              __PRETTY_FUNCTION__);
        }
        return *instance;
    }

    static inline bool IsValid(void) {
        return (instance != nullptr && skt != nullptr &&
            skt->GetDescriptor() != -1);
    }

    void Reload(const std::string &path_socket);

    static inline int GetDescriptor(void) {
        return (skt != nullptr) ? skt->GetDescriptor() : -1; }

    void CreateClientSession(void);

    virtual ~ndServer();

    const char *GetCommandCodeName(CommandCode code) const {
        static const char *name = "UNKNOWN";
        try {
            name = MapCommandCodeName.at(code).c_str();
        } catch (...) { }

        return name;
    }

protected:
    static std::unique_ptr<ndServer> instance;

    std::string path_socket;
    static std::unique_ptr<ndSocketServer> skt;

    void Close(void);

    const char *CC_NONE = { "NONE" };
    const char *CC_STATUS = { "STATUS" };
    const char *CC_RELOAD = { "RELOAD" };
    const char *CC_RESTART = { "RESTART" };
    const char *CC_GROUP_ADDR_ADD = { "GROUP_ADDR_ADD" };
    const char *CC_GROUP_ADDR_DEL = { "GROUP_ADDR_DEL" };
    const char *CC_GROUP_ADDR_FLUSH = { "GROUP_ADDR_FLUSH" };
    const char *CC_GROUP_ADDR_LOOKUP = { "GROUP_ADDR_LOOKUP" };
    const char *CC_GROUP_ADDR_LIST = { "GROUP_ADDR_LIST" };
    const char *CC_GROUP_ADDR_LOAD = { "GROUP_ADDR_LOAD" };
    const char *CC_GROUP_ADDR_SAVE = { "GROUP_ADDR_SAVE" };
    const char *CC_HANGUP = { "HANGUP" };

    const std::unordered_map<
        CommandCode, std::string, ndEnumHasher> MapCommandCodeName = {
        { CommandCode::NONE, CC_NONE },
        { CommandCode::STATUS, CC_STATUS },
        { CommandCode::RELOAD, CC_RELOAD },
        { CommandCode::RESTART, CC_RESTART },
        { CommandCode::GROUP_ADDR_ADD, CC_GROUP_ADDR_ADD },
        { CommandCode::GROUP_ADDR_DEL, CC_GROUP_ADDR_DEL },
        { CommandCode::GROUP_ADDR_FLUSH, CC_GROUP_ADDR_FLUSH },
        { CommandCode::GROUP_ADDR_LOOKUP, CC_GROUP_ADDR_LOOKUP },
        { CommandCode::GROUP_ADDR_LIST, CC_GROUP_ADDR_LIST },
        { CommandCode::GROUP_ADDR_LOAD, CC_GROUP_ADDR_LOAD },
        { CommandCode::GROUP_ADDR_SAVE, CC_GROUP_ADDR_SAVE },
        { CommandCode::HANGUP, CC_HANGUP },
    };

private:
    ndServer() { }
};

class ndServerSaxConsumer : public nlohmann::json::json_sax_t
{
public:
    std::string key_current;

    std::stack<std::string> obj_stack;
    std::stack<std::string> array_stack;

    uint64_t data_total = 0;
    uint64_t data_errors = 0;

    ndServer::CommandCode command = ndServer::CommandCode::NONE;

    std::string addr_group;

    bool null() override {
        return true;
    }

    bool boolean(bool val) override {
        return true;
    }

    bool number_integer(nlohmann::json::number_integer_t val) override;

    bool number_unsigned(nlohmann::json::number_unsigned_t val) override;

    bool number_float(
      nlohmann::json::number_float_t val, const std::string& s) override {
        return true;
    }

    bool string(std::string& val) override;

    bool start_object(std::size_t elements) override;

    bool end_object() override;

    bool start_array(std::size_t elements) override;

    bool end_array() override;

    bool key(std::string& val) override;

    bool binary(nlohmann::json::binary_t& val) override {
        return true;
    }

    bool parse_error(
      std::size_t position, const std::string& last_token,
      const nlohmann::json::exception& ex) override;
};
