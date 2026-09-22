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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <array>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <ctime>
#include <thread>

#include <pthread.h>
#include <sys/select.h>

#include "nd-config.hpp"
#include "nd-instance.hpp"
#include "nd-server.hpp"
#include "nd-signal.hpp"
#include "nd-util.hpp"

using namespace std;
using json = nlohmann::json;
using json_ordered = nlohmann::ordered_json;

unique_ptr<ndServer> ndServer::instance = nullptr;
unique_ptr<ndSocketServer> ndServer::skt = nullptr;

static atomic<bool> ndServer_ClientTerminate{false};

static void ndServer_ClientResponse(FILE *hf, const json_ordered &jpayload) {
    string payload;
    nd_json_to_string(jpayload, payload, ndGC_DEBUG);

    fprintf(hf, "%s\n", payload.c_str());
    fflush(hf);
}

static void ndServer_ClientResponse(FILE *hf,
    ndServer::ResponseCode code, const string &message) {
    json_ordered j;

    j["code"] = code;
    j["message"] = message;

    ndServer_ClientResponse(hf, j);
}

static void ndServer_ClientResponse(FILE *hf,
    ndServer::ResponseCode code, const string &message, const json &jdata) {
    json_ordered j;

    j["code"] = code;
    j["message"] = message;
    j["data"] = jdata;

    ndServer_ClientResponse(hf, j);
}

static bool ndServer_ClientRequest(FILE *hf) {
    bool result = false;

    try {
        ndServerSaxConsumer ssc;

        result = json::sax_parse(
          hf, &ssc, json::input_format_t::json,
            false, // strict?
            true // ignore whitespace?
        );

        if (feof(hf) || ferror(hf)) return false;

        if (result) {
            json jdata;

            nd_dprintf("ndServer: %s\n",
              ndServer::GetInstance().GetCommandCodeName(ssc.command));

            switch (ssc.command) {
            case ndServer::CommandCode::NONE:
                ndServer_ClientResponse(hf,
                  ndServer::ResponseCode::ERROR, "No command specified.");
                break;

            case ndServer::CommandCode::STATUS:
                jdata["agent_version"] = nd_get_version_and_features();

                ndInstance::GetInstance().GetStatus().Encode(jdata);
                ndServer_ClientResponse(hf,
                  ndServer::ResponseCode::OK, "Ok.", jdata);
                break;

            case ndServer::CommandCode::RELOAD:
                ndInstance::GetInstance().SendSignal(SIGHUP);
                ndServer_ClientResponse(hf,
                  ndServer::ResponseCode::OK, "Ok.", jdata);
                break;

            case ndServer::CommandCode::RESTART:
                kill(getpid(), ND_SIG_RESTART);
                ndServer_ClientResponse(hf,
                  ndServer::ResponseCode::OK, "Bye, bye.", jdata);
                break;

            case ndServer::CommandCode::GROUP_ADDR_ADD:
            case ndServer::CommandCode::GROUP_ADDR_DEL:
                jdata["total"] = ssc.data_total;
                jdata["errors"] = ssc.data_errors;

                ndServer_ClientResponse(hf,
                  ndServer::ResponseCode::OK, "Ok.", jdata);
                break;

            case ndServer::CommandCode::GROUP_ADDR_FLUSH:
                if (ssc.addr_group.empty()) {
                    ndServer_ClientResponse(hf,
                      ndServer::ResponseCode::ERROR, "No group specified.");
                }
                else if (ndInstance::GetInstance()
                  .addr_lookup.RemoveGroup(ssc.addr_group)) {
                    ndServer_ClientResponse(hf,
                      ndServer::ResponseCode::OK, "Ok.");
                }
                else {
                    ndServer_ClientResponse(hf,
                      ndServer::ResponseCode::ERROR, "Group not found.");
                }
                break;

            case ndServer::CommandCode::GROUP_ADDR_LIST:
                break;

            case ndServer::CommandCode::GROUP_ADDR_LOAD:
                if (ssc.addr_group.empty()) {
                    ndServer_ClientResponse(hf,
                      ndServer::ResponseCode::ERROR, "No group specified.");
                }
                else {
                    string filename;
                    if (! ndInstance::GetInstance().addr_lookup
                      .GetGroupFilename(ssc.addr_group, filename)) {
                        ndServer_ClientResponse(hf,
                          ndServer::ResponseCode::ERROR,
                            "No group filename assigned."
                        );
                        break;
                    }

                    filename = ndGC.path_addr_groups + "/" + filename;
                    if (! ndInstance::GetInstance().addr_lookup
                      .LoadGroupAddress(ssc.addr_group, filename)) {
                        ndServer_ClientResponse(hf,
                          ndServer::ResponseCode::ERROR,
                            "Error loading group address(es)."
                        );
                    }
                    else {
                        ndServer_ClientResponse(hf,
                          ndServer::ResponseCode::OK,
                            "Loaded group address(es)."
                        );
                    }
                }
                break;

            case ndServer::CommandCode::GROUP_ADDR_SAVE:
                if (ssc.addr_group.empty()) {
                    ndServer_ClientResponse(hf,
                      ndServer::ResponseCode::ERROR, "No group specified.");
                }
                else {
                    string filename;
                    if (! ndInstance::GetInstance().addr_lookup
                      .GetGroupFilename(ssc.addr_group, filename)) {

                        if (! ndInstance::GetInstance().addr_lookup
                          .SetGroupFilename(ssc.addr_group)) {

                            ndServer_ClientResponse(hf,
                              ndServer::ResponseCode::ERROR,
                                "Error assigning group filename."
                            );
                            break;
                        }
                    }

                    if (! ndInstance::GetInstance().addr_lookup
                      .GetGroupFilename(ssc.addr_group, filename)) {
                        ndServer_ClientResponse(hf,
                          ndServer::ResponseCode::ERROR,
                            "No group filename assigned."
                        );
                        break;
                    }

                    filename = ndGC.path_addr_groups + "/" + filename;
                    if (! ndInstance::GetInstance().addr_lookup
                      .SaveGroupAddress(ssc.addr_group, filename)) {
                        ndServer_ClientResponse(hf,
                          ndServer::ResponseCode::ERROR,
                            "Error saving group address(es)."
                        );
                    }
                    else {
                        ndServer_ClientResponse(hf,
                          ndServer::ResponseCode::OK,
                            "Saved group address(es)."
                        );
                    }
                }
                break;

            case ndServer::CommandCode::HANGUP:
                break;

            default:
                ndServer_ClientResponse(hf,
                  ndServer::ResponseCode::UNIMPLEMENTED, "Unimplemented.");
                break;
            }
        }

    } catch (exception &e) {
        nd_dprintf("ndServer: Exception: %s\n", e.what());
        ndServer_ClientResponse(hf,
          ndServer::ResponseCode::PARSE_ERROR, e.what());
    }

    return result;
}

static void ndServer_ClientEntry(unique_ptr<ndSocket> client) {
    int rc;
    fd_set fds_read;
    int client_fd = client->GetDescriptor();

    FILE *hf = fdopen(client_fd, "a+");
    if (hf == nullptr) {
        throw ndExceptionSystemError(
          __PRETTY_FUNCTION__, "fdopen");
    }

    while (! ndServer_ClientTerminate.load()) {
        FD_ZERO(&fds_read);
        FD_SET(client_fd, &fds_read);

        struct timeval tv = { 1, 0 };

        rc = select(client_fd + 1, &fds_read, nullptr, nullptr, &tv);

        if (rc == -1) {
            throw ndExceptionSystemError(
              __PRETTY_FUNCTION__, "select");
        }

        if (rc > 0 && FD_ISSET(client_fd, &fds_read) &&
          ! ndServer_ClientRequest(hf)) break;
    }

    nd_dprintf("ndServer: Client exit.\n");
}

ndServer &ndServer::Create(void) {
    if (instance != nullptr) {
        throw ndException("%s: %s: %s", __PRETTY_FUNCTION__,
          "ndServer", strerror(EEXIST));
    }

    instance = unique_ptr<ndServer>(new ndServer);
    ndServer_ClientTerminate = false;

    return *instance;
}

void ndServer::Destroy(void) {
    if (instance == nullptr) {
        throw ndException("%s: %s: %s", __PRETTY_FUNCTION__,
          "ndServer", strerror(EINVAL));
    }

    instance.reset();
}

void ndServer::Reload(const string &path_socket) {
    if (path_socket.empty() || path_socket != this->path_socket)
        Close();

    if (! path_socket.empty() && path_socket == this->path_socket)
        return;

    try {
        if (! path_socket.empty()) {
            auto server = make_unique<ndSocketServerLocal>(path_socket);
            server->SetBlockingMode(false);
            server->SetPermissions(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
            skt = std::move(server);

            this->path_socket = path_socket;
        }
        else this->path_socket.clear();
    } catch (exception &e) {
        nd_printf("Error creating JSON API server: %s: %s (disabled)\n",
            this->path_socket.c_str(), e.what());
        this->path_socket.clear();
    }
}

void ndServer::Close() {
    if (skt != nullptr) {
        skt.reset();
    }
}

void ndServer::CreateClientSession() {
    unique_ptr<ndSocket> skt_client;

    try {
        skt_client.reset(skt->Accept());
    }
    catch (exception &e) {
        throw;
    }

    if (skt_client)
        thread(ndServer_ClientEntry, std::move(skt_client)).detach();
}

ndServer::~ndServer() {
    Close();
    ndServer_ClientTerminate = true;
}

bool ndServerSaxConsumer::number_integer(number_integer_t val) {
    if (! key_current.empty()) {
    }
    return true;
}

bool ndServerSaxConsumer::number_unsigned(number_unsigned_t val) {
    if (! key_current.empty()) {
    }
    return true;
}

bool ndServerSaxConsumer::string(string_t &val) {
    if (obj_stack.size() == 1 &&
      strcasecmp(key_current.c_str(), "command") == 0) {

        if (command != ndServer::CommandCode::NONE)
            throw ndException("command already set");

        if (strcasecmp(val.c_str(), "status") == 0)
            command = ndServer::CommandCode::STATUS;
        else if (strcasecmp(val.c_str(), "reload") == 0)
            command = ndServer::CommandCode::RELOAD;
        else if (strcasecmp(val.c_str(), "restart") == 0)
            command = ndServer::CommandCode::RESTART;
        else if (strcasecmp(val.c_str(), "add-group-address") == 0)
            command = ndServer::CommandCode::GROUP_ADDR_ADD;
        else if (strcasecmp(val.c_str(), "remove-group-address") == 0 ||
            strcasecmp(val.c_str(), "delete-group-address") == 0)
            command = ndServer::CommandCode::GROUP_ADDR_DEL;
        else if (strcasecmp(val.c_str(), "flush-address-group") == 0)
            command = ndServer::CommandCode::GROUP_ADDR_FLUSH;
        else if (strcasecmp(val.c_str(), "lookup-group-address") == 0)
            command = ndServer::CommandCode::GROUP_ADDR_LOOKUP;
        else if (strcasecmp(val.c_str(), "list-address-groups") == 0)
            command = ndServer::CommandCode::GROUP_ADDR_LIST;
        else if (strcasecmp(val.c_str(), "load-address-group") == 0)
            command = ndServer::CommandCode::GROUP_ADDR_LOAD;
        else if (strcasecmp(val.c_str(), "save-address-group") == 0)
            command = ndServer::CommandCode::GROUP_ADDR_SAVE;
        else
            throw ndException("invalid command");
    }
    else if (obj_stack.size() == 1 &&
      strcasecmp(key_current.c_str(), "group") == 0) {

        switch (command) {
        case ndServer::CommandCode::GROUP_ADDR_ADD:
        case ndServer::CommandCode::GROUP_ADDR_DEL:
        case ndServer::CommandCode::GROUP_ADDR_FLUSH:
        case ndServer::CommandCode::GROUP_ADDR_LOOKUP:
        case ndServer::CommandCode::GROUP_ADDR_LOAD:
        case ndServer::CommandCode::GROUP_ADDR_SAVE:
            addr_group = val;
            break;
        default:
            break;
        }
    }
    else if (obj_stack.size() == 1 &&
      strcasecmp(key_current.c_str(), "data") == 0) {

        if (command == ndServer::CommandCode::GROUP_ADDR_ADD) {
            if (addr_group.empty())
                throw ndException("No address group tag set");

            data_total++;
            if (! ndInstance::GetInstance()
              .addr_lookup.AddGroupAddress(addr_group, ndAddr(val)))
                data_errors++;
        }
        else if (command == ndServer::CommandCode::GROUP_ADDR_DEL) {
            if (addr_group.empty())
                throw ndException("No address group tag set");

            data_total++;
            if (! ndInstance::GetInstance()
              .addr_lookup.RemoveGroupAddress(addr_group, ndAddr(val)))
                data_errors++;
        }
    }

    return true;
}

bool ndServerSaxConsumer::start_object(std::size_t elements) {
    obj_stack.push((key_current.empty()) ? "root" : key_current);
    return true;
}

bool ndServerSaxConsumer::end_object() {
    obj_stack.pop();
    return true;
}

bool ndServerSaxConsumer::start_array(std::size_t elements) {
    array_stack.push((key_current.empty()) ? "root" : key_current);
    return true;
}

bool ndServerSaxConsumer::end_array() {
    array_stack.pop();
    return true;
}

bool ndServerSaxConsumer::key(string_t &val) {
    key_current = val;
    return true;
}

bool ndServerSaxConsumer::parse_error(
  std::size_t position, const std::string &last_token,
  const json::exception &ex) {

    if (position == 1 && last_token.empty()) {
        command = ndServer::CommandCode::HANGUP;
        return false;
    }

    throw ndException(
      "parse error at position: %u, token: %s, "
      "reason: %s",
      position, last_token.c_str(), ex.what());
}

