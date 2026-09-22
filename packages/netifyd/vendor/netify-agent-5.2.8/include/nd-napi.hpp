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

#include <unistd.h>

#include <ctime>
#include <map>
#include <memory>
#include <mutex>

#include <nlohmann/json.hpp>

#include "nd-config.hpp"
#include "nd-thread.hpp"
#include "nd-util.hpp"

namespace ndNetifyApiAuthMethod {

enum class Type : uint8_t {
    INVALID,
    HTTP_BASIC,
    HTTP_BEARER,
    MTLS,
};

namespace TypeName {

constexpr const char *INVALID = { "invalid" };
constexpr const char *HTTP_BASIC = { "basic" };
constexpr const char *HTTP_BEARER = { "bearer" };
constexpr const char *MTLS = { "mtls" };

}

const std::unordered_map<std::string, Type> MapTagType = {
    { TypeName::HTTP_BASIC, Type::HTTP_BASIC },
    { TypeName::HTTP_BEARER, Type::HTTP_BEARER },
    { TypeName::MTLS, Type::MTLS },
};

const std::unordered_map<Type, std::string, ndEnumHasher> MapTypeTag = {
    { Type::INVALID, TypeName::INVALID },
    { Type::HTTP_BASIC, TypeName::HTTP_BASIC },
    { Type::HTTP_BEARER, TypeName::HTTP_BEARER },
    { Type::MTLS, TypeName::MTLS },
};

class Base;
using Ptr = std::shared_ptr<ndNetifyApiAuthMethod::Base>;

Ptr Create(const std::string &tag, const nlohmann::json &jconfig);

class Base {
public:
    Base(Type type) : type(type) { }
    virtual ~Base() = default;

    inline Type GetType(void) const { return type; }
    inline const std::string GetTypeTag(void) const {
        return MapTypeTag.at(type);
    }

    static Type GetType(const std::string &tag) {
        auto i = MapTagType.find(tag);
        if (i == MapTagType.end()) return Type::INVALID;
        return i->second;
    }

    static const std::string GetTypeTag(Type type) {
        std::string tag;
        auto i = MapTypeTag.find(type);
        if (i != MapTypeTag.end()) tag = i->second;
        return tag;
    }

protected:
    const Type type;
};

class Token : public Base {
public:
    Token(Type type, const std::string &token)
      : Base(type), token(token) { }
    virtual ~Token() = default;

    std::string GetToken(void) { return token; }

protected:
    std::string token;
};

class mTLS : public Base {
public:
    mTLS(const std::string &cert_filename, const std::string &key_filename)
      : Base(Type::MTLS),
      cert_filename(cert_filename), key_filename(key_filename) { }
    virtual ~mTLS() = default;

    inline bool HasCAFilename(void) const { return ! ca_filename.empty(); }
    std::string GetCAFilename(void) const { return ca_filename; }
    void SetCAFilename(const std::string &ca_filename) {
        this->ca_filename = ca_filename;
    }
    std::string GetCertificateFilename(void) const { return cert_filename; }
    std::string GetKeyFilename(void) const { return key_filename; }

protected:
    std::string ca_filename;
    std::string cert_filename;
    std::string key_filename;
};

} // ndNetifyApiAuthMethod

namespace ndNetifyApiData {

enum class Type : uint8_t {
    INVALID,
    AGENT,
    INTEL,
    DEV_DISCOVERY,
};

namespace TypeName {

constexpr const char *INVALID = { "invalid" };
constexpr const char *AGENT = { "agent" };
constexpr const char *INTEL = { "intel" };
constexpr const char *DEV_DISCOVERY = { "dev-discovery" };

}

const std::unordered_map<std::string, Type> MapTagType = {
    { TypeName::AGENT, Type::AGENT },
    { TypeName::INTEL, Type::INTEL },
    { TypeName::DEV_DISCOVERY, Type::DEV_DISCOVERY },
};

const std::unordered_map<Type, std::string, ndEnumHasher> MapTypeTag = {
    { Type::INVALID, TypeName::INVALID },
    { Type::AGENT, TypeName::AGENT },
    { Type::INTEL, TypeName::INTEL },
    { Type::DEV_DISCOVERY, TypeName::DEV_DISCOVERY },
};

class Base;

using Ptr = std::shared_ptr<ndNetifyApiData::Base>;
using Urls = std::unordered_map<std::string, std::string>;

Ptr Create(
  const std::string &tag, Type type, const nlohmann::json &jconfig);

class Base {
public:
    Base(
      Type type, ndNetifyApiAuthMethod::Ptr &auth_method, const Urls &urls)
      : type(type), auth_method(auth_method), urls(urls) { }
    virtual ~Base() = default;

    inline Type GetType(void) const { return type; }
    inline const std::string GetTypeTag(void) const {
        return MapTypeTag.at(type);
    }

    static Type GetType(const std::string &tag) {
        auto i = MapTagType.find(tag);
        if (i == MapTagType.end()) return Type::INVALID;
        return i->second;
    }

    static const std::string GetTypeTag(Type type) {
        std::string tag;
        auto i = MapTypeTag.find(type);
        if (i != MapTypeTag.end()) tag = i->second;
        return tag;
    }

    ndNetifyApiAuthMethod::Ptr GetAuthMethod(void) { return auth_method; }
    std::string GetUrl(const std::string &tag) {
        std::string url;
        auto i = urls.find(tag);
        if (i != urls.end()) url = i->second;
        return url;
    }

protected:
    const Type type;
    ndNetifyApiAuthMethod::Ptr auth_method;
    Urls urls;
};

} // ndNetifyApiData

class ndNetifyApiManager;

class ndNetifyApiThread : public ndThread
{
public:
    ndNetifyApiThread(const std::string &tag,
      const ndNetifyApiAuthMethod::Ptr &auth_method = nullptr);

    virtual ~ndNetifyApiThread();

    virtual void *Entry(void) = 0;

    void AppendContent(const char *data, size_t length);

    void ParseHeader(const std::string &header_raw);

    enum class Method : uint8_t {
        GET,
        HEAD,
        POST,
    };

    typedef std::map<std::string, std::string> Headers;

protected:
    friend class ndNetifyApiManager;

    void SetAuthMethod(
      const ndNetifyApiAuthMethod::Ptr &auth_method = nullptr);

    void CreateHeaders(const Headers &headers);
    void DestroyHeaders(void);

    void Perform(
      Method method,
      const std::string &url, const std::string &payload = "");

    Headers headers_tx, headers_rx;

    std::string payload;

    std::string content;
    std::string content_type;
    std::string content_filename;

    void *curl_private = { nullptr };

    ndNetifyApiAuthMethod::Ptr auth_method;

    long GetResponseCode(void);
};

class ndNetifyApiBootstrap : public ndNetifyApiThread
{
public:
    ndNetifyApiBootstrap(
      const ndNetifyApiAuthMethod::Ptr &auth_method = nullptr)
      : ndNetifyApiThread("api-bootstrap", auth_method) { }

    virtual void *Entry(void);

protected:
    friend class ndNetifyApiManager;
};

class ndNetifyApiDownload : public ndNetifyApiThread
{
public:
    ndNetifyApiDownload(
      const ndNetifyApiAuthMethod::Ptr &auth_method,
      const std::string &url, const std::string &filename = "");

    virtual ~ndNetifyApiDownload();

    virtual void *Entry(void);

protected:
    friend class ndNetifyApiManager;

    std::string url;
    ndDigestSHA1 digest;
};

class ndNetifyApiManager
{
public:
    ndNetifyApiManager() : ttl_last_update(0) { }
    virtual ~ndNetifyApiManager() { Terminate(); }

    enum class UpdateResult : uint8_t {
        OK,
        RELOAD,
        RELOAD_BROADCAST,
        ERROR
    };

    UpdateResult Update(void);

    void Terminate(void);

    inline const nlohmann::json &GetStatus(void) const {
        return jstatus;
    }

    enum class Request : uint8_t {
        NONE,
        BOOTSTRAP,
        DOWNLOAD_APPLICATIONS,
        DOWNLOAD_CATEGORIES,
        DOWNLOAD_INTELLIGENCE,
        DOWNLOAD_OVERLAY,
    };

    const ndNetifyApiData::Ptr
      GetBootstrapData(ndNetifyApiData::Type type) const;

    inline void ForceUpdate(void) {
        ttl_last_update = 0;
        nd_dprintf("%s: forcing an update...\n", tag.c_str());
    }

protected:
    const std::string tag = { "netify-api" };
    mutable std::mutex lock;

    nlohmann::json jstatus;

    struct RequestHash {
        template <typename T>
        size_t operator()(T t) const {
            return static_cast<std::size_t>(t);
        }
    };

    using Requests = std::unordered_map<
      Request, ndNetifyApiThread *, RequestHash>;
    using Urls = std::unordered_map<Request, std::string, RequestHash>;

    Requests requests;

    Urls urls;
    ndNetifyApiData::Ptr agent_data;
    ndNetifyApiData::Ptr intel_data;

    time_t ttl_last_update;

    typedef std::unordered_map<Request, bool, RequestHash> Results;

    Results download_results;

    using BootstrapData = std::unordered_map<
      ndNetifyApiData::Type, ndNetifyApiData::Ptr>;
    BootstrapData bootstrap_data;

    UpdateResult ProcessBootstrapRequest(
      ndNetifyApiBootstrap *bootstrap);

    bool ProcessDownloadRequest(
      ndNetifyApiDownload *download, Request type);
};
