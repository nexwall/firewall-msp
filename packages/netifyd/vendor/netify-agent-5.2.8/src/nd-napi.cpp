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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <fstream>

#include "nd-config.hpp"
#include "nd-except.hpp"
#include "nd-napi.hpp"
#include "nd-napi-curl.hpp"
#include "nd-sha1.h"
#include "nd-util.hpp"

using namespace std;
using json = nlohmann::json;

ndNetifyApiAuthMethod::Ptr ndNetifyApiAuthMethod::Create(
  const string &tag, const json &jconfig)
{
    string key = "auth";

    try {
        auto jauth = jconfig.at(key);

        key = "type";
        Type type = Token::GetType(jauth.at(key).get<string>());

        if (type == Type::HTTP_BASIC || type == Type::HTTP_BEARER) {
            key = "token";
            auto jtoken = jauth.at(key);

            shared_ptr<Token> method(new Token(type, jtoken.get<string>()));
            return static_pointer_cast<ndNetifyApiAuthMethod::Base>(method);
        }
        if (type == Type::MTLS) {
            string cert_filename, key_filename;

            auto jcert_filename = jauth.find("cert_filename");
            if (jcert_filename != jauth.end() && jcert_filename->is_string())
                cert_filename = jcert_filename->get<string>();
            else
                cert_filename = ndGC.napi_cert_file;

            auto jkey_filename = jauth.find("key_filename");
            if (jkey_filename != jauth.end() && jkey_filename->is_string())
                key_filename = jkey_filename->get<string>();
            else
                key_filename = ndGC.napi_key_file;

            if (cert_filename.empty()) {
                nd_dprintf("%s: unsupported auth method: %s is not set\n",
                    tag.c_str(), "cert_filename");
            }
            else if (key_filename.empty()) {
                nd_dprintf("%s: unsupported auth method: %s is not set\n",
                    tag.c_str(), "key_filename");
            }
            else {
                shared_ptr<mTLS> method(
                  new mTLS(cert_filename, key_filename));

                if (! ndGC.napi_ca_file.empty())
                    method->SetCAFilename(ndGC.napi_ca_file);

                return static_pointer_cast<ndNetifyApiAuthMethod::Base>(method);
            }
        }
        else {
            nd_dprintf("%s: unsupported auth method: %s\n", tag.c_str(),
                jauth.at(key).get<string>().c_str());
        }
    }
    catch (std::out_of_range &e) {
        nd_dprintf("%s: %s not found or is invalid: %s\n",
            tag.c_str(), key.c_str(), e.what());
    }
    catch (json::exception &e) {
        nd_dprintf("%s: %s not found or is invalid: %s\n",
            tag.c_str(), key.c_str(), e.what());
    }

    return nullptr;
}

ndNetifyApiData::Ptr ndNetifyApiData::Create(
  const string &tag, Type type, const json &jconfig)
{
    if (type == Type::INVALID) return nullptr;

    ndNetifyApiAuthMethod::Ptr auth_method =
        ndNetifyApiAuthMethod::Create(tag, jconfig);

    Urls urls;
    for (auto &i : jconfig.items()) {
        auto p = i.key().find_first_of("_");
        if (p == string::npos) continue;

        auto prefix = i.key().substr(0, p);
        if (prefix != "url") continue;

        urls.emplace(
          make_pair(
            i.key().substr(p + 1), i.value().get<string>()
          )
        );
    }

    return Ptr(new Base(type, auth_method, urls));
}

static int ndNetifyApiThread_curl_debug(
  CURL *ch __attribute__((unused)),
  curl_infotype type, char *data, size_t size, void *param)
{
    if (! ndGC_DEBUG_CURL) return 0;

    string buffer;
    ndThread *thread = reinterpret_cast<ndThread *>(param);

    switch (type) {
    case CURLINFO_TEXT:
        buffer.assign(data, size);
        nd_dprintf("%s: %s", thread->GetTag().c_str(),
          buffer.c_str());
        break;
    case CURLINFO_HEADER_IN:
        buffer.assign(data, size);
        nd_dprintf("%s: <-- %s", thread->GetTag().c_str(),
          buffer.c_str());
        break;
    case CURLINFO_HEADER_OUT:
        buffer.assign(data, size);
        nd_dprintf("%s: --> %s", thread->GetTag().c_str(),
          buffer.c_str());
        break;
    case CURLINFO_DATA_IN:
        nd_dprintf("%s: <-- %lu data bytes\n",
          thread->GetTag().c_str(), size);
        break;
    case CURLINFO_DATA_OUT:
        nd_dprintf("%s: --> %lu data bytes\n",
          thread->GetTag().c_str(), size);
        break;
    case CURLINFO_SSL_DATA_IN:
        nd_dprintf("%s: <-- %lu SSL bytes\n",
          thread->GetTag().c_str(), size);
        break;
    case CURLINFO_SSL_DATA_OUT:
        nd_dprintf("%s: --> %lu SSL bytes\n",
          thread->GetTag().c_str(), size);
        break;
    default: break;
    }

    return 0;
}

static size_t ndNetifyApiThread_read_data(char *data,
  size_t size, size_t nmemb, void *user) {
    size_t length = size * nmemb;
    ndNetifyApiThread *thread_napi =
      reinterpret_cast<ndNetifyApiThread *>(user);

    thread_napi->AppendContent((const char *)data, length);

    return length;
}

static size_t ndNetifyApiThread_parse_header(char *data,
  size_t size, size_t nmemb, void *user) {
    size_t length = size * nmemb;

    if (size != 1 || length == 0) return 0;

    ndNetifyApiThread *thread_napi =
      reinterpret_cast<ndNetifyApiThread *>(user);

    string header_data;
    header_data.assign(data, length);

    thread_napi->ParseHeader(header_data);

    return length;
}

#if (LIBCURL_VERSION_NUM < 0x073200)
static int ndNetifyApiThread_progress(void *user,
  double dltotal __attribute__((unused)),
  double dlnow __attribute__((unused)),
  double ultotal __attribute__((unused)),
  double ulnow __attribute__((unused)))
#else
static int ndNetifyApiThread_progress(void *user,
  curl_off_t dltotal __attribute__((unused)),
  curl_off_t dlnow __attribute__((unused)),
  curl_off_t ultotal __attribute__((unused)),
  curl_off_t ulnow __attribute__((unused)))
#endif
{
    ndNetifyApiThread *thread_napi =
      reinterpret_cast<ndNetifyApiThread *>(user);

    if (thread_napi->ShouldTerminate()) return 1;

    return 0;
}

ndNetifyApiCurl::ndNetifyApiCurl() {
    if ((ch = curl_easy_init()) == nullptr) {
        throw ndException(__PRETTY_FUNCTION__,
          "curl_easy_init");
    }

    curl_easy_setopt(ch, CURLOPT_MAXREDIRS, 3);
    curl_easy_setopt(ch, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(ch, CURLOPT_CONNECTTIMEOUT, 20);
    curl_easy_setopt(ch, CURLOPT_TIMEOUT, 60);
    curl_easy_setopt(ch, CURLOPT_NOSIGNAL, 1);

    curl_easy_setopt(ch, CURLOPT_SSL_VERIFYPEER, ndGC.napi_tls_verify);
    curl_easy_setopt(ch, CURLOPT_SSL_VERIFYHOST, (ndGC.napi_tls_verify) ? 2 : 0);
    // curl_easy_setopt(ch, CURLOPT_SSLVERSION,
    // CURL_SSLVERSION_TLSv1);

#ifdef _ND_WITH_LIBCURL_ZLIB
#if (LIBCURL_VERSION_NUM >= 0x072106)
    curl_easy_setopt(ch, CURLOPT_ACCEPT_ENCODING, "gzip");
#endif
#endif  // _ND_WITH_LIBCURL_ZLIB
}

ndNetifyApiCurl::~ndNetifyApiCurl() {
    if (ch != nullptr) {
        curl_easy_cleanup(ch);
        ch = nullptr;
    }
}

ndNetifyApiThread::ndNetifyApiThread(
  const string &tag, const ndNetifyApiAuthMethod::Ptr &auth_method)
  : ndThread(tag)
{
    curl_private = static_cast<void *>(new ndNetifyApiCurl);

    curl_easy_setopt(ndCurl->ch, CURLOPT_WRITEFUNCTION,
      ndNetifyApiThread_read_data);
    curl_easy_setopt(ndCurl->ch, CURLOPT_WRITEDATA,
      static_cast<void *>(this));

    curl_easy_setopt(ndCurl->ch, CURLOPT_HEADERFUNCTION,
      ndNetifyApiThread_parse_header);
    curl_easy_setopt(ndCurl->ch, CURLOPT_HEADERDATA,
      static_cast<void *>(this));

    curl_easy_setopt(ndCurl->ch, CURLOPT_NOPROGRESS, 0);
#if (LIBCURL_VERSION_NUM < 0x073200)
    curl_easy_setopt(ndCurl->ch, CURLOPT_PROGRESSFUNCTION,
      ndNetifyApiThread_progress);
    curl_easy_setopt(ndCurl->ch, CURLOPT_PROGRESSDATA,
      static_cast<void *>(this));
#else
    curl_easy_setopt(ndCurl->ch, CURLOPT_XFERINFOFUNCTION,
      ndNetifyApiThread_progress);
    curl_easy_setopt(ndCurl->ch, CURLOPT_XFERINFODATA,
      static_cast<void *>(this));
#endif
    if (ndGC_DEBUG_CURL) {
        curl_easy_setopt(ndCurl->ch, CURLOPT_VERBOSE, 1);
        curl_easy_setopt(ndCurl->ch, CURLOPT_DEBUGFUNCTION,
          ndNetifyApiThread_curl_debug);
        curl_easy_setopt(ndCurl->ch, CURLOPT_DEBUGDATA,
          static_cast<void *>(this));
    }

    SetAuthMethod(auth_method);
}

ndNetifyApiThread::~ndNetifyApiThread() {

    Terminate();
    Join();

    DestroyHeaders();

    if (curl_private != nullptr) {
        delete ndCurl;
        curl_private = nullptr;
    }
}

void ndNetifyApiThread::AppendContent(const char *data,
  size_t length) {
    if (content_filename.empty())
        content.append(data, length);
    else {
        ofstream ofs(content_filename, ofstream::app);
        if (! ofs.is_open()) {
            throw ndException("%s: %s: %s", __PRETTY_FUNCTION__,
              content_filename.c_str(), strerror(EINVAL));
        }

        string buffer;
        buffer.assign(data, length);
        ofs << buffer;
    }
}

void ndNetifyApiThread::ParseHeader(const string &header_raw) {
    string key, value;
    size_t p = string::npos;
    if ((p = header_raw.find_first_of(":")) != string::npos) {
        key = header_raw.substr(0, p);
        value = header_raw.substr(p + 1);
    }

    if (! key.empty() && ! value.empty()) {
        transform(key.begin(), key.end(), key.begin(),
          [](unsigned char c) { return tolower(c); });

        nd_trim(key);
        nd_trim(value);

        if (headers_rx.find(key) == headers_rx.end()) {
            headers_rx[key] = value;
            if (ndGC_DEBUG_CURL) {
                nd_dprintf("%s: header: %s: %s\n",
                  tag.c_str(), key.c_str(), value.c_str());
            }
        }
    }
}

void ndNetifyApiThread::SetAuthMethod(
    const ndNetifyApiAuthMethod::Ptr &auth_method) {

    if (auth_method != this->auth_method)
        this->auth_method = auth_method;

    if (auth_method) {
        ndNetifyApiAuthMethod::Type type = auth_method->GetType();

        if (type == ndNetifyApiAuthMethod::Type::HTTP_BASIC ||
          type == ndNetifyApiAuthMethod::Type::HTTP_BEARER) {

            ndNetifyApiAuthMethod::Token *token =
              static_cast<ndNetifyApiAuthMethod::Token *>(
                auth_method.get()
              );

            string credentials(
              (type == ndNetifyApiAuthMethod::Type::HTTP_BASIC) ?
                "Basic " : "Bearer ");
            credentials.append(token->GetToken());

            headers_tx.insert(make_pair("Authorization", credentials));
        }
        else if (type == ndNetifyApiAuthMethod::Type::MTLS) {
            ndNetifyApiAuthMethod::mTLS *mtls =
              static_cast<ndNetifyApiAuthMethod::mTLS *>(
                auth_method.get()
              );

            if (mtls->HasCAFilename()) {
                curl_easy_setopt(ndCurl->ch, CURLOPT_CAINFO,
                  mtls->GetCAFilename().c_str());
            }

            curl_easy_setopt(ndCurl->ch, CURLOPT_SSLCERT,
              mtls->GetCertificateFilename().c_str());
            curl_easy_setopt(ndCurl->ch, CURLOPT_SSLKEY,
              mtls->GetKeyFilename().c_str());

            // Force strict verification when mTLS is enabled
            curl_easy_setopt(ndCurl->ch, CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(ndCurl->ch, CURLOPT_SSL_VERIFYHOST, 2L);
        }
    }
}

void ndNetifyApiThread::CreateHeaders(const Headers &headers) {
    DestroyHeaders();

    string header("User-Agent: ");
    header.append(nd_get_version_and_features());
    ndCurl->headers_tx = curl_slist_append(ndCurl->headers_tx, header.c_str());

    header = "X-Vendor-ID: ";
    header.append(ndGC.napi_vendor.c_str());
    ndCurl->headers_tx = curl_slist_append(ndCurl->headers_tx, header.c_str());

    for (auto &h : headers) {
        header = h.first;
        header.append(": ");
        header.append(h.second);
        ndCurl->headers_tx = curl_slist_append(ndCurl->headers_tx, header.c_str());
    }

    curl_easy_setopt(ndCurl->ch, CURLOPT_HTTPHEADER, ndCurl->headers_tx);
}

void ndNetifyApiThread::DestroyHeaders(void) {
    if (ndCurl->headers_tx != nullptr) {
        curl_slist_free_all(ndCurl->headers_tx);
        ndCurl->headers_tx = nullptr;
    }
}

void ndNetifyApiThread::Perform(
 Method method, const string &url, const string &payload)
{
    ndCurl->curl_rc = CURLE_OK;
    curl_easy_setopt(ndCurl->ch, CURLOPT_URL, url.c_str());

    ndCurl->http_rc = -1;
    content.clear();
    headers_rx.clear();

    CreateHeaders(headers_tx);

    curl_easy_setopt(ndCurl->ch, CURLOPT_NOBODY, 0);

    switch (method) {
    case Method::GET:
        curl_easy_setopt(ndCurl->ch, CURLOPT_POST, 0);
        nd_dprintf("%s: %s: %s\n", tag.c_str(), "GET", url.c_str());
        break;
    case Method::HEAD:
        curl_easy_setopt(ndCurl->ch, CURLOPT_POST, 0);
        curl_easy_setopt(ndCurl->ch, CURLOPT_NOBODY, 1);

        nd_dprintf("%s: %s: %s\n", tag.c_str(), "HEAD",
          url.c_str());
        break;
    case Method::POST:
        curl_easy_setopt(ndCurl->ch, CURLOPT_POST, 1);
        curl_easy_setopt(ndCurl->ch, CURLOPT_POSTFIELDSIZE, payload.size());
        if (payload.size()) {
            curl_easy_setopt(ndCurl->ch, CURLOPT_POSTFIELDS,
              payload.c_str());
        }

        nd_dprintf("%s: %s: %s: %u byte(s)\n", tag.c_str(),
          "POST", url.c_str(), payload.size());
        break;
    }

    if ((ndCurl->curl_rc = curl_easy_perform(ndCurl->ch)) != CURLE_OK) {
        throw ndException("%s [%d]",
          curl_easy_strerror(ndCurl->curl_rc), ndCurl->curl_rc);
    }

    if ((ndCurl->curl_rc = curl_easy_getinfo(ndCurl->ch,
           CURLINFO_RESPONSE_CODE, &ndCurl->http_rc)) != CURLE_OK) {
        throw ndException("%s [%d]",
          curl_easy_strerror(ndCurl->curl_rc), ndCurl->curl_rc);
    }

    char *ct = nullptr;
    curl_easy_getinfo(ndCurl->ch, CURLINFO_CONTENT_TYPE, &ct);
    if (ct != nullptr) content_type = ct;
    else {
        auto i = headers_rx.find("content-type");
        if (i == headers_rx.end()) content_type.clear();
        else {
            content_type = i->second;
        }
    }
}

long ndNetifyApiThread::GetResponseCode(void) {
    return (curl_private) ? ndCurl->http_rc : -1L;
}

void *ndNetifyApiBootstrap::Entry(void) {

    static map<ndUUID, string> uuids = {
        { ndUUID::AGENT, "X-UUID" },
        { ndUUID::SERIAL, "X-UUID-Serial" },
        { ndUUID::SITE, "X-UUID-Site" }
    };

    for (auto &uuid : uuids) {
        string value("-");

        if (! ndGC.LoadUUID(uuid.first, value)) {
            nd_dprintf("%s: no UUID set for: %s\n",
              tag.c_str(), uuid.second.c_str());
        }
        headers_tx.insert(make_pair(uuid.second, value));
    }

    string url = ndGC.url_napi_bootstrap;
    string payload;

    try {
        string license;
        nd_file_load(ndGC.path_state_persistent + "/license.json", license);

        if (! license.empty()) {
            json jlicense = json::parse(license);

            json jpayload;
            jpayload["license"] = jlicense;
            nd_json_to_string(jpayload, payload);

            headers_tx.insert(make_pair("Content-type", "application/json"));
        }
    }
    catch (exception &e) {
        nd_dprintf("%s: error creating bootstrap payload: license: %s\n",
          tag.c_str(), e.what());
    }

    try {
        Perform(ndNetifyApiThread::Method::POST, url, payload);
    }
    catch (ndException &e) {
        nd_dprintf("%s: bootstrap request error: %s\n",
          tag.c_str(), e.what());
    }

    return nullptr;
}

ndNetifyApiDownload::ndNetifyApiDownload(
  const ndNetifyApiAuthMethod::Ptr &auth_method,
  const string &url, const string &filename)
  : ndNetifyApiThread("api-download", auth_method), url(url)
{
    if (! filename.empty()) {
        nd_sha1_file(filename, digest);
        nd_basename(filename, tag);
    }
}

ndNetifyApiDownload::~ndNetifyApiDownload() {
    if (! content_filename.empty())
        unlink(content_filename.c_str());
}

void *ndNetifyApiDownload::Entry(void) {
    nd_tmpfile("/tmp/nd-napi", content_filename);

    try {
        Perform(ndNetifyApiThread::Method::HEAD, url);

        if (ndCurl->http_rc == 200) {
            auto hdr_sha1 = headers_rx.find("x-sha1-hash");
            if (hdr_sha1 == headers_rx.end()) {
                nd_dprintf(
                  "%s: no SHA1 hash found in headers, can't compare.\n",
                  tag.c_str());

                Perform(ndNetifyApiThread::Method::GET, url);
            }
            else {
                string old_hash;
                nd_sha1_to_string(digest, old_hash);

                if (old_hash == hdr_sha1->second) {
                    nd_dprintf(
                      "%s: file has not changed.\n", tag.c_str());
                    ndCurl->http_rc = 304;
                    content = "{\"status_code\":304, "
                      "\"status_message\":\"Not modified\"}";
                }
                else {
                    nd_dprintf(
                      "%s: file has changed, downloading update...\n",
                      tag.c_str());
                    Perform(ndNetifyApiThread::Method::GET, url);
                }
            }
        }
    }
    catch (ndException &e) {
        nd_dprintf("%s: download request error: %s\n",
          tag.c_str(), e.what());
    }

    return nullptr;
}

ndNetifyApiManager::UpdateResult ndNetifyApiManager::Update(void) {
    UpdateResult result = UpdateResult::OK;
    auto request = requests.find(Request::BOOTSTRAP);

    if (request != requests.end()) {
        ndNetifyApiBootstrap *bootstrap =
          static_cast<ndNetifyApiBootstrap *>(request->second);

        if (bootstrap->HasTerminated()) {
            result = ProcessBootstrapRequest(bootstrap);

            requests.erase(request);
            delete bootstrap;
        }
    }
    else {
        ndNetifyApiAuthMethod::Ptr auth_method = nullptr;

        if (ndGC.napi_mtls_enable) {
            shared_ptr<ndNetifyApiAuthMethod::mTLS> mtls(
              new ndNetifyApiAuthMethod::mTLS(
                ndGC.napi_cert_file, ndGC.napi_key_file.c_str()
              )
            );

            if (! ndGC.napi_ca_file.empty())
                mtls->SetCAFilename(ndGC.napi_ca_file);

            auth_method =
              static_pointer_cast<ndNetifyApiAuthMethod::Base>(mtls);
        }

        ndNetifyApiBootstrap *bootstrap =
          new ndNetifyApiBootstrap(auth_method);

        auto request = requests.insert(
          make_pair(Request::BOOTSTRAP, bootstrap));

        if (request.second != true) delete bootstrap;
        else {
            try {
                request.first->second->Create();
            }
            catch (exception &e) {
                nd_printf(
                  "%s: Error creating bootstrap request: %s\n",
                  tag.c_str(), e.what());
                delete bootstrap;
                requests.erase(request.first);
            }
        }
    }

    size_t downloads = 0;
    static const vector<Request> types = {
        Request::DOWNLOAD_APPLICATIONS,
        Request::DOWNLOAD_CATEGORIES,
        Request::DOWNLOAD_INTELLIGENCE,
        Request::DOWNLOAD_OVERLAY,
    };

    for (auto &type : types) {
        auto request = requests.find(type);

        if (request != requests.end()) {
            downloads++;
            ndNetifyApiDownload *download =
              static_cast<ndNetifyApiDownload *>(request->second);

            if (download->HasTerminated()) {
                download_results[type] =
                  ProcessDownloadRequest(download, type);

                requests.erase(request);
                delete download;
            }
        }
    }

    if (downloads == 0 && download_results.size()) {
        bool reload = false;
        size_t successful = 0;

        for (auto &r : download_results) {
            if (! r.second) continue;
            reload = true;
            successful++;
        }

        nd_dprintf("%s: %lu of %lu download(s) successful.\n",
          tag.c_str(), successful, download_results.size());

        download_results.clear();

        if (reload && result == UpdateResult::OK)
            result = UpdateResult::RELOAD;

        return result;
    }

    if (agent_data) {
        time_t now = nd_time_monotonic();

        if (downloads == 0 &&
          (ttl_last_update == 0 ||
            now > (ttl_last_update + ndGC.ttl_napi_update)))
        {
            ttl_last_update = now;

            for (auto &url : urls) {
                string filename;
                ndNetifyApiAuthMethod::Ptr auth_method;

                if (url.first == Request::DOWNLOAD_APPLICATIONS) {
                    filename = ndGC.path_app_config;
                    auth_method = agent_data->GetAuthMethod();
                }
                else if (url.first == Request::DOWNLOAD_CATEGORIES) {
                    filename = ndGC.path_cat_config;
                    auth_method = agent_data->GetAuthMethod();
                }
                else if (url.first == Request::DOWNLOAD_OVERLAY) {
                    filename = ndGC.path_overlay_config;
                    auth_method = agent_data->GetAuthMethod();
                }
                else if (url.first == Request::DOWNLOAD_INTELLIGENCE) {
                    filename = ndGC.path_intel_config;
                    auth_method = intel_data->GetAuthMethod();
                }

                ndNetifyApiDownload *download = new ndNetifyApiDownload(
                  auth_method, url.second, filename);

                auto request = requests.insert(
                  make_pair(url.first, download));

                if (request.second != true) delete download;
                else {
                    try {
                        request.first->second->Create();
                    }
                    catch (exception &e) {
                        nd_printf(
                          "%s: Error creating download request: %s\n",
                          tag.c_str(), e.what());
                        delete download;
                        requests.erase(request.first);
                    }
                }
            }
        }
    }

    return result;
}

void ndNetifyApiManager::Terminate(void) {
    for (auto &request : requests)
        request.second->Terminate();
    for (auto &request : requests) delete request.second;
    requests.clear();
}

const ndNetifyApiData::Ptr ndNetifyApiManager::GetBootstrapData(
  ndNetifyApiData::Type type) const
{
    unique_lock<mutex> ul(lock);

    const auto data = bootstrap_data.find(type);
    if (data == bootstrap_data.end())
        return nullptr;

    return data->second;
}

ndNetifyApiManager::UpdateResult
  ndNetifyApiManager::ProcessBootstrapRequest(
    ndNetifyApiBootstrap *bootstrap)
{
    jstatus["bootstrap"]["code"] = -1;
    jstatus["bootstrap"]["last_update"] = time(nullptr);

    if (ndCurlParent(bootstrap)->curl_rc != CURLE_OK) {
        jstatus["bootstrap"]["message"] = curl_easy_strerror(
          ndCurlParent(bootstrap)->curl_rc);
        return UpdateResult::ERROR;
    }
    else {
        jstatus["bootstrap"]["message"] = "Unknown result";
    }

    if (ndCurlParent(bootstrap)->http_rc == 0) {
        jstatus["bootstrap"]["code"] = -1;
        jstatus["bootstrap"]["message"] = "Request failure";
        nd_printf("%s: Bootstrap request failed.\n", tag.c_str());
        return UpdateResult::ERROR;
    }

    if (bootstrap->content.length() == 0) {
        jstatus["bootstrap"]["code"] = -1;
        jstatus["bootstrap"]["message"] = "Empty response";
        nd_printf("%s: Empty bootstrap content.\n", tag.c_str());
        return UpdateResult::ERROR;
    }

    if (bootstrap->content_type != "application/json") {
        jstatus["bootstrap"]["code"] = -1;
        jstatus["bootstrap"]["message"] =
          "Invalid content type";
        nd_printf("%s: Invalid bootstrap content type.\n", tag.c_str());
        return UpdateResult::ERROR;
    }

    try {
        json content = json::parse(bootstrap->content);

        int code = -1;
        string message("Unknown");

        static const vector<string> status_codes = {
            "status_"
            "code",
            "resp_code"
        };

        for (auto &key : status_codes) {
            auto ji = content.find(key);
            if (ji != content.end() &&
              (ji->type() == json::value_t::number_integer ||
                ji->type() == json::value_t::number_unsigned))
            {
                code = ji->get<int>();
                break;
            }
        }

        static const vector<string> status_messages = {
            "status_message", "resp_message"
        };

        for (auto &key : status_messages) {
            auto ji = content.find(key);
            if (ji != content.end() &&
              ji->type() == json::value_t::string)
            {
                message = ji->get<string>();
                break;
            }
        }

        nd_rtrim(message, '.');
        jstatus["bootstrap"]["code"] = code;
        jstatus["bootstrap"]["message"] = message;

        if (ndCurlParent(bootstrap)->http_rc != 200 || code != 0) {
            nd_printf("%s: Bootstrap request failed: HTTP %ld: %s [%d]\n",
              tag.c_str(), ndCurlParent(bootstrap)->http_rc,
              message.c_str(), code);
            return UpdateResult::ERROR;
        }

        auto jdata = content.find("data");
        if (jdata == content.end()) {
            jstatus["bootstrap"]["code"] = -1;
            jstatus["bootstrap"]["message"] = "Data not found";
            nd_dprintf("%s: Malformed bootstrap content: %s\n",
              tag.c_str(), "data not found");
            return UpdateResult::ERROR;
        }

        auto juuid_site = jdata->find("uuid-site");
        if (juuid_site != jdata->end() && juuid_site->is_string()) {
            string new_uuid = juuid_site->get<string>();
            if (ndGC.SaveUUID(ndUUID::SITE, new_uuid)) {
                jstatus["bootstrap"]["code"] = 0;
                jstatus["bootstrap"]["message"] = "Site provisioned";
                nd_printf("%s: Site UUID provisioned: %s\n",
                  tag.c_str(), new_uuid.c_str());
            }
            return UpdateResult::RELOAD_BROADCAST;
        }

        unique_lock<mutex> ul(lock);

        agent_data = nullptr;
        intel_data = nullptr;

        bootstrap_data.clear();

        for (auto &jdc : jdata->items()) {
            ndNetifyApiData::Type type = ndNetifyApiData::Base::GetType(
              jdc.key()
            );

            if (type == ndNetifyApiData::Type::INVALID) continue;

            ndNetifyApiData::Ptr data = ndNetifyApiData::Create(
                jdc.key(), type, jdc.value());

            if (! data) continue;

            if (type == ndNetifyApiData::Type::AGENT)
                agent_data = data;
            if (type == ndNetifyApiData::Type::INTEL)
                intel_data = data;

            bootstrap_data.emplace(make_pair(type, data));
        }

        if (bootstrap_data.empty()) {
            jstatus["bootstrap"]["code"] = -1;
            jstatus["bootstrap"]["message"] =
              "No bootstrap configuration data found";
            nd_dprintf("%s: Malformed bootstrap content: %s\n",
              tag.c_str(), "no valid data entries found");
            return UpdateResult::ERROR;
        }

        if (agent_data) {
            auto url = agent_data->GetUrl("apps");
            if (! url.empty())
                urls[Request::DOWNLOAD_APPLICATIONS] = url;

            url = agent_data->GetUrl("categories");
            if (! url.empty())
                urls[Request::DOWNLOAD_CATEGORIES] = url;

            url = agent_data->GetUrl("overlay");
            if (! url.empty())
                urls[Request::DOWNLOAD_OVERLAY] = url;
        }

        if (intel_data) {
            auto url = intel_data->GetUrl("intel");
            if (! url.empty())
                urls[Request::DOWNLOAD_INTELLIGENCE] = url;
        }
    }
    catch (json::exception &e) {
        jstatus["bootstrap"]["code"] = -1;
        jstatus["bootstrap"]["message"] =
          "Exception encountered while assigning signature download URLs";
        nd_printf("%s: Failed to decode bootstrap content.\n", tag.c_str());
        nd_dprintf("%s: JSON exception: %s\n", tag.c_str(), e.what());
        return UpdateResult::ERROR;
    }

    return UpdateResult::OK;
}

bool ndNetifyApiManager::ProcessDownloadRequest(
  ndNetifyApiDownload *download, Request type) {
    string status_type;

    switch (type) {
    case Request::DOWNLOAD_APPLICATIONS:
        status_type = "applications";
        break;
    case Request::DOWNLOAD_CATEGORIES:
        status_type = "categories";
        break;
    case Request::DOWNLOAD_INTELLIGENCE:
        status_type = "intelligence";
        break;
    case Request::DOWNLOAD_OVERLAY:
        status_type = "overlay";
        break;
    default:
        nd_dprintf("%s: invalid download type: %d", tag.c_str(), type);
        return false;
    }

    jstatus[status_type]["code"] = ndCurlParent(download)->http_rc;
    jstatus[status_type]["last_update"] = time(nullptr);

    if (ndCurlParent(download)->curl_rc != CURLE_OK) {
        jstatus[status_type]["message"] = curl_easy_strerror(
          ndCurlParent(download)->curl_rc);
        return false;
    }

    switch (ndCurlParent(download)->http_rc) {
    case 200:
        jstatus[status_type]["message"] = "Updated";
        break;
    case 304:
        jstatus[status_type]["message"] = "Up-to-date (not modified)";
        return false;
    case 401:
        jstatus[status_type]["message"] = "Authorization failure";
        break;
    case 403:
        jstatus[status_type]["message"] = "Forbidden request";
        break;
    default:
        jstatus[status_type]["message"] = "Request failure";
        break;
    }

    if (ndCurlParent(download)->http_rc != 200) {
        nd_printf("%s: Download request failed: HTTP %ld: type: %d\n",
          tag.c_str(), ndCurlParent(download)->http_rc, type);

        if (ndCurlParent(download)->http_rc == 401 ||
            ndCurlParent(download)->http_rc == 403) {
            nd_dprintf("%s: reset update TTL on authorization failure.\n",
              tag.c_str());

            ttl_last_update = 0;
        }

        return false;
    }

    if (type == Request::DOWNLOAD_APPLICATIONS) {
        string content_type = download->content_type;
        auto p = content_type.find_first_of(";");
        if (p != string::npos) content_type.erase(p);

        if (content_type == "text/plain") {
            return nd_copy_file(download->content_filename,
              ndGC.path_app_config,
              S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        }
        else if (content_type == "application/octet-stream") {
            return nd_copy_file(download->content_filename,
              nd_change_ext(ndGC.path_app_config, "dat"),
              S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        }
    }
    else if (type == Request::DOWNLOAD_CATEGORIES) {
        if (download->content_type == "application/json") {
            return nd_copy_file(download->content_filename,
              ndGC.path_cat_config,
              S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        }
    }
    else if (type == Request::DOWNLOAD_INTELLIGENCE) {
        if (download->content_type == "application/json") {
            return nd_copy_file(download->content_filename,
              ndGC.path_intel_config,
              S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        }
        else if (download->content_type == "application/octet-stream") {
            return nd_copy_file(download->content_filename,
              nd_change_ext(ndGC.path_intel_config, "dat"),
              S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        }
    }
    else if (type == Request::DOWNLOAD_OVERLAY) {
        if (download->content_type == "application/json") {
            return nd_copy_file(download->content_filename,
              ndGC.path_overlay_config,
              S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        }
    }

    jstatus[status_type]["message"] =
      "Invalid content-type:" + download->content_type;

    return false;
}
