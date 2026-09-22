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

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <glob.h>
#include <grp.h>
#include <libgen.h>
#include <math.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#if defined(__FreeBSD__)
#include <sys/sysctl.h>
#include <sys/user.h>
#endif
#if defined(__linux__)
#ifdef _ND_ENABLE_LIBCAP
#include <sys/capability.h>
#include <sys/prctl.h>
#endif // _ND_ENABLE_LIBCAP
#endif
#include <syslog.h>
#include <unistd.h>
#include <zlib.h>

#include <array>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <regex>
#include <sched.h>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include "timezone.hpp"

#include "nd-config.hpp"
#include "nd-except.hpp"
#include "nd-license-client.hpp"
#include "nd-util.hpp"
#include "netifyd.hpp"

using namespace std;
using json = nlohmann::json;
using json_ordered = nlohmann::ordered_json;

std::mutex nd_printf_mutex;

const bool nd_isatty = (isatty(STDOUT_FILENO) == 1 &&
  isatty(STDERR_FILENO) == 1);

const char *ndTerm::Color::RED =
  (nd_isatty) ? "\033[0;31m" : "";
const char *ndTerm::Color::GREEN =
  (nd_isatty) ? "\033[0;32m" : "";
const char *ndTerm::Color::YELLOW =
  (nd_isatty) ? "\033[0;33m" : "";

const char *ndTerm::Attr::RESET = (nd_isatty) ? "\033[0m" : "";
const char *ndTerm::Attr::CURSOR_HIDE =
  (nd_isatty) ? "\033[?25l" : "";
const char *ndTerm::Attr::CURSOR_SHOW =
  (nd_isatty) ? "\033[?25h" : "";
const char *ndTerm::Attr::CLEAR_EOL =
  (nd_isatty) ? "\033[0K" : "";
const char *ndTerm::Attr::BOLD = (nd_isatty) ? "\033[1m" : "";
const char *ndTerm::Attr::UNDERLINE =
  (nd_isatty) ? "\033[4m" : "";

const char *ndTerm::Icon::INFO = "•";
const char *ndTerm::Icon::OK = "✓";
const char *ndTerm::Icon::WARN = "!";
const char *ndTerm::Icon::FAIL = "✗";
const char *ndTerm::Icon::NOTE = "↪";
const char *ndTerm::Icon::RARROW = "→";

bool ndTerm::IsTTY(void) {
    return nd_isatty;
}

void nd_output_lock(void) {
    nd_printf_mutex.lock();
}

void nd_output_unlock(void) {
    nd_printf_mutex.unlock();
}

void nd_printf(const char *format, ...) {
    if (ndGC_QUIET && ndGC.h_debug_log == stderr) return;

    va_list ap;
    va_start(ap, format);
    nd_printf(format, ap);
    va_end(ap);
}

void nd_printf(const char *format, va_list ap) {
    if (ndGC_QUIET && ndGC.h_debug_log == stderr) return;

    lock_guard<mutex> lock(nd_printf_mutex);

    vsyslog(LOG_DAEMON | LOG_INFO, format, ap);

    if (ndGC.h_debug_log != stderr) {
        vfprintf(ndGC.h_debug_log, format, ap);
        fflush(ndGC.h_debug_log);
    }
}

void nd_dprintf(const char *format, ...) {
    if (! ndGC_DEBUG && ndGC.h_debug_log == stderr) return;

    va_list ap;
    va_start(ap, format);
    nd_dprintf(format, ap);
    va_end(ap);
}

void nd_dprintf(const char *format, va_list ap) {
    if (! ndGC_DEBUG && ndGC.h_debug_log == stderr) return;

    lock_guard<mutex> lock(nd_printf_mutex);

    vfprintf(ndGC.h_debug_log, format, ap);

    if (ndGC.h_debug_log != stderr) fflush(ndGC.h_debug_log);
}

void nd_flow_printf(const char *format, ...) {
    lock_guard<mutex> lock(nd_printf_mutex);

    va_list ap;
    va_start(ap, format);
    vfprintf(ndGC.h_debug_log_flow, format, ap);
    va_end(ap);

    fflush(ndGC.h_debug_log_flow);
}

int ndLogBuffer::overflow(int ch) {
    if (ch != EOF) os << (char)ch;

    if (ch == '\n') return sync();

    return 0;
}

int ndLogBuffer::sync() {
    if (! os.str().empty()) {
        nd_printf("%s", os.str().c_str());
        os.str("");
    }

    return 0;
}

int ndDebugLogBuffer::sync() {
    if (! os.str().empty()) {
        nd_dprintf("%s", os.str().c_str());
        os.str("");
    }

    return 0;
}

int ndDebugLogBufferUnlocked::sync() {
    if (! os.str().empty()) {
        if (ndGC_DEBUG || ndGC.h_debug_log != stderr) {
            fprintf(ndGC.h_debug_log, "%s", os.str().c_str());
            if (ndGC.h_debug_log != stderr) fflush(ndGC.h_debug_log);
        }
        os.str("");
    }

    return 0;
}

int ndDebugLogBufferFlow::sync() {
    if (! os.str().empty()) {
        if (ndGC_DEBUG || ndGC.h_debug_log_flow != stderr) {
            fprintf(ndGC.h_debug_log_flow, "%s", os.str().c_str());
            if (ndGC.h_debug_log_flow != stderr) fflush(ndGC.h_debug_log_flow);
        }
        os.str("");
    }

    return 0;
}

void nd_ltrim(string &s, unsigned char c) {
    s.erase(s.begin(),
      find_if(s.begin(), s.end(), [c](unsigned char ch) {
          if (c == 0) return ! isspace(ch);
          else return (ch != c);
      }));
}

void nd_rtrim(string &s, unsigned char c) {
    s.erase(
      find_if(
        s.rbegin(), s.rend(),
        [c](unsigned char ch) {
        if (c == 0) return ! isspace(ch);
        else return (ch != c);
        })
        .base(),
      s.end());
}

void nd_trim(string &s, unsigned char c) {
    nd_ltrim(s, c);
    nd_rtrim(s, c);
}

int nd_xxh64_file(const string &filename, ndDigest &digest) {
    int fd = open(filename.c_str(), O_RDONLY);
    uint8_t buffer[ND_SHA1_BUFFER];
    ssize_t bytes;

    if (fd < 0) {
        nd_printf("Unable to hash file: %s: %s\n",
          filename.c_str(), strerror(errno));
        return -1;
    }

    // Just read entire file to hash.
    vector<uint8_t> file_data;
    do {
        bytes = read(fd, buffer, ND_SHA1_BUFFER);
        if (bytes > 0)
            file_data.insert(file_data.end(), buffer, buffer + bytes);
        else if (bytes < 0) {
            nd_printf("Unable to hash file: %s: %s\n",
              filename.c_str(), strerror(errno));
            close(fd);
            return -1;
        }
    } while (bytes != 0);

    close(fd);
    digest = nd_xxh64(file_data.data(), file_data.size());

    return 0;
}

int nd_sha1_file(const string &filename, ndDigestSHA1 &digest) {
    sha1 ctx;
    int fd = open(filename.c_str(), O_RDONLY);
    uint8_t buffer[ND_SHA1_BUFFER];
    ssize_t bytes;

    sha1_init(&ctx);

    if (fd < 0) {
        nd_printf("Unable to hash file: %s: %s\n",
          filename.c_str(), strerror(errno));
        return -1;
    }

    do {
        bytes = read(fd, buffer, ND_SHA1_BUFFER);

        if (bytes > 0)
            sha1_write(&ctx, (const char *)buffer, bytes);
        else if (bytes < 0) {
            nd_printf("Unable to hash file: %s: %s\n",
              filename.c_str(), strerror(errno));
            close(fd);
            return -1;
        }
    }
    while (bytes != 0);

    close(fd);
    sha1_result(&ctx, digest.data());

    return 0;
}

static inline uint64_t XXH_rotl64(uint64_t x, int r) {
    return (x << r) | (x >> (64 - r));
}

uint64_t nd_xxh64(const void *input, size_t length, uint64_t seed) {
    static const uint64_t PRIME64_1 = 11400714785074694791ULL;
    static const uint64_t PRIME64_2 = 14029467366897019727ULL;
    static const uint64_t PRIME64_3 = 1609587929392839161ULL;
    static const uint64_t PRIME64_4 = 9650029242287828579ULL;
    static const uint64_t PRIME64_5 = 2870177450012600261ULL;

    const uint8_t *p = (const uint8_t *)input;
    const uint8_t *end = p + length;
    uint64_t h64;

    if (length >= 32) {
        const uint8_t *limit = end - 32;
        uint64_t v1 = seed + PRIME64_1 + PRIME64_2;
        uint64_t v2 = seed + PRIME64_2;
        uint64_t v3 = seed + 0;
        uint64_t v4 = seed - PRIME64_1;

        do {
            v1 += (*(const uint64_t *)p) * PRIME64_2;
            v1 = XXH_rotl64(v1, 31);
            v1 *= PRIME64_1;
            p += 8;
            v2 += (*(const uint64_t *)p) * PRIME64_2;
            v2 = XXH_rotl64(v2, 31);
            v2 *= PRIME64_1;
            p += 8;
            v3 += (*(const uint64_t *)p) * PRIME64_2;
            v3 = XXH_rotl64(v3, 31);
            v3 *= PRIME64_1;
            p += 8;
            v4 += (*(const uint64_t *)p) * PRIME64_2;
            v4 = XXH_rotl64(v4, 31);
            v4 *= PRIME64_1;
            p += 8;
        }
        while (p <= limit);

        h64 = XXH_rotl64(v1, 1) + XXH_rotl64(v2, 7) +
          XXH_rotl64(v3, 12) + XXH_rotl64(v4, 18);

        v1 *= PRIME64_2;
        v1 = XXH_rotl64(v1, 31);
        v1 *= PRIME64_1;
        h64 ^= v1;
        h64 = h64 * PRIME64_1 + PRIME64_4;

        v2 *= PRIME64_2;
        v2 = XXH_rotl64(v2, 31);
        v2 *= PRIME64_1;
        h64 ^= v2;
        h64 = h64 * PRIME64_1 + PRIME64_4;

        v3 *= PRIME64_2;
        v3 = XXH_rotl64(v3, 31);
        v3 *= PRIME64_1;
        h64 ^= v3;
        h64 = h64 * PRIME64_1 + PRIME64_4;

        v4 *= PRIME64_2;
        v4 = XXH_rotl64(v4, 31);
        v4 *= PRIME64_1;
        h64 ^= v4;
        h64 = h64 * PRIME64_1 + PRIME64_4;
    }
    else {
        h64 = seed + PRIME64_5;
    }

    h64 += (uint64_t)length;

    while (p + 8 <= end) {
        uint64_t k1 = (*(const uint64_t *)p) * PRIME64_2;
        k1 = XXH_rotl64(k1, 31);
        k1 *= PRIME64_1;
        h64 ^= k1;
        h64 = XXH_rotl64(h64, 27) * PRIME64_1 + PRIME64_4;
        p += 8;
    }

    if (p + 4 <= end) {
        h64 ^= (*(const uint32_t *)p) * PRIME64_1;
        h64 = XXH_rotl64(h64, 23) * PRIME64_2 + PRIME64_3;
        p += 4;
    }

    while (p < end) {
        h64 ^= (*p) * PRIME64_5;
        h64 = XXH_rotl64(h64, 11) * PRIME64_1;
        p++;
    }

    h64 ^= h64 >> 33;
    h64 *= PRIME64_2;
    h64 ^= h64 >> 29;
    h64 *= PRIME64_3;
    h64 ^= h64 >> 32;

    return h64;
}

void nd_xxh64_to_string(const ndDigest &digest, string &digest_str) {
    char buf[17];
    snprintf(buf, sizeof(buf), "%016llx", (unsigned long long)digest);
    digest_str.assign(buf, 16);
}

void nd_sha1_to_string(const ndDigestSHA1 &digest, string &digest_str) {
    array<char, SHA1_DIGEST_LENGTH * 2 + 1> _digest;
    char *p = _digest.data();

    for (int i = 0; i < SHA1_DIGEST_LENGTH; i++, p += 2)
        sprintf(p, "%02hhx", digest[i]);

    digest_str.assign(_digest.begin(), _digest.end() - 1);
}

void nd_sha1_to_string(const ndDigestDynamic &digest, string &digest_str) {
    if (digest.size() != SHA1_DIGEST_LENGTH) {
        throw ndException(
          "%s: invalid digest length: %lu != %u",
          __PRETTY_FUNCTION__, digest.size(), SHA1_DIGEST_LENGTH);
    }

    array<char, SHA1_DIGEST_LENGTH * 2 + 1> _digest;
    char *p = _digest.data();

    for (size_t i = 0; i < SHA1_DIGEST_LENGTH; i++, p += 2)
        sprintf(p, "%02hhx", digest[i]);

    digest_str.assign(_digest.begin(), _digest.end() - 1);
}

bool nd_string_to_xxh64(const string &digest_str, ndDigest &digest) {
    if (digest_str.size() != 16) return false;
    try {
        digest = std::stoull(digest_str, nullptr, 16);
        return true;
    } catch (...) {
        return false;
    }
}

bool nd_string_to_sha1(const string &digest_str,
  ndDigestDynamic &digest) {
    if (digest_str.size() != SHA1_DIGEST_LENGTH * 2) return false;

    digest.assign(SHA1_DIGEST_LENGTH, '\0');

    size_t i = 0;
    istringstream is(digest_str);
    while (i < SHA1_DIGEST_LENGTH && is.good()) {
        string octet;
        is >> setw(2) >> octet;
        if (octet.size() == 2) {
            try {
                uint8_t byte = (uint8_t)stoul(octet, nullptr, 16);
                digest[i++] = byte;
            }
            catch (invalid_argument &e) {
                nd_dprintf(
                  "error converting string to SHA1: %s: "
                  "%s\n",
                  e.what(), octet.c_str());
                return false;
            }
            catch (out_of_range &e) {
                nd_dprintf(
                  "error converting string to SHA1: %s: "
                  "%s\n",
                  e.what(), octet.c_str());
                return false;
            }
        }
    }

    return (i == SHA1_DIGEST_LENGTH);
}

bool nd_string_to_mac(const string &src, uint8_t *mac) {
    if (src.size() != ND_STR_ETHALEN) return false;

    uint8_t *p = mac;
    const char *s = src.c_str();

    for (int i = 0; i < ND_STR_ETHALEN; i += 3, p++) {
        if (sscanf(s + i, "%2hhx", p) != 1) return false;
    }

    return true;
}

sa_family_t
nd_string_to_ip(const string &src, sockaddr_storage *ip) {
    sa_family_t family = AF_UNSPEC;
    struct sockaddr_in *ipv4 =
      reinterpret_cast<struct sockaddr_in *>(ip);
    struct sockaddr_in6 *ipv6 =
      reinterpret_cast<struct sockaddr_in6 *>(ip);

    if (inet_pton(AF_INET, src.c_str(), &ipv4->sin_addr) == 1)
        family = AF_INET;
    else if (inet_pton(AF_INET6, src.c_str(), &ipv6->sin6_addr) == 1)
        family = AF_INET6;

    return family;
}

bool nd_ip_to_string(sa_family_t af, const void *addr, string &dst) {
    char ip[INET6_ADDRSTRLEN];

    switch (af) {
    case AF_INET:
        inet_ntop(AF_INET, addr, ip, INET_ADDRSTRLEN);
        break;
    case AF_INET6:
        inet_ntop(AF_INET6, addr, ip, INET6_ADDRSTRLEN);
        break;
    default: return false;
    }

    dst.assign(ip);

    return true;
}

bool nd_ip_to_string(const sockaddr_storage &ip, string &dst) {
    const struct sockaddr_in *ipv4 =
      reinterpret_cast<const struct sockaddr_in *>(&ip);
    const struct sockaddr_in6 *ipv6 =
      reinterpret_cast<const struct sockaddr_in6 *>(&ip);

    switch (ip.ss_family) {
    case AF_INET:
        return nd_ip_to_string(AF_INET,
          (const void *)&ipv4->sin_addr.s_addr, dst);
    case AF_INET6:
        return nd_ip_to_string(AF_INET6,
          (const void *)&ipv6->sin6_addr.s6_addr, dst);
    default: return false;
    }

    return false;
}

void nd_json_to_string(const json &j, string &output, bool pretty) {
    output = j.dump(pretty ? ND_JSON_INDENT : -1, ' ', true,
      json::error_handler_t::replace);

    // TODO: Make this it's own helper function...
    vector<pair<regex *, string> >::const_iterator i;
    for (i = ndGC.privacy_regex.begin();
         i != ndGC.privacy_regex.end();
         i++)
    {
        string result = regex_replace(output, *((*i).first),
          (*i).second);
        if (result.size()) output = result;
    }
}

void nd_ordered_json_to_string(
  const json_ordered &j, string &output, bool pretty) {
    output = j.dump(pretty ? ND_JSON_INDENT : -1, ' ', true,
      json::error_handler_t::replace);

    // TODO: Make this it's own helper function...
    vector<pair<regex *, string> >::const_iterator i;
    for (i = ndGC.privacy_regex.begin();
         i != ndGC.privacy_regex.end();
         i++)
    {
        string result = regex_replace(output, *((*i).first),
          (*i).second);
        if (result.size()) output = result;
    }
}

uint8_t nd_netmask_to_prefix(const struct sockaddr_storage *netmask) {
    uint8_t p = 0;

    if (netmask->ss_family == AF_INET) {
        const struct sockaddr_in *addr =
          reinterpret_cast<const struct sockaddr_in *>(netmask);
        unsigned n = ntohl(addr->sin_addr.s_addr);
        while (n > 0) {
            n = n << 1;
            p++;
        }
    }
    else if (netmask->ss_family == AF_INET6) {
        const struct sockaddr_in6 *addr =
          reinterpret_cast<const struct sockaddr_in6 *>(netmask);
        for (int i = 0; i < 4; i++) {
            unsigned n = ntohl(addr->sin6_addr.s6_addr32[i]);
            while (n > 0) {
                n = n << 1;
                p++;
            }
        }
    }

    return p;
}

uint8_t nd_netmask_to_prefix(const std::string &netmask) {
    sockaddr_storage addr;
    struct sockaddr_in *ipv4 =
      reinterpret_cast<struct sockaddr_in *>(&addr);
    struct sockaddr_in6 *ipv6 =
      reinterpret_cast<struct sockaddr_in6 *>(&addr);

    if (inet_pton(AF_INET, netmask.c_str(), &ipv4->sin_addr) == 1)
        return nd_netmask_to_prefix(&addr);
    else if (inet_pton(AF_INET6, netmask.c_str(), &ipv6->sin6_addr) == 1)
        return nd_netmask_to_prefix(&addr);

    return 0;
}

bool nd_is_ipaddr(const char *ip) {
    struct in_addr addr4;
    struct in6_addr addr6;

    if (inet_pton(AF_INET, ip, &addr4) == 1) return true;
    return (inet_pton(AF_INET6, ip, &addr6) == 1) ? true : false;
}

void nd_private_ipaddr(uint8_t index, struct sockaddr_storage &addr) {
    int rc = -1;
    ostringstream os;

    if (addr.ss_family == AF_INET) {
        os << ND_PRIVATE_IPV4 << (int)index;
        struct sockaddr_in *sa =
          reinterpret_cast<struct sockaddr_in *>(&addr);
        rc = inet_pton(AF_INET, os.str().c_str(), &sa->sin_addr);
    }
    else if (addr.ss_family == AF_INET6) {
        os << ND_PRIVATE_IPV6 << hex << (int)index;
        struct sockaddr_in6 *sa =
          reinterpret_cast<struct sockaddr_in6 *>(&addr);
        rc = inet_pton(AF_INET6, os.str().c_str(), &sa->sin6_addr);
    }

    switch (rc) {
    case -1:
        nd_dprintf("Invalid private address family.\n");
        break;
    case 0:
        nd_dprintf("Invalid private address: %s\n",
          os.str().c_str());
        break;
    }
}

bool nd_load_uuid(string &uuid, const string &path, size_t length) {
    struct stat sb;
    unique_ptr<char[]> _uuid(new char[length + 1]);

    if (stat(path.c_str(), &sb) == -1) {
        if (errno != ENOENT) {
            nd_printf("Error loading uuid: %s: %s\n",
              path.c_str(), strerror(errno));
        }
        return false;
    }

    if (! S_ISREG(sb.st_mode)) {
        nd_printf("Error loading uuid: %s: %s\n",
          path.c_str(), "Not a regular file");
        return false;
    }

    if (sb.st_mode & S_IXUSR) {
        FILE *ph = popen(path.c_str(), "r");

        if (ph == nullptr) {
            if (ndGC_DEBUG || errno != ENOENT) {
                nd_printf(
                  "Error loading uuid from pipe: %s: %s\n",
                  path.c_str(), strerror(errno));
            }
            return false;
        }

        size_t bytes = 0;

        bytes = fread((void *)_uuid.get(), 1, length, ph);

        int rc = pclose(ph);

        if (bytes <= 0 || rc != 0) {
            nd_printf(
              "Error loading uuid from pipe: %s: %s: %d\n",
              path.c_str(), "Invalid pipe read", rc);
            return false;
        }

        _uuid[bytes - 1] = '\0';
    }
    else {
        FILE *fh = fopen(path.c_str(), "r");

        if (fh == nullptr) {
            if (ndGC_DEBUG || errno != ENOENT) {
                nd_printf(
                  "Error loading uuid from file: %s: %s\n",
                  path.c_str(), strerror(errno));
            }
            return false;
        }

        if (fread((void *)_uuid.get(), 1, length, fh) != length) {
            fclose(fh);
            nd_printf(
              "Error reading uuid from file: %s: %s\n",
              path.c_str(), strerror(errno));
            return false;
        }

        fclose(fh);

        _uuid[length] = '\0';
    }

    uuid.assign(_uuid.get());

    nd_rtrim(uuid);

    return true;
}

bool nd_save_uuid(const string &uuid, const string &path,
  size_t length) {
    FILE *fh = fopen(path.c_str(), "w");

    if (fh == nullptr) {
        nd_printf("Error saving uuid: %s: %s\n",
          path.c_str(), strerror(errno));
        return false;
    }

    if (fwrite((const void *)uuid.c_str(), 1, length, fh) != length)
    {
        fclose(fh);
        nd_printf("Error writing uuid: %s: %s\n",
          path.c_str(), strerror(errno));
        return false;
    }

    fclose(fh);
    return true;
}

void nd_seed_rng(void) {
    FILE *fh = fopen("/dev/urandom", "r");
    unsigned int seed = (unsigned int)time(nullptr);

    if (fh == nullptr)
        nd_printf("Error opening random device: %s\n",
          strerror(errno));
    else {
        if (fread((void *)&seed, sizeof(unsigned int), 1, fh) != 1)
            nd_printf(
              "Error reading from random device: %s\n",
              strerror(errno));
        fclose(fh);
    }

    srand(seed);
}

void nd_generate_uuid(string &uuid) {
    int digit = 0;
    deque<char> result;
    uint64_t input = 623714775;
    const char *clist = {
        "0123456789abcdefghijklmnpqrstuvwxyz"
    };
    ostringstream os;

    input = (uint64_t)rand();
    input += (uint64_t)rand() << 32;

    while (input != 0) {
        result.push_front(toupper(clist[input % strlen(clist)]));
        input /= strlen(clist);
    }

    for (size_t i = result.size(); i < 8; i++)
        result.push_back('0');

    while (result.size() && digit < 8) {
        os << result.front();
        result.pop_front();
        if (digit == 1) os << "-";
        if (digit == 3) os << "-";
        if (digit == 5) os << "-";
        digit++;
    }

    uuid = os.str();
}

const char *nd_get_version(void) {
    return ND_VERSION_STR;
}

const string &nd_get_version_and_features(bool fancy) {
    static mutex lock;
    static string version;

    lock_guard<mutex> ul(lock);

    if (version.empty()) {
        string os;
        nd_os_detect(os);

        ostringstream ident;
        if (fancy) ident << ndTerm::Attr::BOLD;
        ident << ND_NAME << "/" << GIT_RELEASE;
        if (fancy) ident << ndTerm::Attr::RESET;
        ident << " (" << os << "; " << _ND_HOST_OS << "; " << _ND_HOST_CPU;

        if (ndGC_USE_CONNTRACK) ident << "; conntrack";
        if (ndGC_USE_NETLINK) ident << "; netlink";
        if (ndGC_USE_DHC) ident << "; dns-cache";
#ifdef _ND_ENABLE_TPACKETV3
        ident << "; tpv3";
#endif
#ifdef _ND_ENABLE_NFQUEUE
        ident << "; nfqueue";
#endif
#ifdef _ND_ENABLE_LIBTCMALLOC
        ident << "; tcmalloc";
#endif
#ifdef HAVE_WORKING_REGEX
        ident << "; regex";
#endif
        if (ndLicenseClient::IsValid())
            ident << "; nlm";
        ident << ")";

        version = ident.str();
    }

    return version;
}

bool nd_parse_app_tag(const string &tag, unsigned &id, string &name) {
    id = 0;
    name.clear();

    size_t p;
    if ((p = tag.find_first_of(".")) != string::npos) {
        id = (unsigned)strtoul(tag.substr(0, p).c_str(),
          nullptr, 0);
        name = tag.substr(p + 1);

        return true;
    }

    return false;
}

int nd_touch(const string &filename) {
    int fd;
    struct timespec now[2];

    fd = open(filename.c_str(),
      O_WRONLY | O_CREAT | O_NONBLOCK | O_NOCTTY,
      S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

    if (fd < 0) return fd;

    clock_gettime(CLOCK_REALTIME, &now[0]);
    clock_gettime(CLOCK_REALTIME, &now[1]);

    if (futimens(fd, now) < 0) return -1;

    close(fd);

    return 0;
}

int nd_file_load(const string &filename, string &data) {
    struct stat sb;
    int fd = open(filename.c_str(), O_RDONLY);

    if (fd < 0) {
        if (errno != ENOENT) {
            throw ndException("%s: open(%s): %s", __PRETTY_FUNCTION__,
              filename.c_str(), strerror(errno));
        }
        else {
            nd_dprintf("Unable to load file: %s: %s\n",
              filename.c_str(), strerror(errno));
            return -1;
        }
    }

    if (flock(fd, LOCK_SH) < 0) {
        close(fd);
        throw ndException("%s: flock(LOCK_SH, %s): %s",
          __PRETTY_FUNCTION__, filename.c_str(), strerror(errno));
    }

    if (fstat(fd, &sb) < 0) {
        close(fd);
        throw ndException("%s: fstat(%s): %s", __PRETTY_FUNCTION__,
          filename.c_str(), strerror(errno));
    }

    if (sb.st_size == 0) data.clear();
    else {
        auto buffer = make_shared<vector<uint8_t>>(sb.st_size);
        if (read(fd, (void *)buffer->data(), sb.st_size) < 0)
        {
            throw ndException("%s: read(%s): %s", __PRETTY_FUNCTION__,
              filename.c_str(), strerror(errno));
        }
        data.assign((const char *)buffer->data(), sb.st_size);
    }

    flock(fd, LOCK_UN);
    close(fd);

    return 0;
}

void nd_file_save(const string &filename, const string &data,
  bool append, mode_t mode, const char *user, const char *group) {
    int fd = open(filename.c_str(), O_WRONLY);
    uid_t owner_user = -1;
    gid_t owner_group = -1;

    if (fd < 0) {
        if (errno != ENOENT) {
            throw ndException("%s: open(%s): %s", __PRETTY_FUNCTION__,
              filename.c_str(), strerror(errno));
        }
        fd = open(filename.c_str(), O_WRONLY | O_CREAT, mode);
        if (fd < 0) {
            throw ndException("%s: open(%s): %s", __PRETTY_FUNCTION__,
              filename.c_str(), strerror(errno));
        }

        if (user != nullptr)
            owner_user = nd_get_user_id(user);

        if (group != nullptr)
            owner_group = nd_get_group_id(group);

        if (fchown(fd, owner_user, owner_group) < 0) {
            throw ndException("%s: fchown(%s, %s, %s): %s",
              __PRETTY_FUNCTION__, (user != nullptr) ? user : "-1",
              (group != nullptr) ? group : "-1",
              filename.c_str(), strerror(errno));
        }
    }

    if (flock(fd, LOCK_EX) < 0) {
        throw ndException("%s: flock(LOCK_EX, %s): %s",
          __PRETTY_FUNCTION__, filename.c_str(), strerror(errno));
    }

    if (lseek(fd, 0, (! append) ? SEEK_SET : SEEK_END) < 0) {
        throw ndException("%s: lseek(0, %s, %s): %s",
          __PRETTY_FUNCTION__, (! append) ? "SEEK_SET" : "SEEK_END",
          filename.c_str(), strerror(errno));
    }

    if (! append && ftruncate(fd, 0) < 0) {
        throw ndException("%s: ftruncate(%s): %s",
          __PRETTY_FUNCTION__, filename.c_str(), strerror(errno));
    }

    if (write(fd, (const void *)data.c_str(), data.length()) < 0)
    {
        throw ndException("%s: write(%s): %s", __PRETTY_FUNCTION__,
          filename.c_str(), strerror(errno));
    }

    flock(fd, LOCK_UN);
    close(fd);
}

int nd_ifreq(const string &name, unsigned long request,
  struct ifreq *ifr) {
    int fd, rc = -1;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        nd_printf("%s: error creating ifreq socket: %s\n",
          name.c_str(), strerror(errno));
        return rc;
    }

    memset(ifr, '\0', sizeof(struct ifreq));
    strncpy(ifr->ifr_name, name.c_str(), IFNAMSIZ - 1);

    if (ioctl(fd, request, (char *)ifr) == -1) {
        nd_dprintf(
          "%s: error sending interface request: %s\n",
          name.c_str(), strerror(errno));
    }
    else rc = 0;

    close(fd);
    return rc;
}

void nd_basename(const string &path, string &base) {
    base = path;
    size_t p = path.find_last_of("/");
    if (p == string::npos) return;
    base = path.substr(p + 1);
}

void nd_pathname(const string &path, string &base) {
    size_t p = path.find_last_of("/");
    if (p != string::npos) base = path.substr(0, p);
}

#if defined(__linux__)
pid_t nd_is_running(pid_t pid, const string &exe_base) {
    pid_t rc = -1;
    struct stat sb;
    ostringstream proc_exe_link;

    proc_exe_link << "/proc/" << pid << "/exe";

    if (lstat(proc_exe_link.str().c_str(), &sb) == -1) {
        if (errno != ENOENT) {
            nd_printf("%s: lstat: %s: %s\n", __PRETTY_FUNCTION__,
              proc_exe_link.str().c_str(), strerror(errno));
            return rc;
        }

        return 0;
    }

    vector<char> link_path(1024, '\0');
    ssize_t length = readlink(proc_exe_link.str().c_str(),
      &link_path[0], link_path.size());

    if (length != -1) {
        if (strncmp(basename(&link_path[0]),
              exe_base.c_str(), exe_base.size()))
        {
            rc = 0;
        }
        else rc = pid;
    }
    else {
        nd_printf("%s: readlink: %s: %s\n", __PRETTY_FUNCTION__,
          proc_exe_link.str().c_str(), strerror(errno));
    }

    return rc;
}
#elif defined(__FreeBSD__)
pid_t nd_is_running(pid_t pid, const string &exe_base) {
    int mib[4];
    pid_t rc = -1;
    size_t length = 4;
    char pathname[PATH_MAX];

    if (sysctlnametomib("kern.proc.pathname", mib, &length) < 0)
    {
        nd_printf("%s: sysctlnametomib: %s: %s\n", __PRETTY_FUNCTION__,
          "kern.proc.pathname", strerror(errno));
        return rc;
    }

    mib[3] = pid;
    length = sizeof(pathname);

    if (sysctl(mib, 4, pathname, &length, nullptr, 0) == -1) {
        nd_printf("%s: sysctl: %s(%ld): %s\n", __PRETTY_FUNCTION__,
          "kern.proc.pathname", pid, strerror(errno));
    }
    else if (length > 0) {
        char *pathname_base = basename(pathname);
        length = strlen(pathname_base);
        if (exe_base.size() < length)
            length = exe_base.size();

        if (strncmp(pathname_base, exe_base.c_str(), length) == 0)
        {
            rc = pid;
        }
        else rc = 0;
    }

    return rc;
}
#else
#error "Unsupported platform, not Linux or BSD >= 4.4."
#endif

int nd_load_pid(const string &pidfile) {
    pid_t pid = -1;
    FILE *hpid = fopen(pidfile.c_str(), "r");

    if (hpid != nullptr) {
        char _pid[32];
        if (fgets(_pid, sizeof(_pid), hpid))
            pid = (pid_t)strtol(_pid, nullptr, 0);
        fclose(hpid);
    }
    else if (errno == ENOENT) {
        pid = 0;
    }

    return pid;
}

int nd_save_pid(const string &pidfile, pid_t pid) {
    FILE *hpid = fopen(pidfile.c_str(), "w+");

    if (hpid == nullptr) {
        nd_printf("Error opening PID file: %s: %s\n",
          pidfile.c_str(), strerror(errno));

        return -1;
    }

    fprintf(hpid, "%d\n", pid);
    fclose(hpid);

    return 0;
}

int nd_file_exists(const string &path) {
    struct stat sb;

    if (stat(path.c_str(), &sb) == -1) {
        if (errno == ENOENT) return 0;
        return -1;
    }

    return 1;
}

int nd_dir_exists(const string &path) {
    struct stat sb;

    if (stat(path.c_str(), &sb) == -1) {
        if (errno == ENOENT) return 0;
        return -1;
    }

    if (! S_ISDIR(sb.st_mode)) return 0;

    return 1;
}

void nd_uptime(time_t ut, string &uptime) {
    constexpr time_t _ND_UT_MIN = 60;
    constexpr time_t _ND_UT_HOUR = (_ND_UT_MIN * 60);
    constexpr time_t _ND_UT_DAY = (_ND_UT_HOUR * 24);

    time_t seconds = ut;
    time_t days = 0, hours = 0, minutes = 0;

    if (seconds > 0) {
        days = seconds / _ND_UT_DAY;
        seconds -= days * _ND_UT_DAY;
    }

    if (seconds > 0) {
        hours = seconds / _ND_UT_HOUR;
        seconds -= hours * _ND_UT_HOUR;
    }

    if (seconds > 0) {
        minutes = seconds / _ND_UT_MIN;
        seconds -= minutes * _ND_UT_MIN;
    }

    ostringstream os;
    ios os_state(nullptr);
    os_state.copyfmt(os);

    os << days << "d";
    os << " " << setfill('0') << setw(2) << hours;
    os.copyfmt(os_state);
    os << ":" << setfill('0') << setw(2) << minutes;
    os.copyfmt(os_state);
    os << ":" << setfill('0') << setw(2) << seconds;

    uptime.assign(os.str());
}

int nd_functions_exec(const string &func, const string &arg,
  string &output) {
    ostringstream os;
    os << "sh -c \". " << ndGC.path_functions << " && " << func;
    if (! arg.empty()) os << " " << arg;
    os << "\" 2>&1";

    int rc = -1;
    FILE *ph = popen(os.str().c_str(), "r");

    if (ph != nullptr) {
        char buffer[64];
        size_t bytes = 0;

        do {
            if ((bytes = fread(buffer, 1, sizeof(buffer), ph)) > 0)
                output.append(buffer, bytes);
        }
        while (bytes > 0);

        rc = pclose(ph);
    }

    return rc;
}

void nd_os_detect(string &os) {
    string output;
    int rc = nd_functions_exec("detect_os", string(), output);

    if (rc == 0 && output.size()) {
        const char *ws = "\n";
        output.erase(output.find_last_not_of(ws) + 1);
        os.assign(output);
    }
    else os = "unknown";
}

ndLogDirectory::ndLogDirectory(const string &path,
  const string &prefix,
  const string &suffix,
  bool overwrite)
  : path(path), prefix(prefix), suffix(suffix),
    overwrite(overwrite), hf_cur(nullptr) {
    struct stat sb;

    if (stat(path.c_str(), &sb) == -1) {
        if (errno == ENOENT) {
            if (mkdir(path.c_str(), 0750) != 0)
                throw ndException("%s: mkdir(%s): %s",
                  __PRETTY_FUNCTION__, filename.c_str(),
                  strerror(errno));
        }
        else {
            throw ndException("%s: stat(%s): %s", __PRETTY_FUNCTION__,
              filename.c_str(), strerror(errno));
        }

        if (! S_ISDIR(sb.st_mode)) {
            throw ndException("%s: ! S_ISDIR(%s)",
              __PRETTY_FUNCTION__, filename.c_str());
        }
    }
}

ndLogDirectory::~ndLogDirectory() {
    Close();
}

FILE *ndLogDirectory::Open(const string &ext) {
    if (hf_cur != nullptr) {
        nd_dprintf(
          "Log file already open; close or discard "
          "first: "
          "%s\n",
          filename.c_str());
        return nullptr;
    }

    if (! overwrite) {
        time_t now = time(nullptr);
        struct tm tm_now;

        tzset();
        localtime_r(&now, &tm_now);

        char stamp[_ND_LOG_FILE_STAMP_SIZE];
        strftime(stamp, _ND_LOG_FILE_STAMP_SIZE,
          _ND_LOG_FILE_STAMP, &tm_now);

        filename = prefix + stamp + suffix + ext;
    }
    else filename = prefix + suffix + ext;

    string full_path = path + "/." + filename;

    if (! (hf_cur = fopen(full_path.c_str(), "w"))) {
        nd_dprintf("Error opening log file: %s: %s\n",
          full_path.c_str(), strerror(errno));
        return nullptr;
    }

    return hf_cur;
}

void ndLogDirectory::Close(void) {
    if (hf_cur != nullptr) {
        fclose(hf_cur);

        string src = path + "/." + filename;
        string dst = path + "/" + filename;

        if (overwrite) unlink(dst.c_str());

        if (rename(src.c_str(), dst.c_str()) != 0) {
            nd_dprintf(
              "Error renaming log file: %s -> %s: %s\n",
              src.c_str(), dst.c_str(), strerror(errno));
        }

        hf_cur = nullptr;
    }
}

void ndLogDirectory::Discard(void) {
    if (hf_cur != nullptr) {
        string full_path = path + "/." + filename;

        nd_dprintf("Discarding log file: %s\n", full_path.c_str());

        fclose(hf_cur);

        unlink(full_path.c_str());

        hf_cur = nullptr;
    }
}

void nd_regex_error(const regex_error &e, string &error) {
    switch (e.code()) {
    case regex_constants::error_collate:
        error =
          "The expression contains an invalid collating "
          "element name";
        break;
    case regex_constants::error_ctype:
        error =
          "The expression contains an invalid "
          "character class name";
        break;
    case regex_constants::error_escape:
        error =
          "The expression contains an invalid escaped "
          "character or a trailing escape";
        break;
    case regex_constants::error_backref:
        error =
          "The expression contains an invalid back "
          "reference";
        break;
    case regex_constants::error_brack:
        error =
          "The expression contains mismatched square "
          "brackets ('[' and ']')";
        break;
    case regex_constants::error_paren:
        error =
          "The expression contains mismatched "
          "parentheses ('(' and ')')";
        break;
    case regex_constants::error_brace:
        error =
          "The expression contains mismatched curly "
          "braces ('{' and '}')";
        break;
    case regex_constants::error_badbrace:
        error =
          "The expression contains an invalid range in "
          "a {} expression";
        break;
    case regex_constants::error_range:
        error =
          "The expression contains an invalid "
          "character range (e.g. [b-a])";
        break;
    case regex_constants::error_space:
        error =
          "There was not enough memory to convert the "
          "expression into a finite state machine";
        break;
    case regex_constants::error_badrepeat:
        error =
          "one of *?+{ was not preceded by a valid "
          "regular expression";
        break;
    case regex_constants::error_complexity:
        error =
          "The complexity of an attempted match "
          "exceeded a predefined level";
        break;
    case regex_constants::error_stack:
        error =
          "There was not enough memory to perform a "
          "match";
        break;
    default: error = e.what(); break;
    }
}

bool nd_scan_dotd(const string &path, vector<string> &files) {
    DIR *dh = opendir(path.c_str());

    if (dh == nullptr) {
        nd_printf("Error opening directory: %s: %s\n",
          path.c_str(), strerror(errno));
        return false;
    }

    files.clear();

    struct dirent *result = nullptr;
    while ((result = readdir(dh)) != nullptr) {
        if (
#ifdef _DIRENT_HAVE_D_RECLEN
          result->d_reclen == 0 ||
#endif
#ifdef _DIRENT_HAVE_D_TYPE
          (result->d_type != DT_LNK && result->d_type != DT_REG &&
            result->d_type != DT_UNKNOWN) ||
#endif
          ! isdigit(result->d_name[0]))
            continue;

        string name(result->d_name);
        size_t p = name.find_last_of('.');
        if (p == string::npos ||
          name.substr(p + 1) != "conf")
            continue;

        files.push_back(name);
    }

    closedir(dh);

    return true;
}

bool nd_get_dotd_tag(const string &filename, string &tag) {
    size_t p1 = filename.find_first_of("-");
    if (p1 == string::npos) {
        nd_dprintf(
          "Invalid dotd file (wrong format; missing hyphen): %s\n",
            filename.c_str());
        return false;
    }

    size_t p2 = filename.find_last_of(".");
    if (p2 == string::npos) {
        nd_dprintf(
          "Rejecting dotd file (wrong format; missing extension): %s\n",
          filename.c_str());
        return false;
    }

    tag = filename.substr(p1 + 1, p2 - p1 - 1);

    return true;
}

void nd_set_hostname(string &dst, bool strict) {
    transform(dst.begin(), dst.end(), dst.begin(),
      [strict](unsigned char c) {
        if (strict) {
            if (isalnum(c) || c == '-' || c == '_' || c == '.')
                return (unsigned char)tolower(c);
        }
        else {
            if (isalnum(c) || ispunct(c) || c == ' ') {
                return c;
            }
        }
        return (unsigned char)'_';
    });

    nd_trim(dst, '.');
}

void nd_set_hostname(string &dst, const char *src,
  size_t length, bool strict) {
    dst.clear();
    dst.reserve(length);

    // Sanitize host server name; RFC 952 plus underscore for
    // SSDP.
    if (strict) {
        for (size_t i = 0; i < length; i++) {
            if (src[i] == '\0') break;
            if (isalnum(src[i]) || src[i] == '-' ||
              src[i] == '_' || src[i] == '.')
                dst += (char)tolower(src[i]);
        }
    }
    else {
        for (size_t i = 0; i < length; i++) {
            if (src[i] == '\0') break;
            if (isalnum(src[i]) || ispunct(src[i]) ||
              src[i] == ' ' || src[i] == '\0')
                dst += src[i];
            else dst += '_';
        }
    }

    nd_trim(dst, '.');
}

void nd_set_hostname(char *dst, const char *src,
  size_t length, bool strict) {
    string buffer;
    nd_set_hostname(buffer, src, length, strict);
    strncpy(dst, buffer.c_str(), min(length, buffer.length()));
}

void nd_expand_variables(const string &input,
  string &output, map<string, string> &vars) {
    output = input;

    for (auto &var : vars) {
        size_t p;

        while ((p = output.find(var.first)) != string::npos) {
            if (var.second.size() > var.first.size()) {
                output.insert(p + var.first.size(),
                  var.second.size() - var.first.size(),
                  ' ');
            }

            output.replace(p, var.second.size(), var.second);

            if (var.second.size() < var.first.size()) {
                output.erase(p + var.second.size(),
                  var.first.size() - var.second.size());
            }
        }
    }
}

void nd_gz_inflate(size_t length, const uint8_t *data,
  vector<uint8_t> &output) {
    int rc;
    z_stream zs;
    array<uint8_t, ND_ZLIB_CHUNK_SIZE> chunk;

    zs.zalloc = Z_NULL;
    zs.zfree = Z_NULL;
    zs.opaque = Z_NULL;
    zs.next_in = Z_NULL;
    zs.avail_in = 0;

    if (inflateInit2(&zs, 15 + 32) != Z_OK) {
        throw ndException("%s: inflateInit: %s",
          __PRETTY_FUNCTION__, strerror(EINVAL));
    }

    zs.next_in = (uint8_t *)data;
    zs.avail_in = length;

    do {
        zs.avail_out = chunk.size();
        zs.next_out = chunk.data();

        if ((rc = inflate(&zs, Z_SYNC_FLUSH)) < 0) {
            throw ndException("%s: inflate: %d",
              __PRETTY_FUNCTION__, rc);
        }
        output.insert(output.end(), chunk.begin(),
          chunk.begin() + (chunk.size() - zs.avail_out));
    }
    while (zs.avail_out == 0);

    inflateEnd(&zs);

    if (rc != Z_STREAM_END) {
        throw ndException("%s: inflate: %d",
          __PRETTY_FUNCTION__, rc);
    }
}

void nd_gz_deflate(size_t length, const uint8_t *data,
  vector<uint8_t> &output) {
    int rc;
    z_stream zs;
    array<uint8_t, ND_ZLIB_CHUNK_SIZE> chunk;

    output.clear();

    zs.zalloc = Z_NULL;
    zs.zfree = Z_NULL;
    zs.opaque = Z_NULL;

    if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
          15 /* window bits */ | 16 /* enable GZIP format */,
          8, Z_DEFAULT_STRATEGY) != Z_OK)
    {
        throw ndException("%s: deflateInit2: %s",
          __PRETTY_FUNCTION__, strerror(EINVAL));
    }

    zs.next_in = (uint8_t *)data;
    zs.avail_in = length;

    do {
        zs.avail_out = chunk.size();
        zs.next_out = chunk.data();
        if ((rc = deflate(&zs, Z_FINISH)) == Z_STREAM_ERROR) {
            throw ndException("%s: deflate: %s",
              __PRETTY_FUNCTION__, strerror(EINVAL));
        }
        output.insert(output.end(), chunk.begin(),
          chunk.begin() + (chunk.size() - zs.avail_out));
    }
    while (zs.avail_out == 0);

    deflateEnd(&zs);

    if (rc != Z_STREAM_END) {
        throw ndException("%s: deflate: %d",
          __PRETTY_FUNCTION__, rc);
    }
#if 0
    nd_dprintf(
        "%s: payload compressed: %lu -> %lu: %.1f%%\n",
        __PRETTY_FUNCTION__, length, output.size(),
        100.0f - ((float)output.size() * 100.0f / (float)length)
    );
#endif
}

void ndTimer::Create(int sig) {
    this->sig = sig;

    if (valid) {
        throw ndException("%s: timer: %s",
          __PRETTY_FUNCTION__, strerror(EEXIST));
    }

#if defined(__APPLE__)
    if (! (id = dispatch_source_create(
      DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
      dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0)
    )))
        throw ndExceptionSystemError(__PRETTY_FUNCTION__,
            "dispatch_source_create");

    // Capture the signal to send when the timer fires
    dispatch_source_set_event_handler(id, ^{
        kill(getpid(), sig);
    });

    // The source is created in a suspended state, so we must resume it
    dispatch_resume(id);
#else
    struct sigevent sigev;
    memset(&sigev, 0, sizeof(struct sigevent));
    sigev.sigev_notify = SIGEV_SIGNAL;
    sigev.sigev_signo = sig;

    if (timer_create(CLOCK_MONOTONIC, &sigev, &id) < 0) {
        throw ndExceptionSystemError(__PRETTY_FUNCTION__,
          "timer_create");
    }
#endif

    valid = true;
}

void ndTimer::Reset(void) {
    if (valid) {
#if defined(__APPLE__)
        dispatch_source_cancel(id);
        dispatch_release(id);
#else
        timer_delete(id);
#endif
        valid = false;
    }
}

void ndTimer::Set(const struct itimerspec &itspec) {
    if (! valid) {
        throw ndException("%s: timer: %s",
          __PRETTY_FUNCTION__, strerror(EEXIST));
    }

#if defined(__APPLE__)
    uint64_t start_nsec =
        (uint64_t)itspec.it_value.tv_sec * NSEC_PER_SEC
      + (uint64_t)itspec.it_value.tv_nsec;
    uint64_t interval_nsec =
        (uint64_t)itspec.it_interval.tv_sec * NSEC_PER_SEC
      + (uint64_t)itspec.it_interval.tv_nsec;

    if (start_nsec == 0) {
        // Disarm the timer
        dispatch_source_set_timer(
          id, DISPATCH_TIME_FOREVER, DISPATCH_TIME_FOREVER, 0);
    } else {
        dispatch_time_t start_time = dispatch_time(
          DISPATCH_TIME_NOW, start_nsec);
        uint64_t interval = (interval_nsec == 0)
          ? DISPATCH_TIME_FOREVER : interval_nsec;
        dispatch_source_set_timer(id, start_time, interval, 0);
    }
#else
    if (timer_settime(id, 0, &itspec, nullptr) != 0) {
        throw ndExceptionSystemError(__PRETTY_FUNCTION__,
          "timer_settime");
    }
#endif
}

ndCPUSet::ndCPUSet(bool empty) {
    if (empty) return;

    cpu_set_t mask;
    if (sched_getaffinity(0, sizeof(mask), &mask) == -1) {
        throw ndExceptionSystemError(__PRETTY_FUNCTION__,
          "sched_getaffinity");
    }

    for (int i = 0; i < CPU_SETSIZE; i++) {
        if (! CPU_ISSET(i, &mask)) continue;
        cpu_set.push_back(i);
    }
}

ndCPUSet::ndCPUSet(const std::string &cpu_list) {
}

void ndCPUSet::Get(cpu_set_t &cpu_set) {
    CPU_ZERO(&cpu_set);
    for (auto& cpu : this->cpu_set)
        CPU_SET(cpu, &cpu_set);
}

void nd_get_ip_protocol_name(int protocol, string &result) {
    static mutex lock;
    static unordered_map<int, string> cache;

    lock_guard<mutex> ul(lock);

    auto it = cache.find(protocol);
    if (it != cache.end()) {
        result = it->second;
        return;
    }

    int rc = 0;
    struct protoent *pe_result;
#ifdef HAVE_GETPROTOBYNUMBER_R
    struct protoent pe_buffer;
    constexpr size_t _ND_GET_PROTO_BUFSIZ = 1024;
    array<uint8_t, _ND_GET_PROTO_BUFSIZ> buffer;

    rc = getprotobynumber_r(protocol, &pe_buffer,
      reinterpret_cast<char *>(buffer.data()),
      _ND_GET_PROTO_BUFSIZ, &pe_result);
#else
    // XXX: Fall back to non-reentrant version.
    // We're holding a static mutex lock here anyway...
    pe_result = getprotobynumber(protocol);
#endif
    if (rc != 0 || pe_result == nullptr)
        result = to_string(protocol);
    else {
        if (pe_result->p_aliases != nullptr &&
          pe_result->p_aliases[0] != nullptr)
            result = pe_result->p_aliases[0];
        else {
            result = pe_result->p_name;
            transform(result.begin(), result.end(), result.begin(),
              [](unsigned char c) { return toupper(c); });
        }
        cache.insert(make_pair(protocol, result));
    }
}

int nd_glob(const string &pattern, vector<string> &results) {
    int rc;
    glob_t gr = { 0 };
    if ((rc = glob(pattern.c_str(), 0, nullptr, &gr)) == 0) {
        for (size_t i = 0; i < gr.gl_pathc; i++)
            results.push_back(gr.gl_pathv[i]);
        globfree(&gr);
    }
    else results.push_back(pattern);

    switch (rc) {
    case 0: break;
    case GLOB_NOSPACE: rc = ENOMEM; break;
    case GLOB_NOMATCH: rc = ENOENT; break;
    default: rc = EINVAL; break;
    }

    return rc;
}

time_t nd_time_monotonic(void) {
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
        throw ndExceptionSystemError(__PRETTY_FUNCTION__,
          "clock_gettime");
    }

    return ts.tv_sec;
}

void nd_tmpfile(const string &prefix, string &filename) {
    int fd;
    string path;
    vector<char> buffer;

    size_t p = prefix.find_last_of("/");
    if (p == string::npos) {
        const string temp = prefix + "XXXXXX";
        buffer.assign(temp.begin(), temp.end());
    }
    else {
        // XXX: Old glibc mkstemp can not include a path!
        path = prefix.substr(0, p);
        const string base = prefix.substr(p + 1) + "XXXXXX";
        if (chdir(path.c_str()) != 0) {
            nd_dprintf(
              "WARNING: unable to change working "
              "directory "
              "to: "
              "%s\n",
              path.c_str());
        }
        buffer.assign(base.begin(), base.end());
    }

    buffer.push_back('\0');

    filename.clear();

    if ((fd = mkstemp(&buffer[0])) < 0) {
        throw ndException("%s: mkstemp(%s): %s",
          __PRETTY_FUNCTION__, "clock_gettime", strerror(errno));
    }

    close(fd);

    if (! path.empty()) filename = path + "/";
    filename.append(buffer.begin(), buffer.end());
}

bool nd_copy_file(const string &src, const string &dst, mode_t mode) {
    ifstream ifs(src, ios::binary);
    if (! ifs.is_open()) {
        nd_dprintf("error opening source file: %s\n", src.c_str());
        return false;
    }

    ofstream ofs(dst, ofstream::trunc | ios::binary);
    if (! ofs.is_open()) {
        nd_dprintf("error opening destination file: %s\n",
          dst.c_str());
        return false;
    }

    ofs << ifs.rdbuf();

    nd_dprintf("copied file: %s -> %s\n", src.c_str(), dst.c_str());

    if (chmod(dst.c_str(), mode) != 0) {
        nd_dprintf(
          "WARNING: unable to change file permissions: "
          "%s: %s\n",
          dst.c_str(), strerror(errno));
    }

    return true;
}

void nd_time_ago(time_t seconds, string &ago) {
    string unit = "second";
    bool plural = false;
    double days = 0, hours = 0, minutes = 0;
    double value = seconds;

    if (seconds >= 86400) {
        unit = "day";
        value = days = round(seconds / 86400);
    }
    else if (seconds >= 3600) {
        unit = "hour";
        value = hours = round(seconds / 3600);
    }
    else if (seconds >= 60) {
        unit = "minute";
        value = minutes = round(seconds / 60);
    }

    if ((days && days > 1) || (hours && hours > 1) ||
      (minutes && minutes > 1))
        plural = true;
    else if (! days && ! hours && ! minutes && seconds != 1)
        plural = true;

    ago = to_string((time_t)value) + " " + unit +
      ((plural) ? "s" : "");
}

std::ostream &operator<<(std::ostream &stream, ndApp::Id id) {
    stream << static_cast<unsigned>(id);
    return stream;
}

#if defined(__linux__)
int nd_set_netns(const string &ns) {
    string path = "/var/run/netns/" + ns;

    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0)
        fd = open(ns.c_str(), O_RDONLY);
    if (fd < 0) {
        path = "/proc/" + ns + "/ns/net";
        fd = open(path.c_str(), O_RDONLY);
    }
    if (fd < 0)
        throw ndException("open: %s", strerror(errno));

    int rc = setns(fd, CLONE_NEWNET);

    close(fd);

    if (rc < 0)
        throw ndException("setns: %s", strerror(errno));

    return rc;
}

void nd_get_memusage(const string &process, size_t &vm_kb, size_t &rss_kb) {
    string pid, comm, state, ppid, pgrp, session, tty_nr;
    string tpgid, flags, minflt, cminflt, majflt, cmajflt;
    string utime, stime, cutime, cstime, priority, nice;
    string O, itrealvalue, starttime;
    size_t vsize, rss;

    ifstream ifs("/proc/" + process + "/stat", ios_base::in);
    ifs >> pid >> comm >> state >> ppid >> pgrp >> session >> tty_nr
        >> tpgid >> flags >> minflt >> cminflt >> majflt >> cmajflt
        >> utime >> stime >> cutime >> cstime >> priority >> nice
        >> O >> itrealvalue >> starttime >> vsize >> rss;

    static long page_size_kb = sysconf(_SC_PAGE_SIZE) / 1024;

    vm_kb = vsize / 1024;
    rss_kb = rss * page_size_kb;
}
#endif // __linux__

uid_t nd_get_user_id(const string &name) {
    const long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX) > 0 ?
        sysconf(_SC_GETPW_R_SIZE_MAX) : 16384;

    unique_ptr<char[]> buffer(new char[bufsize]);

    struct passwd pwd;
    struct passwd *result;
    int rc = getpwnam_r(name.c_str(),
        &pwd, buffer.get(), bufsize, &result);

    if (result == nullptr) {
        if (rc == 0) {
            throw ndException("%s: getpwnam_r(%s): %s",
                __PRETTY_FUNCTION__, name.c_str(), strerror(ENOENT));
        }

        errno = rc;
        throw ndException("%s: getpwnam_r(%s): %s",
            __PRETTY_FUNCTION__, name.c_str(), strerror(errno));
    }

    return pwd.pw_uid;
}

gid_t nd_get_group_id(const string &name) {
    const long bufsize = sysconf(_SC_GETGR_R_SIZE_MAX) > 0 ?
        sysconf(_SC_GETGR_R_SIZE_MAX) : 16384;

    unique_ptr<char[]> buffer(new char[bufsize]);

    struct group grp;
    struct group *result;
    int rc = getgrnam_r(name.c_str(),
        &grp, buffer.get(), bufsize, &result);

    if (result == nullptr) {
        if (rc == 0) {
            throw ndException("%s: getgrnam_r(%s): %s",
                __PRETTY_FUNCTION__, name.c_str(), strerror(ENOENT));
        }

        errno = rc;
        throw ndException("%s: getgrnam_r(%s): %s",
            __PRETTY_FUNCTION__, name.c_str(), strerror(errno));
    }

    return grp.gr_gid;
}

void nd_drop_privileges(const std::string &user, const std::string &group) {
#ifdef _ND_ENABLE_LIBCAP
    cap_t ctx = cap_get_proc();

    const vector<cap_value_t> caps = { CAP_NET_ADMIN, CAP_NET_RAW };

    cap_set_flag(ctx, CAP_PERMITTED, caps.size(), caps.data(), CAP_SET);

    if (cap_set_proc(ctx)) {
        throw ndException("%s: cap_set_proc(): %s",
          __PRETTY_FUNCTION__, strerror(errno));
    }

    if (prctl(PR_SET_KEEPCAPS, 1L)) {
        throw ndException("%s: prctl(PR_SET_KEEPCAPS): %s",
          __PRETTY_FUNCTION__, strerror(errno));
    }

    cap_free(ctx);
#endif // _ND_ENABLE_LIBCAP

    uid_t uid = -1;
    gid_t gid = -1;
    if (! group.empty()) gid = nd_get_group_id(group);

    if (! user.empty()) {
        uid = nd_get_user_id(user);
        initgroups(user.c_str(), gid);
    }

    if (setgid(gid) > 0) {
        throw ndException("%s: setgid(%d): %s",
          __PRETTY_FUNCTION__, gid, strerror(errno));
    }

    if (setuid(uid) > 0) {
        throw ndException("%s: setuid(%d): %s",
          __PRETTY_FUNCTION__, uid, strerror(errno));
    }

#ifdef _ND_ENABLE_LIBCAP
    ctx = cap_get_proc();
    cap_set_flag(ctx, CAP_EFFECTIVE, caps.size(), caps.data(), CAP_SET);

    if (cap_set_proc(ctx)) {
        throw ndException("%s: cap_set_proc(): %s",
          __PRETTY_FUNCTION__, strerror(errno));
    }

    cap_free(ctx);
#endif //
}

void nd_enable_coredumps(bool enable) {
    struct rlimit limit = {
        .rlim_cur = (enable) ? RLIM_INFINITY : 0,
        .rlim_max = (enable) ? RLIM_INFINITY : 0
    };

    if (setrlimit(RLIMIT_CORE, &limit) < 0) {
        nd_printf("WARNING: Unable to %s coredumps.\n",
            (enable) ? "enable" : "disable", strerror(errno));
    }
}

void ndTimeOfDay::Load(ndTimeOfDay &tod, const json &jconfig) {
    tod.valid = false;
    tod.is_epoch = false;

    // Optional: day, default: all days
    tod.days = ndTod_to_days(Day::NONE);

    if (jconfig.contains("time_start_epoch") || jconfig.contains("time_end_epoch")) {
        tod.time_start_epoch = 0;
        tod.time_end_epoch = 0;

        if (jconfig.contains("time_start_epoch")) {
            auto &v = jconfig.at("time_start_epoch");
            // Handle both "123" and 123
            tod.time_start_epoch = v.is_string() ? std::stoul(v.get<string>()) : v.get<uint32_t>();
        }

        if (jconfig.contains("time_end_epoch")) {
            auto &v = jconfig.at("time_end_epoch");
            tod.time_end_epoch = v.is_string() ? std::stoul(v.get<string>()) : v.get<uint32_t>();
        }

        tod.is_epoch = true;
        tod.valid = true;
        nd_printf("SUCCESS: Loaded Epoch Rule: %u to %u\n", tod.time_start_epoch, tod.time_end_epoch);
        return;
    }

    auto jdays = jconfig.find("day");
    if (jdays != jconfig.end()) {
        if (! jdays->is_array())
            throw ndException("day must be an array");

        for (auto &jd : *jdays) {
            if (! jd.is_string()) continue;

            string day = jd.get<string>().c_str();
            const char *d = day.c_str();

            if (strncasecmp("all", d, 3) == 0) {
                tod.days = ndTod_to_days(Day::ALL);
                break;
            }

            if (strncasecmp("sun", d, 3) == 0)
                tod.days |= ndTod_to_days(Day::SUN);
            else if (strncasecmp("mon", d, 3) == 0)
                tod.days |= ndTod_to_days(Day::MON);
            else if (strncasecmp("tue", d, 3) == 0)
                tod.days |= ndTod_to_days(Day::TUE);
            else if (strncasecmp("wed", d, 3) == 0)
                tod.days |= ndTod_to_days(Day::WED);
            else if (strncasecmp("thu", d, 3) == 0)
                tod.days |= ndTod_to_days(Day::THU);
            else if (strncasecmp("fri", d, 3) == 0)
                tod.days |= ndTod_to_days(Day::FRI);
            else if (strncasecmp("sat", d, 3) == 0)
                tod.days |= ndTod_to_days(Day::SAT);
            else
                throw ndException("invalid day of the week: %s", d);
        }
    }
    else tod.days = ndTod_to_days(Day::ALL);

    // Mandatory: time_start
    auto jtime_start = jconfig.find("time_start");
    if (jtime_start == jconfig.end())
        throw ndException("time_start not found");
    if (! jtime_start->is_string())
        throw ndException("time_start must be a string");
    tod.time_start = ParseTime(jtime_start->get<string>());

    // Mandatory: time_end
    auto jtime_end = jconfig.find("time_end");
    if (jtime_end == jconfig.end())
        throw ndException("time_end not found");
    if (! jtime_end->is_string())
        throw ndException("time_end must be a string");
    tod.time_end = ParseTime(jtime_end->get<string>());

    // Optional: policy, default: inclusive
    auto jpolicy = jconfig.find("policy");
    if (jpolicy != jconfig.end()) {
        if (! jpolicy->is_string())
            throw ndException("day must be an string: inclusive, or exclusive");

        string policy = jpolicy->get<string>();
        if (strncasecmp("inc", policy.c_str(), 3) == 0)
            tod.policy = Policy::INCLUDE;
        else if (strncasecmp("exc", policy.c_str(), 3) == 0)
            tod.policy = Policy::EXCLUDE;
        else
            throw ndException("invalid policy: %s", policy.c_str());
    }
    else tod.policy = Policy::INCLUDE;

    tod.valid = true;
}

void ndTimeOfDay::Load(ndTimeOfDay &tod,
    const string &time_start, const string &time_end,
    ndTimeOfDay::Days days, ndTimeOfDay::Policy policy) {

    tod.valid = false;

    tod.time_start = ParseTime(time_start);
    tod.time_end = ParseTime(time_end);
    tod.days = days;
    tod.policy = policy;

    if (time_start > time_end)
        throw ndException("%s: time_start > time_end", __PRETTY_FUNCTION__);

    if (time_start == time_end)
        throw ndException("%s: time_start == time_end", __PRETTY_FUNCTION__);

    tod.valid = true;
}

time_t ndTimeOfDay::ParseTime(const string &time_string) {
    size_t p1 = time_string.find_first_of(":");
    if (p1 == string::npos) {
        throw ndException(
            "%s: invalid time_string, must be 00:00[:00]",
            __PRETTY_FUNCTION__);
    }

    time_t time_hour = (time_t)strtold(
        time_string.substr(0, p1).c_str(), nullptr);

    if (time_hour > 23) {
        throw ndException(
            "%s: invalid hour (%lu > 23)",
            __PRETTY_FUNCTION__, time_hour);
    }

    size_t p2 = time_string.find(":", ++p1);

    time_t time_min;

    if (p2 == string::npos) {
        time_min = (time_t)strtold(
            time_string.substr(p1).c_str(), nullptr);
    }
    else {
        if (p2 - p1 != 2) {
            throw ndException(
                "%s: minutes must be 2 digits (%lu digits found)",
                __PRETTY_FUNCTION__, p2 - p1);
        }

        time_min = (time_t)strtold(
            time_string.substr(p1, 2).c_str(), nullptr);
    }

    if (time_min > 59) {
        throw ndException(
            "%s: invalid minute (%lu > 59)",
            __PRETTY_FUNCTION__, time_min);
    }

    time_t time_sec = 0;

    if (p2 != string::npos) {
        time_sec = (time_t)strtold(
            time_string.substr(++p2).c_str(), nullptr);

        if (time_sec > 59) {
            throw ndException(
                "%s: invalid seconds (%lu > 59)",
                __PRETTY_FUNCTION__, time_sec);
        }
    }
#if 0
    nd_dprintf("%s: %s == %lu seconds.\n",
        __PRETTY_FUNCTION__, time_string.c_str(),
        (time_hour * 3600) + (time_min * 60) + time_sec);
#endif
    return (time_hour * 3600) + (time_min * 60) + time_sec;
}

void ndTimeOfDay::Describe(const ndTimeOfDay &tod, string &desc) {
    ostringstream os;

    if (! tod.valid) os << "[invalid] ";

    if (tod.is_epoch) {
        os << "absolute range: " << tod.time_start_epoch << " to " << tod.time_end_epoch;
        desc = os.str();
        return;
    }

    os << ((tod.policy == ndTimeOfDay::Policy::INCLUDE) ?
            "within " : "outside of ");
    os << tod.time_start << "s and " << tod.time_end << "s, on:";

    if (tod.days == ndTod_to_days(Day::NONE)) os << " no days";
    else if (tod.days == ndTod_to_days(Day::ALL)) {
        os << " all days";
    }
    else {
        if (tod.days & ndTod_to_days(Day::SUN)) os << " SUN";
        if (tod.days & ndTod_to_days(Day::MON)) os << " MON";
        if (tod.days & ndTod_to_days(Day::TUE)) os << " TUE";
        if (tod.days & ndTod_to_days(Day::WED)) os << " WED";
        if (tod.days & ndTod_to_days(Day::THU)) os << " THU";
        if (tod.days & ndTod_to_days(Day::FRI)) os << " FRI";
        if (tod.days & ndTod_to_days(Day::SAT)) os << " SAT";
    }

    desc = os.str();
}

void ndTimeOfDay::UpdateTimezone(void) {
    try {
        if (timezone.empty()) {
            string tz_error;

            try {
                civil_time::timezone tz;

                timezone = tz.name();
                timezone_abbrv = tz.abbrv();
                is_dst = tz.is_dst();
                utc_offset = tz.utc_offset();

            } catch (runtime_error const &e) {
                tz_error = "runtime_error: localtime: ";
                tz_error.append(e.what());
            } catch (invalid_argument const &e) {
                tz_error = "invalid_argument: localtime: ";
                tz_error.append(e.what());
            }

            if (! tz_error.empty()) {

                nd_dprintf(
                    "WARNING: unable to set timezone: %s, trying UTC...\n",
                    tz_error.c_str());

                civil_time::timezone tz("UTC");

                timezone = tz.name();
                timezone_abbrv = tz.abbrv();
                is_dst = tz.is_dst();
                utc_offset = tz.utc_offset();
            }
        }
        else {
            civil_time::timezone tz(timezone);

            timezone = tz.name();
            timezone_abbrv = tz.abbrv();
            is_dst = tz.is_dst();
            utc_offset = tz.utc_offset();
        }
    } catch (runtime_error const &e) {
        ndException("runtime_error: %s: %s",
            timezone.empty() ? "UTC" : timezone.c_str(),
            e.what());
    } catch (invalid_argument const &e) {
        throw ndException("invalid_argument: %s: %s",
            timezone.empty() ? "UTC" : timezone.c_str(),
            e.what());
    }

    nd_dprintf("%s: %s (%s): utc_offset: %d, is_dst: %s\n",
        __PRETTY_FUNCTION__,
        timezone.empty() ? "local" : timezone.c_str(),
        timezone_abbrv.empty() ? "???" : timezone_abbrv.c_str(),
        utc_offset, (is_dst) ? "yes" : "no");
}

time_t ndTimeOfDay::TickUpdate(void) {
    time_t tv_now = nd_time_monotonic();

    if (tv_last_update + tv_update_freq < tv_now) {
            UpdateTimezone();
            tv_last_update = tv_now;
    }

    return time(nullptr) + utc_offset;
}

bool ndTimeOfDay::operator==(const time_t tv) const {
    if (! valid) return false;

    struct tm tm = { 0 };

    if (gmtime_r(&tv, &tm) != &tm) {
        throw ndException("%s: %s: %s", __PRETTY_FUNCTION__,
          "gmtime_r", strerror(errno));
    }

    if (is_epoch) {
        uint32_t true_utc_now = (uint32_t)time(nullptr);

        bool start_ok = (time_start_epoch == 0 || true_utc_now >= time_start_epoch);
        bool end_ok = (time_end_epoch == 0 || true_utc_now <= time_end_epoch);
        bool epoch_match = (start_ok && end_ok);

        /*
        nd_dprintf("Epoch Check: Rule[%u-%u] vs SystemUTC[%u]. Match: %s\n",
                    time_start_epoch, time_end_epoch, true_utc_now,
                    (start_ok && end_ok) ? "YES" : "NO");
        */

        // If the days map is NONE, the epoch check is the final answer.
        if (days == ndTod_to_days(Day::NONE)) {
          return epoch_match;
        }

        // Otherwise, if we ARE using a schedule, but the epoch check failed,
        // we should stop here because the "master window" is closed.
        if (!epoch_match) {
            return false;
        }
    }

    if (days == ndTod_to_days(Day::NONE)) return false;

    if (days != ndTod_to_days(Day::ALL)) {
        switch (tm.tm_wday) {
        case 0:
            if (policy == Policy::INCLUDE && ! (days & ndTod_to_days(Day::SUN)))
                return false;
            if (policy == Policy::EXCLUDE && (days & ndTod_to_days(Day::SUN)))
                return false;
            break;
        case 1:
            if (policy == Policy::INCLUDE && ! (days & ndTod_to_days(Day::MON)))
                return false;
            if (policy == Policy::EXCLUDE && (days & ndTod_to_days(Day::MON)))
                return false;
            break;
        case 2:
            if (policy == Policy::INCLUDE && ! (days & ndTod_to_days(Day::TUE)))
                return false;
            if (policy == Policy::EXCLUDE && (days & ndTod_to_days(Day::TUE)))
                return false;
            break;
        case 3:
            if (policy == Policy::INCLUDE && ! (days & ndTod_to_days(Day::WED)))
                return false;
            if (policy == Policy::EXCLUDE && (days & ndTod_to_days(Day::WED)))
                return false;
            break;
        case 4:
            if (policy == Policy::INCLUDE && ! (days & ndTod_to_days(Day::THU)))
                return false;
            if (policy == Policy::EXCLUDE && (days & ndTod_to_days(Day::THU)))
                return false;
            break;
        case 5:
            if (policy == Policy::INCLUDE && ! (days & ndTod_to_days(Day::FRI)))
                return false;
            if (policy == Policy::EXCLUDE && (days & ndTod_to_days(Day::FRI)))
                return false;
            break;
        case 6:
            if (policy == Policy::INCLUDE && ! (days & ndTod_to_days(Day::SAT)))
                return false;
            if (policy == Policy::EXCLUDE && (days & ndTod_to_days(Day::SAT)))
                return false;
            break;
        }
    }

    tm.tm_sec = tm.tm_min = tm.tm_hour = 0;

    time_t tv_today = timegm(&tm);
    if (tv_today == (time_t)-1) {
        throw ndException(
            "%s: timegm: %s", __PRETTY_FUNCTION__, strerror(errno));
    }

    time_t tv_seconds = tv - tv_today;

    if (policy == Policy::INCLUDE &&
        (tv_seconds < time_start || tv_seconds > time_end)) return false;

    if (policy == Policy::EXCLUDE &&
        tv_seconds >= time_start && tv_seconds <= time_end) return false;

    return true;
}

string nd_change_ext(const string &filename, const string &ext) {
    size_t p;
    string result(filename);

    if ((p = filename.find_last_of(".")) != string::npos)
        result = filename.substr(0, p + 1) + ext;

    return result;
}

bool nd_has_expired(const string &tag,
  time_t ttl, time_t last_update, bool monotonic, time_t now) {

    if (last_update == 0) return true;

    time_t delta = (now ? now :
      (monotonic ? nd_time_monotonic() : time(nullptr))) - last_update;
    bool expired = (delta > ttl);
#if 0
    nd_dprintf("%s: expired (delta: %lus > ttl: %lus)? %s\n", tag.c_str(),
        delta, ttl, (expired) ? "yes" : "no");
#endif
    return expired;
}
