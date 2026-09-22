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

#include <array>
#include <atomic>
#include <cstddef>
#include <ctime>
#include <exception>
#include <iomanip>
#include <list>
#include <map>
#include <mutex>
#include <queue>
#include <regex>
#include <sstream>
#include <type_traits>
#include <unordered_map>
#include <vector>

#include <sys/socket.h>
#include <sys/stat.h>

#if defined(__APPLE__)
#include <dispatch/dispatch.h>
#endif

#include <sched.h>

#include <nlohmann/json.hpp>

#include "nd-except.hpp"
#include "nd-sha1.h"
#include "nd-types.hpp"

constexpr unsigned ND_SHA1_BUFFER = 4096;

constexpr size_t ND_XXH64_DIGEST_LENGTH_STR = 16;

typedef uint64_t ndDigest;

typedef std::array<uint8_t, SHA1_DIGEST_LENGTH> ndDigestSHA1;
typedef std::vector<uint8_t> ndDigestDynamic;

namespace ndTerm {

class Attr
{
public:
    static const char *RESET;
    static const char *CURSOR_HIDE;
    static const char *CURSOR_SHOW;
    static const char *CLEAR_EOL;
    static const char *BOLD;
    static const char *UNDERLINE;
};

class Color
{
public:
    static const char *RED;
    static const char *GREEN;
    static const char *YELLOW;
};

class Icon
{
public:
    static const char *INFO;
    static const char *OK;
    static const char *WARN;
    static const char *FAIL;
    static const char *NOTE;
    static const char *RARROW;
};

bool IsTTY(void);

}  // namespace ndTerm

constexpr const char *_ND_LOG_FILE_STAMP = "%Y%m%d-%H%M%S";
constexpr size_t _ND_LOG_FILE_STAMP_SIZE = sizeof(
  "YYYYMMDD-HHMMSS");

#define ndEnumCast(T, n) \
    static_cast<typename std::underlying_type<T>::type>(T::n)

class ndLogBuffer : public std::streambuf
{
public:
    int overflow(int ch = EOF);
    virtual int sync();

protected:
    std::ostringstream os;
};

class ndDebugLogBuffer : public ndLogBuffer
{
public:
    virtual int sync();
};

class ndDebugLogBufferUnlocked : public ndLogBuffer
{
public:
    virtual int sync();
};

class ndDebugLogBufferFlow : public ndLogBuffer
{
public:
    virtual int sync();
};

class ndLogStream : public std::ostream
{
public:
    ndLogStream() : std::ostream(new ndLogBuffer) { }

    virtual ~ndLogStream() {
        delete reinterpret_cast<ndLogBuffer *>(rdbuf());
    }
};

class ndDebugLogStream : public std::ostream
{
public:
    enum class Type : uint8_t {
        NONE,
        UNLOCKED,
        FLOW,
    };

    ndDebugLogStream(Type type = Type::NONE)
      : std::ostream((type == Type::NONE) ?
            new ndDebugLogBuffer :
            ((type == Type::UNLOCKED) ?
                reinterpret_cast<std::streambuf *>(new ndDebugLogBufferUnlocked) :
                reinterpret_cast<std::streambuf *>(
                  new ndDebugLogBufferFlow))),
        type(type) {
        imbue(std::locale());
    }

    virtual ~ndDebugLogStream() {
        switch (type) {
        case Type::NONE:
            delete reinterpret_cast<ndDebugLogBuffer *>(rdbuf());
            break;
        case Type::UNLOCKED:
            delete reinterpret_cast<ndDebugLogBufferUnlocked *>(
              rdbuf());
            break;
        case Type::FLOW:
            delete reinterpret_cast<ndDebugLogBufferFlow *>(rdbuf());
            break;
        }
    }

private:
    Type type;
};

class ndLogFormat
{
public:
    enum class Format : uint8_t {
        NONE,
        BYTES,
        PACKETS,
        PERCENT,
    };

    ndLogFormat(Format format, float value, int width = 0,
      int precision = 3)
      : format(format), value(value), width(width),
        precision(precision){};

    friend std::ostream &
    operator<<(std::ostream &os, const ndLogFormat &f) {
        std::ios old_state(nullptr);
        old_state.copyfmt(os);
        os << std::setw(f.width) << std::setprecision(f.precision);

        switch (f.format) {
        case Format::BYTES:
            if (f.value >= 1099511627776.0f) {
                os << (f.value / 1099511627776.0f)
                   << std::setw(0) << " TiB";
            }
            else if (f.value >= 1073741824.0f) {
                os << (f.value / 1073741824.0f) << std::setw(0) << " GiB";
            }
            else if (f.value >= 1048576.0f) {
                os << (f.value / 1048576.0f) << std::setw(0) << " MiB";
            }
            else if (f.value >= 1024.0f) {
                os << (f.value / 1024.0f) << std::setw(0) << " KiB";
            }
            else {
                os << f.value;
            }
            break;

        case Format::PACKETS:
            if (f.value >= 1000000000000.0f) {
                os << (f.value / 1000000000000.0f)
                   << std::setw(0) << " TP";
            }
            else if (f.value >= 1000000000.0f) {
                os << (f.value / 1000000000.0f) << std::setw(0) << " GP";
            }
            else if (f.value >= 1000000.0f) {
                os << (f.value / 1000000.0f) << std::setw(0) << " MP";
            }
            else if (f.value >= 1000.0f) {
                os << (f.value / 1000.0f) << std::setw(0) << " KP";
            }
            else {
                os << f.value;
            }
            break;

        case Format::PERCENT:
            os << f.value << " "
               << "%";
            break;
        default: os << f.value; break;
        }

        os.copyfmt(old_state);
        return os;
    }

protected:
    const Format format;
    const float value;
    const int width;
    const int precision;
};

void nd_output_lock(void);
void nd_output_unlock(void);

void nd_printf(const char *format, ...);
void nd_printf(const char *format, va_list ap);
void nd_dprintf(const char *format, ...);
void nd_dprintf(const char *format, va_list ap);
void nd_flow_printf(const char *format, ...);

void nd_ltrim(std::string &s, unsigned char c = 0);
void nd_rtrim(std::string &s, unsigned char c = 0);
void nd_trim(std::string &s, unsigned char c = 0);

int nd_xxh64_file(const std::string &filename, ndDigest &digest);
int nd_sha1_file(const std::string &filename, ndDigestSHA1 &digest);

uint64_t nd_xxh64(const void *input, size_t length, uint64_t seed = 0);

void nd_xxh64_to_string(const ndDigest &digest, std::string &digest_str);
void nd_sha1_to_string(const ndDigestSHA1 &digest, std::string &digest_str);
void nd_sha1_to_string(const ndDigestDynamic &digest, std::string &digest_str);

bool nd_string_to_xxh64(const std::string &digest_str, ndDigest &digest);
bool nd_string_to_sha1(const std::string &digest_str, ndDigestDynamic &digest);

bool nd_string_to_mac(const std::string &src, uint8_t *mac);
sa_family_t nd_string_to_ip(const std::string &src, sockaddr_storage *ip);
bool nd_ip_to_string(sa_family_t af, const void *addr, std::string &dst);
bool nd_ip_to_string(const sockaddr_storage &ip, std::string &dst);

void nd_json_to_string(
  const nlohmann::json &j, std::string &output, bool pretty = false);
void nd_ordered_json_to_string(
  const nlohmann::ordered_json &j, std::string &output, bool pretty = false);

uint8_t nd_netmask_to_prefix(const struct sockaddr_storage *netmask);
uint8_t nd_netmask_to_prefix(const std::string &netmask);

bool nd_is_ipaddr(const char *ip);

void nd_private_ipaddr(uint8_t index, struct sockaddr_storage &addr);

bool nd_load_uuid(
  std::string &uuid, const std::string &path, size_t length);
bool nd_save_uuid(
  const std::string &uuid, const std::string &path, size_t length);

void nd_seed_rng(void);

void nd_generate_uuid(std::string &uuid);

const char *nd_get_version(void);
const std::string &nd_get_version_and_features(bool fancy = false);

bool nd_parse_app_tag(const std::string &tag, unsigned &id,
  std::string &name);

int nd_touch(const std::string &filename);

int nd_file_load(const std::string &filename, std::string &data);

void nd_file_save(const std::string &filename,
  const std::string &data, bool append = false,
  mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP,
  const char *user = NULL, const char *group = NULL);

int nd_ifreq(const std::string &name, unsigned long request,
  struct ifreq *ifr);

void nd_basename(const std::string &path, std::string &base);
void nd_pathname(const std::string &path, std::string &base);

pid_t nd_is_running(pid_t pid, const std::string &exe_base);
pid_t nd_load_pid(const std::string &pidfile);
int nd_save_pid(const std::string &pidfile, pid_t pid);

int nd_file_exists(const std::string &path);
int nd_dir_exists(const std::string &path);

void nd_uptime(time_t ut, std::string &uptime);

int nd_functions_exec(const std::string &func,
  const std::string &arg, std::string &output);

void nd_os_detect(std::string &os);

class ndLogDirectory
{
public:
    ndLogDirectory(const std::string &path, const std::string &prefix,
      const std::string &suffix, bool overwrite = false);
    virtual ~ndLogDirectory();

    FILE *Open(const std::string &ext = "");
    void Close(void);
    void Discard(void);

protected:
    std::string path;
    std::string prefix;
    std::string suffix;

    bool overwrite;

    FILE *hf_cur;
    std::string filename;
};

void nd_regex_error(const std::regex_error &e, std::string &error);

bool nd_scan_dotd(const std::string &path, std::vector<std::string> &files);
bool nd_get_dotd_tag(const std::string &filename, std::string &tag);

void nd_set_hostname(std::string &dst, bool strict = true);
void nd_set_hostname(std::string &dst, const char *src,
  size_t length, bool strict = true);
void nd_set_hostname(char *dst, const char *src,
  size_t length, bool strict = true);

void nd_expand_variables(const std::string &input,
  std::string &output, std::map<std::string, std::string> &vars);

void nd_gz_inflate(size_t length, const uint8_t *data,
  std::vector<uint8_t> &output);
void nd_gz_deflate(size_t length, const uint8_t *data,
  std::vector<uint8_t> &output);

class ndTimer
{
public:
    ndTimer(void) : sig(-1), valid(false), id(nullptr) { }
    virtual ~ndTimer() { Reset(); }

    void Create(int sig);
    void Reset(void);

    void Set(const struct itimerspec &itspec);

    inline bool IsValid(void) const { return valid; }
    inline int GetSignal(void) const { return sig; }

protected:
    int sig;
    bool valid;
#if defined(__APPLE__)
    dispatch_source_t id;
#else
    timer_t id;
#endif
};

class ndCPUSet
{
public:
    ndCPUSet(bool empty = false);
    ndCPUSet(const std::string &cpu_list);

    void Get(cpu_set_t &cpu_set);

    std::vector<int> cpu_set;
};

void nd_get_ip_protocol_name(int protocol, std::string &result);

int nd_glob(const std::string &pattern,
  std::vector<std::string> &results);

time_t nd_time_monotonic(void);

void nd_tmpfile(const std::string &prefix, std::string &filename);

bool nd_copy_file(const std::string &src, const std::string &dst,
  mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP);

void nd_time_ago(time_t seconds, std::string &ago);

template <typename K, typename V = K>
class ndLRUCache
{
public:
    class CacheStats
    {
    public:
        std::atomic<uint64_t> insert_hit = { 0 };
        std::atomic<uint64_t> insert_miss = { 0 };
        std::atomic<uint64_t> lookup_hit = { 0 };
        std::atomic<uint64_t> lookup_miss = { 0 };
    };

    CacheStats stats;

    ndLRUCache(size_t max_size, bool lockable = false)
      : max_size(max_size), lockable(lockable) {
        if (! max_size)
            throw ndException(
              "maxiumum LRU cache size cannot be zero");
    }

    size_t GetSize(void) const {
        if (lockable) {
            std::lock_guard<std::mutex> lg(lock);
            return kvmap.size();
        }
        return kvmap.size();
    }

    void Encode(nlohmann::json &jstats) const {
        size_t cache_size = 0;

        if (lockable) {
            std::lock_guard<std::mutex> lg(lock);
            cache_size = kvmap.size();
        }

        uint64_t insert_hit = stats.insert_hit;
        uint64_t insert_miss = stats.insert_miss;
        uint64_t insert_total = insert_hit + insert_miss;

        float insert_hit_pct = 0;
        if (insert_total > 0) {
            insert_hit_pct = 100.0f * (float)insert_hit /
              (float)insert_total;
        }

        uint64_t lookup_hit = stats.lookup_hit;
        uint64_t lookup_miss = stats.lookup_miss;
        uint64_t lookup_total = lookup_hit + lookup_miss;

        float lookup_hit_pct = 0;
        if (lookup_total > 0) {
            lookup_hit_pct = 100.0f * (float)lookup_hit /
              (float)lookup_total;
        }

        jstats["cache_size"] = cache_size;
        jstats["insert_hit"] = insert_hit;
        jstats["insert_hit_pct"] = insert_hit_pct;
        jstats["insert_miss"] = insert_miss;
        jstats["lookup_hit"] = lookup_hit;
        jstats["lookup_hit_pct"] = lookup_hit_pct;
        jstats["lookup_miss"] = lookup_miss;
    }

    void Scoreboard(const std::string &tag) const {
        size_t cache_size = 0;
        uint64_t insert_hit = 0;
        float insert_hit_pct = 0.0;
        uint64_t insert_miss = 0;
        uint64_t insert_total = 0;
        uint64_t lookup_hit = 0;
        float lookup_hit_pct = 0;
        uint64_t lookup_miss = 0;
        uint64_t lookup_total = 0;

        try {
            nlohmann::json jstats;
            Encode(jstats);

            cache_size = jstats["cache_size"].get<unsigned>();
            insert_hit = jstats["insert_hit"].get<uint64_t>();
            insert_hit_pct = jstats["insert_hit_pct"].get<float>();
            insert_miss = jstats["insert_miss"].get<uint64_t>();
            insert_total = insert_hit + insert_miss;
            lookup_hit = jstats["lookup_hit"].get<uint64_t>();
            lookup_hit_pct = jstats["lookup_hit_pct"].get<float>();
            lookup_miss = jstats["lookup_miss"].get<uint64_t>();
            lookup_total = lookup_hit + lookup_miss;
        }
        catch (nlohmann::json::exception &e) {
            nd_dprintf(
              "%s: error decoding JSON status: %s\n",
              tag.c_str(), e.what());
            return;
        }

        nd_dprintf(
          "%s entries: %lu, inserts: %lu (%.01f%%), "
          "lookups: %lu (%.01f%%)\n",
          tag.c_str(), cache_size, insert_total,
          insert_hit_pct, lookup_total, lookup_hit_pct);
    }

    void Prune(time_t ttl) {
        std::unique_lock<std::mutex> lg(lock, std::defer_lock);

        if (lockable) lg.lock();

        time_t now = time(nullptr);

        for (auto it = kvmap.begin(); it != kvmap.end(); ) {
            if (now - it->second.timestamp >= ttl) {
                entries.erase(it->second.it);
                it = kvmap.erase(it);
            } else {
                ++it;
            }
        }
    }

protected:
    void CacheInsert(const K &key, const V &value,
      bool update = false) {
        std::unique_lock<std::mutex> lg(lock, std::defer_lock);

        if (lockable) lg.lock();

        auto i = kvmap.find(key);
        if (i == kvmap.end()) {
            stats.insert_miss++;

            entries.push_front(key);
            kvmap[key] = { value, time(nullptr), entries.begin() };

            while (kvmap.size() > max_size) {
                kvmap.erase(entries.back());
                entries.pop_back();
            }
        }
        else {
            stats.insert_hit++;

            entries.erase(i->second.it);
            entries.push_front(key);

            i->second.it = entries.begin();
            i->second.timestamp = time(nullptr);
            if (update) i->second.value = value;
        }
    }

    bool CacheLookup(const K key, V &value) {
        std::unique_lock<std::mutex> lg(lock, std::defer_lock);

        if (lockable) lg.lock();

        auto i = kvmap.find(key);
        if (i == kvmap.end()) {
            stats.lookup_miss++;
            return false;
        }

        stats.lookup_hit++;

        entries.erase(i->second.it);
        entries.push_front(key);

        i->second.it = entries.begin();
        i->second.timestamp = time(nullptr);

        value = i->second.value;

        return true;
    }

    size_t max_size;
    bool lockable;

    mutable std::mutex lock;

    struct CacheEntry {
        V value;
        time_t timestamp;
        typename std::list<K>::iterator it;
    };

    std::list<K> entries;
    std::unordered_map<K, CacheEntry> kvmap;
};

struct ndEnumHasher {
    template <class T>
    inline void hash_combine(size_t &seed, const T &v) const {
        std::hash<T> hasher;
        seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    }

    template <class T>
    size_t operator()(const T &v) const {
        size_t ss_hash = 0;

        hash_combine<unsigned>(ss_hash, static_cast<unsigned>(v));

        return ss_hash;
    }
};

struct ndArrayHasher {
    template <class T, size_t N>
    std::size_t operator()(const std::array<T, N>& a) const {
        std::hash<T> hasher;
        std::size_t ss_hash = 0;
        for (const auto& e : a) {
            ss_hash ^= hasher(e) + 0x9e3779b9 + (ss_hash << 6) + (ss_hash >> 2);
        }

        return ss_hash;
    }
};

std::ostream &operator<<(std::ostream &stream, ndApp::Id id);

#if defined(__linux__)
int nd_set_netns(const std::string &ns);
#endif

inline void nd_sprintf(std::string &dst, const char *format) {
    dst.assign(format);
}

template<typename... Args>
void nd_sprintf(std::string &dst, const char *format, Args... args) {
    int length = std::snprintf(nullptr, 0, format, args...);
    if (length == 0)
        throw ndException("format string is zero length");

    char *buffer = new char[length + 1];
    std::snprintf(buffer, length + 1, format, args...);

    dst.assign(buffer);
    delete[] buffer;
}

#if defined(__linux__)
void nd_get_memusage(const std::string &process, size_t &vm_kb, size_t &rss_kb);
#endif

uid_t nd_get_user_id(const std::string &name);
gid_t nd_get_group_id(const std::string &name);

void nd_drop_privileges(const std::string &user, const std::string &group);

void nd_enable_coredumps(bool enable = true);

#define ndTod_to_days(days) static_cast<ndTimeOfDay::Days>(days)
#define ndTod_to_policy(policy) static_cast<uint8_t>(policy)

class ndTimeOfDay {
public:
    typedef uint8_t Days;

    enum class Day : Days {
        NONE = 0,
        SUN = (1 << 0),
        MON = (1 << 1),
        TUE = (1 << 2),
        WED = (1 << 3),
        THU = (1 << 4),
        FRI = (1 << 5),
        SAT = (1 << 6),
        ALL = (SUN | MON | TUE | WED | THU | FRI | SAT),
    };

    enum class Policy : uint8_t {
        INCLUDE,
        EXCLUDE
    };

    ndTimeOfDay(time_t tv_update_freq, const std::string &timezone = "") {
        SetTimezone(tv_update_freq, timezone);
    }

    ndTimeOfDay(const nlohmann::json &jconfig) {
        Load(*this, jconfig);
    }
    ndTimeOfDay(
        const std::string &time_start = "00:00",
        const std::string &time_end = "23:59",
        Days days = ndTod_to_days(Day::ALL),
        Policy policy = Policy::INCLUDE) {
        Load(*this, time_start, time_end, days, policy);
    }

    bool is_epoch = false;
    uint32_t time_start_epoch = 0;
    uint32_t time_end_epoch = 0;

    static void Load(ndTimeOfDay &tod,
        const nlohmann::json &jconfig);
    static void Load(ndTimeOfDay &tod,
        const std::string &time_start = "00:00",
        const std::string &time_end = "23:59",
        Days days = ndTod_to_days(Day::ALL),
        Policy policy = Policy::INCLUDE);

    static time_t ParseTime(const std::string &time_string);

    static void Describe(const ndTimeOfDay &tod, std::string &desc);

    void SetTimezone(time_t tv_update_freq, const std::string &timezone) {
        tv_last_update = 0;
        this->tv_update_freq = tv_update_freq;
        this->timezone = timezone;

        TickUpdate();
    }

    void UpdateTimezone(void);

    time_t TickUpdate(void);

    bool operator==(const time_t tv) const;
    bool operator!=(const time_t tv) const {
        return (! ((*this) == tv));
    }

    bool valid = { false };
    time_t time_start = { 0 };
    time_t time_end = { 3600 * 23 + 59 };
    Days days = { ndTod_to_days(Day::ALL) };
    Policy policy = { Policy::INCLUDE };
    time_t tv_update_freq = { 0 };
    time_t tv_last_update = { 0 };
    time_t tv_tick = { 0 };
    std::string timezone;
    std::string timezone_abbrv;
    bool is_dst = { false };
    int utc_offset = { 0 };
};

std::string nd_change_ext(const std::string &filename, const std::string &ext);

bool nd_has_expired(const std::string &tag,
  time_t ttl, time_t last_update, bool monotonic = true, time_t now = 0);

#ifdef _ND_DEBUG_ALLOCATOR

template<class Tp>
struct ndDebugAllocator
{
    typedef Tp value_type;
    size_t allocated = { 0 };
    size_t allocations = { 0 };

    ndDebugAllocator() = default;

    template<class T> ndDebugAllocator(const ndDebugAllocator<T>&) { }

    Tp* allocate(std::size_t n) {
        n *= sizeof(Tp);
        allocated += n;
        nd_dprintf("%p: allocated %lu bytes, total: %lu\n",
          this, n, allocated);

        return static_cast<Tp*>(::operator new(n));
    }

    void deallocate(Tp* p, std::size_t n) {
        n *= sizeof(Tp);
        allocated -= n;
        nd_dprintf("%p: deallocated %lu bytes, total: %lu\n",
          this, n, allocated);

        ::operator delete(p);
    }
};

template<class T, class U>
bool operator==(const ndDebugAllocator<T>&, const ndDebugAllocator<U>&) {
    return true;
}
template<class T, class U>
bool operator!=(const ndDebugAllocator<T>&, const ndDebugAllocator<U>&) {
    return false;
}

#endif // _ND_DEBUG_ALLOCATOR

template<class T, size_t N>
class ndLeanQueueAdapter
{
private:
#ifdef _ND_DEBUG_ALLOCATOR
    std::deque<T, ndDebugAllocator<T>> q;
#else
    std::deque<T> q;
#endif
    size_t pop_count = { 0 };

public:
    using const_reference = const T&;
    using reference = T&;
    using size_type = std::size_t;
    using value_type = T;

    bool empty() const noexcept{
        return q.empty();
    }

    size_t size() const noexcept{
        return q.size();
    }

    T& front() noexcept{
        return q.front();
    }

    const T& front() const noexcept{
        return q.front();
    }

    T& back() noexcept{
        return q.back();
    }

    const T& back() const noexcept{
        return q.back();
    }

    void push_back(const T& t) {
        return q.push_back(t);
    }

    void push_back(T&& t) {
        return q.push_back(std::move(t));
    }

    void pop_front() {
        q.pop_front();

        if (++pop_count % N == 0U) {
            q.shrink_to_fit();
            nd_dprintf("queue shrink_to_fit @ %lu pops.\n", pop_count);
        }
    }
};
