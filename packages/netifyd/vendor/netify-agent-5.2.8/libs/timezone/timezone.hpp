//
// timezone.hpp
//
// Bill Seymour, 2024-03-29
//
// Copyright Bill Seymour 2024.
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
// This is the header for the timezone and tz_data classes, the latter
// a structure that can hold one of zoneinfo's binary files, a private
// data member of the timezone class; but there's no reason it couldn't
// be a stand-alone class as well.
//
// Also declared are functions to get the local machine's TZ and TZ_ROOT
// environment variables.
//
// All the functions are defined in timezone.cpp.
//

#ifndef TIMEZONE_HPP_INCLUDED
#define TIMEZONE_HPP_INCLUDED

#include <string>
#include <utility> // swap (also std::move in most TUs)
#include <mutex>   // call_once

#include <cstdint> // int32_t, int64_t
#include <climits>
#include <ctime>

static_assert(sizeof(std::time_t) * CHAR_BIT >= 64, "64-bit time_t required");

namespace civil_time {

using std::swap;

const std::string& get_tz() noexcept;
void set_tz(const char*);
void set_tz(const std::string&);
void set_tz(std::string&&);

const std::string& get_tz_root() noexcept;
void set_tz_root(const char*);
void set_tz_root(const std::string&);
void set_tz_root(std::string&&);

namespace zoneinfo {

typedef std::int32_t tz_int;
typedef std::int64_t tz_time;

struct tz_data final
{
  #pragma pack(4)
    struct header
    {
        char   version[20];
        tz_int tzh_ttisgmtcnt;
        tz_int tzh_ttisstdcnt;
        tz_int tzh_leapcnt;
        tz_int tzh_timecnt;
        tz_int tzh_typecnt;
        tz_int tzh_charcnt;
    };
    header hdr;
  #pragma pack()

    tz_time* trans_times;
    unsigned char* info_idx;

  #pragma pack(2)
  // There's no padding in zoneinfo's binary files.
    struct ttinfo
    {
        tz_int        tt_gmtoff;
        unsigned char tt_isdst;
        unsigned char tt_abbrind;
    };
  #pragma pack()
    ttinfo* info;
    char* abbrv;

  #pragma pack(4)
    struct leapsecs
    {
        tz_time leap;
        tz_int  cnt;
    };
    leapsecs* leaps;
  #pragma pack()

    char* stdind;
    char* utcind;
    char* tzenv;

    //
    // Not from a TZif file...created by the make_posix() function:
    //
    struct tzrule
    {
        int mo, wc /*week count*/, wd /*weekday*/, jd /*Julian day*/,
            hr, mn, sc;
        tzrule() noexcept;
        tzrule(const std::tm&) noexcept;
        int compare(const tzrule&) const noexcept;
    };
    tzrule* tzrules;

private:
    void free_arrays() noexcept;
    void cleanup() noexcept;
    void clear_header() noexcept;
public:
    void clear() noexcept
    {
        free_arrays();
        cleanup();
    }
    void all_clear() noexcept
    {
        clear();
        clear_header();
    }

    tz_data() noexcept;
    ~tz_data() noexcept { free_arrays(); }

    tz_data(const tz_data&);
    tz_data(tz_data&&) noexcept;

    tz_data& operator=(const tz_data&);
    tz_data& operator=(tz_data&&) noexcept;

    void swap(tz_data&) noexcept;

    tz_data& read(const std::string&);
    std::string make_posix(const std::string&);

    static std::string get_posix_tz(const std::string&);
};

using std::swap;
inline void swap(tz_data& lhs, tz_data& rhs) noexcept
{
    lhs.swap(rhs);
}

} // namespace zoneinfo

//----------------------------------------------------------------------------

class timezone
{
    zoneinfo::tz_data data;

    std::string nam;
    std::time_t tt = LLONG_MIN;
    zoneinfo::tz_data::ttinfo* info_ptr = nullptr;
    zoneinfo::tz_int stdoff = INT_MIN, dstoff = INT_MIN;

    int  find_time_t() const noexcept;
    void new_time_t() noexcept;
    void load_TZif();
    void make_fixed(int, int, int);
    void make_offsets() noexcept;

public:
    timezone();
    explicit timezone(int, int = 0, int = 0);
    explicit timezone(const std::string&);
    explicit timezone(std::string&&);

    virtual ~timezone() noexcept { } // virtual so it can be safely inherited

    timezone(const timezone&) = default;
    timezone(timezone&&) = default;

    timezone& operator=(const timezone&) = default;
    timezone& operator=(timezone&&) = default;

    void swap(timezone&);

    timezone& switch_to_local();
    timezone& switch_to_offset(int, int = 0, int = 0);
    timezone& switch_to_utc() { return switch_to_offset(0); }
    timezone& switch_to(const std::string&);
    timezone& switch_to(std::string&&);

    timezone& for_time(std::time_t) noexcept;

    const std::string& name() const noexcept { return nam; }

    std::string posix_tz_env_var() const;
    static std::string posix_tz_env_var(const std::string& zone)
    {
        return zoneinfo::tz_data::get_posix_tz(zone);
    }

    std::time_t effective_time() const noexcept { return tt; }

    int std_offset() const noexcept { return stdoff; }
    int dst_offset() const noexcept { return dstoff; }

    const zoneinfo::tz_data& raw_data() const noexcept { return data; }

    enum class trans_type { unknown = -1, wall, std, utc };
    trans_type transition_type() const noexcept;

    int utc_offset() const noexcept;
    bool is_dst() const noexcept;
    const char* abbrv() const noexcept;
};

inline void swap(timezone& lhs, timezone& rhs)
{
    lhs.swap(rhs);
}

} // namespace civil_time

#endif // TIMEZONE_HPP_INCLUDED
