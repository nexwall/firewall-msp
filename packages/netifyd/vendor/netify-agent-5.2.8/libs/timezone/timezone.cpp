//
// timezone.cpp
//
// Bill Seymour, 2024-03-29
//
// Copyright Bill Seymour 2024.
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
// This TU implements the timezone class declared in
// timezone.hpp along with some undocumented helpers.
//

#include "timezone.hpp" // #includes <string>, <utility>, <ctime>
#include "timezone_config.hpp"

#include <iostream>
#include <fstream>

#ifndef NDEBUG
#include <iomanip> // for tracing
#endif

#include <cstring> // strlen, memcpy
#include <cstddef> // size_t, ptrdiff_t
#ifdef CIVIL_TIME_USE_GETENV
  #include <cstdlib>
#endif
#include <cassert>

#ifdef _MSC_VER
  // MSVC warns that getenv() and localtime() are unsafe,
  // suggests vendor lock-in alternatives.
  #pragma warning(disable:4996)
#endif

namespace {

using std::string;
using std::size_t;
using std::time_t;
using std::memcpy;

using civil_time::zoneinfo::tz_int;
using civil_time::zoneinfo::tz_time;

#if defined(CIVIL_TIME_USE_NAME_XLATE) || defined(CIVIL_TIME_USE_LINK_XLATE)
    //
    // We might need to translate one C-style string to another.
    //
    // We'll pass the following function a two-dimensional array of strings
    // with initializers that look like {"foo","bar"}.  They'll be sorted
    // by the [][0] string, so we'll do a binary search.
    //
    char const * xlate(char const * const translations[][2],
                       size_t ntrans,
                       char const * const target)
    {
        for (size_t beg = 0, end = ntrans; beg < end; )
        {
            size_t mid = (beg + end) / 2;

            int cmp = std::strcmp(target, translations[mid][0]);

            if (cmp == 0)
            {
                return translations[mid][1];
            }
            if (cmp < 0)
            {
                end = mid;
            }
            else
            {
                beg = mid + 1;
            }
        }

        // If not found, target might be correct.
        return target;
    }
#endif

#ifdef CIVIL_TIME_USE_NAME_XLATE
    //
    // When we don't have the TZif files, or when the user requests it,
    // when constructing a timezone from a Zoneinfo binary fails, we'll
    // look up the zone's POSIX-style TZ variable and try to construct
    // a timezone from that.
    //
    string xlate_name(const string& fn)
    {
        static char const * const trans[][2] =
        {
            #include "tz_names_xlate.inc"
        };
        static constexpr size_t ntrans = sizeof trans / sizeof trans[0];

        const char* target = fn.c_str();
        const char* result = xlate(trans, ntrans, target);

        return result != target && std::strcmp(result, target) != 0 ?
                   string(result) : fn;
    }
#else
    //
    // When compiling for Linux and in-memory translation is not explicitly
    // requested, we'll call tz_data's static get_posix() function which
    // reads the appropriate TZif file to get the POSIX TZ string.
    //
    #define xlate_name(s) civil_time::zoneinfo::tz_data::get_posix_tz(s)
#endif

#ifdef CIVIL_TIME_USE_LINK_XLATE
    //
    // When we don't have the TZif files, or if the user requests it,
    // we'll want to translate Link names to real Zone names.  If not found,
    // the argument isn't a Link name, so no translation is required.
    //
    string xlate_link(const string& fn)
    {
        static char const * const trans[][2] =
        {
            #include "tz_links_xlate.inc"
        };
        static constexpr size_t ntrans = sizeof trans / sizeof trans[0];

        return string(xlate(trans, ntrans, fn.c_str()));
    }
#else
    //
    // When compiling for Linux and in-memory translation is not explicitly
    // requested, we just use the filesystem's existing symbolic links.
    //
    #define xlate_link(s) s
#endif

//
// Values that might be stored in POSIX' TZ and TZ_ROOT environment variables:
//
#ifdef CIVIL_TIME_TZ
  string tz(CIVIL_TIME_TZ);
#else
  string tz;
#endif

#ifdef CIVIL_TIME_TZ_ROOT
  string tz_root(CIVIL_TIME_TZ_ROOT);
#else
  string tz_root;
#endif

#ifdef CIVIL_TIME_USE_GETENV
    //
    // Here's a singleton that eagerly initializes the tz and tz_root strings
    // by calling getenv() before anything else happens in this TU.
    //
    // It's not technically the poltergeist anti-pattern since it doesn't get
    // destructed until the end of the complete program; but from the user's
    // point of view, it is occult. 8-)
    //
    struct tzinit
    {
        tzinit();
        ~tzinit() = default;
        tzinit(const tzinit&) = delete;
        tzinit(tzinit&&) = delete;
        tzinit& operator=(const tzinit&) = delete;
        tzinit& operator=(tzinit&&) = delete;
    };
    tzinit::tzinit()
    {
        const char* val = std::getenv("TZ");
        if (val != nullptr)
        {
            tz.assign(val);
        }

        val = std::getenv("TZ_ROOT");
        if (val != nullptr)
        {
            tz_root.assign(val);
        }
    }
    tzinit tz_initializer;
#endif

} // anonymous namespace

namespace civil_time {

const string& get_tz() noexcept { return tz; }
void set_tz(const char* val)    { tz.assign(val); }
void set_tz(const string& val)  { tz.assign(val); }
void set_tz(string&& val)       { tz.assign(val); }

const string& get_tz_root() noexcept { return tz_root; }
void set_tz_root(const char* val)    { tz_root.assign(val); }
void set_tz_root(const string& val)  { tz_root.assign(val); }
void set_tz_root(string&& val)       { tz_root.assign(val); }

//
// timezone's private helpers:
//

//
// When the current time_t value changes, we do a binary search of
// data.trans_times, get the new data.info index from data.info_idx,
// and then assign the new value to this->info_ptr.
//
// If the new time_t is earlier than the first data.trans_times entry,
// or if we don't have any transition times at all, we just use the
// first (or only) data.info entry.  Similarly, if we're after the
// latest transition time, the latest one is the right one.
//
// If data was constructed from a POSIX TZ value (data.tzrules != nullptr),
// then all we have to do is find out whether we're observing DST.
// If std::localtime() returns nullptr, we assume not.
//
// First, find the time_t of interest:
//
int timezone::find_time_t() const noexcept
{
    //
    // If we have no transition times at all, return -1 to indicate that.
    //
    if (data.trans_times == nullptr)
    {
        return -1;
    }

    //
    // If we're before the first transition time, use the first one.
    //
    if (tt < *data.trans_times)
    {
        return 0;
    }

    //
    // If we're after the last transition time, use the last one.
    //
    if (tt >= data.trans_times[data.hdr.tzh_timecnt - 1])
    {
        return data.hdr.tzh_timecnt - 1;
    }

    //
    // Else do the binary search.
    //
    // Note that we're not looking for an exact match:  if we're between
    // two entries, the earlier one is the right one.  Also, because of
    // the tests above, we're guaranteed to find something.
    //
    int beg = 0, end = data.hdr.tzh_timecnt, mid = 0;
    for (;;)
    {
        if (beg + 1 == end) // We must have found it.
        {
            mid = beg;
            break;
        }

        mid = (beg + end) / 2;

        if (tt >= data.trans_times[mid] && tt < data.trans_times[mid + 1])
        {
            break;
        }
        if (tt < data.trans_times[mid])
        {
            end = mid;
        }
        else
        {
            beg = mid + 1;
        }
    }
    return mid;
}

//
// Now select the transition type.
//
void timezone::new_time_t() noexcept
{
    assert((data.trans_times != nullptr) == (data.hdr.tzh_timecnt > 0));

    //
    // If there's only one transition type, use it.
    //
    if (data.hdr.tzh_typecnt == 1)
    {
        info_ptr = data.info;
        return;
    }

    //
    // If constructed from a POSIX TZ value with rules:
    //
    if (data.tzrules != nullptr)
    {
        assert(data.info != nullptr && data.hdr.tzh_typecnt == 2);

        //
        // Both rules have to be 'J' || both have to be 'M'.
        //
        #ifndef NDEBUG
        {
            bool j0 = data.tzrules[0].jd == INT_MIN;
            bool j1 = data.tzrules[1].jd == INT_MIN;
            assert(j0 == j1);
        }
        #endif

        bool dst_1st = data.info[0].tt_isdst != '\0';
        assert(data.info[int(dst_1st)].tt_isdst == '\0');

        //
        // The STD-to-DST rule:
        //
        tz_time temptt = tt + data.info[int(dst_1st)].tt_gmtoff;
        std::tm* ptm = std::gmtime(&temptt);
        //
        // If temptt is out of bounds, we're way early,
        // so just use the first type.
        //
        if (ptm == nullptr)
        {
            info_ptr = data.info;
            return;
        }
        zoneinfo::tz_data::tzrule stod_rule(*ptm);

        //
        // Now the DST-to-STD rule:
        //
        temptt = tt + data.info[int(!dst_1st)].tt_gmtoff;
        ptm = std::gmtime(&temptt);
        assert(ptm != nullptr); // This has to work.
        zoneinfo::tz_data::tzrule dtos_rule(*ptm);

        //
        // If the STD-to-DST rule is earlier in the year
        // (northern hemisphere except Ireland):
        //
        // NB:  pathological coupling explained in tzrule::compare().
        //
        if (data.tzrules[0].compare(data.tzrules[1]) < 0)
        {
            if (data.tzrules[0].compare(stod_rule) <= 0 &&
                data.tzrules[1].compare(stod_rule) > 0)
            {
                // STD-to-DST <= now && DST-to-STD > now,
                // so we're inside the DST range
                info_ptr = data.info + 1;
                return;
            }
            info_ptr = data.info;
            return;
        }

        //
        // Else the DST-to-STD rule is earlier in the year
        // (southern hemisphere and Ireland):
        //
        if (data.tzrules[0].compare(dtos_rule) <= 0 ||
            data.tzrules[1].compare(dtos_rule) > 0)
        {
            // DST-to-STD > now || STD-to-DST <= now,
            // so we're inside the DST range
            info_ptr = data.info + 1;
            return;
        }
        info_ptr = data.info;
        return;
    }

    //
    // Else, do the search.
    //
    assert(data.hdr.tzh_timecnt != 0);
    int idx = find_time_t();
    assert(idx >= 0);
    info_ptr = data.info + data.info_idx[idx];
}

void timezone::load_TZif()
{
  #ifndef CIVIL_TIME_NO_ZONEINFO
    if (nam.find(',') == string::npos)
    {
        try
        {
            data.read(nam);
        }
        catch (const std::invalid_argument&)
        {
            //
            // No such file or it's not a TZif file.
            // Assume it's a POSIX TZ environment variable instead.
            //
            nam.assign(std::move(data.make_posix(nam)));
        }
        // Or just let any other exception pass through.
    }
    else
    {
        try
        {
            nam.assign(std::move(data.make_posix(nam)));
        }
        catch (const std::invalid_argument& e)
        {
            string msg(e.what());
            msg.append(" making POSIX data out of ");
            msg.append(nam);
            throw std::invalid_argument(msg);
        }
    }
  #else
    //
    // We don't have the Zoneinfo data at all,
    // so nam had better be a POSIX TZ-like name.
    //
    try
    {
        string temp(xlate_link(nam));
        nam.assign(std::move(data.make_posix(xlate_name(temp))));
    }
    catch (const std::invalid_argument& e)
    {
        string msg(e.what());
        msg.append(" making POSIX data out of ");
        msg.append(nam);
        throw std::invalid_argument(msg);
    }
  #endif

    new_time_t();
    make_offsets();
}

void timezone::make_fixed(int hrs, int mins, int secs)
{
  #ifndef CIVIL_TIME_MIN_OFF_HRS
  #define CIVIL_TIME_MIN_OFF_HRS -23
  #endif
  #ifndef CIVIL_TIME_MAX_OFF_HRS
  #define CIVIL_TIME_MAX_OFF_HRS +24
  #endif
    assert(hrs >= CIVIL_TIME_MIN_OFF_HRS && hrs <= CIVIL_TIME_MAX_OFF_HRS);
    assert(mins > -60 && mins < +60);
    assert(secs > -60 && secs < +60);

    if ((hrs < 0 && mins > 0) || (hrs > 0 && mins < 0))
    {
        mins = -mins;
    }
    if ((hrs < 0 && secs > 0) || (hrs > 0 && secs < 0))
    {
        secs = -secs;
    }
    zoneinfo::tz_int off = (hrs * 60 + mins) * 60 + secs;

    data.hdr.tzh_typecnt = 1;
    data.info = new zoneinfo::tz_data::ttinfo[1];
    data.info->tt_gmtoff = off;
    data.info->tt_isdst = data.info->tt_abbrind = 0;
    info_ptr = data.info;

    //
    // A string version of the (still unsigned) offset for the name,
    // abbreviation and TZ environment variable:
    //
    string stroff;
    if (hrs > 9)
    {
        stroff.append(1, '1');
        hrs %= 10;
    }
    stroff.append(1, static_cast<char>(hrs + '0'));
    if (mins != 0 || secs != 0)
    {
        if (mins < 0)
        {
            mins = -mins;
        }
        stroff.append(1, ':');
        std::div_t d = std::div(mins, 10);
        stroff.append(1, static_cast<char>(d.quot + '0'));
        stroff.append(1, static_cast<char>(d.rem  + '0'));

        if (secs != 0)
        {
            if (secs < 0)
            {
                secs = -secs;
            }
            stroff.append(1, ':');
            d = std::div(secs, 10);
            stroff.append(1, static_cast<char>(d.quot + '0'));
            stroff.append(1, static_cast<char>(d.rem  + '0'));
        }
    }
    bool neg = hrs < 0;

    //
    // The name and abbreviation will be the same.
    //
    nam.assign("UTC");
    if (off != 0)
    {
        nam.append(1, neg ? '+' : '-'); // NB, wrong sign
        nam.append(stroff);
    }
    size_t len = nam.size() + 1;
    data.abbrv = new char[len];
    memcpy(data.abbrv, nam.c_str(), len);

    //
    // The TZ environment variable will follow the <+n>-n convention.
    //
    string tzvar(1, '<');
    if (off != 0)
    {
        tzvar.append(1, neg ? '+' : '-'); // NB, wrong sign
    }
    tzvar.append(stroff);
    tzvar.append(1, '>');
    tzvar.append(1, neg ? '-' : '+'); // correct sign
    tzvar.append(stroff);
    len = tzvar.size() + 1;
    data.tzenv = new char[len];
    memcpy(data.tzenv, tzvar.c_str(), len);

    //
    // We never have DST:
    //
    stdoff = info_ptr->tt_gmtoff;
    dstoff = INT_MIN;
}

void timezone::make_offsets() noexcept
{
    stdoff = dstoff = INT_MIN;

    //
    // If we have a zone that never observes DST (i.e., if there's exactly one
    // info array element or if the TZ environment variable contains no comma),
    // just use the current info:
    //
    if (data.hdr.tzh_typecnt == 1)
    {
        stdoff = info_ptr->tt_gmtoff;
        return;
    }

    //
    // If we have exactly two types, maybe one is STD and the other is DST
    // (although it could be just that the standard offset changed some time
    // in the past).
    //
    if (data.hdr.tzh_typecnt == 2)
    {
        zoneinfo::tz_data::ttinfo const * beg = data.info;
        zoneinfo::tz_data::ttinfo const * const end = beg + 2;

        for ( ; beg != end; ++beg)
        {
            int off = beg->tt_gmtoff;
            if (beg->tt_isdst == '\0')
            {
                stdoff = off;
            }
            else
            {
                dstoff = off;
            }
        }
        if (stdoff == INT_MIN) // seems highly unlikely
        {
            stdoff = dstoff;
            dstoff = INT_MIN;
        }
        return;
    }

    //
    // Else find the current type and go forward from there.
    //
    int idx = find_time_t();
    if (idx < 0)
    {
        idx = 0;
    }
    const int end = data.hdr.tzh_timecnt;
    for ( ; (stdoff == INT_MIN || dstoff == INT_MIN) && idx < end; ++idx)
    {
        zoneinfo::tz_data::ttinfo* ptr = data.info + data.info_idx[idx];
        int off = ptr->tt_gmtoff;
        if (ptr->tt_isdst == '\0')
        {
            if (stdoff == INT_MIN)
            {
                stdoff = off;
            }
        }
        else
        {
            if (dstoff == INT_MIN)
            {
                dstoff = off;
            }
        }
    }
    if (stdoff == INT_MIN) // just in case
    {
        stdoff = dstoff;
        dstoff = INT_MIN;
    }
}

//
// Public member functions:
//

timezone::timezone() : data(), nam(), tt(std::time(nullptr)), info_ptr(nullptr)
{
/*
std::cout << "\ntt == " << tt << std::endl;
std::tm* ptm = std::localtime(&tt);
assert(ptm != nullptr);
std::cout << std::setfill('0') << ptm->tm_year + 1900
          << '-' << std::setw(2) << ptm->tm_mon + 1
          << '-' << std::setw(2) << ptm->tm_mday
          << ' ' << std::setw(2) << ptm->tm_hour
          << ':' << std::setw(2) << ptm->tm_min
          << ':' << std::setw(2) << ptm->tm_sec << std::endl;
*/
    string tzval(get_tz());
    assert(tzval.size() > 2);
    if (tzval[0] == ':') // Must be ":chars"-type TZ env. var.
    {                    // Remove ':', assume rest is Zoneinfo Zone.
        tzval.erase(0, 1);
    }
    nam.assign(std::move(xlate_link(tzval)));
    assert(!nam.empty());
    load_TZif();
}

timezone::timezone(int hrs, int mins, int secs)
  : data(), nam(), tt(std::time(nullptr)), info_ptr(nullptr)
{
    make_fixed(hrs, mins, secs);
}

timezone::timezone(const std::string& s)
  : data(), nam(xlate_link(s)), tt(std::time(nullptr)), info_ptr(nullptr)
{
    assert(!nam.empty());
    load_TZif();
}

timezone::timezone(std::string&& s)
  : data(), nam(std::move(xlate_link(s))),
    tt(std::time(nullptr)), info_ptr(nullptr)
{
    assert(!nam.empty());
    load_TZif();
}

void timezone::swap(timezone& other)
{
    data.swap(other.data);
    nam.swap(other.nam);
    std::swap(tt, other.tt);
    std::swap(info_ptr, other.info_ptr);
    std::swap(stdoff, other.stdoff);
    std::swap(dstoff, other.dstoff);
}

timezone& timezone::switch_to_local()
{
    data.all_clear();
    info_ptr = nullptr;

    string tzval(get_tz());
    assert(tzval.size() > 2);
    if (tzval[0] == ':') // Must be ":chars"-type TZ env. var.
    {                    // Remove ':', assume rest is Zoneinfo Zone.
        tzval.erase(0, 1);
    }
    nam.assign(std::move(xlate_link(tzval)));
    assert(!nam.empty());

    load_TZif();
    return *this;
}
timezone& timezone::switch_to_offset(int hrs, int mins, int secs)
{
    data.all_clear();
    info_ptr = nullptr;
    nam.clear();
    make_fixed(hrs, mins, secs);
    return *this;
}
timezone& timezone::switch_to(const std::string& s)
{
    data.all_clear();
    info_ptr = nullptr;
  #ifndef CIVIL_TIME_NO_ZONEINFO
    nam = xlate_link(s);
    load_TZif();
  #else
    nam = data.make_posix(xlate_name(s));
  #endif
    return *this;
}
timezone& timezone::switch_to(std::string&& s)
{
    data.all_clear();
    info_ptr = nullptr;
  #ifndef CIVIL_TIME_NO_ZONEINFO
    nam = std::move(xlate_link(s));
    load_TZif();
  #else
    nam = data.make_posix(xlate_name(s));
  #endif
    return *this;
}

timezone& timezone::for_time(std::time_t t) noexcept
{
    tt = t;
    new_time_t();
    make_offsets();
    return *this;
}

timezone::trans_type timezone::transition_type() const noexcept
{
    if (info_ptr != nullptr)
    {
        assert(data.stdind != nullptr && data.utcind != nullptr);
        std::ptrdiff_t indidx = info_ptr - data.info;
        return data.utcind[indidx] != '\0' ?
            trans_type::utc :
            (data.stdind[indidx] != '\0' ? trans_type::std : trans_type::wall);
    }
    return trans_type::unknown;
}

int timezone::utc_offset() const noexcept
{
    return info_ptr != nullptr ? info_ptr->tt_gmtoff : INT_MIN;
}

bool timezone::is_dst() const noexcept
{
    return info_ptr != nullptr && info_ptr->tt_isdst == '\1';
}

const char* timezone::abbrv() const noexcept
{
    return info_ptr != nullptr ? data.abbrv + info_ptr->tt_abbrind : nullptr;
}

std::string timezone::posix_tz_env_var() const
{
    if (data.tzenv != nullptr)
    {
        return std::string(data.tzenv);
    }
    return "[unknown TZ]";
}

} // namespace civil_time

// End of timezone.cpp
