//
// tz_data.cpp
//
// Bill Seymour, 2024-03-29
//
// Copyright Bill Seymour 2024.
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
// This TU implements the tz_data class declared
// in timezone.hpp along with some undocumented helpers.
//

#include "timezone.hpp" // #includes <string>, <utility>, <ctime>

#include <iostream>
#include <fstream>

#include <cstring> // strlen, memcpy, memcmp, memset
#include <cstddef> // size_t
#include <cerrno>
#include <cassert>

namespace {

using std::string;
using std::time_t;
using std::memcpy;

using civil_time::zoneinfo::tz_int;
using civil_time::zoneinfo::tz_time;

constexpr std::ios_base::openmode bin_mode =
    std::ios_base::in | std::ios_base::binary;

//
// The full path to a TZif file:
//
string full_path(const string& zone_name)
{
    string retval;

  #ifdef _MSC_VER
    assert(zone_name.size() >= 3);
    if (zone_name[0] != '\\' && (zone_name[1] != ':' || zone_name[2] != '\\'))
  #else
    assert(!zone_name.empty());
    if (zone_name[0] != '/')
  #endif
    {
        retval.assign(civil_time::get_tz_root());
        retval.append(1, '/');
    }
    // else already full path

    retval.append(zone_name);

  #ifdef _MSC_VER
    for (char& c : retval)
    {
        if (c == '/')
        {
            c = '\\';
        }
    }
  #endif

    return retval;
}

//
// All the ints and time_ts in the TZif files are big-endian.
//
template<typename intT>
bool little_endian()
{
    static const union endian_checker
    {
        intT i;
        char c[sizeof(intT)];
        endian_checker() : i(1) { }
    } u;
    return u.c[0] != 0;
}

void fix_endianness() { }

template<typename First, typename... Rest>
void fix_endianness(First& first, Rest&... rest)
{
    unsigned char* data = reinterpret_cast<unsigned char*>(&first);

    for (int beg = 0, end = int(sizeof(First)) - 1; beg < end; ++beg, --end)
    {
        std::swap(data[beg], data[end]);
    }

    fix_endianness(rest...);
}

//
// Conditionally allocate memory for a tz_data array pointer
// and copy the contents of the array from src to dest.
//
// This is called from tz_data's copy ctor.  It deliberately does
// nothing, and sets dest == nullptr, if there's nothing to copy.
// (Note that the first argument is a pointer passed by reference.)
//
template<typename T>
void copy(T*& dest, T* src, tz_int size)
{
    assert((size > 0) == (src != nullptr));
    if (size > 0)
    {
        dest = new T[size];
        memcpy(dest, src, size * sizeof(T));
    }
    else
    {
        dest = nullptr;
    }
}

//
// A couple of exceptions that tz_data::read() can throw:
//
void wrong_file(const string& fn)
{
    string msg(fn);
    msg.append(" isn't a TZif2, 3 or 4");
    throw std::invalid_argument(msg);
}
void read_err(const char* why, const string& what)
{
    string msg(why);
    msg.append(1, ' ');
    msg.append(what);
    throw std::runtime_error(msg);
}

//
// Skipping over the version 1 part of a TZif file:
//
using civil_time::zoneinfo::tz_int;
using civil_time::zoneinfo::tz_data;

void get_version_2(const string& fn, std::istream& istr, tz_data::header& hdr)
{
    //
    // We've tried to open the file but haven't yet checked for success.
    //
    if (!istr.good())
    {
        wrong_file(fn);
    }

    //
    // The version 1 header:
    //
    istr.read(reinterpret_cast<char*>(&hdr), sizeof hdr);
    if (!istr.good() || istr.gcount() != sizeof hdr ||
        std::memcmp(hdr.version, "TZif", 4) != 0 ||
        hdr.version[4] < '2' || hdr.version[4] > '4')
    {
        wrong_file(fn);
    }

    //
    // Skip to version 2:
    //
    if (little_endian<tz_int>())
    {
        fix_endianness(hdr.tzh_timecnt, hdr.tzh_typecnt,
                       hdr.tzh_charcnt, hdr.tzh_leapcnt,
                       hdr.tzh_ttisstdcnt, hdr.tzh_ttisgmtcnt);
    }

    static constexpr size_t old_time_t_size = sizeof(tz_int);
    istr.ignore(hdr.tzh_timecnt * old_time_t_size +
                hdr.tzh_timecnt +
                hdr.tzh_typecnt * sizeof(tz_data::ttinfo) +
                hdr.tzh_charcnt +
                hdr.tzh_leapcnt * old_time_t_size +
                hdr.tzh_leapcnt * sizeof(tz_int) +
                hdr.tzh_ttisstdcnt +
                hdr.tzh_ttisgmtcnt);

    if (!istr.good())
    {
        read_err("Error reading", fn);
    }
}

//
// The POSIX TZ environment variable is just a string
// that begins and ends with a '\n'; but we don't know
// its length; so we'll just read one char at a time
// into a std::string so we don't overflow if we get
// a ridiculous string.
//
string get_tz_env(const string& fn, std::istream& istr)
{
    string tzenv_temp;

    istr.ignore(1); // leading '\n'
    if (istr.good())
    {
        char c;
        do {
            c = static_cast<char>(istr.get());
            tzenv_temp.append(1, c);
        } while (istr.good() && c != '\n');
    }
    if (!istr.good() || tzenv_temp.back() != '\n')
    {
        read_err("Error reading", fn);
    }
    tzenv_temp.pop_back(); // trailing '\n'

    return tzenv_temp;
}

} // anonymous namespace

namespace civil_time {
namespace zoneinfo {

//-----------------------------------------------------------------------------
// The tzrule type:
//

tz_data::tzrule::tzrule() noexcept
  : mo(0), wc(0), wd(0), jd(INT_MIN), hr(0), mn(0), sc(0) { }

tz_data::tzrule::tzrule(const std::tm& rhs) noexcept
  : mo(rhs.tm_mon + 1), wc((rhs.tm_mday - 1) % 7 + 1),
    wd(rhs.tm_wday), jd(rhs.tm_yday),
    hr(rhs.tm_hour), mn(rhs.tm_min), sc(rhs.tm_sec) { }

int tz_data::tzrule::compare(const tzrule& rhs) const noexcept
{
    //
    // Pathological coupling:  always call with *this being
    // a rule created by tz_data::make_posix(const string&)
    // because mo, wc and wd will be INT_MIN in a 'J' rule.
    // (A rule constructed from a std::tm will have no INT_MINs,
    // so rhs can be either one.)
    //

    int cmp = 0;
    if (jd != INT_MIN)
    {
        assert(rhs.jd != INT_MIN);
        cmp = jd - rhs.jd;
    }
    else
    {
        assert(rhs.mo != INT_MIN);
        cmp = mo - rhs.mo;
        if (cmp == 0)
        {
            cmp = wc - rhs.wc;
            if (cmp == 0)
            {
                cmp = wd - rhs.wd;
            }
        }
    }
    if (cmp == 0)
    {
        cmp = hr - rhs.hr;
        if (cmp == 0)
        {
            cmp = mn - rhs.mn;
            if (cmp == 0)
            {
                cmp = sc - rhs.sc;
            }
        }
    }
    return cmp;
}

//-----------------------------------------------------------------------------
// The tz_data type:
//

void tz_data::free_arrays() noexcept
{
    delete [] tzrules;
    delete [] tzenv;
    delete [] utcind;
    delete [] stdind;
    delete [] leaps;
    delete [] abbrv;
    delete [] info;
    delete [] info_idx;
    delete [] trans_times;
}

void tz_data::cleanup() noexcept
{
    tzrules = nullptr;
    tzenv = nullptr;
    utcind = nullptr;
    stdind = nullptr;
    leaps = nullptr;
    abbrv = nullptr;
    info = nullptr;
    info_idx = nullptr;
    trans_times = nullptr;
}

void tz_data::clear_header() noexcept
{
    std::memset(hdr.version, '\0', sizeof(header));
}

tz_data::tz_data() noexcept
  : trans_times(nullptr), info_idx(nullptr),
    info(nullptr), abbrv(nullptr), leaps(nullptr),
    stdind(nullptr), utcind(nullptr), tzenv(nullptr),
    tzrules(nullptr)
{
    std::memset(hdr.version, '\0', sizeof(header));
}

//
// tz_data needs to be copyable, moveable, and swappable
// because it's a data member of the timezone class which,
// in turn, is copyable, etc.
//
// It's not technically TriviallyCopyable because of all
// the pointers to allocated memory and the non-trivial
// constructors and destructor; but we think we can get
// away with all the memcpy()ing below because we're
// careful to new[] and delete[] all the pointers and
// set them to nullptr at the right times, there are
// no virtual functions, and all non-static data members
// that aren't pointers are either chars or ints.
//
tz_data::tz_data(const tz_data& rhs)
{
    memcpy(this, &rhs, sizeof(header));

    copy(trans_times, rhs.trans_times, hdr.tzh_timecnt);
    copy(info_idx, rhs.info_idx, hdr.tzh_timecnt);
    copy(info, rhs.info, hdr.tzh_typecnt);
    copy(leaps, rhs.leaps, hdr.tzh_leapcnt);
    copy(stdind, rhs.stdind, hdr.tzh_ttisstdcnt);
    copy(utcind, rhs.utcind, hdr.tzh_ttisgmtcnt);
    copy(abbrv, rhs.abbrv, hdr.tzh_charcnt);
    copy(tzenv, rhs.tzenv, std::strlen(rhs.tzenv) + 1);
    copy(tzrules, rhs.tzrules, 2);
}
tz_data& tz_data::operator=(const tz_data& rhs)
{
    return *this = std::move(tz_data(rhs));
}

//
// We can just copy the pointers when moving or swapping
// as long as we're careful to set them all to nullptr
// in the object that we're moving from.
//
tz_data::tz_data(tz_data&& rhs) noexcept
{
    memcpy(this, &rhs, sizeof(tz_data));
    rhs.cleanup();
}
tz_data& tz_data::operator=(tz_data&& rhs) noexcept
{
    free_arrays();
    memcpy(this, &rhs, sizeof(tz_data));
    rhs.cleanup();
    return *this;
}
void tz_data::swap(tz_data& other) noexcept
{
    tz_data temp;
    memcpy(&temp, &other, sizeof(tz_data));
    memcpy(&other, this, sizeof(tz_data));
    memcpy(this, &temp, sizeof(tz_data));
    temp.cleanup();
}

//
// We'll first read the data into a local temporary
// and then move the temporary to *this when we're
// sure that everything worked OK.
//
tz_data& tz_data::read(const string& fn)
{
    static tz_data temp;

    std::ifstream istr(full_path(fn), bin_mode);

    get_version_2(fn, istr, temp.hdr);

    //
    // Read the version 2 header:
    //
    istr.read(reinterpret_cast<char*>(&temp), sizeof(header));
    if (!istr.good())
    {
        read_err("Error reading", fn);
    }

    //
    // OK so far, so we should be able to allocate all the pointers correctly
    // once the ints in the header all have the correct endianness.
    //
    if (little_endian<tz_int>())
    {
        fix_endianness(temp.hdr.tzh_timecnt, temp.hdr.tzh_typecnt,
                       temp.hdr.tzh_charcnt, temp.hdr.tzh_leapcnt,
                       temp.hdr.tzh_ttisstdcnt, temp.hdr.tzh_ttisgmtcnt);
    }

    if (temp.hdr.tzh_timecnt > 0)
    {
        temp.trans_times = new tz_time[temp.hdr.tzh_timecnt];
        istr.read(reinterpret_cast<char*>(temp.trans_times),
                  temp.hdr.tzh_timecnt * sizeof(tz_time));
        if (little_endian<tz_time>())
        {
            for (tz_int idx = 0; idx < temp.hdr.tzh_timecnt; ++idx)
            {
                fix_endianness(temp.trans_times[idx]);
            }
        }

        temp.info_idx = new unsigned char[temp.hdr.tzh_timecnt];
        istr.read(reinterpret_cast<char*>(temp.info_idx), temp.hdr.tzh_timecnt);
    }
    // else just stick with nullptr because there are no transitions to read.
    // We do a similar test for all the arrays below (except the ttinfo array
    // because tzh_typecnt is documented to never be zero).

    temp.info = new ttinfo[temp.hdr.tzh_typecnt];
    istr.read(reinterpret_cast<char*>(temp.info),
              temp.hdr.tzh_typecnt * sizeof(ttinfo));
    if (little_endian<tz_int>())
    {
        for (tz_int idx = 0; idx < temp.hdr.tzh_typecnt; ++idx)
        {
            fix_endianness(temp.info[idx].tt_gmtoff);
        }
    }

    if (temp.hdr.tzh_charcnt > 0)
    {
        temp.abbrv = new char[temp.hdr.tzh_charcnt];
        istr.read(temp.abbrv, temp.hdr.tzh_charcnt);
    }

    if (temp.hdr.tzh_leapcnt > 0)
    {
        temp.leaps = new leapsecs[temp.hdr.tzh_leapcnt];
        istr.read(reinterpret_cast<char*>(temp.leaps),
                  temp.hdr.tzh_leapcnt * sizeof(leapsecs));
        if (little_endian<tz_time>() || little_endian<tz_int>())
        {
            for (tz_int idx = 0, end = temp.hdr.tzh_leapcnt; idx < end; ++idx)
            {
                fix_endianness(temp.leaps[idx].leap, temp.leaps[idx].cnt);
            }
        }
    }

    if (temp.hdr.tzh_ttisstdcnt > 0)
    {
        temp.stdind = new char[temp.hdr.tzh_ttisstdcnt];
        istr.read(temp.stdind, temp.hdr.tzh_ttisstdcnt);
    }

    if (temp.hdr.tzh_ttisstdcnt > 0)
    {
        temp.utcind = new char[temp.hdr.tzh_ttisgmtcnt];
        istr.read(temp.utcind, temp.hdr.tzh_ttisgmtcnt);
    }

    //
    // The POSIX TZ environment variable:
    //
    string tzenv_temp(get_tz_env(fn, istr));
    temp.tzenv = new char[tzenv_temp.size() + 1];
    memcpy(temp.tzenv, tzenv_temp.c_str(), tzenv_temp.size() + 1);

    // Success:
    return *this = std::move(temp);
}

//
// When we want a POSIX TZ environment variable
// for some TZif file we haven't loaded yet:
//
string tz_data::get_posix_tz(const string& fn)
{
    static tz_data::header hdr;

    std::ifstream istr(full_path(fn), bin_mode);

    get_version_2(fn, istr, hdr);

    //
    // Skip over the version 2 data as well.
    //
    istr.read(reinterpret_cast<char*>(&hdr), sizeof hdr);
    if (!istr.good())
    {
        read_err("Error reading", fn);
    }
    if (little_endian<tz_int>())
    {
        fix_endianness(hdr.tzh_timecnt, hdr.tzh_typecnt,
                       hdr.tzh_charcnt, hdr.tzh_leapcnt,
                       hdr.tzh_ttisstdcnt, hdr.tzh_ttisgmtcnt);
    }
    istr.ignore(hdr.tzh_timecnt * sizeof(tz_time) +
                hdr.tzh_timecnt +
                hdr.tzh_typecnt * sizeof(tz_data::ttinfo) +
                hdr.tzh_charcnt +
                hdr.tzh_leapcnt * sizeof(tz_time) +
                hdr.tzh_leapcnt * sizeof(tz_int) +
                hdr.tzh_ttisstdcnt +
                hdr.tzh_ttisgmtcnt);
    if (!istr.good())
    {
        read_err("Error reading", fn);
    }

    return get_tz_env(fn, istr);
}

} // namespace zoneinfo
} // namespace civil_time

// End of tz_data.cpp
