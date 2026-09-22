//
// tzdata_make_posix.cpp
//
// Bill Seymour, 2024-03-29
//
// Copyright Bill Seymour 2024.
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
// This is the function that tries to parse a POSIX TZ environment variable.
// It's in its own source file because it's likely to be pretty complicated,
// and we don't want that to obscure the other stuff in tz_data.cpp.
//

#include "timezone.hpp"

#include <stdexcept>
#if 0
  // for tracing
  #include <iostream>
  using std::cerr;
  using std::endl;
#endif

#include <cstring>
#include <cstddef> // size_t
#include <cstdlib> // atoi
#include <cctype>  // isdigit

namespace {

using std::string;
using std::atoi;
using std::size_t;

constexpr int secs_per_min = 60;
constexpr int secs_per_hour = secs_per_min * 60;

[[noreturn]] void throw_invalid(const string& tzvar)
{
    string msg("Can't parse TZ string \"");
    msg.append(tzvar);
    msg.append(1, '"');
    throw std::invalid_argument(msg);
}

//
// The tz_rule argument will begin with a comma.
//
void make_rule(civil_time::zoneinfo::tz_data::tzrule& rule,
               const string& tz_rule)
{
    if (tz_rule.size() < 2 || tz_rule[0] != ',')
    {
        throw_invalid(tz_rule);
    }

    //
    // If we have a Julian day argument:
    //
    if (tz_rule[1] == 'J' ||
        std::isdigit(static_cast<unsigned char>(tz_rule[1])))
    {
        rule.mo = rule.wc = rule.wd = INT_MIN;
        const char* s = tz_rule.c_str() + 1;
        if (tz_rule[1] == 'J')
        {
            ++s;
        }
        rule.jd = atoi(s);
        if (rule.jd > 0 && rule.jd <= 365)
        {
            return; // NB: we're done
        }
        throw_invalid(tz_rule);
    }

    //
    // Else we must have a month-day type argument:
    //
    static constexpr char minrule[] = ",M0.0.0";
    static constexpr size_t minrulesize = sizeof minrule - 1;

    if (tz_rule.size() < minrulesize || tz_rule[1] != 'M')
    {
        throw_invalid(tz_rule);
    }

    rule.jd = INT_MIN;

    const char* s = tz_rule.c_str() + 2;
    rule.mo = atoi(s);

    s = std::strchr(s, '.');
    if (s == nullptr)
    {
        throw_invalid(tz_rule);
    }
    ++s;
    rule.wc = atoi(s);

    s = std::strchr(s, '.');
    if (s == nullptr)
    {
        throw_invalid(tz_rule);
    }
    ++s;
    rule.wd = atoi(s);

    s = std::strchr(s, '/');
    if (s == nullptr)
    {
        rule.hr = 2;
        rule.mn = rule.sc = 0;
    }
    else
    {
        bool neg = false;
        ++s;
        if (*s == '-')
        {
            neg = true;
            ++s;
        }
        else if (*s == '+')
        {
            ++s;
        }
        rule.hr = atoi(s);

        s = std::strchr(s, ':');
        if (s == nullptr)
        {
            rule.mn = rule.sc = 0;
        }
        else
        {
            ++s;
            rule.mn = atoi(s);

            s = std::strchr(s, ':');
            rule.sc = s == nullptr ? 0 : atoi(s + 1);
        }

        if (neg)
        {
            rule.hr = -rule.hr;
            rule.mn = -rule.mn;
            rule.sc = -rule.sc;
        }
    }
}

//
// Convert a legacy POSIX-style offset from UTC
// (with the wrong sign) to a number of seconds:
//
int get_offset(const char* s, const char* end)
{
    bool neg = true;
    if (*s == '-')
    {
        neg = false;
        ++s;
    }
    else if (*s == '+')
    {
        ++s;
    }

    int retval = atoi(s) * secs_per_hour;
    s = strchr(s, ':');
    if (s != nullptr && s < end)
    {
        retval += atoi(++s) * secs_per_min;
        s = strchr(s, ':');
        if (s != nullptr && s < end)
        {
            retval += atoi(s + 1);
        }
    }

    return neg ? -retval : retval;
}

constexpr size_t npos = string::npos;

//
// Get an abbreviation and, maybe, an offset from a TZ string.
// A DST abbreviation might not have an offset after it,
// so use INT_MIN to indicate that.  Return whether it succeeds.
//
struct name_parts
{
    string std, dst; // abbreviations
    int soff, doff;  // offsets
};
bool get_name_parts(name_parts& parts, const string& name)
{
    if (name.size() < 4)
    {
        return false;
    }

    const char* sp = name.c_str();

    size_t sabrbeg = 0, sabrend = 0, dabrbeg = 0, dabrend = 0,
           soffbeg = 0, soffend = 0, doffbeg = 0, doffend = 0;

    if (*sp == '<')
    {
        sabrbeg = 1;
        sabrend = name.find('>');
        if (sabrend == npos)
        {
            return false;
        }
        if (sabrend == name.size())
        {
            return false;
        }
        soffbeg = sabrend + 1;
        soffend = name.find('<', soffbeg);
        if (soffend == npos)
        {
            soffend = name.size();
        }
        parts.std.assign(name, sabrbeg, sabrend - sabrbeg);
        parts.soff = get_offset(sp + soffbeg, sp + soffend);

        if (soffend == name.size())
        {
            parts.doff = INT_MIN;
            return true;
        }

        //
        // Else we have dst but it might not have an offset.
        //

        dabrbeg = soffend + 1;
        dabrend = name.find('>', dabrbeg);
        if (dabrend == npos)
        {
            return false;
        }
        doffbeg = dabrend + 1;
        doffend = name.size();
        parts.dst.assign(name, dabrbeg, dabrend - dabrbeg);
        parts.doff =
            doffbeg == doffend ? // no dst offset
            parts.soff + secs_per_hour : // so default to std off + 1 hour
            get_offset(sp + doffbeg, sp + doffend);
        return true;
    }

    //
    // Else we have something like CST6CDT, maybe with dst.
    //

    // sabrbeg remains 0
    sabrend = name.find_first_of("+-:0123456789");
    if (sabrend == npos)
    {
        return false;
    }
    soffbeg = sabrend;
    soffend = name.find_first_not_of("+-:0123456789", soffbeg);
    if (soffend == npos)
    {
        soffend = dabrbeg = dabrend = doffbeg = doffend = name.size();
    }
    else
    {
        dabrbeg = soffend;
        dabrend = name.find_first_of("+-:0123456789", dabrbeg);
        if (dabrend == npos)
        {
            dabrend = doffbeg = doffend = name.size();
        }
        else
        {
            doffbeg = dabrend;
            doffend = name.size();
        }
    }
    parts.std.assign(name, sabrbeg, sabrend - sabrbeg);
    parts.soff = get_offset(sp + soffbeg, sp + soffend);
    if (dabrbeg == name.size())
    {
        parts.doff = INT_MIN;
        return true;
    }
    parts.dst.assign(name, dabrbeg, dabrend - dabrbeg);
    parts.doff = doffbeg == doffend ?
                 parts.soff + secs_per_hour :
                 get_offset(sp + doffbeg, sp + doffend);
    return true;
}

} // anonymous namespace

namespace civil_time {
namespace zoneinfo {

#ifdef _MSC_VER
// MSVC says strcpy unsafe, suggests vendor lock-in alternative.
#pragma warning(disable:4996)
#endif

//
// Return what we'll use for the zone name.
//
string tz_data::make_posix(const string& tzvar)
{
    //
    // Do we have rules?
    //
    size_t comma1 = tzvar.find(',');
    size_t comma2 = comma1 == npos ? npos : tzvar.find(',', comma1 + 1);
    if (comma1 != npos && comma2 == npos)
    {
        // Gotta have either 0 or 2 rules.
        throw_invalid(tzvar);
    }

    string name(tzvar, 0, comma1);

    name_parts parts;
    if (!get_name_parts(parts, name))
    {
        throw_invalid(tzvar);
    }

    //
    // As in tz_data::read(), make a local object first and
    // don't touch *this until we're sure that all went OK.
    //
    tz_data temp;

    temp.tzenv = new char[tzvar.size() + 1];
    strcpy(temp.tzenv, tzvar.c_str());

    //
    // If no DST, just one info and no rule:
    //
    if (parts.doff == INT_MIN)
    {
        if (comma1 != npos)
        {
            // Can't have a rule without DST.
            throw_invalid(tzvar);
        }
        temp.hdr.tzh_typecnt = 1;
        temp.info = new ttinfo[1];

        temp.info->tt_gmtoff = static_cast<tz_int>(parts.soff);
        temp.info->tt_isdst = temp.info->tt_abbrind = 0;

        temp.hdr.tzh_charcnt = static_cast<tz_int>(parts.std.size() + 1);
        temp.abbrv = new char[temp.hdr.tzh_charcnt];
        strcpy(temp.abbrv, parts.std.c_str());

        // Success:
        *this = std::move(temp);
        return tzvar;
    }

    //
    // Else we have DST, so two infos, two abbreviations, and two rules.
    //
    temp.hdr.tzh_typecnt = 2;
    temp.info = new ttinfo[2];

    temp.info[0].tt_gmtoff = static_cast<tz_int>(parts.soff);
    temp.info[0].tt_isdst = temp.info->tt_abbrind = 0;

    size_t stdsize = parts.std.size() + 1; // including '\0'

    temp.info[1].tt_gmtoff = static_cast<tz_int>(parts.doff);
    temp.info[1].tt_isdst = 1;
    temp.info[1].tt_abbrind = static_cast<unsigned char>(stdsize);

    //
    // Now the two abbreviations:
    //
    size_t dstsize = parts.dst.size() + 1;
    temp.hdr.tzh_charcnt = static_cast<tz_int>(stdsize + dstsize);
    temp.abbrv = new char[temp.hdr.tzh_charcnt];
    strcpy(temp.abbrv, parts.std.c_str());
    strcpy(temp.abbrv + stdsize, parts.dst.c_str());

    //
    // Now the two rules:
    //
    temp.tzrules = new tzrule[2];
    if (comma1 != npos)
    {
        // The STD-to-DST rule comes first in the input string.
        make_rule(temp.tzrules[0], string(tzvar, comma1, comma2 - comma1));
        make_rule(temp.tzrules[1], string(tzvar, comma2));
    }
    else
    {
        // No rules given, default to current U.S. rules.
        temp.tzrules[0].mo = 3;
        temp.tzrules[1].mo = 11;
        temp.tzrules[0].wc = 2;
        temp.tzrules[1].wc = 1;
        temp.tzrules[0].hr = temp.tzrules[1].hr = 2;

        temp.tzrules[0].wd = temp.tzrules[1].wd =
        temp.tzrules[0].mn = temp.tzrules[1].mn =
        temp.tzrules[0].sc = temp.tzrules[1].sc = 0;
    }

    //
    // Success:
    //
    *this = std::move(temp);
    return string(tzvar, 0, comma1);
}

} // namespace zoneinfo
} // namespace civil_time

// End of tzdata_make_posix.cpp
