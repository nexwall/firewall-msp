//
// xlate-tz-names.cpp
//
// Bill Seymour, 2024-02-28
//
// Copyright Bill Seymour 2024.
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
// This program generates the tz_names_xlate.inc and tz_links_xlate.inc files
// needed for Bill's timezone class.  It reads Zoneinfo's tzdata.zi file
// to get the Zone names and the Links, and for each Zone name, it reads
// appropriate TZif file to get the POSIX TZ environment variable.
//
// It runs on a system that has the Zoneinfo data installed.  The name of the
// Zoneinfo root directory can be specified on the command line, but it can
// also just default to /usr/share/zoneinfo which is probably correct for Linux.
//
// Both of the output files contain initializers for const char*[][2] arrays
// of the form:
//
//   {"some-name","translated-name"},
//
// In the tz_names_xlate.inc file, "some-name" is an actual Zoneinfo Zone
// name and "translated-name" is that zone's POSIX TZ environment variable
// determined by reading the actual Zoneinfo binary.
//
// In the tz_links_xlate.inc file, "some-name" is a Zoneinfo Link name
// and "translated-name" is the real Zone name determined by the "L" records
// in the tzdata.zi file.
//
// The two files will be written to the current working directory.
//
// No error is fatal (except for inability to read the tzdata.zi file itself).
// We might write a bunch of error messages to cerr, but we keep trying to
// get through the whole tzdata.zi file.
//
// This program requires at least a C++11 compiler and standard library.
// It can run on both POSIX and Windows systems, but note that it needs
// the actual Zoneinfo installation to be present.
//

#include <iostream>
#include <fstream>
#include <string>
#include <utility> // swap, move
#include <map>

#include <cstdlib> // EXIT_FAILURE, EXIT_SUCCESS
#include <cstring> // strlen, memcmp
#include <cstdint> // int32_t
#include <cstddef> // size_t
#include <ctime>   // time_t (we need to know its size)
#include <climits> // CHAR_BIT

static_assert(sizeof(std::time_t) * CHAR_BIT >= 64, "64-bit time_ts required");

namespace {

using std::cerr;
using std::string;
using std::move;

#ifdef _MSC_VER
  #define POSIX_SEP '/'
  #define WIN_SEP '\\'
  #define SEP '\\'
#else
  #define SEP '/'
#endif

//
// We'll accumulate all the data in a couple of map<string,string>s
// and then write it out when we're all done recursing the directory.
// This has the side effect of automatically sorting the data so that
// Bill's timezone class can do a binary search.
//
typedef std::map<string,string> translations;
translations names, links;

const char* root = nullptr;
std::size_t rootsize = 0;

typedef std::int32_t tzint;

//
// The "header" portion of a Zoneinfo binary:
//
#pragma pack(4)
  struct tz_header
  {
      char version[20];
      tzint tzh_ttisgmtcnt;
      tzint tzh_ttisstdcnt;
      tzint tzh_leapcnt;
      tzint tzh_timecnt;
      tzint tzh_typecnt;
      tzint tzh_charcnt;
  };
#pragma pack()
tz_header head;

//
// What a ttinfo is (we need to know its size):
//
#pragma pack(2)
  struct ttinfo
  {
      tzint tt_gmtoff;
      unsigned char tt_isdst;
      unsigned char tt_abbrind;
  };
#pragma pack()

//
// The leap seconds:
//
#pragma pack(4)
  struct leapsecs
  {
      std::time_t leap;
      tzint cnt;
  };
#pragma pack()

//
// The first six bytes in a TZif file.
//
const char filetype[] = "TZifn";
constexpr std::size_t typesize = sizeof filetype;
constexpr std::size_t begsize = typesize - 2;
constexpr std::size_t nullpos = typesize - 1;

//
// Verify that we're really working on a TZif2 or 3 file.
//
bool check_file_type(std::istream& is)
{
    return is.read(head.version, typesize).good() &&
           is.gcount() == typesize &&
           std::memcmp(head.version, filetype, begsize) == 0 &&
           (head.version[begsize] == '2' || head.version[begsize] == '3') &&
           head.version[nullpos] == '\0';
}

//
// All the ints in the TZif files are big-endian.
//
void fix_endianness()
{
    static const union endian_checker
    {
        tzint i;
        char c[sizeof(tzint)];
        endian_checker() : i(1) { }
    } u;
    if (u.c[0] == 0)
    {
        // We're running on a big-endian box, so nothing to do.
        return;
    }

    static tzint* const first = &head.tzh_ttisgmtcnt;
    static tzint* const last  = &head.tzh_charcnt;

    for (tzint* ptr = first; ptr <= last; ++ptr)
    {
        unsigned char* data = reinterpret_cast<unsigned char*>(ptr);

        for (int beg = 0, end = int(sizeof(tzint)) - 1; beg < end; ++beg, --end)
        {
            std::swap(data[beg], data[end]);
        }
    }
}

//
// Find the "POSIX TZ environment variable" in a TZif2 or 3.
//
bool skip_to_tzvar(std::istream& is)
{
    //
    // We've read typesize bytes already.
    // Read the rest of the version 1 header.
    //
    is.read(head.version + typesize, sizeof head - typesize);

    //
    // Now skip to version 2.
    //
    static constexpr std::size_t old_time_t_size = 4;

    fix_endianness();
    is.ignore(head.tzh_timecnt * old_time_t_size +
              head.tzh_timecnt +
              head.tzh_typecnt * sizeof(ttinfo) +
              head.tzh_charcnt +
              head.tzh_leapcnt * old_time_t_size * 2 +
              head.tzh_ttisstdcnt +
              head.tzh_ttisgmtcnt);

    //
    // Read the version 2 header and skip to the POSIX TZ variable.
    //
    is.read(head.version, sizeof head);
    fix_endianness();
    is.ignore(head.tzh_timecnt * sizeof(std::time_t) +
              head.tzh_timecnt +
              head.tzh_typecnt * sizeof(ttinfo) +
              head.tzh_charcnt +
              head.tzh_leapcnt * sizeof(leapsecs) +
              head.tzh_ttisstdcnt +
              head.tzh_ttisgmtcnt);

    return is.good();
}

//
// Return the "POSIX TZ environment variable",
// or return "oops" if there's any read error.
//
string read_tzvar(std::istream& is)
{
    string retval;
    retval.reserve(64);

    //
    // The string begins and ends with '\n' characters
    // which we don't want to save.
    //
    is.ignore(1);
    if (is.good())
    {
        char c;
        do {
            c = static_cast<char>(is.get());
            retval.append(1, c);
        } while (is.good() && c != '\n');
    }
    if (is.good() && retval.back() == '\n')
    {
        retval.pop_back();
    }
    else
    {
        retval.assign("oops");
    }

    return retval;
}

#ifdef _MSC_VER
    void local_sep(string& fn)
    {
        for (char& c : fn)
        {
            if (c == POSIX_SEP)
            {
                c = WIN_SEP;
            }
        }
    }
    void posix_sep(string& fn)
    {
        for (char& c : fn)
        {
            if (c == WIN_SEP)
            {
                c = POSIX_SEP;
            }
        }
    }
#else
    inline void local_sep(const string&) { }
    inline void posix_sep(const string&) { }
#endif

//
// Read a regular file.  If it's a proper TZif file,
// get the POSIX TZ variable and add one entry
// to the names map.
//
void get_tz(string&& zone_name)
{
    string full_path(root);
    full_path.append(1, SEP);
    full_path.append(zone_name);
    local_sep(full_path);

    std::ifstream is(full_path, std::ios_base::in | std::ios_base::binary);
    if (!is)
    {
        cerr << "Can't open " << full_path << '\n';
        return;
    }

    if (!check_file_type(is))
    {
        return; // not a TZif
    }

    if (!skip_to_tzvar(is))
    {
        cerr << "Error reading " << full_path << '\n';
        return;
    }

    string tzvar(read_tzvar(is));
    if (tzvar == "oops")
    {
        cerr << "Error reading " << full_path << '\n';
        return;
    }

    // Don't include the zoneinfo root in the map key.
    string namekey(full_path, rootsize, string::npos);
    posix_sep(namekey);
    names[move(namekey)].assign(tzvar);
}

//
// Read the tzdata.zi file and load the two maps.
//
bool read_tzdata()
{
    string fn(root);
    fn.append(1, SEP);
    fn.append("tzdata.zi");
    local_sep(fn);

    std::ifstream is(fn);
    if (!is)
    {
        cerr << "Can't open " << fn << '\n';
        return false;
    }

    for (string input; getline(is, input); )
    {
        if (input.size() > 2 && input[1] == ' ')
        {
            static constexpr size_t namebeg = 2;
            if (input[0] == 'Z')
            {
                size_t nameend = input.find_first_of(" \t", namebeg);
                get_tz(move(input.substr(namebeg, nameend - namebeg)));
            }
            else if (input[0] == 'L')
            {
                size_t nameend = input.find_first_of(" \t", namebeg);
                size_t linkbeg = input.find_first_not_of(" \t", nameend);
                size_t linkend = input.size();

                string name(input, namebeg, nameend - namebeg);
                string link(input, linkbeg, linkend - linkbeg);

                posix_sep(name);
                posix_sep(link);

                links[move(input.substr(linkbeg, linkend - linkbeg))]
                    .assign(move(input.substr(namebeg, nameend - namebeg)));
            }
        }
    }

    if (is.bad() || !is.eof())
    {
        cerr << "Error reading " << fn << '\n';
        return false;
    }
    return true;
}

//
// Write one file when we're done accumulating all the data.
//
void write(const char* fn, const translations& trans)
{
    if (trans.empty())
    {
        cerr << "No translations found for " << fn << '\n';
        return;
    }

    std::ofstream os(fn);
    if (!os)
    {
        cerr << "Can't create " << fn << '\n';
        return;
    }

    os << "// " << fn << "\n// MACHINE-GENERATED CODE - DO NOT MODIFY\n\n";

    for (const auto& node : trans)
    {
        os << "{\"" << node.first << "\",\"" << node.second << "\"},\n";
    }

    os.flush();
    bool ok = os.good();
    os.close();

    if (!ok)
    {
        cerr << "Error writing " << fn << '\n';
    }
}

} // anonymous namespace

int main(int argc, char** argv)
{
    if (argc > 2)
    {
        cerr << "Usage:  xlate-tz-names [zoneinfo directory]\n";
        return EXIT_FAILURE;
    }

    root = argc < 2 ? "/usr/share/zoneinfo" : argv[1];
    rootsize = std::strlen(root) + 1;

    if (read_tzdata())
    {
        write("tz_names_xlate.inc", names);
        write("tz_links_xlate.inc", links);
        return EXIT_SUCCESS;
    }

    return EXIT_FAILURE;
}

// End of xlate-tz-names.cpp
