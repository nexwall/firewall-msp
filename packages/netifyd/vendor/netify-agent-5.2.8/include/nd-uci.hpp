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

#pragma once

#include <map>
#include <string>
#include <vector>

extern "C" {
  #include <uci.h>
}

#define ND_UCI_MAX_LOOKUP   128

#define ndUci_vector(i)         i->second
#define ndUci_string(i, n)      i->second[n]
#define ndUci_cstr(i, n)        i->second[n].c_str()
#define ndUci_unsigned(i, n)    (unsigned)strtoul(i->second[n].c_str(), NULL, 0)
#define ndUci_bool(i, n)        (bool)strtoul(i->second[n].c_str(), NULL, 0)
#define ndUci_exists(i, r, k)   ((i = r.find(k)) != r.end())
#define ndUci_anonymous(i, r)   (\
    (i = r.find(".anonymous")) != r.end() && \
    i->second[0].c_str() == "1" \
)

class ndUci
{
public:
    typedef std::map<std::string, std::vector<std::string>> result;
    typedef result::const_iterator result_iter;

public:
    ndUci(const std::string &package);
    virtual ~ndUci();

    bool Get(const std::string &lookup, ndUci::result &result);

    bool Set(const std::string &lookup, const std::string &value);
    bool Set(const std::string &lookup, const std::vector<std::string> &values);

    bool AddSection(const std::string &type, std::string &name);

    bool Delete(const std::string &section);

    bool Revert(void);

    void Commit(bool overwrite = false);

protected:
    struct uci_context *ctx;
    struct uci_package *pkg;
    std::string package;
    std::vector<char> search;

    bool Lookup(const std::string &lookup, struct uci_ptr &ptr);
};
