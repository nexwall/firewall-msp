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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <algorithm>

#include "nd-except.hpp"
#include "nd-uci.hpp"
#include "nd-util.hpp"

using namespace std;

ndUci::ndUci(const string &package)
    : ctx(nullptr), pkg(nullptr), package(package)
{
    ctx = uci_alloc_context();
    if (ctx == nullptr) {
        throw ndException(
            "%s: uci_alloc_context: %s", package.c_str(), strerror(ENOMEM));
    }

    int rc;
    if ((rc = uci_load(ctx, package.c_str(), &pkg) != UCI_OK)) {
        throw ndException(
            "%s: uci_load: %d", package.c_str(), rc);
    }
}

ndUci::~ndUci()
{
    if (ctx != nullptr) {
        if (pkg != nullptr) {
            uci_unload(ctx, pkg);
            pkg = nullptr;
        }

        uci_free_context(ctx);
        ctx = nullptr;
    }
}

bool ndUci::Get(const string &lookup, ndUci::result &result)
{
    uci_ptr up;
    if (! Lookup(lookup, up)) return false;

    result.clear();

    struct uci_section *us;
    struct uci_option *uo;
    struct uci_element *ue;

    switch (up.last->type) {
    case UCI_TYPE_SECTION:
        us = uci_to_section(up.last);

        result[".section"] = { us->e.name };
        result[".type"] = { us->type };
        result[".anonymous"] = { (us->anonymous) ? "1" : "0" };

        uci_foreach_element(&us->options, ue) {
            uo = uci_to_option(ue);

            if (uo->type == UCI_TYPE_STRING)
                result[uo->e.name] = { uo->v.string };
            else if (uo->type == UCI_TYPE_LIST) {
                struct uci_element *e;
                bool exists = (result.find(uo->e.name) != result.end());

                uci_foreach_element(&uo->v.list, e) {
                    if (! exists) {
                        result[uo->e.name] = { e->name };
                        exists = true;
                    }
                    else
                        result[uo->e.name].push_back(e->name);
                }
            }
        }
        break;

    case UCI_TYPE_OPTION:
        uo = uci_to_option(up.last);

        if (uo->type == UCI_TYPE_STRING)
            result[uo->e.name] = { uo->v.string };
        else if (uo->type == UCI_TYPE_LIST) {
            struct uci_element *e;
            bool exists = (result.find(uo->e.name) != result.end());

            uci_foreach_element(&uo->v.list, e) {
                if (! exists) {
                    result[uo->e.name] = { e->name };
                    exists = true;
                }
                else
                    result[uo->e.name].push_back(e->name);
            }
        }
        break;

    default:
        nd_printf("Unsupported UCI query type: %u\n", up.last->type);
        return false;
    }

    return true;
}

bool ndUci::Set(const string &lookup, const string &value)
{
    struct uci_ptr up;

    Lookup(lookup, up);

    up.value = value.c_str();
    if (uci_set(ctx, &up) != UCI_OK) return false;

    return true;
}

bool ndUci::Set(const string &lookup, const vector<string> &values)
{
    struct uci_ptr up;

    Delete(lookup);

    Lookup(lookup, up);

    for (auto i = values.begin(); i != values.end(); i++) {
        up.value = (*i).c_str();
        if (uci_add_list(ctx, &up) != UCI_OK) return false;
    }

    return true;
}

bool ndUci::AddSection(const string &type, string &name)
{
    struct uci_section *us = nullptr;

    if (uci_add_section(ctx, pkg, type.c_str(), &us) != UCI_OK || us == nullptr)
        return false;

    name = us->e.name;
    nd_dprintf("%s: Created section: %s %s\n",
        package.c_str(), type.c_str(), name.c_str());

    return true;
}

bool ndUci::Delete(const string &lookup)
{
    struct uci_ptr up;

    if (Lookup(lookup, up) == false) return false;

    if (uci_delete(ctx, &up) != UCI_OK) return false;

    return true;
}

bool ndUci::Lookup(const string &lookup, struct uci_ptr &up)
{
    int rc;

    memset(&up, 0, sizeof(struct uci_ptr));
    up.flags = uci_ptr::UCI_LOOKUP_EXTENDED;

    search.clear();
    copy(package.begin(), package.end(), back_inserter(search));
    search.push_back('.');
    copy(lookup.begin(), lookup.end(), back_inserter(search));
    search.push_back('\0');

    if ((rc = uci_lookup_ptr(ctx, &up, &search[0], true)) != UCI_OK) {
        nd_dprintf("%s: Lookup failed: %s: %d\n",
            package.c_str(), lookup.c_str(), rc);
        return false;
    }

    if (! (up.flags & uci_ptr::UCI_LOOKUP_COMPLETE)) {
#if _ND_UCI_DEBUG
        nd_dprintf("%s: Lookup not found: %s\n",
            package.c_str(), lookup.c_str());
#endif
        return false;
    }

    return true;
}

bool ndUci::Revert(void)
{
    struct uci_ptr up;

    memset(&up, 0, sizeof(struct uci_ptr));
    up.p = pkg;

    if (uci_revert(ctx, &up) != UCI_OK) {
        nd_dprintf("Failed to revert uci context.\n");
        return false;
    }

    ctx = uci_alloc_context();
    if (ctx == nullptr) {
        throw ndException(
            "%s: uci_alloc_context: %s", package.c_str(), strerror(ENOMEM));
    }

    int rc;
    if ((rc = uci_load(ctx, package.c_str(), &pkg) != UCI_OK)) {
        throw ndException(
            "%s: uci_load: %d", package.c_str(), rc);
    }

    return true;
}

void ndUci::Commit(bool overwrite)
{
    int rc;
    if ((rc = uci_commit(ctx, &pkg, overwrite) != UCI_OK))
        throw ndException("%s: uci_commit: %d", package.c_str(), rc);
}
