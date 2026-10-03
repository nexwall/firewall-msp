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

#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <set>
#include <string>
#include <unordered_set>

#include "nd-addr.hpp"

class ndCategory;

using ndRN4Categories = radix_tree<
  ndRadixNetworkEntry<_ND_ADDR_BITSv4>, unsigned>;
using ndRN6Categories = radix_tree<
  ndRadixNetworkEntry<_ND_ADDR_BITSv6>, unsigned>;

class ndCategories
{
public:
    using Id = unsigned;
    enum class Type : uint8_t { NONE, APP, PROTO, MAX };

    ndCategories();
    virtual ~ndCategories();

    bool Load(const std::string &filename);
    bool LoadCustom(const std::string &filename);
    bool LoadDotDirectory(const std::string &path);

    bool Save(const std::string &filename);

    void Dump(Type type = Type::MAX);

    bool IsMember(Type type, Id cat_id, unsigned id);
    bool IsMember(Type type, const std::string &cat_tag, unsigned id);

    Id Lookup(Type type, unsigned id) const;
    Id LookupTag(Type type, const std::string &tag) const;
    Id ResolveTag(Type type, unsigned id, std::string &tag) const;

    std::string GetTag(Type type, Id id) const;
    bool GetTag(Type type, Id id, std::string &tag) const;

    Id LookupDotDirectory(const std::string &domain);
    Id LookupDotDirectory(const ndAddr &addr);

protected:
    mutable std::mutex lock;

    using Categories = std::map<Type, ndCategory>;
    Categories categories;

    using Domains = std::unordered_map<Id, std::unordered_set<std::string>>;
    Domains domains;

    using RegExprs = std::unordered_map<Id, std::regex>;
    RegExprs rxps;

    bool Load(Type type, nlohmann::json &jdata);
    bool LoadLegacy(const nlohmann::json &jdata);

    void ResetCategories(void);
    inline void ResetDomains(void) { domains.clear(); }
    inline void ResetRegExprs(void) { rxps.clear(); }
    void ResetNetworks(bool free_only = true);

private:
    std::unique_ptr<ndRN4Categories> networks4;
    std::unique_ptr<ndRN6Categories> networks6;
};

class ndCategory
{
public:
    const static ndCategories::Id UNKNOWN;

    using TagIndex = std::map<std::string, ndCategories::Id>;
    using IdSet = std::set<unsigned>;
    using CategoryIndex = std::map<ndCategories::Id, IdSet>;
    using CategoryIndexInsert = std::pair<ndCategories::Id, IdSet>;

protected:
    friend class ndCategories;

    TagIndex tag;
    CategoryIndex index;

    ndCategories::Type type;
};
