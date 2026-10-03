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

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include <nlohmann/json.hpp>

#include "nd-apps.hpp"
#include "nd-category.hpp"
#include "nd-flow.hpp"
#include "nd-protos.hpp"
#include "nd-util.hpp"

namespace ndOverlay {

using Result = std::set<std::string>;

class Criteria
{
public:
    void Load(const nlohmann::json &jconfig);
    bool operator==(const ndFlow::Ptr &flow) const;

protected:
    using Apps = std::unordered_set<ndApp::Id, ndEnumHasher>;

    Apps apps;

    using Categories = std::unordered_set<ndCategories::Id>;

    Categories app_categories;

    using Protos = std::unordered_set<ndProto::Id, ndEnumHasher>;

    Protos protos;

    using IPProto = uint8_t;
    using IPProtos = std::unordered_set<IPProto>;

    IPProtos ip_protos;

    using Port = uint16_t;
    using Ports = std::unordered_set<Port>;

    Ports ports;
    Ports src_ports;
    Ports dst_ports;
};

class Group
{
public:
    Group(const std::string &tag) : tag(tag) { }

    void Load(const nlohmann::json &jconfig);
    bool MatchFlow(const ndFlow::Ptr &flow,
      Result &result, const std::string &prefix) const;

protected:
    std::string tag;

    Criteria criteria;
};

class Tag
{
public:
    Tag(const std::string &tag) : tag(tag) { }

    void Load(const nlohmann::json &jconfig);
    bool MatchFlow(ndFlow::Ptr &flow, Result &result) const;

protected:
    std::string tag;
    ndCategories::Id category_id = { 0 };

    using Groups = std::unordered_map<std::string, Group>;
    Groups groups;
};

class Tags
{
public:
    bool MatchFlow(ndFlow::Ptr &flow) const;
    bool Reload(void);

protected:
    mutable std::mutex lock;
    std::unordered_map<std::string, Tag> tags;
};

} // ndOverlay
