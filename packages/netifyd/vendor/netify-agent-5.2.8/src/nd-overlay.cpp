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

#include <fstream>

#include "nd-config.hpp"
#include "nd-except.hpp"
#include "nd-overlay.hpp"
#include "nd-util.hpp"

using namespace std;
using namespace ndOverlay;
using json = nlohmann::json;

void Criteria::Load(const nlohmann::json &jconfig) {
    auto ji = jconfig.find("applications");
    if (ji != jconfig.end()) apps = ji->get<Apps>();

    ji = jconfig.find("application_categories");
    if (ji != jconfig.end()) app_categories = ji->get<Categories>();

    ji = jconfig.find("protocols");
    if (ji != jconfig.end()) protos = ji->get<Protos>();

    ji = jconfig.find("ip_protocols");
    if (ji != jconfig.end()) ip_protos = ji->get<IPProtos>();

    ji = jconfig.find("ports");
    if (ji != jconfig.end()) ports = ji->get<Ports>();

    ji = jconfig.find("dst_ports");
    if (ji != jconfig.end()) dst_ports = ji->get<Ports>();

    ji = jconfig.find("src_ports");
    if (ji != jconfig.end()) src_ports = ji->get<Ports>();
}

bool Criteria::operator==(const ndFlow::Ptr &flow) const {
    if (! apps.empty() &&
      apps.find(flow->detected_application) == apps.end()) return false;

    if (! app_categories.empty() &&
      app_categories.find(flow->category.application) == app_categories.end()) return false;

    if (! protos.empty() &&
      protos.find(flow->detected_protocol) == protos.end()) return false;

    if (! ip_protos.empty() &&
      ip_protos.find(flow->ip_protocol) == ip_protos.end()) return false;

    if (! ports.empty() &&
      ports.find(flow->lower_addr.GetPort()) == ports.end() &&
      ports.find(flow->upper_addr.GetPort()) == ports.end()) return false;

    if (! src_ports.empty() && flow->origin == ndFlow::Origin::LOWER &&
        src_ports.find(flow->lower_addr.GetPort()) == src_ports.end())
        return false;

    if (! src_ports.empty() && flow->origin == ndFlow::Origin::UPPER &&
        src_ports.find(flow->upper_addr.GetPort()) == src_ports.end())
        return false;

    if (! dst_ports.empty() && flow->origin == ndFlow::Origin::LOWER &&
        dst_ports.find(flow->upper_addr.GetPort()) == dst_ports.end())
        return false;

    if (! dst_ports.empty() && flow->origin == ndFlow::Origin::UPPER &&
        dst_ports.find(flow->lower_addr.GetPort()) == dst_ports.end())
        return false;

    return true;
}

void Group::Load(const nlohmann::json &jconfig) {
    auto jcriteria = jconfig.at("criteria");

    criteria.Load(jcriteria);
}

bool Group::MatchFlow(const ndFlow::Ptr &flow,
  Result &result, const string &prefix) const {
    if (criteria == flow) {
        auto r = result.insert(prefix + "." + tag);
        return r.second;
    }

    return false;
}

void Tag::Load(const nlohmann::json &jconfig) {
    auto jcat = jconfig.find("category_id");
    if (jcat != jconfig.end())
        category_id = jcat->get<ndCategories::Id>();

    auto jgroups = jconfig.at("groups");
    if (! jgroups.is_array())
        throw ndException("%s must be %s", "groups", "an array");

    for (auto &jg : jgroups) {
        auto jtag = jg.at("group");

        Group group(jtag.get<string>());
        group.Load(jg);

        groups.insert(make_pair(jtag.get<string>(), group));
    }
}

bool Tag::MatchFlow(ndFlow::Ptr &flow, Result &result) const {
    size_t matches = 0;
    for (auto &g : groups) {
        if (! g.second.MatchFlow(flow, result, tag)) continue;
        matches++;
    }

    if (matches > 0) {
        flow->category.overlay = category_id;
        return true;
    }

    return false;
}

bool Tags::MatchFlow(ndFlow::Ptr &flow) const {
    const lock_guard<mutex> lg(lock);

    Result result;
    for (auto &t : tags) t.second.MatchFlow(flow, result);

    flow->tags.clear();
    flow->tags.insert(result.begin(), result.end());

    return (! flow->tags.empty());
}

bool Tags::Reload(void) {
    const string filename = ndGC.path_overlay_config;

    if (nd_file_exists(filename) != 1) return true;

    ifstream ifs(filename);

    if (! ifs.is_open()) {
        nd_dprintf(
          "Error opening overlay configuration: %s.",
          filename.c_str());
    }

    const lock_guard<mutex> lg(lock);

    json jconfig;

    try {
        ifs >> jconfig;

        tags.clear();

        auto jtags = jconfig.find("tags");
        if (jtags == jconfig.end()) return true;

        if (! jtags->is_array())
            throw ndException("%s must be %s", "tags", "an array");

        for (auto &jt : *jtags) {
            auto jtag = jt.at("tag");

            Tag tag(jtag.get<string>());
            tag.Load(jt);

            tags.insert(make_pair(jtag.get<string>(), tag));
            nd_dprintf("loaded overlay tag: %s\n", jtag.get<string>().c_str());
        }
    }
    catch (exception &e) {
        nd_printf(
          "Error loading overlay configuration: %s",
          filename.c_str());
        nd_dprintf("%s: %s\n", filename.c_str(), e.what());

        return false;
    }

    return true;
}

