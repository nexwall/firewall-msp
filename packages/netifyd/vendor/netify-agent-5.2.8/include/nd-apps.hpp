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

#include <cstdint>
#include <istream>
#include <map>
#include <memory>
#include <regex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "nd-addr.hpp"
#include "nd-flow.hpp"
#include "nd-types.hpp"

class ndFlowParser;

using nd_rn4_app = radix_tree<ndRadixNetworkEntry<_ND_ADDR_BITSv4>, ndApp::Id>;
using nd_rn6_app = radix_tree<ndRadixNetworkEntry<_ND_ADDR_BITSv6>, ndApp::Id>;

class ndApplication
{
public:
    ndApp::Id id;
    std::string tag;

    ndApplication()
      : id(ndApp::Id::UNKNOWN), tag(ndApp::Tag::UNKNOWN) { }
    ndApplication(ndApp::Id id, const std::string &tag)
      : id(id), tag(tag) { }
};

typedef std::map<std::string, ndApp::Id> nd_apps_t;
typedef std::map<std::string, std::shared_ptr<ndApplication>> nd_app_tag_map;
typedef std::unordered_set<std::string> nd_tlds_t;
typedef std::unordered_map<ndApp::Id, std::shared_ptr<ndApplication>, ndEnumHasher> nd_app_id_map;
typedef std::unordered_map<std::string, ndApp::Id> nd_domains_t;
typedef std::unordered_map<std::string, std::pair<std::unique_ptr<std::regex>, std::string>> nd_domain_rx_xforms_t;

class ndSoftDissector
{
public:
    signed aid;
    signed pid;
    const std::string expr;

    ndSoftDissector() : aid(-1), pid(-1), expr{} { }
    ndSoftDissector(signed aid, signed pid, const std::string &expr)
      : aid(aid), pid(pid), expr(expr) { }
    ndSoftDissector &operator=(const ndSoftDissector &other) {
        aid = other.aid;
        pid = other.pid;

        return *this;
    };
};

typedef std::vector<ndSoftDissector> nd_nsd_t;

class ndApplications : public ndSerializer
{
public:
    ndApplications();
    virtual ~ndApplications();

    bool Load(const std::string &filename);
    bool Load(std::istream &stream);
    bool LoadLegacy(const std::string &filename);

    bool Save(const std::string &filename);
    bool SaveLegacy(const std::string &filename);

    ndApp::Id Find(const std::string &domain);
    ndApp::Id Find(const ndAddr &addr, bool app_override = false);

    bool Lookup(ndApp::Id id, std::string &dst);
    const char *Lookup(ndApp::Id id);
    ndApp::Id Lookup(const std::string &tag);
    bool Lookup(const std::string &tag, ndApplication &app);
    bool Lookup(ndApp::Id id, ndApplication &app);

    void Get(nd_apps_t &apps_copy) const;
    const std::string GetLibrary(void) const { return library; }
    const std::string GetName(void) const { return name; }
    const std::string GetVersion(void) const { return version; }

    bool SoftDissectorMatch(ndFlow::Ptr const &flow,
      ndFlowParser *parser,
      ndSoftDissector &match);

    template <class T>
    void Encode(T &output) const {
        serialize(output, { "signatures", "version" }, version);
        serialize(output, { "signatures", "apps" }, stats.ac);
        serialize(output, { "signatures", "app_id_overrides" },
          stats.oc);
        serialize(output, { "signatures", "domains" }, stats.dc);
        serialize(output, { "signatures", "networks" },
          stats.nc);
        serialize(output,
          { "signatures", "soft_dissectors" }, stats.sc);
        serialize(output, { "signatures", "transforms" },
          stats.xc);
    };

protected:
    mutable std::recursive_mutex lock;

    nd_app_id_map apps;
    nd_app_tag_map app_tags;
    nd_tlds_t tlds;
    nd_domains_t domains;
    nd_nsd_t soft_dissectors;
    nd_domain_rx_xforms_t domain_xforms;
    std::string library = { "-" };
    std::string name = { "-" };
    std::string version = { "-" };

    struct {
        size_t ac, dc, nc, oc, sc, xc;
    } stats;

    void Reset(bool free_only = false);

    ndApplication *AddApp(ndApp::Id id, const std::string &tag);
    bool AddDomain(ndApp::Id id, const std::string &domain);
    bool AddDomainTransform(const std::string &search,
      const std::string &replace);
    bool AddNetwork(ndApp::Id id,
      const std::string &network, bool app_override = false);
    bool AddSoftDissector(signed aid, signed pid,
      const std::string &expr);

private:
    std::unique_ptr<nd_rn4_app> app_networks4;
    std::unique_ptr<nd_rn6_app> app_networks6;
    std::unique_ptr<nd_rn4_app> app_overrides4;
    std::unique_ptr<nd_rn6_app> app_overrides6;
};
