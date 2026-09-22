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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <fstream>
#include <radix/radix_tree.hpp>

#include "nd-apps.hpp"
#include "nd-base64.hpp"
#include "nd-except.hpp"
#include "nd-flow-parser.hpp"
#include "nd-license-client.hpp"

using namespace std;

ndApplications::ndApplications()
  : stats{ 0 } {
    Reset();
}

ndApplications::~ndApplications() {
    Reset(true);
}

bool ndApplications::Load(const string &filename) {

    if (ndLicenseClient::IsValid()) {
        string datfile = nd_change_ext(filename, "dat");

        if (nd_file_exists(datfile) == 1) {
            stringstream ss;
            if (ndLicenseClient::GetInstance().LoadData(
              "application-signatures", datfile, ss) && Load(ss))
                return true;
        }
    }

    ifstream ifs(filename);
    if (! ifs.is_open()) return false;

    return Load(ifs);
}

bool ndApplications::Load(istream &ifs) {
    stats.ac = stats.dc = stats.nc = stats.oc = stats.sc = stats.xc = 0;

    lock_guard<recursive_mutex> ul(lock);

    Reset();

    string line;
    while (getline(ifs, line)) {
        nd_ltrim(line);
        if (line.empty() || line[0] == '#') continue;

        size_t p;
        if ((p = line.find_first_of(":")) == string::npos)
            continue;

        string type = line.substr(0, p);

        if (type != "app" && type != "aio" && type != "dom" &&
          type != "net" && type != "nsd" && type != "xfm" && type != "ver")
            continue;

        line = line.substr(p + 1);

        if (type == "app" || type == "aio" || type == "dom" || type == "net") {
            if ((p = line.find_first_of(":")) == string::npos)
                continue;

            ndApp::Id id = static_cast<ndApp::Id>(
                strtoul(line.substr(0, p).c_str(), nullptr, 0)
            );

            if (type == "app" && apps.find(id) == apps.end())
            {
                if (AddApp(id, line.substr(p + 1)) != nullptr)
                    stats.ac++;
            }
            else if (type == "aio")
            {
                if (AddNetwork(id, line.substr(p + 1), true))
                    stats.oc++;
            }
            else if (type == "dom") {
                if (AddDomain(id, line.substr(p + 1)))
                    stats.dc++;
            }
            else if (type == "net") {
                if (AddNetwork(id, line.substr(p + 1)))
                    stats.nc++;
            }
        }
        else if (type == "xfm") {
            if ((p = line.find_first_of(":")) == string::npos)
                continue;
            if (AddDomainTransform(line.substr(0, p),
                  line.substr(p + 1)))
                stats.xc++;
        }
        else if (type == "nsd") {
            if ((p = line.find_last_of(":")) == string::npos)
                continue;

            string expr = line.substr(p + 1);
            line = line.substr(0, p);
            if ((p = line.find_last_of(":")) == string::npos)
                continue;

            signed pid = (signed)strtol(
              line.substr(p + 1).c_str(), nullptr, 0);

            line = line.substr(0, p);
            signed aid = (signed)strtol(line.c_str(), nullptr, 0);

            if (AddSoftDissector(aid, pid, expr))
                stats.sc++;
        }
        else if (type == "ver") {
            version = line;
        }
    }

    if (stats.ac > 0) {
        nd_dprintf(
          "Loaded %u apps, %u domains, %u networks, %u app IP overrides, %u "
          "soft-dissectors, %u transforms, version: %s\n",
          stats.ac, stats.dc, stats.nc, stats.oc, stats.sc, stats.xc,
          version.c_str());
    }

    return (stats.ac > 0 && (stats.ac > 0 || stats.nc > 0));
}

bool ndApplications::LoadLegacy(const string &filename) {
    size_t ac = 0, dc = 0, nc = 0;

    ifstream ifs(filename);

    if (! ifs.is_open()) return false;

    lock_guard<recursive_mutex> ul(lock);

    Reset();

    string line;
    while (getline(ifs, line)) {
        nd_trim(line);
        if (line.empty() || line[0] == '#') continue;

        size_t p;
        if ((p = line.find_last_of("@")) == string::npos)
            continue;

        stringstream entries(line.substr(0, p));

        string app = line.substr(p + 1);
        nd_trim(app);

        if ((p = app.find_first_of(".")) == string::npos)
            continue;

        ndApp::Id app_id = static_cast<ndApp::Id>(
            strtoul(app.substr(0, p).c_str(), nullptr, 0)
        );

        string app_tag = app.substr(p + 1);
        nd_trim(app_tag);

        if (apps.find(app_id) == apps.end()) {
            if (AddApp(app_id, app_tag) != nullptr) ac++;
            else return false;
        }

        string entry;
        while (getline(entries, entry, ',')) {
            nd_trim(entry);

            if ((p = entry.find_first_of(":")) == string::npos)
                continue;

            string type = entry.substr(0, p);
            nd_trim(type);

            if (type == "host") {
                string domain = entry.substr(p + 1);
                nd_trim(domain);
                nd_trim(domain, '"');
                if (domain[0] != '^') continue;
                nd_ltrim(domain, '^');
                nd_rtrim(domain, '$');

                if (AddDomain(app_id, domain)) dc++;
            }
            else if (type == "ip") {
                string cidr = entry.substr(p + 1);
                nd_trim(cidr);

                if (AddNetwork(app_id, cidr)) nc++;
            }
        }
    }

    if (ac > 0) {
        nd_dprintf(
          "Loaded [legacy] %u apps, %u domains, %u "
          "networks, %u transforms.\n",
          ac, dc, nc, 0);
    }

    return (ac > 0 && (ac > 0 || nc > 0));
}

bool ndApplications::Save(const string &filename) {
#ifndef _ND_LEAN_AND_MEAN
    size_t nc = 0, oc = 0;

    ofstream ofs(filename, ofstream::trunc);

    if (! ofs.is_open()) return false;

    lock_guard<recursive_mutex> ul(lock);

    for (auto &it : apps)
        ofs << "app:" << it.first << ":" << it.second->tag << endl;
    for (auto &it : domains)
        ofs << "dom:" << it.second << ":" << it.first << endl;

    nd_rn4_app *rn4 = app_networks4.get();
    for (auto &it : (*rn4)) {
        string ip;
        if (it.first.GetString(ip, ndAddr::MakeFlags::PREFIX)) {
            ofs << "net:" << it.second << ":" << ip << endl;
            nc++;
        }
    }

    nd_rn6_app *rn6 = app_networks6.get();
    for (auto &it : (*rn6)) {
        string ip;
        if (it.first.GetString(ip, ndAddr::MakeFlags::PREFIX)) {
            ofs << "net:" << it.second << ":" << ip << endl;
            nc++;
        }
    }

    rn4 = app_overrides4.get();
    for (auto &it : (*rn4)) {
        string ip;
        if (it.first.GetString(ip, ndAddr::MakeFlags::PREFIX))
        {
            ofs << "aio:" << it.second << ":" << ip << endl;
            oc++;
        }
    }

    rn6 = app_overrides6.get();
    for (auto &it : (*rn6)) {
        string ip;
        if (it.first.GetString(ip, ndAddr::MakeFlags::PREFIX))
        {
            ofs << "aio:" << it.second << ":" << ip << endl;
            oc++;
        }
    }
    for (auto &it : domain_xforms)
        ofs << "xfm:" << it.first << ":" << it.second.second << endl;

    nd_dprintf(
      "Exported %u apps, %u domains, %u networks, "
      "%u app IP overrides, %u transforms.\n",
      apps.size(), domains.size(), nc, oc, domain_xforms.size());

    return true;
#else
    nd_printf(
      "Sorry, this feature was disabled (embedded).\n");
    return false;
#endif  // _ND_LEAN_AND_MEAN
}

bool ndApplications::SaveLegacy(const string &filename) {
#ifndef _ND_LEAN_AND_MEAN
    size_t nc = 0;

    ofstream ofs(filename, ofstream::trunc);

    if (! ofs.is_open()) return false;

    lock_guard<recursive_mutex> ul(lock);

    for (auto &it : domains) {
        ofs << "host:\"" << it.first << "\"@"
            << Lookup(it.second) << endl;
    }

    nd_rn4_app *rn4 = app_networks4.get();
    for (auto &it : (*rn4)) {
        string ip;
        if (it.first.GetString(ip, ndAddr::MakeFlags::PREFIX))
        {
            ofs << "ip:" << ip << "@" << Lookup(it.second) << endl;
            nc++;
        }
    }

    nd_rn6_app *rn6 = app_networks6.get();
    for (auto &it : (*rn6)) {
        string ip;
        if (it.first.GetString(ip,
              ndAddr::MakeFlags::PREFIX | ndAddr::MakeFlags::IPV6_URI))
        {
            ofs << "ipv6:" << ip << "@" << Lookup(it.second) << endl;
            nc++;
        }
    }

    nd_dprintf(
      "Exported [legacy] %u apps, %u domains, %u networks, "
      "%u transforms.\n",
      apps.size(), domains.size(), nc, 0);
    return true;
#else
    nd_printf(
      "Sorry, this feature was disabled (embedded).\n");
    return false;
#endif  // _ND_LEAN_AND_MEAN
}

ndApp::Id ndApplications::Find(const string &domain) {
    lock_guard<recursive_mutex> ul(lock);

    vector<string> search;

    if (! domain.empty()) {
        for (auto &rx : domain_xforms) {
            string result = regex_replace(domain,
              (*rx.second.first), rx.second.second);
            if (result.size()) search.push_back(result);
        }

        if (search.empty()) search.push_back(domain);
    }

    for (auto &it : search) {
        for (size_t p = it.find('.'); ! it.empty(); p = it.find('.'))
        {
            if (p == string::npos && tlds.find(it) == tlds.end())
                break;

            auto it_domain = domains.find(it);
            if (it_domain != domains.end())
                return it_domain->second;

            if (p == string::npos) break;

            it = it.substr(p + 1);
        }
    }

    return ndApp::Id::UNKNOWN;
}

ndApp::Id ndApplications::Find(const ndAddr &addr, bool app_override) {
    if (! addr.IsValid() || ! addr.IsIP())
        return ndApp::Id::UNKNOWN;

    if (addr.IsIPv4()) {
        ndRadixNetworkEntry<_ND_ADDR_BITSv4> entry;
        if (ndRadixNetworkEntry<_ND_ADDR_BITSv4>::CreateQuery(
              entry, addr))
        {
            lock_guard<recursive_mutex> ul(lock);

            nd_rn4_app::iterator it;
            nd_rn4_app *rn4 = ((app_override) ?
              app_overrides4.get() :
              app_networks4.get());
#if 0
            vector<nd_rn4_app::iterator> it_matches;
            rn4->prefix_match(entry, it_matches);
            if (it_matches.size()) {
                nd_dprintf("Prefix matches:\n");
                for (auto &i : it_matches) {
                    string ip;
                    i->first.GetString(ip, ndAddr::MakeFlags::PREFIX);
                    nd_dprintf(" %s\n", ip.c_str());
                }
            }

            it_matches.clear();

            rn4->greedy_match(entry, it_matches);
            if (it_matches.size()) {
                nd_dprintf("Greedy matches:\n");
                for (auto &i : it_matches) {
                    string ip;
                    i->first.GetString(ip, ndAddr::MakeFlags::PREFIX);
                    nd_dprintf(" %s\n", ip.c_str());
                }
            }
#endif
            if ((it = rn4->longest_match(entry)) != rn4->end())
                return it->second;
        }
    }

    if (addr.IsIPv6()) {
        ndRadixNetworkEntry<_ND_ADDR_BITSv6> entry;
        if (ndRadixNetworkEntry<_ND_ADDR_BITSv6>::CreateQuery(
              entry, addr))
        {
            lock_guard<recursive_mutex> ul(lock);

            nd_rn6_app::iterator it;
            nd_rn6_app *rn6 = ((app_override) ?
              app_overrides6.get() :
              app_networks6.get());

            if ((it = rn6->longest_match(entry)) != rn6->end())
                return it->second;
        }
    }

    return ndApp::Id::UNKNOWN;
}

bool ndApplications::Lookup(ndApp::Id id, string &dst) {
    lock_guard<recursive_mutex> ul(lock);

    auto it = apps.find(id);
    if (it == apps.end()) {
        dst = "Unknown";
        return false;
    }
    dst = it->second->tag;
    return true;
}

const char *ndApplications::Lookup(ndApp::Id id) {
    lock_guard<recursive_mutex> ul(lock);

    auto it = apps.find(id);
    if (it != apps.end()) return it->second->tag.c_str();
    return "Unknown";
}

ndApp::Id ndApplications::Lookup(const string &tag) {
    lock_guard<recursive_mutex> ul(lock);

    auto it = app_tags.find(tag);
    if (it != app_tags.end()) return it->second->id;
    return ndApp::Id::UNKNOWN;
}

bool ndApplications::Lookup(const string &tag, ndApplication &app) {
    lock_guard<recursive_mutex> ul(lock);

    auto it = app_tags.find(tag);
    if (it != app_tags.end()) {
        app = (*it->second);
        return true;
    }

    return false;
}

bool ndApplications::Lookup(ndApp::Id id, ndApplication &app) {
    lock_guard<recursive_mutex> ul(lock);

    auto it = apps.find(id);
    if (it != apps.end()) {
        app = (*it->second);
        return true;
    }
    return false;
}

void ndApplications::Reset(bool free_only) {
    app_networks4.reset();
    app_networks6.reset();
    app_overrides4.reset();
    app_overrides6.reset();

    if (! free_only) {
        app_networks4 = make_unique<nd_rn4_app>();
        app_networks6 = make_unique<nd_rn6_app>();

        app_overrides4 = make_unique<nd_rn4_app>();
        app_overrides6 = make_unique<nd_rn6_app>();
    }

    apps.clear();
    app_tags.clear();
    domains.clear();
    domain_xforms.clear();
    soft_dissectors.clear();
}

void ndApplications::Get(nd_apps_t &apps_copy) const {
    apps_copy.clear();

    lock_guard<recursive_mutex> ul(lock);

    for (auto &app : apps)
        apps_copy.insert(make_pair(app.second->tag, app.first));
}

ndApplication *
ndApplications::AddApp(ndApp::Id id, const string &tag) {
    auto it_id = apps.find(id);
    if (it_id != apps.end()) return it_id->second.get();

    auto it_tag = app_tags.find(tag);
    if (it_tag != app_tags.end()) return nullptr;

    auto app = make_shared<ndApplication>(id, tag);

    apps.insert(make_pair(id, app));
    app_tags.insert(make_pair(tag, app));

    return app.get();
}

bool ndApplications::AddDomain(ndApp::Id id, const string &domain) {
    auto rc = domains.insert(make_pair(domain, id));
    if (domain.find_first_of(".") == string::npos)
        tlds.insert(domain);
    return rc.second;
}

bool ndApplications::AddDomainTransform(const string &search,
  const string &replace) {
    if (search.size() == 0) return false;
    if (domain_xforms.find(search) != domain_xforms.end())
        return false;

    try {
        auto rx = make_unique<regex>(search,
          regex::extended | regex::icase | regex::optimize);
        domain_xforms[search] = make_pair(std::move(rx), replace);
        return true;
    }
    catch (const regex_error &e) {
        string error;
        nd_regex_error(e, error);
        nd_printf(
          "WARNING: Error compiling domain transform "
          "regex: "
          "%s: %s [%d]\n",
          search.c_str(), error.c_str(), e.code());
    }

    return false;
}

bool ndApplications::AddNetwork(ndApp::Id id,
  const string &network, bool app_override) {
    ndAddr addr(network);

    if (! addr.IsValid() || ! addr.IsIP()) {
        nd_printf("Invalid IPv4/6 network address: %s\n",
          network.c_str());
        return false;
    }

    try {
        if (addr.IsIPv4()) {
            ndRadixNetworkEntry<_ND_ADDR_BITSv4> entry;
            if (ndRadixNetworkEntry<_ND_ADDR_BITSv4>::Create(entry, addr))
            {
                nd_rn4_app *rn4 = ((app_override) ?
                  app_overrides4.get() :
                  app_networks4.get());

                (*rn4)[entry] = id;
                return true;
            }
        }
        else {
            ndRadixNetworkEntry<_ND_ADDR_BITSv6> entry;
            if (ndRadixNetworkEntry<_ND_ADDR_BITSv6>::Create(entry, addr))
            {
                nd_rn6_app *rn6 = ((app_override) ?
                  app_overrides6.get() :
                  app_networks6.get());

                (*rn6)[entry] = id;
                return true;
            }
        }
    }
    catch (runtime_error &e) {
        nd_dprintf("Error adding network: %s: %s\n",
          network.c_str(), e.what());
    }

    return false;
}

bool ndApplications::AddSoftDissector(signed aid,
  signed pid, const string &encoded_expr) {
    string decoded_expr = base64_decode(encoded_expr.c_str(),
      encoded_expr.size());

    if (aid < 0 && pid < 0) return false;

    if (ndGC.verbosity > 4) {
        nd_dprintf("%s: app: %d, proto: %d, expr: \"%s\"\n",
          __PRETTY_FUNCTION__, aid, pid, decoded_expr.c_str());
    }

    soft_dissectors.push_back(
      ndSoftDissector(aid, pid, decoded_expr));

    return true;
}

bool ndApplications::SoftDissectorMatch(ndFlow::Ptr const &flow,
  ndFlowParser *parser, ndSoftDissector &match) {
    lock_guard<recursive_mutex> ul(lock);

    for (auto &it : soft_dissectors) {
        try {
            if (! parser->Parse(flow, it.expr)) continue;
            match = it;
            return true;
        }
        catch (string &e) {
            nd_dprintf("%s: %s: %s\n", __PRETTY_FUNCTION__,
              it.expr.c_str(), e.c_str());
        }
    }

    return false;
}
