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

#include <ostream>
#include <string>
#include <vector>

#include "nd-apps.hpp"
#include "nd-except.hpp"
#include "nd-flow.hpp"
#include "nd-protos.hpp"
#include "nd-types.hpp"
#include "nd-util.hpp"

class ndFlowHashCacheEntry
{
public:
    ndFlowHashCacheEntry()
      : app_id(ndApp::Id::UNKNOWN), proto_id(ndProto::Id::UNKNOWN) { }
    ndFlowHashCacheEntry(const ndFlow::Ptr &flow)
      : app_id(flow->detected_application),
        proto_id(flow->detected_protocol) {
        if (flow->digest_mdata.empty())
            throw ndExceptionSystemError(
              "FlowHashCacheEntry",
              "flow metadata vector can not be empty");
        digest = flow->digest_mdata.back();
    }

    friend std::ostream &operator<<(std::ostream &stream,
      const ndFlowHashCacheEntry &entry) {
        std::string _digest;
        nd_xxh64_to_string(entry.digest, _digest);
        stream << _digest << "," << entry.app_id << ","
               << static_cast<unsigned>(entry.proto_id);
        return stream;
    }

    ndDigest digest;
    ndApp::Id app_id;
    ndProto::Id proto_id;
};

class ndFlowHashCache :
  public ndLRUCache<ndDigest, ndFlowHashCacheEntry>
{
public:
    ndFlowHashCache(size_t cache_size);

    inline void Insert(const ndFlow::Ptr &flow) {
        CacheInsert(flow->digest_lower, ndFlowHashCacheEntry(flow));
    }

    inline void Insert(const ndDigest &digest_lower,
      const ndFlowHashCacheEntry &entry) {
        CacheInsert(digest_lower, entry);
    }

    inline bool Lookup(const ndDigest &digest_lower,
      ndFlowHashCacheEntry &entry) {
        return CacheLookup(digest_lower, entry);
    }

    void Load(void);
    void Save(void) const;
};
