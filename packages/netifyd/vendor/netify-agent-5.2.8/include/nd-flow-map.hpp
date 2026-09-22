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
#include <unordered_map>
#include <utility>
#include <vector>

#include "nd-flow.hpp"

class ndFlowMap
{
public:
    ndFlowMap(size_t buckets = ND_FLOW_MAP_BUCKETS);
    virtual ~ndFlowMap();

    ndFlow::Ptr Lookup(uint64_t hash_id,
      bool acquire_lock = false);
    bool Insert(uint64_t hash_id,
      ndFlow::Ptr &flow, bool unlocked = false);
    inline bool InsertUnlocked(uint64_t hash_id,
      ndFlow::Ptr &flow) {
        return Insert(hash_id, flow, true);
    }

    bool Delete(uint64_t hash_id);
    void MoveToTail(uint64_t hash_id, ndFlow* flow);
    void MoveToShort(uint64_t hash_id, ndFlow* flow);


    struct Bucket {
        std::unordered_map<uint64_t, ndFlow::Ptr> map;
        ndFlow* lru_short_head = nullptr;
        ndFlow* lru_short_tail = nullptr;
        ndFlow* lru_long_head = nullptr;
        ndFlow* lru_long_tail = nullptr;

        void PushBackShort(ndFlow* f);
        void PushBackLong(ndFlow* f);
        void Remove(ndFlow* f);
    };
    typedef Bucket Map;

    Map &Acquire(size_t b);
    const Map &AcquireConst(size_t b) const;

    void ReleaseBucket(size_t b) const;
#if 0
    inline void Release(uint64_t hash_id) const {
        ReleaseBucket(HashToBucket(hash_id));
    }
#else
    void Release(uint64_t hash_id) const;
#endif
#ifndef _ND_LEAN_AND_MEAN
    void DumpBucketStats(void);
#endif

    inline size_t GetBuckets(void) const { return buckets; }

protected:
    unsigned HashToBucket(uint64_t hash_id) const {
        return (hash_id % buckets);
    }

    size_t buckets;

    typedef std::vector<Map *> FlowBucket;
    FlowBucket bucket;

    typedef std::vector<std::unique_ptr<std::mutex>> BucketLock;
    mutable BucketLock bucket_lock;
};
