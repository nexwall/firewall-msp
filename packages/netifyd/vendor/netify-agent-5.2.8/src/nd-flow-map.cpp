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

#include "nd-except.hpp"
#include "nd-flow-map.hpp"

using namespace std;

ndFlowMap::ndFlowMap(size_t buckets) : buckets(buckets) {
    for (size_t i = 0; i < buckets; i++) {
        Map *b = new Map;
#ifdef HAVE_CXX11
        b->reserve(ND_HASH_BUCKETS_FLOWS);
#endif
        bucket.push_back(b);
        bucket_lock.emplace_back(new mutex);
    }

    nd_dprintf("Created %lu flow map buckets.\n", buckets);
}

ndFlowMap::~ndFlowMap() {
    for (size_t i = 0; i < buckets; i++) {
        lock_guard<mutex> lock(*bucket_lock[i]);

        delete bucket[i];
    }

    bucket.clear();
    bucket_lock.clear();
}

ndFlow::Ptr
ndFlowMap::Lookup(uint64_t hash_id, bool acquire_lock) {
    ndFlow::Ptr f;
    size_t b = HashToBucket(hash_id);

    bucket_lock[b]->lock();

    auto fi = bucket[b]->map.find(hash_id);
    if (fi != bucket[b]->map.end()) f = fi->second;

    if (! acquire_lock) bucket_lock[b]->unlock();

    return f;
}

bool ndFlowMap::Insert(uint64_t hash_id,
  ndFlow::Ptr &flow, bool unlocked) {
    bool result = false;
    size_t b = HashToBucket(hash_id);

    if (! unlocked) bucket_lock[b]->lock();

    auto fi = bucket[b]->map.insert(make_pair(hash_id, flow));

    result = fi.second;

    if (result) {
        if (flow->ip_protocol == IPPROTO_TCP) bucket[b]->PushBackLong(flow.get());
        else bucket[b]->PushBackShort(flow.get());
    }


    if (! unlocked) bucket_lock[b]->unlock();

    return result;
}

bool ndFlowMap::Delete(uint64_t hash_id) {
    bool deleted = false;
    size_t b = HashToBucket(hash_id);
    lock_guard<mutex> lock(*bucket_lock[b]);

    auto fi = bucket[b]->map.find(hash_id);
    if (fi != bucket[b]->map.end()) {
        deleted = true;
        bucket[b]->Remove(fi->second.get());

        bucket[b]->map.erase(fi);
    }

    return deleted;
}

ndFlowMap::Map &ndFlowMap::Acquire(size_t b) {
    if (b >= buckets) {
        throw ndException("%s: %s: %s", __PRETTY_FUNCTION__,
          "bucket", strerror(EINVAL));
    }

    bucket_lock[b]->lock();

    return *bucket[b];
}

const ndFlowMap::Map &ndFlowMap::AcquireConst(size_t b) const {
    if (b >= buckets) {
        throw ndException("%s: %s: %s", __PRETTY_FUNCTION__,
          "bucket", strerror(EINVAL));
    }

    bucket_lock[b]->lock();

    return *bucket[b];
}

void ndFlowMap::ReleaseBucket(size_t b) const {
    if (b >= buckets) {
        throw ndException("%s: %s: %s", __PRETTY_FUNCTION__,
          "bucket", strerror(EINVAL));
    }

    bucket_lock[b]->unlock();
}

void ndFlowMap::Release(uint64_t hash_id) const {
    ReleaseBucket(HashToBucket(hash_id));
}

#ifndef _ND_LEAN_AND_MEAN
void ndFlowMap::DumpBucketStats(void) {
    for (size_t i = 0; i < buckets; i++) {
        if (bucket_lock[i]->try_lock()) {
            nd_dprintf("ndFlowMap: %4u: %u flow(s).\n", i,
              bucket[i]->map.size());

            bucket_lock[i]->unlock();
        }
        else nd_dprintf("ndFlowMap: %4u: locked.\n", i);
    }
}
#endif

void ndFlowMap::Bucket::PushBackShort(ndFlow* f) {
    if (f->lru_prev || f->lru_next || lru_short_head == f || lru_long_head == f) return;
    if (!lru_short_tail) {
        lru_short_head = lru_short_tail = f;
    } else {
        lru_short_tail->lru_next = f;
        f->lru_prev = lru_short_tail;
        lru_short_tail = f;
    }
    f->lru_list = 1;
}

void ndFlowMap::Bucket::PushBackLong(ndFlow* f) {
    if (f->lru_prev || f->lru_next || lru_short_head == f || lru_long_head == f) return;
    if (!lru_long_tail) {
        lru_long_head = lru_long_tail = f;
    } else {
        lru_long_tail->lru_next = f;
        f->lru_prev = lru_long_tail;
        lru_long_tail = f;
    }
    f->lru_list = 2;
}

void ndFlowMap::Bucket::Remove(ndFlow* f) {
    if (f->lru_list == 1) {
        if (f->lru_prev) f->lru_prev->lru_next = f->lru_next;
        else if (lru_short_head == f) lru_short_head = f->lru_next;
        if (f->lru_next) f->lru_next->lru_prev = f->lru_prev;
        else if (lru_short_tail == f) lru_short_tail = f->lru_prev;
    } else if (f->lru_list == 2) {
        if (f->lru_prev) f->lru_prev->lru_next = f->lru_next;
        else if (lru_long_head == f) lru_long_head = f->lru_next;
        if (f->lru_next) f->lru_next->lru_prev = f->lru_prev;
        else if (lru_long_tail == f) lru_long_tail = f->lru_prev;
    }
    f->lru_prev = f->lru_next = nullptr;
    f->lru_list = 0;
}

void ndFlowMap::MoveToTail(uint64_t hash_id, ndFlow* flow) {
    size_t b = HashToBucket(hash_id);
    bucket_lock[b]->lock();
    if (flow->lru_list == 1) {
        bucket[b]->Remove(flow);
        bucket[b]->PushBackShort(flow);
    } else if (flow->lru_list == 2) {
        bucket[b]->Remove(flow);
        bucket[b]->PushBackLong(flow);
    }
    bucket_lock[b]->unlock();
}

void ndFlowMap::MoveToShort(uint64_t hash_id, ndFlow* flow) {
    size_t b = HashToBucket(hash_id);
    bucket_lock[b]->lock();
    if (flow->lru_list == 2) {
        bucket[b]->Remove(flow);
        bucket[b]->PushBackShort(flow);
    }
    bucket_lock[b]->unlock();
}
