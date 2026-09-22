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

#include <map>

#include <ndpi_protocol_ids.h>

#include "nd-category.hpp"
#include "nd-config.hpp"
#include "nd-instance.hpp"
#include "nd-ndpi.hpp"
#include "nd-protos.hpp"
#include "nd-thread.hpp"
#include "nd-util.hpp"

using namespace std;

extern mutex nd_printf_mutex;

static ndpi_global_context *ndpi_ctx = nullptr;
static NDPI_PROTOCOL_BITMASK ndpi_protos;

#ifdef _ND_ENABLE_NDPI_DEBUG
void nd_ndpi_debug_printf(uint32_t protocol,
  struct ndpi_detection_module_struct *ndpi,
  ndpi_log_level_t level, const char *file,
  const char *func, unsigned line, const char *format, ...) {
    if (ndGC_DEBUG && (ndGC_DEBUG_NDPI || level == NDPI_LOG_ERROR))
    {
        lock_guard<mutex> lock(nd_printf_mutex);

        va_list ap;
        va_start(ap, format);

        fprintf(stdout,
          "[nDPI:%08x:%p:%s]: %s/%s:%d: ", protocol, ndpi,
          (level == NDPI_LOG_ERROR)         ? "ERROR" :
            (level == NDPI_LOG_TRACE)       ? "TRACE" :
            (level == NDPI_LOG_DEBUG)       ? "DEBUG" :
            (level == NDPI_LOG_DEBUG_EXTRA) ? "DEXTRA" :
                                              "UNK???",
          file, func, line);

        vfprintf(stdout, format, ap);
        va_end(ap);
    }
}
#endif  // _ND_ENABLE_NDPI_DEBUG

void nd_ndpi_global_init(void) {
    nd_dprintf("Initializing nDPI v%s, API v%u...\n",
      ndpi_revision(), NDPI_API_VERSION);

    if (ndpi_ctx == nullptr) ndpi_ctx = ndpi_global_init();

    if (ndpi_get_api_version() != NDPI_API_VERSION) {
        throw ndException(
          "%s: nDPI library version mis-match", __PRETTY_FUNCTION__);
    }

    NDPI_BITMASK_RESET(ndpi_protos);

    auto it = ndGC.protocols.find("ALL");
    if (it == ndGC.protocols.end()) {
        it = ndGC.protocols.find("all");
        if (it == ndGC.protocols.end())
            it = ndGC.protocols.find("All");
    }

    if (it != ndGC.protocols.end()) {
        if (strcasecmp(it->second.c_str(), "include") == 0) {
            NDPI_BITMASK_SET_ALL(ndpi_protos);
            nd_dprintf("Enabled all protocols.\n");
        }
        else if (strcasecmp(it->second.c_str(), "exclude") == 0)
        {
            nd_dprintf("Disabled all protocols.\n");
        }
    }

    for (auto it : ndGC.protocols) {
        enum class Action : int8_t {
            NONE = -1,
            INCLUDE = 0,
            EXCLUDE = 1,
        };

        Action action = Action::NONE;

        if (strcasecmp(it.second.c_str(), "include") == 0)
            action = Action::INCLUDE;
        else if (strcasecmp(it.second.c_str(), "exclude") == 0)
            action = Action::EXCLUDE;
        else continue;

        map<const string, uint16_t> ids;
        uint16_t id = NDPI_PROTOCOL_UNKNOWN;
        ndProto::Id proto = ndProto::GetId(it.first);

        if (proto == ndProto::Id::UNKNOWN) {
            id = ndProto::nDPI::Find(static_cast<ndProto::Id>(
              strtoul(it.first.c_str(), nullptr, 0)));
        }
        else id = ndProto::nDPI::Find(proto);

        if (id != NDPI_PROTOCOL_UNKNOWN)
            ids.insert(make_pair(it.first, id));
        else {
            const ndInstance &ndi = ndInstance::GetInstance();
            ndCategories::Id cat_id = ndi.categories.LookupTag(
              ndCategories::Type::PROTO, it.first);
            if (cat_id == ndCategory::UNKNOWN) continue;

            for (auto &p : ndProto::Tags) {
                if (ndi.categories.Lookup(ndCategories::Type::PROTO,
                      static_cast<unsigned>(p.first)) == cat_id)
                {
                    id = ndProto::nDPI::Find(p.first);
                    if (id == NDPI_PROTOCOL_UNKNOWN)
                        continue;
                    ids.insert(make_pair(
                      it.first + ": " + p.second, id));
                }
            }
        }

        for (auto &i : ids) {
            switch (action) {
            case Action::INCLUDE:
                NDPI_ADD_PROTOCOL_TO_BITMASK(ndpi_protos, i.second);
                nd_dprintf(
                  "Enabled protocol: %s (ID# %hu)\n",
                  i.first.c_str(), i.second);
                break;

            case Action::EXCLUDE:
                NDPI_DEL_PROTOCOL_FROM_BITMASK(ndpi_protos, i.second);
                nd_dprintf(
                  "Disabled protocol: %s (ID# %hu)\n",
                  i.first.c_str(), i.second);
                break;
            default: break;
            }
        }

        if (ndGC.verbosity > 4) {
            for (auto &p : ndProto::Tags) {
                id = ndProto::nDPI::Find(p.first);
                if (id == NDPI_PROTOCOL_UNKNOWN) continue;
                if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi_protos, id))
                {
                    nd_dprintf(
                      "Enabled dissector: %s (ID# "
                      "%hu/%hu)\n",
                      p.second, p.first, id);
                }
            }
        }
    }

    if (ndGC.protocols.empty()) {
        NDPI_BITMASK_SET_ALL(ndpi_protos);
        nd_dprintf("Enabled all protocols.\n");
    }

    for (auto &it : ndProto::nDPI::Disabled) {
        NDPI_DEL_PROTOCOL_FROM_BITMASK(ndpi_protos, it);
        if (ndGC.verbosity > 4)
            nd_dprintf("Banned protocol by ID: %hu\n", it);
    }
}

void nd_ndpi_global_shutdown(void) {
    if (ndpi_ctx != nullptr) {
        ndpi_global_deinit(ndpi_ctx);
        ndpi_ctx = nullptr;
    }
}

struct ndpi_detection_module_struct *nd_ndpi_init(void) {

    if (ndpi_ctx == nullptr) {
        throw ndException("%s: %s", __PRETTY_FUNCTION__,
          "ndpi_ctx == nullptr");
    }

    struct ndpi_detection_module_struct *ndpi = nullptr;
    ndpi = ndpi_init_detection_module(ndpi_ctx);

    if (ndpi == nullptr) {
        throw ndException("%s: %s", __PRETTY_FUNCTION__,
          "ndpi_init_detection_module");
    }

#ifdef _ND_ENABLE_NDPI_DEBUG
    if (ndGC_DEBUG) {
        set_ndpi_debug_function(ndpi, nd_ndpi_debug_printf);

        ndpi_set_config(ndpi, nullptr, "log.level", "0");
        if (! ndGC_QUIET) {
            ndpi_set_config(ndpi, nullptr, "log.level", "2");
        }
        if (ndGC_DEBUG_NDPI) {
            ndpi_set_config(ndpi, nullptr, "log.level", "3");
        }
    }
#endif
    ndpi_set_config(ndpi, nullptr, "flow_risk_lists.load",
      "0");
    ndpi_set_config(ndpi, nullptr, "fpc", "0");

    ndpi_set_config(ndpi, nullptr,
      "flow_risk.anonymous_subscriber.list."
      "icloudprivaterelay.load",
      "0");
    ndpi_set_config(ndpi, nullptr,
      "flow_risk.anonymous_subscriber.list.protonvpn.load",
      "1");
    ndpi_set_config(ndpi, nullptr,
      "flow_risk.crawler_bot.list.load", "0");

    ndpi_set_config(ndpi, "any", "ip_list.load", "0");

    ndpi_set_config(ndpi, "dns", "process_response", "1");

    ndpi_set_config(ndpi, "tls",
      "metadata.ja3c_fingerprint", "0");
    ndpi_set_config(ndpi, "tls",
      "metadata.ja3s_fingerprint", "0");
    ndpi_set_config(ndpi, "tls",
      "metadata.ja4c_fingerprint", "1");

    ndpi_set_protocol_detection_bitmask2(ndpi, &ndpi_protos);

    ndpi_finalize_initialization(ndpi);

    return ndpi;
}

void nd_ndpi_free(struct ndpi_detection_module_struct *ndpi) {
    ndpi_exit_detection_module(ndpi);
}
