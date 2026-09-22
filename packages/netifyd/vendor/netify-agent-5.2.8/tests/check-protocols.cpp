// Netify Agent Test Suite
// Copyright (C) 2024 eGloo Incorporated
// <http://www.egloo.ca>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <algorithm>
#include <iostream>

#include "nd-ndpi.hpp"
#include "nd-protos.hpp"

using namespace std;

int main(int argc, char *argv[]) {
    int rc = 0;
    char proto_name[64];

    cerr << "Testing Netify Agent Protocols..." << endl;

    nd_ndpi_global_init();
    ndpi_detection_module_struct *ndpi = nd_ndpi_init();

    cerr << endl
         << "nDPI protocol count: " << NDPI_LAST_IMPLEMENTED_PROTOCOL
         << endl;
    cerr << "Netify Agent protocol count: "
         << ndProto::nDPI::Protos.size() << endl
         << endl;

    cout << "\"ndpi_id\", \"netifyd_id\", \"ndpi_tag\", "
            "\"problem\""
         << endl;

    for (uint16_t id = 0; id < NDPI_LAST_IMPLEMENTED_PROTOCOL; id++)
    {
        auto it = ndProto::nDPI::Protos.find(id);
        if (find(ndProto::nDPI::Disabled.begin(),
              ndProto::nDPI::Disabled.end(),
              id) != ndProto::nDPI::Disabled.end())
            continue;
        if (find(ndProto::nDPI::Free.begin(),
              ndProto::nDPI::Free.end(),
              id) != ndProto::nDPI::Free.end())
            continue;

        ndpi_protocol proto = { { 0 } };
        proto.proto.master_protocol = id;
        ndpi_protocol2name(ndpi, proto, proto_name,
          sizeof(proto_name));

        if (it != ndProto::nDPI::Protos.end()) {
            auto tag = ndProto::Tags.find((it->second));
            if (tag == ndProto::Tags.end()) {
                cout << id << ", " << (unsigned)it->second
                     << ", \"" << proto_name << "\", "
                     << "\"missing tag\"" << endl;
                rc++;
            }

            continue;
        }

        rc++;
        cout << id << ", " << 0 << ", \"" << proto_name << "\", "
             << "\"missing protocol\"" << endl;
    }

    if (rc != 0) cerr << endl;
    cerr << "Test result: " << ((rc == 0) ? "PASS" : "FAIL") << endl
         << endl;

    return rc;
}
