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

#include <dlfcn.h>

#include "nd-config.hpp"
#include "nd-except.hpp"
#include "nd-license-client.hpp"
#include "nd-util.hpp"

using namespace std;

ndLicenseClient *ndLicenseClient::instance = nullptr;
void *ndLicenseClient::so_handle = nullptr;

ndLicenseClient &ndLicenseClient::Create(void) {
    if (instance != nullptr) {
        throw ndException("%s: %s: %s", __PRETTY_FUNCTION__,
          "nlc", strerror(EEXIST));
    }

    instance = new ndLicenseClient;

    return *instance;
}

void ndLicenseClient::Destroy(void) {
    if (instance == nullptr) {
        throw ndException("%s: %s: %s", __PRETTY_FUNCTION__,
          "nlc", strerror(EINVAL));
    }

    delete instance;
    instance = nullptr;
}

void ndLicenseClient::Reload(const string &so_name) {
    Close();

    so_handle = dlopen(so_name.c_str(), RTLD_NOW);
    if (so_handle == nullptr) {
        nd_dprintf("%s: %s\n", tag.c_str(), dlerror());
        return;
    }

    char *dlerror_string;

    dlerror();
    *(void **)(&LoadData) = dlsym(so_handle, "NLM_LoadData");

    if ((dlerror_string = dlerror()) != nullptr) {
        Close();

        nd_dprintf("%s: %s\n", tag.c_str(), dlerror_string);
    }
}

void ndLicenseClient::Close() {
    if (so_handle != nullptr) {
        dlclose(so_handle);
        so_handle = nullptr;
    }
}
