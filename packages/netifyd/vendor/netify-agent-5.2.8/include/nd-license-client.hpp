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

#include <string>
#include <sstream>

class ndLicenseClient
{
public:
    static ndLicenseClient& Create(void);
    static void Destroy(void);

    ndLicenseClient(const ndLicenseClient &) = delete;
    ndLicenseClient &operator=(const ndLicenseClient &) = delete;

    static inline ndLicenseClient &GetInstance() {
        if (instance == nullptr) {
            throw ndException("%s: license client not found",
              __PRETTY_FUNCTION__);
        }
        return *instance;
    }

    static inline bool IsValid(void) {
        return (instance != nullptr && so_handle != nullptr);
    }

    void Reload(const std::string &so_name);

    typedef bool (*LoadDataFunction)(
      const std::string &, const std::string &, std::stringstream &);
    LoadDataFunction LoadData;

protected:
    static ndLicenseClient *instance;

    const std::string tag = { "nlc" };
    static void *so_handle;

    void Close(void);

private:
    ndLicenseClient() { }
    virtual ~ndLicenseClient() { Close(); }
};
