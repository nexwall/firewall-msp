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

#include <curl/curl.h>

class ndNetifyApiCurl
{
public:
    ndNetifyApiCurl();
    virtual ~ndNetifyApiCurl();

    CURL *ch = { nullptr };
    CURLcode curl_rc = { CURLE_OK };
    long http_rc = { -1 };
    struct curl_slist *headers_tx = { nullptr };
};

#define ndCurl (static_cast<ndNetifyApiCurl *>(curl_private))
#define ndCurlParent(p) (static_cast<ndNetifyApiCurl *>(p->curl_private))
