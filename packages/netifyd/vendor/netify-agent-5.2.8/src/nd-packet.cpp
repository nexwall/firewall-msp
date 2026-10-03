// Netify Agent
// Copyright (C) 2026 eGloo Incorporated
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

#include "nd-packet.hpp"

using namespace std;

ndPacket::ndPacket(const ndFlags<StatusFlags> &status,
  const uint16_t &length, const uint16_t &caplen,
  uint8_t *data, const struct timeval &tv,
  int ifidx_logical
#if defined(_ND_ENABLE_NFQUEUE)
  , int ifidx_src, int ifidx_dst
#endif
  ) : status(status), length(length), caplen(caplen),
    data(data), tv_sec(tv.tv_sec), tv_usec(tv.tv_usec),
    ifidx_logical(ifidx_logical)
#if defined(_ND_ENABLE_NFQUEUE)
    , ifidx_src(ifidx_src), ifidx_dst(ifidx_dst)
#endif
{
}

ndPacket::~ndPacket() {
    if (data != nullptr) delete[] data;
    status = StatusFlags::INIT;
}
