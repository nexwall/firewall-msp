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

#include <ndpi_api.h>
#include <ndpi_main.h>
#include <ndpi_typedefs.h>

#ifdef _ND_ENABLE_NDPI_DEBUG
void nd_ndpi_debug_printf(uint32_t protocol, void *ndpi,
  ndpi_log_level_t level, const char *file,
  const char *func, unsigned line, const char *format, ...);
#endif

void nd_ndpi_global_init(void);
void nd_ndpi_global_shutdown(void);

struct ndpi_detection_module_struct *nd_ndpi_init(void);

void nd_ndpi_free(struct ndpi_detection_module_struct *ndpi);
