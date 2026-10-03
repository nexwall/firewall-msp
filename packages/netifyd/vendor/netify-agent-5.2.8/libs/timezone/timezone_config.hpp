//
// timezone_config.hpp
//
// Bill Seymour, 2024-03-29
//
// Copyright Bill Seymour 2024.
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
// This header defines macros that control how code in the author's
// civil time library finds the local time zone and the directory
// where the Zoneinfo binaries can be found.  It also controls
// whether we use tz_names_xlate.inc and tz_links_xlate.inc.
//

#ifndef TIMEZONE_CONFIG_HPP_INCLUDED
#define TIMEZONE_CONFIG_HPP_INCLUDED

#ifndef _MSC_VER
//
// If we're not compiling for Windows, we'll assume Linux; but we also want it
// to work on a Mac, so we'll spell out "/etc/localtime".
//
  #ifndef CIVIL_TIME_USE_GETENV
    #ifndef CIVIL_TIME_TZ
      #define CIVIL_TIME_TZ "/etc/localtime"
    #endif
    #ifndef CIVIL_TIME_TZ_ROOT
      #define CIVIL_TIME_TZ_ROOT "/usr/share/zoneinfo"
    #endif
  #else
    // Use std::getenv()
    #undef CIVIL_TIME_TZ
    #undef CIVIL_TIME_TZ_ROOT
  #endif

  //
  // We default to not using the .inc files.
  //
  #if !defined(CIVIL_TIME_USE_NAME_XLATE) && !defined(CIVIL_TIME_NO_NAME_XLATE)
    #define CIVIL_TIME_NO_NAME_XLATE
  #endif
  #if !defined(CIVIL_TIME_USE_LINK_XLATE) && !defined(CIVIL_TIME_NO_LINK_XLATE)
    #define CIVIL_TIME_NO_LINK_XLATE
  #endif

#else
//
// If this is for Windows, default to the author's setup.
// TZ and TZ_ROOT can be changed programmatically at run time.
//
  #ifndef CIVIL_TIME_USE_GETENV

    #ifndef CIVIL_TIME_TZ
      // Default to US central time zone:
      #ifndef CIVIL_TIME_NO_ZONEINFO
        #define CIVIL_TIME_TZ "America/Chicago"
      #else
        #define CIVIL_TIME_TZ "CST6CDT,M3.2.0,M11.1.0"
      #endif
    #endif

    #ifndef CIVIL_TIME_TZ_ROOT
      #ifndef CIVIL_TIME_NO_ZONEINFO
        // Where the author put his zoneinfo binaries:
        #define CIVIL_TIME_TZ_ROOT "c:\\Users\\Public\\Zoneinfo"
      #else
        #define CIVIL_TIME_TZ_ROOT ""
      #endif
    #endif

  #else

    // Use std::getenv()
    #undef CIVIL_TIME_TZ
    #undef CIVIL_TIME_TZ_ROOT

  #endif

  //
  // We use the .inc files by default...the opposite of what we do for Linux.
  //
  #if !defined(CIVIL_TIME_USE_NAME_XLATE) && !defined(CIVIL_TIME_NO_NAME_XLATE)
    #define CIVIL_TIME_USE_NAME_XLATE
  #endif
  #if !defined(CIVIL_TIME_USE_LINK_XLATE) && !defined(CIVIL_TIME_NO_LINK_XLATE)
    #define CIVIL_TIME_USE_LINK_XLATE
  #endif

#endif // Linux or Windows

#endif // TIMEZONE_CONFIG_HPP_INCLUDED
