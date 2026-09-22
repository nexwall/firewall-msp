/*
 * ndpi_content_match.c.inc
 *
 * Copyright (C) 2011-23 - ntop.org and contributors
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/* ****************************************************** */


static ndpi_network ndpi_http_crawler_bot_hardcoded_protocol_list[] = {
 { 0x0, 0, 0 }
};

static ndpi_network6 ndpi_http_crawler_bot_hardcoded_protocol_list_6[] = {
 { NULL, 0, 0 },
};

static ndpi_network host_protocol_list[] = {
  { 0x0, 0, 0 }
};

static ndpi_network6 host_protocol_list_6[] = {
 { NULL, 0, 0 }
};

/* ****************************************************** */

/*
  Host-based match

  HTTP:  Server: field
  HTTPS: Server certificate name

  Risk classification criteria
  ----------------------------

  NDPI_PROTOCOL_SAFE
  - Web sites (and CDNs) which are not commonly used to host malicious activities.
  - OS update hosts.
  - App stores.
  - Commonly used services with passwords in encrypted channels (SMTPS, POPS, etc)

  NDPI_PROTOCOL_ACCEPTABLE
  - Cloud services may be used to host malware (e.g., https://www.fireeye.com/blog/threat-research/2015/11/china-based-threat.html),
  but it is mostly used for normal purposes.
  - Webmail sites, which can be used to phising.
  - Encrypted administrative protocols, such as SSH.
  - Text, voice or video communication (e.g., Skype, Slack, Whatsapp).
  - Ads services are commonly used to spread malware
  (https://www.tripwire.com/state-of-security/security-data-protection/crypto-ransomware-spreads-via-poisoned-ads-on-major-websites/)

  NDPI_PROTOCOL_FUN
  - Social media sites and services.
  - Communication used for fun purposes, like Snapchat, Tinder, etc.
  - Audio and videostreamming services (e.g., Netflix).
  - Game services.

  NDPI_PROTOCOL_UNSAFE
  - Unencrypted administrative protocols, such as Telnet.
  - Cloud hosted servers when accessed by default domains, such as *.amazonaws.com.
  - "AWS Supports 41% of Malware Hosting Sites, More than Any Other Web Host or ISP"
  http://www.thewhir.com/web-hosting-news/aws-supports-41-malware-hosting-sites-web-host-isp
  - https://www.scmagazine.com/600-plus-cloud-repositories-spotted-hosting-malware-and-malicious-files/article/572205/
  - https://howtoremove.guide/remove-s3-amazonaws-virus/
  - Torrents.
  - Commonly used services with passwords in unencrypted channels (SMTP, POP, etc)

  NDPI_PROTOCOL_POTENTIALLY_DANGEROUS
  - Tor and other anonymization access.
  - Sites commonly used to host malware and not as commonly used by "normal" users. (e.g., pastebin.com)
  https://isc.sans.edu/forums/diary/Many+Malware+Samples+Found+on+Pastebin/22036/

  NDPI_PROTOCOL_UNRATED
  - Avoid this class.

*/

/* ****************************************************** */

static ndpi_protocol_match host_match[] =
  {
   { NULL, NULL, NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_DEFAULT_LEVEL }
  };

/* ******************************************************************** */

static ndpi_tls_cert_name_match tls_certificate_match [] = {
  { NULL, 0 }
};

/* ******************************************************************** */

/*
   IMPORTANT

   Do NOT pur here strings that overlap with string in host_match[]
   specified above
*/

static ndpi_category_match category_match[] = {
   { NULL, 0 }
};
