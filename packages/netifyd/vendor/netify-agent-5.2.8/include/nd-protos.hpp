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

#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <ndpi_protocol_ids.h>

#include "nd-ndpi.hpp"
#include "nd-util.hpp"

namespace ndProto {

enum class Id : uint32_t {
    UNKNOWN = 0,
    FTP_CONTROL = 1,
    MAIL_POP = 2,
    MAIL_SMTP = 3,
    MAIL_IMAP = 4,
    DNS = 5,
    IPP = 6,
    HTTP = 7,
    MDNS = 8,
    NTP = 9,
    NETBIOS = 10,
    NFS = 11,
    SSDP = 12,
    BGP = 13,
    SNMP = 14,
    XDMCP = 15,
    SMBV1 = 16,
    SYSLOG = 17,
    DHCP = 18,
    POSTGRES = 19,
    MYSQL = 20,
    FTPS = 21,
    DEPR22 = 22,  // Deprecated: Direct Download Link
    MAIL_POPS = 23,
    DEPR24 = 24,  // Deprecated: AppleJuice
    DEPR25 = 25,  // Deprecated: DirectConnect
    DEPR26 = 26,  // Deprecated: NTOP
    COAP = 27,
    VMWARE = 28,
    MAIL_SMTPS = 29,
    DEPR30 = 30,  // Deprecated: Facebook Zero
    UBNTAC2 = 31,
    DEPR32 = 32,  // Deprecated: Kontiki
    DEPR33 = 33,  // Deprecated: OpenFT
    DEPR34 = 34,  // Deprecated: FastTrack
    GNUTELLA = 35,
    DEPR36 = 36,  // Deprecated: eDonkey
    BITTORRENT = 37,
    SKYPE_TEAMS_CALL = 38,
    SIGNAL_CALL = 39,
    MEMCACHED = 40,
    SMBV23 = 41,
    MINING = 42,
    NEST_LOG_SINK = 43,
    MODBUS = 44,
    DEPR45 = 45,  // Deprecated: WhatsApp Video
    DATASAVER = 46,
    XBOX = 47,
    QQ = 48,
    DEPR49 = 49,  // Deprecated: TikTok - not a protocol
    RTSP = 50,
    MAIL_IMAPS = 51,
    ICECAST = 52,
    DEPR53 = 53,  // Deprecated: PPLive
    DEPR54 = 54,  // Deprecated: PPStream
    ZATTOO = 55,
    DEPR56 = 56,  // Deprecated: Shoutcast
    DEPR57 = 57,  // Deprecated: Sopcast
    DEPR58 = 58,  // Deprecated: TVANTS
    DEPR59 = 59,  // Deprecated: TVUplayer
    DEPR60 = 60,  // Deprecated: HTTP_Download
    DEPR61 = 61,  // Deprecated: QQLive
    DEPR62 = 62,  // Deprecated: Thunder
    DEPR63 = 63,  // Deprecated: SoulSeek
    DEPR64 = 64,  // Deprecated: SSL No Cert
    IRC = 65,
    DEPR66 = 66,  // Deprecated: Ayiya
    XMPP = 67,  // Renamed: Jabber
    FREE68 = 68,
    FREE69 = 69,
    DEPR70 = 70,  // Deprecated: Yahoo
    FREE71 = 71,
    FREE72 = 72,
    IP_VRRP = 73,
    STEAM = 74,
    HALFLIFE2 = 75,
    WORLDOFWARCRAFT = 76,
    TELNET = 77,
    STUN = 78,
    IPSEC = 79,
    IP_GRE = 80,
    IP_ICMP = 81,
    IP_IGMP = 82,
    IP_EGP = 83,
    IP_SCTP = 84,
    IP_OSPF = 85,
    IP_IP_IN_IP = 86,
    RTP = 87,
    RDP = 88,
    VNC = 89,
    DEPR90 = 90,  // Deprecated: pcAnywhere
    TLS = 91,
    SSH = 92,
    NNTP = 93,
    MGCP = 94,
    IAX = 95,
    TFTP = 96,
    AFP = 97,
    DEPR98 = 98,  // Deprecated: StealthNet
    DEPR99 = 99,  // Deprecated: Aimini
    SIP = 100,
    TRUPHONE = 101,
    IP_ICMPV6 = 102,
    DHCPV6 = 103,
    ARMAGETRON = 104,
    CROSSFIRE = 105,
    DOFUS = 106,
    DEPR107 = 107,  // Deprecated: Fiesta
    DEPR108 = 108,  // Deprecated: Florensia
    GUILDWARS = 109,
    FREE110 = 110,
    KERBEROS = 111,
    LDAP = 112,
    DEPR113 = 113, // Deprecated: MapleStory
    MSSQL_TDS = 114,
    PPTP = 115,
    WARCRAFT3 = 116,
    WORLDOFKUNGFU = 117,
    DEPR118 = 118,  // Deprecated: Slack
    FREE119 = 119,
    FREE120 = 120,
    DROPBOX = 121,
    FREE122 = 122,
    FREE123 = 123,
    FREE124 = 124,
    DEPR125 = 125,  // Deprecated: Skype
    FREE126 = 126,
    DCERPC = 127,  // Distributed Computing Environment / Remote Procedure Calls
    NETFLOW = 128,
    SFLOW = 129,
    HTTP_CONNECT = 130,
    HTTP_PROXY = 131,
    CITRIX = 132,
    FREE133 = 133,
    FREE134 = 134,
    DEPR135 = 135,  // Deprecated: Waze
    FREE136 = 136,
    DEPR137 = 137,  // Deprecated: Generic (old category matching)
    CHECKMK = 138,
    AJP = 139,
    DEPR140 = 140,  // Deprecated: Apple
    FREE141 = 141,
    WHATSAPP = 142,
    DEPR143 = 143,  // Deprecated: Apple iCloud
    VIBER = 144,
    DEPR145 = 145,  // Deprecated: Apple iTunes
    RADIUS = 146,
    FREE147 = 147,
    TEAMVIEWER = 148,
    FREE149 = 149,
    LOTUS_NOTES = 150,
    SAP = 151,
    GTP = 152,
    WSD = 153,  // Renamed: UPnP
    LLMNR = 154,
    REMOTE_SCAN = 155,
    SPOTIFY = 156,
    DEPR157 = 157,  // Deprecated: FB? Messenger
    H323 = 158,
    OPENVPN = 159,
    NOE = 160,  // Alcatel new office environment
    CISCO_VPN = 161,
    TEAMSPEAK = 162,
    DEPR163 = 163,  // Deprecated: TOR
    CISCO_SKINNY = 164,
    RTCP = 165,
    RSYNC = 166,
    ORACLE = 167,
    CORBA = 168,
    FREE169 = 169,
    WHOIS_DAS = 170,
    COLLECTD = 171,
    SOCKS = 172,
    NINTENDO = 173,
    RTMP = 174,
    FTP_DATA = 175,
    FREE176 = 176,
    ZMQ = 177,
    FREE178 = 178,
    FREE179 = 179,
    FREE180 = 180,
    MEGACO = 181,
    RESP = 182,
    FREE183 = 183,
    VHUA = 184,
    TELEGRAM = 185,
    FREE186 = 186,
    FREE187 = 187,
    QUIC = 188,
    DEPR189 = 189,  // Deprecated: WhatsApp/Voice
    EAQ = 190,
    OOKLA = 191,
    AMQP = 192,
    DEPR193 = 193,  // Deprecated: Kakaotalk
    KAKAOTALK_VOICE = 194,
    FREE195 = 195,
    HTTPS = 196,
    FREE197 = 197,
    MPEGTS = 198,
    FREE199 = 199,
    FREE200 = 200,
    FREE201 = 201,
    FREE202 = 202,
    FREE203 = 203,
    BJNP = 204,
    FREE205 = 205,
    WIREGUARD = 206,
    SMPP = 207,
    FREE208 = 208,
    TINC = 209,
    FREE210 = 210,
    FREE211 = 211,
    FREE212 = 212,
    STARCRAFT = 213,
    TEREDO = 214,
    DEPR215 = 215,  // Deprecated: Hotspot Shield VPN
    DEPR216 = 216,  // Deprecated: HEP
    FREE217 = 217,
    FREE218 = 218,
    FREE219 = 219,
    FREE220 = 220,
    FREE221 = 221,
    MQTT = 222,
    RX = 223,
    FREE224 = 224,
    FREE225 = 225,
    GIT = 226,
    DRDA = 227,
    FREE228 = 228,
    SOMEIP = 229,
    FIX = 230,
    FREE231 = 231,
    FREE232 = 232,
    FREE233 = 233,
    FREE234 = 234,
    DEPR235 = 235,  // Deprecated by STEAM: CSGO (Counter Strike GO)
    LISP = 236,
    DIAMETER = 237,
    APPLE_PUSH = 238,
    FREE239 = 239,
    FREE240 = 240,
    FREE241 = 241,
    FREE242 = 242,
    DOH = 243,
    DTLS = 244,
    GOOGLE_CALL = 245,
    WHATSAPP_CALL = 246,
    SKYPE_TEAMS = 247,  // TODO: Implement in Agent.
    ZOOM = 248,
    FREE249 = 249,
    FREE250 = 250,
    FREE251 = 251,
    FREE252 = 252,
    FREE253 = 253,
    FREE254 = 254,
    SNAPCHAT_CALL = 255,
    FTPS_DATA = 256,
    SIPS = 257,
    MQTTS = 258,
    NNTPS = 259,
    DOT = 260,
    DOQ = 261,  // TODO: Refine QUIC via ALPN (doq)
    DEPR262 = 262,  // Deprecated: Amazon Video
    AMONG_US = 263,
    AVAST_SDNS = 264,
    CAPWAP = 265,
    CASSANDRA = 266,
    CPHA = 267,
    DNP3 = 268,
    DNSCRYPT = 269,

    // EtherNet/IP (explicit messaging)
    // https://www.odva.org/wp-content/uploads/2021/05/PUB00138R7_Tech-Series-EtherNetIP.pdf
    ETHERNET_IP = 270,

    GENSHIN_IMPACT = 271,
    GTP_C = 272,
    GTP_P = 273,
    GTP_U = 274,
    HP_VIRTGRP = 275,
    CISCO_HSRP = 276,
    IEC60870_5_104 = 277,  // Extension for industrial 104 protocol
    // recognition
    DEPR278 = 278,  // Deprecated: IMO
    IRCS = 279,  // IRC over TLS
    MONGODB = 280,  // MongoDB

    // NATS: Connective Technology for Adaptive Edge &
    // Distributed Systems https://docs.nats.io/
    NATS = 281,

    // S7comm (S7 Communication) is a Siemens proprietary
    // protocol that runs between programmable logic
    // controllers (PLCs) of the Siemens S7-300/400 family.
    S7COMM = 282,

    SOAP = 283,
    TARGUS_GETDATA = 284,  // Targus Dataspeed (speedtest).
    VXLAN = 285,  // Virtual Extensible LAN.
    WEBSOCKET = 286,  // Websocket

    // Z39.50 dissector.
    // International standard client–server, application layer
    // communications protocol.
    Z3950 = 287,

    ZABBIX = 288,

    I3D = 289,
    MPEGDASH = 290,
    RAKNET = 291,
    RIOTGAMES = 292,
    RSH = 293,
    SD_RTN = 294,
    TOCA_BOCA = 295,
    ULTRASURF = 296,
    XIAOMI = 297,
    IP_PGM = 298,
    IP_PIM = 299,
    THREEMA = 300,
    ALICLOUD = 301,
    SYSLOGS = 302,
    NATPMP = 303,  // NAT Port Mapping Protocol
    // TUYA LAN Protocol
    // https://github.com/tuya/tuya-iotos-embeded-sdk-wifi-ble-bk7231n
    // */
    TUYA_LP = 304,

    ELASTICSEARCH = 305,
    AVAST = 306,
    CRYNET = 307,
    FASTCGI = 308,
    KISMET = 309,
    LINE_CALL = 310,
    MUNIN = 311,
    SYNCTHING = 312,
    TIVOCONNECT = 313,
    TPLINK_SHP = 314,  // TP-LINK Smart Home Protocol
    TAILSCALE = 315,  // Tailscale
    MERAKI_CLOUD = 316,  // Meraki Cloud
    HOTS = 317,  // Heroes of the Storm
    BACNET = 318,  // BACnet
    SOURCE_ENGINE = 319,  // Source Engine
    OICQ = 320,  // OICQ Chat
    SRTP = 321,  // SRTP
    XMPPS = 322,  // XMPPS over TLS
    BITCOIN = 323,  // Bitcoin
    APACHE_THRIFT = 324,  // Apache Thrift
    SLP = 325,  // Service Location Protocol
    HTTP2 = 326,  // HTTP/2
    FACEBOOK_VOIP = 327,  // Facebook VoIP (STUN)
    HAPROXY = 328,  // High availability load balancer and reverse proxy for TCP and HTTP-based applications
    RMCP = 329,  // Remote Management Control Protocol, IPMI component
    ISO_11898_1_CAN = 330,  // Controller Area Network, ISO 11898-1
    PROTOBUF = 331,  // Data serialzer: https://en.wikipedia.org/wiki/Protocol_Buffers
    ETHEREUM = 332,  // Ethereum: decentralized block chain
    TELEGRAM_VOIP = 333,  // Telegram VoIP (STUN)
    APACHE_KAFKA = 334,  // Apache Kafka
    BECKHOFF_ADS = 335,  // Beckhoff ADS: https://infosys.beckhoff.com/english.php?content=../content/1033/tcinfosys3/11291871243.html&id=
    BFD = 336,  // Bidirectional Forwarding Detection (BFD)
    ANSI_C1222 = 337,  // Protocol Specification for Interfacing to Data Communication Networks (ANSI C12.22)
    CEPH = 338,  // CEPH Network Protocol: https://docs.ceph.com/en/latest/dev/network-protocol/
    CIP = 339,  // Common Industrial Protocol: https://en.wikipedia.org/wiki/Common_Industrial_Protocol
    MS_RPCH = 340,  // Microsoft RPC
    DLEP = 341,  // Dynamic Link Exchange Protocol (RFC 8175): https://datatracker.ietf.org/doc/rfc8175/
    ETHERSBUS = 342,  // Ether-S-Bus protocol: https://wiki.wireshark.org/EtherSBus
    ETHERSIO = 343,  // Ether-S-IO protocol: https://wiki.wireshark.org/EtherSIO
    FINS = 344,  // Factory Interface Network Service: https://en.wikipedia.org/wiki/Factory_Interface_Network_Service
    GAIJIN = 345,  // Online Games Distribution Service: https://gaijin.net/en
    GEARMAN = 346,  // Gearman Job Server Protocol: https://en.wikipedia.org/wiki/Gearman
    HART_IP = 347,  // Hart-IP: https://www.fieldcommgroup.org/technologies/HART-IP/explained
    HISLIP = 348,  // High Speed LAN Instrument Protocol: https://en.wikipedia.org/wiki/High_Speed_LAN_Instrument_Protocol
    HL7 = 349,  // Health Level 7: https://en.wikipedia.org/wiki/Health_Level_7
    IEC62056 = 350,  // IEC 62056: https://en.wikipedia.org/wiki/IEC_62056
    IEEE_C37118 = 351,  // IEEE C37.118: https://wiki.wireshark.org/IEEE%20C37.118
    ISO_9506_1_MMS = 352,  // ISO 9506.1 Manufacturing Message Specification: https://en.wikipedia.org/wiki/Manufacturing_Message_Specification
    JSON_RPC = 353,  // JSON-RPC: https://www.jsonrpc.org/specification
    KCP = 354,  // KCP - A Fast and Reliable ARQ Protocol: https://github.com/skywind3000/kcp/blob/master/README.en.md
    MONERO = 355,  // Monero Crypto: https://en.wikipedia.org/wiki/Monero
    MUMBLE = 356,  // Mumble VoIP: https://mumble-protocol.readthedocs.io/en/latest/
    NETEASE_GAMES = 357,  // NetEase Games: https://www.neteasegames.com/
    NX_NOMACHINE = 358,  // NX/NoMachine Remote Desktop: https://en.wikipedia.org/wiki/NX_technology
    OPC_UA = 359,  // OPC Unified Architecture: https://www.softwareag.com/en_corporate/resources/iot/article/opc-ua.html
    OPENFLOW = 360,  // OpenFlow: https://en.wikipedia.org/wiki/OpenFlow
    PATH_OF_EXILE = 361,  // Path of Exile - A Free Online Action RPG
    PROFINET_IO = 362,  // PROFINET IO: https://en.wikipedia.org/wiki/Profinet
    PTPV2 = 363,  // Precision Time Protocol version 2 (IEEE 1588-2008): https://en.wikipedia.org/wiki/Precision_Time_Protocol
    RADMIN = 364,  // Radmin Remote Desktop: https://www.radmin.com/
    RAFT = 365,  // Raft Consensus Algorithm: https://raft.github.io/
    ROUGHTIME = 366,  // Roughtime secure time synchronisation: https://roughtime.googlesource.com/roughtime
    RTPS = 367,  // Real-Time Publish-Subscribe: https://wiki.wireshark.org/Protocols/rtps
    S7COMM_PLUS = 368,  // The S7 Comm Plus protocol is a new version of the original S7 Comm protocol.
    STOMP = 369,  // Streaming Text Oriented Messaging Protocol: https://en.wikipedia.org/wiki/Streaming_Text_Oriented_Messaging_Protocol
    TENCENT_GAMES = 370,  // Tencent Mobile Games
    UFTP = 371,  // UDP-based File Transfer Protocol: https://en.wikipedia.org/wiki/UFTP
    UMAS = 372,  // Unified Messaging Application Services: https://johnwiltshire.com/umas-protocol-explained/
    VALVE_SDR = 373,  // Valve Steam Datagram Relay: https://developer.valvesoftware.com/wiki/Steam_Datagram_Relay
    WEBDAV = 374,  // WebDAV: https://en.wikipedia.org/wiki/WebDAV
    YOJIMBO = 375,  // Network protocol for client/server games: https://github.com/mas-bandwidth/yojimbo
    BFCP = 376,  // The Binary Floor Control Protocol (BFCP): https://datatracker.ietf.org/doc/html/rfc4582
    EGD = 377,  // Ethernet Global Data: https://en.wikipedia.org/wiki/Ethernet_Global_Data_Protocol
    COD_MOBILE = 378,  // Call of Duty Mobile: https://www.callofduty.com/mobile
    PFCP = 379,  // Packet Forwarding Control Protocol (PFCP): https://en.wikipedia.org/wiki/PFCP
    FLUTE = 380,  // File Delivery over Unidirectional Transport (FLUTE): https://datatracker.ietf.org/doc/html/rfc6726
    LOL_WILD_RIFT = 381,  // League of Legends: Wild Rift: https://wildrift.leagueoflegends.com/en-us/
    TESO = 382,  // The Elder Scrolls Online: https://www.elderscrollsonline.com/
    LDP = 383,  // Label Distribution Protocol: https://en.wikipedia.org/wiki/Label_Distribution_Protocol
    KNXNET_IP = 384,  // IP extension of KNX bus: https://www.wireshark.org/docs/dfref/k/knx.html
    VIBER_VOIP = 385,  // Viber VoIP (STUN)
    ZUG = 386,  // ZUG Consensus Protocol: https://arxiv.org/abs/2205.06314
    JRMI = 416,  // Java Remote Method Invocation over TCP: https://docs.oracle.com/javase/9/docs/specs/rmi/protocol.html
    RIPE_ATLAS = 417,  // RIPE Atlas - RIPE Network Coordination Centre: https://atlas.ripe.net/
    HLS = 418,  // HTTP Live Streaming: https://en.wikipedia.org/wiki/HTTP_Live_Streaming
    NANO_NP = 420,  // Nano Network Protocol: https://docs.nano.org/protocol-design/networking/
    OPENWIRE = 421,  // ActiveMQ OpenWire: https://activemq.apache.org/components/classic/documentation/openwire
    CNP_IP = 422,  // Control Network Protocol (ISO/IEC 14908-4:2012): https://www.iso.org/standard/60206.html
    ATG = 423,  // Automatic Tank Gauge (ATG) protocol.
    TRDP = 424,  // Train Real Time Data Protocol (TRDP): https://www.typhoon-hil.com/documentation/typhoon-hil-software-manual/References/iec_61375_trdp_protocol.html
    LUSTRE = 425,  // Lustre distributed file-systemd: https://www.lustre.org/
    SONOS = 426,  // SONOS: https://www.sonos.com/en-ca/home
    DINGTALK = 427,  // DingTalk communication and collaboration platform developed by Alibaba Group: https://www.dingtalk.com/en
    PALTALK = 428,  // paltalk video chat: https://www.paltalk.com/
    MIKROTIK_NDP = 429,  // MikroTik Neighbor Discovery Protocol: https://help.mikrotik.com/docs/spaces/ROS/pages/24805517/Neighbor+discovery/
    DICOM = 430,  // Digital Imaging and Communications in Medicine: https://en.wikipedia.org/wiki/DICOM/
    IQIYI = 431,  // IQIYI (Baidu) video streaming protocol.
    NEXON = 432,  // South Korean video game developer and publisher specializing in live service games.
    BLIZZARD = 433,  // Generic Blizzard dissector
    LAGOFAST= 434,  // LagoFast: Game FPS booster: https://www.lagofast.com/en/
    GEARUP_BOOSTER = 435,  // GearUP Booster: Game FPS booster: https://www.gearupbooster.com/

    MAX,
    TODO = 0xffffffff
};

const std::unordered_map<Id, const char *, ndEnumHasher> Tags = {
    { Id::AFP, "AFP" },
    { Id::AJP, "AJP" },
    { Id::ALICLOUD, "Alibaba/Cloud" },
    { Id::AMONG_US, "AmongUs" },
    { Id::AMQP, "AMQP" },
    { Id::ANSI_C1222, "ANSI/C1222" },
    { Id::APACHE_KAFKA, "Apache/Kafka" },
    { Id::APACHE_THRIFT, "Apache/Thrift" },
    { Id::APPLE_PUSH, "Apple/Push" },
    { Id::ARMAGETRON, "Armagetron" },
    { Id::ATG, "ATG" },
    { Id::AVAST, "AVAST" },
    { Id::AVAST_SDNS, "AVAST/SecureDNS" },
    { Id::BACNET, "BACnet" },
    { Id::BECKHOFF_ADS, "Beckhoff/ADS" },
    { Id::BFCP, "BFCP" },
    { Id::BFD, "BFD" },
    { Id::BGP, "BGP" },
    { Id::BITCOIN, "Bitcoin" },
    { Id::BITTORRENT, "BitTorrent" },
    { Id::BJNP, "BJNP" },
    { Id::BLIZZARD, "Blizzard" },
    { Id::CAPWAP, "CAPWAP" },
    { Id::CASSANDRA, "Cassandra" },
    { Id::CEPH, "CEPH" },
    { Id::CHECKMK, "CHECKMK" },
    { Id::CIP, "CIP" },
    { Id::CISCO_HSRP, "Cisco/HSRP" },
    { Id::CISCO_SKINNY, "Cisco/Skinny" },
    { Id::CISCO_VPN, "Cisco/VPN" },
    { Id::CITRIX, "Citrix" },
    { Id::CNP_IP, "CNP/IP" },
    { Id::COAP, "COAP" },
    { Id::COD_MOBILE, "CoD/Mobile" },
    { Id::COLLECTD, "Collectd" },
    { Id::CORBA, "Corba" },
    { Id::CPHA, "CheckPointHA" },
    { Id::CROSSFIRE, "Crossfire" },
    { Id::CRYNET, "CryNetwork" },
    { Id::DATASAVER, "DataSaver" },
    { Id::DCERPC, "DCE/RPC" },
    { Id::DHCP, "DHCP" },
    { Id::DHCPV6, "DHCPv6" },
    { Id::DIAMETER, "Diameter" },
    { Id::DICOM, "DICOM" },
    { Id::DINGTALK, "DingTalk" },
    { Id::DLEP, "DLEP" },
    { Id::DNP3, "DNP3" },
    { Id::DNSCRYPT, "DNSCrypt" },
    { Id::DNS, "DNS" },
    { Id::DOFUS, "Dofus" },
    { Id::DOH, "DoH" },
    { Id::DOQ, "DoQ" },
    { Id::DOT, "DoT" },
    { Id::DRDA, "DRDA" },
    { Id::DROPBOX, "Dropbox" },
    { Id::DTLS, "DTLS" },
    { Id::EAQ, "EAQ" },
    { Id::EGD, "EGD" },
    { Id::ELASTICSEARCH, "ElasticSearch" },
    { Id::ETHEREUM, "Ethereum" },
    { Id::ETHERNET_IP, "EtherNet/IP" },
    { Id::ETHERSBUS, "Ether/S/Bus" },
    { Id::ETHERSIO, "Ether/S/IO" },
    { Id::FACEBOOK_VOIP, "Facebook/VoIP" },
    { Id::FASTCGI, "FastCGI" },
    { Id::FINS, "FINS" },
    { Id::FIX, "FIX" },
    { Id::FLUTE, "FLUTE" },
    { Id::FTP_CONTROL, "FTP/C" },
    { Id::FTP_DATA, "FTP/D" },
    { Id::FTPS, "FTP/S" },
    { Id::GAIJIN, "Gaijin" },
    { Id::GEARMAN, "Gearman" },
    { Id::GEARUP_BOOSTER, "GearUPBooster" },
    { Id::GENSHIN_IMPACT, "Genshin/Impact" },
    { Id::GIT, "Git" },
    { Id::GNUTELLA, "Gnutella" },
    { Id::GOOGLE_CALL, "Google/Call" },
    { Id::GTP_C, "GTP/C" },
    { Id::GTP, "GTP" },
    { Id::GTP_P, "GTP/P" },
    { Id::GTP_U, "GTP/U" },
    { Id::GUILDWARS, "Guildwars" },
    { Id::H323, "H323" },
    { Id::HALFLIFE2, "HalfLife2" },
    { Id::HAPROXY, "HAProxy" },
    { Id::HART_IP, "Hart/IP" },
    { Id::HISLIP, "HiSLIP" },
    { Id::HL7, "HealthLevel7" },
    { Id::HLS, "HTTP/LiveStream" },
    { Id::HOTS, "HerosOfTheStorm" },
    { Id::HP_VIRTGRP, "HP/VirtGrp" },
    { Id::HTTP2, "HTTP/2" },
    { Id::HTTP_CONNECT, "HTTP/Connect" },
    { Id::HTTP, "HTTP" },
    { Id::HTTP_PROXY, "HTTP/Proxy" },
    { Id::HTTPS, "HTTP/S" },
    { Id::I3D, "i3D" },
    { Id::IAX, "IAX" },
    { Id::ICECAST, "IceCast" },
    { Id::IEC60870_5_104, "IEC/60870/5/104" },
    { Id::IEC62056, "IEC/62056" },
    { Id::IEEE_C37118, "IEEE/C37/118" },
    { Id::IP_EGP, "EGP" },
    { Id::IP_GRE, "GRE" },
    { Id::IP_ICMP, "ICMP" },
    { Id::IP_ICMPV6, "ICMPv6" },
    { Id::IP_IGMP, "IGMP" },
    { Id::IP_IP_IN_IP, "IPinIP" },
    { Id::IP_OSPF, "OSPF" },
    { Id::IP_PGM, "PGM" },
    { Id::IP_PIM, "PIM" },
    { Id::IPP, "IPP" },
    { Id::IP_SCTP, "SCTP" },
    { Id::IPSEC, "IPSEC" },
    { Id::IP_VRRP, "VRRP" },
    { Id::IQIYI, "IQIYI" },
    { Id::IRC, "IRC" },
    { Id::IRCS, "IRC/S" },
    { Id::ISO_11898_1_CAN, "ISO/11898/1/CAN" },
    { Id::ISO_9506_1_MMS, "ISO/9506/1/MMS" },
    { Id::JRMI, "JRMI" },
    { Id::JSON_RPC, "JSON/RPC" },
    { Id::KAKAOTALK_VOICE, "KakaoTalk/Voice" },
    { Id::KCP, "KCP" },
    { Id::KERBEROS, "Kerberos" },
    { Id::KISMET, "KISMET" },
    { Id::KNXNET_IP, "KNXnet/IP" },
    { Id::LAGOFAST, "LagoFast" },
    { Id::LDAP, "LDAP" },
    { Id::LDP, "LDP" },
    { Id::LINE_CALL, "Line/Call" },
    { Id::LISP, "LISP" },
    { Id::LLMNR, "LLMNR" },
    { Id::LOL_WILD_RIFT, "LoL/WildRift" },
    { Id::LOTUS_NOTES, "LotusNotes" },
    { Id::LUSTRE, "Lustre" },
    { Id::MAIL_IMAP, "IMAP" },
    { Id::MAIL_IMAPS, "IMAP/S" },
    { Id::MAIL_POP, "POP3" },
    { Id::MAIL_POPS, "POP3/S" },
    { Id::MAIL_SMTP, "SMTP" },
    { Id::MAIL_SMTPS, "SMTP/S" },
    { Id::MDNS, "MDNS" },
    { Id::MEGACO, "Megaco" },
    { Id::MEMCACHED, "Memcached" },
    { Id::MERAKI_CLOUD, "Meraki/Cloud" },
    { Id::MGCP, "MGCP" },
    { Id::MIKROTIK_NDP, "Mikrotik/NDP" },
    { Id::MINING, "Mining" },
    { Id::MODBUS, "Modbus" },
    { Id::MONERO, "Monero" },
    { Id::MONGODB, "MongoDB" },
    { Id::MPEGDASH, "MPEG/Dash" },
    { Id::MPEGTS, "MPEGTS" },
    { Id::MQTT, "MQTT" },
    { Id::MQTTS, "MQTT/S" },
    { Id::MS_RPCH, "MS/RPCH" },
    { Id::MSSQL_TDS, "MSSQL/TDS" },
    { Id::MUMBLE, "Mumble/VoIP" },
    { Id::MUNIN, "Munin" },
    { Id::MYSQL, "MYSQL" },
    { Id::NANO_NP, "Nano/NP" },
    { Id::NATPMP, "NAT/PMP" },
    { Id::NATS, "NATS" },
    { Id::NEST_LOG_SINK, "NestLog" },
    { Id::NETBIOS, "NETBIOS" },
    { Id::NETEASE_GAMES, "NetEaseGames" },
    { Id::NETFLOW, "NetFlow" },
    { Id::NEXON, "Nexon" },
    { Id::NFS, "NFS" },
    { Id::NINTENDO, "Nintendo" },
    { Id::NNTP, "NNTP" },
    { Id::NNTPS, "NNTP/S" },
    { Id::NOE, "NOE" },
    { Id::NTP, "NTP" },
    { Id::NX_NOMACHINE, "NX/NoMachine" },
    { Id::OICQ, "OICQ" },
    { Id::OOKLA, "OOKLA" },
    { Id::OPC_UA, "OPC/UA" },
    { Id::OPENFLOW, "OpenFlow" },
    { Id::OPENVPN, "OpenVPN" },
    { Id::OPENWIRE, "OpenWire" },
    { Id::ORACLE, "Oracle" },
    { Id::PALTALK, "paltalk" },
    { Id::PATH_OF_EXILE, "PathOfExile" },
    { Id::PFCP, "PFCP" },
    { Id::POSTGRES, "PGSQL" },
    { Id::PPTP, "PPTP" },
    { Id::PROFINET_IO, "PROFINET/IO" },
    { Id::PROTOBUF, "Protobuf" },
    { Id::PTPV2, "PTP/2" },
    { Id::QQ, "QQ" },
    { Id::QUIC, "QUIC" },
    { Id::RADIUS, "RADIUS" },
    { Id::RADMIN, "Radmin" },
    { Id::RAFT, "Raft" },
    { Id::RAKNET, "RakNet" },
    { Id::RDP, "RDP" },
    { Id::REMOTE_SCAN, "RemoteScan" },
    { Id::RESP, "RESP" },
    { Id::RIOTGAMES, "Riot/Games" },
    { Id::RIPE_ATLAS, "RIPE/Atlas" },
    { Id::RMCP, "RMCP" },
    { Id::ROUGHTIME, "Roughtime" },
    { Id::RSH, "RSH" },
    { Id::RSYNC, "RSYNC" },
    { Id::RTCP, "RTCP" },
    { Id::RTMP, "RTMP" },
    { Id::RTP, "RTP" },
    { Id::RTPS, "RTPS" },
    { Id::RTSP, "RTSP" },
    { Id::RX, "RX" },
    { Id::S7COMM_PLUS, "S7comm/Plus" },
    { Id::S7COMM, "S7comm" },
    { Id::SAP, "SAP" },
    { Id::SD_RTN, "SD/RTN" },
    { Id::SFLOW, "SFlow" },
    { Id::SIGNAL_CALL, "SignalCall" },
    { Id::SIP, "SIP" },
    { Id::SIPS, "SIP/S" },
    { Id::SKYPE_TEAMS_CALL, "Skype/Teams/Call" },
    { Id::SKYPE_TEAMS, "Skype/Teams" },
    { Id::SLP, "SLP" },
    { Id::SMBV1, "SMBv1" },
    { Id::SMBV23, "SMBv23" },
    { Id::SMPP, "SMPP" },
    { Id::SNAPCHAT_CALL, "Snapchat/Call" },
    { Id::SNMP, "SNMP" },
    { Id::SOAP, "SOAP" },
    { Id::SOCKS, "SOCKS" },
    { Id::SOMEIP, "SOMEIP" },
    { Id::SONOS, "SONOS" },
    { Id::SOURCE_ENGINE, "SourceEngine" },
    { Id::SPOTIFY, "Spotify" },
    { Id::SRTP, "SRTP" },
    { Id::SSDP, "SSDP" },
    { Id::SSH, "SSH" },
    { Id::STARCRAFT, "Starcraft" },
    { Id::STEAM, "Steam" },
    { Id::STOMP, "STOMP" },
    { Id::STUN, "STUN" },
    { Id::SYNCTHING, "Syncthing" },
    { Id::SYSLOGS, "SYSLOG/S" },
    { Id::SYSLOG, "SYSLOG" },
    { Id::TAILSCALE, "Tailscale" },
    { Id::TARGUS_GETDATA, "Targus/Dataspeed" },
    { Id::TEAMSPEAK, "TeamSpeak" },
    { Id::TEAMVIEWER, "TeamViewer" },
    { Id::TELEGRAM, "Telegram" },
    { Id::TELEGRAM_VOIP, "Telegram/VoIP" },
    { Id::TELNET, "Telnet" },
    { Id::TENCENT_GAMES, "Tencent/Games" },
    { Id::TEREDO, "Teredo" },
    { Id::TESO, "ElderScrollsOnline" },
    { Id::TFTP, "TFTP" },
    { Id::THREEMA, "Threema" },
    { Id::TINC, "TINC" },
    { Id::TIVOCONNECT, "TiVo/Connect" },
    { Id::TLS, "TLS" },
    { Id::TOCA_BOCA, "TocaBoca" },
    { Id::TODO, "TODO" },
    { Id::TPLINK_SHP, "TPLINK/SHP" },
    { Id::TRDP, "TRDP" },
    { Id::TRUPHONE, "TruPhone" },
    { Id::TUYA_LP, "Tuya/LP" },
    { Id::UBNTAC2, "UBNTAC2" },
    { Id::UFTP, "UFTP" },
    { Id::ULTRASURF, "UltraSurf" },
    { Id::UMAS, "UMAS" },
    { Id::UNKNOWN, "Unknown" },
    { Id::VALVE_SDR, "Valve/SDR" },
    { Id::VHUA, "VHUA" },
    { Id::VIBER, "Viber" },
    { Id::VIBER_VOIP, "Viber/VoIP" },
    { Id::VMWARE, "VMWARE" },
    { Id::VNC, "VNC" },
    { Id::VXLAN, "VXLAN" },
    { Id::WARCRAFT3, "Warcraft3" },
    { Id::WEBDAV, "WebDAV" },
    { Id::WEBSOCKET, "Websocket" },
    { Id::WHATSAPP_CALL, "WhatsApp/Call" },
    { Id::WHATSAPP, "WhatsApp" },
    { Id::WHOIS_DAS, "Whois/DAS" },
    { Id::WIREGUARD, "WireGuard" },
    { Id::WORLDOFKUNGFU, "WoKungFu" },
    { Id::WORLDOFWARCRAFT, "WoW" },
    { Id::WSD, "WSD" },
    { Id::XBOX, "Xbox" },
    { Id::XDMCP, "XDMCP" },
    { Id::XIAOMI, "Xiaomi" },
    { Id::XMPPS, "XMPP/S" },
    { Id::XMPP, "XMPP" },
    { Id::YOJIMBO, "yojimbo" },
    { Id::Z3950, "Z39/50" },
    { Id::ZABBIX, "Zabbix" },
    { Id::ZATTOO, "Zattoo" },
    { Id::ZMQ, "ZMQ" },
    { Id::ZOOM, "ZOOM" },
    { Id::ZUG, "ZUG" },
};

const std::unordered_map<Id, const char *, ndEnumHasher> Twins = {
    { Id::APPLE_PUSH, "netify.apple-push" },
    { Id::AVAST, "netify.avast" },
    { Id::BITCOIN, "netify.bitcoin" },
    { Id::DINGTALK, "netify.dingtalk" },
    { Id::FACEBOOK_VOIP, "netify.meta" },
    { Id::LINE_CALL, "netify.line" },
    { Id::MERAKI_CLOUD, "netify.meraki" },
    { Id::NEST_LOG_SINK, "netify.nest" },
    { Id::NTP, "netify.ntp" },
    { Id::OOKLA, "netify.speedtest" },
    { Id::PALTALK, "netify.paltalk" },
    { Id::QQ, "netify.qq" },
    { Id::RIPE_ATLAS, "netify.ripe-atlas" },
    { Id::SIGNAL_CALL, "netify.signal" },
    { Id::SKYPE_TEAMS_CALL, "netify.teams" },
    { Id::SNAPCHAT_CALL, "netify.snapchat" },
    { Id::SONOS, "netify.sonos" },
    { Id::SPOTIFY, "netify.spotify" },
    { Id::STEAM, "netify.steam" },
    { Id::SYNCTHING, "netify.syncthing" },
    { Id::TEAMVIEWER, "netify.teamviewer" },
    { Id::TELEGRAM_VOIP, "netify.telegram" },
    { Id::TIVOCONNECT, "netify.tivo" },
    { Id::TPLINK_SHP, "netify.tp-link" },
    { Id::TUYA_LP, "netify.tuya-smart" },
    { Id::UBNTAC2, "netify.ubiquiti" },
    { Id::WHATSAPP_CALL, "netify.whatsapp" },
    { Id::XIAOMI, "netify.xiaomi" },
    { Id::ZOOM, "netify.zoom" },
};

inline const char *GetName(Id id) {
    auto i = Tags.find(id);
    if (i == Tags.end()) return "Unknown";
    return i->second;
}

inline Id GetId(const std::string &name) {
    for (auto &it : Tags) {
        if (strcasecmp(it.second, name.c_str())) continue;
        return it.first;
    }
    return Id::UNKNOWN;
}

const std::unordered_map<Id, std::vector<std::pair<uint16_t, Id>>, ndEnumHasher> PortMap = {
    { Id::TLS,
      {
        { 53, Id::DOT },
        { 443, Id::HTTPS },
        { 563, Id::NNTPS },
        { 853, Id::DOT },
        { 465, Id::MAIL_SMTPS },
        { 585, Id::MAIL_IMAPS },
        { 587, Id::MAIL_SMTPS },
        { 993, Id::MAIL_IMAPS },
        { 995, Id::MAIL_POPS },
        { 989, Id::FTPS_DATA },
        { 990, Id::FTPS },
        { 1883, Id::MQTTS },
        { 5061, Id::SIPS },
        { 6514, Id::SYSLOGS },
        { 6697, Id::IRCS },
        { 8883, Id::MQTTS },
      } },
};

namespace nDPI {

const std::unordered_map<uint16_t, Id> Protos = {
    { NDPI_PROTOCOL_AFP, Id::AFP },
    { NDPI_PROTOCOL_AJP, Id::AJP },
    { NDPI_PROTOCOL_ALICLOUD, Id::ALICLOUD },
    { NDPI_PROTOCOL_AMONG_US, Id::AMONG_US },
    { NDPI_PROTOCOL_AMQP, Id::AMQP },
    { NDPI_PROTOCOL_APACHE_KAFKA, Id::APACHE_KAFKA },
    { NDPI_PROTOCOL_APACHE_THRIFT, Id::APACHE_THRIFT },
    { NDPI_PROTOCOL_APPLE_PUSH, Id::APPLE_PUSH },
    { NDPI_PROTOCOL_ARMAGETRON, Id::ARMAGETRON },
    { NDPI_PROTOCOL_ATG, Id::ATG },
    { NDPI_PROTOCOL_AVAST, Id::AVAST },
    { NDPI_PROTOCOL_AVAST_SECUREDNS, Id::AVAST_SDNS },
    { NDPI_PROTOCOL_BACNET, Id::BACNET },
    { NDPI_PROTOCOL_BECKHOFF_ADS, Id::BECKHOFF_ADS },
    { NDPI_PROTOCOL_BFCP, Id::BFCP },
    { NDPI_PROTOCOL_BFD, Id::BFD },
    { NDPI_PROTOCOL_BGP, Id::BGP },
    { NDPI_PROTOCOL_BITCOIN, Id::BITCOIN },
    { NDPI_PROTOCOL_BITTORRENT, Id::BITTORRENT },
    { NDPI_PROTOCOL_BJNP, Id::BJNP },
    { NDPI_PROTOCOL_BLIZZARD, Id::BLIZZARD },
    { NDPI_PROTOCOL_C1222, Id::ANSI_C1222 },
    { NDPI_PROTOCOL_CAN, Id::ISO_11898_1_CAN },
    { NDPI_PROTOCOL_CAPWAP, Id::CAPWAP },
    { NDPI_PROTOCOL_CASSANDRA, Id::CASSANDRA },
    { NDPI_PROTOCOL_CEPH, Id::CEPH },
    { NDPI_PROTOCOL_CHECKMK, Id::CHECKMK },
    { NDPI_PROTOCOL_CIP, Id::CIP },
    { NDPI_PROTOCOL_CISCOVPN, Id::CISCO_VPN },
    { NDPI_PROTOCOL_CITRIX, Id::CITRIX },
    { NDPI_PROTOCOL_CNP_IP, Id::CNP_IP },
    { NDPI_PROTOCOL_COAP, Id::COAP },
    { NDPI_PROTOCOL_COD_MOBILE, Id::COD_MOBILE },
    { NDPI_PROTOCOL_COLLECTD, Id::COLLECTD },
    { NDPI_PROTOCOL_CORBA, Id::CORBA },
    { NDPI_PROTOCOL_CPHA, Id::CPHA },
    { NDPI_PROTOCOL_CROSSFIRE, Id::CROSSFIRE },
    { NDPI_PROTOCOL_CRYNET, Id::CRYNET },
    { NDPI_PROTOCOL_DATASAVER, Id::DATASAVER },
    { NDPI_PROTOCOL_DCERPC, Id::DCERPC },
    { NDPI_PROTOCOL_DHCP, Id::DHCP },
    { NDPI_PROTOCOL_DHCPV6, Id::DHCPV6 },
    { NDPI_PROTOCOL_DIAMETER, Id::DIAMETER },
    { NDPI_PROTOCOL_DICOM, Id::DICOM },
    { NDPI_PROTOCOL_DINGTALK, Id::DINGTALK },
    { NDPI_PROTOCOL_DLEP, Id::DLEP },
    { NDPI_PROTOCOL_DNP3, Id::DNP3 },
    { NDPI_PROTOCOL_DNSCRYPT, Id::DNSCRYPT },
    { NDPI_PROTOCOL_DNS, Id::DNS },
    { NDPI_PROTOCOL_DOFUS, Id::DOFUS },
    { NDPI_PROTOCOL_DOH_DOT, Id::DOQ },
    { NDPI_PROTOCOL_DRDA, Id::DRDA },
    { NDPI_PROTOCOL_DROPBOX, Id::DROPBOX },
    { NDPI_PROTOCOL_DTLS, Id::DTLS },
    { NDPI_PROTOCOL_EAQ, Id::EAQ },
    { NDPI_PROTOCOL_EGD, Id::EGD },
    { NDPI_PROTOCOL_ELASTICSEARCH, Id::ELASTICSEARCH },
    { NDPI_PROTOCOL_ETHEREUM, Id::ETHEREUM },
    { NDPI_PROTOCOL_ETHERNET_IP, Id::ETHERNET_IP },
    { NDPI_PROTOCOL_ETHERSBUS, Id::ETHERSBUS },
    { NDPI_PROTOCOL_ETHERSBUS, Id::ETHERSBUS },
    { NDPI_PROTOCOL_ETHERSIO, Id::ETHERSIO },
    { NDPI_PROTOCOL_FACEBOOK_VOIP, Id::FACEBOOK_VOIP },
    { NDPI_PROTOCOL_FASTCGI, Id::FASTCGI },
    { NDPI_PROTOCOL_FINS, Id::FINS },
    { NDPI_PROTOCOL_FIX, Id::FIX },
    { NDPI_PROTOCOL_FLUTE, Id::FLUTE },
    { NDPI_PROTOCOL_FTP_CONTROL, Id::FTP_CONTROL },
    { NDPI_PROTOCOL_FTP_DATA, Id::FTP_DATA },
    { NDPI_PROTOCOL_FTPS, Id::FTPS },
    { NDPI_PROTOCOL_GAIJIN, Id::GAIJIN },
    { NDPI_PROTOCOL_GEARMAN, Id::GEARMAN },
    { NDPI_PROTOCOL_GEARUP_BOOSTER, Id::GEARUP_BOOSTER },
    { NDPI_PROTOCOL_GENSHIN_IMPACT, Id::GENSHIN_IMPACT },
    { NDPI_PROTOCOL_GIT, Id::GIT },
    { NDPI_PROTOCOL_GNUTELLA, Id::GNUTELLA },
    { NDPI_PROTOCOL_GOOGLE_CALL, Id::GOOGLE_CALL },
    { NDPI_PROTOCOL_GTP_C, Id::GTP_C },
    { NDPI_PROTOCOL_GTP, Id::GTP },
    { NDPI_PROTOCOL_GTP_PRIME, Id::GTP_P },
    { NDPI_PROTOCOL_GTP_U, Id::GTP_U },
    { NDPI_PROTOCOL_GUILDWARS, Id::GUILDWARS },
    { NDPI_PROTOCOL_H323, Id::H323 },
    { NDPI_PROTOCOL_HALFLIFE2, Id::HALFLIFE2 },
    { NDPI_PROTOCOL_HAPROXY, Id::HAPROXY },
    { NDPI_PROTOCOL_HART_IP, Id::HART_IP },
    { NDPI_PROTOCOL_HISLIP, Id::HISLIP },
    { NDPI_PROTOCOL_HL7, Id::HL7 },
    { NDPI_PROTOCOL_HLS, Id::HLS },
    { NDPI_PROTOCOL_HOTS, Id::HOTS },
    { NDPI_PROTOCOL_HPVIRTGRP, Id::HP_VIRTGRP },
    { NDPI_PROTOCOL_HSRP, Id::CISCO_HSRP },
    { NDPI_PROTOCOL_HTTP2, Id::HTTP2 },
    { NDPI_PROTOCOL_HTTP_CONNECT, Id::HTTP_CONNECT },
    { NDPI_PROTOCOL_HTTP, Id::HTTP },
    { NDPI_PROTOCOL_HTTP_PROXY, Id::HTTP_PROXY },
    { NDPI_PROTOCOL_I3D, Id::I3D },
    { NDPI_PROTOCOL_IAX, Id::IAX },
    { NDPI_PROTOCOL_ICECAST, Id::ICECAST },
    { NDPI_PROTOCOL_IEC60870, Id::IEC60870_5_104 },
    { NDPI_PROTOCOL_IEC62056, Id::IEC62056 },
    { NDPI_PROTOCOL_IEEE_C37118, Id::IEEE_C37118 },
    { NDPI_PROTOCOL_IP_EGP, Id::IP_EGP },
    { NDPI_PROTOCOL_IP_GRE, Id::IP_GRE },
    { NDPI_PROTOCOL_IP_ICMP, Id::IP_ICMP },
    { NDPI_PROTOCOL_IP_ICMPV6, Id::IP_ICMPV6 },
    { NDPI_PROTOCOL_IP_IGMP, Id::IP_IGMP },
    { NDPI_PROTOCOL_IP_IP_IN_IP, Id::IP_IP_IN_IP },
    { NDPI_PROTOCOL_IP_OSPF, Id::IP_OSPF },
    { NDPI_PROTOCOL_IP_PGM, Id::IP_PGM },
    { NDPI_PROTOCOL_IPP, Id::IPP },
    { NDPI_PROTOCOL_IP_PIM, Id::IP_PIM },
    { NDPI_PROTOCOL_IP_SCTP, Id::IP_SCTP },
    { NDPI_PROTOCOL_IPSEC, Id::IPSEC },
    { NDPI_PROTOCOL_IP_VRRP, Id::IP_VRRP },
    { NDPI_PROTOCOL_IQIYI, Id::IQIYI },
    { NDPI_PROTOCOL_IRC, Id::IRC },
    { NDPI_PROTOCOL_ISO9506_1_MMS, Id::ISO_9506_1_MMS },
    { NDPI_PROTOCOL_JABBER, Id::XMPP },
    { NDPI_PROTOCOL_JRMI, Id::JRMI },
    { NDPI_PROTOCOL_JSON_RPC, Id::JSON_RPC },
    { NDPI_PROTOCOL_KAKAOTALK_VOICE, Id::KAKAOTALK_VOICE },
    { NDPI_PROTOCOL_KCP, Id::KCP },
    { NDPI_PROTOCOL_KERBEROS, Id::KERBEROS },
    { NDPI_PROTOCOL_KISMET, Id::KISMET },
    { NDPI_PROTOCOL_KNXNET_IP, Id::KNXNET_IP },
    { NDPI_PROTOCOL_LAGOFAST, Id::LAGOFAST },
    { NDPI_PROTOCOL_LDAP, Id::LDAP },
    { NDPI_PROTOCOL_LDP, Id::LDP },
    { NDPI_PROTOCOL_LINE_CALL, Id::LINE_CALL },
    { NDPI_PROTOCOL_LISP, Id::LISP },
    { NDPI_PROTOCOL_LLMNR, Id::LLMNR },
    { NDPI_PROTOCOL_LOLWILDRIFT, Id::LOL_WILD_RIFT },
    { NDPI_PROTOCOL_LOTUS_NOTES, Id::LOTUS_NOTES },
    { NDPI_PROTOCOL_LUSTRE, Id::LUSTRE },
    { NDPI_PROTOCOL_MAIL_IMAP, Id::MAIL_IMAP },
    { NDPI_PROTOCOL_MAIL_IMAPS, Id::MAIL_IMAPS },
    { NDPI_PROTOCOL_MAIL_POP, Id::MAIL_POP },
    { NDPI_PROTOCOL_MAIL_POPS, Id::MAIL_POPS },
    { NDPI_PROTOCOL_MAIL_SMTP, Id::MAIL_SMTP },
    { NDPI_PROTOCOL_MAIL_SMTPS, Id::MAIL_SMTPS },
    { NDPI_PROTOCOL_MDNS, Id::MDNS },
    { NDPI_PROTOCOL_MEGACO, Id::MEGACO },
    { NDPI_PROTOCOL_MEMCACHED, Id::MEMCACHED },
    { NDPI_PROTOCOL_MERAKI_CLOUD, Id::MERAKI_CLOUD },
    { NDPI_PROTOCOL_MGCP, Id::MGCP },
    { NDPI_PROTOCOL_MIKROTIK, Id::MIKROTIK_NDP },
    { NDPI_PROTOCOL_MINING, Id::MINING },
    { NDPI_PROTOCOL_MODBUS, Id::MODBUS },
    { NDPI_PROTOCOL_MONERO, Id::MONERO },
    { NDPI_PROTOCOL_MONGODB, Id::MONGODB },
    { NDPI_PROTOCOL_MPEGDASH, Id::MPEGDASH },
    { NDPI_PROTOCOL_MPEGTS, Id::MPEGTS },
    { NDPI_PROTOCOL_MQTT, Id::MQTT },
    { NDPI_PROTOCOL_MS_RPCH, Id::MS_RPCH },
    { NDPI_PROTOCOL_MSSQL_TDS, Id::MSSQL_TDS },
    { NDPI_PROTOCOL_MSTEAMS_CALL, Id::SKYPE_TEAMS_CALL },
    { NDPI_PROTOCOL_MUMBLE, Id::MUMBLE },
    { NDPI_PROTOCOL_MUNIN, Id::MUNIN },
    { NDPI_PROTOCOL_MYSQL, Id::MYSQL },
    { NDPI_PROTOCOL_NANO, Id::NANO_NP },
    { NDPI_PROTOCOL_NATPMP, Id::NATPMP },
    { NDPI_PROTOCOL_NATS, Id::NATS },
    { NDPI_PROTOCOL_NEST_LOG_SINK, Id::NEST_LOG_SINK },
    { NDPI_PROTOCOL_NETBIOS, Id::NETBIOS },
    { NDPI_PROTOCOL_NETEASE_GAMES, Id::NETEASE_GAMES },
    { NDPI_PROTOCOL_NETFLOW, Id::NETFLOW },
    { NDPI_PROTOCOL_NEXON, Id::NEXON },
    { NDPI_PROTOCOL_NFS, Id::NFS },
    { NDPI_PROTOCOL_NINTENDO, Id::NINTENDO },
    { NDPI_PROTOCOL_NOE, Id::NOE },
    { NDPI_PROTOCOL_NOMACHINE, Id::NX_NOMACHINE },
    { NDPI_PROTOCOL_NTP, Id::NTP },
    { NDPI_PROTOCOL_OICQ, Id::OICQ },
    { NDPI_PROTOCOL_OOKLA, Id::OOKLA },
    { NDPI_PROTOCOL_OPC_UA, Id::OPC_UA },
    { NDPI_PROTOCOL_OPENFLOW, Id::OPENFLOW },
    { NDPI_PROTOCOL_OPENVPN, Id::OPENVPN },
    { NDPI_PROTOCOL_OPENWIRE, Id::OPENWIRE },
    { NDPI_PROTOCOL_ORACLE, Id::ORACLE },
    { NDPI_PROTOCOL_PALTALK, Id::PALTALK },
    { NDPI_PROTOCOL_PATHOFEXILE, Id::PATH_OF_EXILE },
    { NDPI_PROTOCOL_PFCP, Id::PFCP },
    { NDPI_PROTOCOL_POSTGRES, Id::POSTGRES },
    { NDPI_PROTOCOL_PPTP, Id::PPTP },
    { NDPI_PROTOCOL_PROFINET_IO, Id::PROFINET_IO },
    { NDPI_PROTOCOL_PROTOBUF, Id::PROTOBUF },
    { NDPI_PROTOCOL_PTPV2, Id::PTPV2 },
    { NDPI_PROTOCOL_QQ, Id::QQ },
    { NDPI_PROTOCOL_QUIC, Id::QUIC },
    { NDPI_PROTOCOL_RADIUS, Id::RADIUS },
    { NDPI_PROTOCOL_RADMIN, Id::RADMIN },
    { NDPI_PROTOCOL_RAFT, Id::RAFT },
    { NDPI_PROTOCOL_RAKNET, Id::RAKNET },
    { NDPI_PROTOCOL_RDP, Id::RDP },
    { NDPI_PROTOCOL_RESP, Id::RESP },
    { NDPI_PROTOCOL_RIOTGAMES, Id::RIOTGAMES },
    { NDPI_PROTOCOL_RIPE_ATLAS, Id::RIPE_ATLAS },
    { NDPI_PROTOCOL_RMCP, Id::RMCP },
    { NDPI_PROTOCOL_ROUGHTIME, Id::ROUGHTIME },
    { NDPI_PROTOCOL_RSH, Id::RSH },
    { NDPI_PROTOCOL_RSYNC, Id::RSYNC },
    { NDPI_PROTOCOL_RTCP, Id::RTCP },
    { NDPI_PROTOCOL_RTMP, Id::RTMP },
    { NDPI_PROTOCOL_RTP, Id::RTP },
    { NDPI_PROTOCOL_RTPS, Id::RTPS },
    { NDPI_PROTOCOL_RTSP, Id::RTSP },
    { NDPI_PROTOCOL_RX, Id::RX },
    { NDPI_PROTOCOL_S7COMM, Id::S7COMM },
    { NDPI_PROTOCOL_S7COMM_PLUS, Id::S7COMM_PLUS },
    { NDPI_PROTOCOL_SAP, Id::SAP },
    { NDPI_PROTOCOL_SD_RTN, Id::SD_RTN },
    { NDPI_PROTOCOL_SERVICE_LOCATION, Id::SLP },
    { NDPI_PROTOCOL_SFLOW, Id::SFLOW },
    { NDPI_PROTOCOL_SIGNAL_VOIP, Id::SIGNAL_CALL },
    { NDPI_PROTOCOL_SIP, Id::SIP },
    { NDPI_PROTOCOL_SKINNY, Id::CISCO_SKINNY },
    { NDPI_PROTOCOL_SMBV1, Id::SMBV1 },
    { NDPI_PROTOCOL_SMBV23, Id::SMBV23 },
    { NDPI_PROTOCOL_SMPP, Id::SMPP },
    { NDPI_PROTOCOL_SNAPCHAT_CALL, Id::SNAPCHAT_CALL },
    { NDPI_PROTOCOL_SNMP, Id::SNMP },
    { NDPI_PROTOCOL_SOAP, Id::SOAP },
    { NDPI_PROTOCOL_SOCKS, Id::SOCKS },
    { NDPI_PROTOCOL_SOMEIP, Id::SOMEIP },
    { NDPI_PROTOCOL_SONOS, Id::SONOS },
    { NDPI_PROTOCOL_SOURCE_ENGINE, Id::SOURCE_ENGINE },
    { NDPI_PROTOCOL_SPOTIFY, Id::SPOTIFY },
    { NDPI_PROTOCOL_SRTP, Id::SRTP },
    { NDPI_PROTOCOL_SSDP, Id::SSDP },
    { NDPI_PROTOCOL_SSH, Id::SSH },
    { NDPI_PROTOCOL_STEAM, Id::STEAM },
    { NDPI_PROTOCOL_STOMP, Id::STOMP },
    { NDPI_PROTOCOL_STUN, Id::STUN },
    { NDPI_PROTOCOL_SYNCTHING, Id::SYNCTHING },
    { NDPI_PROTOCOL_SYSLOG, Id::SYSLOG },
    { NDPI_PROTOCOL_TAILSCALE, Id::TAILSCALE },
    { NDPI_PROTOCOL_TARGUS_GETDATA, Id::TARGUS_GETDATA },
    { NDPI_PROTOCOL_TEAMSPEAK, Id::TEAMSPEAK },
    { NDPI_PROTOCOL_TEAMVIEWER, Id::TEAMVIEWER },
    { NDPI_PROTOCOL_TELEGRAM, Id::TELEGRAM },
    { NDPI_PROTOCOL_TELEGRAM_VOIP, Id::TELEGRAM_VOIP },
    { NDPI_PROTOCOL_TELNET, Id::TELNET },
    { NDPI_PROTOCOL_TENCENTGAMES, Id::TENCENT_GAMES },
    { NDPI_PROTOCOL_TEREDO, Id::TEREDO },
    { NDPI_PROTOCOL_TESO, Id::TESO },
    { NDPI_PROTOCOL_TFTP, Id::TFTP },
    { NDPI_PROTOCOL_THREEMA, Id::THREEMA },
    { NDPI_PROTOCOL_TINC, Id::TINC },
    { NDPI_PROTOCOL_TIVOCONNECT, Id::TIVOCONNECT },
    { NDPI_PROTOCOL_TLS, Id::TLS },
    { NDPI_PROTOCOL_TOCA_BOCA, Id::TOCA_BOCA },
    { NDPI_PROTOCOL_TPLINK_SHP, Id::TPLINK_SHP },
    { NDPI_PROTOCOL_TRDP, Id::TRDP },
    { NDPI_PROTOCOL_TRUPHONE, Id::TRUPHONE },
    { NDPI_PROTOCOL_TUYA_LP, Id::TUYA_LP },
    { NDPI_PROTOCOL_UBNTAC2, Id::UBNTAC2 },
    { NDPI_PROTOCOL_UFTP, Id::UFTP },
    { NDPI_PROTOCOL_ULTRASURF, Id::ULTRASURF },
    { NDPI_PROTOCOL_UMAS, Id::UMAS },
    { NDPI_PROTOCOL_UNKNOWN, Id::UNKNOWN },
    { NDPI_PROTOCOL_USENET, Id::NNTP },
    { NDPI_PROTOCOL_VALVE_SDR, Id::VALVE_SDR },
    { NDPI_PROTOCOL_VHUA, Id::VHUA },
    { NDPI_PROTOCOL_VIBER, Id::VIBER },
    { NDPI_PROTOCOL_VIBER_VOIP, Id::VIBER_VOIP },
    { NDPI_PROTOCOL_VMWARE, Id::VMWARE },
    { NDPI_PROTOCOL_VNC, Id::VNC },
    { NDPI_PROTOCOL_VXLAN, Id::VXLAN },
    { NDPI_PROTOCOL_WARCRAFT3, Id::WARCRAFT3 },
    { NDPI_PROTOCOL_WEBDAV, Id::WEBDAV },
    { NDPI_PROTOCOL_WEBSOCKET, Id::WEBSOCKET },
    { NDPI_PROTOCOL_WHATSAPP_CALL, Id::WHATSAPP_CALL },
    { NDPI_PROTOCOL_WHATSAPP, Id::WHATSAPP },
    { NDPI_PROTOCOL_WHOIS_DAS, Id::WHOIS_DAS },
    { NDPI_PROTOCOL_WIREGUARD, Id::WIREGUARD },
    { NDPI_PROTOCOL_WORLD_OF_KUNG_FU, Id::WORLDOFKUNGFU },
    { NDPI_PROTOCOL_WORLDOFWARCRAFT, Id::WORLDOFWARCRAFT },
    { NDPI_PROTOCOL_WSD, Id::WSD },
    { NDPI_PROTOCOL_XBOX, Id::XBOX },
    { NDPI_PROTOCOL_XDMCP, Id::XDMCP },
    { NDPI_PROTOCOL_XIAOMI, Id::XIAOMI },
    { NDPI_PROTOCOL_YOJIMBO, Id::YOJIMBO },
    { NDPI_PROTOCOL_Z3950, Id::Z3950 },
    { NDPI_PROTOCOL_ZABBIX, Id::ZABBIX },
    { NDPI_PROTOCOL_ZATTOO, Id::ZATTOO },
    { NDPI_PROTOCOL_ZMQ, Id::ZMQ },
    { NDPI_PROTOCOL_ZOOM, Id::ZOOM },
    { NDPI_PROTOCOL_ZUG, Id::ZUG },
};

const std::vector<uint16_t> Disabled = {
    NDPI_PROTOCOL_1KXUN,  // Not a protocol (no dissector): ID# 295 (1kxun)
    NDPI_PROTOCOL_ACCUWEATHER,  // Not a protocol: ID# 280 (AccuWeather)
    NDPI_PROTOCOL_ACTIVISION,  // Not a protocol (no dissector): ID# 258 (Activision)
    NDPI_PROTOCOL_ADOBE_CONNECT,  // Not a protocol: ID# 59
    NDPI_PROTOCOL_ADS_ANALYTICS_TRACK,  // Not a protocol: ID# 107 (ADS_Analytic_Track)
    NDPI_PROTOCOL_ADULT_CONTENT,  // Not a protocol: ID# 108 (AdultContent)
    NDPI_PROTOCOL_ALIBABA,  // Not a protocol (see ALICLOUD): ID# 274 (Alibaba)
    NDPI_PROTOCOL_AMAZON_ALEXA,  // Not a protocol (no dissector): ID# 110 (AmazonAlexa)
    NDPI_PROTOCOL_AMAZON_AWS,  // Not a protocol (no dissector): ID# 265 (AmazonAWS)
    NDPI_PROTOCOL_AMAZON,  // Not a protocol: ID# 178 (Amazon)
    NDPI_PROTOCOL_AMAZON_VIDEO,  // No detections and no pcap to test.
    NDPI_PROTOCOL_ANYDESK,  // Not a protocol (no dissector): ID# 252 (AnyDesk)
    NDPI_PROTOCOL_APPLE_ICLOUD,  // Not a protocol (no dissector): ID# 143 (AppleiCloud)
    NDPI_PROTOCOL_APPLE_ITUNES,  // Not a protocol (no dissector): ID# 145 (AppleiTunes)
    NDPI_PROTOCOL_APPLE,  // Not a protocol: ID# 140 (Apple)
    NDPI_PROTOCOL_APPLE_SIRI,  // Not a protocol (no dissector): ID# 254 (AppleSiri)
    NDPI_PROTOCOL_APPLESTORE,  // Not a protocol: ID# 224 (AppleStore)
    NDPI_PROTOCOL_APPLETVPLUS,  // Not a protocol (no dissector): ID# 317 (AppleTVPlus)
    NDPI_PROTOCOL_BADOO,  // Not a protocol: ID# 279 (Badoo)
    NDPI_PROTOCOL_BLOOMBERG,  // Not a protocol: ID# 246 (Bloomberg)
    NDPI_PROTOCOL_BLUESKY,  // Not a protocol: ID# 411
    NDPI_PROTOCOL_CACHEFLY,  // Not a protocol: ID# 289 (Cachefly)
    NDPI_PROTOCOL_CACTUSVPN,  // Not a protocol: ID# 428 (CactusVPN)
    NDPI_PROTOCOL_CLICKHOUSE,  // Not a protocol: ID# 419
    NDPI_PROTOCOL_CLOUDFLARE,  // Not a protocol: ID# 220 (Cloudflare)
    NDPI_PROTOCOL_CLOUDFLARE_WARP,  // Not a protocol: ID# 300 (CloudflareWarp)
    NDPI_PROTOCOL_CNN,  // Not a protocol: ID# 180 (CNN)
    NDPI_PROTOCOL_CRASHLYSTICS,  // Not a protocol (no dissector): ID# 275 (Crashlytics)
    NDPI_PROTOCOL_CYBERSECURITY,  // Not a protocol: ID# 283 (Cybersec)
    NDPI_PROTOCOL_DAILYMOTION,  // Not a protocol: ID# 322 (Dailymotion)
    NDPI_PROTOCOL_DAZN,  // Not a protocol: ID# 292 (Dazn)
    NDPI_PROTOCOL_DEEZER,  // Not a protocol: ID# 210 (Deezer)
    NDPI_PROTOCOL_DIGITALOCEAN,  // Not a protocol (no dissector): ID# 442 (DigitalOcean)
    NDPI_PROTOCOL_DIRECTV,  // Not a protocol (no dissector): ID# 318 (DirecTV)
    NDPI_PROTOCOL_DISCORD,  // Not a protocol (no dissector): ID# 58 (Discord)
    NDPI_PROTOCOL_DISNEYPLUS,  // Not a protocol: ID# 71 (DisneyPlus)
    NDPI_PROTOCOL_DOTA2,  // Not a protocol: ID# 386 (DOTA 2)
    NDPI_PROTOCOL_EBAY,  // Not a protocol: ID# 179 (eBay)
    NDPI_PROTOCOL_EDGECAST,  // Not a protocol (no dissector): ID# 288 (Edgecast)
    NDPI_PROTOCOL_EDONKEY,  // Garbage; false-positives.
    NDPI_PROTOCOL_ELECTRONICARTS,  // Not a protocol: ID# 389
    NDPI_PROTOCOL_EPICGAMES,  // Not a protocol: ID# 340 (EpicGames)
    NDPI_PROTOCOL_FACEBOOK_MESSENGER,  // Not a protocol: ID# 157
    NDPI_PROTOCOL_FACEBOOK,  // Not a protocol: ID# 119 (Facebook)
    NDPI_PROTOCOL_FACEBOOK_REEL_STORY,  // Not a protocol: ID# 337 (FBookReelStory)
    NDPI_PROTOCOL_FORTICLIENT,  // Not a protocol (no dissector): ID# 259 (FortiClient)
    NDPI_PROTOCOL_FUZE,  // Not a protocol: ID# 270 (Fuze)
    NDPI_PROTOCOL_GEFORCENOW,  // Not a protocol: ID# 341 (GeForceNow)
    NDPI_PROTOCOL_GITHUB,  // Not a protocol: ID# 203 (Github)
    NDPI_PROTOCOL_GITLAB,  // Not a protocol: ID# 262 (GitLab)
    NDPI_PROTOCOL_GMAIL,  // Not a protocol: ID# 122 (GMail)
    NDPI_PROTOCOL_GOOGLE_CHAT,  // Not a protocol: ID# 382
    NDPI_PROTOCOL_GOOGLE_CLASSROOM,  // Not a protocol: ID# 281 (GoogleClassroom)
    NDPI_PROTOCOL_GOOGLE_CLOUD,  // Not a protocol: ID# 284 (GoogleCloud)
    NDPI_PROTOCOL_GOOGLE_DOCS,  // Not a protocol: ID# 241 (GoogleDocs)
    NDPI_PROTOCOL_GOOGLE_DRIVE,  // Not a protocol (no dissector): ID# 217 (GoogleDrive)
    NDPI_PROTOCOL_GOOGLE_MAPS,  // Not a protocol: ID# 123 (GoogleMaps)
    NDPI_PROTOCOL_GOOGLE_MEET,  // Not a protocol: ID# 201
    NDPI_PROTOCOL_GOOGLE,  // Not a protocol: ID# 126 (Google)
    NDPI_PROTOCOL_GOOGLE_SERVICES,  // Not a protocol: ID# 239 (GoogleServices)
    NDPI_PROTOCOL_GOTO,  // Not a protocol: ID# 293 (GoTo)
    NDPI_PROTOCOL_HBO,  // Not a protocol: ID# 319 (HBO)
    NDPI_PROTOCOL_HOTSPOT_SHIELD,  // Not a protocol: ID# 215 (HotspotShield)
    NDPI_PROTOCOL_HUAWEI_CLOUD,  // Not a protocol: ID# 399
    NDPI_PROTOCOL_HUAWEI,  // Not a protocol: ID# 398
    NDPI_PROTOCOL_HULU,  // Not a protocol: ID# 137 (Hulu)
    NDPI_PROTOCOL_ICLOUD_PRIVATE_RELAY,  // Not a protocol (no dissector): ID# 277 (iCloudPrivateRelay)
    NDPI_PROTOCOL_IFLIX,  // Not a protocol: ID# 202 (IFLIX)
    NDPI_PROTOCOL_IHEARTRADIO,  // Not a protocol: ID# 325 (IHeartRadio)
    NDPI_PROTOCOL_IMO,  // Weak, too many false-positives, and obscure/undocumented.
    NDPI_PROTOCOL_INSTAGRAM,  // Not a protocol: ID# 211 (Instagram)
    NDPI_PROTOCOL_KAKAOTALK,  // Not a protocol (see KAKAOTALK_VOICE): ID# 193 (KakaoTalk)
    NDPI_PROTOCOL_LASTFM,  // Not a protocol: ID# 134 (LastFM)
    NDPI_PROTOCOL_LIKEE,  // Not a protocol: ID# 261 (Likee)
    NDPI_PROTOCOL_LINE,  // Not a protocol: ID# 315 (Line)
    NDPI_PROTOCOL_LINKEDIN,  // Not a protocol: ID# 233 (LinkedIn)
    NDPI_PROTOCOL_LIVESTREAM,  // Not a protocol: ID# 323 (Livestream)
    NDPI_PROTOCOL_LLM,  // Not a protocol (no dissector): ID# 446 (LLM)
    NDPI_PROTOCOL_MASTODON,  // Not a protocol: ID# 412
    NDPI_PROTOCOL_MICROSOFT_365,  // Not a protocol: ID# 219 (Microsoft365)
    NDPI_PROTOCOL_MICROSOFT_AZURE,  // Not a protocol (no dissector): ID# 276 (Azure)
    NDPI_PROTOCOL_MICROSOFT,  // Not a protocol: ID# 212 (Microsoft)
    NDPI_PROTOCOL_MOZILLA,  // Not a protocol (no dissector): ID# 125 (Mozilla)
    NDPI_PROTOCOL_MS_ONE_DRIVE,  // Not a protocol (no dissector): ID# 221 (MS_OneDrive)
    NDPI_PROTOCOL_MS_OUTLOOK,  // Not a protocol: ID# 21 (Outlook)
    NDPI_PROTOCOL_MSTEAMS,  // Not a protocol (see SKYPE_TEAMS_CALL): ID# 250 (Teams)
    NDPI_PROTOCOL_MULLVAD,  // Not a protocol: ID# 348 (Mullvad)
    NDPI_PROTOCOL_NAVER,  // Not a protocol: ID# 433 (Naver)
    NDPI_PROTOCOL_NETFLIX,  // Not a protocol: ID# 133 (NetFlix)
    NDPI_PROTOCOL_NORDVPN,  // Not a protocol: ID# 426 (NordVPN)
    NDPI_PROTOCOL_NTOP,  // Not a protocol: ID# 26 (ntop)
    NDPI_PROTOCOL_NVIDIA,  // Not a protocol: ID# 342 (GeForceNow)
    NDPI_PROTOCOL_OCS,  // Not a protocol: ID# 218 (OCS)
    NDPI_PROTOCOL_OCSP,  // Not a protocol (HTTP): ID# 63 (OCSP)
    NDPI_PROTOCOL_OPENDNS,  // Not a protocol (no dissector): ID# 225 (OpenDNS)
    NDPI_PROTOCOL_OPERA_VPN,  // Not a protocol: ID# 339 (OperaVPN)
    NDPI_PROTOCOL_PANDORA,  // Not a protocol: ID# 187 (Pandora)
    NDPI_PROTOCOL_PARAMOUNTPLUS,  // Not a protocol: ID# 439 (ParamountPlus)
    NDPI_PROTOCOL_PASTEBIN,  // Not a protocol: ID# 232 (Pastebin)
    NDPI_PROTOCOL_PIA,  // Not a protocol: ID# 384
    NDPI_PROTOCOL_PINTEREST,  // Not a protocol: ID# 183 (Pinterest)
    NDPI_PROTOCOL_PLAYSTATION,  // Not a protocol (no dissector): ID# 231 (Playstation)
    NDPI_PROTOCOL_PLAYSTORE,  // Not a protocol: ID# 228 (PlayStore)
    NDPI_PROTOCOL_PLURALSIGHT,  // Not a protocol (no dissector): ID# 61 (Pluralsight)
    NDPI_PROTOCOL_PROTONVPN,  // Not a protocol: ID# 344 (ProtonVPN)
    NDPI_PROTOCOL_PSIPHON,  // Not a protocol: ID# 303 (Psiphon)
    NDPI_PROTOCOL_REDDIT,  // Not a protocol: ID# 205 (Reddit)
    NDPI_PROTOCOL_ROBLOX,  // Not a protocol: ID# 346 (Roblox)
    NDPI_PROTOCOL_RUTUBE,  // Not a protocol (no dissector): ID# 441 (Rutube)
    NDPI_PROTOCOL_SALESFORCE,  // Not a protocol: ID# 266 (Salesforce)
    NDPI_PROTOCOL_SHEIN,  // Not a protocol: ID# 434 (Shein)
    NDPI_PROTOCOL_SHOWTIME,  // Not a protocol: ID# 321 (Showtime)
    NDPI_PROTOCOL_SIGNAL,  // Not a protocol (see SIGNAL_VOIP): ID# 39 (Signal)
    NDPI_PROTOCOL_SINA,  // Not a protocol (no dissector): ID# 200 (Sina(Weibo))
    NDPI_PROTOCOL_SINA_WEIBO,  // Not a protocol: ID# 356 (SinaWeibo)
    NDPI_PROTOCOL_SIRIUSXMRADIO,  // Not a protocol: ID# 328 (SiriusXMRadio)
    NDPI_PROTOCOL_SLACK,  // Not a protocol (no dissector): ID# 118 (Slack)
    NDPI_PROTOCOL_SNAPCHAT,  // Not a protocol (no dissector): ID# 199 (Snapchat)
    NDPI_PROTOCOL_SOFTETHER,  // Not a protocol (no dissector): ID# 290 (Softether)
    NDPI_PROTOCOL_SOUNDCLOUD,  // Not a protocol: ID# 234 (SoundCloud)
    NDPI_PROTOCOL_SURFSHARK,  // Not a protocol: ID# 427 (SurfShark)
    NDPI_PROTOCOL_TAOBAO,  // Not a protocol: ID# 436 (TaoBao)
    NDPI_PROTOCOL_TEMU,  // Not a protocol: ID# 435 (TEMU)
    NDPI_PROTOCOL_TENCENT,  // Not a protocol: ID# 285 (Tencent)
    NDPI_PROTOCOL_TENCENTVIDEO,  // Not a protocol: ID# 324 (Tencentvideo)
    NDPI_PROTOCOL_TESLA_SERVICES,  // Not a protocol: ID# 357
    NDPI_PROTOCOL_THREADS,  // Not a protocol: ID# 413
    NDPI_PROTOCOL_TIDAL,  // Not a protocol: ID# 326 (Tidal)
    NDPI_PROTOCOL_TIKTOK,  // Not a protocol: ID# 49
    NDPI_PROTOCOL_TOR,  // Not a protocol (no dissector): ID# 163 (Tor)
    NDPI_PROTOCOL_TUMBLR,  // Not a protocol: ID# 90 (Tumblr)
    NDPI_PROTOCOL_TUNEIN,  // Not a protocol: ID# 327 (TuneIn)
    NDPI_PROTOCOL_TUNNELBEAR,  // Not a protocol (no dissector): ID# 299 (TunnelBear)
    NDPI_PROTOCOL_TWITCH,  // Not a protocol (no dissector): ID# 195 (Twitch)
    NDPI_PROTOCOL_TWITTER,  // Not a protocol: ID# 120 (Twitter)
    NDPI_PROTOCOL_UBIQUITY,  // Not a protocol (no dissector): ID# 447 (Ubiquity)
    NDPI_PROTOCOL_UBUNTUONE,  // Not a protocol: ID# 169 (UbuntuONE)
    NDPI_PROTOCOL_VIMEO,  // Not a protocol: ID# 267 (Vimeo)
    NDPI_PROTOCOL_VIVOX,  // Not a protocol (no dissector): ID# 441 (Vivox)
    NDPI_PROTOCOL_VK,  // Not a protocol: ID# 22 (VK)
    NDPI_PROTOCOL_VUDU,  // Not a protocol: ID# 320 (Vudu)
    NDPI_PROTOCOL_WAZE,  // Not a protocol: ID# 135 (Waze)
    NDPI_PROTOCOL_WEBEX,  // Not a protocol (no dissector): ID# 141 (Webex)
    NDPI_PROTOCOL_WECHAT,  // Not a protocol (no dissector): ID# 197 (WeChat)
    NDPI_PROTOCOL_WHATSAPP_FILES,  // Not a protocol: ID# 242 (WhatsAppFiles)
    NDPI_PROTOCOL_WIKIPEDIA,  // Not a protocol: ID# 176 (Wikipedia)
    NDPI_PROTOCOL_WINDOWS_UPDATE,  // Not a protocol (no dissector): ID# 147 (WindowsUpdate)
    NDPI_PROTOCOL_WINDSCRIBE,  // Not a protocol: ID# 429 (WindScribe)
    NDPI_PROTOCOL_YAHOO,  // Not a protocol: ID# 70 (Yahoo)
    NDPI_PROTOCOL_YANDEX_ALICE,  // Not a protocol: ID# 440 (YandexAlice)
    NDPI_PROTOCOL_YANDEX_CLOUD,  // Not a protocol: ID# 62 (Yandex Cloud)
    NDPI_PROTOCOL_YANDEX_DIRECT,  // Not a protocol: ID# 99 (Yandex Direct)
    NDPI_PROTOCOL_YANDEX_DISK,  // Not a protocol: ID# 57 (Yandex Disk)
    NDPI_PROTOCOL_YANDEX_MAIL,  // Not a protocol: ID# 33 (Yandex Mail)
    NDPI_PROTOCOL_YANDEX_MARKET,  // Not a protocol: ID# 56 (Yandex Market)
    NDPI_PROTOCOL_YANDEX_METRIKA,  // Not a protocol: ID# 98 (Yandex Metrika)
    NDPI_PROTOCOL_YANDEX_MUSIC,  // Not a protocol: ID# 34 (Yandex Music)
    NDPI_PROTOCOL_YANDEX,  // Not a protocol: ID# 25 (Yandex)
    NDPI_PROTOCOL_YOUTUBE,  // Not a protocol: ID# 124 (YouTube)
    NDPI_PROTOCOL_YOUTUBE_UPLOAD,  // Not a protocol: ID# 136 (YouTubeUpload)
};

const std::vector<uint16_t> Free = {};

const uint16_t Find(Id id);

}  // namespace nDPI
}  // namespace ndProto
