/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

#ifndef YY_YY_ND_FLOW_EXPR_HPP_INCLUDED
# define YY_YY_ND_FLOW_EXPR_HPP_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif
/* "%code requires" blocks.  */
#line 130 "nd-flow-expr.ypp"

typedef void* yyscan_t;

#line 53 "nd-flow-expr.hpp"

/* Token kinds.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    YYEMPTY = -2,
    YYEOF = 0,                     /* "end of file"  */
    YYerror = 256,                 /* error  */
    YYUNDEF = 257,                 /* "invalid token"  */
    FLOW_ANY_IP = 258,             /* FLOW_ANY_IP  */
    FLOW_ANY_MAC = 259,            /* FLOW_ANY_MAC  */
    FLOW_ANY_PORT = 260,           /* FLOW_ANY_PORT  */
    FLOW_APPLICATION = 261,        /* FLOW_APPLICATION  */
    FLOW_APPLICATION_CATEGORY = 262, /* FLOW_APPLICATION_CATEGORY  */
    FLOW_APPLICATION_CATEGORY_ID = 263, /* FLOW_APPLICATION_CATEGORY_ID  */
    FLOW_CATEGORY = 264,           /* FLOW_CATEGORY  */
    FLOW_CATEGORY_ID = 265,        /* FLOW_CATEGORY_ID  */
    FLOW_CONNTRACK_ID = 266,       /* FLOW_CONNTRACK_ID  */
    FLOW_CONNTRACK_MARK = 267,     /* FLOW_CONNTRACK_MARK  */
    FLOW_CONNTRACK_REPLY_DST_IP = 268, /* FLOW_CONNTRACK_REPLY_DST_IP  */
    FLOW_CONNTRACK_REPLY_SRC_IP = 269, /* FLOW_CONNTRACK_REPLY_SRC_IP  */
    FLOW_DETECTED_HOSTNAME = 270,  /* FLOW_DETECTED_HOSTNAME  */
    FLOW_DETECTION_COMPLETE = 271, /* FLOW_DETECTION_COMPLETE  */
    FLOW_DETECTION_GUESSED = 272,  /* FLOW_DETECTION_GUESSED  */
    FLOW_DETECTION_INIT = 273,     /* FLOW_DETECTION_INIT  */
    FLOW_DETECTION_UPDATED = 274,  /* FLOW_DETECTION_UPDATED  */
    FLOW_DHC_HIT = 275,            /* FLOW_DHC_HIT  */
    FLOW_DNS_HOSTNAME = 276,       /* FLOW_DNS_HOSTNAME  */
    FLOW_DOMAIN_CATEGORY = 277,    /* FLOW_DOMAIN_CATEGORY  */
    FLOW_DOMAIN_CATEGORY_ID = 278, /* FLOW_DOMAIN_CATEGORY_ID  */
    FLOW_DST_IP = 279,             /* FLOW_DST_IP  */
    FLOW_DST_MAC = 280,            /* FLOW_DST_MAC  */
    FLOW_DST_NETWORK_CATEGORY = 281, /* FLOW_DST_NETWORK_CATEGORY  */
    FLOW_DST_NETWORK_CATEGORY_ID = 282, /* FLOW_DST_NETWORK_CATEGORY_ID  */
    FLOW_DST_PORT = 283,           /* FLOW_DST_PORT  */
    FLOW_EXPIRED = 284,            /* FLOW_EXPIRED  */
    FLOW_EXPIRING = 285,           /* FLOW_EXPIRING  */
    FLOW_FHC_HIT = 286,            /* FLOW_FHC_HIT  */
    FLOW_IFACE = 287,              /* FLOW_IFACE  */
    FLOW_IFACE_NFQ_DST = 288,      /* FLOW_IFACE_NFQ_DST  */
    FLOW_IFACE_NFQ_SRC = 289,      /* FLOW_IFACE_NFQ_SRC  */
    FLOW_IP_DSCP = 290,            /* FLOW_IP_DSCP  */
    FLOW_IP_NAT = 291,             /* FLOW_IP_NAT  */
    FLOW_IP_PROTO = 292,           /* FLOW_IP_PROTO  */
    FLOW_IP_VERSION = 293,         /* FLOW_IP_VERSION  */
    FLOW_LOCAL_IP = 294,           /* FLOW_LOCAL_IP  */
    FLOW_LOCAL_MAC = 295,          /* FLOW_LOCAL_MAC  */
    FLOW_LOCAL_NETWORK_CATEGORY = 296, /* FLOW_LOCAL_NETWORK_CATEGORY  */
    FLOW_LOCAL_NETWORK_CATEGORY_ID = 297, /* FLOW_LOCAL_NETWORK_CATEGORY_ID  */
    FLOW_LOCAL_PORT = 298,         /* FLOW_LOCAL_PORT  */
    FLOW_NDPI_RISK_SCORE = 299,    /* FLOW_NDPI_RISK_SCORE  */
    FLOW_NDPI_RISK_SCORE_CLIENT = 300, /* FLOW_NDPI_RISK_SCORE_CLIENT  */
    FLOW_NDPI_RISK_SCORE_SERVER = 301, /* FLOW_NDPI_RISK_SCORE_SERVER  */
    FLOW_NETWORK_CATEGORY = 302,   /* FLOW_NETWORK_CATEGORY  */
    FLOW_NETWORK_CATEGORY_ID = 303, /* FLOW_NETWORK_CATEGORY_ID  */
    FLOW_ORIGIN = 304,             /* FLOW_ORIGIN  */
    FLOW_OTHER_IP = 305,           /* FLOW_OTHER_IP  */
    FLOW_OTHER_MAC = 306,          /* FLOW_OTHER_MAC  */
    FLOW_OTHER_NETWORK_CATEGORY = 307, /* FLOW_OTHER_NETWORK_CATEGORY  */
    FLOW_OTHER_NETWORK_CATEGORY_ID = 308, /* FLOW_OTHER_NETWORK_CATEGORY_ID  */
    FLOW_OTHER_PORT = 309,         /* FLOW_OTHER_PORT  */
    FLOW_OTHER_TYPE = 310,         /* FLOW_OTHER_TYPE  */
    FLOW_PROTOCOL = 311,           /* FLOW_PROTOCOL  */
    FLOW_PROTOCOL_CATEGORY = 312,  /* FLOW_PROTOCOL_CATEGORY  */
    FLOW_PROTOCOL_CATEGORY_ID = 313, /* FLOW_PROTOCOL_CATEGORY_ID  */
    FLOW_RISKS = 314,              /* FLOW_RISKS  */
    FLOW_SOFT_DISSECTOR = 315,     /* FLOW_SOFT_DISSECTOR  */
    FLOW_SRC_IP = 316,             /* FLOW_SRC_IP  */
    FLOW_SRC_MAC = 317,            /* FLOW_SRC_MAC  */
    FLOW_SRC_NETWORK_CATEGORY = 318, /* FLOW_SRC_NETWORK_CATEGORY  */
    FLOW_SRC_NETWORK_CATEGORY_ID = 319, /* FLOW_SRC_NETWORK_CATEGORY_ID  */
    FLOW_SRC_PORT = 320,           /* FLOW_SRC_PORT  */
    FLOW_TAG = 321,                /* FLOW_TAG  */
    FLOW_TAG_CATEGORY = 322,       /* FLOW_TAG_CATEGORY  */
    FLOW_TAG_CATEGORY_ID = 323,    /* FLOW_TAG_CATEGORY_ID  */
    FLOW_TLS_CIPHER = 324,         /* FLOW_TLS_CIPHER  */
    FLOW_TLS_ECH = 325,            /* FLOW_TLS_ECH  */
    FLOW_TLS_JA4 = 326,            /* FLOW_TLS_JA4  */
    FLOW_TLS_VERSION = 327,        /* FLOW_TLS_VERSION  */
    FLOW_TUNNEL_TYPE = 328,        /* FLOW_TUNNEL_TYPE  */
    FLOW_VLAN_ID = 329,            /* FLOW_VLAN_ID  */
    FLOW_VLAN = 330,               /* FLOW_VLAN  */
    FLOW_LOCAL_IF_META_SSID = 331, /* FLOW_LOCAL_IF_META_SSID  */
    FLOW_LOCAL_IF_META_PVID = 332, /* FLOW_LOCAL_IF_META_PVID  */
    FLOW_OTHER_IF_META_PVID = 333, /* FLOW_OTHER_IF_META_PVID  */
    FLOW_APP_IP_OVERRIDE = 334,    /* FLOW_APP_IP_OVERRIDE  */
    FLOW_APP_PROTO_TWINS = 335,    /* FLOW_APP_PROTO_TWINS  */
    FLOW_DHCP_CLASS_IDENT = 336,   /* FLOW_DHCP_CLASS_IDENT  */
    FLOW_DHCP_FINGERPRINT = 337,   /* FLOW_DHCP_FINGERPRINT  */
    FLOW_DST_BYTES = 338,          /* FLOW_DST_BYTES  */
    FLOW_DST_PACKETS = 339,        /* FLOW_DST_PACKETS  */
    FLOW_HTTP_URL = 340,           /* FLOW_HTTP_URL  */
    FLOW_HTTP_USER_AGENT = 341,    /* FLOW_HTTP_USER_AGENT  */
    FLOW_LOCAL_BYTES = 342,        /* FLOW_LOCAL_BYTES  */
    FLOW_LOCAL_PACKETS = 343,      /* FLOW_LOCAL_PACKETS  */
    FLOW_MDNS_DOMAIN_NAME = 344,   /* FLOW_MDNS_DOMAIN_NAME  */
    FLOW_NFQ_DST_IFINDEX = 345,    /* FLOW_NFQ_DST_IFINDEX  */
    FLOW_NFQ_SRC_IFINDEX = 346,    /* FLOW_NFQ_SRC_IFINDEX  */
    FLOW_OTHER_BYTES = 347,        /* FLOW_OTHER_BYTES  */
    FLOW_OTHER_PACKETS = 348,      /* FLOW_OTHER_PACKETS  */
    FLOW_SRC_BYTES = 349,          /* FLOW_SRC_BYTES  */
    FLOW_SRC_PACKETS = 350,        /* FLOW_SRC_PACKETS  */
    FLOW_SSH_CLIENT_AGENT = 351,   /* FLOW_SSH_CLIENT_AGENT  */
    FLOW_SSH_SERVER_AGENT = 352,   /* FLOW_SSH_SERVER_AGENT  */
    FLOW_TCP_FIN_ACK = 353,        /* FLOW_TCP_FIN_ACK  */
    FLOW_TCP_LAST_SEQ = 354,       /* FLOW_TCP_LAST_SEQ  */
    FLOW_TLS_ALPN = 355,           /* FLOW_TLS_ALPN  */
    FLOW_TLS_ISSUER_DN = 356,      /* FLOW_TLS_ISSUER_DN  */
    FLOW_TLS_SERVER_CN = 357,      /* FLOW_TLS_SERVER_CN  */
    FLOW_TLS_SUBJECT_DN = 358,     /* FLOW_TLS_SUBJECT_DN  */
    FLOW_TOTAL_BYTES = 359,        /* FLOW_TOTAL_BYTES  */
    FLOW_TOTAL_PACKETS = 360,      /* FLOW_TOTAL_PACKETS  */
    FLOW_TS_FIRST_SEEN = 361,      /* FLOW_TS_FIRST_SEEN  */
    FLOW_TS_LAST_SEEN = 362,       /* FLOW_TS_LAST_SEEN  */
    FLOW_TOTAL_LOCAL_BYTES = 363,  /* FLOW_TOTAL_LOCAL_BYTES  */
    FLOW_TOTAL_OTHER_BYTES = 364,  /* FLOW_TOTAL_OTHER_BYTES  */
    FLOW_TOTAL_SRC_BYTES = 365,    /* FLOW_TOTAL_SRC_BYTES  */
    FLOW_TOTAL_DST_BYTES = 366,    /* FLOW_TOTAL_DST_BYTES  */
    FLOW_TOTAL_LOCAL_PACKETS = 367, /* FLOW_TOTAL_LOCAL_PACKETS  */
    FLOW_TOTAL_OTHER_PACKETS = 368, /* FLOW_TOTAL_OTHER_PACKETS  */
    FLOW_TOTAL_SRC_PACKETS = 369,  /* FLOW_TOTAL_SRC_PACKETS  */
    FLOW_TOTAL_DST_PACKETS = 370,  /* FLOW_TOTAL_DST_PACKETS  */
    FLOW_DETECTION_PACKETS = 371,  /* FLOW_DETECTION_PACKETS  */
    FLOW_LOCAL_RATE = 372,         /* FLOW_LOCAL_RATE  */
    FLOW_OTHER_RATE = 373,         /* FLOW_OTHER_RATE  */
    FLOW_SRC_RATE = 374,           /* FLOW_SRC_RATE  */
    FLOW_DST_RATE = 375,           /* FLOW_DST_RATE  */
    FLOW_TCP_SEQ_ERRORS = 376,     /* FLOW_TCP_SEQ_ERRORS  */
    FLOW_TCP_RESETS = 377,         /* FLOW_TCP_RESETS  */
    FLOW_TCP_RETRANS = 378,        /* FLOW_TCP_RETRANS  */
    FLOW_TLS_CERT_FINGERPRINT = 379, /* FLOW_TLS_CERT_FINGERPRINT  */
    FLOW_TLS_ALPN_SERVER = 380,    /* FLOW_TLS_ALPN_SERVER  */
    FLOW_TLS_PROC_HELLO = 381,     /* FLOW_TLS_PROC_HELLO  */
    FLOW_TLS_PROC_CERTIFICATE = 382, /* FLOW_TLS_PROC_CERTIFICATE  */
    FLOW_SMTP_TLS = 383,           /* FLOW_SMTP_TLS  */
    FLOW_BT_INFO_HASH = 384,       /* FLOW_BT_INFO_HASH  */
    FLOW_STUN_MAPPED = 385,        /* FLOW_STUN_MAPPED  */
    FLOW_STUN_PEER = 386,          /* FLOW_STUN_PEER  */
    FLOW_STUN_RELAYED = 387,       /* FLOW_STUN_RELAYED  */
    FLOW_STUN_RESPONSE = 388,      /* FLOW_STUN_RESPONSE  */
    FLOW_STUN_OTHER = 389,         /* FLOW_STUN_OTHER  */
    FLOW_OTHER_UNKNOWN = 390,      /* FLOW_OTHER_UNKNOWN  */
    FLOW_OTHER_UNSUPPORTED = 391,  /* FLOW_OTHER_UNSUPPORTED  */
    FLOW_OTHER_LOCAL = 392,        /* FLOW_OTHER_LOCAL  */
    FLOW_OTHER_MULTICAST = 393,    /* FLOW_OTHER_MULTICAST  */
    FLOW_OTHER_BROADCAST = 394,    /* FLOW_OTHER_BROADCAST  */
    FLOW_OTHER_REMOTE = 395,       /* FLOW_OTHER_REMOTE  */
    FLOW_OTHER_ERROR = 396,        /* FLOW_OTHER_ERROR  */
    FLOW_ORIGIN_LOCAL = 397,       /* FLOW_ORIGIN_LOCAL  */
    FLOW_ORIGIN_OTHER = 398,       /* FLOW_ORIGIN_OTHER  */
    FLOW_ORIGIN_UNKNOWN = 399,     /* FLOW_ORIGIN_UNKNOWN  */
    FLOW_TUNNEL_NONE = 400,        /* FLOW_TUNNEL_NONE  */
    FLOW_TUNNEL_GTP = 401,         /* FLOW_TUNNEL_GTP  */
    FLOW_INTEL = 402,              /* FLOW_INTEL  */
    CMP_EQUAL = 403,               /* CMP_EQUAL  */
    CMP_NOTEQUAL = 404,            /* CMP_NOTEQUAL  */
    CMP_GTHANEQUAL = 405,          /* CMP_GTHANEQUAL  */
    CMP_LTHANEQUAL = 406,          /* CMP_LTHANEQUAL  */
    BOOL_AND = 407,                /* BOOL_AND  */
    BOOL_OR = 408,                 /* BOOL_OR  */
    VALUE_ADDR_IPMASK = 409,       /* VALUE_ADDR_IPMASK  */
    VALUE_TRUE = 410,              /* VALUE_TRUE  */
    VALUE_FALSE = 411,             /* VALUE_FALSE  */
    VALUE_ADDR_MAC = 412,          /* VALUE_ADDR_MAC  */
    VALUE_NAME = 413,              /* VALUE_NAME  */
    VALUE_REGEX = 414,             /* VALUE_REGEX  */
    VALUE_ADDR_TAG = 415,          /* VALUE_ADDR_TAG  */
    VALUE_ADDR_IPV4 = 416,         /* VALUE_ADDR_IPV4  */
    VALUE_ADDR_IPV4_CIDR = 417,    /* VALUE_ADDR_IPV4_CIDR  */
    VALUE_ADDR_IPV6 = 418,         /* VALUE_ADDR_IPV6  */
    VALUE_ADDR_IPV6_CIDR = 419,    /* VALUE_ADDR_IPV6_CIDR  */
    VALUE_SIGNED = 420,            /* VALUE_SIGNED  */
    VALUE_UNSIGNED = 421,          /* VALUE_UNSIGNED  */
    VALUE_FLOAT = 422              /* VALUE_FLOAT  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif
/* Token kinds.  */
#define YYEMPTY -2
#define YYEOF 0
#define YYerror 256
#define YYUNDEF 257
#define FLOW_ANY_IP 258
#define FLOW_ANY_MAC 259
#define FLOW_ANY_PORT 260
#define FLOW_APPLICATION 261
#define FLOW_APPLICATION_CATEGORY 262
#define FLOW_APPLICATION_CATEGORY_ID 263
#define FLOW_CATEGORY 264
#define FLOW_CATEGORY_ID 265
#define FLOW_CONNTRACK_ID 266
#define FLOW_CONNTRACK_MARK 267
#define FLOW_CONNTRACK_REPLY_DST_IP 268
#define FLOW_CONNTRACK_REPLY_SRC_IP 269
#define FLOW_DETECTED_HOSTNAME 270
#define FLOW_DETECTION_COMPLETE 271
#define FLOW_DETECTION_GUESSED 272
#define FLOW_DETECTION_INIT 273
#define FLOW_DETECTION_UPDATED 274
#define FLOW_DHC_HIT 275
#define FLOW_DNS_HOSTNAME 276
#define FLOW_DOMAIN_CATEGORY 277
#define FLOW_DOMAIN_CATEGORY_ID 278
#define FLOW_DST_IP 279
#define FLOW_DST_MAC 280
#define FLOW_DST_NETWORK_CATEGORY 281
#define FLOW_DST_NETWORK_CATEGORY_ID 282
#define FLOW_DST_PORT 283
#define FLOW_EXPIRED 284
#define FLOW_EXPIRING 285
#define FLOW_FHC_HIT 286
#define FLOW_IFACE 287
#define FLOW_IFACE_NFQ_DST 288
#define FLOW_IFACE_NFQ_SRC 289
#define FLOW_IP_DSCP 290
#define FLOW_IP_NAT 291
#define FLOW_IP_PROTO 292
#define FLOW_IP_VERSION 293
#define FLOW_LOCAL_IP 294
#define FLOW_LOCAL_MAC 295
#define FLOW_LOCAL_NETWORK_CATEGORY 296
#define FLOW_LOCAL_NETWORK_CATEGORY_ID 297
#define FLOW_LOCAL_PORT 298
#define FLOW_NDPI_RISK_SCORE 299
#define FLOW_NDPI_RISK_SCORE_CLIENT 300
#define FLOW_NDPI_RISK_SCORE_SERVER 301
#define FLOW_NETWORK_CATEGORY 302
#define FLOW_NETWORK_CATEGORY_ID 303
#define FLOW_ORIGIN 304
#define FLOW_OTHER_IP 305
#define FLOW_OTHER_MAC 306
#define FLOW_OTHER_NETWORK_CATEGORY 307
#define FLOW_OTHER_NETWORK_CATEGORY_ID 308
#define FLOW_OTHER_PORT 309
#define FLOW_OTHER_TYPE 310
#define FLOW_PROTOCOL 311
#define FLOW_PROTOCOL_CATEGORY 312
#define FLOW_PROTOCOL_CATEGORY_ID 313
#define FLOW_RISKS 314
#define FLOW_SOFT_DISSECTOR 315
#define FLOW_SRC_IP 316
#define FLOW_SRC_MAC 317
#define FLOW_SRC_NETWORK_CATEGORY 318
#define FLOW_SRC_NETWORK_CATEGORY_ID 319
#define FLOW_SRC_PORT 320
#define FLOW_TAG 321
#define FLOW_TAG_CATEGORY 322
#define FLOW_TAG_CATEGORY_ID 323
#define FLOW_TLS_CIPHER 324
#define FLOW_TLS_ECH 325
#define FLOW_TLS_JA4 326
#define FLOW_TLS_VERSION 327
#define FLOW_TUNNEL_TYPE 328
#define FLOW_VLAN_ID 329
#define FLOW_VLAN 330
#define FLOW_LOCAL_IF_META_SSID 331
#define FLOW_LOCAL_IF_META_PVID 332
#define FLOW_OTHER_IF_META_PVID 333
#define FLOW_APP_IP_OVERRIDE 334
#define FLOW_APP_PROTO_TWINS 335
#define FLOW_DHCP_CLASS_IDENT 336
#define FLOW_DHCP_FINGERPRINT 337
#define FLOW_DST_BYTES 338
#define FLOW_DST_PACKETS 339
#define FLOW_HTTP_URL 340
#define FLOW_HTTP_USER_AGENT 341
#define FLOW_LOCAL_BYTES 342
#define FLOW_LOCAL_PACKETS 343
#define FLOW_MDNS_DOMAIN_NAME 344
#define FLOW_NFQ_DST_IFINDEX 345
#define FLOW_NFQ_SRC_IFINDEX 346
#define FLOW_OTHER_BYTES 347
#define FLOW_OTHER_PACKETS 348
#define FLOW_SRC_BYTES 349
#define FLOW_SRC_PACKETS 350
#define FLOW_SSH_CLIENT_AGENT 351
#define FLOW_SSH_SERVER_AGENT 352
#define FLOW_TCP_FIN_ACK 353
#define FLOW_TCP_LAST_SEQ 354
#define FLOW_TLS_ALPN 355
#define FLOW_TLS_ISSUER_DN 356
#define FLOW_TLS_SERVER_CN 357
#define FLOW_TLS_SUBJECT_DN 358
#define FLOW_TOTAL_BYTES 359
#define FLOW_TOTAL_PACKETS 360
#define FLOW_TS_FIRST_SEEN 361
#define FLOW_TS_LAST_SEEN 362
#define FLOW_TOTAL_LOCAL_BYTES 363
#define FLOW_TOTAL_OTHER_BYTES 364
#define FLOW_TOTAL_SRC_BYTES 365
#define FLOW_TOTAL_DST_BYTES 366
#define FLOW_TOTAL_LOCAL_PACKETS 367
#define FLOW_TOTAL_OTHER_PACKETS 368
#define FLOW_TOTAL_SRC_PACKETS 369
#define FLOW_TOTAL_DST_PACKETS 370
#define FLOW_DETECTION_PACKETS 371
#define FLOW_LOCAL_RATE 372
#define FLOW_OTHER_RATE 373
#define FLOW_SRC_RATE 374
#define FLOW_DST_RATE 375
#define FLOW_TCP_SEQ_ERRORS 376
#define FLOW_TCP_RESETS 377
#define FLOW_TCP_RETRANS 378
#define FLOW_TLS_CERT_FINGERPRINT 379
#define FLOW_TLS_ALPN_SERVER 380
#define FLOW_TLS_PROC_HELLO 381
#define FLOW_TLS_PROC_CERTIFICATE 382
#define FLOW_SMTP_TLS 383
#define FLOW_BT_INFO_HASH 384
#define FLOW_STUN_MAPPED 385
#define FLOW_STUN_PEER 386
#define FLOW_STUN_RELAYED 387
#define FLOW_STUN_RESPONSE 388
#define FLOW_STUN_OTHER 389
#define FLOW_OTHER_UNKNOWN 390
#define FLOW_OTHER_UNSUPPORTED 391
#define FLOW_OTHER_LOCAL 392
#define FLOW_OTHER_MULTICAST 393
#define FLOW_OTHER_BROADCAST 394
#define FLOW_OTHER_REMOTE 395
#define FLOW_OTHER_ERROR 396
#define FLOW_ORIGIN_LOCAL 397
#define FLOW_ORIGIN_OTHER 398
#define FLOW_ORIGIN_UNKNOWN 399
#define FLOW_TUNNEL_NONE 400
#define FLOW_TUNNEL_GTP 401
#define FLOW_INTEL 402
#define CMP_EQUAL 403
#define CMP_NOTEQUAL 404
#define CMP_GTHANEQUAL 405
#define CMP_LTHANEQUAL 406
#define BOOL_AND 407
#define BOOL_OR 408
#define VALUE_ADDR_IPMASK 409
#define VALUE_TRUE 410
#define VALUE_FALSE 411
#define VALUE_ADDR_MAC 412
#define VALUE_NAME 413
#define VALUE_REGEX 414
#define VALUE_ADDR_TAG 415
#define VALUE_ADDR_IPV4 416
#define VALUE_ADDR_IPV4_CIDR 417
#define VALUE_ADDR_IPV6 418
#define VALUE_ADDR_IPV6_CIDR 419
#define VALUE_SIGNED 420
#define VALUE_UNSIGNED 421
#define VALUE_FLOAT 422

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 137 "nd-flow-expr.ypp"

    char buffer[_NDFP_MAX_BUFLEN];

    bool bool_number;
    unsigned short us_number;
    long sl_number;
    unsigned long ul_number;
    float fl_number;

    bool bool_result;

#line 419 "nd-flow-expr.hpp"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif

/* Location type.  */
#if ! defined YYLTYPE && ! defined YYLTYPE_IS_DECLARED
typedef struct YYLTYPE YYLTYPE;
struct YYLTYPE
{
  int first_line;
  int first_column;
  int last_line;
  int last_column;
};
# define YYLTYPE_IS_DECLARED 1
# define YYLTYPE_IS_TRIVIAL 1
#endif




int yyparse (yyscan_t scanner);


#endif /* !YY_YY_ND_FLOW_EXPR_HPP_INCLUDED  */
