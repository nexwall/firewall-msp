// Netify Agent Test Suite
// Copyright (C) 2024 eGloo Incorporated
// <http://www.egloo.ca>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <arpa/inet.h>
#include <gtest/gtest.h>

#include <string>

#include "nd-flow.hpp"
#include "nd-flow-parser.hpp"
#include "nd-instance.hpp"

using namespace std;

// #define SPEEDTEST_ITERATIONS 1
#define SPEEDTEST_ITERATIONS 1000000

static ndInstance& instance = ndInstance::Create();
static ndInterface::Ptr iface(new ndInterface("lo", ndCaptureType::PCAP));
static ndFlow::Ptr flow(new ndFlow(iface));
static ndFlowParser parser;

// EXPECT_EQ(s1, "hello world");

TEST(FlowExpressionParser, BadExpressions) {
    // missing semi-colon
    string expr = "detected_hostname";
    EXPECT_THROW(parser.Parse(flow, expr), ndException) << expr;
}

TEST(FlowExpressionParser, BooleanOperators) {
    flow->ip_version = 0;
    string expr = "ip_version;";

    try {
        EXPECT_FALSE(parser.Parse(flow, expr)) << expr;

        expr = "! ip_version;";
        EXPECT_TRUE(parser.Parse(flow, expr)) << expr;

        flow->ip_version = 4;

        expr = "ip_version == 4 && ip_version != 6;";
        EXPECT_TRUE(parser.Parse(flow, expr)) << expr;
        expr = "ip_version == 4 and ip_version != 6;";
        EXPECT_TRUE(parser.Parse(flow, expr)) << expr;

        expr = "ip_version == 4 || ip_version != 6;";
        EXPECT_TRUE(parser.Parse(flow, expr)) << expr;
        expr = "ip_version == 4 or ip_version != 6;";
        EXPECT_TRUE(parser.Parse(flow, expr)) << expr;

    } catch (exception &e) {
        FAIL() << expr << ": " << e.what();
    }
}

TEST(FlowExpressionParser, NumericComparisons) {
    flow->ip_version = 4;
    string expr = "!ip_version > 0 && ip_version >= 4;";

    try {
        expr = "ip_version > 0 && ip_version >= 4;";
        EXPECT_TRUE(parser.Parse(flow, expr)) << expr;

        expr = "ip_version < 6 && ip_version <= 6;";
        EXPECT_TRUE(parser.Parse(flow, expr)) << expr;

    } catch (exception &e) {
        FAIL() << expr << ": " << e.what();
    }
}

TEST(FlowExpressionParser, Precedence) {
    flow->ip_version = 4;

    flow->lower_addr = ndAddr("192.168.0.1");
    flow->lower_addr.SetPort(ntohs(1000));

    flow->upper_addr = ndAddr("10.0.0.1");
    flow->upper_addr.SetPort(ntohs(2000));

    string expr = "ip_version > 0 && ip_version != 6 && "
        "(local_ip == 192.168.0.1 || other_ip == 10.0.0.1) && "
        "((local_ip != 10.0.0.1 && other_ip != 192.168.0.1) && "
        "(local_port == 1000 || local_port == 2000));";

    try {
        EXPECT_TRUE(parser.Parse(flow, expr)) << expr;
    } catch (exception &e) {
        FAIL() << expr << ": " << e.what();
    }
}

TEST(FlowExpressionParser, SpeedTestSimple) {
    flow->host_server_name.clear();

    string expr = "!detected_hostname;";

    try {
        for (auto i = 0; i < SPEEDTEST_ITERATIONS; i++) {
            EXPECT_TRUE(parser.Parse(flow, expr)) << expr;
        }
    } catch (exception &e) {
        FAIL() << expr << ": " << e.what();
    }
}

TEST(FlowExpressionParser, SpeedTestComplex) {
    flow->lower_mac = ndAddr("00:de:ad:be:ef:00");
    flow->host_server_name = "example.com";

    string expr = "detected_hostname == 'example.com' && "
        "(origin == origin_local || origin == origin_other) && "
        "src_mac == 00:de:ad:be:ef:00;";

    try {
        for (auto i = 0; i < SPEEDTEST_ITERATIONS; i++) {
            EXPECT_TRUE(parser.Parse(flow, expr)) << expr;
        }
    } catch (exception &e) {
        FAIL() << expr << ": " << e.what();
    }
}

TEST(FlowExpressionParser, SpeedTestRegex) {
    flow->host_server_name = "some.example.com";

    string expr = "detected_hostname == 'rx:^.*\\.example\\.com$';";

    try {
        for (auto i = 0; i < SPEEDTEST_ITERATIONS; i++) {
            EXPECT_TRUE(parser.Parse(flow, expr)) << expr;
        }
    } catch (exception &e) {
        FAIL() << expr << ": " << e.what();
    }
}

TEST(FlowExpressionParser, DetectedHostname) {
    flow->host_server_name.clear();

    string expr = "!detected_hostname;";

    try {
        EXPECT_TRUE(parser.Parse(flow, expr)) << expr;

        flow->host_server_name = "example.com";

        expr = "detected_hostname;";
        EXPECT_TRUE(parser.Parse(flow, expr)) << expr;

        expr = "detected_hostname == 'example.com';";
        EXPECT_TRUE(parser.Parse(flow, expr)) << expr;

        expr = "detected_hostname != 'example.com';";
        EXPECT_FALSE(parser.Parse(flow, expr)) << expr;

        expr = "detected_hostname == 'rx:^example\\.com$';";
        EXPECT_TRUE(parser.Parse(flow, expr)) << expr;

        expr = "detected_hostname == 'rx:google\\.com';";
        EXPECT_FALSE(parser.Parse(flow, expr)) << expr;

        expr = "detected_hostname != 'rx:\\.com$';";
        EXPECT_FALSE(parser.Parse(flow, expr)) << expr;
    } catch (exception &e) {
        FAIL() << expr << ": " << e.what();
    }
}

#ifdef ND_ENABLE_INTERFACE_METADATA
TEST(FlowExpression, SSID) {
    snprintf(
      flow->if_metadata.local.ssid,
      "%s", sizeof(flow->if_metdata.local.ssid), "test");

    string expr = "ssid == 'test';";

    try {
        EXPECT_TRUE(parser.Parse(flow, expr)) << expr;
    } catch (exception &e) {
        FAIL() << expr << ": " << e.what();
    }
}
#endif

// Ensure gtest has an entry point
int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);

    flow->lower_map = ndFlow::LowerMap::LOCAL;
    flow->origin = ndFlow::Origin::LOWER;

    instance.InitializeConfig(argc, argv);
//    uint32_t result = instance.InitializeConfig(argc, argv);

//    if (ndCR_Result(result) != ndInstance::ConfigResult::OK)
//        exit(ndCR_Code(result));

    return RUN_ALL_TESTS();
}
