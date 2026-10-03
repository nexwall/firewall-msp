// Netify Agent Test Suite
// Copyright (C) 2024 eGloo Incorporated
// <http://www.egloo.ca>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gtest/gtest.h>
#include <arpa/inet.h>
#include <string.h>

#include "nd-util.hpp"

using namespace std;

// Test the nd_trim function family
TEST(UtilTest, StringTrim) {
    string s1 = "  hello world  ";
    nd_trim(s1);
    EXPECT_EQ(s1, "hello world");

    string s2 = "no_trim";
    nd_trim(s2);
    EXPECT_EQ(s2, "no_trim");

    string s3 = "   left";
    nd_ltrim(s3);
    EXPECT_EQ(s3, "left");

    string s4 = "right   ";
    nd_rtrim(s4);
    EXPECT_EQ(s4, "right");
}

// Test extension replacement
TEST(UtilTest, ChangeExtension) {
    EXPECT_EQ(nd_change_ext("test.txt", "log"), "test.log");
    EXPECT_EQ(nd_change_ext("no_ext", "json"), "no_ext"); // Returns unchanged if no dot
    EXPECT_EQ(nd_change_ext("a.b.c", "d"), "a.b.d");
}

// Test IP address conversion
TEST(UtilTest, IpToString) {
    struct sockaddr_storage ss;
    struct sockaddr_in *addr4 = reinterpret_cast<struct sockaddr_in*>(&ss);
    
    memset(&ss, 0, sizeof(ss));
    addr4->sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.1.1", &addr4->sin_addr);

    string dst;
    nd_ip_to_string(ss, dst);
    EXPECT_EQ(dst, "192.168.1.1");
}

// Test hostname processing
TEST(UtilTest, SetHostname) {
    string dst;
    
    // Valid strict
    nd_set_hostname(dst, "www.example.com", 15, true);
    EXPECT_EQ(dst, "www.example.com");

    // Removes trailing dot
    nd_set_hostname(dst, "www.example.com.", 16, true);
    EXPECT_EQ(dst, "www.example.com");
}

// Ensure gtest has an entry point
int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}
