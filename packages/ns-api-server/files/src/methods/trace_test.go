/*
Copyright (C) 2026 Nexwall
SPDX-License-Identifier: GPL-2.0-only
*/

package methods

import (
	"reflect"
	"strings"
	"testing"
)

func TestBuildTraceArgsValid(t *testing.T) {
	cases := []struct {
		name string
		req  TraceRequest
		want []string
	}{
		{"src host + dst port", TraceRequest{Tool: "fwtrace", SrcHost: "192.168.1.102", Port: 443, Both: true, Seconds: 20},
			[]string{"-j", "-i", "20", "--both", "src", "host", "192.168.1.102", "and", "port", "443"}},
		{"default seconds, proto only", TraceRequest{Tool: "drppkt", Proto: "udp"},
			[]string{"-j", "-i", "30", "proto", "udp"}},
		{"net + ipv6 host", TraceRequest{Tool: "drppkt", Net: "10.0.0.0/24", Host: "2001:db8::1", Seconds: 60},
			[]string{"-j", "-i", "60", "host", "2001:db8::1", "and", "net", "10.0.0.0/24"}},
		{"src port", TraceRequest{Tool: "fwtrace", SrcPort: 51000},
			[]string{"-j", "-i", "30", "src", "port", "51000"}},
	}
	for _, c := range cases {
		tool, args, err := buildTraceArgs(c.req)
		if err != nil {
			t.Fatalf("%s: unexpected error %v", c.name, err)
		}
		if tool != c.req.Tool || !reflect.DeepEqual(args, c.want) {
			t.Errorf("%s: got %v want %v", c.name, args, c.want)
		}
	}
}

func TestBuildTraceArgsRejects(t *testing.T) {
	bad := []TraceRequest{
		{Tool: "rm", Host: "1.2.3.4"},
		{Tool: "fwtrace"},                          // no filter at all
		{Tool: "fwtrace", Both: true, Seconds: 30}, // only options
		{Tool: "fwtrace", Host: "1.2.3.4; nft flush ruleset"},
		{Tool: "fwtrace", Host: "1.2.3.4 and port 22"},
		{Tool: "fwtrace", Host: "$(reboot)"},
		{Tool: "fwtrace", Net: "10.0.0.0/99"},
		{Tool: "fwtrace", Net: "10.0.0.0"},
		{Tool: "fwtrace", Host: "1.2.3.4", Port: 70000},
		{Tool: "fwtrace", Host: "1.2.3.4", Port: -1},
		{Tool: "fwtrace", Host: "1.2.3.4", Proto: "sctp"},
		{Tool: "fwtrace", Host: "1.2.3.4", Proto: "tcp; ls"},
		{Tool: "fwtrace", Host: "1.2.3.4", Seconds: 4},
		{Tool: "fwtrace", Host: "1.2.3.4", Seconds: 121},
	}
	for i, r := range bad {
		if _, args, err := buildTraceArgs(r); err == nil {
			t.Errorf("case %d (%+v) should be rejected, got args %v", i, r, args)
		}
	}
}

func TestBuildTraceArgsNeverBuildsAShellString(t *testing.T) {
	// every element is a separate argument: nothing with a space or shell metacharacter can appear
	_, args, err := buildTraceArgs(TraceRequest{Tool: "drppkt", SrcHost: "192.168.1.1", Port: 80, Proto: "tcp", Both: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range args {
		if strings.ContainsAny(a, " ;|&$`<>\"'\\") {
			t.Errorf("argument %q contains shell metacharacters", a)
		}
	}
}
