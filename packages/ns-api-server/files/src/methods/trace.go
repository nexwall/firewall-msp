/*
Copyright (C) 2026 Nexwall
SPDX-License-Identifier: GPL-2.0-only
*/

package methods

// Live firewall tracing for the log viewer: runs fwtrace / drppkt (see nexwall-scripts) on behalf
// of an authenticated administrator and lets the page poll their output.
//
// These tools run as root and insert (harmless, non-terminating) nftables probe rules, so this is
// deliberately narrow: JWT-authenticated like every other route, no shell (arguments are passed
// as a list), every field validated strictly, a hard time limit, one session at a time, bounded
// memory. The tools validate their own arguments again; neither layer trusts the other.

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/NethServer/nethsecurity-api/logs"
	"github.com/NethServer/nethsecurity-api/response"
	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"
)

const (
	traceMinSeconds   = 5
	traceMaxSeconds   = 120
	traceDefaultSecs  = 30
	traceMaxLines     = 2000
	traceMaxLineBytes = 16 << 10
	traceKeepFinished = 10 * time.Minute
)

// TraceRequest is the JSON body of POST /trace/start. Every field is optional except that at
// least one of Host, Net, Port, Proto must be given.
type TraceRequest struct {
	Tool    string `json:"tool"`
	Host    string `json:"host"`
	SrcHost string `json:"src_host"`
	Net     string `json:"net"`
	SrcNet  string `json:"src_net"`
	Port    int    `json:"port"`
	SrcPort int    `json:"src_port"`
	Proto   string `json:"proto"`
	Both    bool   `json:"both"`
	Seconds int    `json:"seconds"`
}

var traceTools = map[string]string{
	"fwtrace": "/usr/sbin/fwtrace",
	"drppkt":  "/usr/sbin/drppkt",
}

// buildTraceArgs validates the request and returns the argument list for the tool. It never
// builds a string that is interpreted by a shell.
func buildTraceArgs(req TraceRequest) (tool string, args []string, err error) {
	if _, ok := traceTools[req.Tool]; !ok {
		return "", nil, fmt.Errorf("unknown tool")
	}
	secs := req.Seconds
	if secs == 0 {
		secs = traceDefaultSecs
	}
	if secs < traceMinSeconds || secs > traceMaxSeconds {
		return "", nil, fmt.Errorf("seconds must be between %d and %d", traceMinSeconds, traceMaxSeconds)
	}
	args = []string{"-j", "-i", strconv.Itoa(secs)}
	if req.Both {
		args = append(args, "--both")
	}

	addHost := func(dir, kw, value string) error {
		if value == "" {
			return nil
		}
		if kw == "host" && net.ParseIP(value) == nil {
			return fmt.Errorf("invalid %s address", dir)
		}
		if kw == "net" {
			if _, _, e := net.ParseCIDR(value); e != nil {
				return fmt.Errorf("invalid %s network", dir)
			}
		}
		if dir == "src" {
			args = append(args, "src")
		}
		args = append(args, kw, value, "and")
		return nil
	}
	if err = addHost("dst", "host", req.Host); err != nil {
		return
	}
	if err = addHost("src", "host", req.SrcHost); err != nil {
		return
	}
	if err = addHost("dst", "net", req.Net); err != nil {
		return
	}
	if err = addHost("src", "net", req.SrcNet); err != nil {
		return
	}
	for _, p := range []struct {
		dir  string
		port int
	}{{"dst", req.Port}, {"src", req.SrcPort}} {
		if p.port == 0 {
			continue
		}
		if p.port < 1 || p.port > 65535 {
			return "", nil, fmt.Errorf("invalid port")
		}
		if p.dir == "src" {
			args = append(args, "src")
		}
		args = append(args, "port", strconv.Itoa(p.port), "and")
	}
	if req.Proto != "" {
		switch req.Proto {
		case "tcp", "udp", "icmp", "icmpv6":
			args = append(args, "proto", req.Proto, "and")
		default:
			return "", nil, fmt.Errorf("invalid protocol")
		}
	}
	if len(args) == 3+btoi(req.Both) {
		return "", nil, fmt.Errorf("give at least one of host, network, port, protocol")
	}
	// drop the trailing "and"
	if args[len(args)-1] == "and" {
		args = args[:len(args)-1]
	}
	return req.Tool, args, nil
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

type traceSession struct {
	id       string
	tool     string
	cmd      *exec.Cmd
	mu       sync.Mutex
	lines    []string
	dropped  int // lines discarded once the cap was reached
	running  bool
	errText  string
	finished time.Time
}

var (
	traceMu       sync.Mutex
	traceSessions = map[string]*traceSession{}
)

func newTraceID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// reapTraceSessions forgets finished sessions after a while. Caller holds traceMu.
func reapTraceSessions() {
	for id, s := range traceSessions {
		s.mu.Lock()
		old := !s.running && time.Since(s.finished) > traceKeepFinished
		s.mu.Unlock()
		if old {
			delete(traceSessions, id)
		}
	}
}

func traceBusy() bool {
	for _, s := range traceSessions {
		s.mu.Lock()
		r := s.running
		s.mu.Unlock()
		if r {
			return true
		}
	}
	return false
}

func traceError(c *gin.Context, code int, msg string) {
	c.JSON(code, structs.Map(response.StatusBadRequest{Code: code, Message: msg, Data: nil}))
}

// TraceStart starts fwtrace/drppkt and returns the session id.
func TraceStart(c *gin.Context) {
	var req TraceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		traceError(c, http.StatusBadRequest, "request fields malformed")
		return
	}
	tool, args, err := buildTraceArgs(req)
	if err != nil {
		traceError(c, http.StatusBadRequest, err.Error())
		return
	}

	traceMu.Lock()
	reapTraceSessions()
	if traceBusy() {
		traceMu.Unlock()
		traceError(c, http.StatusConflict, "a trace is already running")
		return
	}
	cmd := exec.Command(traceTools[tool], args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, e1 := cmd.StdoutPipe()
	stderr, e2 := cmd.StderrPipe()
	if e1 != nil || e2 != nil {
		traceMu.Unlock()
		traceError(c, http.StatusInternalServerError, "cannot start trace")
		return
	}
	if e := cmd.Start(); e != nil {
		traceMu.Unlock()
		logs.Logs.Println("[ERROR][TRACE] start failed:", e.Error())
		traceError(c, http.StatusInternalServerError, "cannot start trace")
		return
	}
	s := &traceSession{id: newTraceID(), tool: tool, cmd: cmd, running: true}
	traceSessions[s.id] = s
	traceMu.Unlock()
	logs.Logs.Println("[INFO][TRACE] started", tool, strings.Join(args, " "))

	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 0, 64<<10), traceMaxLineBytes)
		for sc.Scan() {
			s.mu.Lock()
			if len(s.lines) < traceMaxLines {
				s.lines = append(s.lines, sc.Text())
			} else {
				s.dropped++
			}
			s.mu.Unlock()
		}
	}()
	go func() {
		eb := bufio.NewScanner(stderr)
		for eb.Scan() {
			t := eb.Text()
			// nft's iptables-nft warning is not an error of ours
			if strings.HasPrefix(t, "# Warning:") {
				continue
			}
			s.mu.Lock()
			if len(s.errText) < 500 {
				s.errText += t + "\n"
			}
			s.mu.Unlock()
		}
	}()
	go func() {
		// the tool stops itself after -i seconds; this is the backstop if it hangs
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Duration(traceMaxSeconds+15) * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
			<-done
		}
		s.mu.Lock()
		s.running = false
		s.finished = time.Now()
		s.mu.Unlock()
		logs.Logs.Println("[INFO][TRACE] finished", s.tool, s.id)
	}()

	c.JSON(http.StatusOK, gin.H{"code": 200, "data": gin.H{"id": s.id}})
}

func findTrace(id string) *traceSession {
	traceMu.Lock()
	defer traceMu.Unlock()
	return traceSessions[id]
}

// TraceGet returns the events collected so far, from offset `since`.
func TraceGet(c *gin.Context) {
	s := findTrace(c.Param("id"))
	if s == nil {
		traceError(c, http.StatusNotFound, "trace not found")
		return
	}
	since, _ := strconv.Atoi(c.DefaultQuery("since", "0"))
	s.mu.Lock()
	defer s.mu.Unlock()
	if since < 0 || since > len(s.lines) {
		since = 0
	}
	c.JSON(http.StatusOK, gin.H{"code": 200, "data": gin.H{
		"tool":    s.tool,
		"running": s.running,
		"lines":   s.lines[since:],
		"next":    len(s.lines),
		"dropped": s.dropped,
		"error":   s.errText,
	}})
}

// TraceStop asks a running trace to stop; the tool removes its own probe rules on SIGTERM.
func TraceStop(c *gin.Context) {
	s := findTrace(c.Param("id"))
	if s == nil {
		traceError(c, http.StatusNotFound, "trace not found")
		return
	}
	s.mu.Lock()
	running := s.running
	s.mu.Unlock()
	if running && s.cmd.Process != nil {
		_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGTERM)
	}
	c.JSON(http.StatusOK, gin.H{"code": 200, "data": gin.H{"stopping": running}})
}
