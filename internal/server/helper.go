package server

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/saintonotole/yandex-station-toolkit/internal/dnssrv"
)

// The elevated helper speaks line-delimited JSON over stdin/stdout: the GUI
// owns the pipes, so no sockets or config files are shared with root.
//
// Commands (one JSON object per line, from the GUI):
//   {"cmd":"start","mode":"override","firmwareDir":"..."}
//   {"cmd":"setMode","mode":"passthrough"}
//   {"cmd":"stop"}
//   {"cmd":"shutdown"}
//
// Events (to the GUI):
//   {"event":"log","msg":"..."}
//   {"event":"state","running":true,"mode":"override"}
//   {"event":"fatal","err":"..."}

type helperCommand struct {
	Cmd         string `json:"cmd"`
	Mode        string `json:"mode"`
	FirmwareDir string `json:"firmwareDir"`
	HTTPPort    int    `json:"httpPort"`
	HTTPSPort   int    `json:"httpsPort"`
	DNSPort     int    `json:"dnsPort"`
}

func modeFromString(s string) (Mode, error) {
	switch s {
	case "passthrough":
		return Passthrough, nil
	case "override":
		return Override, nil
	}
	return Passthrough, fmt.Errorf("Server: unknown mode %q", s)
}

type HelperConfig struct {
	// CertPEM, KeyPEM, SyncTemplate come from the embedded payloads; the
	// helper is the same binary, so they are passed by the caller.
	CertPEM      []byte
	KeyPEM       []byte
	SyncTemplate []byte
	// MakeProvider builds a FirmwareProvider over a firmware directory. It
	// may be nil, in which case the helper answers hasUpdate:false. The
	// factory comes from the caller so this package stays decoupled from the
	// firmware store.
	MakeProvider func(dir string, log func(string)) FirmwareProvider
	// Addr is the listen IP for every endpoint; empty means all
	// interfaces (the production Linux helper serves the LAN). Tests
	// pass 127.0.0.1 so their temp binaries never trip the firewall.
	Addr string
}

type helperEvent struct {
	Event   string `json:"event"`
	Msg     string `json:"msg,omitempty"`
	Err     string `json:"err,omitempty"`
	Running bool   `json:"running,omitempty"`
	Mode    string `json:"mode,omitempty"`
}

// RunHelper serves commands until "shutdown" or input EOF. It is transport
// agnostic so tests can drive it with pipes; logs also go to stderr, which
// the OS journal or a redirect captures.
func RunHelper(cfg HelperConfig, in io.Reader, out io.Writer) error {
	emit := func(e helperEvent) {
		b, _ := json.Marshal(e)
		fmt.Fprintln(out, string(b))
	}
	logf := func(format string, args ...any) {
		emit(helperEvent{Event: "log", Msg: fmt.Sprintf(format, args...)})
		fmt.Fprintf(os.Stderr, "Server-helper: "+format+"\n", args...)
	}
	// The Config and provider factories take a plain func(string).
	logLine := func(msg string) { logf("%s", msg) }

	var (
		mu    sync.Mutex
		std   *Server
		fwDir string
	)
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 64*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var cmd helperCommand
		if err := json.Unmarshal(line, &cmd); err != nil {
			emit(helperEvent{Event: "log", Msg: "helper: unreadable command"})
			continue
		}
		mu.Lock()
		s := std
		mu.Unlock()
		switch cmd.Cmd {
		case "start":
			if s != nil {
				logf("helper: already running")
				continue
			}
			if cmd.FirmwareDir != "" {
				fwDir = cmd.FirmwareDir
			}
			scfg := Config{
				CertPEM:      cfg.CertPEM,
				KeyPEM:       cfg.KeyPEM,
				SyncTemplate: cfg.SyncTemplate,
				Addr:         cfg.Addr,
				DNS:          dnssrv.Config{Port: cmd.DNSPort, Addr: cfg.Addr, Log: logLine},
				HTTPPort:     cmd.HTTPPort,
				HTTPSPort:    cmd.HTTPSPort,
				Log:          logLine,
			}
			if cfg.MakeProvider != nil && fwDir != "" {
				scfg.Firmware = cfg.MakeProvider(fwDir, logLine)
			}
			mode, err := modeFromString(cmd.Mode)
			if err != nil {
				emit(helperEvent{Event: "log", Msg: "helper: " + err.Error()})
				continue
			}
			newStd, err := New(scfg)
			if err != nil {
				emit(helperEvent{Event: "fatal", Err: err.Error()})
				continue
			}
			if err := newStd.Start(mode); err != nil {
				emit(helperEvent{Event: "log", Msg: "helper: start: " + err.Error()})
				emit(helperEvent{Event: "state", Running: false})
				continue
			}
			mu.Lock()
			std = newStd
			mu.Unlock()
			emit(helperEvent{Event: "state", Running: true, Mode: cmd.Mode})
		case "setMode":
			if s == nil {
				logf("helper: not running")
				continue
			}
			mode, err := modeFromString(cmd.Mode)
			if err != nil {
				emit(helperEvent{Event: "log", Msg: "helper: " + err.Error()})
				continue
			}
			if err := s.SetMode(mode); err != nil {
				logf("helper: setMode: %v", err)
				continue
			}
			emit(helperEvent{Event: "state", Running: true, Mode: cmd.Mode})
		case "stop":
			if s == nil {
				continue
			}
			s.Stop()
			mu.Lock()
			std = nil
			mu.Unlock()
			emit(helperEvent{Event: "state", Running: false})
		case "shutdown":
			mu.Lock()
			s := std
			std = nil
			mu.Unlock()
			if s != nil {
				s.Stop()
			}
			return nil
		}
	}
	mu.Lock()
	s := std
	std = nil
	mu.Unlock()
	if s != nil {
		s.Stop()
	}
	return nil
}
