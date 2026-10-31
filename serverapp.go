package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/saintonotole/yandex-station-toolkit/internal/dnssrv"
	"github.com/saintonotole/yandex-station-toolkit/internal/firmware"
	"github.com/saintonotole/yandex-station-toolkit/internal/server"
)

// serverCtl owns the bootstrap endpoints. They run in-process whenever the OS
// lets this user bind 53/80/443 (Windows and macOS do); only Linux re-execs
// a pkexec helper, so root code never runs inside the GUI process.
type serverCtl struct {
	app *App

	mu     sync.Mutex
	proc   *server.Server // in-process endpoints
	mode   server.Mode
	err    string
	helper *helperProc // set when elevated
}

type helperProc struct {
	cmd    *exec.Cmd
	stdin  *jsonLineWriter
	events chan serverEvent
}

// serverEvent mirrors Server's helper events, decoded loosely.
type serverEvent struct {
	Event   string `json:"event"`
	Msg     string `json:"msg"`
	Err     string `json:"err"`
	Running bool   `json:"running"`
	Mode    string `json:"mode"`
}

func newServerCtl(app *App) *serverCtl {
	return &serverCtl{app: app, mode: server.Passthrough}
}

func (c *serverCtl) running() (bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.proc != nil || c.helper != nil, c.helper != nil
}

// state emits the state the bootstrap page renders from.
func (c *serverCtl) state() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	mode := "passthrough"
	if c.mode == server.Override {
		mode = "override"
	}
	return map[string]any{
		"running":  c.proc != nil || c.helper != nil,
		"elevated": c.helper != nil,
		"mode":     mode,
		"err":      c.err,
	}
}

func (c *serverCtl) emitState() {
	c.app.emit("serverState", c.state())
}

// logTo mirrors Server log lines into the app journal.
func (c *serverCtl) logTo(msg string) { c.app.log("info", msg) }

// serverConfig builds the endpoint config from the embedded payloads.
func (a *App) serverConfig(log func(string)) (server.Config, error) {
	cert, err := payload(payloadEquasarChain)
	if err != nil {
		return server.Config{}, err
	}
	key, err := payload(payloadEquasarKey)
	if err != nil {
		return server.Config{}, err
	}
	tmpl, err := payload(payloadSyncTemplate)
	if err != nil {
		return server.Config{}, err
	}
	return server.Config{
		CertPEM:      cert,
		KeyPEM:       key,
		SyncTemplate: tmpl,
		// Port 53 is the whole point: dnssrv treats 0 as "OS picks a
		// free port" (tests rely on that), and leaving it unset made
		// the in-process Server listen on a random port while the UI
		// showed it running.
		DNS:      dnssrv.Config{Port: 53, Log: log},
		Firmware: firmware.NewProvider(a.fw, localLANIP, log),
		OnActivation: func(remoteIP, deviceID string) {
			a.onActivation(remoteIP, deviceID)
		},
		Log: log,
	}, nil
}

// start brings the endpoints up in the requested mode.
func (c *serverCtl) start(mode server.Mode) error {
	c.mu.Lock()
	already := c.proc != nil || c.helper != nil
	c.mu.Unlock()
	if already {
		return fmt.Errorf("Server already running")
	}

	logf := func(msg string) { c.logTo(msg) }
	cfg, err := c.app.serverConfig(logf)
	if err != nil {
		return err
	}
	s, err := server.New(cfg)
	if err != nil {
		return err
	}
	if err := s.Start(mode); err != nil {
		if server.PermissionError(err) {
			return c.startElevated(mode, err)
		}
		return err
	}
	c.mu.Lock()
	c.proc = s
	c.mode = mode
	c.err = ""
	c.mu.Unlock()
	c.emitState()
	return nil
}

// startElevated relaunches this binary as a helper through the OS's native
// privilege prompt. Only Linux reaches this path.
func (c *serverCtl) startElevated(mode server.Mode, cause error) error {
	if !server.ElevationSupported() {
		return fmt.Errorf("%v: ports 53/80/443 are not available and elevation is not supported here", cause)
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	real, err := filepath.EvalSymlinks(self)
	if err != nil {
		real = self
	}
	argv := server.HelperArgv(real, []string{"--Server-helper"})
	cmd := exec.Command(argv[0], argv[1:]...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("elevation failed: %w", err)
	}
	h := &helperProc{cmd: cmd, stdin: &jsonLineWriter{w: stdin}, events: make(chan serverEvent, 64)}
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 0, 64*1024), 64*1024)
		for sc.Scan() {
			var e serverEvent
			if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
				continue
			}
			select {
			case h.events <- e:
			default:
			}
			switch e.Event {
			case "log":
				c.logTo(e.Msg)
			case "state":
				c.applyHelperState(e)
			case "fatal":
				c.app.log("err", "Server helper: "+e.Err)
			}
		}
		// The helper died or was closed: drop it from the running state.
		c.mu.Lock()
		if c.helper == h {
			c.helper = nil
			c.err = "helper exited"
		}
		c.mu.Unlock()
		c.emitState()
	}()
	c.mu.Lock()
	c.helper = h
	c.mu.Unlock()

	modeName := "passthrough"
	if mode == server.Override {
		modeName = "override"
	}
	h.stdin.write(map[string]any{
		"cmd":         "start",
		"mode":        modeName,
		"firmwareDir": filepath.Join(configDir(), "firmware"),
		"httpPort":    80,
		"httpsPort":   443,
		"dnsPort":     53,
	})
	// Wait for the helper's confirmation before reporting success.
	deadline := time.After(20 * time.Second)
	for {
		select {
		case e := <-h.events:
			if e.Event == "state" {
				if !e.Running {
					return fmt.Errorf("elevated helper could not start the endpoints")
				}
				c.mu.Lock()
				c.mode = mode
				c.err = ""
				c.mu.Unlock()
				c.emitState()
				return nil
			}
		case <-deadline:
			return fmt.Errorf("elevated helper did not confirm startup")
		}
	}
}

func (c *serverCtl) applyHelperState(e serverEvent) {
	c.mu.Lock()
	if e.Running {
		c.err = ""
		if m, err := helperMode(e.Mode); err == nil {
			c.mode = m
		}
	} else {
		c.helper = nil
		c.proc = nil
	}
	c.mu.Unlock()
	c.emitState()
}

func helperMode(s string) (server.Mode, error) {
	if s == "override" {
		return server.Override, nil
	}
	return server.Passthrough, nil
}

// setMode switches the live endpoints between modes.
func (c *serverCtl) setMode(mode server.Mode) error {
	c.mu.Lock()
	proc, helper := c.proc, c.helper
	c.mu.Unlock()
	modeName := "passthrough"
	if mode == server.Override {
		modeName = "override"
	}
	switch {
	case proc != nil:
		if err := proc.SetMode(mode); err != nil {
			return err
		}
	case helper != nil:
		helper.stdin.write(map[string]any{"cmd": "setMode", "mode": modeName})
		// Confirm via the events channel; the reader goroutine also sees it.
		deadline := time.After(10 * time.Second)
		for {
			select {
			case e := <-helper.events:
				if e.Event == "state" && e.Running {
					c.mu.Lock()
					c.mode = mode
					c.mu.Unlock()
					c.emitState()
					return nil
				}
			case <-deadline:
				return fmt.Errorf("helper did not confirm the mode switch")
			}
		}
	default:
		return fmt.Errorf("not running")
	}
	c.mu.Lock()
	c.mode = mode
	c.mu.Unlock()
	c.emitState()
	return nil
}

// stop brings the endpoints down.
func (c *serverCtl) stop() error {
	c.mu.Lock()
	proc, helper := c.proc, c.helper
	c.proc, c.helper = nil, nil
	c.mu.Unlock()
	if proc != nil {
		proc.Stop()
	}
	if helper != nil {
		helper.stdin.write(map[string]any{"cmd": "shutdown"})
		go func() {
			time.Sleep(500 * time.Millisecond)
			helper.cmd.Process.Kill()
		}()
	}
	c.emitState()
	return nil
}

// shutdown is called from App.Shutdown; it is silent.
func (c *serverCtl) shutdown() {
	c.mu.Lock()
	proc, helper := c.proc, c.helper
	c.proc, c.helper = nil, nil
	c.mu.Unlock()
	if proc != nil {
		proc.Stop()
	}
	if helper != nil {
		helper.stdin.write(map[string]any{"cmd": "shutdown"})
		done := time.AfterFunc(time.Second, func() { helper.cmd.Process.Kill() })
		defer done.Stop()
		_, _ = helper.cmd.Process.Wait()
	}
}

type jsonLineWriter struct {
	w interface{ Write([]byte) (int, error) }
}

func (j *jsonLineWriter) write(v map[string]any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	j.w.Write(append(b, '\n'))
}

// localLANIP picks the address the firmware manifest advertises as its
// fallback IP: whatever this machine uses to reach the internet.
func localLANIP() string {
	conn, err := net.Dial("udp", "77.88.8.8:53")
	if err != nil {
		return ""
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

// onServer handles the bootstrap page's actions.
func (a *App) onServer(m map[string]any) {
	action, _ := m["action"].(string)
	mode := server.Passthrough
	if s, _ := m["mode"].(string); s == "override" {
		mode = server.Override
	}
	switch action {
	case "start":
		go func() {
			a.setBusy(true, "Запуск локального DNS-сервера")
			defer a.setBusy(false, "")
			// Windows' own firewall dialog (if any) appears when the
			// Server binds; fwNote only tells the owner what to expect
			// and refuses to start when a Block rule makes it moot.
			if !a.fwNote() {
				a.emitServerState()
				a.serverPreflight()
				return
			}
			err := a.serverctl.start(mode)
			if err != nil {
				a.serverctl.setError(err)
				a.log("err", "Server: "+err.Error())
			}
			if err == nil && mode == server.Override {
				a.warnMissingFirmware()
			}
			a.emitServerState()
			a.serverPreflight()
		}()
	case "stop":
		go func() {
			a.setBusy(true, "Остановка сервера")
			defer a.setBusy(false, "")
			err := a.serverctl.stop()
			if err != nil {
				a.log("err", "Server: "+err.Error())
			}
			// Firewall rules are Windows' own business now: whatever the
			// owner allowed in the native dialog stays until they
			// change it in the firewall UI, exactly like adb.exe.
			a.emitServerState()
			a.serverPreflight()
		}()
	case "setMode":
		merr := a.serverctl.setMode(mode)
		if merr != nil {
			a.log("err", "Server: "+merr.Error())
		}
		if merr == nil && mode == server.Override {
			// The owner's flow switches to override mid-onboarding; a
			// missing firmware file is invisible until the station asks
			// for it — warn the moment the mode turns on.
			a.warnMissingFirmware()
		}
		a.emitServerState()
	case "status":
		a.emitServerState()
		a.emitFirmwareTargets()
		a.serverPreflight()
	case "ensureFirmware":
		platform, _ := m["platform"].(string)
		go a.ensureFirmware(platform)
	}
}

func (c *serverCtl) setError(err error) {
	c.mu.Lock()
	c.err = err.Error()
	c.mu.Unlock()
}

func (a *App) emitServerState() {
	a.emit("serverState", a.serverctl.state())
}

// emitFirmwareTargets reports the vulnerable-version registry and what is
// already downloaded, plus which platforms were actually seen on the LAN.
// Device platforms resolve through the registry aliases so a Mini 2 seen
// as "yandexmini2" lights up the "yandexmini_2" target's badge.
func (a *App) emitFirmwareTargets() {
	seen := map[string]bool{}
	a.mu.Lock()
	for _, d := range a.devices {
		if d.Platform != "" {
			if t, ok := firmware.TargetFor(d.Platform); ok {
				seen[t.Platform] = true
			} else {
				seen[d.Platform] = true
			}
		}
	}
	a.mu.Unlock()
	var list []map[string]any
	for _, t := range firmware.Targets() {
		list = append(list, map[string]any{
			"platform": t.Platform,
			"device":   t.Device,
			"version":  t.Version,
			"has":      a.fw.Has(t.Platform),
			"seen":     seen[t.Platform],
		})
	}
	a.emit("firmwareTargets", map[string]any{"list": list})
}

// ensureFirmware downloads the vulnerable build for a platform in the
// background; the page tracks it through firmwareTargets events.
func (a *App) ensureFirmware(platform string) {
	t, _ := firmware.TargetFor(platform)
	device := platform
	if t.Device != "" {
		device = t.Device
	}
	_, err := a.fw.Ensure(context.Background(), platform)
	if err != nil {
		a.log("err", "firmware: "+err.Error())
	} else {
		a.log("ok", "firmware: "+device+" ready to serve")
	}
	a.emitFirmwareTargets()
	a.emit("firmwareTargetsDone", map[string]any{"platform": platform, "err": errString(err)})
}

// warnMissingFirmware journals every seen platform whose vulnerable
// firmware is not in the local store. In override mode the station asks
// for that firmware during onboarding and gets hasUpdate:false — which
// looks like a broken jailbreak unless the reason is on the record.
func (a *App) warnMissingFirmware() {
	a.mu.Lock()
	seen := map[string]string{}
	for _, d := range a.devices {
		if d.Platform != "" {
			seen[d.Platform] = d.Platform
		}
	}
	a.mu.Unlock()
	for plat := range seen {
		t, ok := firmware.TargetFor(plat)
		if !ok {
			continue
		}
		if !a.fw.Has(t.Platform) {
			a.log("warn", fmt.Sprintf("firmware for %s is not downloaded — a resetting station will ask for it and get nothing; press «Скачать» in Прошивки before the next attempt", t.Device))
		}
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
