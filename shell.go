package main

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/saintonotole/yandex-station-toolkit/internal/adb"
	"github.com/saintonotole/yandex-station-toolkit/internal/sshkeys"

	"golang.org/x/crypto/ssh"
)

// shell.go — the Консоль tab: a persistent interactive shell on the station,
// over the same channel auto-discovery uses. adb first (a live `adb shell`
// process), then passwordless root SSH with a real PTY. One session at a
// time; the frontend opens it on tab entry and closes it on device switch.

type shellSession struct {
	ip     string
	via    string
	stdin  io.WriteCloser
	resize func(cols, rows int)
	close  func()

	// Wails dispatches every event handler in its own goroutine, so two
	// writes can reach stdin out of order (an Enter overtaking the typed
	// characters executes an empty line — the "two Enters" bug). Writes
	// carry a monotonic seq from the frontend; writeSeq is the highest
	// seq already written, pending holds early arrivals until the gap
	// closes.
	writeMu  sync.Mutex
	writeSeq uint64
	pending  map[uint64]string
}

// startSeq anchors the session's write stream at the seq the frontend
// said its next write will carry (open.seqFrom).
func (s *shellSession) startSeq(seq uint64) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.writeSeq = seq - 1
}

func (s *shellSession) writeOrdered(data string, seq uint64) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if seq == 0 || seq <= s.writeSeq {
		// Unsequenced write, or a stale/duplicate from a previous session.
		if seq == 0 {
			_, _ = s.stdin.Write([]byte(data))
		}
		return
	}
	if seq != s.writeSeq+1 {
		if s.pending == nil {
			s.pending = map[uint64]string{}
		}
		s.pending[seq] = data
		return
	}
	for {
		_, _ = s.stdin.Write([]byte(data))
		s.writeSeq = seq
		next, ok := s.pending[seq+1]
		if !ok {
			return
		}
		delete(s.pending, seq+1)
		data, seq = next, seq+1
	}
}

func (a *App) onShell(m map[string]any) {
	switch str(m, "action") {
	case "open":
		cols, rows := 80, 24
		if v, ok := m["cols"].(float64); ok && v > 0 {
			cols = int(v)
		}
		if v, ok := m["rows"].(float64); ok && v > 0 {
			rows = int(v)
		}
		var seqFrom uint64
		if v, ok := m["seqFrom"].(float64); ok {
			seqFrom = uint64(v)
		}
		a.shellOpen(str(m, "ip"), cols, rows, seqFrom)
	case "write":
		if data, ok := m["data"].(string); ok {
			var seq uint64
			if v, ok := m["seq"].(float64); ok {
				seq = uint64(v)
			}
			a.shellWrite(data, seq)
		}
	case "resize":
		cols, rows := 80, 24
		if v, ok := m["cols"].(float64); ok {
			cols = int(v)
		}
		if v, ok := m["rows"].(float64); ok {
			rows = int(v)
		}
		a.shellResize(cols, rows)
	case "close":
		a.shellClose()
	}
}

func (a *App) shellActive() bool {
	a.shellMu.Lock()
	defer a.shellMu.Unlock()
	return a.shell != nil
}

func (a *App) shellOpen(ip string, cols, rows int, seqFrom uint64) {
	if ip == "" {
		return
	}
	// The mutex guards the session pointer only; connects and probes run
	// outside it, so keystroke writes and close never queue behind a slow
	// open. shellOpening folds repeated open requests into one attempt.
	a.shellMu.Lock()
	if a.shellOpening {
		a.shellMu.Unlock()
		return
	}
	if a.shell != nil && a.shell.ip == ip {
		via := a.shell.via
		a.shellMu.Unlock()
		a.emit("shellState", map[string]any{"ip": ip, "via": via})
		return
	}
	if a.shell != nil {
		sess := a.shell
		a.shell = nil
		a.shellOpening = true
		a.shellMu.Unlock()
		sess.close()
		a.log("info", "console: closed on "+sess.ip)
	} else {
		a.shellOpening = true
		a.shellMu.Unlock()
	}
	defer func() {
		a.shellMu.Lock()
		a.shellOpening = false
		a.shellMu.Unlock()
	}()

	a.mu.Lock()
	d := a.devices[ip]
	a.mu.Unlock()
	if d == nil {
		a.emit("shellState", map[string]any{"ip": ip, "err": "unknown device"})
		return
	}

	// adb: a live shell process, exactly like `adb shell` in a terminal.
	if d.HasADB() {
		if c := a.adbClient(); c != nil {
			ctx, cancel := context.WithCancel(context.Background())
			stdin, out, err := c.Console(adb.Quiet(ctx), ip)
			if err != nil {
				cancel()
				a.log("warn", "console: adb on "+ip+": "+err.Error())
			} else {
				sess := &shellSession{
					ip:    ip,
					via:   "adb",
					stdin: stdin,
					// adb has no PTY resize; the device keeps its default size.
					resize: func(int, int) {},
					close:  cancel,
				}
				sess.startSeq(seqFrom)
				a.shellMu.Lock()
				a.shell = sess
				a.shellMu.Unlock()
				a.log("info", "console: opened via adb on "+ip)
				a.emit("shellState", map[string]any{"ip": ip, "via": "adb"})
				go a.pumpShell(ip, out)
				return
			}
		}
	}

	// SSH: passwordless root first, then the system agent if allowed.
	for _, port := range sshkeys.SSHPorts {
		if !d.Ports[port] {
			continue
		}
		client, err := sshkeys.TryNoneAuth(ip, port, "root", 6*time.Second)
		if err != nil && a.allowSSHAgent() {
			client, err = sshkeys.TryAgentAuth(ip, port, 6*time.Second)
		}
		if err != nil {
			continue
		}
		sess, out, err := newSSHShell(client, cols, rows)
		if err != nil {
			client.Close()
			a.log("warn", fmt.Sprintf("console: ssh %d on %s: %v", port, ip, err))
			continue
		}
		sess.ip, sess.via = ip, fmt.Sprintf("SSH %d", port)
		sess.startSeq(seqFrom)
		a.shellMu.Lock()
		a.shell = sess
		a.shellMu.Unlock()
		a.log("info", fmt.Sprintf("console: opened via ssh %d on %s", port, ip))
		a.emit("shellState", map[string]any{"ip": ip, "via": sess.via})
		go a.pumpShell(ip, out)
		return
	}

	a.emit("shellState", map[string]any{"ip": ip, "err": "no channel: enable network ADB or passwordless SSH on the station"})
}

// newSSHShell starts an interactive PTY shell over an SSH client.
func newSSHShell(client *ssh.Client, cols, rows int) (*shellSession, io.Reader, error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, nil, err
	}
	if err := sess.RequestPty("xterm", rows, cols, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
		sess.Close()
		return nil, nil, err
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		sess.Close()
		return nil, nil, err
	}
	pr, pw := io.Pipe()
	sess.Stdout = pw
	sess.Stderr = pw
	if err := sess.Shell(); err != nil {
		sess.Close()
		return nil, nil, err
	}
	go func() {
		_ = sess.Wait()
		pw.CloseWithError(io.EOF)
	}()
	return &shellSession{
		stdin:  stdin,
		resize: func(cols, rows int) { _ = sess.WindowChange(rows, cols) },
		close: func() {
			sess.Close()
			client.Close()
		},
	}, pr, nil
}

// pumpShell forwards the device's output to the terminal until the session
// ends, then reports the exit to the UI.
func (a *App) pumpShell(ip string, out io.Reader) {
	buf := make([]byte, 32*1024)
	for {
		n, err := out.Read(buf)
		if n > 0 {
			a.emit("shellOut", map[string]any{"ip": ip, "data": string(buf[:n])})
		}
		if err != nil {
			break
		}
	}
	a.shellMu.Lock()
	current := a.shell != nil && a.shell.ip == ip
	if current {
		a.shell = nil
	}
	a.shellMu.Unlock()
	if current {
		a.emit("shellExit", map[string]any{"ip": ip})
	}
}

func (a *App) shellWrite(data string, seq uint64) {
	a.shellMu.Lock()
	s := a.shell
	a.shellMu.Unlock()
	if s == nil {
		return
	}
	s.writeOrdered(data, seq)
}

func (a *App) shellResize(cols, rows int) {
	a.shellMu.Lock()
	s := a.shell
	a.shellMu.Unlock()
	if s != nil && s.resize != nil {
		s.resize(cols, rows)
	}
}

func (a *App) shellClose() {
	a.shellMu.Lock()
	defer a.shellMu.Unlock()
	a.shellCloseLocked()
}

func (a *App) shellCloseLocked() {
	if a.shell == nil {
		return
	}
	a.shell.close()
	a.log("info", "console: closed on "+a.shell.ip)
	a.shell = nil
}
