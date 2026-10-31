// Package adb wraps the adb command line tool for network-only devices.
package adb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const Port = 5555

type Client struct {
	bin string
	own bool // only our downloaded copy may kill the adb server
	log func(msg string)
	mu  sync.Mutex
}

type lineWriter struct {
	w   io.Writer
	cb  func(string)
	buf []byte
}

func (lw *lineWriter) Write(p []byte) (int, error) {
	if lw.w != nil {
		_, _ = lw.w.Write(p)
	}
	lw.buf = append(lw.buf, p...)
	for {
		i := bytes.IndexAny(lw.buf, "\r\n")
		if i < 0 {
			break
		}
		line := strings.TrimRight(string(lw.buf[:i]), "\r \t")
		lw.buf = lw.buf[i+1:]
		if lw.cb != nil && line != "" {
			lw.cb(line)
		}
	}
	return len(p), nil
}

func (lw *lineWriter) flush() {
	if len(lw.buf) > 0 && lw.cb != nil {
		line := strings.TrimRight(string(lw.buf), "\r \t")
		if line != "" {
			lw.cb(line)
		}
	}
	lw.buf = nil
}

var ErrNotFound = errors.New("adb not found")

func Ensure(dir string, log func(string)) (*Client, error) {
	if log == nil {
		log = func(string) {}
	}
	if p := os.Getenv("STATION_TOOL_ADB"); p != "" {
		if _, err := exec.LookPath(p); err != nil {
			return nil, fmt.Errorf("STATION_TOOL_ADB=%q: %w", p, err)
		}
		log("adb: using " + p)
		return &Client{bin: p, log: log}, nil
	}
	if p, err := exec.LookPath("adb"); err == nil {
		log("adb: using PATH (" + p + ")")
		return &Client{bin: p, log: log}, nil
	}
	if p := localBinary(dir); fileExists(p) {
		log("adb: using downloaded copy (" + p + ")")
		return &Client{bin: p, own: true, log: log}, nil
	}
	return nil, ErrNotFound
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

func (c *Client) Version(ctx context.Context) (string, error) {
	out, err := c.Run(ctx, 15*time.Second, []string{"version"}, nil)
	if err != nil {
		return "", err
	}
	line := strings.SplitN(strings.TrimSpace(out), "\n", 2)[0]
	return line, nil
}

// VersionNumber pulls "1.0.41" out of "Android Debug Bridge version 1.0.41".
func VersionNumber(versionLine string) string {
	if i := strings.Index(versionLine, "version "); i >= 0 {
		return strings.TrimSpace(strings.Fields(versionLine[i+len("version "):])[0])
	}
	return ""
}

type quietKey struct{}

// Quiet marks ctx so Run keeps its commands out of the journal. It is meant
// for periodic read-only polls whose command list the caller logs once.
func Quiet(ctx context.Context) context.Context {
	return context.WithValue(ctx, quietKey{}, true)
}

func (c *Client) Run(ctx context.Context, timeout time.Duration, args []string, onLine func(string)) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, c.bin, args...)
	hideWindow(cmd)
	var out bytes.Buffer
	lw := &lineWriter{w: &out, cb: onLine}
	cmd.Stdout = lw
	cmd.Stderr = lw
	logOn := c.log != nil && ctx.Value(quietKey{}) == nil
	if logOn {
		c.log(auditCommand(args))
	}
	err := cmd.Run()
	lw.flush()
	if cctx.Err() == context.DeadlineExceeded {
		if logOn {
			c.log(fmt.Sprintf("adb: timeout\n%s\n%q", auditCommand(args), out.String()))
		}
		return out.String(), fmt.Errorf("adb %s: timeout", strings.Join(args, " "))
	}
	if err != nil && logOn {
		// "exit status N" alone is useless in the log.
		c.log(fmt.Sprintf("adb: %v\n%s\n%q", err, auditCommand(args), out.String()))
	}
	return out.String(), err
}

func serial(ip string) string { return ip + ":5555" }

// ConnectFast runs only `adb connect` — no `shell true` round-trip. The
// flaky small adbd on stations sometimes drops exactly that probe; callers
// that spawn their own shell (the console) want the fast path, where the
// spawned process is the liveness check.
func (c *Client) ConnectFast(ctx context.Context, ip string) error {
	out, err := c.Run(ctx, 15*time.Second, []string{"connect", serial(ip)}, nil)
	out = strings.TrimSpace(out)
	if err == nil && !strings.Contains(out, "connected to") && !strings.Contains(out, "already connected to") {
		err = fmt.Errorf("adb connect: %s", out)
	}
	return err
}

func (c *Client) Connect(ctx context.Context, ip string) error {
	if err := c.ConnectFast(ctx, ip); err != nil {
		return err
	}
	res, err := c.Shell(ctx, ip, "true")
	if err != nil || strings.TrimSpace(res) != "" {
		return fmt.Errorf("adb shell on %s did not answer: %v %q", ip, err, res)
	}
	return nil
}

func (c *Client) Disconnect(ctx context.Context, ip string) {
	_, _ = c.Run(ctx, 10*time.Second, []string{"disconnect", serial(ip)}, nil)
}

// Forward binds a PC-side TCP port to a loopback port on the device:
// `adb forward tcp:<local> tcp:<remotePort>`. The device-side endpoint
// only ever needs its own loopback (e.g. the quasar IPC on 127.0.0.1),
// so nothing new is exposed on the network.
func (c *Client) Forward(ctx context.Context, ip, local string, remotePort int) error {
	_, err := c.Run(Quiet(ctx), 10*time.Second, []string{"-s", serial(ip), "forward", "tcp:" + local, "tcp:" + strconv.Itoa(remotePort)}, nil)
	return err
}

// RemoveForward unbinds one PC-side forward set up by Forward.
func (c *Client) RemoveForward(ctx context.Context, ip, local string) {
	_, _ = c.Run(Quiet(ctx), 10*time.Second, []string{"-s", serial(ip), "forward", "--remove", "tcp:" + local}, nil)
}

func (c *Client) Shell(ctx context.Context, ip, script string) (string, error) {
	out, err := c.Run(ctx, 60*time.Second, []string{"-s", serial(ip), "shell", script}, nil)
	return clean(out), err
}

// Console starts a persistent interactive shell on the device, as the
// Консоль tab needs: keystrokes go to stdin, and out delivers the device's
// answer bytes (PTY output, control sequences included) until the session
// ends with an EOF. The session dies when ctx is canceled. The client's
// mutex is not held for the session lifetime, so one-off commands keep
// working while a console is open. ConnectFast is enough here: the shell
// process itself is the liveness probe, and the extra `shell true` probe
// is the flakiest single command on a station's adbd.
func (c *Client) Console(ctx context.Context, ip string) (io.WriteCloser, io.Reader, error) {
	if err := c.ConnectFast(ctx, ip); err != nil {
		return nil, nil, err
	}
	c.log("adb: console on " + serial(ip))
	cmd := exec.CommandContext(ctx, c.bin, "-s", serial(ip), "shell")
	hideWindow(cmd)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	go func() {
		_ = cmd.Wait()
		// The output copiers are done once Wait returns; closing the pipe
		// signals EOF to the reader.
		pw.CloseWithError(io.EOF)
	}()
	return &nudgedStdin{w: stdin}, pr, nil
}

// nudgedStdin works around the Windows adb client's stdin buffering: a
// write ENDING in \r or \n (xterm's Enter) is held inside the adb client
// until more input arrives — every console command needed a second Enter.
// A following backspace flushes it immediately and is a no-op for the
// device shell on an empty line, so it is appended to such writes.
type nudgedStdin struct {
	w io.WriteCloser
}

func (n *nudgedStdin) Write(p []byte) (int, error) {
	written, err := n.w.Write(p)
	if err == nil && len(p) > 0 && (p[len(p)-1] == '\r' || p[len(p)-1] == '\n') {
		_, _ = n.w.Write([]byte{'\b'})
	}
	return written, err
}

func (n *nudgedStdin) Close() error { return n.w.Close() }

func (c *Client) Push(ctx context.Context, ip, local, remote string) error {
	out, err := c.Run(ctx, 5*time.Minute, []string{"-s", serial(ip), "push", local, remote}, nil)
	out = clean(out)
	if err != nil {
		return fmt.Errorf("adb push %s: %v: %s", filepath.Base(local), err, out)
	}
	if !strings.Contains(out, "file pushed") {
		return fmt.Errorf("adb push %s: unexpected reply: %s", filepath.Base(local), out)
	}
	return nil
}

func (c *Client) KillServer() {
	if c == nil || !c.own {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = c.Run(ctx, 5*time.Second, []string{"kill-server"}, nil)
}

func clean(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

// auditCommand is the journal form of an adb invocation: the binary path is
// omitted, and a shell script is one statement per line.
func auditCommand(args []string) string {
	if len(args) >= 4 && args[0] == "-s" && args[2] == "shell" {
		var b strings.Builder
		b.WriteString("adb shell ")
		b.WriteString(args[1])
		for _, line := range scriptLines(args[3]) {
			b.WriteByte('\n')
			b.WriteString("  ")
			b.WriteString(line)
		}
		return b.String()
	}
	if len(args) >= 5 && args[0] == "-s" && args[2] == "push" {
		return fmt.Sprintf("adb push %s %s -> %s", args[1], filepath.Base(args[3]), args[4])
	}
	return "adb " + strings.Join(args, " ")
}

func scriptLines(script string) []string {
	script = strings.TrimSpace(strings.ReplaceAll(script, "\r\n", "\n"))
	var out []string
	for _, line := range strings.Split(script, "\n") {
		out = append(out, splitStatements(strings.TrimSpace(line))...)
	}
	return out
}

// splitStatements breaks a shell line on ';' that is outside quotes.
func splitStatements(line string) []string {
	if line == "" {
		return nil
	}
	var out []string
	var b strings.Builder
	quote := byte(0)
	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			b.WriteByte(c)
			if c == quote && (i == 0 || line[i-1] != '\\') {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			b.WriteByte(c)
			continue
		}
		if c == ';' {
			if s := strings.TrimSpace(b.String()); s != "" {
				out = append(out, s)
			}
			b.Reset()
			continue
		}
		b.WriteByte(c)
	}
	if s := strings.TrimSpace(b.String()); s != "" {
		out = append(out, s)
	}
	return out
}
