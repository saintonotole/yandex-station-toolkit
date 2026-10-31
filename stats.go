package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/saintonotole/yandex-station-toolkit/internal/adb"
	"github.com/saintonotole/yandex-station-toolkit/internal/provision"
	"github.com/saintonotole/yandex-station-toolkit/internal/sshkeys"
	"github.com/saintonotole/yandex-station-toolkit/internal/stats"
)

// statsConn is the cached channel of the overview poll. Unlike runnerFor
// it is passive: it never offers to download adb, and its commands stay out
// of the journal except for one summary when the channel opens.
type statsConn struct {
	ip     string
	via    string
	runner provision.Runner
	close  func()
}

func (a *App) onStats(m map[string]any) {
	ip := str(m, "ip")
	if ip == "" || !a.statsMu.TryLock() {
		return
	}
	// While a console session is open it owns the device: the 5-second
	// poll's shell bursts are what knock a small adbd offline and kill
	// the interactive session, so polling waits.
	if a.shellActive() {
		a.statsMu.Unlock()
		return
	}
	go func() {
		defer a.statsMu.Unlock()
		ctx, cancel := context.WithTimeout(adb.Quiet(context.Background()), 20*time.Second)
		defer cancel()
		conn, err := a.openStatsConn(ctx, ip)
		if err != nil {
			a.emit("stats", map[string]any{"ip": ip, "err": err.Error()})
			return
		}
		s, err := stats.Collect(func(cmd string) (string, error) { return conn.runner.Shell(ctx, cmd) })
		if err != nil {
			a.closeStatsConn()
			a.emit("stats", map[string]any{"ip": ip, "err": err.Error()})
			return
		}
		a.emit("stats", map[string]any{"ip": ip, "via": conn.via, "stats": s})
	}()
}

// openStatsConn must be called with statsMu held.
func (a *App) openStatsConn(ctx context.Context, ip string) (*statsConn, error) {
	if a.stats != nil && a.stats.ip == ip {
		return a.stats, nil
	}
	a.closeStatsConn()
	a.mu.Lock()
	d := a.devices[ip]
	a.mu.Unlock()
	if d == nil {
		return nil, errors.New("unknown device")
	}
	var conn *statsConn
	if d.HasADB() {
		if c := a.adbClient(); c != nil && c.Connect(ctx, ip) == nil {
			conn = &statsConn{ip: ip, via: "adb", runner: &deviceRunner{c: c, ip: ip}, close: func() {}}
		}
	}
	for _, port := range sshkeys.SSHPorts {
		if conn != nil || !d.Ports[port] {
			continue
		}
		client, err := sshkeys.TryNoneAuth(ip, port, "root", 6*time.Second)
		if err != nil && a.allowSSHAgent() {
			client, err = sshkeys.TryAgentAuth(ip, port, 6*time.Second)
		}
		if err == nil {
			r := &provision.SSHRunner{Client: client}
			conn = &statsConn{ip: ip, via: fmt.Sprintf("SSH %d", port), runner: r, close: func() { _ = r.Close() }}
		}
	}
	if conn == nil {
		return nil, errors.New("no usable ADB or SSH channel")
	}
	a.stats = conn
	a.log("info", fmt.Sprintf("%s: resource widgets poll over %s every 5 s, read-only:\n%s",
		ip, conn.via, "  "+strings.Join(stats.AllQueries, "\n  ")))
	return conn, nil
}

// closeStatsConn must be called with statsMu held.
func (a *App) closeStatsConn() {
	if a.stats != nil {
		a.stats.close()
		a.stats = nil
	}
}
