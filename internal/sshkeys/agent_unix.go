//go:build !windows

package sshkeys

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// dialAgent connects to the SSH agent socket that the real ssh(1) client
// would use for host. On macOS and Linux, ssh_config(5)'s IdentityAgent
// directive — the mechanism 1Password's SSH agent documents for
// integration (https://developer.1password.com/docs/ssh/agent/) — can
// point at a different socket than the SSH_AUTH_SOCK environment variable,
// and a GUI app launched outside a login shell may not even have
// SSH_AUTH_SOCK exported to the socket a shell-configured agent uses.
// Resolving IdentityAgent through ssh -G first matches what `ssh` itself
// would connect to for that host; SSH_AUTH_SOCK remains the fallback.
func dialAgent(host string, timeout time.Duration) (net.Conn, error) {
	if sock := identityAgentSocket(host, timeout); sock != "" {
		if conn, err := net.DialTimeout("unix", sock, timeout); err == nil {
			return conn, nil
		}
	}
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, errNoAgent
	}
	return net.DialTimeout("unix", sock, timeout)
}

// identityAgentSocket asks ssh(1) to print its fully resolved ssh_config(5)
// for host — per ssh(1)'s -G flag, "print the configuration ... and exit"
// — and returns the IdentityAgent path, if any Host/Match block sets one.
func identityAgentSocket(host string, timeout time.Duration) string {
	if host == "" {
		host = "localhost"
	}
	path, err := exec.LookPath("ssh")
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout+time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "-G", host).Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		fields := strings.SplitN(line, " ", 2)
		if len(fields) != 2 || !strings.EqualFold(fields[0], "identityagent") {
			continue
		}
		val := strings.Trim(fields[1], `"`)
		switch val {
		case "", "none", "SSH_AUTH_SOCK":
			return ""
		}
		if strings.HasPrefix(val, "~/") {
			if home, err := os.UserHomeDir(); err == nil {
				val = filepath.Join(home, val[2:])
			}
		}
		return val
	}
	return ""
}
