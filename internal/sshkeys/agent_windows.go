package sshkeys

import (
	"net"
	"time"

	"github.com/Microsoft/go-winio"
)

const agentSocketPath = `\\.\pipe\openssh-ssh-agent`

// host is unused on Windows: per AGENTS.md, 1Password's SSH agent there
// owns the single well-known OpenSSH agent pipe directly, so there is no
// per-host IdentityAgent resolution needed the way there is on macOS/Linux.
func dialAgent(host string, timeout time.Duration) (net.Conn, error) {
	return winio.DialPipe(agentSocketPath, &timeout)
}
