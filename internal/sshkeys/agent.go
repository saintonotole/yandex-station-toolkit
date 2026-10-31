package sshkeys

import (
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var errNoAgent = errors.New("ssh-agent is not configured")

// agentSigners keeps the agent connection open on success: the signers
// sign through it. host picks the agent socket the same way the real ssh
// client would for that host (see dialAgent).
func agentSigners(host string) []ssh.Signer {
	conn, err := dialAgent(host, 500*time.Millisecond)
	if err != nil {
		return nil
	}
	signers, err := agent.NewClient(conn).Signers()
	if err != nil || len(signers) == 0 {
		conn.Close()
		return nil
	}
	return signers
}

func TryAgentAuth(ip string, port int, timeout time.Duration) (*ssh.Client, error) {
	signers := agentSigners(ip)
	if len(signers) == 0 {
		return nil, errors.New("ssh-agent is not running or has no keys")
	}
	var lastErr error
	for _, s := range signers {
		cfg := &ssh.ClientConfig{
			User:            "root",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(s)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         timeout,
		}
		client, err := ssh.Dial("tcp", net.JoinHostPort(ip, fmt.Sprint(port)), cfg)
		if err == nil {
			return client, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func AgentAvailable(host string) bool {
	conn, err := dialAgent(host, 300*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
