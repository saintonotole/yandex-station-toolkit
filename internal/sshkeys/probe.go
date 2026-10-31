package sshkeys

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

var SSHPorts = []int{SSHPort, 22}

type ProbeResult struct {
	Port   int
	Banner string
}

func ProbeSSH(ip string, timeout time.Duration) (ProbeResult, error) {
	var lastErr error
	for _, port := range SSHPorts {
		banner, err := Banner(ip, port, timeout)
		if err == nil {
			return ProbeResult{Port: port, Banner: banner}, nil
		}
		lastErr = err
	}
	return ProbeResult{}, fmt.Errorf("neither 2222 nor 22 answered: %v", lastErr)
}

// TryNoneAuth makes a single empty-password attempt: stock images with an
// open root login are the only ones identifiable over SSH without a key.
func TryNoneAuth(ip string, port int, user string, timeout time.Duration) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password("")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}
	return ssh.Dial("tcp", net.JoinHostPort(ip, fmt.Sprint(port)), cfg)
}

func RunProbeScript(client *ssh.Client, script string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("session: %v", err)
	}
	defer sess.Close()
	out, err := sess.Output(script)
	if err != nil {
		return "", fmt.Errorf("command: %v", err)
	}
	return string(out), nil
}
