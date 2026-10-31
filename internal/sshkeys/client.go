package sshkeys

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const SSHPort = 2222

func Banner(ip string, port int, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return "", fmt.Errorf("port %d is closed: %v", port, err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("port %d is open, but the SSH banner was not read: %v", port, err)
	}
	// The identification string is one ASCII line. Dropbear may already
	// have the binary KEXINIT queued behind it; never log those bytes.
	banner := identLine(buf[:n])
	if !strings.HasPrefix(banner, "SSH-") {
		return "", fmt.Errorf("port %d is open, but it is not SSH", port)
	}
	return banner, nil
}

func identLine(buf []byte) string {
	if i := bytes.IndexAny(buf, "\r\n"); i >= 0 {
		buf = buf[:i]
	}
	end := 0
	for end < len(buf) && buf[end] >= 32 && buf[end] <= 126 {
		end++
	}
	return strings.TrimSpace(string(buf[:end]))
}

func TestAuth(ip string, port int, user string, signer ssh.Signer, timeout time.Duration) (string, error) {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // LAN appliance, key unknown by design
		Timeout:         timeout,
	}
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", ip, port), cfg)
	if err != nil {
		return "", fmt.Errorf("connect: %v", err)
	}
	defer client.Close()
	if err := echoCheck(client); err != nil {
		return "", err
	}
	return fmt.Sprintf("login ok as %s@%s:%d, server: %s", user, ip, port, client.ServerVersion()), nil
}

// Connect establishes a live SSH session with one auth method and
// verifies it answers — the caller owns the returned client.
func Connect(ip string, port int, user string, auth ssh.AuthMethod, timeout time.Duration) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // LAN appliance, key unknown by design
		Timeout:         timeout,
	}
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", ip, port), cfg)
	if err != nil {
		return nil, fmt.Errorf("connect: %v", err)
	}
	if err := echoCheck(client); err != nil {
		client.Close()
		return nil, err
	}
	return client, nil
}

func ConfirmSession(client *ssh.Client) (string, error) {
	if err := echoCheck(client); err != nil {
		return "", err
	}
	return fmt.Sprintf("login ok, server: %s", client.ServerVersion()), nil
}

func echoCheck(client *ssh.Client) error {
	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("session: %v", err)
	}
	defer sess.Close()
	out, err := sess.Output("echo STATION_TOOL_OK")
	if err != nil {
		return fmt.Errorf("command: %v", err)
	}
	if strings.TrimSpace(string(out)) != "STATION_TOOL_OK" {
		return fmt.Errorf("unexpected reply: %q", out)
	}
	return nil
}
