package sshkeys

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

func TestProbeSSHNoPorts(t *testing.T) {
	// The default SSHPorts (2222, 22) cannot be assumed closed on loopback:
	// dev machines run a local sshd. Probe freshly released ephemeral ports.
	saved := SSHPorts
	defer func() { SSHPorts = saved }()
	ports := make([]int, 0, 2)
	for range 2 {
		lst, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skip("no loopback tcp:", err)
		}
		ports = append(ports, lst.Addr().(*net.TCPAddr).Port)
		lst.Close()
	}
	SSHPorts = ports

	_, err := ProbeSSH("127.0.0.1", 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected error on closed ports")
	}
}

func TestProbeSSHAnswersFirst(t *testing.T) {
	// Binding 2222 may need privileges, so override SSHPorts instead.
	lst, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback tcp:", err)
	}
	defer lst.Close()
	port := lst.Addr().(*net.TCPAddr).Port

	go func() {
		c, err := lst.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("SSH-2.0-fake_dropbear_test\r\n"))
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := bufio.NewReader(c)
		_, _ = buf.ReadString('\n')
	}()

	saved := SSHPorts
	SSHPorts = []int{port}
	defer func() { SSHPorts = saved }()

	got, err := ProbeSSH("127.0.0.1", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got.Port != port {
		t.Fatalf("port: %d", got.Port)
	}
	if !strings.HasPrefix(got.Banner, "SSH-2.0-fake_dropbear_test") {
		t.Fatalf("banner: %q", got.Banner)
	}
}

func TestIdentLineDropsBinaryKEX(t *testing.T) {
	raw := []byte("SSH-2.0-dropbear_2026.94\r\n\x00\x00\x01\x94sntrup761x25519-sha512")
	got := identLine(raw)
	if got != "SSH-2.0-dropbear_2026.94" {
		t.Fatalf("banner: %q", got)
	}
}
