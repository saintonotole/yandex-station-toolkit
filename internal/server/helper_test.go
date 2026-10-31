package server

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"
)

func timeoutAfter(sec int) <-chan time.Time { return time.After(time.Duration(sec) * time.Second) }

// freePort picks an unused TCP port for a test listener.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// driveHelper runs RunHelper over pipes and returns every event it emitted.
// wantStates is how many {"event":"state"} lines to wait for before sending
// shutdown.
func driveHelper(t *testing.T, commands []string, wantStates int) []helperEvent {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()

	certPEM, keyPEM := genPair(t)
	cfg := HelperConfig{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		// Loopback: the helper's temp test binary must never trip the
		// Windows Firewall (fresh path every build = a fresh prompt).
		Addr: "127.0.0.1",
		MakeProvider: func(dir string, log func(string)) FirmwareProvider {
			return nil
		},
	}
	done := make(chan error, 1)
	go func() { done <- RunHelper(cfg, inR, outW) }()

	events := make(chan helperEvent, 128)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		sc := bufio.NewScanner(outR)
		for sc.Scan() {
			var e helperEvent
			if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
				continue
			}
			events <- e
		}
	}()

	for _, c := range commands {
		if _, err := inW.Write([]byte(c + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	var seen int
	var collected []helperEvent
	deadline := time.After(5 * time.Second)
	for seen < wantStates {
		select {
		case e := <-events:
			collected = append(collected, e)
			if e.Event == "state" {
				seen++
			}
		case <-deadline:
			t.Fatalf("helper sent fewer than %d state events in time", wantStates)
		}
	}

	inW.Write([]byte(`{"cmd":"shutdown"}` + "\n"))
	inW.Close()
	if err := <-done; err != nil {
		t.Fatalf("RunHelper: %v", err)
	}
	outW.Close()
	<-readDone
	all := collected
	for len(events) > 0 {
		all = append(all, <-events)
	}
	return all
}

// states filters the state transitions out of the events.
func states(events []helperEvent) []helperEvent {
	var out []helperEvent
	for _, e := range events {
		if e.Event == "state" {
			out = append(out, e)
		}
	}
	return out
}

func startCmd(t *testing.T, mode string) string {
	t.Helper()
	return `{"cmd":"start","mode":"` + mode + `","httpPort":` + itoa(freePort(t)) +
		`,"httpsPort":` + itoa(freePort(t)) + `,"dnsPort":` + itoa(freeUDPPort(t)) + `}`
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestHelperStartStopCycle(t *testing.T) {
	events := driveHelper(t, []string{
		startCmd(t, "override"),
		`{"cmd":"stop"}`,
	}, 2)
	st := states(events)
	if len(st) != 2 || !st[0].Running || st[0].Mode != "override" || st[1].Running {
		t.Fatalf("state transitions: %+v", st)
	}
}

func TestHelperSetMode(t *testing.T) {
	events := driveHelper(t, []string{
		startCmd(t, "passthrough"),
		`{"cmd":"setMode","mode":"override"}`,
		`{"cmd":"stop"}`,
	}, 3)
	st := states(events)
	if len(st) != 3 || st[0].Mode != "passthrough" || st[1].Mode != "override" || st[2].Running {
		t.Fatalf("state transitions: %+v", st)
	}
}

func TestHelperUnknownMode(t *testing.T) {
	events := driveHelper(t, []string{
		startCmd(t, "sideways"),
	}, 0)
	for _, e := range states(events) {
		if e.Running {
			t.Fatal("helper started with an unknown mode")
		}
	}
	var logged bool
	for _, e := range events {
		if e.Event == "log" && len(e.Msg) > 0 {
			logged = true
		}
	}
	if !logged {
		t.Fatal("unknown mode produced no log line")
	}
}

func TestHelperArgvUsesPkexec(t *testing.T) {
	argv := HelperArgv("/usr/bin/station-tool", []string{"--Server-helper"})
	if argv[0] != "pkexec" || argv[1] != "/usr/bin/station-tool" || argv[2] != "--Server-helper" {
		t.Fatalf("argv: %v", argv)
	}
}
