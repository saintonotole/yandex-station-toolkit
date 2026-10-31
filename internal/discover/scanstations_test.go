package discover

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// TestScanStationsTwoPhase: a host enters the result only through the
// glagol+mDNS gate, and only survivors get their ADB/SSH probed.
func TestScanStationsTwoPhase(t *testing.T) {
	// .10 is a proper station (glagol + adb open); .11 is a random Android
	// box (adb open, no glagol — must be ignored entirely); .12 answers
	// nothing at all.
	open := map[string]map[int]bool{
		"192.168.1.10": {PortGlagol: true, PortADB: true},
		"192.168.1.11": {PortADB: true},
	}
	probes := map[string]int{}
	var probesMu sync.Mutex
	savedProbe := tcpProbe
	tcpProbe = func(host string, port int, timeout time.Duration) bool {
		probesMu.Lock()
		probes[host+":"+strconv.Itoa(port)]++
		probesMu.Unlock()
		return open[host] != nil && open[host][port]
	}
	defer func() { tcpProbe = savedProbe }()

	// The fake mDNS responder answers with a full station reply
	// (platform + deviceId TXT) for whoever asks.
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skip("no loopback udp:", err)
	}
	defer listener.Close()
	addr := listener.LocalAddr().(*net.UDPAddr)
	savedDial := mdnsDial
	mdnsDial = func(string) *net.UDPAddr { return addr }
	defer func() { mdnsDial = savedDial }()

	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := listener.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_ = n
			_, _ = listener.WriteToUDP(mdnsReply(net.IPv4(192, 168, 178, 63)), from)
		}
	}()

	nets := []*net.IPNet{
		{IP: net.IPv4(192, 168, 1, 0), Mask: net.CIDRMask(24, 32)},
	}
	devices := ScanStations(context.Background(), nets, nil)

	if len(devices) != 1 {
		t.Fatalf("expected exactly 1 station, got %d: %v", len(devices), devices)
	}
	d, ok := devices["192.168.1.10"]
	if !ok {
		t.Fatal("the glagol+mDNS host is missing from the result")
	}
	if !d.Ports[PortGlagol] || !d.Ports[PortADB] {
		t.Fatalf("station ports incomplete: %v", d.Ports)
	}
	if d.Platform != "yandexmicro" {
		t.Fatalf("platform = %q", d.Platform)
	}
	// The ignored box: its adb port was never probed in step 3.
	probesMu.Lock()
	defer probesMu.Unlock()
	if probes["192.168.1.11:"+strconv.Itoa(PortADB)] != 0 {
		t.Fatal("a non-station host must not be probed for adb/ssh")
	}
	// The station: glagol swept in step 1, adb/ssh probed in step 3.
	if probes["192.168.1.10:"+strconv.Itoa(PortGlagol)] == 0 ||
		probes["192.168.1.10:"+strconv.Itoa(PortADB)] == 0 {
		t.Fatalf("station probe pattern wrong: %v", probes)
	}
}
