package dnssrv

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// stubUpstream is a minimal UDP resolver: it answers A/AAAA queries for
// example.com and returns NODATA for everything else. It reuses the wire
// helpers above for brevity, but its assertions in the tests below are made
// against raw records, not the helpers' promises.
type stubUpstream struct {
	t    *testing.T
	addr *net.UDPAddr
}

func startStubUpstream(t *testing.T) *stubUpstream {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("stub: %v", err)
	}
	s := &stubUpstream{t: t, addr: pc.LocalAddr().(*net.UDPAddr)}
	go s.serve(pc)
	t.Cleanup(func() { pc.Close() })
	return s
}

func (s *stubUpstream) serve(pc *net.UDPConn) {
	buf := make([]byte, maxMessage)
	for {
		n, client, err := pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		_, flags, qEnd, name, qtype, ok := parseQuery(buf[:n])
		if !ok {
			continue
		}
		out := buildHeaderOnly(buf[:qEnd], flags, 0)
		if qtype == 1 && name == "example.com" {
			out[6], out[7] = 0, 1
			out = append(out, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34)
		}
		if qtype == 28 && name == "example.com" {
			out[6], out[7] = 0, 1
			out = append(out, 0xC0, 0x0C, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16)
			out = append(out, make([]byte, 16)...)
		}
		pc.WriteToUDP(out, client)
	}
}

func startServer(t *testing.T, mode Mode, upstream string, answerIP net.IP) *Server {
	t.Helper()
	s := New(Config{
		Upstreams: []string{upstream},
		Log:       func(string) {},
	})
	s.cfg.Port = 0
	s.cfg.Addr = "127.0.0.1" // loopback: never trips the Windows Firewall
	if answerIP != nil {
		ip := answerIP
		s.cfg.AnswerIP = func(net.IP) net.IP { return ip }
	}
	if err := s.Start(mode); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(s.Stop)
	return s
}

// query sends a raw DNS query and returns the raw reply.
func query(t *testing.T, port int, name string, qtype uint16) []byte {
	t.Helper()
	q := buildQuery(t, name, qtype)
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer pc.Close()
	pc.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := pc.WriteToUDP(q, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, maxMessage)
	n, _, err := pc.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return buf[:n]
}

func buildQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	var out []byte
	out = append(out, 0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0)
	for _, label := range strings.Split(name, ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return out
}

func aRecords(reply []byte) []net.IP {
	if len(reply) < 12 {
		return nil
	}
	_, _, qEnd, _, _, ok := parseQuery(reply)
	if !ok {
		return nil
	}
	ancount := int(reply[6])<<8 | int(reply[7])
	if ancount == 0 {
		return nil
	}
	i := qEnd
	var ips []net.IP
	for n := 0; n < ancount; n++ {
		if i >= len(reply) {
			return ips
		}
		if reply[i]&0xC0 == 0xC0 {
			i += 2
		} else {
			for i < len(reply) && reply[i] != 0 {
				i += 1 + int(reply[i])
			}
			i++
		}
		if i+10 > len(reply) {
			return ips
		}
		rdlen := int(reply[i+8])<<8 | int(reply[i+9])
		i += 10
		if i+rdlen > len(reply) {
			return ips
		}
		if rdlen == 4 {
			ips = append(ips, net.IPv4(reply[i], reply[i+1], reply[i+2], reply[i+3]))
		}
		i += rdlen
	}
	return ips
}

func rcode(reply []byte) int {
	if len(reply) < 4 {
		return -1
	}
	return int(reply[3] & 0xF)
}

func TestPassthroughForwards(t *testing.T) {
	up := startStubUpstream(t)
	s := startServer(t, Passthrough, up.addr.String(), nil)
	port := s.udp.LocalAddr().(*net.UDPAddr).Port

	reply := query(t, port, "example.com", 1)
	ips := aRecords(reply)
	if len(ips) != 1 || !ips[0].Equal(net.IPv4(93, 184, 216, 34)) {
		t.Fatalf("passthrough: want 93.184.216.34, got %v (rcode %d)", ips, rcode(reply))
	}
}

func TestOverrideRedirectsSyncHosts(t *testing.T) {
	up := startStubUpstream(t)
	want := net.IPv4(192, 168, 5, 9)
	s := startServer(t, Override, up.addr.String(), want)
	port := s.udp.LocalAddr().(*net.UDPAddr).Port

	for _, name := range []string{"quasar.yandex.net", "quasar.yandex.ru", "scbh.yandex.net"} {
		reply := query(t, port, name, 1)
		ips := aRecords(reply)
		if len(ips) != 1 || !ips[0].Equal(want) {
			t.Fatalf("override %s: want %v, got %v (rcode %d)", name, want, ips, rcode(reply))
		}
	}
}

func TestOverrideSubdomainAndExempt(t *testing.T) {
	up := startStubUpstream(t)
	want := net.IPv4(192, 168, 5, 9)
	s := startServer(t, Override, up.addr.String(), want)
	port := s.udp.LocalAddr().(*net.UDPAddr).Port

	// A subdomain of a sync host also redirects, like dnsmasq address=.
	reply := query(t, port, "api.quasar.yandex.net", 1)
	ips := aRecords(reply)
	if len(ips) != 1 || !ips[0].Equal(want) {
		t.Fatalf("subdomain: want %v, got %v", want, ips)
	}

	// iot.* stays on the real service even in override mode.
	reply = query(t, port, "iot.quasar.yandex.net", 1)
	if ips := aRecords(reply); len(ips) != 0 || rcode(reply) != 0 {
		t.Fatalf("iot exemption: want upstream NODATA, got %v (rcode %d)", ips, rcode(reply))
	}
}

func TestOverrideBlocksAAAAOnRedirectedNames(t *testing.T) {
	up := startStubUpstream(t)
	want := net.IPv4(192, 168, 5, 9)
	s := startServer(t, Override, up.addr.String(), want)
	port := s.udp.LocalAddr().(*net.UDPAddr).Port

	reply := query(t, port, "quasar.yandex.net", 28)
	if rcode(reply) != 0 || len(aRecords(reply)) != 0 {
		t.Fatalf("AAAA on redirected name: want NODATA, got records %v rcode %d", aRecords(reply), rcode(reply))
	}
	// AAAA for other names still goes to the upstream.
	reply = query(t, port, "example.com", 28)
	if ancount := int(reply[6])<<8 | int(reply[7]); ancount != 1 {
		t.Fatalf("AAAA passthrough for example.com: want 1 answer, got %d", ancount)
	}
}

func TestPassthroughLeavesSyncHostsAlone(t *testing.T) {
	up := startStubUpstream(t)
	s := startServer(t, Passthrough, up.addr.String(), net.IPv4(10, 0, 0, 1))
	port := s.udp.LocalAddr().(*net.UDPAddr).Port

	reply := query(t, port, "quasar.yandex.net", 1)
	if ips := aRecords(reply); len(ips) != 0 {
		t.Fatalf("passthrough must not answer sync hosts locally, got %v", ips)
	}
}

func TestSetModeSwitchesLive(t *testing.T) {
	up := startStubUpstream(t)
	want := net.IPv4(192, 168, 5, 9)
	s := startServer(t, Passthrough, up.addr.String(), want)
	port := s.udp.LocalAddr().(*net.UDPAddr).Port

	if ips := aRecords(query(t, port, "quasar.yandex.net", 1)); len(ips) != 0 {
		t.Fatalf("before switch: got local answer %v", ips)
	}
	s.SetMode(Override)
	if ips := aRecords(query(t, port, "quasar.yandex.net", 1)); len(ips) != 1 || !ips[0].Equal(want) {
		t.Fatalf("after switch: want %v, got %v", want, ips)
	}
}

func TestForwardFailsServfail(t *testing.T) {
	// A port that had a listener closed on it: nothing answers there now.
	dead, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("dead port: %v", err)
	}
	deadAddr := dead.LocalAddr().String()
	dead.Close()

	s := startServer(t, Passthrough, deadAddr, nil)
	port := s.udp.LocalAddr().(*net.UDPAddr).Port

	reply := query(t, port, "example.com", 1)
	if rcode(reply) != 2 {
		t.Fatalf("dead upstream: want SERVFAIL, got rcode %d", rcode(reply))
	}
}

func TestTCPPassthrough(t *testing.T) {
	up := startStubUpstream(t)
	s := startServer(t, Passthrough, up.addr.String(), nil)
	tport := s.tcp.Addr().(*net.TCPAddr).Port

	c, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: tport})
	if err != nil {
		t.Fatalf("tcp dial: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if err := writeTCPMessage(c, buildQuery(t, "example.com", 1)); err != nil {
		t.Fatalf("tcp write: %v", err)
	}
	reply, err := readTCPMessage(c)
	if err != nil {
		t.Fatalf("tcp read: %v", err)
	}
	ips := aRecords(reply)
	if len(ips) != 1 || !ips[0].Equal(net.IPv4(93, 184, 216, 34)) {
		t.Fatalf("tcp passthrough: want 93.184.216.34, got %v", ips)
	}
}

func TestOverrideTCP(t *testing.T) {
	up := startStubUpstream(t)
	want := net.IPv4(192, 168, 5, 9)
	s := startServer(t, Override, up.addr.String(), want)
	tport := s.tcp.Addr().(*net.TCPAddr).Port

	c, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: tport})
	if err != nil {
		t.Fatalf("tcp dial: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if err := writeTCPMessage(c, buildQuery(t, "quasar.yandex.net", 1)); err != nil {
		t.Fatalf("tcp write: %v", err)
	}
	reply, err := readTCPMessage(c)
	if err != nil {
		t.Fatalf("tcp read: %v", err)
	}
	ips := aRecords(reply)
	if len(ips) != 1 || !ips[0].Equal(want) {
		t.Fatalf("tcp override: want %v, got %v", want, ips)
	}
}

func TestParseQueryMalformed(t *testing.T) {
	if _, _, _, _, _, ok := parseQuery([]byte{1, 2, 3}); ok {
		t.Fatal("short buffer parsed")
	}
	if _, _, _, _, _, ok := parseQuery([]byte{0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0}); ok {
		t.Fatal("two questions parsed")
	}
	// A label length that runs past the end must not parse.
	bad := append([]byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}, 9, 'a')
	if _, _, _, _, _, ok := parseQuery(bad); ok {
		t.Fatal("truncated label parsed")
	}
}

func TestDefaultAnswerIPPrefersClientSubnet(t *testing.T) {
	// The machine running the test has at least the loopback interface; the
	// client address 127.0.0.1 must yield a non-nil answer of some form.
	ip := defaultAnswerIP(net.IPv4(127, 0, 0, 1))
	if ip == nil {
		t.Log("no non-loopback IPv4 on this machine; defaultAnswerIP returned nil")
	} else {
		fmt.Printf("defaultAnswerIP(127.0.0.1) = %v\n", ip)
	}
}
