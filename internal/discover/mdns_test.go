package discover

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

func TestReverseARPA(t *testing.T) {
	if got := reverseARPA("192.168.1.5"); got != "5.1.168.192.in-addr.arpa." {
		t.Fatalf("got %q", got)
	}
	if got := reverseARPA("10.0.0.1"); got != "1.0.0.10.in-addr.arpa." {
		t.Fatalf("got %q", got)
	}
	if got := reverseARPA("bogus"); got != "" {
		t.Fatalf("non-ip: %q", got)
	}
}

func TestStripLocalSuffix(t *testing.T) {
	cases := map[string]string{
		"yandexmicro-LG00000.local.": "yandexmicro-LG00000",
		"yandexmini-xyz.LOCAL":       "yandexmini-xyz",
		"plain-name.":                "plain-name",
		"":                           "",
	}
	for in, want := range cases {
		if got := stripLocalSuffix(in); got != want {
			t.Errorf("stripLocalSuffix(%q)=%q want %q", in, got, want)
		}
	}
}

func TestBuildQuery(t *testing.T) {
	q := buildQuery("5.1.168.192.in-addr.arpa.", 12)
	if binary.BigEndian.Uint16(q[4:6]) != 1 {
		t.Fatal("qdcount != 1")
	}
	if got := binary.BigEndian.Uint16(q[len(q)-4:]); got != 12 {
		t.Fatalf("qtype=%d", got)
	}
	if got := binary.BigEndian.Uint16(q[len(q)-2:]); got != 0x8001 {
		t.Fatalf("qclass=%#x", got)
	}
	if !strings.Contains(string(q), "in-addr") {
		t.Fatal("qname missing")
	}
}

func putName(b []byte, name string) []byte {
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

// mdnsReply mirrors a real station reply: reverse PTR, service PTR, TXT and A.
func mdnsReply(ip net.IP) []byte {
	// header: id 0, flags 0x8400, qd 0, an 3, ns 0, ar 1
	b := []byte{0, 0, 0x84, 0, 0, 0, 0, 3, 0, 0, 0, 1}
	arpa := "63.178.168.192.in-addr.arpa."
	host := "yandexmicro-LG00000000000069405300008cbd5526.local."
	svc := "_yandexio._tcp.local."
	instance := "YandexIOReceiver-LG00000000000069405300008cbd5526." + svc

	// RR1: PTR arpa -> host
	b = putName(b, arpa)
	b = binary.BigEndian.AppendUint16(b, 12)
	b = binary.BigEndian.AppendUint16(b, 1)
	b = binary.BigEndian.AppendUint32(b, 120)
	b = binary.BigEndian.AppendUint16(b, uint16(len(host)+1))
	b = putName(b, host)

	// RR2: PTR svc -> instance
	b = putName(b, svc)
	b = binary.BigEndian.AppendUint16(b, 12)
	b = binary.BigEndian.AppendUint16(b, 1)
	b = binary.BigEndian.AppendUint32(b, 4500)
	b = binary.BigEndian.AppendUint16(b, uint16(len(instance)+1))
	b = putName(b, instance)

	// RR3 (additional): TXT instance
	txt := "deviceId=LG00000000000069405300008cbd5526\x00platform=yandexmicro\x00cluster=yes"
	rd := []byte{}
	for _, s := range strings.Split(txt, "\x00") {
		rd = append(rd, byte(len(s)))
		rd = append(rd, s...)
	}
	b = putName(b, instance)
	b = binary.BigEndian.AppendUint16(b, 16)
	b = binary.BigEndian.AppendUint16(b, 1)
	b = binary.BigEndian.AppendUint32(b, 4500)
	b = binary.BigEndian.AppendUint16(b, uint16(len(rd)))
	b = append(b, rd...)

	// RR4 (additional): A host -> ip
	b = putName(b, host)
	b = binary.BigEndian.AppendUint16(b, 1)
	b = binary.BigEndian.AppendUint16(b, 1)
	b = binary.BigEndian.AppendUint32(b, 120)
	b = binary.BigEndian.AppendUint16(b, 4)
	b = append(b, ip.To4()...)
	return b
}

func TestParseDNSMessage(t *testing.T) {
	ip := net.IPv4(192, 168, 178, 63)
	msg := mdnsReply(ip)

	rrs, err := parseDNSMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(rrs) != 4 {
		t.Fatalf("rrs=%d: %+v", len(rrs), rrs)
	}

	ptr := rrs[0]
	if ptr.Type != 12 || ptr.Data != "yandexmicro-LG00000000000069405300008cbd5526.local." {
		t.Fatalf("PTR: %+v", ptr)
	}
	if ptr.Owner != "63.178.168.192.in-addr.arpa." {
		t.Fatalf("PTR owner: %q", ptr.Owner)
	}
	svcPtr := rrs[1]
	if svcPtr.Type != 12 || !strings.HasSuffix(svcPtr.Data, "_yandexio._tcp.local.") {
		t.Fatalf("svc PTR: %+v", svcPtr)
	}
	txt := rrs[2]
	if txt.Type != 16 || len(txt.TXT) != 3 ||
		txt.TXT[0] != "deviceId=LG00000000000069405300008cbd5526" ||
		txt.TXT[1] != "platform=yandexmicro" {
		t.Fatalf("TXT: %+v", txt)
	}
	a := rrs[3]
	if a.Type != 1 || !a.IP.Equal(ip) {
		t.Fatalf("A: %+v", a)
	}
}

func TestParseDNSMessageTruncated(t *testing.T) {
	if _, err := parseDNSMessage([]byte{0, 0, 0x84, 0}); err == nil {
		t.Fatal("truncated must fail")
	}
}

func TestHostnameModel(t *testing.T) {
	cases := map[string]string{
		"yandexmicro-a1b2c3":    "",             // ambiguous family (Лайт or Мини)
		"yandex-station-midi-x": "Станция Миди", // real hostname (quasar rootfs)
		"yandexmango-xyz":       "Станция Стрит",
		"yandexsaturn-xyz":      "Умный хаб",
		"some-pc":               "",
		"yandex-something-else": "",
	}
	for in, want := range cases {
		if got := HostnameModel(in); got != want {
			t.Errorf("HostnameModel(%q)=%q want %q", in, got, want)
		}
	}
}

func TestResolveMDNSViaFakeResponder(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skip("no loopback udp:", err)
	}
	defer server.Close()
	addr := server.LocalAddr().(*net.UDPAddr)
	savedDial := mdnsDial
	mdnsDial = func(string) *net.UDPAddr { return addr }
	defer func() { mdnsDial = savedDial }()

	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := server.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// Answer only the reverse PTR question.
			if strings.Contains(string(buf[:n]), "in-addr") {
				resp := mdnsReply(net.IPv4(192, 168, 178, 63))
				_, _ = server.WriteToUDP(resp, from)
			}
		}
	}()

	got := ResolveMDNS(t.Context(), []string{"192.168.178.63"}, 2*time.Second, 2)
	info, ok := got["192.168.178.63"]
	if !ok {
		t.Fatalf("no info: %+v", got)
	}
	if info.Hostname != "yandexmicro-LG00000000000069405300008cbd5526" {
		t.Fatalf("hostname: %q", info.Hostname)
	}
	if info.Platform != "yandexmicro" {
		t.Fatalf("platform: %q", info.Platform)
	}
	if info.DeviceID != "LG00000000000069405300008cbd5526" {
		t.Fatalf("deviceId: %q", info.DeviceID)
	}
}
