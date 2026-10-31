package discover

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

// Stations ignore multicast one-shot mDNS queries but answer unicast ones
// sent to <ip>:5353, and unicast replies pass the Windows stateful firewall
// without prompts. So each host is asked directly for its reverse PTR and
// the _yandexio._tcp service TXT record.

var (
	errTruncated = errors.New("dns: truncated message")
	errBadLabel  = errors.New("dns: bad name label")
	errNameLoop  = errors.New("dns: name pointer loop")
)

const svcYandexIO = "_yandexio._tcp.local."

// Tests replace mdnsDial to target a fake responder.
var mdnsDial = func(ip string) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP(ip), Port: 5353}
}

type MDNSInfo struct {
	Hostname string // without .local
	Platform string
	DeviceID string
}

func ResolveMDNS(ctx context.Context, ips []string, timeout time.Duration, workers int) map[string]MDNSInfo {
	res := map[string]MDNSInfo{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for _, ip := range ips {
		select {
		case <-ctx.Done():
			wg.Wait()
			return res
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			info, err := mdnsQuery(ip, timeout)
			if err == nil && (info.Hostname != "" || info.Platform != "") {
				mu.Lock()
				res[ip] = info
				mu.Unlock()
			}
		}(ip)
	}
	wg.Wait()
	return res
}

func mdnsQuery(ip string, timeout time.Duration) (MDNSInfo, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return MDNSInfo{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	dst := mdnsDial(ip)
	arpa := reverseARPA(ip)
	if arpa == "" {
		return MDNSInfo{}, errors.New("not an IP address")
	}
	if _, err := conn.WriteToUDP(buildQuery(arpa, 12), dst); err != nil {
		return MDNSInfo{}, err
	}
	if _, err := conn.WriteToUDP(buildQuery(svcYandexIO, 12), dst); err != nil {
		return MDNSInfo{}, err
	}

	var info MDNSInfo
	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			break // deadline
		}
		rrs, err := parseDNSMessage(buf[:n])
		if err != nil {
			continue
		}
		for _, rr := range rrs {
			switch rr.Type {
			case 12: // PTR
				if strings.EqualFold(rr.Owner, arpa) {
					if hn := stripLocalSuffix(rr.Data); hn != "" {
						info.Hostname = hn
					}
				}
			case 1: // A
				if rr.IP != nil && rr.IP.Equal(net.ParseIP(ip)) {
					if hn := stripLocalSuffix(rr.Owner); hn != "" && info.Hostname == "" {
						info.Hostname = hn
					}
				}
			case 16: // TXT: key=value strings
				for _, kv := range rr.TXT {
					k, v, ok := strings.Cut(kv, "=")
					if !ok {
						continue
					}
					switch strings.ToLower(k) {
					case "platform":
						info.Platform = v
					case "deviceid":
						info.DeviceID = v
					}
				}
			}
		}
		if info.Hostname != "" && info.Platform != "" {
			break
		}
	}
	return info, nil
}

func reverseARPA(ip string) string {
	octets := strings.Split(ip, ".")
	if len(octets) != 4 {
		return ""
	}
	var b strings.Builder
	for i := 3; i >= 0; i-- {
		b.WriteString(octets[i])
		b.WriteByte('.')
	}
	b.WriteString("in-addr.arpa.")
	return b.String()
}

func buildQuery(qname string, qtype uint16) []byte {
	b := make([]byte, 0, 64)
	b = binary.BigEndian.AppendUint16(b, 0) // id
	b = binary.BigEndian.AppendUint16(b, 0) // flags
	b = binary.BigEndian.AppendUint16(b, 1) // qdcount
	b = binary.BigEndian.AppendUint16(b, 0) // ancount
	b = binary.BigEndian.AppendUint16(b, 0) // nscount
	b = binary.BigEndian.AppendUint16(b, 0) // arcount
	for _, label := range strings.Split(strings.TrimSuffix(qname, "."), ".") {
		if len(label) == 0 || len(label) > 63 {
			continue
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, qtype)  // QTYPE
	b = binary.BigEndian.AppendUint16(b, 0x8001) // QCLASS = IN | unicast-response
	return b
}

type rr struct {
	Owner string
	Type  uint16 // 1 = A, 12 = PTR, 16 = TXT
	Data  string // PTR target
	IP    net.IP // A address
	TXT   []string
}

func parseDNSMessage(msg []byte) ([]rr, error) {
	if len(msg) < 12 {
		return nil, errTruncated
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	ns := int(binary.BigEndian.Uint16(msg[8:10]))
	ar := int(binary.BigEndian.Uint16(msg[10:12]))
	off := 12
	var err error

	for i := 0; i < qd; i++ {
		_, off, err = readName(msg, off)
		if err != nil {
			return nil, err
		}
		off += 4 // qtype + qclass
	}

	var out []rr
	for i := 0; i < an+ns+ar; i++ {
		var owner string
		owner, off, err = readName(msg, off)
		if err != nil {
			return out, err
		}
		if off+10 > len(msg) {
			return out, errTruncated
		}
		typ := binary.BigEndian.Uint16(msg[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdlen > len(msg) {
			return out, errTruncated
		}
		r := rr{Owner: owner, Type: typ}
		switch typ {
		case 12: // PTR
			if data, _, err2 := readName(msg, off); err2 == nil {
				r.Data = data
			}
		case 1: // A
			if rdlen == 4 {
				r.IP = append(net.IP(nil), msg[off:off+4]...)
			}
		case 16: // TXT: length-prefixed strings
			p := off
			end := off + rdlen
			for p < end {
				l := int(msg[p])
				p++
				if p+l > end {
					break
				}
				if l > 0 {
					r.TXT = append(r.TXT, string(msg[p:p+l]))
				}
				p += l
			}
		}
		out = append(out, r)
		off += rdlen
	}
	return out, nil
}

// readName returns the offset just past the name in its original
// location, not past a compression pointer target.
func readName(msg []byte, off int) (string, int, error) {
	var sb strings.Builder
	jumped := false
	next := off
	ptrs := 0
	for {
		if off >= len(msg) {
			return "", 0, errTruncated
		}
		l := int(msg[off])
		if l == 0 {
			off++
			if !jumped {
				next = off
			}
			if sb.Len() == 0 {
				return "", next, nil
			}
			return sb.String() + ".", next, nil
		}
		switch l & 0xC0 {
		case 0xC0: // pointer
			if off+1 >= len(msg) {
				return "", 0, errTruncated
			}
			ptr := int(l&0x3F)<<8 | int(msg[off+1])
			if !jumped {
				next = off + 2
			}
			jumped = true
			ptrs++
			if ptrs > 16 {
				return "", 0, errNameLoop
			}
			off = ptr
		case 0x00: // label
			if off+1+l > len(msg) {
				return "", 0, errTruncated
			}
			if sb.Len() > 0 {
				sb.WriteByte('.')
			}
			sb.Write(msg[off+1 : off+1+l])
			off += 1 + l
		default:
			return "", 0, errBadLabel
		}
	}
}

func stripLocalSuffix(name string) string {
	name = strings.TrimSuffix(name, ".")
	if strings.HasSuffix(strings.ToLower(name), ".local") {
		return name[:len(name)-len(".local")]
	}
	return name
}
