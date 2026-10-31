// Package dnssrv runs the local DNS server used for the station bootstrap.
//
// Passthrough mode is a plain forwarding resolver: the station onboards
// normally and the router's DNS can stay pointed at this machine. Override
// mode additionally answers the Yandex sync hosts with this machine's LAN
// IP, so the station's sync traffic reaches the local HTTPS endpoint.
package dnssrv

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type Mode int

const (
	Passthrough Mode = iota
	Override
)

func (m Mode) String() string {
	if m == Override {
		return "override"
	}
	return "passthrough"
}

// redirectNames mirrors dnsmasq's address= entries in lite-kit: these hosts
// (and their subdomains) resolve to this machine in override mode.
var redirectNames = []string{
	"quasar.yandex.net",
	"quasar.yandex.ru",
	"scbh.yandex.net",
}

// passSubdomains keep resolving to the real service even in override mode,
// like dnsmasq's server=/iot.../ entries.
var passSubdomains = map[string]bool{
	"iot.quasar.yandex.net": true,
	"iot.quasar.yandex.ru":  true,
}

const (
	defaultTTL    = 60 * time.Second
	questionStart = 12
	maxMessage    = 4096
)

type Config struct {
	// Upstreams are plain IPs on port 53, tried in order.
	Upstreams []string
	// Port is the listen port; 0 lets the OS pick one (tests). The app passes 53.
	Port int
	// Addr is the listen IP; empty means all interfaces (production).
	// Tests pass "127.0.0.1" so loopback binds stay invisible to the
	// Windows Firewall (no prompts, no rules for throwaway test binaries).
	Addr string
	// AnswerIP picks the LAN IP a redirected name resolves to. When nil the
	// server picks an IP in the querying client's subnet, else any non-loopback
	// local IP.
	AnswerIP func(clientIP net.IP) net.IP
	// Log receives one line per notable event; may be nil.
	Log func(msg string)
}

type Server struct {
	cfg Config

	mu   sync.Mutex
	mode Mode

	udp  *net.UDPConn
	tcp  net.Listener
	stop chan struct{}
}

func New(cfg Config) *Server {
	if len(cfg.Upstreams) == 0 {
		cfg.Upstreams = []string{"77.88.8.8", "1.1.1.1", "8.8.8.8"}
	}
	if cfg.AnswerIP == nil {
		cfg.AnswerIP = defaultAnswerIP
	}
	if cfg.Log == nil {
		cfg.Log = func(string) {}
	}
	return &Server{cfg: cfg}
}

func (s *Server) Mode() Mode {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mode
}

// SetMode switches modes on the fly; the listener stays up.
func (s *Server) SetMode(m Mode) {
	s.mu.Lock()
	old := s.mode
	s.mode = m
	s.mu.Unlock()
	if old != m {
		s.cfg.Log(fmt.Sprintf("dns server: mode %s -> %s", old, m))
	}
}

func (s *Server) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.udp != nil
}

// Start binds UDP and TCP (all interfaces, or cfg.Addr when set) and
// begins serving.
func (s *Server) Start(mode Mode) error {
	if s.Running() {
		return fmt.Errorf("dns: already running")
	}
	ip := net.ParseIP(s.cfg.Addr) // nil when empty: all interfaces
	addr := &net.UDPAddr{IP: ip, Port: s.cfg.Port}
	udp, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("dns: udp :%d: %w", s.cfg.Port, err)
	}
	tcp, err := net.ListenTCP("tcp", &net.TCPAddr{IP: ip, Port: s.cfg.Port})
	if err != nil {
		udp.Close()
		return fmt.Errorf("dns: tcp :%d: %w", s.cfg.Port, err)
	}

	s.mu.Lock()
	s.mode = mode
	s.udp = udp
	s.tcp = tcp
	s.stop = make(chan struct{})
	s.mu.Unlock()

	go s.serveUDP(udp)
	go s.serveTCP(tcp)
	s.cfg.Log(fmt.Sprintf("dns server: listening on :%d (%s)", s.cfg.Port, mode))
	return nil
}

func (s *Server) Stop() {
	s.mu.Lock()
	udp, tcp, stop := s.udp, s.tcp, s.stop
	s.udp, s.tcp, s.stop = nil, nil, nil
	s.mu.Unlock()
	if udp == nil {
		return
	}
	close(stop)
	udp.Close()
	tcp.Close()
}

func (s *Server) serveUDP(conn *net.UDPConn) {
	buf := make([]byte, maxMessage)
	for {
		n, client, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		query := append([]byte(nil), buf[:n]...)
		go func() {
			if reply := s.handle(client.IP, query); reply != nil {
				conn.WriteToUDP(reply, client)
			}
		}()
	}
}

func (s *Server) serveTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			for {
				query, err := readTCPMessage(c)
				if err != nil {
					return
				}
				// The reply goes through the same handler; the client IP is
				// only used to pick the answer IP, never to filter.
				reply := s.handle(remoteIP(c), query)
				if reply == nil {
					return
				}
				if err := writeTCPMessage(c, reply); err != nil {
					return
				}
			}
		}(c)
	}
}

func (s *Server) handle(clientIP net.IP, query []byte) []byte {
	_, flags, qEnd, name, qtype, ok := parseQuery(query)
	if !ok {
		return nil
	}
	if s.Mode() == Override && shouldRedirect(name, qtype) {
		var reply []byte
		answer := "NODATA"
		if qtype == 28 { // AAAA: NODATA, or the station bypasses us over IPv6
			reply = buildHeaderOnly(query[:qEnd], flags, 0)
		} else {
			ip := s.cfg.AnswerIP(clientIP)
			if ip == nil {
				reply = buildHeaderOnly(query[:qEnd], flags, 2) // SERVFAIL
				answer = "SERVFAIL"
			} else {
				reply = buildAReply(query[:qEnd], flags, ip)
				answer = ip.String()
			}
		}
		// The answered IP matters: it must be this machine in the
		// station's subnet, or the station never reaches the endpoints.
		s.cfg.Log(fmt.Sprintf("dns server: %s %s -> %s (override)", name, qtypeName(qtype), answer))
		return reply
	}
	reply := s.forward(query)
	if reply == nil {
		s.cfg.Log(fmt.Sprintf("dns server: %s: upstreams failed", name))
		return buildHeaderOnly(query[:qEnd], flags, 2)
	}
	return reply
}

func (s *Server) forward(query []byte) []byte {
	for _, up := range s.cfg.Upstreams {
		addr := up
		if !strings.ContainsRune(addr, ':') {
			addr = net.JoinHostPort(addr, "53")
		}
		c, err := net.DialTimeout("udp", addr, time.Second)
		if err != nil {
			continue
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2500 * time.Millisecond))
		if _, err := c.Write(query); err != nil {
			continue
		}
		buf := make([]byte, maxMessage)
		n, err := c.Read(buf)
		if err != nil || n < questionStart {
			continue
		}
		return append([]byte(nil), buf[:n]...)
	}
	return nil
}

// shouldRedirect reports whether override mode answers name locally. Subdomains
// of the sync hosts redirect too (dnsmasq address= semantics), except the
// exempted iot.* ones.
func shouldRedirect(name string, qtype uint16) bool {
	if qtype != 1 && qtype != 28 { // only A and AAAA are hijacked
		return false
	}
	if passSubdomains[name] {
		return false
	}
	for _, d := range redirectNames {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

func defaultAnswerIP(client net.IP) net.IP {
	type iface struct {
		addrs []net.Addr
	}
	var all []iface
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		all = append(all, iface{addrs: addrs})
	}

	var best net.IP
	bestBits := -1
	client4 := client.To4()
	for _, ifc := range all {
		for _, a := range ifc.addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP.To4()
			if ip == nil || ip.IsLoopback() {
				continue
			}
			bits := 0
			if client4 != nil && ipnet.Contains(client4) {
				bits = 32
			}
			if bits > bestBits {
				best, bestBits = ip, bits
			}
		}
	}
	if best == nil {
		// No subnet match; any routable local IPv4 is still better than none.
		for _, ifc := range all {
			for _, a := range ifc.addrs {
				if ipnet, ok := a.(*net.IPNet); ok {
					if ip := ipnet.IP.To4(); ip != nil && !ip.IsLoopback() {
						return ip
					}
				}
			}
		}
	}
	return best
}

func remoteIP(c net.Conn) net.IP {
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

// --- wire format ---

// parseQuery extracts the header and the single question. ok is false for
// malformed messages, which are silently dropped like dnsmasq does.
func parseQuery(q []byte) (id, flags uint16, questionEnd int, name string, qtype uint16, ok bool) {
	if len(q) < questionStart+5 {
		return 0, 0, 0, "", 0, false
	}
	id = uint16(q[0])<<8 | uint16(q[1])
	flags = uint16(q[2])<<8 | uint16(q[3])
	qdcount := uint16(q[4])<<8 | uint16(q[5])
	if qdcount != 1 {
		return 0, 0, 0, "", 0, false
	}
	i := questionStart
	var sb strings.Builder
	for {
		if i >= len(q) {
			return 0, 0, 0, "", 0, false
		}
		l := int(q[i])
		i++
		if l == 0 {
			break
		}
		if l&0xC0 != 0 || i+l > len(q) {
			return 0, 0, 0, "", 0, false
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(q[i : i+l])
		i += l
		if sb.Len() > 255 {
			return 0, 0, 0, "", 0, false
		}
	}
	if i+4 > len(q) {
		return 0, 0, 0, "", 0, false
	}
	qtype = uint16(q[i])<<8 | uint16(q[i+1])
	questionEnd = i + 4
	return id, flags, questionEnd, strings.ToLower(sb.String()), qtype, true
}

// buildHeaderOnly makes a reply with no answer records: NODATA with rcode 0,
// SERVFAIL with rcode 2.
func buildHeaderOnly(question []byte, qflags uint16, rcode uint16) []byte {
	id := uint16(question[0])<<8 | uint16(question[1])
	out := make([]byte, questionStart, questionStart+len(question)+16)
	out[0], out[1] = byte(id>>8), byte(id)
	// QR=1, RD copied, RA=1.
	setFlags := uint16(0x8000) | (qflags & 0x0100) | 0x0080 | (rcode & 0xF)
	out[2], out[3] = byte(setFlags>>8), byte(setFlags)
	out[5] = 1 // QDCOUNT
	return append(out, question[questionStart:]...)
}

func buildAReply(question []byte, qflags uint16, ip net.IP) []byte {
	out := buildHeaderOnly(question, qflags, 0)
	// ANCOUNT=1
	out[6], out[7] = 0, 1
	out = append(out, 0xC0, 0x0C) // NAME: pointer to the question
	out = append(out, 0, 1)       // TYPE: A
	out = append(out, 0, 1)       // CLASS: IN
	sec := uint32(defaultTTL.Seconds())
	out = append(out, byte(sec>>24), byte(sec>>16), byte(sec>>8), byte(sec))
	out = append(out, 0, 4) // RDLENGTH
	return append(out, ip.To4()...)
}

func qtypeName(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 28:
		return "AAAA"
	default:
		return fmt.Sprintf("type%d", t)
	}
}

// readTCPMessage reads one length-prefixed DNS message.
func readTCPMessage(c net.Conn) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := ioReadFull(c, lenBuf[:]); err != nil {
		return nil, err
	}
	n := int(lenBuf[0])<<8 | int(lenBuf[1])
	if n == 0 || n > 65535 {
		return nil, fmt.Errorf("bad tcp dns length %d", n)
	}
	msg := make([]byte, n)
	if _, err := ioReadFull(c, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func writeTCPMessage(c net.Conn, msg []byte) error {
	out := make([]byte, 0, len(msg)+2)
	out = append(out, byte(len(msg)>>8), byte(len(msg)))
	out = append(out, msg...)
	_, err := c.Write(out)
	return err
}

func ioReadFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
