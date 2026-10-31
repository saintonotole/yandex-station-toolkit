package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// upstreamResolvers are queried directly over UDP, bypassing the system
// resolver: during a bootstrap the system resolver may be this machine's own
// hijacking DNS server.
var upstreamResolvers = []string{"77.88.8.8", "1.1.1.1", "8.8.8.8"}

// fallbackQuasarIP is the last resort for the sync hosts, as in lite-kit.
const fallbackQuasarIP = "213.180.193.230"

// resolveTimeout bounds one resolver attempt.
const resolveTimeout = 5 * time.Second

type resolver struct {
	// useDoH tries the dns.google JSON API before plain UDP.
	useDoH bool
	// resolvers are plain IPs on port 53.
	resolvers []string
	log       func(string)

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	ip  net.IP
	exp time.Time
}

func newResolver(useDoH bool, log func(string)) *resolver {
	return &resolver{
		useDoH:    useDoH,
		resolvers: upstreamResolvers,
		log:       log,
		cache:     map[string]cacheEntry{},
	}
}

// resolve returns the real public IP for host, never one of this machine's
// own addresses (the hijack must not proxy to itself).
func (r *resolver) resolve(host string) (net.IP, error) {
	host = strings.ToLower(host)
	r.mu.Lock()
	if e, ok := r.cache[host]; ok && time.Now().Before(e.exp) {
		r.mu.Unlock()
		return e.ip, nil
	}
	r.mu.Unlock()

	mine := localIPSet()
	try := func(ip net.IP) bool {
		if ip == nil || ip.IsLoopback() {
			return false
		}
		_, own := mine[ip.String()]
		return !own
	}

	if r.useDoH {
		if ip, ok := r.doh(host); ok && try(ip) {
			r.remember(host, ip)
			return ip, nil
		}
	}
	for _, res := range r.resolvers {
		for _, ip := range directQuery(res, host) {
			if try(ip) {
				r.remember(host, ip)
				return ip, nil
			}
		}
	}
	// Only the sync hosts have a known fallback; anything else is an error.
	if strings.HasSuffix(host, "yandex.net") || strings.HasSuffix(host, "yandex.ru") {
		ip := net.ParseIP(fallbackQuasarIP)
		r.remember(host, ip)
		return ip, nil
	}
	return nil, fmt.Errorf("Server: cannot resolve upstream %s", host)
}

func (r *resolver) remember(host string, ip net.IP) {
	r.mu.Lock()
	r.cache[host] = cacheEntry{ip: ip, exp: time.Now().Add(5 * time.Minute)}
	r.mu.Unlock()
}

func (r *resolver) doh(host string) (net.IP, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	defer cancel()
	url := "https://dns.google/resolve?name=" + host + "&type=A"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	var out struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, false
	}
	for _, a := range out.Answer {
		if a.Type == 1 {
			if ip := net.ParseIP(a.Data); ip != nil {
				return ip, true
			}
		}
	}
	return nil, false
}

// directQuery sends one A query to a plain DNS resolver and parses the answers.
func directQuery(resolverIP, name string) []net.IP {
	q := buildAQuery(name)
	conn, err := net.DialTimeout("udp", net.JoinHostPort(resolverIP, "53"), resolveTimeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(resolveTimeout))
	if _, err := conn.Write(q); err != nil {
		return nil
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return nil
	}
	return parseAAnswers(buf[:n])
}

func buildAQuery(name string) []byte {
	var out []byte
	out = append(out, 0x77, 0x66, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0)
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0, 0, 1, 0, 1) // root label, TYPE=A, CLASS=IN
	return out
}

// parseAAnswers walks a DNS reply and returns every A record. Malformed
// input yields whatever could be read before the problem.
func parseAAnswers(msg []byte) []net.IP {
	if len(msg) < 12 {
		return nil
	}
	qdcount := int(msg[4])<<8 | int(msg[5])
	ancount := int(msg[6])<<8 | int(msg[7])
	i := 12
	for q := 0; q < qdcount && i < len(msg); q++ {
		for {
			if i >= len(msg) {
				return nil
			}
			l := msg[i]
			if l == 0 {
				i++
				break
			}
			if l&0xC0 == 0xC0 {
				i += 2
				break
			}
			i += 1 + int(l)
			if i > len(msg) {
				return nil
			}
		}
		i += 4 // QTYPE + QCLASS
	}
	var ips []net.IP
	for a := 0; a < ancount && i < len(msg); a++ {
		for {
			if i >= len(msg) {
				return ips
			}
			l := msg[i]
			if l == 0 {
				i++
				break
			}
			if l&0xC0 == 0xC0 {
				i += 2
				break
			}
			i += 1 + int(l)
			if i > len(msg) {
				return ips
			}
		}
		if i+10 > len(msg) {
			break
		}
		rdlen := int(msg[i+8])<<8 | int(msg[i+9])
		i += 10
		if i+rdlen > len(msg) {
			break
		}
		if rdlen == 4 {
			ips = append(ips, net.IPv4(msg[i], msg[i+1], msg[i+2], msg[i+3]))
		}
		i += rdlen
	}
	return ips
}

// localIPSet is every IPv4/IPv6 address of this machine.
func localIPSet() map[string]struct{} {
	out := map[string]struct{}{}
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifs {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil {
				out[ip.String()] = struct{}{}
			}
		}
	}
	return out
}
