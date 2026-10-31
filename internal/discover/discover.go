// Package discover finds Yandex stations on the local network and identifies them.
package discover

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/saintonotole/yandex-station-toolkit/internal/adb"
)

const (
	PortADB      = 5555
	PortSSH      = 2222
	PortSSHStock = 22
	PortGlagol   = 1961
)

const MaxHosts = 65536

type Device struct {
	IP           string            `json:"ip"`
	Ports        map[int]bool      `json:"ports"`
	Model        string            `json:"model"`    // retail name"
	ModelRaw     string            `json:"modelRaw"` // device-tree model string
	Compat       string            `json:"compat"`   // first compatible entry, e.g. yandex,station-mini2
	Hostname     string            `json:"hostname"`
	Platform     string            `json:"platform"` // mDNS TXT platform=…
	DeviceID     string            `json:"deviceId"` // mDNS TXT deviceId=…
	MAC          string            `json:"mac"`
	Firmware     string            `json:"firmware"` // /system/vendor/quasar/version_full, else VERSION
	Root         bool              `json:"root"`
	RootKnown    bool              `json:"rootKnown"`
	Android      bool              `json:"android"`
	Identified   bool              `json:"identified"`
	IdentErr     string            `json:"identErr"`
	IsYandex     bool              `json:"isYandex"`
	YandexVia    string            `json:"yandexVia"` // "mdns" | "glagol" | "mdns+glagol" | ""
	IdentVia     string            `json:"identVia"`  // "adb" | "ssh" | "ssh-agent" | "mdns" | ""
	Nickname     string            `json:"nickname"`
	Color        string            `json:"color"`
	Colors       []string          `json:"colors"`   // case colors this model was sold in (from the APK)
	Icon         string            `json:"icon"`     // official generic icon
	Icons        map[string]string `json:"icons"`    // verified color -> APK icon filename
	SKU          string            `json:"sku"`      // YNDX-… from the station identify table
	YSEKnown     bool              `json:"yseKnown"` // shell was available to check yse
	YSEInstalled bool              `json:"yseInstalled"`
	ADBPending   bool              `json:"adbPending"` // ADB port is open, but the adb binary is unavailable
	SSHLocked    bool              `json:"sshLocked"`  // SSH port is open, but no working credentials were found
}

func (d *Device) HasADB() bool { return d.Ports[PortADB] }

func (d *Device) HasSSH() bool { return d.Ports[PortSSH] }

func (d *Device) HasStockSSH() bool { return d.Ports[PortSSHStock] }

func (d *Device) HasAnySSH() bool { return d.HasSSH() || d.HasStockSSH() }

func (d *Device) LooksYandex() bool { return d.Ports[PortGlagol] }

func (d *Device) MDNSYandex() bool {
	return d.Platform != "" || strings.HasPrefix(strings.ToLower(d.Hostname), "yandex")
}

// Networks are capped at /24 to keep scans fast.
func LocalNetworks() ([]*net.IPNet, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var nets []*net.IPNet
	seen := map[string]bool{}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipn.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
				continue
			}
			mask := net.CIDRMask(24, 32)
			if ones, _ := ipn.Mask.Size(); ones > 24 {
				mask = ipn.Mask
			}
			n := &net.IPNet{IP: ip4.Mask(mask), Mask: mask}
			key := n.String()
			if !seen[key] {
				seen[key] = true
				nets = append(nets, n)
			}
		}
	}
	return nets, nil
}

type Interface struct {
	Name         string   `json:"name"`
	HardwareAddr string   `json:"hardwareAddr"`
	Up           bool     `json:"up"`
	Virtual      bool     `json:"virtual"`
	CIDRs        []string `json:"cidrs"`
	Addrs        []string `json:"addrs"` // interface's own host addresses
	nets         []*net.IPNet
}

// There is no portable kernel flag for virtual adapters, so match by name.
func IsVirtualInterface(name string) bool {
	n := strings.ToLower(name)
	if strings.HasPrefix(n, "docker") || strings.HasPrefix(n, "br-") {
		return true
	}
	if strings.HasPrefix(n, "vethernet") || strings.HasPrefix(n, "veth") {
		return true
	}
	if strings.HasPrefix(n, "vboxnet") || strings.HasPrefix(n, "vmnet") {
		return true
	}
	if strings.HasPrefix(n, "virbr") {
		return true
	}
	if strings.HasPrefix(n, "tap") || strings.HasPrefix(n, "tun") || strings.HasPrefix(n, "utun") {
		return true
	}
	if strings.HasPrefix(n, "ppp") || strings.HasPrefix(n, "ipsec") || strings.HasPrefix(n, "wg") {
		return true
	}
	if strings.HasPrefix(n, "hns") || strings.HasPrefix(n, "ws-l") || strings.HasPrefix(n, "wsl") {
		return true
	}
	if strings.Contains(n, "hyper-v") || strings.Contains(n, "virtual") {
		return true
	}
	return false
}

func LocalInterfaces() ([]Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []Interface
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		var nets []*net.IPNet
		var cidrs []string
		var hostAddrs []string
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipn.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
				continue
			}
			mask := net.CIDRMask(24, 32)
			if ones, _ := ipn.Mask.Size(); ones > 24 {
				mask = ipn.Mask
			}
			n := &net.IPNet{IP: ip4.Mask(mask), Mask: mask}
			nets = append(nets, n)
			cidrs = append(cidrs, n.String())
			hostAddrs = append(hostAddrs, ip4.String())
		}
		if len(nets) == 0 {
			continue
		}
		out = append(out, Interface{
			Name:         ifc.Name,
			HardwareAddr: ifc.HardwareAddr.String(),
			Addrs:        hostAddrs,
			Up:           ifc.Flags&net.FlagUp != 0,
			Virtual:      IsVirtualInterface(ifc.Name),
			CIDRs:        cidrs,
			nets:         nets,
		})
	}
	return out, nil
}

// Empty names select all physical adapters.
func NetworksForInterfaces(names []string) []*net.IPNet {
	all, err := LocalInterfaces()
	if err != nil {
		return nil
	}
	want := map[string]bool{}
	for _, n := range names {
		want[strings.ToLower(strings.TrimSpace(n))] = true
	}
	physical := len(want) == 0
	var nets []*net.IPNet
	seen := map[string]bool{}
	for _, ifc := range all {
		if !want[strings.ToLower(ifc.Name)] && (!physical || ifc.Virtual) {
			continue
		}
		for _, n := range ifc.nets {
			key := n.String()
			if !seen[key] {
				seen[key] = true
				nets = append(nets, n)
			}
		}
	}
	return nets
}

// Ranges wider than /16 are capped at /16.
func ParseRanges(s string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == ';' }) {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if !strings.Contains(tok, "/") {
			tok += "/32"
		}
		_, n, err := net.ParseCIDR(tok)
		if err != nil {
			return nil, fmt.Errorf("range %q: %v", tok, err)
		}
		if n.IP.To4() == nil {
			return nil, fmt.Errorf("range %q: IPv4 only", tok)
		}
		if ones, _ := n.Mask.Size(); ones < 16 {
			n.Mask = net.CIDRMask(16, 32)
			n.IP = n.IP.Mask(n.Mask)
		}
		nets = append(nets, n)
	}
	return nets, nil
}

// PortOpen reports whether a TCP port answers within timeout.
func PortOpen(ip string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(port)), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func Hosts(n *net.IPNet, limit int) []string {
	ip4 := n.IP.To4()
	if ip4 == nil {
		return nil
	}
	ones, bits := n.Mask.Size()
	if bits != 32 {
		return nil
	}
	if ones >= 31 {
		return []string{n.IP.String()}
	}
	first := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
	last := first | (^uint32(0) >> uint(ones))
	var out []string
	for cur := first + 1; cur < last && len(out) < limit; cur++ {
		if cur&0xFF == 0 || cur&0xFF == 0xFF {
			continue // .0 / .255 inside wider ranges: keep scan lean
		}
		out = append(out, fmt.Sprintf("%d.%d.%d.%d", byte(cur>>24), byte(cur>>16), byte(cur>>8), byte(cur)))
	}
	return out
}

// tcpProbe dials a TCP port; the package var lets tests fake responders.
var tcpProbe = func(host string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(port)), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func scanHosts(nets []*net.IPNet) []string {
	set := map[string]bool{}
	var hosts []string
	for _, n := range nets {
		for _, h := range Hosts(n, MaxHosts) {
			if !set[h] {
				set[h] = true
				hosts = append(hosts, h)
			}
		}
	}
	sort.Strings(hosts)
	return hosts
}

func Scan(ctx context.Context, nets []*net.IPNet, ports []int, workers int, progress func(checked, total, found int)) map[string]*Device {
	hosts := scanHosts(nets)

	devices := map[string]*Device{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var checked int64
	sem := make(chan struct{}, workers)
	total := len(hosts) * len(ports)

	for _, h := range hosts {
		for _, p := range ports {
			select {
			case <-ctx.Done():
				wg.Wait()
				return devices
			case sem <- struct{}{}:
			}
			wg.Add(1)
			go func(host string, port int) {
				defer wg.Done()
				defer func() { <-sem }()
				if tcpProbe(host, port, 500*time.Millisecond) {
					mu.Lock()
					d := devices[host]
					if d == nil {
						d = &Device{IP: host, Ports: map[int]bool{}}
						devices[host] = d
					}
					d.Ports[port] = true
					mu.Unlock()
				}
				if c := atomic.AddInt64(&checked, 1); c%64 == 0 && progress != nil {
					mu.Lock()
					n := len(devices)
					mu.Unlock()
					progress(int(c), total, n)
				}
			}(h, p)
		}
	}
	wg.Wait()
	if progress != nil {
		progress(total, total, len(devices))
	}
	return devices
}

// ScanStations finds Yandex stations in nets in two steps:
//
//  1. every address is checked for the glagol port, and the survivors'
//     mDNS must carry the Yandex platform marker — that pair is what
//     makes a host a station;
//  2. ADB/SSH ports are probed on those hosts alone.
//
// Every other host on the network is neither queried further nor
// counted. The progress callback reports the glagol sweep (checked and
// total over the whole range) with the growing station count.
func ScanStations(ctx context.Context, nets []*net.IPNet, progress func(checked, total, found int)) map[string]*Device {
	hosts := scanHosts(nets)

	// Step 1: the glagol sweep. Glagol is Yandex's own control port —
	// a TV, a phone or a KVM box does not keep it open.
	var mu sync.Mutex
	var wg sync.WaitGroup
	var checked int64
	sem := make(chan struct{}, 256)
	var candidates []string
	total := len(hosts)
	for _, h := range hosts {
		select {
		case <-ctx.Done():
			wg.Wait()
			return map[string]*Device{}
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			if tcpProbe(host, PortGlagol, 500*time.Millisecond) {
				mu.Lock()
				candidates = append(candidates, host)
				mu.Unlock()
			}
			if c := atomic.AddInt64(&checked, 1); c%64 == 0 && progress != nil {
				mu.Lock()
				n := len(candidates)
				mu.Unlock()
				progress(int(c), total, n)
			}
		}(h)
	}
	wg.Wait()
	sort.Strings(candidates)

	// Step 2: the mDNS confirm. A correct Yandex response carries the
	// platform marker; anything else drops out here and is never
	// queried again.
	infos := ResolveMDNS(ctx, candidates, 1200*time.Millisecond, 64)
	devices := map[string]*Device{}
	for _, ip := range candidates {
		info, ok := infos[ip]
		if !ok || info.Platform == "" {
			continue
		}
		devices[ip] = &Device{
			IP:       ip,
			Ports:    map[int]bool{PortGlagol: true},
			Hostname: info.Hostname,
			Platform: info.Platform,
			DeviceID: info.DeviceID,
		}
	}
	if progress != nil {
		progress(total, total, len(devices))
	}

	// Step 3: ADB/SSH on the survivors only.
	for _, d := range SortedDevices(devices) {
		for _, port := range []int{PortADB, PortSSH, PortSSHStock} {
			if ctx.Err() != nil {
				break
			}
			if tcpProbe(d.IP, port, 500*time.Millisecond) {
				d.Ports[port] = true
			}
		}
	}
	return devices
}

// Collect reads identity from the device, one command at a time.
// A missing file is skipped. Collect fails only when every read fails.
func Collect(run func(cmd string) (string, error), d *Device) error {
	var transport error
	got := false
	read := func(cmd string) string {
		out, err := run(cmd)
		out = strings.TrimSpace(strings.Trim(out, "\x00"))
		if err != nil && out == "" && transport == nil {
			transport = err
		}
		if out != "" {
			got = true
		}
		return out
	}

	if model := read("cat /proc/device-tree/model"); model != "" {
		d.ModelRaw = model
	}
	if compat := read("cat /proc/device-tree/compatible"); compat != "" {
		compat = strings.ReplaceAll(compat, "\x00", "\n")
		if f := strings.Fields(compat); len(f) > 0 {
			d.Compat = f[0]
		}
	}
	if host := read("hostname"); host != "" {
		d.Hostname = host
	}
	if uid := read("id -u"); uid != "" {
		d.RootKnown = true
		d.Root = uid == "0"
	}
	if mac := read("cat /sys/class/net/wlan0/address"); mac != "" {
		d.MAC = strings.ToLower(mac)
	}
	if fw := read("cat /system/vendor/quasar/version_full"); fw != "" {
		d.Firmware = fw
	} else if fw := read("cat /system/vendor/quasar/VERSION"); fw != "" {
		d.Firmware = fw
	}
	propDevice := read("getprop ro.product.device")
	propModel := read("getprop ro.product.model")
	if g := strings.TrimSpace(propDevice + "\n" + propModel); g != "" {
		d.Android = true
		d.ModelRaw = g
	}

	if !got {
		if transport != nil {
			return transport
		}
		return fmt.Errorf("device did not answer identity commands")
	}
	if d.Model == "" {
		d.Model = ModelName(d.Compat, d.ModelRaw)
	}
	if d.Model == "" {
		d.Model = HostnameModel(d.Hostname)
	}
	d.Identified = true
	return nil
}

func Identify(ctx context.Context, c *adb.Client, d *Device, log func(string)) error {
	if err := c.Connect(ctx, d.IP); err != nil {
		d.IdentErr = err.Error()
		return err
	}
	err := Collect(func(cmd string) (string, error) {
		return c.Shell(ctx, d.IP, cmd)
	}, d)
	if err != nil {
		d.IdentErr = err.Error()
		return err
	}
	d.IdentVia = "adb"
	if log != nil {
		log(fmt.Sprintf("%s: %s (compat=%s fw=%s root=%v)", d.IP, d.Model, d.Compat, d.Firmware, d.Root))
	}
	return nil
}

func SortedDevices(m map[string]*Device) []*Device {
	out := make([]*Device, 0, len(m))
	for _, d := range m {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		return ipLess(out[i].IP, out[j].IP)
	})
	return out
}

func ipLess(a, b string) bool {
	ai, aok := parseIPv4(a)
	bi, bok := parseIPv4(b)
	if aok && bok {
		return ai < bi
	}
	return a < b
}

func parseIPv4(s string) (uint32, bool) {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0, false
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3]), true
}
