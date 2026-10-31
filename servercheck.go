package main

// servercheck.go — pre-flight checks for the DNS-spoofing endpoints: are
// ports 53/80/443 bindable, and (on Windows) does anything let inbound
// traffic through to this executable? Busy ports disable the start
// button and name the holder. The firewall model is Windows' own: the
// app never elevates and never manages firewall rules. For TCP
// listeners Windows raises its native allow/deny dialog AT BIND time
// when nothing allows the app yet (verified live: a fresh exe binding
// an uncovered TCP port gets the prompt with zero traffic), so an
// uncovered Server shows the dialog the moment it starts. A port that
// is already covered — by a rule naming this exe, or on this owner's
// machine by the leftover lite-kit any-program TCP rule on 53/80/443 —
// binds silently and works; the pre-flight names the covering rule so
// the journal explains why no prompt is coming. Declining the dialog
// makes a Block rule, which the scan reports; start then refuses.

import (
	"fmt"
	"net"
	"time"
)

type portCheck struct {
	Port   int    `json:"port"`
	Proto  string `json:"proto"`            // "udp" | "tcp"
	Free   bool   `json:"free"`             // bindable right now
	Holder string `json:"holder,omitempty"` // occupier as name.exe (pid N)
}

type fwState struct {
	Needed  bool   `json:"needed"`            // Windows will show its allow/deny dialog
	Reason  string `json:"reason,omitempty"`  // what the scan found (empty = no app firewall on this OS)
	Blocked bool   `json:"blocked,omitempty"` // a previous «Отмена» denies inbound; start would be dead
}

// serverCheck is the page state the frontend renders from.
type serverCheck struct {
	Running bool        `json:"running"`
	Ports   []portCheck `json:"ports"`
	FW      fwState     `json:"firewall"`
}

// serverPreflight probes the endpoint ports on loopback (binding
// 127.0.0.1 keeps the firewall out of the measurement) plus the
// firewall state, and emits "serverCheck". Skipped while running.
// The firewall scan outcome goes to the journal for investigation:
// verdict, coverage reason and duration, one line per pre-flight.
func (a *App) serverPreflight() {
	running, _ := a.serverctl.running()
	if running {
		a.emit("serverCheck", serverCheck{Running: true})
		return
	}
	go func() {
		t0 := time.Now()
		fw := firewallCheck()
		a.logFwScan("pre-flight", fw, time.Since(t0))
		a.emit("serverCheck", serverCheck{
			Ports: []portCheck{
				probePort("udp", 53),
				probePort("tcp", 80),
				probePort("tcp", 443),
			},
			FW: fw,
		})
	}()
}

func probePort(proto string, port int) portCheck {
	pc := portCheck{Port: port, Proto: proto, Free: true}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	var err error
	if proto == "udp" {
		var c net.PacketConn
		c, err = net.ListenPacket("udp", addr)
		if err == nil {
			c.Close()
		}
	} else {
		var l net.Listener
		l, err = net.Listen("tcp", addr)
		if err == nil {
			l.Close()
		}
	}
	if err != nil {
		pc.Free = false
		pc.Holder = portHolder(proto, port)
	}
	return pc
}

// logFwScan journals one firewall scan: where it ran (pre-flight, on
// start), the verdict reason and duration. The ports are named in
// every line so a log excerpt is self-contained for investigation.
// An empty reason (no app firewall on this OS) stays silent.
func (a *App) logFwScan(where string, fw fwState, took time.Duration) {
	if fw.Reason == "" {
		return
	}
	a.log("info", fmt.Sprintf("firewall %s (inbound udp/53, tcp/80, tcp/443): %s, took %.1fs",
		where, fw.Reason, took.Seconds()))
}

// fwNote runs at start: it journals what the owner should expect from
// Windows' own firewall dialog before the Server binds — a prompt to
// allow, or silence because something already allows — and refuses to
// start when a Block rule would make the Server dead on arrival.
func (a *App) fwNote() bool {
	t0 := time.Now()
	fw := firewallCheck()
	a.logFwScan("on start", fw, time.Since(t0))
	switch {
	case fw.Blocked:
		a.log("err", "firewall: inbound is DENIED by an existing rule (a previous «Отмена»?) — remove the block for this app in Windows Firewall")
		return false
	case fw.Needed:
		a.log("info", "firewall: inbound not allowed yet — Windows shows its allow/deny prompt when the server binds; press «Разрешить доступ» when it appears")
		return true
	default:
		return true
	}
}
