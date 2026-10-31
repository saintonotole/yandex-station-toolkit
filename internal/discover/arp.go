package discover

import (
	"context"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// A MAC-shaped token: six hex pairs, dash- or colon-separated.
var macRe = regexp.MustCompile(`(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}`)

// ARPMAC reads ip's hardware address from the OS neighbor table. Scanning
// dials every host before this runs, so the entry exists for any host that
// answered — also for stations with every shell channel closed. Nothing is
// sent to the device; an unknown host returns "".
func ARPMAC(ip string) string {
	var cmds [][]string
	switch runtime.GOOS {
	case "windows":
		cmds = [][]string{{"arp", "-a", ip}}
	case "linux":
		cmds = [][]string{
			{"ip", "neigh", "show", ip},
			{"arp", "-n", ip}, // minimal images without iproute2
		}
	default: // darwin
		cmds = [][]string{{"arp", "-n", ip}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, argv := range cmds {
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		hideWindow(cmd)
		out, err := cmd.Output()
		if err != nil {
			continue
		}
		if mac := parseNeighMAC(string(out), ip); mac != "" {
			return mac
		}
	}
	return ""
}

// parseNeighMAC finds the MAC on the line that names ip, in any of the
// three formats the supported OSes print (localized headers included: the
// address token matches, the header words never do).
func parseNeighMAC(out, ip string) string {
	for _, line := range strings.Split(out, "\n") {
		if !containsIP(line, ip) {
			continue
		}
		if m := macRe.FindString(line); m != "" {
			return strings.ToLower(strings.ReplaceAll(m, "-", ":"))
		}
	}
	return ""
}

// containsIP reports whether ip appears in line as a standalone address,
// so 192.168.178.6 does not match a line about 192.168.178.63.
func containsIP(line, ip string) bool {
	for i := 0; i < len(line); {
		j := strings.Index(line[i:], ip)
		if j < 0 {
			return false
		}
		j += i
		before := j == 0 || !isIPByte(line[j-1])
		after := j+len(ip) >= len(line) || !isIPByte(line[j+len(ip)])
		if before && after {
			return true
		}
		i = j + 1
	}
	return false
}

func isIPByte(b byte) bool { return b == '.' || (b >= '0' && b <= '9') }
