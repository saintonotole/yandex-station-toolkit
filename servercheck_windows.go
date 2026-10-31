//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

// portHolder names the process holding a local port, via netstat + tasklist.
func portHolder(proto string, port int) string {
	out, err := runHidden("netstat", "-ano", "-p", proto)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		// Proto Local Foreign State PID (TCP) / Proto Local * PID (UDP)
		if len(f) < 4 || !strings.EqualFold(f[0], proto) {
			continue
		}
		local := f[1]
		i := strings.LastIndex(local, ":")
		if i < 0 {
			continue
		}
		if p, err := strconv.Atoi(local[i+1:]); err != nil || p != port {
			continue
		}
		pid, err := strconv.Atoi(f[len(f)-1])
		if err != nil {
			continue
		}
		if name := processName(pid); name != "" {
			return fmt.Sprintf("%s (pid %d)", name, pid)
		}
		return fmt.Sprintf("pid %d", pid)
	}
	return ""
}

func processName(pid int) string {
	out, err := runHidden("tasklist", "/fo", "csv", "/nh", "/fi", fmt.Sprintf("PID eq %d", pid))
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(out)
	if i := strings.IndexByte(line, ','); i > 0 {
		return strings.Trim(line[:i], "\"")
	}
	return ""
}

// longExePath expands any 8.3 components: the firewall stores the path it
// was given, and comparing short vs long forms never matches.
func longExePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	p, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return exe, nil
	}
	buf := make([]uint16, len(exe)+260)
	n, err := windows.GetLongPathName(p, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 {
		return exe, nil
	}
	return windows.UTF16ToString(buf[:n]), nil
}

// firewallCheck predicts what Windows' own firewall will do with inbound
// traffic to this exe — the app never manages rules itself. Covered is:
// the firewall being off, a default-allow profile, or an Allow rule
// naming this exe (case-insensitive, on an active profile) — in those
// cases binding the Server binds silently. Otherwise Windows will show
// its native allow/deny dialog for the app once it binds (Needed=true).
// A Block rule naming this exe (the result of declining that dialog)
// outranks Allow and is reported as Blocked: the dialog never comes
// back while it exists, so the owner must remove it by hand.
//
// Any-program rules NEVER count as coverage: Windows ships ~50, all
// scoped (CoreNetworking ICMP, WMP, per-port leftovers such as
// lite-kit's TCP 53/80/443 rule), and even protocol-Any UWP
// packaged-app rules masquerade as scopeless on this API — counting
// them once suppressed the prompt while the firewall actually blocked
// the Server. The cost of a needless prompt is one click; the cost of a
// wrongly covered verdict is a Server that silently never works.
//
// Rules are enumerated through the documented INetFwPolicy2 COM object:
// one pass over all rules answers every case in under a second. The
// Get-NetFirewallApplicationFilter pipe shape that preceded it issued a
// CIM association query per matched rule (~30 ms each) and cost 15–40 s
// per check. The indexed CIM query stays as a fallback if COM fails.
func firewallCheck() fwState {
	exe, err := longExePath()
	if err != nil {
		return fwState{Needed: false, Reason: "scan failed, assumed allowed"}
	}
	ps := fmt.Sprintf(`
$ps = @(Get-NetFirewallProfile | Where-Object Enabled)
if ($ps.Count -eq 0) { 'OFF' ; exit }
if (@($ps | Where-Object DefaultInboundAction -eq 'Allow').Count -gt 0) { 'DEFAULTALLOW' ; exit }
$exe = '%s'
# NET_FW_RULE_DIRECTION_IN = 1, NET_FW_ACTION_ALLOW = 1, NET_FW_ACTION_BLOCK = 0.
try { $fw = New-Object -ComObject HNetCfg.FwPolicy2 } catch { $fw = $null }
if ($fw) {
  $cur = $fw.CurrentProfileTypes
  foreach ($r in $fw.Rules) {
    if ($r.Direction -ne 1 -or -not $r.Enabled) { continue }
    if (-not ($r.Profiles -band $cur)) { continue }
    $app = $r.ApplicationName
    if ($app) {
      if ($app -ine $exe) { continue }
      if ($r.Action -eq 0) { 'BLOCKED' ; exit }
      if ($r.Action -eq 1) { 'EXE' ; exit }
      continue
    }
    # any-program rule: covering only when it is TCP (6) with explicit
    # local ports that include all of the Server's TCP listeners
    # 53/80/443 — the shape of the owner's leftover lite-kit rule.
    # UWP packaged rules also masquerade as any-program but are never
    # port-scoped like this, so they cannot cause a false verdict.
    if ($r.Action -eq 1 -and [string]$r.Protocol -eq '6' -and $r.LocalPorts) {
      $ports = @{}
      foreach ($p in ($r.LocalPorts -split ',')) {
        if ($p -match '^\s*(\d+)\s*-\s*(\d+)\s*$') {
          for ($q = [int]$Matches[1]; $q -le [int]$Matches[2]; $q++) { $ports[[string]$q] = $true }
        } elseif ($p -match '^\s*(\d+)\s*$') { $ports[$Matches[1].Trim()] = $true }
      }
      if ($ports['53'] -and $ports['80'] -and $ports['443']) { 'ANYPORTS:' + $r.Name ; exit }
    }
  }
  'NEEDED' ; exit
}
# Fallback if COM failed: indexed query; the path is stored as given at rule creation.
$hit = @(Get-NetFirewallApplicationFilter -Program $exe -ErrorAction SilentlyContinue | Get-NetFirewallRule | Where-Object { $_.Enabled -and $_.Direction -eq 'Inbound' })
if (@($hit | Where-Object Action -eq 'Block').Count -gt 0) { 'BLOCKED' ; exit }
if (@($hit | Where-Object Action -eq 'Allow').Count -gt 0) { 'EXE' ; exit }
'NEEDED'`, strings.ReplaceAll(exe, "'", "''"))
	out, err := runHidden("powershell", "-NoProfile", "-Command", ps)
	if err != nil {
		// The check failed; assume no prompt rather than nagging.
		return fwState{Needed: false, Reason: "scan failed, assumed allowed"}
	}
	verdict := strings.TrimSpace(out)
	switch {
	case verdict == "OFF":
		return fwState{Needed: false, Reason: "covered: firewall off"}
	case verdict == "DEFAULTALLOW":
		return fwState{Needed: false, Reason: "covered: default inbound allow"}
	case verdict == "EXE":
		return fwState{Needed: false, Reason: "covered: app allow rule"}
	case verdict == "BLOCKED":
		return fwState{Blocked: true, Needed: false, Reason: "blocked: an app rule denies inbound (a declined prompt?) — remove the block in Windows Firewall"}
	case verdict == "NEEDED":
		return fwState{Needed: true, Reason: "no covering rule — Windows will ask"}
	case strings.HasPrefix(verdict, "ANYPORTS:"):
		name := strings.TrimSpace(strings.TrimPrefix(verdict, "ANYPORTS:"))
		return fwState{Needed: false, Reason: fmt.Sprintf("covered: any-program TCP rule '%s' on 53/80/443 (udp/53 uncovered)", name)}
	}
	return fwState{Needed: false, Reason: "scan failed, assumed allowed"}
}

func runHidden(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags = cmd.SysProcAttr.CreationFlags | 0x08000000 // CREATE_NO_WINDOW
	cmd.SysProcAttr.HideWindow = true
	out, err := cmd.Output()
	return string(out), err
}
