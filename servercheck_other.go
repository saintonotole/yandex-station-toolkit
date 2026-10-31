//go:build !windows

package main

// portHolder: naming the occupier stays Windows-only for now; elsewhere
// the check reports the port as busy without a name.
func portHolder(proto string, port int) string { return "" }

// firewallCheck: macOS and Linux have no app-scoped firewall to adjust.
// The empty Reason keeps the scan out of the journal there.
func firewallCheck() fwState { return fwState{Needed: false} }
