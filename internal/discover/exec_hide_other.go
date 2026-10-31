//go:build !windows

package discover

import "os/exec"

func hideWindow(_ *exec.Cmd) {}
