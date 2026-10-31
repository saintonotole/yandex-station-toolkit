//go:build !windows

package adb

import "os/exec"

func hideWindow(_ *exec.Cmd) {}
