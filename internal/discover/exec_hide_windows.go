//go:build windows

package discover

import (
	"os/exec"
	"syscall"
)

// Without CREATE_NO_WINDOW every neighbor-table lookup flashes a console.
func hideWindow(c *exec.Cmd) {
	if c.SysProcAttr == nil {
		c.SysProcAttr = &syscall.SysProcAttr{}
	}
	c.SysProcAttr.CreationFlags = c.SysProcAttr.CreationFlags | 0x08000000 // CREATE_NO_WINDOW
	c.SysProcAttr.HideWindow = true
}
