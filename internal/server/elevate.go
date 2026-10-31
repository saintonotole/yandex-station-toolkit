package server

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"syscall"
)

// PermissionError reports whether a bind failure is a privilege problem —
// the only case where re-launching elevated can help. A busy port will not
// be fixed by root, and lite-kit's users know that pain as "порт 53 уже
// занят" (systemd-resolved, avahi, Windows ICS).
func PermissionError(err error) bool {
	if os.IsPermission(err) {
		return true
	}
	return errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM)
}

// BindError extracts the bind error from a Start/SetMode failure without
// matching on the message text.
func BindError(err error) error {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return opErr.Err
	}
	return err
}

// ElevationSupported is true only where privileged ports exist: Linux.
// macOS (since Mojave) and Windows let any user bind 53/80/443, so the app
// starts the endpoints in-process there and never prompts.
func ElevationSupported() bool {
	return runtime.GOOS == "linux"
}

// HelperArgv is the command line the GUI spawns to run the elevated helper.
// On Linux it goes through pkexec, whose polkit agent shows the native GUI
// password prompt; the helper itself is this same binary with
// --Server-helper.
func HelperArgv(selfPath string, args []string) []string {
	argv := []string{"pkexec", selfPath}
	return append(argv, args...)
}

// BusyPortHint explains what the app tells the user when a bind fails
// without a privilege cause: elevation will not free an occupied port.
func BusyPortHint(err error) string {
	return fmt.Sprintf("%v — порт занят другим сервисом (Linux: systemd-resolved или avahi; Windows: служба ICS). Повыешение прав не поможет, нужно освободить порт.", err)
}
