package provision

import (
	"context"
	"fmt"
	"strings"
)

// Network adbd is started by an init script, the same way dropbear is.
// The quasmodrom markers under /data/quasar are left alone: a later
// cloud sync deletes them, so they are not a durable switch.
const (
	adbDaemon     = "/usr/bin/adbd"
	adbInit       = "/etc/init.d/S99zadbd"
	adbInitStaged = "/data/opt/S99zadbd"
)

type ADBBootStatus struct {
	Autostart bool `json:"autostart"`
	Running   bool `json:"running"`
}

// rcS runs S99zadbd after S99quasar.
func ADBInitScript() []byte {
	return []byte(`#!/bin/sh
# Autostart network adbd on :5555 (installed by Yandex Station ToolKit).
# Remove this file to uninstall. Quasmodrom markers are not touched.
DB=/usr/bin/adbd
start() {
  [ -x "$DB" ] || return 1
  pidof adbd >/dev/null 2>&1 && return 0
  start-stop-daemon -S -b -x "$DB"
}
case "$1" in
  start)   start ;;
  stop)    start-stop-daemon -K -x "$DB" 2>/dev/null; killall adbd 2>/dev/null ;;
  restart) start-stop-daemon -K -x "$DB" 2>/dev/null; killall adbd 2>/dev/null; sleep 1; start ;;
esac
exit 0
`)
}

func ADBBootStatusCmd(ctx context.Context, r Runner) (ADBBootStatus, error) {
	autostart, err := answeredYes(ctx, r, "[ -x "+adbInit+" ] && echo yes || echo no")
	if err != nil {
		return ADBBootStatus{}, fmt.Errorf("adb status: %v", err)
	}
	running, err := answeredYes(ctx, r, "pidof adbd >/dev/null 2>&1 && echo yes || echo no")
	if err != nil {
		return ADBBootStatus{}, fmt.Errorf("adb status: %v", err)
	}
	return ADBBootStatus{Autostart: autostart, Running: running}, nil
}

func StartADB(ctx context.Context, r Runner, log Logger) error {
	log.Logf("starting adbd")
	out, _ := run(ctx, r, "pidof adbd")
	if out == "" {
		if _, err := run(ctx, r, "start-stop-daemon -S -b -x "+adbDaemon); err != nil {
			return err
		}
		var err error
		out, err = run(ctx, r, "pidof adbd")
		if err != nil || out == "" {
			return fmt.Errorf("start adbd: %v (%s)", err, out)
		}
	}
	log.Logf("adbd running (pid %s), port 5555", strings.Fields(out)[0])
	return nil
}

func StopADB(ctx context.Context, r Runner, log Logger) error {
	log.Logf("stopping adbd")
	_, _ = r.Shell(ctx, "killall adbd 2>/dev/null")
	_, _ = r.Shell(ctx, "sleep 1")
	running, err := answeredYes(ctx, r, "pidof adbd >/dev/null 2>&1 && echo yes || echo no")
	if err != nil {
		return err
	}
	if running {
		return fmt.Errorf("stop adbd: still running")
	}
	log.Logf("adbd stopped")
	return nil
}

func EnableADBBoot(ctx context.Context, r Runner, log Logger) error {
	dir := tempDir()
	local, err := WriteTemp(dir, "S99zadbd", ADBInitScript())
	if err != nil {
		return err
	}
	log.Logf("staging %s", adbInitStaged)
	if err := r.Push(ctx, local, adbInitStaged); err != nil {
		return err
	}
	log.Logf("installing %s (remount rw)", adbInit)
	if err := rootfs(ctx, r,
		"cp "+adbInitStaged+" "+adbInit,
		"chmod 755 "+adbInit,
		"sync",
		"[ -x "+adbInit+" ]",
	); err != nil {
		return fmt.Errorf("install %s: %v", adbInit, err)
	}
	log.Logf("adbd will start on boot")
	return nil
}

func DisableADBBoot(ctx context.Context, r Runner, log Logger) error {
	log.Logf("removing %s", adbInit)
	if err := rootfs(ctx, r,
		"rm -f "+adbInit+" "+adbInitStaged,
		"sync",
		"[ ! -e "+adbInit+" ]",
	); err != nil {
		return fmt.Errorf("remove %s: %v", adbInit, err)
	}
	log.Logf("ADB autostart removed")
	return nil
}
