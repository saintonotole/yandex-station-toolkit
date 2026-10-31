// Package provision installs scripts and binaries onto a station over adb or SSH.
package provision

import (
	"context"
	"fmt"
	"os"
	"strings"
)

type Runner interface {
	Shell(ctx context.Context, cmd string) (string, error)
	Push(ctx context.Context, local, remote string) error
}

type Logger func(msg string)

func (l Logger) Logf(format string, args ...any) {
	if l != nil {
		l(fmt.Sprintf(format, args...))
	}
}

func run(ctx context.Context, r Runner, cmd string) (string, error) {
	out, err := r.Shell(ctx, cmd)
	out = strings.TrimSpace(out)
	if err != nil {
		return out, fmt.Errorf("%s: %v (%s)", cmd, err, out)
	}
	return out, nil
}

func answeredYes(ctx context.Context, r Runner, cmd string) (bool, error) {
	out, err := run(ctx, r, cmd)
	if err != nil {
		return false, err
	}
	return out == "yes", nil
}

// rootfs remounts the root filesystem writable, runs each command on its
// own, then remounts it read-only even when a command fails.
func rootfs(ctx context.Context, r Runner, cmds ...string) error {
	if _, err := run(ctx, r, "mount -o remount,rw /"); err != nil {
		return err
	}
	var first error
	for _, cmd := range cmds {
		if _, err := run(ctx, r, cmd); err != nil && first == nil {
			first = err
		}
	}
	_, _ = r.Shell(ctx, "mount -o remount,ro /")
	return first
}

const RemoteNoUpdate = "/data/opt/yandex-noupdate.sh"

type OTAStatus struct {
	ScriptPresent  bool   `json:"scriptPresent"`
	UpdaterInConf  bool   `json:"updaterInConf"`  // --updatesd still in launch.json
	UpdaterRunning bool   `json:"updaterRunning"` // maind --updatesd is running
	ApplierStubbed bool   `json:"applierStubbed"` // device_ota_update.sh is stubbed
	KeyReplaced    bool   `json:"keyReplaced"`    // ota_script.pub is replaced
	Raw            string `json:"raw"`
}

func (s OTAStatus) Blocked() bool {
	// Disk state only: launch.json without the updater task, the apply
	// script stubbed, the OTA signature key replaced. The updater
	// PROCESS may still be running from a previous boot — with the key
	// and the applier neutralized it cannot apply anything, so it does
	// not affect the verdict.
	return !s.UpdaterInConf && s.ApplierStubbed && s.KeyReplaced
}

func EnsureScript(ctx context.Context, r Runner, localScript string, log Logger) error {
	out, _ := r.Shell(ctx, "[ -f "+RemoteNoUpdate+" ] && echo yes || echo no")
	if strings.TrimSpace(out) == "yes" {
		log.Logf("script %s is already on the device", RemoteNoUpdate)
		return nil
	}
	if err := r.Push(ctx, localScript, RemoteNoUpdate); err != nil {
		return err
	}
	log.Logf("script uploaded to %s", RemoteNoUpdate)
	return nil
}

func OTAInstall(ctx context.Context, r Runner, localScript string, log Logger) (OTAStatus, error) {
	if err := EnsureScript(ctx, r, localScript, log); err != nil {
		return OTAStatus{}, err
	}
	log.Logf("disabling updates…")
	out, err := r.Shell(ctx, "sh "+RemoteNoUpdate)
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) != "" {
			log.Logf("  %s", strings.TrimSpace(line))
		}
	}
	if err != nil {
		return OTAStatus{}, fmt.Errorf("script failed: %v", err)
	}
	st, err := OTAStatusCmd(ctx, r, localScript, log)
	if err != nil {
		return st, err
	}
	if !st.Blocked() {
		return st, fmt.Errorf("updates are not fully blocked — see the log")
	}
	return st, nil
}

func OTAStatusCmd(ctx context.Context, r Runner, localScript string, log Logger) (OTAStatus, error) {
	if err := EnsureScript(ctx, r, localScript, log); err != nil {
		return OTAStatus{}, err
	}
	out, err := r.Shell(ctx, "sh "+RemoteNoUpdate+" status")
	if err != nil {
		return OTAStatus{}, fmt.Errorf("status: %v (output: %q)", err, strings.TrimSpace(out))
	}
	st := ParseOTAStatus(out)
	st.ScriptPresent = true
	return st, nil
}

func OTARestore(ctx context.Context, r Runner, localScript string, log Logger) error {
	if err := EnsureScript(ctx, r, localScript, log); err != nil {
		return err
	}
	out, err := r.Shell(ctx, "sh "+RemoteNoUpdate+" restore")
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) != "" {
			log.Logf("  %s", strings.TrimSpace(line))
		}
	}
	return err
}

// ParseOTAStatus matches the Russian output of the script's do_status.
func ParseOTAStatus(out string) OTAStatus {
	st := OTAStatus{Raw: out}
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.Contains(line, "updatesd ПРИСУТСТВУЕТ"):
			st.UpdaterInConf = true
		case strings.Contains(line, "updatesd убран"):
			st.UpdaterInConf = false
		case strings.Contains(line, "maind --updatesd РАБОТАЕТ"):
			st.UpdaterRunning = true
		case strings.Contains(line, "maind --updatesd") && strings.Contains(line, "не запущен"):
			st.UpdaterRunning = false
		case strings.Contains(line, "applier") && strings.Contains(line, "заглушён"):
			st.ApplierStubbed = true
		case strings.Contains(line, "applier") && strings.Contains(line, "штатный"):
			st.ApplierStubbed = false
		case strings.Contains(line, "ota key") && strings.Contains(line, "подменён"):
			st.KeyReplaced = true
		case strings.Contains(line, "ota key") && strings.Contains(line, "штатный"):
			st.KeyReplaced = false
		}
	}
	return st
}

func Reboot(ctx context.Context, r Runner, log Logger) error {
	log.Logf("rebooting…")
	_, err := r.Shell(ctx, "reboot")
	if err != nil && !isConnectionClosed(err) {
		return err
	}
	return nil
}

func isConnectionClosed(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "closed") || strings.Contains(s, "reset") || strings.Contains(s, "EOF")
}

func WriteTemp(dir, name string, data []byte) (string, error) {
	p := dir + string(os.PathSeparator) + name
	if err := os.WriteFile(p, data, 0o755); err != nil {
		return "", err
	}
	return p, nil
}
