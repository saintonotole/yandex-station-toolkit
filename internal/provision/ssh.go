package provision

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/saintonotole/yandex-station-toolkit/internal/sshkeys"
)

const (
	remoteBinDir      = "/data/opt/bin"
	remoteEtcDir      = "/data/opt/etc/dropbear"
	remoteMulti       = remoteBinDir + "/dropbearmulti"
	remoteDropbear    = remoteBinDir + "/dropbear"
	remoteDropbearkey = remoteBinDir + "/dropbearkey"
	remoteHostKey     = remoteEtcDir + "/hk_ed25519"
	remoteKeys        = remoteEtcDir + "/authorized_keys"
	remoteInitStaged  = remoteEtcDir + "/S99zdropbear"
	remoteInit        = "/etc/init.d/S99zdropbear"
)

// Dropbear is dropbearmulti; dropbear and dropbearkey are symlinks to it.
type SSHFiles struct {
	Dropbear string
}

// InstallDropbear snapshots the previous init script so a bad config can
// be rolled back without losing the current connection.
func InstallDropbear(ctx context.Context, r Runner, f SSHFiles, keys []sshkeys.PubKey, opts SSHOpts, log Logger) error {
	if len(keys) == 0 && !opts.AllowBlankPassword {
		return fmt.Errorf("key list is empty")
	}
	if opts.Port == 0 {
		opts.Port = 2222
	}

	if out, _ := r.Shell(ctx, "id -u"); strings.TrimSpace(out) != "0" {
		return fmt.Errorf("root is required (id -u = %q)", strings.TrimSpace(out))
	}

	prevInit, _ := r.Shell(ctx, "cat "+remoteInit+" 2>/dev/null")
	prevInit = strings.TrimSpace(prevInit)

	log.Logf("uploading dropbearmulti to %s …", remoteBinDir)
	if _, err := r.Shell(ctx, "mkdir -p "+remoteBinDir+" "+remoteEtcDir); err != nil {
		return fmt.Errorf("mkdir: %v", err)
	}
	// Dropbear's strict-modes check refuses authorized_keys when any
	// parent directory is group/world-writable — an external edit can
	// leave /data/opt that way and every login fails until it is fixed.
	if _, err := run(ctx, r, "chmod 755 /data/opt"); err != nil {
		return err
	}
	if err := r.Push(ctx, f.Dropbear, remoteMulti); err != nil {
		return err
	}
	// ln -sf also replaces separate binaries left by older installs.
	if _, err := run(ctx, r, "chmod 755 "+remoteMulti); err != nil {
		return err
	}
	if _, err := run(ctx, r, "ln -sf dropbearmulti "+remoteDropbear); err != nil {
		return err
	}
	if _, err := run(ctx, r, "ln -sf dropbearmulti "+remoteDropbearkey); err != nil {
		return err
	}

	log.Logf("checking the ed25519 host key…")
	out, err := run(ctx, r, "[ -s "+remoteHostKey+" ] && echo ok || echo no")
	if err != nil {
		return err
	}
	if out != "ok" {
		if _, err := run(ctx, r, remoteDropbearkey+" -t ed25519 -f "+remoteHostKey); err != nil {
			return err
		}
	}

	// Blank-password installs skip the authorized_keys write entirely:
	// dropbear starts with -B and whatever keys are already on the
	// device stay as they are.
	if len(keys) > 0 {
		log.Logf("reading existing keys from the device…")
		existingOut, _ := r.Shell(ctx, "cat "+remoteKeys+" 2>/dev/null")
		existing := sshkeys.ParseDeviceAuthorizedKeys(existingOut)
		merged := sshkeys.MergeKeys(existing, keys)
		log.Logf("authorized_keys now has %d key(s) (was %d)", len(merged), len(existing))

		// /data stays writable; the rootfs needs a remount.
		akBytes := []byte(keysFileContent(merged))
		akLocal, err := WriteTemp(tempDir(), "authorized_keys", akBytes)
		if err != nil {
			return err
		}
		if err := r.Push(ctx, akLocal, remoteKeys); err != nil {
			return err
		}
	}
	initLocal, err := WriteTemp(tempDir(), "S99zdropbear", BuildInitScript(opts))
	if err != nil {
		return err
	}
	if err := r.Push(ctx, initLocal, remoteInitStaged); err != nil {
		return err
	}
	if len(keys) > 0 {
		if _, err := run(ctx, r, "chmod 600 "+remoteKeys); err != nil {
			return err
		}
	}
	if _, err := run(ctx, r, "chmod 755 "+remoteInitStaged); err != nil {
		return err
	}

	log.Logf("installing the init script and keys into the rootfs (remount rw)…")
	if err := rootfs(ctx, r,
		"cp "+remoteInitStaged+" "+remoteInit,
		"chmod 755 "+remoteInit,
		"sync",
	); err != nil {
		return fmt.Errorf("rootfs install: %v", err)
	}

	authTag := "keys only"
	if opts.AllowBlankPassword {
		authTag = "blank password (insecure)"
	}
	log.Logf("starting dropbear on port %d (%s)…", opts.Port, authTag)
	// The session we are using is a child of the running dropbear, so
	// `restart` (killall) drops this connection. Schedule it in a new
	// session and return before that happens. The caller checks the
	// port after a short wait.
	sched := "/usr/bin/setsid sh -c 'sleep 1; " + remoteInit + " restart' </dev/null >/data/opt/etc/dropbear/restart.log 2>&1 & echo scheduled"
	out, err = r.Shell(ctx, sched)
	if err != nil || !strings.Contains(out, "scheduled") {
		if prevInit != "" {
			_ = RestoreInitScript(ctx, r, prevInit, log)
		}
		return fmt.Errorf("start: %v (%s)", err, strings.TrimSpace(out))
	}
	log.Logf("dropbear restart scheduled, port %d, %s", opts.Port, authTag)
	return nil
}

func RestoreInitScript(ctx context.Context, r Runner, prevInit string, log Logger) error {
	if strings.TrimSpace(prevInit) == "" {
		_, _ = r.Shell(ctx, "killall dropbear 2>/dev/null")
		return nil
	}
	dir, _ := os.MkdirTemp("", "yandex-station-toolkit-restore-*")
	defer os.RemoveAll(dir)
	local, err := WriteTemp(dir, "S99zdropbear", []byte(prevInit))
	if err != nil {
		return err
	}
	if _, err := r.Shell(ctx, "mount -o remount,rw / 2>/dev/null"); err != nil {
		return fmt.Errorf("remount rw: %v", err)
	}
	if err := r.Push(ctx, local, remoteInit); err != nil {
		return err
	}
	if _, err := r.Shell(ctx, "chmod 755 "+remoteInit+"; mount -o remount,ro / 2>/dev/null; "+remoteInit+" restart"); err != nil {
		return fmt.Errorf("restart: %v", err)
	}
	log.Logf("rolled back to the previous init script")
	return nil
}

func ReadAuthorizedKeys(ctx context.Context, r Runner) (string, error) {
	out, err := r.Shell(ctx, "cat "+remoteKeys+" 2>/dev/null")
	existing := sshkeys.ParseDeviceAuthorizedKeys(out)
	var b strings.Builder
	for _, k := range existing {
		b.WriteString(k.Line())
		b.WriteByte('\n')
	}
	return strings.TrimSpace(b.String()), err
}

func ReadDropbearConfig(ctx context.Context, r Runner) (opts SSHOpts, installed bool, err error) {
	out, e := r.Shell(ctx, "cat "+remoteInit+" 2>/dev/null")
	if e != nil {
		return SSHOpts{}, false, e
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return SSHOpts{}, false, nil
	}
	o, ok := ParseInitScript(out)
	if !ok {
		return SSHOpts{}, false, nil
	}
	return o, true, nil
}

func keysFileContent(keys []sshkeys.PubKey) string {
	var b strings.Builder
	b.WriteString("# installed by Yandex Station ToolKit; edit /data/opt/etc/dropbear/authorized_keys\n")
	for _, k := range keys {
		b.WriteString(k.Line())
		b.WriteString("\n")
	}
	return b.String()
}

// UninstallDropbear keeps binaries and keys in /data/opt.
func UninstallDropbear(ctx context.Context, r Runner, log Logger) error {
	log.Logf("removing %s …", remoteInit)
	if err := rootfs(ctx, r, "rm -f "+remoteInit, "sync"); err != nil {
		return fmt.Errorf("uninstall: %v", err)
	}
	_, _ = r.Shell(ctx, "killall dropbear 2>/dev/null")
	log.Logf("SSH removed (binaries and keys remain in /data/opt and do not affect the speaker)")
	return nil
}

// Tests replace tempDir.
var tempDir = defaultTempDir
