package provision

import (
	"bytes"
	"context"
	"fmt"
	"strings"
)

// yse — the device-side package manager (Entware + .yap registries), per
// https://hackalice.me/start/packages/. The project is actively developed,
// so the script is fetched live from its repository at install time instead
// of shipping a bundled copy — the wiki's own installer pulls the same file.
const yseURL = "https://raw.githubusercontent.com/Marker284/yandex-station-extended/main/contrib/bin/yse"

const (
	remoteYSE       = "/data/opt/bin/yse"
	remoteYSEBinDir = "/data/opt/bin"
)

func InstallYSE(ctx context.Context, r Runner, log Logger) error {
	if out, _ := r.Shell(ctx, "id -u"); strings.TrimSpace(out) != "0" {
		return fmt.Errorf("root is required (id -u = %q)", strings.TrimSpace(out))
	}

	log.Logf("downloading yse from Marker284/yandex-station-extended (main branch)…")
	script, err := httpGet(ctx, yseURL)
	if err != nil {
		return fmt.Errorf("download yse: %v", err)
	}
	if len(script) < 200 || !bytes.HasPrefix(script, []byte("#!")) {
		return fmt.Errorf("downloaded yse does not look like a shell script (%d bytes)", len(script))
	}

	log.Logf("uploading yse to %s …", remoteYSEBinDir)
	if _, err := r.Shell(ctx, "mkdir -p "+remoteYSEBinDir); err != nil {
		return fmt.Errorf("mkdir: %v", err)
	}

	dir := tempDir()
	local, err := WriteTemp(dir, "yse", script)
	if err != nil {
		return err
	}
	if err := r.Push(ctx, local, remoteYSE); err != nil {
		return fmt.Errorf("push yse: %v", err)
	}
	if _, err := r.Shell(ctx, "chmod 755 "+remoteYSE); err != nil {
		return fmt.Errorf("chmod yse: %v", err)
	}

	checkOut, _ := r.Shell(ctx, "[ -x /data/opt/bin/yse ] && [ -d /data/opt/entware ] && echo yes || echo no")
	if strings.TrimSpace(checkOut) == "yes" {
		log.Logf("yse is already installed and Entware is present — updating the script only")
		return nil
	}

	log.Logf("running yse bootstrap (Entware)…")
	out, err := r.Shell(ctx, remoteYSE+" bootstrap")
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) != "" {
			log.Logf("  %s", strings.TrimSpace(line))
		}
	}
	if err != nil {
		return fmt.Errorf("yse bootstrap: %v (%s)", err, strings.TrimSpace(out))
	}
	log.Logf("yse installed. Reconnect over SSH so yse is on PATH.")
	return nil
}

// UninstallYSE keeps user data under /data/opt/home.
func UninstallYSE(ctx context.Context, r Runner, log Logger) error {
	log.Logf("removing yse and Entware/yap …")
	if _, err := run(ctx, r, `for c in /data/opt/bin/*; do grep -q '^# yse-yap ' "$c" 2>/dev/null && rm "$c"; done`); err != nil {
		return err
	}
	if _, err := run(ctx, r, "rm -rf /data/opt/bin/yse /data/opt/entware /data/opt/yap /data/opt/var/yse /data/opt/etc/yse"); err != nil {
		return err
	}
	// /opt is a symlink to /data/opt; restore the empty mount point.
	log.Logf("cleaning /opt (remount rw)…")
	if err := rootfs(ctx, r, "rm -rf /opt", "mkdir -p /opt", "sync"); err != nil {
		// Some images have no /opt symlink.
		log.Logf("  /opt: %v — continuing", err)
	}
	log.Logf("yse removed. Reboot the speaker so PATH updates.")
	return nil
}

func IsYSEInstalled(ctx context.Context, r Runner) (bool, error) {
	out, err := r.Shell(ctx, "[ -x /data/opt/bin/yse ] && [ -d /data/opt/entware ] && echo yes || echo no")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) == "yes", nil
}
