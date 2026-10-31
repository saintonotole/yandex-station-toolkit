package provision

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// YSE-adjacent package managers, per https://hackalice.me/start/packages/
// and https://hackalice.me/recipes/yam/. Both projects move fast:
//
//   - YAM 0.2 is a package manager that runs on the station itself
//     (/data/yam, no daemon, no web UI — the panel arrives as the yam/luna
//     package from the signed registry). Deployed exactly like the
//     upstream installer does it.
//   - BetterYAM keeps a daemon (betteryamd, :8099) but ships its own
//     installer: manifest-driven daemon per model (Mini, Lite, Mini 3) and
//     a managed init script. We mirror that installer's station-side steps
//     over our own channel, including its init script verbatim, so the
//     upstream uninstaller keeps working.
//
// The daemon lives on /data (the path is "quazar", with a z).
const yamPort = 8099

func httpGet(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "YandexStationToolKit")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func downloadVerified(ctx context.Context, sumsURL, fileURL, name string) ([]byte, error) {
	sums, err := httpGet(ctx, sumsURL)
	if err != nil {
		return nil, fmt.Errorf("checksums: %v", err)
	}
	want, ok := checksumFor(string(sums), name)
	if !ok {
		return nil, fmt.Errorf("SHA256SUMS has no entry for %s", name)
	}
	body, err := httpGet(ctx, fileURL)
	if err != nil {
		return nil, fmt.Errorf("download %s: %v", name, err)
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != want {
		return nil, fmt.Errorf("checksum mismatch for %s", name)
	}
	return body, nil
}

func checksumFor(sums, name string) (string, bool) {
	for _, line := range strings.Split(sums, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		got := strings.TrimPrefix(f[len(f)-1], "*")
		if got == name && len(f[0]) == 64 {
			return strings.ToLower(f[0]), true
		}
	}
	return "", false
}

// --- YAM 0.2 ------------------------------------------------------------------

const (
	yamRepo       = "https://github.com/nyakokitsu/yam"
	yamAPI        = "https://api.github.com/repos/nyakokitsu/yam/releases?per_page=100"
	yamRoot       = "/data/yam"
	yamAssetAmd64 = "yam-aarch64-unknown-linux-musl" // station-side binary, aarch64
	yamPanelURL   = "https://repo.yse.wtf/v2"        // signed registry, see docs/QUICKSTART.md
	yamPanelKey   = "ed25519:5Rz8F47uftWVU5kLgWYhprkEZ4rpP2kecUge/a7KQas="
	yamPanelPkg   = "yam/luna" // the web panel package
)

// Platform profiles shipped by YAM; the mDNS platform marker of every model
// maps onto one of them directly.
var yamProfiles = []string{
	"yandexmicro", "plum", "yandexplum", "yandexmini", "yandexmini_2",
	"bergamot", "pickle", "cucumber", "yandexmidi", "mango",
	"yandexstation_2", "yandexstation", "saturn", "jbl_link_music", "orion",
}

// yamProfileFor maps the app's mDNS platform marker onto a YAM platform
// profile. The names agree for most models; the odd ones out are the mDNS
// spellings (yandexminni, yandexmini2, yandexbergamot, yandexpickle).
func yamProfileFor(platform string) (string, error) {
	p := strings.ToLower(strings.TrimSpace(platform))
	for _, profile := range yamProfiles {
		if p == profile {
			return profile, nil
		}
	}
	switch p {
	case "yandexminni":
		return "yandexmini", nil
	case "yandexmini2":
		return "yandexmini_2", nil
	case "yandexbergamot":
		return "bergamot", nil
	case "yandexpickle":
		return "pickle", nil
	}
	return "", fmt.Errorf("YAM has no platform profile for %q; supported: %s",
		platform, strings.Join(yamProfiles, ", "))
}

// yamLatestTag resolves the newest release on the yam-v* channel (the 0.2
// line), the way the upstream installer does: first tag_name in the
// releases list that starts with yam-v.
func yamLatestTag(ctx context.Context) (string, error) {
	body, err := httpGet(ctx, yamAPI)
	if err != nil {
		return "", fmt.Errorf("releases: %v", err)
	}
	s := string(body)
	marker := `"tag_name"`
	pos := 0
	for {
		i := strings.Index(s[pos:], marker)
		if i < 0 {
			break
		}
		rest := s[pos+i+len(marker):]
		c := strings.Index(rest, ":")
		if c < 0 {
			break
		}
		rest = rest[c+1:]
		q := strings.Index(rest, `"`)
		if q < 0 {
			break
		}
		rest = rest[q+1:]
		e := strings.Index(rest, `"`)
		if e < 0 {
			break
		}
		tag := rest[:e]
		if strings.HasPrefix(tag, "yam-v") {
			return tag, nil
		}
		pos += i + len(marker) + c + q + e + 1
	}
	return "", fmt.Errorf("no release on the yam-v channel")
}

// yamRunScript is the station-side launcher the upstream installer writes:
// it pins the platform, the profile directory and the root, then execs yam.
func yamRunScript(platform string) []byte {
	return []byte("#!/bin/sh\n" +
		"export YAM_PLATFORM='" + platform + "'\n" +
		"export YAM_PROFILES='" + yamRoot + "/platforms'\n" +
		"export YAM_ROOT='" + yamRoot + "'\n" +
		"exec '" + yamRoot + "/bin/yam' \"$@\"\n")
}

func InstallYAM(ctx context.Context, r Runner, log Logger, platform string) error {
	machine, err := run(ctx, r, "uname -m")
	if err != nil {
		return err
	}
	if machine != "aarch64" && machine != "arm64" {
		return fmt.Errorf("YAM needs a 64-bit kernel (aarch64); this speaker is %s", machine)
	}
	profile, err := yamProfileFor(platform)
	if err != nil {
		return err
	}
	log.Logf("platform profile: %s", profile)

	tag, err := yamLatestTag(ctx)
	if err != nil {
		return err
	}
	log.Logf("YAM release: %s", tag)
	releaseURL := yamRepo + "/releases/download/" + tag
	bin, err := downloadVerified(ctx, releaseURL+"/SHA256SUMS", releaseURL+"/"+yamAssetAmd64, yamAssetAmd64)
	if err != nil {
		return err
	}

	// The 0.1 daemon is EOL and lives in the old location; the upstream
	// installer removes it on request, so a fresh install does the same.
	if legacy, _ := r.Shell(ctx, "[ -d /data/quazar/yam ] && echo yes || echo no"); strings.TrimSpace(legacy) == "yes" {
		log.Logf("removing legacy YAM 0.1 daemon (/data/quazar/yam)…")
		if err := rootfs(ctx, r,
			"if [ -r /data/quazar/yam/yamd.pid ]; then pid=$(cat /data/quazar/yam/yamd.pid 2>/dev/null || true); case \"$pid\" in \"\"|*[!0-9]*) ;; *) kill \"$pid\" 2>/dev/null || true ;; esac; fi",
			"rm -f /etc/init.d/S99zyam",
			"rm -rf /data/quazar/yam",
			"sync",
		); err != nil {
			log.Logf("  legacy removal: %v — continuing", err)
		}
	}

	dir := tempDir()
	log.Logf("uploading yam to %s/bin/ …", yamRoot)
	if _, err := run(ctx, r, "mkdir -p "+yamRoot+"/bin "+yamRoot+"/platforms"); err != nil {
		return err
	}
	yamLocal, err := WriteTemp(dir, "yam", bin)
	if err != nil {
		return err
	}
	if err := r.Push(ctx, yamLocal, yamRoot+"/bin/yam.new"); err != nil {
		return fmt.Errorf("push yam: %v", err)
	}

	log.Logf("uploading %d platform profiles…", len(yamProfiles))
	for _, p := range yamProfiles {
		yaml, err := httpGet(ctx, yamRepo+"/raw/main/platforms/"+p+".yaml")
		if err != nil {
			return fmt.Errorf("platform profile %s: %v", p, err)
		}
		local, err := WriteTemp(dir, "profile-"+p+".yaml", yaml)
		if err != nil {
			return err
		}
		if err := r.Push(ctx, local, yamRoot+"/platforms/"+p+".yaml"); err != nil {
			return fmt.Errorf("push %s profile: %v", p, err)
		}
	}

	runLocal, err := WriteTemp(dir, "yam-run", yamRunScript(profile))
	if err != nil {
		return err
	}
	if err := r.Push(ctx, runLocal, yamRoot+"/bin/yam-run.new"); err != nil {
		return fmt.Errorf("push yam-run: %v", err)
	}
	if _, err := run(ctx, r,
		"chmod 0755 "+yamRoot+"/bin/yam.new && mv "+yamRoot+"/bin/yam.new "+yamRoot+"/bin/yam"+
			" && chmod 0755 "+yamRoot+"/bin/yam-run.new && mv "+yamRoot+"/bin/yam-run.new "+yamRoot+"/bin/yam-run"+
			" && test -s "+yamRoot+"/bin/yam-run"); err != nil {
		return fmt.Errorf("activate yam: %v", err)
	}

	// The PATH hook, exactly as the upstream installer writes it: refuse a
	// /usr/bin/yam that belongs to someone else, export the PATH, symlink.
	log.Logf("wiring /usr/bin/yam and /etc/profile.d/yam.sh (remount rw)…")
	if err := rootfs(ctx, r,
		`if [ -e /usr/bin/yam ] && { [ ! -L /usr/bin/yam ] || [ "$(readlink /usr/bin/yam)" != "`+yamRoot+`/bin/yam-run" ]; }; then echo "/usr/bin/yam already belongs to another program" >&2; exit 1; fi`,
		"mkdir -p /etc/profile.d",
		`printf '%s\n' '# Managed by YAM installer' 'export PATH="`+yamRoot+`/bin:$PATH"' > /etc/profile.d/yam.sh`,
		"chmod 0644 /etc/profile.d/yam.sh",
		"ln -sfn "+yamRoot+"/bin/yam-run /usr/bin/yam",
		"sync",
	); err != nil {
		return fmt.Errorf("PATH wiring: %v", err)
	}

	// The Lite keeps its boot hook: refresh the symlink and self-update.
	if profile == "yandexmicro" {
		log.Logf("installing the boot auto-update hook (Lite)…")
		hook := "#!/bin/sh\n" +
			"root='" + yamRoot + "'\n" +
			"platform='" + profile + "'\n" +
			"case \"${1:-}\" in\n" +
			"  start)\n" +
			"    [ -x \"$root/bin/yam\" ] || exit 0\n" +
			"    ln -sfn \"$root/bin/yam-run\" /usr/bin/yam\n" +
			"    /usr/bin/yam update || true\n" +
			"    ;;\n" +
			"esac\n"
		local, err := WriteTemp(dir, "S99yam", []byte(hook))
		if err != nil {
			return err
		}
		staged := yamRoot + "/S99yam.new"
		if err := r.Push(ctx, local, staged); err != nil {
			return fmt.Errorf("push S99yam: %v", err)
		}
		if err := rootfs(ctx, r,
			"cp "+staged+" /etc/init.d/S99yam",
			"chmod 0755 /etc/init.d/S99yam",
			"sync",
			"[ -x /etc/init.d/S99yam ]",
		); err != nil {
			return fmt.Errorf("install S99yam: %v", err)
		}
	}

	log.Logf("YAM %s deployed to %s/bin/yam (use /data/yam/bin/yam-run on the station)", tag, yamRoot)
	return nil
}

func UninstallYAM(ctx context.Context, r Runner, log Logger) error {
	log.Logf("removing YAM (%s, PATH wiring, boot hook)…", yamRoot)
	if err := rootfs(ctx, r,
		`if [ -L /usr/bin/yam ] && [ "$(readlink /usr/bin/yam)" = "`+yamRoot+`/bin/yam-run" ]; then rm -f /usr/bin/yam; fi`,
		`if [ -f /etc/profile.d/yam.sh ] && grep -q "Managed by YAM installer" /etc/profile.d/yam.sh; then rm -f /etc/profile.d/yam.sh; fi`,
		`if [ -f /etc/init.d/S99yam ] && grep -q "`+yamRoot+`" /etc/init.d/S99yam; then rm -f /etc/init.d/S99yam; fi`,
		"rm -rf "+yamRoot,
		"sync",
	); err != nil {
		return err
	}
	log.Logf("YAM removed")
	return nil
}

func IsYAMInstalled(ctx context.Context, r Runner) (bool, error) {
	out, err := r.Shell(ctx, "[ -x "+yamRoot+"/bin/yam ] && echo yes || echo no")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) == "yes", nil
}

// InstallYAMPanel installs the web panel package (yam/luna) from the signed
// registry, registering the registry first the way docs/QUICKSTART.md does.
func InstallYAMPanel(ctx context.Context, r Runner, log Logger) error {
	installed, err := IsYAMInstalled(ctx, r)
	if err != nil {
		return err
	}
	if !installed {
		return fmt.Errorf("YAM is not installed")
	}
	yamRun := yamRoot + "/bin/yam-run"
	log.Logf("registering the signed package registry…")
	if _, err := run(ctx, r,
		yamRun+" registry list | grep -q official || "+yamRun+" registry add official "+yamPanelURL+" --key "+yamPanelKey); err != nil {
		return fmt.Errorf("registry: %v", err)
	}
	log.Logf("installing %s …", yamPanelPkg)
	out, err := r.Shell(ctx, yamRun+" install "+yamPanelPkg)
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) != "" {
			log.Logf("  %s", strings.TrimSpace(line))
		}
	}
	if err != nil {
		return fmt.Errorf("install %s: %v", yamPanelPkg, strings.TrimSpace(out))
	}
	log.Logf("web panel installed (start it from the station shell: %s)", yamRun)
	return nil
}

// --- BetterYAM ----------------------------------------------------------------

// BetterYAM is the per-model daemon fork of YAM (Mini armv7, Lite, Mini 3);
// its installer is manifest-driven and manages its own init script. We
// mirror the installer's station-side steps over our own channel, init
// script verbatim, so the upstream uninstaller keeps working.
var BetterYAM = Daemon{
	name:    "BetterYAM",
	prefix:  "/data/quazar/betteryam",
	bin:     "betteryamd",
	release: "https://github.com/Yandex-Station-Universal-Repo/BetterYAM/releases/latest/download",
	init:    "/etc/init.d/S99zzbetteryam",
}

type Daemon struct {
	name    string
	prefix  string
	bin     string
	release string // GitHub latest/download base, no trailing slash
	init    string
}

type DaemonStatus struct {
	Installed bool `json:"installed"`
	Running   bool `json:"running"`
	Autostart bool `json:"autostart"`
}

func (d Daemon) Label() string { return d.name }

const betterYAMMarker = "# Managed by BetterYAM"

// betterYAMInit is the init script from the BetterYAM installer, verbatim:
// managed marker, remount-guarded start, pid wait, stop/restart.
const betterYAMInit = `#!/bin/sh
# Managed by BetterYAM
set -eu

root=/data/quazar/betteryam
binary=$root/bin/betteryamd
pidfile=$root/betteryamd.pid

start_daemon() {
  mount -o remount,rw / || {
    echo "BetterYAMd: could not remount / read-write" >&2
    return 1
  }
  mount | grep ' on / ' | grep -q '(rw' || {
    echo "BetterYAMd: root filesystem is not writable" >&2
    return 1
  }
  if [ ! -x "$binary" ]; then
    echo "BetterYAMd: daemon binary is missing: $binary" >&2
    return 1
  fi
  mkdir -p "$root/data"
  if [ -f "$pidfile" ]; then
    pid=$(cat "$pidfile")
    case "$pid" in
      ''|*[!0-9]*) rm -f "$pidfile" ;;
      *)
        if kill -0 "$pid" 2>/dev/null; then
          return 0
        fi
        rm -f "$pidfile"
      ;;
    esac
  fi
  start-stop-daemon --start --background --make-pidfile \
    --pidfile "$pidfile" --startas "$binary" -- \
    --data-dir "$root/data"
}

stop_daemon() {
  if [ ! -f "$pidfile" ]; then
    return 0
  fi
  pid=$(cat "$pidfile")
  case "$pid" in
    ''|*[!0-9]*)
      echo "BetterYAMd: invalid pid file: $pidfile" >&2
      return 1
    ;;
  esac
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid"
    attempt=0
    while kill -0 "$pid" 2>/dev/null && [ "$attempt" -lt 50 ]; do
      sleep 0.1
      attempt=$((attempt + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
      echo "BetterYAMd: process $pid did not stop" >&2
      return 1
    fi
  fi
  rm -f "$pidfile"
}

case "${1:-start}" in
  start) start_daemon ;;
  stop) stop_daemon ;;
  restart)
    stop_daemon
    start_daemon
  ;;
  *)
    echo "Usage: $0 {start|stop|restart}" >&2
    exit 2
  ;;
esac
`

// betterYAMSwap is the installer's staged swap: refuse an unmanaged init,
// stop the old daemon, back the binary up, move both pieces in, start, and
// roll the binary back when the daemon did not come up.
const betterYAMSwap = `set -eu
root=/data/quazar/betteryam
binary=$root/bin/betteryamd
staged=$root/bin/betteryamd.new
backup=$root/bin/betteryamd.previous
staged_init=$root/betteryamd.init.new
init=/etc/init.d/S99zzbetteryam
pidfile=$root/betteryamd.pid

if [ -e "$init" ] && ! grep -q '^# Managed by BetterYAM$' "$init"; then
  echo "Refusing to replace unmanaged init script: $init" >&2
  exit 1
fi
chmod 0755 "$staged" "$staged_init"
if [ -x "$init" ]; then
  "$init" stop
elif [ -f "$pidfile" ]; then
  pid=$(cat "$pidfile")
  case "$pid" in
    ''|*[!0-9]*) echo "Invalid BetterYAMd pid file" >&2; exit 1 ;;
  esac
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid"
    attempt=0
    while kill -0 "$pid" 2>/dev/null && [ "$attempt" -lt 50 ]; do
      sleep 0.1
      attempt=$((attempt + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
      echo "BetterYAMd did not stop" >&2
      exit 1
    fi
  fi
  rm -f "$pidfile"
fi
if [ -f "$binary" ]; then
  cp "$binary" "$backup"
fi
mv "$staged" "$binary"
mv "$staged_init" "$init"
if "$init" start; then
  sleep 1
  pid=$(cat "$pidfile" 2>/dev/null || true)
  case "$pid" in
    ''|*[!0-9]*) ;;
    *)
      if kill -0 "$pid" 2>/dev/null; then
        exit 0
      fi
    ;;
  esac
fi
echo "BetterYAMd failed to start; restoring previous binary." >&2
"$init" stop || true
if [ -f "$backup" ]; then
  mv "$backup" "$binary"
  "$init" start
fi
exit 1
`

// betterYAMUninstall is the installer's uninstall script, verbatim.
const betterYAMUninstall = `set -eu
mount -o remount,rw /
mount | grep ' on / ' | grep -q '(rw' || {
  echo "Root filesystem is not writable after remount." >&2
  exit 1
}
root=/data/quazar/betteryam
init=/etc/init.d/S99zzbetteryam
if [ -f "$init" ]; then
  if ! grep -q '^# Managed by BetterYAM$' "$init"; then
    echo "Refusing to remove unmanaged init script: $init" >&2
    exit 1
  fi
  "$init" stop
  rm -f "$init"
elif [ -f "$root/betteryamd.pid" ]; then
  pid=$(cat "$root/betteryamd.pid")
  case "$pid" in
    ''|*[!0-9]*) echo "Invalid BetterYAMd pid file" >&2; exit 1 ;;
  esac
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid"
    attempt=0
    while kill -0 "$pid" 2>/dev/null && [ "$attempt" -lt 50 ]; do
      sleep 0.1
      attempt=$((attempt + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
      echo "BetterYAMd did not stop" >&2
      exit 1
    fi
  fi
fi
rm -rf "$root"
`

// betterYAMManifest is the release manifest that maps a station model to
// its daemon build.
type betterYAMManifest struct {
	Devices []struct {
		Device   string   `json:"device"`
		Models   []string `json:"models"`
		Asset    string   `json:"asset"`
		SHA256   string   `json:"sha256sum"`
		Filepath string   `json:"filepath"`
	} `json:"devices"`
}

// betterYAMSelect picks the one daemon entry whose models list contains the
// model id (a device without a models list matches on its device name).
func betterYAMSelect(body []byte, modelID string) (asset, wantSum, filepath string, err error) {
	var manifest betterYAMManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return "", "", "", err
	}
	matches := 0
	for _, dev := range manifest.Devices {
		models := dev.Models
		if len(models) == 0 && dev.Device != "" {
			models = []string{dev.Device}
		}
		hit := false
		for _, m := range models {
			if m == modelID {
				hit = true
				break
			}
		}
		if hit {
			matches++
			asset, wantSum, filepath = dev.Asset, dev.SHA256, dev.Filepath
		}
	}
	if matches != 1 || asset == "" {
		return "", "", "", fmt.Errorf("the BetterYAM release has no daemon for model %q", modelID)
	}
	return asset, wantSum, filepath, nil
}

// stripDeviceID cuts the four-character device suffix the stations append
// to their hostname (YandexStationMini_729E -> YandexStationMini), the way
// the BetterYAM installer does.
var deviceIDSuffix = regexp.MustCompile(`[-_][A-Z0-9]{4}$`)

func betterYAMModelID(node string) string {
	node = deviceIDSuffix.ReplaceAllString(strings.TrimSpace(node), "")
	model := strings.ToLower(node)
	model = regexp.MustCompile(`[^a-z0-9_-]+`).ReplaceAllString(model, "-")
	model = regexp.MustCompile(`-{2,}`).ReplaceAllString(model, "-")
	model = strings.Trim(model, "-")
	return model
}

func DaemonStatusCmd(ctx context.Context, r Runner, d Daemon) (DaemonStatus, error) {
	installed, err := answeredYes(ctx, r, fmt.Sprintf("[ -x %s/bin/%s ] && echo yes || echo no", d.prefix, d.bin))
	if err != nil {
		return DaemonStatus{}, fmt.Errorf("%s status: %v", d.name, err)
	}
	running, err := answeredYes(ctx, r, fmt.Sprintf("pidof %s >/dev/null 2>&1 && echo yes || echo no", d.bin))
	if err != nil {
		return DaemonStatus{}, fmt.Errorf("%s status: %v", d.name, err)
	}
	autostart, err := answeredYes(ctx, r, fmt.Sprintf("[ -x %s ] && echo yes || echo no", d.init))
	if err != nil {
		return DaemonStatus{}, fmt.Errorf("%s status: %v", d.name, err)
	}
	return DaemonStatus{Installed: installed, Running: running, Autostart: autostart}, nil
}

// runDeviceScript pushes a shell script and runs it inside a read-write
// rootfs window, restoring the read-only mount afterwards.
func runDeviceScript(ctx context.Context, r Runner, name, script string, log Logger) error {
	dir := tempDir()
	local, err := WriteTemp(dir, name, []byte(script))
	if err != nil {
		return err
	}
	remote := "/tmp/" + name
	if err := r.Push(ctx, local, remote); err != nil {
		return fmt.Errorf("push %s: %v", name, err)
	}
	out, err := r.Shell(ctx, "mount -o remount,rw /; sh "+remote+"; rc=$?; rm -f "+remote+
		"; mount -o remount,ro / >/dev/null 2>&1 || true; exit $rc")
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) != "" {
			log.Logf("  %s", strings.TrimSpace(line))
		}
	}
	if err != nil {
		return fmt.Errorf("%s: %v", name, strings.TrimSpace(err.Error()))
	}
	return nil
}

func InstallDaemon(ctx context.Context, r Runner, d Daemon, log Logger) error {
	node, err := run(ctx, r, "uname -n")
	if err != nil {
		return err
	}
	modelID := betterYAMModelID(node)
	log.Logf("station model: %s (manifest id %q)", strings.TrimSpace(node), modelID)

	log.Logf("downloading the BetterYAM release manifest…")
	manifestBody, err := httpGet(ctx, d.release+"/manifest.json")
	if err != nil {
		return fmt.Errorf("manifest: %v", err)
	}
	asset, wantSum, filepath, err := betterYAMSelect(manifestBody, modelID)
	if err != nil {
		return fmt.Errorf("manifest: %v", err)
	}
	log.Logf("daemon build: %s", filepath)

	log.Logf("downloading %s …", asset)
	body, err := downloadVerified(ctx, d.release+"/SHA256SUMS", d.release+"/"+asset, asset)
	if err != nil {
		return err
	}
	if wantSum != "" {
		sum := sha256.Sum256(body)
		if got := hex.EncodeToString(sum[:]); got != strings.ToLower(wantSum) {
			return fmt.Errorf("manifest checksum mismatch for %s", asset)
		}
	}

	dir := tempDir()
	local, err := WriteTemp(dir, d.bin, body)
	if err != nil {
		return err
	}
	remoteBin := d.prefix + "/bin/" + d.bin + ".new"
	log.Logf("uploading %s to %s", d.bin, d.prefix+"/bin/")
	if _, err := r.Shell(ctx, "mkdir -p "+d.prefix+"/bin "+d.prefix+"/data"); err != nil {
		return fmt.Errorf("mkdir: %v", err)
	}
	if err := r.Push(ctx, local, remoteBin); err != nil {
		return fmt.Errorf("push %s: %v", d.bin, err)
	}
	initLocal, err := WriteTemp(dir, d.init[strings.LastIndex(d.init, "/")+1:]+".new", []byte(betterYAMInit))
	if err != nil {
		return err
	}
	if err := r.Push(ctx, initLocal, d.prefix+"/betteryamd.init.new"); err != nil {
		return fmt.Errorf("push init: %v", err)
	}

	log.Logf("swapping the daemon in (their init, staged update with rollback)…")
	if err := runDeviceScript(ctx, r, "betteryam-swap.sh", betterYAMSwap, log); err != nil {
		return fmt.Errorf("%s swap: %v", d.name, err)
	}
	log.Logf("%s running, web UI on port %d", d.name, yamPort)
	return nil
}

func StartDaemon(ctx context.Context, r Runner, d Daemon, log Logger) error {
	st, err := DaemonStatusCmd(ctx, r, d)
	if err != nil {
		return err
	}
	if !st.Installed {
		return fmt.Errorf("%s is not installed", d.name)
	}
	if st.Running {
		log.Logf("%s is already running", d.bin)
		return nil
	}
	log.Logf("starting %s (their init)…", d.bin)
	if _, err := run(ctx, r, d.init+" start"); err != nil {
		return err
	}
	out, err := run(ctx, r, "pidof "+d.bin)
	if err != nil || out == "" {
		return fmt.Errorf("start %s: %v (%s)", d.bin, err, out)
	}
	log.Logf("%s running (pid %s), web UI on port %d", d.name, strings.Fields(out)[0], yamPort)
	return nil
}

func StopDaemon(ctx context.Context, r Runner, d Daemon, log Logger) error {
	log.Logf("stopping %s (their init)…", d.bin)
	_, _ = run(ctx, r, d.init+" stop")
	running, err := answeredYes(ctx, r, "pidof "+d.bin+" >/dev/null 2>&1 && echo yes || echo no")
	if err != nil {
		return err
	}
	if running {
		return fmt.Errorf("stop %s: still running", d.bin)
	}
	log.Logf("%s stopped", d.bin)
	return nil
}

// EnableDaemonAutostart installs the managed init script; Disable removes it
// (only when it carries the BetterYAM marker — a foreign script is refused).
func EnableDaemonAutostart(ctx context.Context, r Runner, d Daemon, log Logger) error {
	st, err := DaemonStatusCmd(ctx, r, d)
	if err != nil {
		return err
	}
	if !st.Installed {
		return fmt.Errorf("%s is not installed", d.name)
	}
	if st.Autostart {
		log.Logf("%s autostart is already on", d.name)
		return nil
	}
	dir := tempDir()
	initLocal, err := WriteTemp(dir, d.init[strings.LastIndex(d.init, "/")+1:]+".new", []byte(betterYAMInit))
	if err != nil {
		return err
	}
	staged := d.prefix + "/betteryamd.init.new"
	log.Logf("staging %s", staged)
	if err := r.Push(ctx, initLocal, staged); err != nil {
		return err
	}
	log.Logf("installing %s (remount rw)", d.init)
	if err := rootfs(ctx, r,
		"cp "+staged+" "+d.init,
		"chmod 755 "+d.init,
		"sync",
		"[ -x "+d.init+" ]",
	); err != nil {
		return fmt.Errorf("install %s: %v", d.init, err)
	}
	log.Logf("%s will start on boot", d.name)
	return nil
}

func DisableDaemonAutostart(ctx context.Context, r Runner, d Daemon, log Logger) error {
	log.Logf("removing %s", d.init)
	if err := rootfs(ctx, r,
		`grep -q '^# Managed by BetterYAM$' `+d.init+` && rm -f `+d.init,
		"rm -f "+d.prefix+"/betteryamd.init.new",
		"sync",
	); err != nil {
		return fmt.Errorf("remove %s: %v", d.init, err)
	}
	log.Logf("%s autostart removed", d.name)
	return nil
}

func UninstallDaemon(ctx context.Context, r Runner, d Daemon, log Logger) error {
	log.Logf("removing %s (their uninstall, managed-init guarded)…", d.name)
	if err := runDeviceScript(ctx, r, "betteryam-uninstall.sh", betterYAMUninstall, log); err != nil {
		return fmt.Errorf("%s uninstall: %v", d.name, err)
	}
	log.Logf("%s removed", d.name)
	return nil
}
