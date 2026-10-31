package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/saintonotole/yandex-station-toolkit/internal/adb"
	"github.com/saintonotole/yandex-station-toolkit/internal/discover"
	"github.com/saintonotole/yandex-station-toolkit/internal/firmware"
	"github.com/saintonotole/yandex-station-toolkit/internal/nicknames"
	"github.com/saintonotole/yandex-station-toolkit/internal/provision"
	"github.com/saintonotole/yandex-station-toolkit/internal/settings"
	"github.com/saintonotole/yandex-station-toolkit/internal/sshkeys"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/crypto/ssh"
)

type App struct {
	ctx      context.Context
	mu       sync.Mutex
	busy     bool
	adb      *adb.Client
	adbMu    sync.Mutex // serializes adb resolution (may block on a dialog/download)
	devices  map[string]*discover.Device
	privKey  string // last generated / selected private key path
	nicks    *nicknames.Store
	settings *settings.Store

	statsMu sync.Mutex // one overview poll at a time; guards stats
	stats   *statsConn

	askSeq      int64
	pendingAsks map[int64]chan bool
	adbDeclined bool // one rejection of the adb download is final until restart

	shellMu      sync.Mutex // guards shell and shellOpening (one console session at a time)
	shell        *shellSession
	shellOpening bool

	fw        *firmware.Store
	serverctl *serverCtl

	jbWatchers map[string]bool // in-flight automated jailbreak finishes, by device id
}

func newApp() *App {
	dir := configDir()
	a := &App{
		devices:  map[string]*discover.Device{},
		nicks:    nicknames.New(dir),
		settings: settings.New(dir),
		fw:       firmware.New(filepath.Join(dir, "firmware"), "", nil),
	}
	a.serverctl = newServerCtl(a)
	return a
}

// allowSSHAgent reports whether discovery and provisioning may try the
// system SSH agent's keys against a station.
func (a *App) allowSSHAgent() bool {
	return a.settings.Get().AllowSSHAgent
}

func configDir() string {
	base := os.TempDir()
	if v := os.Getenv("LOCALAPPDATA"); v != "" {
		base = v
	} else if home, err := os.UserHomeDir(); err == nil {
		base = filepath.Join(home, ".config")
	}
	dir := filepath.Join(base, "YandexStationToolKit")
	legacy := filepath.Join(base, "YandexStationTool")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if _, err := os.Stat(legacy); err == nil {
			return legacy
		}
	}
	return dir
}

func (a *App) log(level, msg string) {
	msg = strings.Map(func(r rune) rune {
		if r == '\n' {
			return r
		}
		if r == '\t' {
			return ' '
		}
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, msg)
	ts := time.Now()
	a.emit("log", map[string]any{"level": level, "msg": msg, "ts": ts.Format("15:04:05")})
	a.logToFile(ts, level, msg)
}

// logToFile appends the journal line to <configDir>/journal.log so the
// story survives app restarts and can be read without copy-paste. The
// file rotates at 5 MiB into journal.log.old.
func (a *App) logToFile(ts time.Time, level, msg string) {
	dir := configDir()
	_ = os.MkdirAll(dir, 0o755)
	path := filepath.Join(dir, "journal.log")
	if st, err := os.Stat(path); err == nil && st.Size() > 5<<20 {
		_ = os.Rename(path, filepath.Join(configDir(), "journal.log.old"))
	}
	line := fmt.Sprintf("%s %s %s\n", ts.Format("2006-01-02 15:04:05"), level, msg)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(line)
}

func (a *App) emit(name string, data any) {
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, name, data)
	}
}

func (a *App) setBusy(on bool, what string) {
	a.mu.Lock()
	a.busy = on
	a.mu.Unlock()
	a.emit("busy", map[string]any{"on": on, "what": what})
}

func (a *App) isBusy() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.busy
}

// Startup is called by wails once the frontend is ready.
func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx
	a.privKey = defaultPrivKeyPath()

	events := map[string]func(map[string]any){
		"scan":               a.onScan,
		"connect":            a.onConnect,
		"ota":                a.onOTA,
		"ssh":                a.onSSH,
		"yse":                a.onYSE,
		"yam":                a.onYAM,
		"betteryam":          func(m map[string]any) { a.onDaemon(m, provision.BetterYAM, "byamStatus") },
		"adbboot":            a.onADBBoot,
		"genkey":             a.onGenKey,
		"reboot":             a.onReboot,
		"setNickname":        a.onSetNickname,
		"setColor":           a.onSetColor,
		"pickkey":            a.onPickKey,
		"inspectkey":         a.onInspectKey,
		"setSSHAgentAllowed": a.onSetSSHAgentAllowed,
		"cleanup":            a.onCleanup,
		"askUIResult":        a.onAskUIResult,
		"stats":              a.onStats,
		"shell":              a.onShell,
		"Server":             a.onServer,
	}
	for name, h := range events {
		runtime.EventsOn(ctx, name, func(data ...any) {
			m, _ := data[0].(map[string]any)
			h(m)
		})
	}

	a.emit("state", map[string]any{
		"version":       version,
		"payloads":      payloadStatus(),
		"privKey":       a.privKey,
		"allowSSHAgent": a.allowSSHAgent(),
	})
	// The UI renders adapter checkboxes before the first scan.
	if ifaces, err := discover.LocalInterfaces(); err == nil {
		a.emit("adapters", map[string]any{"list": ifaces})
	}
	a.emitCleanupState()
	a.log("info", fmt.Sprintf("Yandex Station ToolKit %s started", version))
	go a.checkADB()
}

// checkADB looks for adb on PATH or a previously downloaded copy, without
// offering to download it, and logs the result. ADB-dependent features stay
// disabled until adb is found or the user agrees to download it.
func (a *App) checkADB() {
	logf := func(msg string) { a.log("info", msg) }
	c, err := adb.Ensure(configDir(), logf)
	if err != nil {
		a.log("warn", "adb: not found — adb features are disabled until it is installed or downloaded")
		return
	}
	a.mu.Lock()
	a.adb = c
	a.mu.Unlock()
	// One readable line instead of the raw "adb version" command echo.
	ctx := adb.Quiet(context.Background())
	if v, err := c.Version(ctx); err == nil {
		if ver := adb.VersionNumber(v); ver != "" {
			a.log("info", "adb "+ver+" ready")
		} else {
			a.log("info", "adb ready")
		}
	}
}

func (a *App) onSetSSHAgentAllowed(m map[string]any) {
	allow, _ := m["allow"].(bool)
	if err := a.settings.SetAllowSSHAgent(allow); err != nil {
		a.log("warn", "cannot save settings: "+err.Error())
	}
	if allow {
		a.log("info", "ssh-agent authentication is now allowed for discovery")
	} else {
		a.log("info", "ssh-agent authentication is now disabled for discovery")
	}
}

// onCleanup removes the app's downloaded external helpers — the
// platform-tools copy and the firmware files — after the UI's
// confirmation dialog. "status" only reports their sizes. A PATH adb is
// never touched: only the copy inside the config directory goes.
func (a *App) onCleanup(m map[string]any) {
	if action, _ := m["action"].(string); action != "run" {
		a.emitCleanupState()
		return
	}
	// adb.exe cannot be deleted while the server is running.
	a.adb.KillServer()
	for _, d := range []struct{ name, path string }{
		{"platform-tools", filepath.Join(configDir(), "platform-tools")},
		{"firmware", filepath.Join(configDir(), "firmware")},
	} {
		if fi, err := os.Stat(d.path); err != nil || !fi.IsDir() {
			continue
		}
		if err := os.RemoveAll(d.path); err != nil {
			a.log("err", "cleanup: "+d.name+": "+err.Error())
			continue
		}
		a.log("info", "cleanup: removed "+d.name)
	}
	a.mu.Lock()
	a.adb = nil
	a.mu.Unlock()
	a.emitCleanupState()
}

// emitCleanupState reports how much disk the downloaded helpers occupy.
func (a *App) emitCleanupState() {
	a.emit("cleanupState", map[string]any{
		"adbBytes": dirBytes(filepath.Join(configDir(), "platform-tools")),
		"fwBytes":  dirBytes(filepath.Join(configDir(), "firmware")),
	})
}

// dirBytes sums the file sizes under dir; 0 when it does not exist.
func dirBytes(dir string) int64 {
	var sum int64
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d != nil && !d.IsDir() {
			if info, e := d.Info(); e == nil {
				sum += info.Size()
			}
		}
		return nil
	})
	return sum
}

func (a *App) Shutdown(ctx context.Context) {
	a.shellClose()
	a.serverctl.shutdown()
	a.adb.KillServer()
}

// onActivation starts the automated post-activation flow the moment the
// dns server delivers an ADB activation to a station: the jailbreak
// command has been accepted, and the rest — waiting for adb, watching
// the firmware version through reboots, persisting adb autostart,
// disabling OTA and rebooting — runs by itself.
func (a *App) onActivation(remoteIP, deviceID string) {
	ip := hostOfRemote(remoteIP)
	key := deviceID
	if key == "" {
		key = "ip:" + ip
	}
	a.mu.Lock()
	if a.jbWatchers == nil {
		a.jbWatchers = map[string]bool{}
	}
	if a.jbWatchers[key] {
		a.mu.Unlock()
		return
	}
	a.jbWatchers[key] = true
	a.mu.Unlock()
	a.log("info", fmt.Sprintf("jailbreak: ADB activation delivered to %s — finishing the setup automatically", ip))
	go a.autoFinishJailbreak(key, ip, deviceID)
}

func hostOfRemote(remote string) string {
	if h, _, err := net.SplitHostPort(remote); err == nil {
		return h
	}
	return remote
}

// autoFinishJailbreak walks a freshly activated speaker to the finished
// state: adb available, firmware on the target build, adb autostart
// persisted, OTA disabled, then a reboot. Reboots and DHCP IP changes
// on the way are expected and tolerated.
func (a *App) autoFinishJailbreak(key, ip, deviceID string) {
	defer func() {
		a.mu.Lock()
		delete(a.jbWatchers, key)
		a.mu.Unlock()
	}()
	deadline := time.Now().Add(30 * time.Minute)
	const poll = 5 * time.Second
	lastVersion := ""
	failStreak := 0
	announcedADB := false
	announcedVersion := false

	for time.Now().Before(deadline) {
		// An open console owns the device: poll bursts knock small adbd
		// instances offline (same rule as the resource poll).
		if a.shellActive() {
			time.Sleep(poll)
			continue
		}

		c := a.adbClient()
		if c == nil {
			var err error
			c, err = a.ensureADB()
			if err != nil {
				a.log("warn", "jailbreak: waiting for adb to become available")
				time.Sleep(poll)
				continue
			}
		}

		if err := c.ConnectFast(context.Background(), ip); err != nil {
			failStreak++
			if failStreak == 3 {
				a.log("info", fmt.Sprintf("jailbreak: %s is not answering adb — looking for the speaker on the network (reboots move it to a new address)", ip))
				if newIP := a.relocateSpeaker(ip, deviceID); newIP != "" && newIP != ip {
					a.log("info", fmt.Sprintf("jailbreak: the speaker is now at %s", newIP))
					ip = newIP
				}
				failStreak = 0
			}
			time.Sleep(poll)
			continue
		}
		failStreak = 0
		if !announcedADB {
			announcedADB = true
			a.log("info", fmt.Sprintf("jailbreak: adb is available at %s", ip))
		}

		ctx := adb.Quiet(context.Background())
		fw, err := c.Shell(ctx, ip, "cat /system/vendor/quasar/version_full")
		fw = strings.TrimSpace(strings.Trim(fw, "\x00"))
		if err != nil || fw == "" {
			// A reboot in progress or a flaky adbd — retry.
			time.Sleep(poll)
			continue
		}
		if fw != lastVersion {
			lastVersion = fw
			a.log("info", fmt.Sprintf("jailbreak: the speaker runs firmware %s", fw))
		}

		platform := a.platformOf(ip, deviceID)
		target, ok := firmware.TargetFor(platform)
		if !ok {
			a.log("warn", fmt.Sprintf("jailbreak: platform %s has no known target firmware — leaving the version as it is", platform))
		} else if !firmware.SameVersion(fw, target.Version) {
			if !announcedVersion {
				announcedVersion = true
				a.log("info", fmt.Sprintf("jailbreak: waiting for the firmware downgrade to %s", firmware.ShortVersion(target.Version)))
			}
			time.Sleep(poll)
			continue
		}
		announcedVersion = false

		// The goal state: adb up + the target firmware. Finish the setup.
		a.log("info", fmt.Sprintf("jailbreak: firmware matches the target — persisting adb autostart, ssh and the OTA block"))
		r := &deviceRunner{c: c, ip: ip}
		pctx := context.Background()
		plog := provision.Logger(func(msg string) { a.log("info", "jailbreak: "+msg) })

		boot, err := provision.ADBBootStatusCmd(pctx, r)
		if err == nil && !boot.Autostart {
			if err := provision.EnableADBBoot(pctx, r, plog); err != nil {
				a.log("err", "jailbreak: adb autostart: "+err.Error())
				time.Sleep(poll)
				continue
			}
			a.speakPhrase(c, ip, "Отладка включена")
		}

		// Passwordless keyless SSH: the durable remote channel for
		// everything the owner does next. Installed only when it is not
		// there yet.
		_, sshInstalled, sshErr := provision.ReadDropbearConfig(pctx, r)
		if sshErr != nil {
			plog.Logf("ssh status: %v", sshErr)
		}
		if !sshInstalled {
			dropbearPayload, err := payload(payloadDropbear)
			if err != nil {
				a.log("err", "jailbreak: "+err.Error())
				return
			}
			dir, _ := os.MkdirTemp("", "yandex-station-toolkit-jb-*")
			defer os.RemoveAll(dir)
			dbLocal, err := provision.WriteTemp(dir, "dropbearmulti", dropbearPayload)
			if err != nil {
				a.log("err", "jailbreak: "+err.Error())
				return
			}
			plog.Logf("installing passwordless ssh on :2222")
			if err := provision.InstallDropbear(pctx, r, provision.SSHFiles{Dropbear: dbLocal}, nil, provision.SSHOpts{Port: 2222, AllowBlankPassword: true}, plog); err != nil {
				a.log("err", "jailbreak: ssh install: "+err.Error())
			} else {
				a.speakPhrase(c, ip, "Удалённый доступ включён")
			}
		}

		script, err := payload(payloadNoUpdate)
		if err != nil {
			a.log("err", "jailbreak: "+err.Error())
			return
		}
		dir, _ := os.MkdirTemp("", "yandex-station-toolkit-jb-*")
		defer os.RemoveAll(dir)
		local, err := provision.WriteTemp(dir, "yandex-noupdate.sh", script)
		if err != nil {
			a.log("err", "jailbreak: "+err.Error())
			return
		}
		ota, err := provision.OTAStatusCmd(pctx, r, local, plog)
		if err != nil {
			a.log("err", "jailbreak: ota status: "+err.Error())
			time.Sleep(poll)
			continue
		}
		if !ota.Blocked() {
			if _, err := provision.OTAInstall(pctx, r, local, plog); err != nil {
				a.log("err", "jailbreak: ota: "+err.Error())
				time.Sleep(poll)
				continue
			}
		}

		a.log("info", "jailbreak: everything is in place — rebooting the speaker")
		if err := provision.Reboot(pctx, r, plog); err != nil {
			a.log("err", "jailbreak: reboot: "+err.Error())
			time.Sleep(poll)
			continue
		}
		a.verifyFinished(key, ip, deviceID, deadline)
		return
	}
	a.log("warn", "jailbreak: gave up after 30 minutes — the manual steps remain on the Jailbreak page")
}

// relocateSpeaker re-runs the station discovery and returns the new
// address of the speaker with the same device id.
func (a *App) relocateSpeaker(oldIP, deviceID string) string {
	if deviceID == "" {
		return "" // nothing stable to match on
	}
	nets, err := discover.LocalNetworks()
	if err != nil {
		return ""
	}
	devices := discover.ScanStations(context.Background(), nets, nil)
	for _, d := range devices {
		if d.DeviceID == deviceID && d.IP != oldIP {
			return d.IP
		}
	}
	return ""
}

// platformOf resolves the platform through mDNS, with a retry — the
// speaker answers mDNS whenever it is up.
func (a *App) platformOf(ip, deviceID string) string {
	if d := a.knownDevice(ip, deviceID); d != nil && d.Platform != "" {
		return d.Platform
	}
	infos := discover.ResolveMDNS(context.Background(), []string{ip}, 1200*time.Millisecond, 1)
	if info, ok := infos[ip]; ok && info.Platform != "" {
		return info.Platform
	}
	return ""
}

// knownDevice finds the device map entry for an ip or a device id.
func (a *App) knownDevice(ip, deviceID string) *discover.Device {
	a.mu.Lock()
	defer a.mu.Unlock()
	if d, ok := a.devices[ip]; ok && d != nil {
		if deviceID == "" || d.DeviceID == deviceID || d.DeviceID == "" {
			return d
		}
	}
	if deviceID != "" {
		for _, d := range a.devices {
			if d != nil && d.DeviceID == deviceID {
				return d
			}
		}
	}
	return nil
}

// finishPhrase is spoken by the speaker itself (Alice cloud TTS through
// the station's local IPC) when the automated jailbreak finishes.
const finishPhrase = "Взлом завершён, обновления отключены"

// speakFinish announces the finished jailbreak with the speaker's own
// voice. The station's quasar IPC lives on its loopback (127.0.0.1:9875),
// so it is tunneled: adb forward first, an SSH channel as the fallback.
// A failure here is a missing flourish, never a failed jailbreak; a
// protocol error on a working tunnel is NOT retried over ssh — the
// phrase would announce twice.
func (a *App) speakFinish(c *adb.Client, ip string) {
	a.speakPhrase(c, ip, finishPhrase)
}

// speakPhrase speaks text with the speaker's own Alice voice. The
// station's quasar IPC lives on its loopback (127.0.0.1:9875), so it is
// tunneled: adb forward first, an SSH channel as the fallback.
func (a *App) speakPhrase(c *adb.Client, ip, text string) {
	ctx := context.Background()
	plog := provision.Logger(func(msg string) { a.log("info", "jailbreak: "+msg) })

	if c != nil {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			a.log("info", "jailbreak: no free port for the tts tunnel: "+err.Error())
		} else {
			port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
			listener.Close()
			if err := c.Forward(ctx, ip, port, 9875); err != nil {
				a.log("info", "jailbreak: tts tunnel: "+err.Error())
			} else {
				conn, derr := net.Dial("tcp", "127.0.0.1:"+port)
				if derr != nil {
					a.log("info", "jailbreak: tts tunnel dial: "+derr.Error())
				} else if verr := provision.AliceVocalizeConn(ctx, conn, text, 30*time.Second, plog); verr == nil {
					_ = conn.Close()
					c.RemoveForward(ctx, ip, port)
					a.log("ok", "jailbreak: the speaker announced: "+text)
					return
				} else {
					// The tunnel worked and the protocol was answered —
					// a replay over ssh would announce the phrase twice.
					a.log("info", "jailbreak: "+verr.Error())
				}
				_ = conn.Close()
				c.RemoveForward(ctx, ip, port)
			}
		}
	}

	client := a.sshTunnelClient(ip)
	if client == nil {
		a.log("info", "jailbreak: no tts tunnel — adb forwarding and ssh are both unavailable")
		return
	}
	defer client.Close()
	conn, err := client.Dial("tcp", "127.0.0.1:9875")
	if err != nil {
		a.log("info", "jailbreak: ssh tunnel dial: "+err.Error())
		return
	}
	defer conn.Close()
	if err := provision.AliceVocalizeConn(ctx, conn, text, 30*time.Second, plog); err != nil {
		a.log("info", "jailbreak: "+err.Error())
		return
	}
	a.log("ok", "jailbreak: the speaker announced: "+text+" (ssh tunnel)")
}

// sshTunnelClient establishes an SSH session to the speaker for the IPC
// tunnel: passwordless root (the exploit state), then the app's own
// generated key (the key-only dropbear it installs), then the agent
// when the owner allowed it.
func (a *App) sshTunnelClient(ip string) *ssh.Client {
	for _, port := range sshkeys.SSHPorts {
		if client, err := sshkeys.TryNoneAuth(ip, port, "root", 6*time.Second); err == nil {
			a.log("info", fmt.Sprintf("jailbreak: ssh tunnel via passwordless root on port %d", port))
			return client
		}
	}
	if a.privKey != "" {
		if signer, err := sshkeys.LoadPrivateKey(a.privKey, ""); err == nil {
			auth := ssh.PublicKeys(signer)
			for _, port := range sshkeys.SSHPorts {
				if client, err := sshkeys.Connect(ip, port, "root", auth, 6*time.Second); err == nil {
					a.log("info", fmt.Sprintf("jailbreak: ssh tunnel via the app key on port %d", port))
					return client
				}
			}
		}
	}
	if a.allowSSHAgent() && sshkeys.AgentAvailable(ip) {
		for _, port := range sshkeys.SSHPorts {
			if client, err := sshkeys.TryAgentAuth(ip, port, 6*time.Second); err == nil {
				a.log("info", fmt.Sprintf("jailbreak: ssh tunnel via the agent on port %d", port))
				return client
			}
		}
	}
	return nil
}

// verifyFinished waits out the reboot and confirms the finished state
// once: adb answers again, the autostart script is installed, OTA is
// blocked and the firmware is on target.
func (a *App) verifyFinished(key, ip, deviceID string, deadline time.Time) {
	a.log("info", "jailbreak: waiting for the speaker to come back from the reboot")
	time.Sleep(25 * time.Second)
	for time.Now().Before(deadline) {
		if a.shellActive() {
			time.Sleep(5 * time.Second)
			continue
		}
		c := a.adbClient()
		if c == nil {
			return
		}
		if err := c.ConnectFast(context.Background(), ip); err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		r := &deviceRunner{c: c, ip: ip}
		pctx := adb.Quiet(context.Background())
		boot, err := provision.ADBBootStatusCmd(pctx, r)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		dir, _ := os.MkdirTemp("", "yandex-station-toolkit-jb-*")
		defer os.RemoveAll(dir)
		script, err := payload(payloadNoUpdate)
		if err != nil {
			return
		}
		local, err := provision.WriteTemp(dir, "yandex-noupdate.sh", script)
		if err != nil {
			return
		}
		ota, err := provision.OTAStatusCmd(pctx, r, local, provision.Logger(func(string) {}))
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		if boot.Autostart && ota.Blocked() {
			a.log("ok", fmt.Sprintf("jailbreak: %s is done — adb autostart persists, OTA is blocked, firmware is on target", ip))
			a.speakFinish(c, ip)
			return
		}
		a.log("warn", fmt.Sprintf("jailbreak: %s is back but the finished state is incomplete (autostart: %v, ota blocked: %v)", ip, boot.Autostart, ota.Blocked()))
		return
	}
}

// adbClient returns the cached adb client, or looks one up on PATH / the
// configured download directory without offering to download it. It returns
// nil when adb is unavailable, so callers can fall back to SSH instead of
// treating a missing adb as an error.
func (a *App) adbClient() *adb.Client {
	a.mu.Lock()
	c := a.adb
	a.mu.Unlock()
	if c != nil {
		return c
	}
	c, err := adb.Ensure(configDir(), nil)
	if err != nil {
		return nil
	}
	a.mu.Lock()
	a.adb = c
	a.mu.Unlock()
	return c
}

// ensureADB is like adbClient, but offers to download adb when it is
// missing. Reserved for explicit actions where no other channel worked.
func (a *App) ensureADB() (*adb.Client, error) {
	a.adbMu.Lock()
	defer a.adbMu.Unlock()
	a.mu.Lock()
	c := a.adb
	a.mu.Unlock()
	if c != nil {
		return c, nil
	}
	logf := func(msg string) { a.log("info", msg) }
	c, err := adb.Ensure(configDir(), logf)
	downloaded := false
	if errors.Is(err, adb.ErrNotFound) {
		if _, uerr := adb.DownloadURL(); uerr != nil {
			return nil, uerr
		}
		if !a.confirmADBDownload() {
			return nil, errors.New("adb is not installed: download declined")
		}
		c, err = adb.Download(context.Background(), configDir(), logf)
		downloaded = err == nil
	}
	if err != nil {
		return nil, err
	}
	if v, err := c.Version(context.Background()); err == nil {
		a.log("info", v)
	}
	a.mu.Lock()
	a.adb = c
	a.mu.Unlock()
	if downloaded {
		a.recheckADB(c)
	}
	return c, nil
}

// confirmADBDownload shows the IN-APP confirmation card (the app's modal,
// not a native OS window) and remembers a rejection for the rest of the
// session, so one "no" is final until the app restarts.
func (a *App) confirmADBDownload() bool {
	if a.adbDeclined {
		return false
	}
	ok := a.askUI("adb не найден в PATH. Скачать?")
	if !ok {
		a.adbDeclined = true
		a.log("info", "adb: download declined — not asking again until the app restarts")
	}
	return ok
}

// askUI shows the in-app ask card from a goroutine and waits for the
// answer. The frontend renders its modal and replies with "askUIResult".
func (a *App) askUI(question string) bool {
	if a.ctx == nil {
		return false
	}
	a.mu.Lock()
	a.askSeq++
	id := a.askSeq
	if a.pendingAsks == nil {
		a.pendingAsks = map[int64]chan bool{}
	}
	ch := make(chan bool, 1)
	a.pendingAsks[id] = ch
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(a.pendingAsks, id)
		a.mu.Unlock()
	}()
	runtime.EventsEmit(a.ctx, "askUI", map[string]any{"id": id, "question": question})
	ok, oked := <-ch
	return oked && ok
}

// onAskUIResult delivers the modal's answer to the waiting goroutine.
func (a *App) onAskUIResult(m map[string]any) {
	id, _ := m["id"].(float64)
	ok, _ := m["ok"].(bool)
	a.mu.Lock()
	ch := a.pendingAsks[int64(id)]
	a.mu.Unlock()
	if ch != nil {
		ch <- ok
	}
}

// recheckADB identifies discovered devices whose ADB port was open but could
// not be used before adb was downloaded.
func (a *App) recheckADB(c *adb.Client) {
	a.mu.Lock()
	list := discover.SortedDevices(a.devices)
	a.mu.Unlock()
	n := 0
	for _, d := range list {
		if !d.HasADB() || d.IdentVia == "adb" {
			continue
		}
		n++
		d.ADBPending = false
		a.log("info", "identifying "+d.IP+" over adb…")
		// Quiet: the command echo is noise; failures carry their own context.
		if err := discover.Identify(adb.Quiet(context.Background()), c, d, func(string) {}); err != nil {
			a.log("warn", d.IP+": "+err.Error())
			continue
		}
		d.IdentErr = ""
		a.noteYSE(d, &deviceRunner{c: c, ip: d.IP})
	}
	if n > 0 {
		a.emitDevices()
		a.log("info", fmt.Sprintf("adb recheck: %d device(s)", n))
	}
}

// runnerFor returns a cleanup function that callers must defer.
func (a *App) runnerFor(ip string) (provision.Runner, *discover.Device, func(), error) {
	a.mu.Lock()
	d := a.devices[ip]
	a.mu.Unlock()
	if d == nil {
		d = &discover.Device{IP: ip, Ports: map[int]bool{}}
	}
	noop := func() {}

	// 1) ADB — already open, no login attempt needed.
	if d.HasADB() {
		if c := a.adbClient(); c != nil {
			if err := c.Connect(context.Background(), ip); err == nil {
				a.log("info", "channel: ADB")
				return &deviceRunner{c: c, ip: ip}, d, noop, nil
			}
		}
	}

	// 2) SSH passwordless root.
	if d.HasAnySSH() {
		for _, port := range sshkeys.SSHPorts {
			if !d.Ports[port] {
				continue
			}
			client, err := sshkeys.TryNoneAuth(ip, port, "root", 6*time.Second)
			if err == nil {
				a.log("info", fmt.Sprintf("channel: SSH %d (passwordless root)", port))
				r := &provision.SSHRunner{Client: client}
				return r, d, func() { _ = r.Close() }, nil
			}
			a.log("info", fmt.Sprintf("SSH %d: passwordless login failed (%v)", port, err))
		}

		// 3) SSH via the system ssh-agent, opt-in only.
		if a.allowSSHAgent() && sshkeys.AgentAvailable(ip) {
			for _, port := range sshkeys.SSHPorts {
				if !d.Ports[port] {
					continue
				}
				client, err := sshkeys.TryAgentAuth(ip, port, 6*time.Second)
				if err == nil {
					a.log("info", fmt.Sprintf("channel: SSH %d (agent)", port))
					r := &provision.SSHRunner{Client: client}
					return r, d, func() { _ = r.Close() }, nil
				}
				a.log("info", fmt.Sprintf("SSH %d: agent auth failed (%v)", port, err))
			}
		} else if a.allowSSHAgent() {
			a.log("info", "ssh-agent is not running — skipping agent keys")
		}
	}

	// 4) Last resort: adb is the only open channel but is not installed yet.
	if d.HasADB() {
		c, err := a.ensureADB()
		if err != nil {
			return nil, d, noop, err
		}
		if err := c.Connect(context.Background(), ip); err != nil {
			return nil, d, noop, err
		}
		a.log("info", "channel: ADB (downloaded)")
		return &deviceRunner{c: c, ip: ip}, d, noop, nil
	}

	return nil, d, noop, fmt.Errorf("%s: no usable channel — the ADB/SSH ports found at the scan are closed now, rescan the network", ip)
}

type deviceRunner struct {
	c  *adb.Client
	ip string
}

func (r *deviceRunner) Shell(ctx context.Context, cmd string) (string, error) {
	return r.c.Shell(ctx, r.ip, cmd)
}

func (r *deviceRunner) Push(ctx context.Context, local, remote string) error {
	return r.c.Push(ctx, r.ip, local, remote)
}

func str(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func (a *App) onScan(m map[string]any) {
	if a.isBusy() {
		a.log("warn", "busy: another operation is still running")
		return
	}
	go func() {
		a.setBusy(true, "Сканирование сети")
		defer a.setBusy(false, "")

		ifaces, err := discover.LocalInterfaces()
		if err != nil {
			a.log("err", "cannot list network interfaces: "+err.Error())
			return
		}
		a.emit("adapters", map[string]any{"list": ifaces})

		// An empty selection scans physical adapters only.
		enabledNames := []string{}
		if v, ok := m["adapters"].([]any); ok {
			for _, x := range v {
				if s, ok := x.(string); ok {
					enabledNames = append(enabledNames, s)
				}
			}
		}
		nets := discover.NetworksForInterfaces(enabledNames)
		for _, n := range nets {
			a.log("info", "scanning "+n.String()+"…")
		}
		if len(nets) == 0 {
			a.log("err", "no usable networks — enable an adapter")
			return
		}

		// probedTotal: how many addresses the scan actually knocked on —
		// the denominator that makes the "hosts answered" count readable.
		// Two-step discovery: only glagol+mDNS survivors come back, so
		// everything in the map is a Yandex station by construction.
		probedTotal := 0
		found := discover.ScanStations(context.Background(), nets,
			func(checked, total, n int) {
				if total > probedTotal {
					probedTotal = total
				}
				a.emit("scanProgress", map[string]any{"checked": checked, "total": total, "found": n})
			})

		devices := map[string]*discover.Device{}
		for ip, d := range found {
			devices[ip] = d
		}
		a.mu.Lock()
		a.devices = devices
		a.mu.Unlock()

		for _, d := range discover.SortedDevices(devices) {
			a.log("info", fmt.Sprintf("%s: Yandex station found (platform %s)", d.IP, d.Platform))
			if d.Model == "" {
				d.Model = discover.PlatformModel(d.Platform)
			}
			if d.Model == "" {
				d.Model = discover.HostnameModel(d.Hostname)
			}
			if d.Model == "" {
				d.Model = discover.ModelName(d.Compat, d.Model)
			}
		}

		// The glagol+mDNS pair settled Yandex-ness; record which side
		// proved it and fill the identity fields the UI keeps.
		for _, d := range devices {
			mdns := d.MDNSYandex()
			glagol := d.LooksYandex()
			d.IsYandex = mdns || glagol
			switch {
			case mdns && glagol:
				d.YandexVia = "mdns+glagol"
			case mdns:
				d.YandexVia = "mdns"
			case glagol:
				d.YandexVia = "glagol"
			}
			// The glagol sweep populated the neighbor table, so the MAC
			// is known even without a shell channel — it identifies the
			// device for nicknames when mDNS gave no deviceId.
			if d.IsYandex && d.MAC == "" {
				d.MAC = discover.ARPMAC(d.IP)
			}
			if d.Nickname == "" {
				d.Nickname = a.nicks.Lookup(d.DeviceID, d.MAC)
			}
			if d.Color == "" {
				d.Color = a.nicks.LookupColor(d.DeviceID, d.MAC)
			}
		}

		var sshCount, adbCount, lockedCount int
		for _, d := range discover.SortedDevices(devices) {
			if a.identifyDevice(d) {
				if d.IdentVia == "adb" {
					adbCount++
				} else {
					sshCount++
				}
			} else if d.ADBPending || d.SSHLocked {
				lockedCount++
			}
		}

		a.emitDevices()
		a.log("info", fmt.Sprintf("scan finished: %d Yandex stations (adb: %d, ssh: %d, not configured yet: %d); %d addresses were checked for the glagol port, the rest of the network was not queried",
			len(devices), adbCount, sshCount, lockedCount, probedTotal))
	}()
}

// identifyDevice tries the discovery channels in priority order — ADB
// (already open, no login attempt), then passwordless SSH, then SSH via the
// system agent if the user opted in — and sets the markers the UI uses for
// a port that is open but not currently usable.
func (a *App) identifyDevice(d *discover.Device) bool {
	if d.HasADB() {
		c := a.adbClient()
		if c == nil {
			d.ADBPending = true
			a.log("info", d.IP+": adb port is open, but adb is not installed")
		} else {
			a.log("info", "identifying "+d.IP+" over adb…")
			// Quiet: the command echo is noise; failures carry their own context.
			if err := discover.Identify(adb.Quiet(context.Background()), c, d, func(string) {}); err != nil {
				a.log("warn", d.IP+": "+err.Error())
			} else {
				a.noteYSE(d, &deviceRunner{c: c, ip: d.IP})
				return true
			}
		}
	}

	if d.HasAnySSH() {
		a.log("info", "identifying "+d.IP+" over ssh…")
		if a.identifyViaSSHNoAuth(d) {
			return true
		}
		if a.allowSSHAgent() {
			if sshkeys.AgentAvailable(d.IP) {
				if a.identifyViaSSHAgent(d) {
					return true
				}
			} else {
				a.log("info", d.IP+": ssh-agent auth is allowed, but no agent is reachable")
			}
		}
		d.SSHLocked = true
	}
	return false
}

func (a *App) identifyViaSSHNoAuth(d *discover.Device) bool {
	for _, port := range sshkeys.SSHPorts {
		if !d.Ports[port] {
			continue
		}
		client, err := sshkeys.TryNoneAuth(d.IP, port, "root", 6*time.Second)
		if err != nil {
			a.log("info", fmt.Sprintf("%s:%d: passwordless login failed (%v)", d.IP, port, err))
			continue
		}
		defer client.Close()
		a.log("info", fmt.Sprintf("%s:%d: passwordless root login (%s) — collecting info", d.IP, port, client.ServerVersion()))
		if a.finishIdentifyViaSSH(d, client, "ssh") {
			return true
		}
	}
	return false
}

func (a *App) identifyViaSSHAgent(d *discover.Device) bool {
	for _, port := range sshkeys.SSHPorts {
		if !d.Ports[port] {
			continue
		}
		client, err := sshkeys.TryAgentAuth(d.IP, port, 6*time.Second)
		if err != nil {
			a.log("info", fmt.Sprintf("%s:%d: agent auth failed (%v)", d.IP, port, err))
			continue
		}
		defer client.Close()
		a.log("info", fmt.Sprintf("%s:%d: agent key login (%s) — collecting info", d.IP, port, client.ServerVersion()))
		if a.finishIdentifyViaSSH(d, client, "ssh-agent") {
			return true
		}
	}
	return false
}

func (a *App) finishIdentifyViaSSH(d *discover.Device, client *ssh.Client, via string) bool {
	err := discover.Collect(func(cmd string) (string, error) {
		return (&provision.SSHRunner{Client: client}).Shell(context.Background(), cmd)
	}, d)
	if err != nil {
		a.log("warn", d.IP+": identify failed: "+err.Error())
		return false
	}
	d.IdentVia = via
	d.Root = true
	d.RootKnown = true
	a.noteYSE(d, &provision.SSHRunner{Client: client})
	a.log("ok", fmt.Sprintf("%s: %s — fw %s, root access via %s", d.IP, d.Model, d.Firmware, via))
	return true
}

func (a *App) noteYSE(d *discover.Device, r provision.Runner) {
	// Quiet: the yse presence check is a per-device detail; its command
	// echo would spam every scan.
	installed, err := provision.IsYSEInstalled(adb.Quiet(context.Background()), r)
	if err != nil {
		return
	}
	d.YSEKnown = true
	d.YSEInstalled = installed
}

func (a *App) emitDevices() {
	a.mu.Lock()
	list := discover.SortedDevices(a.devices)
	a.mu.Unlock()
	for _, d := range list {
		d.SKU = discover.RetailSKU(d.Model)
		d.Colors = discover.ModelColors(d.Model)
		d.Icon = discover.ModelIcon(d.Model)
		d.Icons = discover.ModelColorIcons(d.Model)
	}
	a.emit("devices", map[string]any{"list": list})
	a.emitFirmwareTargets()
}

func (a *App) onConnect(m map[string]any) {
	ip := str(m, "ip")
	if ip == "" {
		return
	}
	if a.isBusy() {
		a.log("warn", "busy: another operation is still running")
		return
	}
	go func() {
		a.setBusy(true, "Подключение к "+ip)
		defer a.setBusy(false, "")

		// mDNS fills hostname/platform/deviceId even when ADB is down.
		infos := discover.ResolveMDNS(context.Background(), []string{ip}, 1200*time.Millisecond, 2)
		d := &discover.Device{IP: ip, Ports: map[int]bool{}}
		if info, ok := infos[ip]; ok {
			d.Hostname = info.Hostname
			d.Platform = info.Platform
			d.DeviceID = info.DeviceID
			if d.Model == "" {
				d.Model = discover.HostnameModel(d.Hostname)
			}
			if d.Model == "" {
				d.Model = discover.ModelName(d.Compat, d.Model)
			}
		}
		// A manually entered IP is trusted to be a station.
		d.IsYandex = true

		for _, port := range []int{discover.PortADB, discover.PortSSH, discover.PortSSHStock, discover.PortGlagol} {
			if discover.PortOpen(ip, port, 700*time.Millisecond) {
				d.Ports[port] = true
			}
		}
		if !d.HasADB() && !d.HasAnySSH() {
			a.log("err", "no ADB or SSH port answered: "+ip)
			return
		}
		// The port probes above populated the neighbor table; the MAC
		// identifies the device when mDNS gave no deviceId.
		if d.MAC == "" {
			d.MAC = discover.ARPMAC(ip)
		}
		if d.Nickname == "" {
			d.Nickname = a.nicks.Lookup(d.DeviceID, d.MAC)
		}
		if d.Color == "" {
			d.Color = a.nicks.LookupColor(d.DeviceID, d.MAC)
		}

		ok := a.identifyDevice(d)
		a.mu.Lock()
		a.devices[ip] = d
		a.mu.Unlock()
		a.emitDevices()
		switch {
		case ok:
			a.log("ok", "connected via "+d.IdentVia+": "+ip)
		case d.ADBPending || d.SSHLocked:
			a.log("warn", ip+": a channel port is open, but no usable channel was found (see the device list)")
		default:
			a.log("err", "could not connect over ADB or SSH: "+ip)
		}
	}()
}

func (a *App) onOTA(m map[string]any) {
	ip, action := str(m, "ip"), str(m, "action")
	if ip == "" || a.isBusy() {
		return
	}
	go func() {
		a.setBusy(true, "OTA: "+action+" ("+ip+")")
		defer a.setBusy(false, "")
		r, _, cleanup, err := a.runnerFor(ip)
		if err != nil {
			a.log("err", err.Error())
			return
		}
		defer cleanup()
		script, err := payload(payloadNoUpdate)
		if err != nil {
			a.log("err", err.Error())
			return
		}
		dir, _ := os.MkdirTemp("", "yandex-station-toolkit-ota-*")
		defer os.RemoveAll(dir)
		local, err := provision.WriteTemp(dir, "yandex-noupdate.sh", script)
		if err != nil {
			a.log("err", err.Error())
			return
		}
		log := provision.Logger(func(msg string) { a.log("info", msg) })
		ctx := context.Background()

		// otaStatusDetail journals the raw status lines: the verdict
		// without its evidence sent one debugging session down a wrong
		// path.
		otaStatusDetail := func(st provision.OTAStatus) {
			for _, line := range strings.Split(st.Raw, "\n") {
				if l := strings.TrimSpace(line); l != "" && !strings.HasPrefix(l, "==") {
					a.log("info", "ota: "+l)
				}
			}
		}
		otaNotBlockedReasons := func(st provision.OTAStatus) string {
			var why []string
			if st.UpdaterInConf {
				why = append(why, "launch.json still has the updater task")
			}
			if !st.ApplierStubbed {
				why = append(why, "the applier script is stock")
			}
			if !st.KeyReplaced {
				why = append(why, "the OTA signature key is stock")
			}
			return strings.Join(why, "; ")
		}

		switch action {
		case "disable":
			st, err := provision.OTAInstall(ctx, r, local, log)
			a.emitOTAStatus(ip, st)
			if err != nil {
				a.log("err", err.Error())
				return
			}
			otaStatusDetail(st)
			if st.Blocked() {
				a.log("ok", "updates are blocked on the disk — reboot the speaker to apply")
			} else {
				a.log("warn", "updates are not blocked: "+otaNotBlockedReasons(st))
			}
		case "status":
			st, err := provision.OTAStatusCmd(ctx, r, local, log)
			a.emitOTAStatus(ip, st)
			if err != nil {
				a.log("err", err.Error())
				return
			}
			otaStatusDetail(st)
			if st.Blocked() {
				if st.UpdaterRunning {
					// The process predates the edit; with the key and the
					// applier neutralized it cannot apply anything.
					a.log("ok", "updates are blocked on the disk; the updater process is still running from the previous boot and applies nothing")
				} else {
					a.log("ok", "updates are blocked")
				}
			} else {
				a.log("warn", "updates are not blocked: "+otaNotBlockedReasons(st))
			}
		case "restore":
			if err := provision.OTARestore(ctx, r, local, log); err != nil {
				a.log("err", err.Error())
				return
			}
			a.log("ok", "factory update settings restored; reboot the speaker")
		}
	}()
}

func (a *App) emitOTAStatus(ip string, st provision.OTAStatus) {
	a.emit("otaStatus", map[string]any{"ip": ip, "status": st})
}

func (a *App) onSSH(m map[string]any) {
	ip, action := str(m, "ip"), str(m, "action")
	if ip == "" || a.isBusy() {
		return
	}
	go func() {
		a.setBusy(true, "SSH: "+action+" ("+ip+")")
		defer a.setBusy(false, "")
		ctx := context.Background()
		log := provision.Logger(func(msg string) { a.log("info", msg) })

		switch action {
		case "install":
			a.sshInstall(ctx, ip, m, log)
		case "uninstall":
			r, _, cleanup, err := a.runnerFor(ip)
			if err != nil {
				a.log("err", err.Error())
				return
			}
			defer cleanup()
			if err := provision.UninstallDropbear(ctx, r, log); err != nil {
				a.log("err", err.Error())
				return
			}
		case "test":
			a.sshTest(ctx, ip, str(m, "via"), str(m, "privateKey"), str(m, "passphrase"))
		case "status":
			a.sshStatus(ctx, ip)
		}
	}()
}

func (a *App) sshStatus(ctx context.Context, ip string) {
	r, _, cleanup, err := a.runnerFor(ip)
	if err != nil {
		a.log("err", err.Error())
		return
	}
	defer cleanup()
	opts, installed, err := provision.ReadDropbearConfig(ctx, r)
	if err != nil {
		a.log("warn", "reading SSH config: "+err.Error())
	}
	keys, err := provision.ReadAuthorizedKeys(ctx, r)
	if err != nil {
		a.log("warn", "reading authorized_keys: "+err.Error())
	}
	a.emit("sshStatus", map[string]any{
		"ip":        ip,
		"installed": installed,
		"port":      opts.Port,
		"blankPwd":  opts.AllowBlankPassword,
		"keys":      keys,
	})
}

func (a *App) sshInstall(ctx context.Context, ip string, m map[string]any, log provision.Logger) {
	port := 2222
	switch str(m, "portMode") {
	case "22":
		port = 22
	case "custom":
		if p := str(m, "portCustom"); p != "" {
			var n int
			fmt.Sscanf(p, "%d", &n)
			if n > 0 && n < 65536 {
				port = n
			} else {
				a.log("err", "custom port is not a number, using 2222")
			}
		}
	}
	allowBlank := str(m, "security") == "blank"
	opts := provision.SSHOpts{Port: port, AllowBlankPassword: allowBlank}

	var keys []sshkeys.PubKey
	if t := str(m, "keys"); t != "" {
		ks, err := sshkeys.ParseAuthorizedKeys(t)
		if err != nil {
			a.log("err", "keys: "+err.Error())
			return
		}
		keys = append(keys, ks...)
	}
	if gh := str(m, "githubUser"); gh != "" {
		a.log("info", "fetching SSH keys for GitHub user "+gh+"…")
		ghKeys, err := sshkeys.FetchGitHubKeys(ctx, gh)
		if err != nil {
			a.log("err", err.Error())
			return
		}
		a.log("info", fmt.Sprintf("GitHub: imported %d key(s)", len(ghKeys)))
		keys = append(keys, ghKeys...)
	}
	if len(keys) == 0 && !allowBlank {
		// Blank-password installs need no keys: dropbear starts with -B.
		a.log("err", "provide at least one public key or a GitHub user")
		return
	}
	keys = sshkeys.MergeKeys(nil, keys)
	r, _, cleanup, err := a.runnerFor(ip)
	if err != nil {
		a.log("err", err.Error())
		return
	}
	defer cleanup()
	dropbear, err := payload(payloadDropbear)
	if err != nil {
		a.log("err", err.Error())
		return
	}
	dir, _ := os.MkdirTemp("", "yandex-station-toolkit-ssh-*")
	defer os.RemoveAll(dir)
	dbLocal, err := provision.WriteTemp(dir, "dropbearmulti", dropbear)
	if err != nil {
		a.log("err", err.Error())
		return
	}
	if err := provision.InstallDropbear(ctx, r, provision.SSHFiles{Dropbear: dbLocal}, keys, opts, log); err != nil {
		a.log("err", err.Error())
		return
	}
	// The restart is scheduled one second after the SSH command returns,
	// then dropbear needs a moment to bind the port again.
	time.Sleep(3 * time.Second)
	banner, err := sshkeys.Banner(ip, opts.Port, 4*time.Second)
	if err != nil {
		a.log("warn", fmt.Sprintf("SSH port %d did not answer: %v", opts.Port, err))
		return
	}
	a.log("ok", "SSH is up: "+banner)

	a.mu.Lock()
	if d := a.devices[ip]; d != nil {
		d.Ports[opts.Port] = true
	}
	a.mu.Unlock()
	a.emitDevices()

	if pk := a.privKey; pk != "" {
		if signer, err := sshkeys.LoadPrivateKey(pk, ""); err == nil {
			if msg, err := sshkeys.TestAuth(ip, opts.Port, "root", signer, 6*time.Second); err == nil {
				a.log("ok", msg)
				a.emit("sshTest", map[string]any{"ip": ip, "ok": true, "msg": msg})
				return
			}
			a.log("warn", "login check: "+err.Error())
		}
	}
	a.emit("sshTest", map[string]any{"ip": ip, "ok": true, "msg": fmt.Sprintf("server answers; check login manually: ssh -p %d root@%s", opts.Port, ip)})
}

func (a *App) sshTest(ctx context.Context, ip, via, material, passphrase string) {
	probe, perr := sshkeys.ProbeSSH(ip, 4*time.Second)
	if perr != nil {
		a.log("err", perr.Error())
		a.emit("sshTest", map[string]any{"ip": ip, "ok": false, "msg": perr.Error()})
		return
	}
	a.log("info", fmt.Sprintf("SSH server: %s on port %d", probe.Banner, probe.Port))

	switch via {
	case "agent":
		client, err := sshkeys.TryAgentAuth(ip, probe.Port, 6*time.Second)
		if err != nil {
			a.log("err", "agent: "+err.Error())
			a.emit("sshTest", map[string]any{"ip": ip, "ok": false, "msg": err.Error()})
			return
		}
		defer client.Close()
		msg, err := sshkeys.ConfirmSession(client)
		if err != nil {
			a.log("err", "login failed: "+err.Error())
			a.emit("sshTest", map[string]any{"ip": ip, "ok": false, "msg": err.Error()})
			return
		}
		a.log("ok", msg)
		a.emit("sshTest", map[string]any{"ip": ip, "ok": true, "msg": msg})
	default:
		if material == "" {
			material = a.privKey
		}
		if material == "" {
			a.log("err", "no private key given")
			a.emit("sshTest", map[string]any{"ip": ip, "ok": false, "msg": "no private key given"})
			return
		}
		var signer ssh.Signer
		var err error
		if strings.Contains(material, "PRIVATE KEY") {
			signer, err = sshkeys.ParsePrivateKeyBytes([]byte(material), passphrase)
		} else {
			signer, err = sshkeys.LoadPrivateKey(material, passphrase)
		}
		if err != nil {
			a.log("err", err.Error())
			a.emit("sshTest", map[string]any{"ip": ip, "ok": false, "needPass": strings.Contains(err.Error(), "passphrase"), "msg": err.Error()})
			return
		}
		msg, err := sshkeys.TestAuth(ip, probe.Port, "root", signer, 6*time.Second)
		if err != nil {
			a.log("err", "login failed: "+err.Error())
			a.emit("sshTest", map[string]any{"ip": ip, "ok": false, "msg": err.Error()})
			return
		}
		a.log("ok", msg)
		a.emit("sshTest", map[string]any{"ip": ip, "ok": true, "msg": msg})
	}
}

func (a *App) onInspectKey(m map[string]any) {
	material := str(m, "material")
	if material == "" {
		a.emit("keyInfo", map[string]any{"encrypted": false})
		return
	}
	var data []byte
	var err error
	if str(m, "via") == "file" {
		data, err = os.ReadFile(material)
	} else {
		data = []byte(material)
	}
	if err != nil {
		a.emit("keyInfo", map[string]any{"encrypted": false, "err": err.Error()})
		return
	}
	_, err = sshkeys.ParsePrivateKeyBytes(data, "")
	encrypted := err != nil && strings.Contains(err.Error(), "passphrase")
	a.emit("keyInfo", map[string]any{"encrypted": encrypted})
}

func (a *App) onPickKey(map[string]any) {
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Приватный ключ SSH",
	})
	if err != nil {
		a.log("err", err.Error())
		return
	}
	if path == "" {
		return
	}
	a.emit("pickKey", map[string]any{"path": path})
}

func defaultPrivKeyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	path := filepath.Join(home, ".ssh", "yandex_station_toolkit_ed25519")
	legacy := filepath.Join(home, ".ssh", "station_tool_ed25519")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if _, err := os.Stat(legacy); err == nil {
			return legacy
		}
	}
	return path
}

// ensureAppKey returns the app's ed25519 keypair, generating it when
// missing. The private key never leaves this computer.
func (a *App) ensureAppKey() (privPath, pubLine string, err error) {
	path := defaultPrivKeyPath()
	if path == "" {
		return "", "", fmt.Errorf("cannot determine the home directory")
	}
	if pub, err := os.ReadFile(path + ".pub"); err == nil && len(pub) > 0 {
		a.privKey = path
		return path, strings.TrimSpace(string(pub)), nil
	}
	priv, pub, err := sshkeys.GenerateEd25519("Yandex Station ToolKit")
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(path, []byte(priv), 0o600); err != nil {
		return "", "", fmt.Errorf("cannot write the private key: %v", err)
	}
	if err := os.WriteFile(path+".pub", []byte(pub+"\n"), 0o644); err != nil {
		return "", "", err
	}
	a.privKey = path
	a.log("ok", "key created: "+path+" (the private key stays on this computer)")
	return path, pub, nil
}

func (a *App) onGenKey(m map[string]any) {
	if a.isBusy() {
		return
	}
	go func() {
		a.setBusy(true, "Генерация ключа")
		defer a.setBusy(false, "")

		path, existed := "", false
		if p := defaultPrivKeyPath(); p != "" {
			if _, err := os.Stat(p); err == nil {
				existed = true
			}
			path = p
		}
		if path == "" {
			a.log("err", "cannot determine the home directory")
			return
		}
		privPath, pub, err := a.ensureAppKey()
		if err != nil {
			a.log("err", err.Error())
			return
		}
		if existed {
			a.log("info", "key already exists: "+path)
		}
		a.emit("genkey", map[string]any{"pub": pub, "path": privPath})
	}()
}

func (a *App) onReboot(m map[string]any) {
	ip := str(m, "ip")
	if ip == "" || a.isBusy() {
		return
	}
	go func() {
		a.setBusy(true, "Перезагрузка "+ip)
		defer a.setBusy(false, "")
		r, _, cleanup, err := a.runnerFor(ip)
		if err != nil {
			a.log("err", err.Error())
			return
		}
		defer cleanup()
		if err := provision.Reboot(context.Background(), r, provision.Logger(func(msg string) { a.log("info", msg) })); err != nil {
			a.log("warn", err.Error())
			return
		}
		a.log("ok", "speaker is rebooting; wait a minute and scan again")
	}()
}

func (a *App) onSetNickname(m map[string]any) {
	ip := str(m, "ip")
	nick := str(m, "nickname")
	if ip == "" {
		return
	}
	a.mu.Lock()
	d := a.devices[ip]
	a.mu.Unlock()
	if d == nil {
		a.log("err", "device not found: "+ip)
		return
	}
	if err := a.nicks.Set(d.DeviceID, d.MAC, nick); err != nil {
		a.log("err", "cannot save nickname: "+err.Error())
		return
	}
	d.Nickname = nick
	a.emitDevices()
	if nick == "" {
		a.log("info", "nickname cleared for "+ip)
	} else {
		a.log("info", "nickname "+nick+" saved for "+ip)
	}
}

func (a *App) onSetColor(m map[string]any) {
	ip := str(m, "ip")
	color := str(m, "color")
	if ip == "" {
		return
	}
	a.mu.Lock()
	d := a.devices[ip]
	a.mu.Unlock()
	if d == nil {
		a.log("err", "device not found: "+ip)
		return
	}
	if err := a.nicks.SetColor(d.DeviceID, d.MAC, color); err != nil {
		a.log("err", "cannot save color: "+err.Error())
		return
	}
	d.Color = color
	a.emitDevices()
	if color == "" {
		a.log("info", "color cleared for "+ip)
	} else {
		a.log("info", "color "+color+" saved for "+ip)
	}
}

// The cloud-managed quasmodrom markers are deliberately left alone.
func (a *App) onADBBoot(m map[string]any) {
	ip, action := str(m, "ip"), str(m, "action")
	if ip == "" {
		return
	}
	if action != "status" && a.isBusy() {
		return
	}
	go func() {
		if action != "status" {
			a.setBusy(true, "ADB: "+action)
			defer a.setBusy(false, "")
		}
		ctx := context.Background()
		log := provision.Logger(func(msg string) { a.log("info", msg) })
		r, _, cleanup, err := a.runnerFor(ip)
		if err != nil {
			a.log("err", err.Error())
			return
		}
		defer cleanup()
		switch action {
		case "start":
			if err := provision.StartADB(ctx, r, log); err != nil {
				a.log("err", err.Error())
			}
		case "stop":
			if err := provision.StopADB(ctx, r, log); err != nil {
				a.log("err", err.Error())
			}
		case "autostart-on":
			if err := provision.EnableADBBoot(ctx, r, log); err != nil {
				a.log("err", err.Error())
			}
		case "autostart-off":
			if err := provision.DisableADBBoot(ctx, r, log); err != nil {
				a.log("err", err.Error())
			}
		case "status":
		default:
			return
		}
		st, err := provision.ADBBootStatusCmd(ctx, r)
		if err != nil {
			a.log("warn", err.Error())
		}
		a.noteADBPort(ip, st.Running)
		a.emit("adbBoot", map[string]any{"ip": ip, "autostart": st.Autostart, "running": st.Running})
	}()
}

func (a *App) noteADBPort(ip string, running bool) {
	a.mu.Lock()
	d := a.devices[ip]
	if d != nil {
		if d.Ports == nil {
			d.Ports = map[int]bool{}
		}
		d.Ports[discover.PortADB] = running
	}
	a.mu.Unlock()
	if d != nil {
		a.emitDevices()
	}
}

// https://hackalice.me/recipes/yam/
func (a *App) onDaemon(m map[string]any, d provision.Daemon, event string) {
	ip, action := str(m, "ip"), str(m, "action")
	if ip == "" {
		return
	}
	if action != "status" && a.isBusy() {
		return
	}
	go func() {
		if action != "status" {
			a.setBusy(true, d.Label()+": "+action)
			defer a.setBusy(false, "")
		}
		ctx := context.Background()
		log := provision.Logger(func(msg string) { a.log("info", msg) })
		r, _, cleanup, err := a.runnerFor(ip)
		if err != nil {
			a.log("err", err.Error())
			return
		}
		defer cleanup()
		switch action {
		case "install":
			if err := provision.InstallDaemon(ctx, r, d, log); err != nil {
				a.log("err", err.Error())
			} else {
				a.log("ok", fmt.Sprintf("%s web UI: http://%s:8099", d.Label(), ip))
			}
		case "uninstall":
			if err := provision.UninstallDaemon(ctx, r, d, log); err != nil {
				a.log("err", err.Error())
			}
		case "start":
			if err := provision.StartDaemon(ctx, r, d, log); err != nil {
				a.log("err", err.Error())
			}
		case "stop":
			if err := provision.StopDaemon(ctx, r, d, log); err != nil {
				a.log("err", err.Error())
			}
		case "autostart-on":
			if err := provision.EnableDaemonAutostart(ctx, r, d, log); err != nil {
				a.log("err", err.Error())
			}
		case "autostart-off":
			if err := provision.DisableDaemonAutostart(ctx, r, d, log); err != nil {
				a.log("err", err.Error())
			}
		case "status":
		default:
			return
		}
		st, err := provision.DaemonStatusCmd(ctx, r, d)
		if err != nil {
			a.log("warn", err.Error())
		}
		a.emit(event, map[string]any{
			"ip": ip, "installed": st.Installed, "running": st.Running, "autostart": st.Autostart,
		})
	}()
}

// https://hackalice.me/start/packages/
func (a *App) onYSE(m map[string]any) {
	ip, action := str(m, "ip"), str(m, "action")
	if ip == "" || a.isBusy() {
		return
	}
	go func() {
		a.setBusy(true, "YSE: "+action+" ("+ip+")")
		defer a.setBusy(false, "")
		ctx := context.Background()
		log := provision.Logger(func(msg string) { a.log("info", msg) })

		r, _, cleanup, err := a.runnerFor(ip)
		if err != nil {
			a.log("err", err.Error())
			return
		}
		defer cleanup()

		switch action {
		case "status":
			installed, err := provision.IsYSEInstalled(ctx, r)
			if err != nil {
				a.log("warn", "yse status: "+err.Error())
			}
			a.emit("yseStatus", map[string]any{"ip": ip, "installed": installed})
		case "install":
			if err := provision.InstallYSE(ctx, r, log); err != nil {
				a.log("err", err.Error())
				return
			}
			a.emit("yseStatus", map[string]any{"ip": ip, "installed": true})
		case "uninstall":
			if err := provision.UninstallYSE(ctx, r, log); err != nil {
				a.log("err", err.Error())
				return
			}
			a.emit("yseStatus", map[string]any{"ip": ip, "installed": false})
		}
	}()
}

// onYAM drives the YAM 0.2 integration: the package manager runs on the
// station itself, so the actions are install/uninstall/status plus the
// optional web-panel package (yam/luna).
func (a *App) onYAM(m map[string]any) {
	ip, action := str(m, "ip"), str(m, "action")
	if ip == "" || a.isBusy() {
		return
	}
	go func() {
		a.setBusy(true, "YAM: "+action+" ("+ip+")")
		defer a.setBusy(false, "")
		ctx := context.Background()
		log := provision.Logger(func(msg string) { a.log("info", msg) })

		r, _, cleanup, err := a.runnerFor(ip)
		if err != nil {
			a.log("err", err.Error())
			return
		}
		defer cleanup()

		switch action {
		case "status":
			installed, err := provision.IsYAMInstalled(ctx, r)
			if err != nil {
				a.log("warn", "yam status: "+err.Error())
			}
			a.emit("yamStatus", map[string]any{"ip": ip, "installed": installed})
		case "install":
			if err := provision.InstallYAM(ctx, r, log, a.platformOf(ip, str(m, "deviceId"))); err != nil {
				a.log("err", err.Error())
				return
			}
			a.emit("yamStatus", map[string]any{"ip": ip, "installed": true})
		case "uninstall":
			if err := provision.UninstallYAM(ctx, r, log); err != nil {
				a.log("err", err.Error())
				return
			}
			a.emit("yamStatus", map[string]any{"ip": ip, "installed": false})
		case "panel":
			if err := provision.InstallYAMPanel(ctx, r, log); err != nil {
				a.log("err", err.Error())
				return
			}
		default:
			return
		}
		if installed, err := provision.IsYAMInstalled(ctx, r); err == nil {
			a.emit("yamStatus", map[string]any{"ip": ip, "installed": installed})
		}
	}()
}
