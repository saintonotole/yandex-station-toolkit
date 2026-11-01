package provision

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/saintonotole/yandex-station-toolkit/internal/sshkeys"
)

type fakeRunner struct {
	shell    func(cmd string) (string, error)
	pushes   map[string]string // remote -> local content
	shellLog []string
}

func newFakeRunner(shell func(string) (string, error)) *fakeRunner {
	return &fakeRunner{shell: shell, pushes: map[string]string{}}
}

func (f *fakeRunner) Shell(_ context.Context, cmd string) (string, error) {
	f.shellLog = append(f.shellLog, cmd)
	return f.shell(cmd)
}

func (f *fakeRunner) Push(_ context.Context, local, remote string) error {
	b, err := os.ReadFile(local)
	if err != nil {
		return err
	}
	f.pushes[remote] = string(b)
	return nil
}

func ok(out string) (string, error)  { return out, nil }
func okEmpty(string) (string, error) { return "", nil }

func TestParseOTAStatus(t *testing.T) {
	st := ParseOTAStatus(`== статус обновлений ==
launch.json : updatesd ПРИСУТСТВУЕТ (апдейтер стартует)
applier     : заглушён
ota key     : подменён
-- процессы апдейтера:
   maind --updatesd РАБОТАЕТ`)
	if !st.UpdaterInConf || !st.UpdaterRunning || !st.ApplierStubbed || !st.KeyReplaced {
		t.Fatalf("unblocked parse: %+v", st)
	}
	if st.Blocked() {
		t.Fatal("must not be blocked")
	}

	st = ParseOTAStatus(`launch.json : updatesd убран
applier     : заглушён
ota key     : подменён
   maind --updatesd не запущен`)
	if st.UpdaterInConf || st.UpdaterRunning || !st.Blocked() {
		t.Fatalf("blocked parse: %+v", st)
	}

	// The updater process may still run from a previous boot after the
	// disk was blocked (the launcher starts the role from quasar.cfg);
	// with the key and the applier neutralized it cannot apply anything,
	// so the disk state alone decides the verdict.
	st = ParseOTAStatus(`launch.json : updatesd убран
applier     : заглушён
ota key     : подменён
-- процессы апдейтера:
   maind --updatesd РАБОТАЕТ`)
	if st.UpdaterInConf || !st.UpdaterRunning || !st.ApplierStubbed || !st.KeyReplaced {
		t.Fatalf("leftover-process parse: %+v", st)
	}
	if !st.Blocked() {
		t.Fatal("disk-blocked with a leftover process must count as blocked")
	}
}

func TestBuildInitScript(t *testing.T) {
	s := string(BuildInitScript(DefaultSSHOpts()))
	if !strings.Contains(s, `-D "$DIR"`) {
		t.Fatal("-D (authorized_keys dir) not baked in")
	}
	if strings.Contains(s, "ROOTSSH") || strings.Contains(s, "sync_keys") {
		t.Fatal("home directory key sync must not be used")
	}
	if strings.Contains(s, " -B") {
		t.Fatal("-B (blank password) must NOT be used by default")
	}
	if !strings.Contains(s, "-s 2>>") {
		t.Fatal("-s (disable password auth) missing")
	}
	s2 := string(BuildInitScript(SSHOpts{Port: 2223}))
	if !strings.Contains(s2, "-p 2223 ") {
		t.Fatal("custom port not rendered")
	}
	s3 := string(BuildInitScript(SSHOpts{Port: 2222, AllowBlankPassword: true}))
	dropLine3 := ""
	for _, raw := range strings.Split(s3, "\n") {
		if l := strings.TrimSpace(raw); strings.Contains(l, "\"$DB\"") && strings.Contains(l, " -r ") {
			dropLine3 = l
			break
		}
	}
	if dropLine3 == "" {
		t.Fatal("dropbear invocation line not found")
	}
	if !strings.Contains(dropLine3, " -B ") || strings.Contains(dropLine3, " -s ") {
		t.Fatalf("blank-password mode should use -B not -s on the dropbear line: %q", dropLine3)
	}
}

func TestParseInitScript(t *testing.T) {
	o, ok := ParseInitScript(string(BuildInitScript(SSHOpts{Port: 2222})))
	if !ok || o.Port != 2222 || o.AllowBlankPassword {
		t.Fatalf("key-only parse: %+v ok=%v", o, ok)
	}
	o2, ok := ParseInitScript(string(BuildInitScript(SSHOpts{Port: 2200, AllowBlankPassword: true})))
	if !ok || o2.Port != 2200 || !o2.AllowBlankPassword {
		t.Fatalf("blank-pwd parse: %+v ok=%v", o2, ok)
	}
	if _, ok := ParseInitScript("not a dropbear script"); ok {
		t.Fatal("non-script must not parse")
	}
}

func TestKeysFileContent(t *testing.T) {
	c := keysFileContent([]sshkeys.PubKey{{Type: "ssh-ed25519", Blob: "AA"}})
	if !strings.HasPrefix(c, "#") || !strings.Contains(c, "ssh-ed25519 AA") {
		t.Fatalf("content: %q", c)
	}
}

func TestInstallDropbearSequence(t *testing.T) {
	dir := t.TempDir()
	savedTempDir := tempDir
	tempDir = func() string { return dir }
	defer func() { tempDir = savedTempDir }()

	f := newFakeRunner(func(cmd string) (string, error) {
		switch {
		case strings.Contains(cmd, "id -u"):
			return "0", nil
		case strings.Contains(cmd, "dropbearkey -t"):
			return "generated", nil
		case strings.Contains(cmd, "[ -s /data/opt/etc/dropbear/hk_ed25519 ]"):
			return "ok", nil // host key exists
		case strings.Contains(cmd, "pidof dropbear"):
			return "1234", nil
		case strings.Contains(cmd, "setsid"):
			return "scheduled", nil
		case strings.Contains(cmd, "remount"):
			return "", nil
		default:
			fmt.Println("shell:", cmd)
			return "", nil
		}
	})

	db, _ := WriteTemp(dir, "dropbearmulti", []byte("\x7fELFfake"))
	keys := []sshkeys.PubKey{{Type: "ssh-ed25519", Blob: "AAA", Comment: "t@t"}}

	err := InstallDropbear(context.Background(), f, SSHFiles{Dropbear: db}, keys, DefaultSSHOpts(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}

	joined := strings.Join(f.shellLog, "\n&&\n")
	if strings.Contains(joined, ".ssh/authorized_keys") {
		t.Errorf("must not touch a home directory .ssh: %s", joined)
	}
	for _, want := range []string{
		"id -u",
		"mkdir -p /data/opt/bin /data/opt/etc/dropbear",
		"chmod 755 /data/opt/bin/dropbearmulti",
		"ln -sf dropbearmulti /data/opt/bin/dropbear",
		"ln -sf dropbearmulti /data/opt/bin/dropbearkey",
		"cp /data/opt/etc/dropbear/S99zdropbear /etc/init.d/S99zdropbear",
		"/etc/init.d/S99zdropbear restart",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing command: %q", want)
		}
	}

	if p, okp := f.pushes["/data/opt/bin/dropbearmulti"]; !okp || p != "\x7fELFfake" {
		t.Error("dropbearmulti not pushed")
	}
	if len(f.pushes) != 3 {
		t.Errorf("expected dropbearmulti, authorized_keys and init script only, got %d pushes", len(f.pushes))
	}
	ak, ok := f.pushes["/data/opt/etc/dropbear/authorized_keys"]
	if !ok {
		t.Fatal("authorized_keys not pushed")
	}
	if !strings.Contains(ak, "ssh-ed25519 AAA t@t") {
		t.Fatalf("authorized_keys content: %q", ak)
	}
	init, ok := f.pushes["/data/opt/etc/dropbear/S99zdropbear"]
	if !ok || !strings.Contains(init, `-D "$DIR"`) {
		t.Fatal("init script not staged or missing -D")
	}
}

func TestInstallDropbearMergesExistingKeys(t *testing.T) {
	dir := t.TempDir()
	savedTempDir := tempDir
	tempDir = func() string { return dir }
	defer func() { tempDir = savedTempDir }()

	_, existingLine, err := sshkeys.GenerateEd25519("old@station")
	if err != nil {
		t.Fatal(err)
	}
	f := newFakeRunner(func(cmd string) (string, error) {
		switch {
		case strings.Contains(cmd, "id -u"):
			return "0", nil
		case strings.Contains(cmd, "cat /data/opt/etc/dropbear/authorized_keys"):
			return existingLine + "\n", nil
		case strings.Contains(cmd, "[ -s /data/opt/etc/dropbear/hk_ed25519 ]"):
			return "ok", nil
		case strings.Contains(cmd, "pidof dropbear"):
			return "1234", nil
		case strings.Contains(cmd, "setsid"):
			return "scheduled", nil
		default:
			return "", nil
		}
	})
	db, _ := WriteTemp(dir, "dropbearmulti", []byte("x"))
	_, newLine, err := sshkeys.GenerateEd25519("new@pc")
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := sshkeys.ParseKeyLine(newLine)
	if err != nil {
		t.Fatal(err)
	}
	keys := []sshkeys.PubKey{newKey}

	if err := InstallDropbear(context.Background(), f, SSHFiles{Dropbear: db}, keys, DefaultSSHOpts(), nil); err != nil {
		t.Fatal(err)
	}
	ak := f.pushes["/data/opt/etc/dropbear/authorized_keys"]
	if strings.Count(ak, "ssh-ed25519") != 2 {
		t.Fatalf("dedupe failed: %q", ak)
	}
	if !strings.Contains(ak, "new@pc") || !strings.Contains(ak, "old@station") {
		t.Fatalf("keys missing: %q", ak)
	}
}

func TestInstallDropbearRefusesWithoutKeys(t *testing.T) {
	f := newFakeRunner(okEmpty)
	err := InstallDropbear(context.Background(), f, SSHFiles{Dropbear: "a"}, nil, DefaultSSHOpts(), nil)
	if err == nil {
		t.Fatal("must refuse empty keys")
	}
}

func TestEnsureScriptPushesOnce(t *testing.T) {
	dir := t.TempDir()
	local, _ := WriteTemp(dir, "yandex-noupdate.sh", []byte("#!/bin/sh\n"))
	f := newFakeRunner(func(cmd string) (string, error) {
		if strings.Contains(cmd, "[ -f /data/opt/yandex-noupdate.sh ]") {
			return "no", nil
		}
		return "", nil
	})
	if err := EnsureScript(context.Background(), f, local, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.pushes[RemoteNoUpdate]; !ok {
		t.Fatal("script was not pushed")
	}
	// The second call finds the script already in place.
	if err := EnsureScript(context.Background(), f, local, nil); err != nil {
		t.Fatal(err)
	}
	if len(f.pushes) != 1 {
		t.Fatalf("pushed twice: %v", f.pushes)
	}
}

func TestADBInitLeavesCloudMarkersAlone(t *testing.T) {
	body := string(ADBInitScript())
	if !strings.Contains(body, "/usr/bin/adbd") || !strings.Contains(body, "start-stop-daemon -S") {
		t.Fatalf("script: %s", body)
	}
	if strings.Contains(body, "chattr") || strings.Contains(body, "activate_adb_quasmodrom") {
		t.Fatal("script must not lock or rewrite quasmodrom markers")
	}
	f := newFakeRunner(func(cmd string) (string, error) {
		switch {
		case strings.Contains(cmd, adbInit):
			return "yes", nil
		case strings.Contains(cmd, "pidof adbd"):
			return "no", nil
		default:
			return "", fmt.Errorf("unexpected: %s", cmd)
		}
	})
	st, err := ADBBootStatusCmd(context.Background(), f)
	if err != nil || !st.Autostart || st.Running {
		t.Fatalf("%+v %v", st, err)
	}
}

func TestEnableADBBootInstallsInit(t *testing.T) {
	dir := t.TempDir()
	saved := tempDir
	tempDir = func() string { return dir }
	defer func() { tempDir = saved }()
	f := newFakeRunner(func(cmd string) (string, error) {
		if strings.Contains(cmd, "pidof adbd") {
			return "99\n", nil
		}
		return "", nil
	})
	if err := EnableADBBoot(context.Background(), f, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.pushes[adbInitStaged], "DB=/usr/bin/adbd") {
		t.Fatal("init script was not staged")
	}
	joined := strings.Join(f.shellLog, "\n")
	if !strings.Contains(joined, "mount -o remount,rw /") || strings.Contains(joined, adbInit+" start") {
		t.Fatalf("commands: %s", joined)
	}
}

func TestYAMChecksumsAndProfiles(t *testing.T) {
	sums := "b15893bbad9b247328bec63cbd4c9dd17d7ea9e9a486336da104b7acffe9c152  yam-aarch64-unknown-linux-musl\n" +
		"d1729c7a24555b228aff946335340e4351d817978f2ca01e80e1a367f554bf9d *betteryamd-yandexstationmini-armv7-linux\n"
	if got, ok := checksumFor(sums, "yam-aarch64-unknown-linux-musl"); !ok || len(got) != 64 {
		t.Fatalf("yam sum: %q %v", got, ok)
	}
	if _, ok := checksumFor(sums, "betteryamd-yandexstationmini-armv7-linux"); !ok {
		t.Fatal("star prefix not accepted")
	}
	// The quasar.cfg deviceType values map onto the YAM profile ids.
	for platform, want := range map[string]string{
		"yandexmicro":  "yandexmicro",
		"plum":         "plum",
		"yandexmidi":   "yandexmidi",
		"yandexmini":   "yandexmini",
		"yandexmini_2": "yandexmini_2",
		"bergamot":     "bergamot",
		"pickle":       "pickle",
	} {
		got, err := yamProfileFor(platform)
		if err != nil || got != want {
			t.Fatalf("yamProfileFor(%q) = %q, %v; want %q", platform, got, err, want)
		}
	}
	if _, err := yamProfileFor("chiron"); err == nil {
		t.Fatal("yamProfileFor must reject platforms without a profile")
	}
}

func TestBetterYAMModelAndManifest(t *testing.T) {
	// The device-id suffix is stripped before matching, like the upstream
	// installer does with uname -n.
	if got := betterYAMModelID("YandexStationMini_729E"); got != "yandexstationmini" {
		t.Fatalf("model id: %q", got)
	}
	if got := betterYAMModelID("yandexmicro"); got != "yandexmicro" {
		t.Fatalf("model id: %q", got)
	}
	manifest := []byte(`{"devices":[
		{"device":"yandexstationmini","asset":"betteryamd-mini-armv7-linux","sha256sum":"aaa","filepath":"daemons/mini"},
		{"device":"yandexmicro","models":["yandexmicro","yandex-station-lite"],"asset":"betteryamd-lite-aarch64-linux","sha256sum":"bbb","filepath":"daemons/lite"}
	]}`)
	asset, sum, filepath, err := betterYAMSelect(manifest, "yandexstationmini")
	if err != nil || asset != "betteryamd-mini-armv7-linux" || sum != "aaa" || filepath != "daemons/mini" {
		t.Fatalf("select mini: %q %q %q %v", asset, sum, filepath, err)
	}
	if _, _, _, err := betterYAMSelect(manifest, "yandexmicro"); err != nil {
		t.Fatalf("select lite (models list): %v", err)
	}
	if _, _, _, err := betterYAMSelect(manifest, "yandexstation2"); err == nil {
		t.Fatal("select must fail for a model without a daemon")
	}
}

func TestBetterYAMInitAndSwap(t *testing.T) {
	if !strings.Contains(betterYAMInit, "# Managed by BetterYAM") ||
		!strings.Contains(betterYAMInit, "/data/quazar/betteryam") ||
		!strings.Contains(betterYAMInit, "--data-dir") {
		t.Fatalf("init: %s", betterYAMInit)
	}
	// The swap refuses an init script that BetterYAM does not manage.
	if !strings.Contains(betterYAMSwap, "Refusing to replace unmanaged init script") ||
		!strings.Contains(betterYAMSwap, "betteryamd.previous") {
		t.Fatalf("swap: %s", betterYAMSwap)
	}
}

func TestPushCommandKeepsUnixSlashes(t *testing.T) {
	got := pushCommand("/data/opt/bin/dropbear")
	want := "mkdir -p '/data/opt/bin' && cat > '/data/opt/bin/dropbear.new' && chmod 755 '/data/opt/bin/dropbear.new' && mv -f '/data/opt/bin/dropbear.new' '/data/opt/bin/dropbear'"
	if got != want {
		t.Fatalf("push command: %s", got)
	}
}
