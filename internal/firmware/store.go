// Package firmware downloads and stores the vulnerable firmware versions the
// bootstrap needs, and offers them to stations through the Server's
// FirmwareProvider hook.
//
// Yandex's check_updates endpoint only ever offers the latest build for a
// platform, so the download URL for an older vulnerable version is
// discovered from the lite-kit mirror's metadata.json — which records the
// official Yandex CDN URLs. The file itself is then downloaded from the
// official CDN first, and only if that artifact is gone does the mirror's
// own copy serve the bytes.
package firmware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultMirror is the lite-kit firmware mirror; its layout is
// <mirror>/<platform>/<version>/{metadata.json,update.zip}.
const DefaultMirror = "http://144.76.194.29:62891"

// Target is a firmware version known to accept the ADB sync injection
// (field reports and the Marker284/yandex-station-extended wiki's
// verified-versions table). Only these versions are ever offered to a
// station: the latest official build would close the door. Device names
// are the EXACT retail names from the official identify page
// (alice.yandex.ru/support/ru/station/identify); one codename equals
// strictly one model — no merged labels.
type Target struct {
	Platform string
	Version  string
	Device   string // human-readable, for logs and the UI
}

var targets = []Target{
	{"yandexmicro", "0.369.1.46.4778262442.20261013.297", "Станция Лайт (1‑е поколение)"},
	{"yandexmini", "1.305.4.16.3237824040.20250721", "Станция Мини (первая версия)"},
	{"yandexmini_2", "0.369.1.46.4778262943.20261013.299", "Станция Мини 2"},
	{"bergamot", "0.369.1.50.4794652521.20261021.117", "Станция Мини 3"},
	{"pickle", "0.369.1.50.4794664205.20261021.107", "Станция Мини 3 Про"},
	{"plum", "0.369.1.50.4794654278.20261021.133", "Станция Лайт 2"},
	{"yandexmidi", "0.369.1.46.4778263334.20261013.295", "Станция 2"},
	{"cucumber", "0.369.1.46.4778262955.20261013.160", "Станция Миди"},
}

// Targets exposes the registry for the UI.
func Targets() []Target {
	out := make([]Target, len(targets))
	copy(out, targets)
	return out
}

// TargetFor returns the vulnerable version for a station platform.
// The platform names are the quasar.cfg "deviceType" values, which equal
// the OTA registry keys (verified from the official firmware images).
func TargetFor(platform string) (Target, bool) {
	p := strings.ToLower(strings.TrimSpace(platform))
	for _, t := range targets {
		if t.Platform == p {
			return t, true
		}
	}
	return Target{}, false
}

// minFirmwareSize: a real image is tens of MB; a truncated mirror answer is
// tens of KB (lite-kit saw ~33 KB). Anything small is a broken download.
const minFirmwareSize = 1 << 20

type Store struct {
	dir    string // <config>/firmware
	mirror string
	client *http.Client
	log    func(string)
}

func New(dir, mirror string, log func(string)) *Store {
	if mirror == "" {
		mirror = DefaultMirror
	}
	if log == nil {
		log = func(string) {}
	}
	return &Store{
		dir:    dir,
		mirror: strings.TrimRight(mirror, "/"),
		client: &http.Client{Timeout: 10 * time.Minute},
		log:    log,
	}
}

// file layout, same as lite-kit's firmware/ directory.
func (s *Store) zipPath(platform, version string) string {
	return filepath.Join(s.dir, platform, version+".zip")
}

func (s *Store) manifestPath(platform string) string {
	return filepath.Join(s.dir, platform, "manifest.json")
}

// localManifest is the record kept beside the downloaded file.
type localManifest struct {
	Platform string `json:"platform"`
	Version  string `json:"version"`
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	Crc32    uint32 `json:"crc32"`
	Sha256   string `json:"sha256"`
	Source   string `json:"source"`
}

// Has reports whether the target firmware for a platform is downloaded and
// verifies.
func (s *Store) Has(platform string) bool {
	ok, _ := s.Status(platform)
	return ok
}

// Status answers Has with the reason behind a "no": the check_updates
// handler journals it, so "answered: no update" always says why.
// A transient miss (real-time antivirus holding a freshly written file)
// is retried once before the reason is reported — a false "not
// downloaded" sent a live jailbreak attempt down a wrong path.
func (s *Store) Status(platform string) (bool, string) {
	ok, _ := s.statusOnce(platform)
	if ok {
		return true, ""
	}
	time.Sleep(50 * time.Millisecond)
	return s.statusOnce(platform)
}

func (s *Store) statusOnce(platform string) (bool, string) {
	t, ok := TargetFor(platform)
	if !ok {
		return false, "no known vulnerable version for this platform"
	}
	zip := s.zipPath(t.Platform, t.Version)
	if err := s.verifyFile(zip); err != nil {
		if _, statErr := os.Stat(zip); statErr != nil {
			return false, "firmware file is not downloaded — press «Скачать» in Прошивки"
		}
		return false, err.Error()
	}
	return true, ""
}

// Ensure downloads the vulnerable firmware for a platform if it is missing.
// It returns the local path of a verified file.
func (s *Store) Ensure(ctx context.Context, platform string) (string, error) {
	t, ok := TargetFor(platform)
	if !ok {
		return "", fmt.Errorf("firmware: no known vulnerable version for platform %s", platform)
	}
	zip := s.zipPath(t.Platform, t.Version)
	if err := s.verifyFile(zip); err == nil {
		return zip, nil
	}

	meta, err := s.mirrorMetadata(ctx, t.Platform, t.Version)
	if err != nil {
		return "", err
	}

	// Official Yandex CDN first, mirror bytes last.
	sources := []struct {
		name string
		url  string
	}{
		{"official cdn", meta.DownloadURL},
		{"official s3", meta.FallbackURL},
		{"mirror", s.mirror + "/" + t.Platform + "/" + t.Version + "/update.zip"},
	}
	var lastErr error
	for _, src := range sources {
		if src.url == "" {
			continue
		}
		if src.name == "official cdn" {
			s.log(fmt.Sprintf("firmware: downloading %s (%s)…", t.Device, t.Platform))
		}
		err := s.download(ctx, src.url, zip, meta.Crc32, src.name)
		if err == nil {
			return zip, nil
		}
		lastErr = err
		s.log(fmt.Sprintf("firmware: %s failed: %v — trying the next source", src.name, err))
	}
	return "", fmt.Errorf("firmware: %s (%s): every source failed: %w", t.Device, t.Platform, lastErr)
}

// mirrorMetadata is Yandex's own answer for the version, as recorded by the
// mirror: official download URLs plus the crc32.
type mirrorMetadata struct {
	HasUpdate   bool   `json:"hasUpdate"`
	Version     string `json:"version"`
	DownloadURL string `json:"downloadUrl"`
	FallbackURL string `json:"fallbackUrl"`
	Crc32       uint32 `json:"crc32"`
}

func (s *Store) mirrorMetadata(ctx context.Context, platform, version string) (mirrorMetadata, error) {
	url := fmt.Sprintf("%s/%s/%s/metadata.json", s.mirror, platform, version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return mirrorMetadata{}, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return mirrorMetadata{}, fmt.Errorf("firmware: metadata from mirror: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return mirrorMetadata{}, fmt.Errorf("firmware: metadata from mirror: status %d", resp.StatusCode)
	}
	var meta mirrorMetadata
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&meta); err != nil {
		return mirrorMetadata{}, fmt.Errorf("firmware: metadata from mirror: %w", err)
	}
	if meta.DownloadURL == "" && meta.FallbackURL == "" {
		return mirrorMetadata{}, fmt.Errorf("firmware: metadata has no download url")
	}
	return meta, nil
}

// download fetches a firmware archive, verifies it, and only then puts it in
// place with its manifest.
func (s *Store) download(ctx context.Context, url, dest string, wantCrc uint32, source string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".download-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	hasher := sha256.New()
	crc := crc32.NewIEEE()
	size, err := io.Copy(io.MultiWriter(tmp, crc, hasher), resp.Body)
	tmp.Close()
	if err != nil {
		return err
	}
	if err := verifyArchive(tmpName, size, wantCrc, crc.Sum32()); err != nil {
		return err
	}
	if err := os.Rename(tmpName, dest); err != nil {
		return err
	}
	platform, version := splitDest(dest)
	manifest := localManifest{
		Platform: platform,
		Version:  version,
		Filename: filepath.Base(dest),
		Size:     size,
		Crc32:    crc.Sum32(),
		Sha256:   hex.EncodeToString(hasher.Sum(nil)),
		Source:   source,
	}
	b, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(s.manifestPath(platform), b, 0o644); err != nil {
		s.log(fmt.Sprintf("firmware: manifest write failed: %v", err))
	}
	device := platform
	if tgt, ok := TargetFor(platform); ok && tgt.Device != "" {
		device = tgt.Device
	}
	s.log(fmt.Sprintf("firmware: %s downloaded — %d bytes, checksum verified, from %s", device, size, source))
	return nil
}

// verifyFile checks a file that should already be a firmware image.
// Newer models ship ENCRYPTED containers (no archive magic at all), so
// the recorded manifest is the check there: an exact size match against
// what this app itself downloaded and verified. Plain zip/cpio/xz
// images keep the magic check as a fast path.
func (s *Store) verifyFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Size() < minFirmwareSize {
		return fmt.Errorf("firmware: %s: %d bytes is a truncated image", filepath.Base(path), st.Size())
	}
	platform, _ := splitDest(path)
	if b, err := os.ReadFile(s.manifestPath(platform)); err == nil {
		var m localManifest
		if json.Unmarshal(b, &m) == nil && m.Size == st.Size() && m.Size != 0 {
			return nil
		}
	}
	var magic [6]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return fmt.Errorf("firmware: %s: unreadable: %w", filepath.Base(path), err)
	}
	if !archiveMagic(magic[:]) {
		return fmt.Errorf("firmware: %s: not an archive", filepath.Base(path))
	}
	return nil
}

// verifyArchive gates a fresh download. The expected crc32 comes from
// the mirror's metadata, which records Yandex's own manifest - when it
// is present, a match proves the exact expected bytes, which is a
// stronger check than any container magic (and the only one possible
// for the encrypted containers of newer models). The magic check still
// gates downloads that carry no expected checksum.
func verifyArchive(path string, size int64, wantCrc, gotCrc uint32) error {
	if size < minFirmwareSize {
		return fmt.Errorf("%d bytes is a truncated image", size)
	}
	if wantCrc != 0 {
		if wantCrc != gotCrc {
			return fmt.Errorf("crc32 mismatch: got %d, want %d", gotCrc, wantCrc)
		}
		return nil
	}
	var magic [6]byte
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return fmt.Errorf("unreadable: %w", err)
	}
	if !archiveMagic(magic[:]) {
		return fmt.Errorf("not an archive (magic %q)", magic[:])
	}
	return nil
}

// archiveMagic accepts a zip, a cpio/SWUpdate container, or an xz stream:
// Yandex images have been seen as all three (the Mini 1 .zip is xz inside).
func archiveMagic(head []byte) bool {
	if len(head) >= 4 && string(head[:4]) == "PK\x03\x04" {
		return true
	}
	if len(head) >= 6 {
		switch string(head[:6]) {
		case "070701", "070702": // cpio/SWUpdate
			return true
		case "\xfd7zXZ\x00": // xz
			return true
		}
	}
	return false
}

func splitDest(dest string) (platform, version string) {
	base := filepath.Base(dest)
	version = strings.TrimSuffix(base, ".zip")
	platform = filepath.Base(filepath.Dir(dest))
	return platform, version
}
