package firmware

import (
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

// otaManifest is the answer a station expects from check_updates, the same
// shape Yandex itself sends (and lite-kit reproduces).
type otaManifest struct {
	HasUpdate   bool   `json:"hasUpdate"`
	Version     string `json:"version"`
	DownloadURL string `json:"downloadUrl"`
	Crc32       uint32 `json:"crc32"`
	Critical    bool   `json:"critical"`
	FallbackURL string `json:"fallbackUrl"`
	FallbackIP  string `json:"fallbackIp"`
	UpdateID    string `json:"updateId"`
}

// Provider implements the Server's FirmwareProvider on top of the store: it
// offers a downloaded vulnerable build to a station that is not on it yet,
// and serves the file over the local endpoint the DNS hijack points to.
type Provider struct {
	store    *Store
	answerIP func() string
	updateID string
	log      func(string)
}

func NewProvider(store *Store, answerIP func() string, log func(string)) *Provider {
	if log == nil {
		log = func(string) {}
	}
	return &Provider{store: store, answerIP: answerIP, updateID: "150484", log: log}
}

// Update offers the vulnerable target build to a station, or returns nil
// (no update) when the platform has no known target, the file is not
// downloaded, or the station already runs that version. lite-kit's prefix
// rule treats "1.305.4.16…" as matching "1.305.4.16…": a station that
// already got the vulnerable build must not be re-offered it.
//
// Every decision is journaled with its reason — an "answered: no update"
// line without the why sent the first real jailbreak attempt down a
// wrong path (the firmware simply was not downloaded).
func (p *Provider) Update(platform, current string) []byte {
	if platform == "" {
		platform = "unknown"
	}
	t, ok := TargetFor(platform)
	if !ok {
		p.log(fmt.Sprintf("dns server: check_updates for platform %s: no known vulnerable version — hasUpdate:false", platform))
		return nil
	}
	if ok, why := p.store.Status(t.Platform); !ok {
		p.log(fmt.Sprintf("dns server: check_updates for %s: %s — hasUpdate:false", t.Device, why))
		return nil
	}
	if SameVersion(current, t.Version) {
		p.log(fmt.Sprintf("dns server: check_updates for %s: the station already runs the offered build — hasUpdate:false", t.Device))
		return nil
	}
	crc, err := p.store.crc32Of(t.Platform)
	if err != nil {
		p.log(fmt.Sprintf("dns server: check_updates for %s: no checksum available (%v) — hasUpdate:false", t.Device, err))
		return nil
	}
	ran := current
	if ran == "" {
		ran = "factory firmware"
	}
	p.log(fmt.Sprintf("dns server: the station runs %s — offering %s (%s), the download starts next", ran, t.Device, ShortVersion(t.Version)))
	ip := ""
	if p.answerIP != nil {
		ip = p.answerIP()
	}
	// The station resolves quasar.yandex.net to this machine, so these
	// "official" URLs are served from the local endpoint.
	local := fmt.Sprintf("https://quasar.yandex.net/%s/ota/%s.zip", t.Platform, t.Version)
	out, err := json.Marshal(otaManifest{
		HasUpdate:   true,
		Version:     t.Version,
		DownloadURL: local,
		Crc32:       crc,
		Critical:    true,
		FallbackURL: local,
		FallbackIP:  ip,
		UpdateID:    p.updateID,
	})
	if err != nil {
		return nil
	}
	return out
}

// ServeFile delivers the firmware file to a station, with native HTTP Range
// support through http.ServeContent. Returns false when nothing was served.
func (p *Provider) ServeFile(w http.ResponseWriter, r *http.Request, platform, name string) bool {
	if !validServeName(name) {
		return false
	}
	t, ok := TargetFor(platform)
	if !ok {
		return false
	}
	// Only the exact URL the offered manifest carries is ever answered.
	if name != t.Version+".zip" {
		return false
	}
	zip := p.store.zipPath(t.Platform, t.Version)
	f, err := os.Open(zip)
	if err != nil {
		return false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		return false
	}
	w.Header().Set("Content-Type", "application/zip")
	// Count the bytes actually written: ServeContent returns without an
	// error when the station walks away mid-transfer, and "delivered"
	// without the count hid exactly that during the first live run.
	cw := &countingWriter{ResponseWriter: w}
	start := time.Now()
	http.ServeContent(cw, r, name, st.ModTime(), f)
	p.log(fmt.Sprintf("dns server: firmware delivery to %s ended: %d of %d bytes in %.1fs",
		r.RemoteAddr, cw.n, st.Size(), time.Since(start).Seconds()))
	return true
}

// countingWriter counts the payload bytes that reach the response.
type countingWriter struct {
	http.ResponseWriter
	n int64
}

func (c *countingWriter) Write(b []byte) (int, error) {
	n, err := c.ResponseWriter.Write(b)
	c.n += int64(n)
	return n, err
}

// validServeName blocks path traversal: only a bare <version>.zip of the
// registered target is ever served.
func validServeName(name string) bool {
	if name == "" || strings.Contains(name, "/") || strings.Contains(name, "\\") || strings.Contains(name, "..") {
		return false
	}
	if !strings.HasSuffix(name, ".zip") {
		return false
	}
	if path.Clean("/"+name) != "/"+name {
		return false
	}
	return true
}

// ShortVersion renders the first four version groups — enough to tell
// builds apart in the journal; the full string lives in the manifest.
func ShortVersion(v string) string {
	parts := strings.Split(strings.TrimSpace(v), ".")
	if len(parts) > 4 {
		parts = parts[:4]
	}
	return strings.Join(parts, ".")
}

// SameVersion is lite-kit's "already" check: version strings with different
// build suffixes still count when one is a prefix of the other.
func SameVersion(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	return strings.HasPrefix(a, b) || strings.HasPrefix(b, a)
}

// crc32Of returns the checksum for the platform's firmware: the value
// recorded at download time, or — when the manifest is missing or stale,
// which happens to hand-moved files — computed from the file itself, as
// lite-kit does ("the manifest often does not match"). The station
// verifies the download against this number, so it must match the bytes
// we actually serve.
func (s *Store) crc32Of(platform string) (uint32, error) {
	b, err := os.ReadFile(s.manifestPath(platform))
	if err == nil {
		var m localManifest
		if json.Unmarshal(b, &m) == nil && m.Crc32 != 0 {
			return m.Crc32, nil
		}
	}
	t, ok := TargetFor(platform)
	if !ok {
		return 0, fmt.Errorf("firmware: no crc32 recorded for %s", platform)
	}
	f, err := os.Open(s.zipPath(t.Platform, t.Version))
	if err != nil {
		return 0, fmt.Errorf("firmware: no crc32 recorded for %s", platform)
	}
	defer f.Close()
	crc := crc32.NewIEEE()
	if _, err := io.Copy(crc, f); err != nil {
		return 0, fmt.Errorf("firmware: checksum: %w", err)
	}
	return crc.Sum32(), nil
}
