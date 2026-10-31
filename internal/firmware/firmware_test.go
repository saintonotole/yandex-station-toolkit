package firmware

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"hash/crc32"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/saintonotole/yandex-station-toolkit/internal/dnssrv"
	"github.com/saintonotole/yandex-station-toolkit/internal/server"
)

const miniVersion = "1.305.4.16.3237824040.20250721"

// fakeImage is a plausible firmware file: zip magic padded past the
// truncation threshold.
func fakeImage(t *testing.T, size int) []byte {
	t.Helper()
	if size < 6 {
		size = 6
	}
	b := make([]byte, size)
	copy(b, "PK\x03\x04")
	for i := 6; i < len(b); i++ {
		b[i] = byte(i % 251)
	}
	return b
}

// xzImage mirrors the real Mini 1 artifact: the ".zip" Yandex serves is
// an xz stream (live-observed magic FD 37 7A 58 5A 00).
func xzImage(t *testing.T, size int) []byte {
	t.Helper()
	if size < 6 {
		size = 6
	}
	b := fakeImage(t, size)
	copy(b, "\xfd7zXZ\x00")
	return b
}

func TestArchiveMagicAcceptsXZ(t *testing.T) {
	if !archiveMagic([]byte("\xfd7zXZ\x00")) {
		t.Fatal("xz magic must be accepted (the Mini 1 image is xz)")
	}
	if archiveMagic([]byte("GARBAGE")) {
		t.Fatal("garbage must not pass as an archive")
	}
}

// stubCDN serves one body at every path and counts hits.
type stubCDN struct {
	srv  *httptest.Server
	hits int
	fail bool
	body []byte
}

func startCDN(t *testing.T, body []byte) *stubCDN {
	t.Helper()
	st := &stubCDN{body: body}
	st.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st.hits++
		if st.fail {
			w.WriteHeader(503)
			return
		}
		w.Write(st.body)
	}))
	t.Cleanup(st.srv.Close)
	return st
}

// stubMirror serves the lite-kit layout: metadata.json and update.zip under
// <platform>/<version>/, with metadata pointing at the official URL.
type stubMirror struct {
	srv     *httptest.Server
	zipHits int
	body    []byte
	fail    bool
}

func startMirror(t *testing.T, officialURL string, crc uint32, body []byte) *stubMirror {
	t.Helper()
	m := &stubMirror{body: body}
	mux := http.NewServeMux()
	mux.HandleFunc("/yandexmini/"+miniVersion+"/metadata.json", func(w http.ResponseWriter, r *http.Request) {
		if m.fail {
			w.WriteHeader(503)
			return
		}
		w.Write([]byte(`{"hasUpdate":true,"version":"` + miniVersion + `","downloadUrl":"` + officialURL + `","crc32":` + strconv.FormatUint(uint64(crc), 10) + `}`))
	})
	mux.HandleFunc("/yandexmini/"+miniVersion+"/update.zip", func(w http.ResponseWriter, r *http.Request) {
		m.zipHits++
		w.Write(m.body)
	})
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func newTestStore(t *testing.T, mirrorURL string) *Store {
	t.Helper()
	return New(t.TempDir(), mirrorURL, func(msg string) { t.Log(msg) })
}

func TestTargetsKnown(t *testing.T) {
	for _, p := range []string{"yandexmicro", "yandexmini", "yandexmini_2", "bergamot", "pickle", "plum", "yandexmidi", "cucumber"} {
		if _, ok := TargetFor(p); !ok {
			t.Fatalf("no target for %s", p)
		}
	}
	// Identifier aliases a station may report instead of the OTA name.
	for alias, want := range map[string]string{
		"yandexmini2":    "yandexmini_2",
		"yandexminni":    "yandexmini",
		"yandexbergamot": "bergamot",
		"yandexpickle":   "pickle",
		"yandexplum":     "plum",
		"yandexcucumber": "cucumber",
	} {
		got, ok := TargetFor(alias)
		if !ok || got.Platform != want {
			t.Fatalf("alias %s must resolve to %s", alias, want)
		}
	}
	if _, ok := TargetFor("yandexstation"); ok {
		t.Fatal("yandexstation must not carry an unverified target")
	}
}

func TestEnsurePrefersOfficialCDN(t *testing.T) {
	body := fakeImage(t, minFirmwareSize+64)
	official := startCDN(t, body)
	mirror := startMirror(t, official.srv.URL+"/yandexmini/ota/release/x/"+miniVersion+".zip", official.crcOf(), body)
	s := newTestStore(t, mirror.srv.URL)

	path, err := s.Ensure(context.Background(), "yandexmini")
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if official.hits != 1 {
		t.Fatalf("official cdn: want 1 download, got %d", official.hits)
	}
	if mirror.zipHits != 0 {
		t.Fatalf("mirror must stay a fallback, but was hit %d times", mirror.zipHits)
	}
	if filepath.Base(path) != miniVersion+".zip" {
		t.Fatalf("stored under %s", filepath.Base(path))
	}
	if !s.Has("yandexmini") {
		t.Fatal("stored file does not verify")
	}
	// A second Ensure must not download again.
	if _, err := s.Ensure(context.Background(), "yandexmini"); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if official.hits != 1 {
		t.Fatalf("re-downloaded an existing file (official hits %d)", official.hits)
	}
}

func TestEnsureFallsBackToMirrorBytes(t *testing.T) {
	body := fakeImage(t, minFirmwareSize+64)
	official := startCDN(t, body)
	official.fail = true
	mirror := startMirror(t, official.srv.URL+"/yandexmini/ota/release/x/"+miniVersion+".zip", crc32.ChecksumIEEE(body), body)
	s := newTestStore(t, mirror.srv.URL)

	if _, err := s.Ensure(context.Background(), "yandexmini"); err != nil {
		t.Fatalf("Ensure with dead official CDN: %v", err)
	}
	if official.hits == 0 {
		t.Fatal("official CDN was never tried")
	}
	if mirror.zipHits != 1 {
		t.Fatalf("mirror fallback: want 1 hit, got %d", mirror.zipHits)
	}
	if !s.Has("yandexmini") {
		t.Fatal("mirror bytes did not verify")
	}
}

func TestEnsureRejectsWrongChecksum(t *testing.T) {
	body := fakeImage(t, minFirmwareSize+64)
	official := startCDN(t, body)
	// Metadata advertises a checksum of something else entirely.
	mirror := startMirror(t, official.srv.URL+"/x.zip", 12345, body)
	s := newTestStore(t, mirror.srv.URL)

	_, err := s.Ensure(context.Background(), "yandexmini")
	if err == nil {
		t.Fatal("checksum mismatch must fail")
	}
	if !strings.Contains(err.Error(), "crc32") {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Has("yandexmini") {
		t.Fatal("a rejected download must not be kept as valid")
	}
}

func TestEnsureRejectsTruncatedMirrorFile(t *testing.T) {
	truncated := fakeImage(t, 33000) // lite-kit saw ~33 KB answers
	official := startCDN(t, truncated)
	mirror := startMirror(t, official.srv.URL+"/x.zip", crc32.ChecksumIEEE(truncated), truncated)
	s := newTestStore(t, mirror.srv.URL)

	_, err := s.Ensure(context.Background(), "yandexmini")
	if err == nil {
		t.Fatal("a truncated image must fail verification")
	}
}

func TestEnsureUnknownPlatform(t *testing.T) {
	s := newTestStore(t, "http://127.0.0.1:1")
	if _, err := s.Ensure(context.Background(), "cucumber"); err == nil {
		t.Fatal("unknown platform must fail, not invent a version")
	}
}

// placeVerified writes a file and its manifest directly, as a finished
// download would have.
func placeVerified(t *testing.T, s *Store, platform, version string) {
	t.Helper()
	body := fakeImage(t, minFirmwareSize+32)
	zip := filepath.Join(s.dir, platform, version+".zip")
	if err := os.MkdirAll(filepath.Dir(zip), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zip, body, 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := localManifest{
		Platform: platform, Version: version, Filename: version + ".zip",
		Size: int64(len(body)), Crc32: crc32.ChecksumIEEE(body), Source: "test",
	}
	b, _ := json.Marshal(manifest)
	if err := os.WriteFile(s.manifestPath(platform), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestProviderUpdateManifest(t *testing.T) {
	s := newTestStore(t, "http://127.0.0.1:1")
	p := NewProvider(s, func() string { return "192.168.1.9" }, nil)

	// Nothing downloaded yet -> no offer (Server answers hasUpdate:false).
	if out := p.Update("yandexmini", "1.0.0"); out != nil {
		t.Fatal("provider must not offer a file it does not have")
	}

	placeVerified(t, s, "yandexmini", miniVersion)

	out := p.Update("yandexmini", "1.3.4.12")
	if out == nil {
		t.Fatal("no offer for an old version")
	}
	var m otaManifest
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("offer is not the station's manifest shape: %v", err)
	}
	if !m.HasUpdate || !m.Critical || m.Version != miniVersion {
		t.Fatalf("offer fields wrong: %s", out)
	}
	if m.DownloadURL != "https://quasar.yandex.net/yandexmini/ota/"+miniVersion+".zip" {
		t.Fatalf("offer must point at the local endpoint, got %s", m.DownloadURL)
	}
	if m.FallbackIP != "192.168.1.9" {
		t.Fatalf("fallbackIp must be the LAN IP, got %q", m.FallbackIP)
	}

	// A station already on the target (or its prefix) must not be re-offered.
	if out := p.Update("yandexmini", miniVersion); out != nil {
		t.Fatal("station on target was re-offered")
	}
	if out := p.Update("yandexmini", miniVersion+".something"); out != nil {
		t.Fatal("prefix-matching version was re-offered")
	}
	// Unknown platform: no offer.
	if out := p.Update("cucumber", "1.0.0"); out != nil {
		t.Fatal("unknown platform was offered")
	}
}

func TestProviderServeFile(t *testing.T) {
	s := newTestStore(t, "http://127.0.0.1:1")
	placeVerified(t, s, "yandexmini", miniVersion)
	p := NewProvider(s, nil, nil)

	get := func(url string, headers map[string]string) *http.Response {
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// Full download.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plat, name, ok := parseOtaServePath(r.URL.Path)
		if !ok || !p.ServeFile(w, r, plat, name) {
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)

	resp := get(srv.URL+"/yandexmini/ota/"+miniVersion+".zip", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("full download: %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Range request, as the station's updater uses.
	resp = get(srv.URL+"/yandexmini/ota/"+miniVersion+".zip", map[string]string{"Range": "bytes=0-1023"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("range request: want 206, got %d", resp.StatusCode)
	}

	// Traversal and wrong platform must never serve.
	for _, bad := range []string{
		"/yandexmini/ota/..%2F..%2Fetc%2Fpasswd.zip",
		"/cucumber/ota/" + miniVersion + ".zip",
		"/yandexmini/ota/nonsense.zip",
	} {
		resp := get(srv.URL+bad, nil)
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Fatalf("%s: want 404, got %d", bad, resp.StatusCode)
		}
	}
}

// parseOtaServePath is the same split the Server performs.
func parseOtaServePath(p string) (string, string, bool) {
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if len(parts) != 3 || parts[1] != "ota" {
		return "", "", false
	}
	return parts[0], parts[2], true
}

func TestServerIntegrationOffersFirmware(t *testing.T) {
	s := newTestStore(t, "http://127.0.0.1:1")
	placeVerified(t, s, "yandexmini", miniVersion)

	certPEM, keyPEM := testKeypair(t)
	// Loopback everywhere: test binaries live in fresh temp paths, and a
	// non-loopback bind makes Windows Firewall prompt for every build.
	cfg := server.Config{
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		Addr:     "127.0.0.1",
		DNS:      dnssrv.Config{Port: 0, Addr: "127.0.0.1", Log: func(string) {}},
		Firmware: NewProvider(s, func() string { return "192.168.1.9" }, func(msg string) { t.Log("provider: " + msg) }),
		Log:      func(string) {},
	}
	st, err := server.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Start(server.Override); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Stop)
	httpPort := 0
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if p, _, ok := st.Ports(); ok {
			httpPort = p
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if httpPort == 0 {
		t.Fatal("Server did not open its http endpoint")
	}
	base := "http://127.0.0.1:" + strconv.Itoa(httpPort)

	// The station's check_updates gets the local vulnerable build.
	req, _ := http.NewRequest(http.MethodGet, base+"/check_updates?platform=yandexmini&version=1.3.4.12&device_id=x", nil)
	req.Host = "quasar.yandex.net"
	req.Header.Set("User-Agent", "yandexmini-firmware")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	if !strings.Contains(body, `"hasUpdate":true`) || !strings.Contains(body, miniVersion) {
		t.Fatalf("station was not offered the local vulnerable build: %s", body)
	}

	// The offered URL must actually download through the Server.
	req, _ = http.NewRequest(http.MethodGet, base+"/yandexmini/ota/"+miniVersion+".zip", nil)
	req.Host = "quasar.yandex.net"
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("firmware download through Server: %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") != "application/zip" {
		t.Fatalf("content type: %s", resp.Header.Get("Content-Type"))
	}
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	buf := new(strings.Builder)
	b := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(b)
		buf.Write(b[:n])
		if err != nil {
			break
		}
	}
	return buf.String()
}

func (c *stubCDN) crcOf() uint32 { return crc32.ChecksumIEEE(c.body) }

// testKeypair makes a throwaway certificate for the Server's HTTPS listener.
func testKeypair(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "quasar.yandex.net"},
		DNSNames:     []string{"quasar.yandex.net"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pemEncode("CERTIFICATE", der)
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pemEncode("EC PRIVATE KEY", keyDER)
	return certPEM, keyPEM
}

func pemEncode(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}
