package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/saintonotole/yandex-station-toolkit/internal/dnssrv"
)

// genPair makes a throwaway certificate for the Server's HTTPS listener.
func genPair(t *testing.T) (certPEM, keyPEM []byte) {
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
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// stubYandex mimics the real endpoint over TLS: sync answers carry a native
// marker field, check_updates offers a newer build, other paths echo upstream.
type stubYandex struct {
	srv     *httptest.Server
	certPEM []byte
	failAll bool
}

func startYandex(t *testing.T) *stubYandex {
	t.Helper()
	st := &stubYandex{}
	mux := http.NewServeMux()
	mux.HandleFunc("/get_sync_info", func(w http.ResponseWriter, r *http.Request) {
		if st.failAll {
			w.WriteHeader(429)
			return
		}
		writeJSON(w, []byte(`{"status":"ok","config":{"device_config":{"name":"quasar","marker":"upstream"}},"glagol":{"security":"station-secret"}}`))
	})
	mux.HandleFunc("/check_updates", func(w http.ResponseWriter, r *http.Request) {
		if st.failAll {
			w.WriteHeader(429)
			return
		}
		writeJSON(w, []byte(`{"hasUpdate":true,"version":"9.9.9","marker":"upstream"}`))
	})
	mux.HandleFunc("/anything", func(w http.ResponseWriter, r *http.Request) {
		if st.failAll {
			w.WriteHeader(500)
			return
		}
		writeJSON(w, []byte(`{"marker":"upstream"}`))
	})
	// A certificate for the real host name, so the proxy's verification
	// (ServerName=quasar.yandex.net) succeeds against the stub.
	certPEM, keyPEM := genPair(t)
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	st.srv = srv
	st.certPEM = certPEM
	return st
}

func newTestServer(t *testing.T, st *stubYandex, mode Mode) *Server {
	t.Helper()
	certPEM, keyPEM := genPair(t)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(st.certPEM)
	cfg := Config{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		DNS:     dnssrv.Config{Port: 0, Addr: "127.0.0.1", Log: func(string) {}},
		// UpstreamRootCAs: trust the stub's self-signed certificate.
		UpstreamRootCAs: pool,
		HTTPPort:        0,
		HTTPSPort:       0,
		// Loopback: never trips the Windows Firewall.
		Addr:       "127.0.0.1",
		RetryDelay: time.Millisecond,
		ResolveEndpoint: func(host, port string) (string, error) {
			return st.srv.Listener.Addr().String(), nil
		},
		Log: func(string) {},
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Start(mode); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(s.Stop)
	return s
}

func serverURL(t *testing.T, s *Server, scheme string) string {
	t.Helper()
	for i := 0; i < 50; i++ {
		httpPort, httpsPort, ok := s.Ports()
		if ok {
			if scheme == "https" {
				return "https://127.0.0.1:" + strconv.Itoa(httpsPort)
			}
			return "http://127.0.0.1:" + strconv.Itoa(httpPort)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("Server did not open http endpoints")
	return ""
}

var testClient = &http.Client{
	Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	Timeout:   5 * time.Second,
}

// get performs a request as the given client, with the Host header the
// station would send.
func get(t *testing.T, url, ua string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "quasar.yandex.net"
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	resp, err := testClient.Do(req)
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	defer resp.Body.Close()
	buf := &strings.Builder{}
	b := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(b)
		buf.Write(b[:n])
		if err != nil {
			break
		}
	}
	return resp.StatusCode, buf.String()
}

const columnUA = "yandexmini-firmware/1.3"

// TestSyncNotifiesActivation: a delivered sync answer reports the
// activation to the app with the device id from the request.
func TestSyncNotifiesActivation(t *testing.T) {
	st := startYandex(t)
	s := newTestServer(t, st, Override)
	base := serverURL(t, s, "https")

	type act struct {
		ip, deviceID string
	}
	got := make(chan act, 4)
	s.mu.Lock()
	s.cfg.OnActivation = func(remoteIP, deviceID string) {
		got <- act{remoteIP, deviceID}
	}
	s.mu.Unlock()

	code, _ := get(t, base+"/get_sync_info?device_id=LGTEST&platform=yandexmini", columnUA)
	if code != 200 {
		t.Fatalf("sync: status %d", code)
	}
	select {
	case a := <-got:
		if a.deviceID != "LGTEST" {
			t.Fatalf("device id: %q", a.deviceID)
		}
		if a.ip == "" {
			t.Fatal("remote ip is empty")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnActivation was not called")
	}
}

func TestOverrideSyncInjectsADBD(t *testing.T) {
	st := startYandex(t)
	s := newTestServer(t, st, Override)
	base := serverURL(t, s, "https")

	code, body := get(t, base+"/get_sync_info?device_id=x&platform=yandexmini", columnUA)
	if code != 200 {
		t.Fatalf("sync: status %d", code)
	}
	var d map[string]any
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		t.Fatalf("sync: bad JSON: %v", err)
	}
	// The real answer's native fields survive...
	if !strings.Contains(body, `"marker":"upstream"`) {
		t.Fatalf("sync: native fields lost: %s", body)
	}
	// ...and every adbd branch a firmware generation may read is present.
	if d["adbd"] == nil {
		t.Fatal("sync: top-level adbd missing")
	}
	cfg, _ := d["config"].(map[string]any)
	if cfg == nil || cfg["adbd"] == nil {
		t.Fatal("sync: config.adbd missing")
	}
	for _, section := range []string{"system_config", "device_config"} {
		sub, _ := cfg[section].(map[string]any)
		if sub == nil || sub["adbd"] == nil {
			t.Fatalf("sync: config.%s.adbd missing", section)
		}
	}
}

func TestOverrideSyncFallsBackToTemplate(t *testing.T) {
	st := startYandex(t)
	st.failAll = true
	s := newTestServer(t, st, Override)
	base := serverURL(t, s, "https")

	code, body := get(t, base+"/get_sync_info?device_id=x", columnUA)
	if code != 200 {
		t.Fatalf("fallback sync: status %d", code)
	}
	var d map[string]any
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		t.Fatalf("fallback sync: bad JSON: %v", err)
	}
	if d["adbd"] == nil {
		t.Fatal("fallback sync: no adbd")
	}
	if strings.Contains(body, "glagol") || strings.Contains(body, "user_wifi_config") || strings.Contains(body, "location") {
		t.Fatalf("fallback sync: template carried private fields: %s", body)
	}
}

func TestPassthroughProxiesUntouched(t *testing.T) {
	st := startYandex(t)
	s := newTestServer(t, st, Passthrough)
	if _, _, ok := s.Ports(); ok {
		t.Fatal("passthrough must not run the https endpoint")
	}
	if !s.Running() {
		t.Fatal("passthrough must still run the dns server")
	}
}

func TestSetModeSwitchesInjection(t *testing.T) {
	st := startYandex(t)
	s := newTestServer(t, st, Passthrough)
	if err := s.SetMode(Override); err != nil {
		t.Fatalf("SetMode: %v", err)
	}
	base := serverURL(t, s, "http")

	code, body := get(t, base+"/get_sync_info?device_id=x", columnUA)
	if code != 200 || !strings.Contains(body, `"adbd"`) {
		t.Fatalf("after switch: adbd missing (status %d): %s", code, body)
	}
}

func TestColumnGetsLocalUpdateAnswer(t *testing.T) {
	st := startYandex(t)
	s := newTestServer(t, st, Override)
	base := serverURL(t, s, "http")

	// The station never sees the newer real build during bootstrap.
	code, body := get(t, base+"/check_updates?version=1.0.0&platform=yandexmini&device_id=x", columnUA)
	if code != 200 || strings.Contains(body, "upstream") {
		t.Fatalf("column check_updates: want local hasUpdate:false, got %d %s", code, body)
	}
	var d map[string]any
	json.Unmarshal([]byte(body), &d)
	if d["hasUpdate"] != false {
		t.Fatalf("column check_updates: want hasUpdate:false, got %s", body)
	}

	// The owner's phone keeps seeing the real answer; a phone request has
	// neither a station User-Agent nor device_id/platform markers.
	code, body = get(t, base+"/check_updates?version=1.0.0", "YandexAlisa/12.0 (iPhone)")
	if code != 200 || !strings.Contains(body, "upstream") {
		t.Fatalf("phone check_updates: want real answer, got %d %s", code, body)
	}
}

func TestRegisterAlwaysAllvalid(t *testing.T) {
	st := startYandex(t)
	st.failAll = true
	s := newTestServer(t, st, Override)
	base := serverURL(t, s, "http")

	code, body := get(t, base+"/register?device_id=x", columnUA)
	if code != 200 || !strings.Contains(body, "allvalid") {
		t.Fatalf("register: want allvalid, got %d %s", code, body)
	}
}

func TestOtherPathsProxyAndFallback(t *testing.T) {
	st := startYandex(t)
	s := newTestServer(t, st, Override)
	base := serverURL(t, s, "http")

	code, body := get(t, base+"/anything", columnUA)
	if code != 200 || !strings.Contains(body, "upstream") {
		t.Fatalf("plain proxy: got %d %s", code, body)
	}

	// Upstream overload must not reach the station.
	st.failAll = true
	code, body = get(t, base+"/anything", columnUA)
	if code != 200 || !strings.Contains(body, `"status":"ok"`) {
		t.Fatalf("overload fallback: got %d %s", code, body)
	}
}

func TestBrowserNoise(t *testing.T) {
	st := startYandex(t)
	s := newTestServer(t, st, Override)
	base := serverURL(t, s, "http")

	if code, _ := get(t, base+"/", "Mozilla/5.0"); code != 404 {
		t.Fatalf("/ want 404, got %d", code)
	}
	if code, _ := get(t, base+"/favicon.ico", "Mozilla/5.0"); code != 404 {
		t.Fatalf("/favicon.ico want 404, got %d", code)
	}
	if code, _ := get(t, base+"/generate_204", "wifi-check"); code != 204 {
		t.Fatalf("/generate_204 want 204, got %d", code)
	}
}

func TestShippedKeypairValidates(t *testing.T) {
	cert, err := os.ReadFile("../../payloads/equasar-fullchain.pem")
	if err != nil {
		t.Skip("payloads not present")
	}
	key, err := os.ReadFile("../../payloads/equasar-key.pem")
	if err != nil {
		t.Skip("payloads not present")
	}
	if _, err := tls.X509KeyPair(cert, key); err != nil {
		t.Fatalf("equasar keypair: %v", err)
	}
}

func TestResolveExcludesOwnIPs(t *testing.T) {
	r := newResolver(false, func(string) {})
	// A local address must never be returned even if a resolver says so.
	if ip, err := r.resolve("localhost"); err == nil {
		_, own := localIPSet()[ip.String()]
		if own || ip.IsLoopback() {
			t.Fatalf("resolver returned own/loopback address: %v", ip)
		}
	}
	// The direct-query wire format must at least round-trip a build.
	q := buildAQuery("quasar.yandex.net")
	if len(q) < 18 || q[len(q)-4] != 0 || q[len(q)-3] != 1 {
		t.Fatalf("buildAQuery produced a malformed query: %v", q)
	}
}

func TestSyncFromUpstreamKeepsShape(t *testing.T) {
	in := []byte(`{"status":"ok","config":{"device_config":{"marker":"upstream"}},"glagol":{"security":"x"}}`)
	out, ok := syncFromUpstream(in)
	if !ok {
		t.Fatal("syncFromUpstream rejected a valid answer")
	}
	var d map[string]any
	json.Unmarshal(out, &d)
	if !strings.Contains(string(out), `"marker":"upstream"`) {
		t.Fatal("syncFromUpstream lost native fields")
	}
	if !strings.Contains(string(out), `"glagol"`) {
		t.Fatal("syncFromUpstream stripped glagol from a real answer (only the template is sanitized)")
	}
	if d["adbd"] == nil {
		t.Fatal("syncFromUpstream lost adbd")
	}
	if _, ok := syncFromUpstream([]byte(`not json`)); ok {
		t.Fatal("syncFromUpstream accepted non-JSON")
	}
}
