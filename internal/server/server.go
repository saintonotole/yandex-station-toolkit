package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/saintonotole/yandex-station-toolkit/internal/dnssrv"
)

// Mode is the DNS/endpoint mode, shared with the dnssrv package.
type Mode = dnssrv.Mode

const (
	Passthrough Mode = dnssrv.Passthrough
	Override    Mode = dnssrv.Override
)

// FirmwareProvider is the hook for the firmware stage: it offers downgrade
// manifests and serves firmware files. Nil means no local firmware, and the
// endpoint answers hasUpdate:false so the station never sees a newer build.
type FirmwareProvider interface {
	// Update returns the OTA manifest for a station's platform and current
	// version, or nil when no local firmware applies.
	Update(platform, current string) []byte
	// ServeFile delivers a firmware file; it reports whether it wrote one.
	ServeFile(w http.ResponseWriter, r *http.Request, platform, name string) bool
}

type Config struct {
	// CertPEM and KeyPEM are the station-trusted certificate chain
	// (payloads/equasar-fullchain.pem and equasar-key.pem).
	CertPEM []byte
	KeyPEM  []byte
	// SyncTemplate is the local fallback answer (payloads/equasar-sync-template.json).
	SyncTemplate []byte

	// DNS is the forwarding resolver config; HTTPPort/HTTPSPort default to
	// 80/443 when zero.
	DNS       dnssrv.Config
	HTTPPort  int // default 80
	HTTPSPort int // default 443
	// Addr is the listen IP for every endpoint. Empty means all
	// interfaces (production: the station must reach the Server over the
	// LAN, and Windows shows its own firewall prompt once). Tests set
	// "127.0.0.1" — loopback traffic is firewall-exempt, so test
	// binaries never trigger a Windows Firewall prompt or junk rules.
	Addr string

	// OnActivation fires when a station's sync answer leaves this
	// endpoint carrying the ADB activation — the moment the jailbreak
	// command has been delivered. remoteIP identifies the asker;
	// deviceID is the id from the request (may be empty). The app uses
	// it to start the automated post-activation flow.
	OnActivation func(remoteIP, deviceID string)

	Firmware FirmwareProvider

	// ResolveEndpoint maps an upstream host to "ip:port" (tests override it;
	// production resolves the real IP and keeps the URL's port).
	ResolveEndpoint func(host, port string) (string, error)
	// UpstreamRootCAs and UpstreamInsecureTLS override the proxy's TLS trust (tests).
	UpstreamRootCAs     *x509.CertPool
	UpstreamInsecureTLS bool

	RetryDelay time.Duration // between upstream retries; default 2.5s
	Log        func(string)
}

type Server struct {
	cfg      Config
	cert     tls.Certificate
	tmpl     []byte // sanitized fallback template, marshaled
	res      *resolver
	upstream *upstreamClient

	mu       sync.Mutex
	mode     Mode
	dns      *dnssrv.Server
	httpLn   net.Listener
	httpsLn  net.Listener
	httpSrv  *http.Server
	httpsSrv *http.Server
}

func New(cfg Config) (*Server, error) {
	cert, err := tls.X509KeyPair(cfg.CertPEM, cfg.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("Server: certificate: %w", err)
	}
	tmpl, err := loadSyncTemplate(cfg.SyncTemplate)
	if err != nil {
		return nil, err
	}
	if cfg.Log == nil {
		cfg.Log = func(string) {}
	}
	if cfg.DNS.Log == nil {
		cfg.DNS.Log = cfg.Log
	}
	if cfg.RetryDelay == 0 {
		cfg.RetryDelay = 2500 * time.Millisecond
	}
	s := &Server{
		cfg:  cfg,
		cert: cert,
		tmpl: marshalSync(tmpl),
		res:  newResolver(true, cfg.Log),
	}
	if cfg.ResolveEndpoint == nil {
		cfg.ResolveEndpoint = func(host, port string) (string, error) {
			ip, err := s.res.resolve(host)
			if err != nil {
				return "", err
			}
			return net.JoinHostPort(ip.String(), port), nil
		}
	}
	s.upstream = newUpstreamClient(cfg.ResolveEndpoint, cfg.UpstreamRootCAs, cfg.UpstreamInsecureTLS, 8*time.Second, 3, cfg.RetryDelay)
	return s, nil
}

func (s *Server) Mode() Mode {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mode
}

func (s *Server) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dns != nil && s.dns.Running()
}

// Start begins serving: the DNS server always, the HTTP/HTTPS endpoint only
// in override mode, where the hijacked names actually reach it.
func (s *Server) Start(m Mode) error {
	if s.Running() {
		return fmt.Errorf("Server: already running")
	}
	dnsCfg := s.cfg.DNS
	if dnsCfg.Addr == "" {
		dnsCfg.Addr = s.cfg.Addr // one field drives every endpoint
	}
	dns := dnssrv.New(dnsCfg)
	if err := dns.Start(m); err != nil {
		return err
	}
	s.mu.Lock()
	s.dns = dns
	s.mode = m
	s.mu.Unlock()
	if m == Override {
		if err := s.startHTTP(); err != nil {
			dns.Stop()
			s.mu.Lock()
			s.dns = nil
			s.mu.Unlock()
			return err
		}
	}
	// The dnssrv "listening" line below is the start announcement; one
	// line per state change, not two.
	return nil
}

// SetMode switches modes live: the HTTP endpoint follows, because passthrough
// never redirects anything to this machine.
func (s *Server) SetMode(m Mode) error {
	s.mu.Lock()
	dns := s.dns
	running := dns != nil
	old := s.mode
	s.mu.Unlock()
	if !running {
		return fmt.Errorf("Server: not running")
	}
	if old == m {
		return nil
	}
	if m == Override {
		if err := s.startHTTP(); err != nil {
			return err
		}
	} else {
		s.stopHTTP()
	}
	dns.SetMode(m)
	s.mu.Lock()
	s.mode = m
	s.mu.Unlock()
	return nil
}

func (s *Server) Stop() {
	s.mu.Lock()
	dns := s.dns
	s.dns = nil
	s.mu.Unlock()
	if dns != nil {
		dns.Stop()
	}
	s.stopHTTP()
	s.cfg.Log("dns server: stopped")
}

func (s *Server) startHTTP() error {
	s.mu.Lock()
	already := s.httpSrv != nil
	s.mu.Unlock()
	if already {
		return nil
	}
	httpPort := s.cfg.HTTPPort
	if httpPort == 0 {
		httpPort = 80
	}
	httpsPort := s.cfg.HTTPSPort
	if httpsPort == 0 {
		httpsPort = 443
	}
	host := s.cfg.Addr // empty: all interfaces
	httpLn, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, httpPort))
	if err != nil {
		return fmt.Errorf("Server: http :%d: %w", httpPort, err)
	}
	httpsLn, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, httpsPort))
	if err != nil {
		httpLn.Close()
		return fmt.Errorf("Server: https :%d: %w", httpsPort, err)
	}
	httpSrv := &http.Server{Handler: s, ReadHeaderTimeout: 10 * time.Second}
	httpsSrv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{s.cert}},
	}
	go httpSrv.Serve(httpLn)
	go httpsSrv.ServeTLS(httpsLn, "", "")
	s.mu.Lock()
	s.httpLn, s.httpsLn, s.httpSrv, s.httpsSrv = httpLn, httpsLn, httpSrv, httpsSrv
	s.mu.Unlock()
	s.cfg.Log(fmt.Sprintf("dns server: https endpoint on :%d (override)", httpsPort))
	return nil
}

func (s *Server) stopHTTP() {
	s.mu.Lock()
	httpSrv, httpsSrv := s.httpSrv, s.httpsSrv
	s.httpLn, s.httpsLn, s.httpSrv, s.httpsSrv = nil, nil, nil, nil
	s.mu.Unlock()
	if httpSrv != nil {
		httpSrv.Close()
	}
	if httpsSrv != nil {
		httpsSrv.Close()
	}
}

// ports is the listening ports of the HTTP endpoints, for tests and the UI.
func (s *Server) Ports() (httpPort, httpsPort int, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.httpLn == nil {
		return 0, 0, false
	}
	return s.httpLn.Addr().(*net.TCPAddr).Port, s.httpsLn.Addr().(*net.TCPAddr).Port, true
}

// ServeHTTP routes every request the hijacked names send here.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.Mode() == Passthrough {
		s.proxy(w, r, false)
		return
	}
	s.handleOverride(w, r)
}

func (s *Server) handleOverride(w http.ResponseWriter, r *http.Request) {
	clean := r.URL.Path
	if strings.Contains(strings.ToLower(clean), "sync") {
		s.serveSync(w, r)
		return
	}
	lower := strings.ToLower(clean)
	if clean == "/" || clean == "/favicon.ico" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if clean == "/generate_204" {
		w.WriteHeader(http.StatusNoContent)
		s.cfg.Log(fmt.Sprintf("dns server: connectivity probe from %s answered", r.RemoteAddr))
		return
	}
	if strings.HasPrefix(clean, "/glagol/") || strings.HasPrefix(clean, "/telemetry") || strings.HasPrefix(clean, "/metrics") {
		s.proxy(w, r, true)
		return
	}
	// Firmware downloads: the manifest points the station at
	// quasar.yandex.net/<platform>/ota/<file>, which is this machine.
	if s.cfg.Firmware != nil && strings.HasSuffix(clean, ".zip") {
		if plat, name, ok := parseOtaPath(clean); ok {
			if s.cfg.Firmware.ServeFile(w, r, plat, name) {
				return
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}
	if strings.Contains(lower, "check_updates") || strings.Contains(lower, "allow_update") {
		if isColumn(r) {
			s.serveUpdate(w, r)
			return
		}
		s.proxy(w, r, true)
		return
	}
	if strings.Contains(lower, "register") {
		s.serveRegister(w, r)
		return
	}
	s.proxy(w, r, true)
}

// parseOtaPath splits /<platform>/ota/<name> as the offered manifest URLs
// use.
func parseOtaPath(clean string) (platform, name string, ok bool) {
	rest := strings.TrimPrefix(clean, "/")
	parts := strings.Split(rest, "/")
	if len(parts) != 3 || parts[1] != "ota" {
		return "", "", false
	}
	return parts[0], parts[2], true
}

// isColumn tells a station apart from the owner's phone: the phone hits the
// Server too, since the whole LAN uses this DNS server. Only stations get
// substituted answers.
func isColumn(r *http.Request) bool {
	ua := strings.ToLower(r.Header.Get("User-Agent"))
	for _, k := range []string{"yandexstation", "yandexmicro", "yandexmini", "yandexmidi", "yandexstation1"} {
		if strings.Contains(ua, k) {
			return true
		}
	}
	if r.URL.Query().Get("device_id") != "" {
		return true
	}
	if strings.Contains(strings.ToLower(r.URL.RawQuery), "platform=yandex") {
		return true
	}
	return false
}

func (s *Server) serveSync(w http.ResponseWriter, r *http.Request) {
	body, status, err := s.fetchUpstream(r)
	if err == nil && status == 200 {
		if out, ok := syncFromUpstream(body); ok {
			writeJSON(w, out)
			s.cfg.Log(fmt.Sprintf("dns server: %s asked for its settings — answered with Yandex's own + ADB activation", r.RemoteAddr))
			s.notifyActivation(r)
			return
		}
		s.cfg.Log("dns server: Yandex's answer was unreadable — used the local settings template")
	} else {
		why := "no connection to Yandex"
		if err == nil {
			why = fmt.Sprintf("Yandex answered %d after retries", status)
		}
		s.cfg.Log(fmt.Sprintf("dns server: %s (%s) — used the local settings template", why, r.RemoteAddr))
	}
	s.writeTemplateSync(w)
	s.notifyActivation(r)
}

// notifyActivation reports a delivered ADB activation to the app. The
// device id travels in the request (lite-kit's column marker); it is
// passed on for correlation but never journaled.
func (s *Server) notifyActivation(r *http.Request) {
	if s.cfg.OnActivation == nil {
		return
	}
	deviceID := r.URL.Query().Get("device_id")
	if i := strings.Index(deviceID, "&"); i >= 0 {
		deviceID = deviceID[:i]
	}
	s.cfg.OnActivation(r.RemoteAddr, deviceID)
}

func (s *Server) writeTemplateSync(w http.ResponseWriter) {
	var d map[string]any
	if err := json.Unmarshal(s.tmpl, &d); err != nil {
		writeJSON(w, []byte(builtinSyncTemplate))
		return
	}
	injectADBD(d)
	writeJSON(w, marshalSync(d))
}

func (s *Server) serveUpdate(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	platform, current := q.Get("platform"), q.Get("version")
	if platform == "" {
		platform = "unknown"
	}
	if s.cfg.Firmware == nil {
		writeJSON(w, []byte(`{"hasUpdate":false}`))
		s.cfg.Log(fmt.Sprintf("dns server: %s asked for updates — no firmware provider configured", r.RemoteAddr))
		return
	}
	// The reported running version is the fact that separates "the
	// station took the offer" from "the station stayed on its build".
	ran := current
	if ran == "" {
		ran = "version not reported"
	}
	s.cfg.Log(fmt.Sprintf("dns server: %s asked for updates (platform %s, running %s)", r.RemoteAddr, platform, ran))
	// The provider journals its own decision with the reason.
	if m := s.cfg.Firmware.Update(platform, current); m != nil {
		writeJSON(w, m)
		return
	}
	writeJSON(w, []byte(`{"hasUpdate":false}`))
}

func (s *Server) serveRegister(w http.ResponseWriter, r *http.Request) {
	// lite-kit: the column always gets allvalid, whatever Yandex said.
	_, _, _ = s.fetchUpstream(r)
	writeJSON(w, []byte(`{"message":"allvalid","status":"ok"}`))
	s.cfg.Log(fmt.Sprintf("dns server: %s registered the column as valid", r.RemoteAddr))
}

// fetchUpstream builds and sends the mirrored request to the real endpoint.
func (s *Server) fetchUpstream(r *http.Request) ([]byte, int, error) {
	host := r.Host
	if host == "" {
		host = "quasar.yandex.net"
	}
	url := "https://" + host + r.URL.RequestURI()
	var body io.Reader
	if r.Body != nil && (r.Method == http.MethodPost || r.Method == http.MethodPut) {
		data, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			return nil, 0, err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, url, body)
	if err != nil {
		return nil, 0, err
	}
	copyRequestHeaders(req, r)
	return s.upstream.roundTrip(req)
}

// proxy mirrors a request to the real endpoint. With okFallback, upstream
// soft errors become a local 200 {"status":"ok"} so the station never reads
// an overload as a failed sync; without it the answer passes through.
func (s *Server) proxy(w http.ResponseWriter, r *http.Request, okFallback bool) {
	body, status, err := s.fetchUpstream(r)
	if err != nil {
		if okFallback {
			writeJSON(w, []byte(`{"status":"ok"}`))
			return
		}
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	if okFallback && softError(status) {
		writeJSON(w, []byte(`{"status":"ok"}`))
		return
	}
	w.WriteHeader(status)
	w.Write(body)
}

func writeJSON(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}
