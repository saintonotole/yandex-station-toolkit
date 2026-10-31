package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"time"
)

// hop-by-hop and per-connection headers, never forwarded either way.
var skipRequestHeaders = map[string]bool{
	"connection":          true,
	"content-length":      true,
	"transfer-encoding":   true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"upgrade":             true,
	"accept-encoding":     true, // Go negotiates its own encoding
}

// upstreamClient talks to the real Yandex endpoints by IP while the TLS
// ServerName keeps the original host, so the connection bypasses this
// machine's own DNS hijack but still validates the real certificate.
type upstreamClient struct {
	transport *http.Transport
	attempts  int
	pause     time.Duration
}

func newUpstreamClient(resolve func(host, port string) (string, error), rootCAs *x509.CertPool, insecure bool, timeout time.Duration, attempts int, pause time.Duration) *upstreamClient {
	u := &upstreamClient{attempts: attempts, pause: pause}
	u.transport = &http.Transport{
		DisableKeepAlives: true,
		ForceAttemptHTTP2: false,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				port = "443"
			}
			target, err := resolve(host, port)
			if err != nil {
				return nil, err
			}
			dialer := &net.Dialer{Timeout: timeout}
			conn, err := dialer.DialContext(ctx, network, target)
			if err != nil {
				return nil, err
			}
			tlsCfg := &tls.Config{ServerName: host, RootCAs: rootCAs, InsecureSkipVerify: insecure}
			tlsConn := tls.Client(conn, tlsCfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}
	return u
}

// softError marks upstream statuses the station must never see: rate limits
// and server overload read as activation failure on the device.
func softError(status int) bool {
	return status == 429 || status >= 500
}

// roundTrip sends the request, retrying soft errors like lite-kit: 3 attempts
// with a pause between them. It returns the body of the final answer.
func (u *upstreamClient) roundTrip(req *http.Request) ([]byte, int, error) {
	var (
		data   []byte
		status int
		err    error
	)
	for attempt := 1; attempt <= u.attempts; attempt++ {
		data, status, err = u.once(req)
		if err == nil && !softError(status) {
			return data, status, nil
		}
		if attempt < u.attempts {
			select {
			case <-req.Context().Done():
				return data, status, err
			case <-time.After(u.pause):
			}
		}
	}
	return data, status, err
}

func (u *upstreamClient) once(req *http.Request) ([]byte, int, error) {
	resp, err := u.transport.RoundTrip(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return data, resp.StatusCode, nil
}

// copyRequestHeaders mirrors the caller's headers onto the upstream request.
func copyRequestHeaders(dst, src *http.Request) {
	for k, vs := range src.Header {
		if skipRequestHeaders[k] || k == "Host" {
			continue
		}
		for _, v := range vs {
			dst.Header.Add(k, v)
		}
	}
}
