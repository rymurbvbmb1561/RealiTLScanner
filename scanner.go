package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// ScanResult holds the result of a TLS scan for a single host.
type ScanResult struct {
	IP          string
	Port        string
	ServerName  string
	HasReality  bool
	CertSubject string
	Latency     time.Duration
	Error       error
}

// Scanner performs TLS/Reality detection scans.
type Scanner struct {
	Timeout    time.Duration
	Concurrent int
}

// NewScanner creates a new Scanner with sensible defaults.
func NewScanner(timeout time.Duration, concurrent int) *Scanner {
	if concurrent <= 0 {
		concurrent = 100
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Scanner{
		Timeout:    timeout,
		Concurrent: concurrent,
	}
}

// ScanHost attempts a TLS handshake against ip:port and detects Reality.
func (s *Scanner) ScanHost(ip, port string) ScanResult {
	result := ScanResult{IP: ip, Port: port}

	addr := net.JoinHostPort(ip, port)
	start := time.Now()

	dialer := &net.Dialer{Timeout: s.Timeout}
	rawConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		result.Error = fmt.Errorf("tcp dial: %w", err)
		return result
	}
	defer rawConn.Close()

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 — intentional for scanning
		ServerName:         ip,
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	tlsConn.SetDeadline(time.Now().Add(s.Timeout)) //nolint:errcheck

	if err := tlsConn.Handshake(); err != nil {
		// A failed handshake may still indicate Reality (connection reset).
		result.HasReality = isRealitySignature(err)
		result.Error = fmt.Errorf("tls handshake: %w", err)
		result.Latency = time.Since(start)
		return result
	}

	result.Latency = time.Since(start)
	state := tlsConn.ConnectionState()

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.ServerName = cert.Subject.CommonName
		result.CertSubject = cert.Subject.String()
	}

	// Reality servers typically present self-signed or mismatched certs.
	result.HasReality = detectReality(state)
	return result
}

// ScanBatch scans a slice of ip:port pairs concurrently.
func (s *Scanner) ScanBatch(targets []string) []ScanResult {
	sem := make(chan struct{}, s.Concurrent)
	results := make([]ScanResult, len(targets))
	done := make(chan struct{})

	for i, target := range targets {
		go func(idx int, t string) {
			sem <- struct{}{}
			defer func() { <-sem }()

			ip, port, err := net.SplitHostPort(t)
			if err != nil {
				results[idx] = ScanResult{Error: fmt.Errorf("invalid target %q: %w", t, err)}
			} else {
				results[idx] = s.ScanHost(ip, port)
			}
			done <- struct{}{}
		}(i, target)
	}

	for range targets {
		<-done
	}
	return results
}

// detectReality inspects TLS state for heuristics that suggest a Reality server.
func detectReality(state tls.ConnectionState) bool {
	// Reality servers commonly use TLS 1.3.
	if state.Version != tls.VersionTLS13 {
		return false
	}
	// Additional heuristic: no ALPN negotiated.
	if state.NegotiatedProtocol != "" {
		return false
	}
	return true
}

// isRealitySignature checks whether a handshake error pattern matches Reality behaviour.
func isRealitySignature(err error) bool {
	if err == nil {
		return false
	}
	// Reality proxies may reset the connection on unrecognised clients.
	errStr := err.Error()
	return contains(errStr, "connection reset") || contains(errStr, "EOF")
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && func() bool {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}())
}
