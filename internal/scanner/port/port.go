// Package port runs a concurrent TCP connect scan over a fixed list of common
// ports on a host. It demonstrates nested concurrency: the scanner fans out its
// own goroutines (one per port) inside the goroutine the engine already runs it
// in, bounded by its own semaphore.
package port

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

// commonPorts mirrors the set used by the previous spy-node project.
var commonPorts = []int{
	21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
	1433, 1521, 3306, 5432, 6379, 8080, 8443, 9200, 27017,
}

// sensitivePorts are services that should rarely be exposed to the internet;
// an open one is reported as medium rather than info.
var sensitivePorts = map[int]bool{
	1433: true, 1521: true, 3306: true, 5432: true, 6379: true, 9200: true, 27017: true,
}

var serviceName = map[int]string{
	21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
	143: "imap", 443: "https", 465: "smtps", 587: "submission", 993: "imaps",
	995: "pop3s", 1433: "mssql", 1521: "oracle", 3306: "mysql", 5432: "postgres",
	6379: "redis", 8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
	27017: "mongodb",
}

// Scanner performs the TCP connect scan.
type Scanner struct {
	dialer      model.Dialer
	ports       []int
	timeout     time.Duration
	concurrency int
	bannerBytes int
}

// Option configures the scanner.
type Option func(*Scanner)

// WithPorts overrides the port list (tests pass a single known port).
func WithPorts(ports []int) Option { return func(s *Scanner) { s.ports = ports } }

// WithTimeout sets the per-port dial timeout.
func WithTimeout(d time.Duration) Option { return func(s *Scanner) { s.timeout = d } }

// New builds a port scanner. In production pass &net.Dialer{}.
func New(d model.Dialer, opts ...Option) *Scanner {
	s := &Scanner{
		dialer:      d,
		ports:       commonPorts,
		timeout:     3 * time.Second,
		concurrency: 50,
		bannerBytes: 256,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Name implements model.Scanner.
func (s *Scanner) Name() string { return "port" }

// Scan implements model.Scanner. It dials every port concurrently and emits a
// finding per open port.
func (s *Scanner) Scan(ctx context.Context, t model.Target, emit model.EmitFunc) error {
	host := t.Host
	if host == "" {
		host = t.Domain
	}
	if host == "" {
		return fmt.Errorf("port: empty target")
	}

	sem := make(chan struct{}, s.concurrency)
	var wg sync.WaitGroup

	for _, p := range s.ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			s.probe(ctx, t, host, p, emit)
		}(p)
	}
	wg.Wait()
	return nil
}

// probe dials one port; on success it grabs a short banner and emits.
func (s *Scanner) probe(ctx context.Context, t model.Target, host string, p int, emit model.EmitFunc) {
	dctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	addr := net.JoinHostPort(host, strconv.Itoa(p))
	conn, err := s.dialer.DialContext(dctx, "tcp", addr)
	if err != nil {
		return // closed or filtered
	}
	defer conn.Close()

	banner := s.grabBanner(conn)

	sev := model.SeverityInfo
	title := fmt.Sprintf("port %d/tcp open (%s)", p, serviceName[p])
	if sensitivePorts[p] {
		sev = model.SeverityMedium
		title = fmt.Sprintf("sensitive service exposed: %d/tcp (%s)", p, serviceName[p])
	}

	ev := map[string]any{"port": p, "service": serviceName[p]}
	if banner != "" {
		ev["banner"] = banner
	}
	emit(model.Finding{Scanner: s.Name(), Target: t, Severity: sev, Title: title, Evidence: ev})
}

// grabBanner reads up to bannerBytes with a short deadline. Many services send
// nothing unprompted; an empty banner is normal.
func (s *Scanner) grabBanner(conn net.Conn) string {
	_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, s.bannerBytes)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return ""
	}
	// Keep it printable and single-line.
	out := make([]rune, 0, n)
	for _, r := range string(buf[:n]) {
		if r == '\n' || r == '\r' {
			break
		}
		if r >= 32 && r < 127 {
			out = append(out, r)
		}
	}
	return string(out)
}
