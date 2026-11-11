package port_test

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/model"
	"github.com/RodriguesWall/aegis-recon/internal/scanner/port"
)

func TestScan_DetectsOpenPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Accept and close connections quickly so banner read returns fast.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	openPort, _ := strconv.Atoi(portStr)

	s := port.New(&net.Dialer{}, port.WithPorts([]int{openPort}), port.WithTimeout(time.Second))

	var got []model.Finding
	if err := s.Scan(context.Background(), model.Target{Host: "127.0.0.1"}, func(f model.Finding) {
		got = append(got, f)
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1 (%+v)", len(got), got)
	}
	if got[0].Evidence["port"] != openPort {
		t.Errorf("port = %v, want %d", got[0].Evidence["port"], openPort)
	}
}

func TestScan_ClosedPortNoFinding(t *testing.T) {
	// Grab a port then release it, so nothing is listening.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	closedPort, _ := strconv.Atoi(portStr)
	ln.Close()

	s := port.New(&net.Dialer{}, port.WithPorts([]int{closedPort}), port.WithTimeout(200*time.Millisecond))

	var got []model.Finding
	_ = s.Scan(context.Background(), model.Target{Host: "127.0.0.1"}, func(f model.Finding) {
		got = append(got, f)
	})
	if len(got) != 0 {
		t.Fatalf("expected no findings on closed port, got %+v", got)
	}
}
