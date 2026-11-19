package report

import (
	"bytes"
	"testing"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

func TestPDF(t *testing.T) {
	fs := []model.Finding{
		{Scanner: "port", Target: model.Target{Host: "a.com", Port: 3306}, Severity: model.SeverityHigh, Title: "mysql open"},
	}
	b, err := PDF("a.com", model.Scan{Status: model.StatusCompleted}, fs)
	if err != nil {
		t.Fatalf("PDF: %v", err)
	}
	if !bytes.HasPrefix(b, []byte("%PDF")) {
		t.Fatalf("output is not a PDF (prefix %q)", b[:min(8, len(b))])
	}
	if len(b) < 500 {
		t.Fatalf("PDF suspiciously small: %d bytes", len(b))
	}
}

func TestPDFEmpty(t *testing.T) {
	b, err := PDF("a.com", model.Scan{Status: model.StatusCompleted}, nil)
	if err != nil || !bytes.HasPrefix(b, []byte("%PDF")) {
		t.Fatalf("empty-findings PDF failed: err=%v", err)
	}
}
