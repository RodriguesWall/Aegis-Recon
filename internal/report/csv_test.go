package report

import (
	"encoding/csv"
	"strings"
	"testing"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

func TestCSV(t *testing.T) {
	fs := []model.Finding{
		{Scanner: "port", Target: model.Target{Host: "a.com", Port: 3306}, Severity: model.SeverityHigh, Title: "mysql, open", Evidence: map[string]any{"state": "open"}},
	}
	b, err := CSV(fs)
	if err != nil {
		t.Fatalf("CSV: %v", err)
	}
	rows, err := csv.NewReader(strings.NewReader(string(b))).ReadAll()
	if err != nil {
		t.Fatalf("parse csv: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("want header + 1 row, got %d", len(rows))
	}
	if rows[0][0] != "severity" || rows[0][4] != "title" {
		t.Fatalf("header wrong: %v", rows[0])
	}
	r := rows[1]
	// title with a comma must survive CSV quoting.
	if r[0] != "high" || r[1] != "port" || r[2] != "a.com" || r[3] != "3306" || r[4] != "mysql, open" {
		t.Fatalf("row wrong: %v", r)
	}
	if !strings.Contains(r[6], "open") {
		t.Fatalf("evidence missing: %v", r)
	}
}
