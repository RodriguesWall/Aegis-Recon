package report_test

import (
	"encoding/json"
	"testing"

	"github.com/RodriguesWall/aegis-recon/internal/model"
	"github.com/RodriguesWall/aegis-recon/internal/report"
)

func TestSARIF(t *testing.T) {
	findings := []model.Finding{
		{
			Scanner:  "port",
			Target:   model.Target{Host: "mail.example.com", Port: 3306},
			Severity: model.SeverityMedium,
			Title:    "sensitive service exposed: 3306/tcp (mysql)",
			Evidence: map[string]any{"service": "mysql"},
		},
		{
			Scanner:  "httpprobe",
			Target:   model.Target{Host: "example.com"},
			Severity: model.SeverityLow,
			Title:    "missing Content-Security-Policy header",
		},
		{
			Scanner:  "port",
			Target:   model.Target{Host: "example.com", Port: 22},
			Severity: model.SeverityCritical,
			Title:    "open port: 22/tcp",
		},
	}

	raw, err := report.SARIF(findings)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}

	// Parse back and assert the structure GitHub/IDEs rely on.
	var doc struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					LogicalLocations []struct {
						FullyQualifiedName string `json:"fullyQualifiedName"`
					} `json:"logicalLocations"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, raw)
	}

	if doc.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", doc.Version)
	}
	if doc.Schema == "" {
		t.Error("missing $schema")
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "Aegis-Recon" {
		t.Errorf("driver name = %q", run.Tool.Driver.Name)
	}
	// Two distinct scanners -> two rules (port, httpprobe), sorted.
	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(run.Tool.Driver.Rules))
	}
	if run.Tool.Driver.Rules[0].ID != "httpprobe" || run.Tool.Driver.Rules[1].ID != "port" {
		t.Errorf("rules not sorted: %+v", run.Tool.Driver.Rules)
	}
	if len(run.Results) != 3 {
		t.Fatalf("results = %d, want 3", len(run.Results))
	}

	// Severity -> level mapping and location formatting.
	byTitle := map[string]string{}
	locByTitle := map[string]string{}
	for _, r := range run.Results {
		byTitle[r.Message.Text] = r.Level
		if len(r.Locations) > 0 && len(r.Locations[0].LogicalLocations) > 0 {
			locByTitle[r.Message.Text] = r.Locations[0].LogicalLocations[0].FullyQualifiedName
		}
	}
	if byTitle["open port: 22/tcp"] != "error" {
		t.Errorf("critical -> %q, want error", byTitle["open port: 22/tcp"])
	}
	if byTitle["sensitive service exposed: 3306/tcp (mysql)"] != "warning" {
		t.Errorf("medium -> %q, want warning", byTitle["sensitive service exposed: 3306/tcp (mysql)"])
	}
	if byTitle["missing Content-Security-Policy header"] != "note" {
		t.Errorf("low -> %q, want note", byTitle["missing Content-Security-Policy header"])
	}
	if locByTitle["sensitive service exposed: 3306/tcp (mysql)"] != "mail.example.com:3306" {
		t.Errorf("location = %q, want mail.example.com:3306", locByTitle["sensitive service exposed: 3306/tcp (mysql)"])
	}
}

func TestSARIF_Empty(t *testing.T) {
	raw, err := report.SARIF(nil)
	if err != nil {
		t.Fatalf("SARIF(nil): %v", err)
	}
	if !json.Valid(raw) {
		t.Fatalf("invalid JSON: %s", raw)
	}
}
