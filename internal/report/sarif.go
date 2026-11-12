// Package report converts scan findings into interchange formats. SARIF 2.1.0
// is the OASIS standard consumed by GitHub code scanning, IDEs and other
// security tooling, so findings surface where developers already work.
package report

import (
	"encoding/json"
	"sort"
	"strconv"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

const (
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion = "2.1.0"
	toolName     = "Aegis-Recon"
	toolURI      = "https://github.com/RodriguesWall/Aegis-Recon"
)

// SARIF renders findings as an indented SARIF 2.1.0 document. One rule is
// emitted per distinct scanner module; each finding becomes one result.
func SARIF(findings []model.Finding) ([]byte, error) {
	rulesByID := map[string]sarifRule{}
	results := make([]sarifResult, 0, len(findings))

	for _, f := range findings {
		id := f.Scanner
		if id == "" {
			id = "aegis"
		}
		if _, ok := rulesByID[id]; !ok {
			rulesByID[id] = sarifRule{
				ID:               id,
				Name:             id,
				ShortDescription: sarifText{Text: id + " surface-recon checks"},
			}
		}

		res := sarifResult{
			RuleID:     id,
			Level:      sarifLevel(f.Severity),
			Message:    sarifText{Text: f.Title},
			Properties: map[string]any{"severity": string(f.Severity)},
		}
		if loc := targetName(f.Target); loc != "" {
			res.Locations = []sarifLocation{{
				LogicalLocations: []sarifLogicalLoc{{FullyQualifiedName: loc, Kind: "resource"}},
			}}
		}
		if len(f.Evidence) > 0 {
			res.Properties["evidence"] = f.Evidence
		}
		results = append(results, res)
	}

	// Stable rule order for deterministic output.
	ids := make([]string, 0, len(rulesByID))
	for id := range rulesByID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rules := make([]sarifRule, 0, len(ids))
	for _, id := range ids {
		rules = append(rules, rulesByID[id])
	}

	doc := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: toolName, InformationURI: toolURI, Rules: rules}},
			Results: results,
		}},
	}
	return json.MarshalIndent(doc, "", "  ")
}

// sarifLevel maps an Aegis severity onto the SARIF level enum
// (none|note|warning|error).
func sarifLevel(s model.Severity) string {
	switch s {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default: // low, info, unknown
		return "note"
	}
}

// targetName renders a target as a stable location string: host (or domain),
// with :port appended when set.
func targetName(t model.Target) string {
	name := t.Host
	if name == "" {
		name = t.Domain
	}
	if name == "" {
		return ""
	}
	if t.Port > 0 {
		return name + ":" + strconv.Itoa(t.Port)
	}
	return name
}

// ---- SARIF 2.1.0 types (minimal subset) ----

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	ShortDescription sarifText `json:"shortDescription"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifText       `json:"message"`
	Locations  []sarifLocation `json:"locations,omitempty"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifLocation struct {
	LogicalLocations []sarifLogicalLoc `json:"logicalLocations,omitempty"`
}

type sarifLogicalLoc struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}
