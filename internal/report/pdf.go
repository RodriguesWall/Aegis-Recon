package report

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/model"
	"github.com/go-pdf/fpdf"
)

// PDF renders a scan report as a PDF document: a header, a severity summary and
// the findings sorted by severity. Pure Go (no CGO).
func PDF(asset string, scan model.Scan, findings []model.Finding) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(15, 15, 15)
	pdf.AddPage()

	// Header.
	pdf.SetFont("Helvetica", "B", 18)
	pdf.CellFormat(0, 10, "Aegis-Recon — Scan Report", "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 11)
	pdf.SetTextColor(90, 90, 90)
	pdf.CellFormat(0, 6, "Service: "+asset, "", 1, "L", false, 0, "")
	pdf.CellFormat(0, 6, "Status: "+string(scan.Status), "", 1, "L", false, 0, "")
	when := scan.CreatedAt
	if scan.CompletedAt != nil {
		when = *scan.CompletedAt
	}
	pdf.CellFormat(0, 6, "Generated: "+time.Now().UTC().Format("2006-01-02 15:04 MST")+
		"  ·  Scan: "+when.UTC().Format("2006-01-02 15:04 MST"), "", 1, "L", false, 0, "")
	pdf.SetTextColor(0, 0, 0)
	pdf.Ln(4)

	// Severity summary.
	counts := map[model.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	pdf.SetFont("Helvetica", "B", 12)
	pdf.CellFormat(0, 8, "Summary", "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 11)
	for _, sev := range []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo} {
		pdf.CellFormat(40, 6, cases(string(sev)), "", 0, "L", false, 0, "")
		pdf.CellFormat(0, 6, strconv.Itoa(counts[sev]), "", 1, "L", false, 0, "")
	}
	pdf.CellFormat(40, 6, "Total", "", 0, "L", false, 0, "")
	pdf.CellFormat(0, 6, strconv.Itoa(len(findings)), "", 1, "L", false, 0, "")
	pdf.Ln(4)

	// Findings.
	pdf.SetFont("Helvetica", "B", 12)
	pdf.CellFormat(0, 8, "Findings", "", 1, "L", false, 0, "")

	if len(findings) == 0 {
		pdf.SetFont("Helvetica", "", 11)
		pdf.CellFormat(0, 6, "No findings — clean.", "", 1, "L", false, 0, "")
	}

	sorted := append([]model.Finding(nil), findings...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Severity.Rank() > sorted[j].Severity.Rank() })
	for _, f := range sorted {
		host := f.Target.Host
		if host == "" {
			host = f.Target.Domain
		}
		loc := host
		if f.Target.Port != 0 {
			loc += ":" + strconv.Itoa(f.Target.Port)
		}
		pdf.SetFont("Helvetica", "B", 10)
		pdf.MultiCell(0, 5, fmt.Sprintf("[%s] %s", cases(string(f.Severity)), f.Title), "", "L", false)
		pdf.SetFont("Helvetica", "", 9)
		pdf.SetTextColor(90, 90, 90)
		pdf.MultiCell(0, 5, loc+"  ·  "+f.Scanner, "", "L", false)
		pdf.SetTextColor(0, 0, 0)
		pdf.Ln(1)
	}

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// cases title-cases a lowercase severity for display.
func cases(s string) string {
	if s == "" {
		return s
	}
	return string(s[0]-32) + s[1:]
}
