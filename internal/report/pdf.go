package report

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/model"
	"github.com/RodriguesWall/aegis-recon/internal/version"
	"github.com/go-pdf/fpdf"
)

type rgb struct{ r, g, b int }

var (
	brand    = rgb{139, 92, 246}  // #8b5cf6
	accent   = rgb{6, 182, 212}   // #06b6d4
	ink      = rgb{30, 30, 30}    // body text
	muted    = rgb{120, 120, 120} // secondary text
	hairline = rgb{225, 225, 225}
)

// sevColor maps a severity to its brand color (matches the web UI).
func sevColor(s model.Severity) rgb {
	switch s {
	case model.SeverityCritical:
		return rgb{248, 113, 113}
	case model.SeverityHigh:
		return rgb{251, 146, 60}
	case model.SeverityMedium:
		return rgb{250, 204, 21}
	case model.SeverityLow:
		return rgb{96, 165, 250}
	default:
		return rgb{148, 163, 184}
	}
}

var sevOrder = []model.Severity{
	model.SeverityCritical, model.SeverityHigh, model.SeverityMedium,
	model.SeverityLow, model.SeverityInfo,
}

// PDF renders a branded, printable scan report: a header band, a severity
// summary and the findings grouped by host. Pure Go (no CGO).
func PDF(asset string, scan model.Scan, findings []model.Finding) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	// fpdf fonts use cp1252; translate UTF-8 so "·" and accents render correctly
	// instead of mojibake ("Â·").
	tr := pdf.UnicodeTranslatorFromDescriptor("")
	pdf.SetMargins(15, 14, 15)
	pdf.SetAutoPageBreak(true, 18)
	pdf.SetFooterFunc(func() { footer(pdf, tr) })
	pdf.AddPage()

	header(pdf, tr, asset, scan)
	summary(pdf, findings)
	findingsByHost(pdf, tr, findings)

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func header(pdf *fpdf.Fpdf, tr func(string) string, asset string, scan model.Scan) {
	w, _ := pdf.GetPageSize()
	// Brand band across the top, with a thin accent rule beneath.
	setFill(pdf, brand)
	pdf.Rect(0, 0, w, 24, "F")
	setFill(pdf, accent)
	pdf.Rect(0, 24, w, 1.2, "F")

	pdf.SetXY(15, 7)
	pdf.SetFont("Helvetica", "B", 18)
	pdf.SetTextColor(255, 255, 255)
	pdf.CellFormat(0, 7, "Aegis-Recon", "", 1, "L", false, 0, "")
	pdf.SetX(15)
	pdf.SetFont("Helvetica", "", 10)
	pdf.CellFormat(0, 5, "Scan Report", "", 1, "L", false, 0, "")

	pdf.SetY(32)
	setText(pdf, ink)
	pdf.SetFont("Helvetica", "B", 13)
	pdf.CellFormat(0, 7, tr(asset), "", 1, "L", false, 0, "")

	when := scan.CreatedAt
	if scan.CompletedAt != nil {
		when = *scan.CompletedAt
	}
	setText(pdf, muted)
	pdf.SetFont("Helvetica", "", 9)
	pdf.CellFormat(0, 5, tr("Status: "+string(scan.Status)+
		"   ·   Scan: "+when.UTC().Format("2006-01-02 15:04 MST")+
		"   ·   Generated: "+time.Now().UTC().Format("2006-01-02 15:04 MST")),
		"", 1, "L", false, 0, "")
	pdf.Ln(3)
}

func summary(pdf *fpdf.Fpdf, findings []model.Finding) {
	counts := map[model.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	setText(pdf, muted)
	pdf.SetFont("Helvetica", "B", 9)
	pdf.CellFormat(0, 6, "SUMMARY", "", 1, "L", false, 0, "")

	// A row of severity chips.
	x, y := pdf.GetX(), pdf.GetY()
	const cw, ch, gap = 33.0, 11.0, 3.0
	for i, s := range sevOrder {
		cx := x + float64(i)*(cw+gap)
		setFill(pdf, sevColor(s))
		pdf.RoundedRect(cx, y, cw, ch, 1.5, "1234", "F")
		pdf.SetXY(cx, y+1.5)
		pdf.SetTextColor(30, 30, 30)
		pdf.SetFont("Helvetica", "B", 12)
		pdf.CellFormat(cw, 5, strconv.Itoa(counts[s]), "", 2, "C", false, 0, "")
		pdf.SetFont("Helvetica", "", 7)
		pdf.CellFormat(cw, 4, cases(string(s)), "", 0, "C", false, 0, "")
	}
	pdf.SetXY(x, y+ch+2)
	setText(pdf, muted)
	pdf.SetFont("Helvetica", "", 9)
	pdf.CellFormat(0, 6, "Total findings: "+strconv.Itoa(len(findings)), "", 1, "L", false, 0, "")
	pdf.Ln(2)
}

func findingsByHost(pdf *fpdf.Fpdf, tr func(string) string, findings []model.Finding) {
	setText(pdf, muted)
	pdf.SetFont("Helvetica", "B", 9)
	pdf.CellFormat(0, 6, "FINDINGS", "", 1, "L", false, 0, "")

	if len(findings) == 0 {
		setText(pdf, ink)
		pdf.SetFont("Helvetica", "", 10)
		pdf.CellFormat(0, 6, "No findings — clean.", "", 1, "L", false, 0, "")
		return
	}

	// Group by host, hosts sorted, findings by severity desc.
	byHost := map[string][]model.Finding{}
	for _, f := range findings {
		h := f.Target.Host
		if h == "" {
			h = f.Target.Domain
		}
		if h == "" {
			h = "—"
		}
		byHost[h] = append(byHost[h], f)
	}
	hosts := make([]string, 0, len(byHost))
	for h := range byHost {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	for _, h := range hosts {
		fs := byHost[h]
		sort.SliceStable(fs, func(i, j int) bool { return fs[i].Severity.Rank() > fs[j].Severity.Rank() })

		pdf.Ln(2)
		setText(pdf, ink)
		pdf.SetFont("Helvetica", "B", 11)
		pdf.CellFormat(0, 6, tr(h), "", 1, "L", false, 0, "")
		setDraw(pdf, hairline)
		y := pdf.GetY()
		pdf.Line(15, y, 195, y)
		pdf.Ln(1.5)

		for _, f := range fs {
			finding(pdf, tr, f)
		}
	}
}

func finding(pdf *fpdf.Fpdf, tr func(string) string, f model.Finding) {
	// Severity tag.
	x, y := pdf.GetX(), pdf.GetY()
	label := cases(string(f.Severity))
	setFill(pdf, sevColor(f.Severity))
	pdf.RoundedRect(x, y, 20, 5, 1, "1234", "F")
	pdf.SetXY(x, y+0.6)
	pdf.SetTextColor(30, 30, 30)
	pdf.SetFont("Helvetica", "B", 7.5)
	pdf.CellFormat(20, 4, label, "", 0, "C", false, 0, "")

	// Title.
	setText(pdf, ink)
	pdf.SetFont("Helvetica", "B", 9.5)
	pdf.SetXY(x+23, y)
	pdf.MultiCell(157, 5, tr(f.Title), "", "L", false)

	// Meta line.
	loc := f.Target.Host
	if loc == "" {
		loc = f.Target.Domain
	}
	if f.Target.Port != 0 {
		loc += ":" + strconv.Itoa(f.Target.Port)
	}
	setText(pdf, muted)
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetX(x + 23)
	meta := f.Scanner
	if loc != "" {
		meta = loc + "  ·  " + f.Scanner
	}
	if ev := shortEvidence(f.Evidence); ev != "" {
		meta += "  ·  " + ev
	}
	pdf.MultiCell(157, 4, tr(meta), "", "L", false)
	if rem := Remediation(f); rem != "" {
		setText(pdf, rgb{80, 110, 70})
		pdf.SetFont("Helvetica", "I", 8)
		pdf.SetX(x + 23)
		pdf.MultiCell(157, 4, tr("Fix: "+rem), "", "L", false)
	}
	pdf.Ln(1.5)
}

func footer(pdf *fpdf.Fpdf, tr func(string) string) {
	pdf.SetY(-14)
	setText(pdf, muted)
	pdf.SetFont("Helvetica", "", 7.5)
	pdf.CellFormat(0, 5, tr(fmt.Sprintf("Aegis-Recon %s  ·  authorized use only  ·  page %d",
		version.Version, pdf.PageNo())), "", 0, "C", false, 0, "")
}

func shortEvidence(ev map[string]any) string {
	if len(ev) == 0 {
		return ""
	}
	var parts []string
	for k, v := range ev {
		parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		if len(parts) == 3 {
			break
		}
	}
	sort.Strings(parts)
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	if len(out) > 140 {
		out = out[:140]
	}
	return out
}

func setFill(pdf *fpdf.Fpdf, c rgb) { pdf.SetFillColor(c.r, c.g, c.b) }
func setText(pdf *fpdf.Fpdf, c rgb) { pdf.SetTextColor(c.r, c.g, c.b) }
func setDraw(pdf *fpdf.Fpdf, c rgb) { pdf.SetDrawColor(c.r, c.g, c.b) }

// cases title-cases a lowercase severity for display.
func cases(s string) string {
	if s == "" {
		return s
	}
	return string(s[0]-32) + s[1:]
}
