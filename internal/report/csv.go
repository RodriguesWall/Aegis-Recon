package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strconv"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

// CSV renders findings as a spreadsheet-friendly CSV: one row per finding.
func CSV(findings []model.Finding) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write([]string{"severity", "scanner", "host", "port", "title", "fingerprint", "evidence"}); err != nil {
		return nil, err
	}
	for _, f := range findings {
		host := f.Target.Host
		if host == "" {
			host = f.Target.Domain
		}
		port := ""
		if f.Target.Port != 0 {
			port = strconv.Itoa(f.Target.Port)
		}
		ev := ""
		if len(f.Evidence) > 0 {
			if b, err := json.Marshal(f.Evidence); err == nil {
				ev = string(b)
			}
		}
		if err := w.Write([]string{
			string(f.Severity), f.Scanner, host, port, f.Title, f.Fingerprint(), ev,
		}); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}
