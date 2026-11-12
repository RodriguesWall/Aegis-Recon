package scansvc

import (
	"testing"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

func TestDropInfo(t *testing.T) {
	in := []model.Finding{
		{Severity: model.SeverityInfo, Title: "a"},
		{Severity: model.SeverityLow, Title: "b"},
		{Severity: model.SeverityHigh, Title: "c"},
		{Severity: model.SeverityInfo, Title: "d"},
	}
	out := dropInfo(in)
	if len(out) != 2 {
		t.Fatalf("len = %d, want 2", len(out))
	}
	for _, f := range out {
		if f.Severity == model.SeverityInfo {
			t.Errorf("info finding survived: %+v", f)
		}
	}
}
