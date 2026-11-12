package progress_test

import (
	"testing"

	"github.com/RodriguesWall/aegis-recon/internal/progress"
)

func TestTracker(t *testing.T) {
	tr := progress.New()

	if _, ok := tr.Get("x"); ok {
		t.Fatal("expected no snapshot before start")
	}

	tr.Start("x")
	tr.SetProgress("x", "probing", 1, 10)
	tr.Log("x", "probe a")
	tr.SetProgress("x", "probing", 3, 0) // total 0 keeps previous total
	tr.Log("x", "probe b")

	s, ok := tr.Get("x")
	if !ok {
		t.Fatal("expected snapshot")
	}
	if s.Phase != "probing" || s.Done != 3 || s.Total != 10 {
		t.Fatalf("snapshot = %+v", s)
	}
	if len(s.Log) != 2 || s.Log[1] != "probe b" {
		t.Fatalf("log = %v", s.Log)
	}

	// done should clamp done to total and set phase.
	tr.Done("x")
	s, _ = tr.Get("x")
	if s.Phase != "done" || s.Done != 10 {
		t.Fatalf("after done = %+v", s)
	}
}

func TestTracker_DoneCountMonotonic(t *testing.T) {
	tr := progress.New()
	tr.Start("y")
	tr.SetProgress("y", "probing", 5, 10)
	tr.SetProgress("y", "probing", 2, 10) // out-of-order lower value ignored
	s, _ := tr.Get("y")
	if s.Done != 5 {
		t.Fatalf("done = %d, want 5 (monotonic)", s.Done)
	}
}
