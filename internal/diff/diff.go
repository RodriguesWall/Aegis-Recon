// Package diff compares two scans of the same asset and reports what changed.
// It is pure: no store, no network. Findings are matched by their stable
// fingerprint (see model.Finding.Fingerprint), so the same exposure re-detected
// on a later scan is recognized as the same finding.
package diff

import "github.com/RodriguesWall/aegis-recon/internal/model"

// Status classifies a finding in a diff between a previous and a current scan.
type Status string

const (
	// StatusNew is a finding present in the current scan but not the previous.
	StatusNew Status = "new"
	// StatusResolved is a finding present in the previous scan but not the current.
	StatusResolved Status = "resolved"
	// StatusUnchanged is a finding present in both scans.
	StatusUnchanged Status = "unchanged"
)

// Result groups the findings of a diff by status. New and Unchanged carry
// findings from the current scan; Resolved carries them from the previous scan
// (they no longer exist in the current one).
type Result struct {
	New       []model.Finding `json:"new"`
	Resolved  []model.Finding `json:"resolved"`
	Unchanged []model.Finding `json:"unchanged"`
}

// Counts is the headline summary of a diff.
type Counts struct {
	New       int `json:"new"`
	Resolved  int `json:"resolved"`
	Unchanged int `json:"unchanged"`
}

// Counts returns the per-status totals.
func (r Result) Counts() Counts {
	return Counts{
		New:       len(r.New),
		Resolved:  len(r.Resolved),
		Unchanged: len(r.Unchanged),
	}
}

// SuppressNew reclassifies NEW findings whose fingerprint is marked suppressed
// (e.g. triaged false-positive / accepted-risk) as unchanged, so an already
// judged finding never resurfaces as NEW. Resolved and unchanged are untouched.
// Returns a new Result; the receiver is not mutated.
func (r Result) SuppressNew(suppressed map[string]bool) Result {
	if len(suppressed) == 0 {
		return r
	}
	out := Result{Resolved: r.Resolved, Unchanged: r.Unchanged}
	for _, f := range r.New {
		if suppressed[f.Fingerprint()] {
			out.Unchanged = append(out.Unchanged, f)
		} else {
			out.New = append(out.New, f)
		}
	}
	return out
}

// Scans compares a current scan against a previous one, matching findings by
// fingerprint.
//
//   - new:       in current, not in previous
//   - resolved:  in previous, not in current
//   - unchanged: in both
//
// A nil previous (no earlier scan) makes every current finding new. Within each
// scan the first finding seen for a fingerprint wins, so duplicate fingerprints
// collapse to one entry and never cross-classify.
func Scans(current, previous []model.Finding) Result {
	prev := make(map[string]struct{}, len(previous))
	for _, f := range previous {
		prev[f.Fingerprint()] = struct{}{}
	}

	res := Result{}
	seen := make(map[string]struct{}, len(current))
	for _, f := range current {
		fp := f.Fingerprint()
		if _, dup := seen[fp]; dup {
			continue
		}
		seen[fp] = struct{}{}
		if _, ok := prev[fp]; ok {
			res.Unchanged = append(res.Unchanged, f)
		} else {
			res.New = append(res.New, f)
		}
	}

	resolvedSeen := make(map[string]struct{}, len(previous))
	for _, f := range previous {
		fp := f.Fingerprint()
		if _, dup := resolvedSeen[fp]; dup {
			continue
		}
		resolvedSeen[fp] = struct{}{}
		if _, ok := seen[fp]; !ok {
			res.Resolved = append(res.Resolved, f)
		}
	}

	return res
}
