// Package progress holds live, in-memory progress for running scans. The scan
// service writes to it; the API reads from it so the dashboard can poll. It is
// not durable — progress is only meaningful while a scan runs.
package progress

import (
	"sync"
	"time"
)

const maxLog = 50

// Snapshot is the readable progress state of one scan.
type Snapshot struct {
	Phase     string    `json:"phase"` // discovery | probing | done
	Done      int       `json:"done"`
	Total     int       `json:"total"`
	Log       []string  `json:"log"`
	UpdatedAt time.Time `json:"updated_at"`
}

type entry struct {
	phase string
	done  int
	total int
	log   []string
	at    time.Time
}

// Tracker stores progress per scan id.
type Tracker struct {
	mu sync.RWMutex
	m  map[string]*entry
}

// New returns an empty tracker.
func New() *Tracker { return &Tracker{m: map[string]*entry{}} }

func (t *Tracker) with(id string, fn func(e *entry)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.m[id]
	if e == nil {
		e = &entry{}
		t.m[id] = e
	}
	fn(e)
	e.at = time.Now()
}

// Start initializes a scan's progress.
func (t *Tracker) Start(id string) {
	t.with(id, func(e *entry) {
		e.phase = "discovery"
		e.done, e.total = 0, 0
		e.log = nil
	})
}

// SetProgress updates phase and done/total counts (total 0 leaves it unchanged).
func (t *Tracker) SetProgress(id, phase string, done, total int) {
	t.with(id, func(e *entry) {
		if phase != "" {
			e.phase = phase
		}
		if done > e.done {
			e.done = done
		}
		if total > 0 {
			e.total = total
		}
	})
}

// Log appends a line (keeping the last maxLog).
func (t *Tracker) Log(id, line string) {
	t.with(id, func(e *entry) {
		e.log = append(e.log, line)
		if len(e.log) > maxLog {
			e.log = e.log[len(e.log)-maxLog:]
		}
	})
}

// Done marks the scan finished.
func (t *Tracker) Done(id string) {
	t.with(id, func(e *entry) {
		e.phase = "done"
		if e.total > 0 {
			e.done = e.total
		}
	})
}

// Get returns a snapshot and whether it exists.
func (t *Tracker) Get(id string) (Snapshot, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e := t.m[id]
	if e == nil {
		return Snapshot{}, false
	}
	logCopy := append([]string(nil), e.log...)
	return Snapshot{
		Phase:     e.phase,
		Done:      e.done,
		Total:     e.total,
		Log:       logCopy,
		UpdatedAt: e.at,
	}, true
}
