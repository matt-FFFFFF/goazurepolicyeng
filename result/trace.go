package result

import (
	"fmt"
	"strings"
	"time"
)

// Trace records the evaluation path for diagnostics/explain mode.
type Trace struct {
	Steps []TraceStep
}

// TraceStep is a single evaluation step.
type TraceStep struct {
	Depth    int           `json:"depth"`
	Type     string        `json:"type"`     // "allOf", "anyOf", "not", "field", "value", "count"
	Result   bool          `json:"result"`
	Duration time.Duration `json:"duration"`

	// For field/value conditions
	Field    string `json:"field,omitempty"`
	Operator string `json:"operator,omitempty"`
	Expected any    `json:"expected,omitempty"` // condition operand
	Actual   any    `json:"actual,omitempty"`   // resolved value

	// For count
	Count *int `json:"count,omitempty"` // count result

	// Human-readable detail
	Detail string `json:"detail,omitempty"`
}

// NewTrace creates a new Trace with pre-allocated step storage.
func NewTrace() *Trace {
	return &Trace{Steps: make([]TraceStep, 0, 16)}
}

// Record adds a step to the trace.
func (t *Trace) Record(step TraceStep) {
	if t != nil {
		t.Steps = append(t.Steps, step)
	}
}

// Summary returns a human-readable summary of the trace.
func (t *Trace) Summary() string {
	if t == nil || len(t.Steps) == 0 {
		return "<no trace>"
	}
	var b strings.Builder
	for _, s := range t.Steps {
		indent := strings.Repeat("  ", s.Depth)
		icon := "✗"
		if s.Result {
			icon = "✓"
		}
		fmt.Fprintf(&b, "%s[%s] %s", indent, icon, s.Detail)
		if s.Duration > 0 {
			fmt.Fprintf(&b, " (%s)", s.Duration)
		}
		b.WriteByte('\n')
	}
	return b.String()
}
