package result

// Trace records evaluation steps for diagnostics.
type Trace struct {
	Steps []TraceStep
}

// TraceStep is a single evaluation step.
type TraceStep struct {
	Depth   int
	Type    string // "allOf", "anyOf", "not", "field", "value", "count"
	Result  bool
	Field   string // for field conditions
	Value   any    // resolved field value
	Details string // human-readable
}

// Record adds a step to the trace.
func (t *Trace) Record(step TraceStep) {
	t.Steps = append(t.Steps, step)
}
