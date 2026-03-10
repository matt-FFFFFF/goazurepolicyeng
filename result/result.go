package result

// Reason describes why a resource is non-compliant.
type Reason struct {
	Field    string `json:"field"`    // alias or built-in field name
	Operator string `json:"operator"` // e.g. "equals", "notIn"
	Expected any    `json:"expected"` // what the policy required
	Actual   any    `json:"actual"`   // what the resource had
	Message  string `json:"message"`  // human-readable: "Field 'X' is 'Y', expected 'Z'"
}
