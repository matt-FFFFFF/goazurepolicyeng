package condition

import (
	"testing"
)

func TestOperatorRegistry(t *testing.T) {
	r := DefaultOperatorRegistry()
	for _, name := range []string{
		"equals", "notequals", "like", "notlike", "match", "notmatch",
		"matchinsensitively", "notmatchinsensitively", "contains", "notcontains",
		"in", "notin", "containskey", "notcontainskey", "exists",
		"greater", "greaterorequals", "less", "lessorequals",
	} {
		if _, ok := r.Get(name); !ok {
			t.Errorf("operator %q not found in registry", name)
		}
	}
}

func TestEquals(t *testing.T) {
	tests := []struct {
		name string
		fv   any
		cv   any
		want bool
	}{
		{"string case-insensitive", "Hello", "hello", true},
		{"string mismatch", "Hello", "world", false},
		{"int equal", 42, 42, true},
		{"int not equal", 42, 43, false},
		{"float equal", 3.14, 3.14, true},
		{"string vs int numeric", "42", 42, true},
		{"bool true", true, true, true},
		{"bool false", false, true, false},
		{"bool string", true, "true", true},
		{"nil both", nil, nil, true},
		{"nil field", nil, "hello", false},
		{"nil condition", "hello", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := opEquals(tt.fv, tt.cv)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("equals(%v, %v) = %v, want %v", tt.fv, tt.cv, got, tt.want)
			}
		})
	}
}

func TestNotEquals(t *testing.T) {
	got, _ := opNotEquals("hello", "HELLO")
	if got != false {
		t.Error("notEquals should be false for case-insensitive match")
	}
	got, _ = opNotEquals("a", "b")
	if got != true {
		t.Error("notEquals should be true for different strings")
	}
}

func TestLike(t *testing.T) {
	tests := []struct {
		name string
		fv   any
		cv   any
		want bool
	}{
		{"star at end", "hello world", "hello*", true},
		{"star at start", "hello world", "*world", true},
		{"star in middle", "hello world", "hello*world", true},
		{"star matches empty", "hello", "hello*", true},
		{"question mark", "hat", "h?t", true},
		{"question no match", "h1t", "h?t", true}, // ? = any single char in like
		{"no wildcard exact", "hello", "hello", true},
		{"no wildcard mismatch", "hello", "helo", false},
		{"case insensitive", "Hello", "hello", true},
		{"star middle mismatch", "helloXworld", "hello*earth", false},
		{"length mismatch no star", "ab", "abc", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := opLike(tt.fv, tt.cv)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("like(%v, %v) = %v, want %v", tt.fv, tt.cv, got, tt.want)
			}
		})
	}
}

func TestMatch(t *testing.T) {
	tests := []struct {
		name string
		fv   any
		cv   any
		want bool
	}{
		{"digit match", "a1b", "?#?", true},
		{"digit no match", "aab", "?#?", false},
		{"letter match", "abc", "???", true},
		{"letter no match digit", "a1c", "???", false},
		{"dot any", "a1!", ".#.", true},
		{"literal match", "abc", "abc", true},
		{"literal case sensitive", "Abc", "abc", false},
		{"length mismatch", "ab", "abc", false},
		{"empty both", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := opMatch(tt.fv, tt.cv)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("match(%v, %v) = %v, want %v", tt.fv, tt.cv, got, tt.want)
			}
		})
	}
}

func TestMatchInsensitively(t *testing.T) {
	got, _ := opMatchInsensitively("Abc", "abc")
	if !got {
		t.Error("matchInsensitively should be case-insensitive for literals")
	}
	got, _ = opMatchInsensitively("A1c", "?#?", )
	if !got {
		t.Error("matchInsensitively should match letter-digit-letter")
	}
}

func TestNotMatch(t *testing.T) {
	got, _ := opNotMatch("abc", "abc")
	if got {
		t.Error("notMatch should be false for exact match")
	}
	got, _ = opNotMatch("Abc", "abc")
	if !got {
		t.Error("notMatch should be true for case mismatch")
	}
}

func TestNotMatchInsensitively(t *testing.T) {
	got, _ := opNotMatchInsensitively("Abc", "abc")
	if got {
		t.Error("notMatchInsensitively should be false for case-insensitive match")
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		name string
		fv   any
		cv   any
		want bool
	}{
		{"substring", "hello world", "WORLD", true},
		{"substring no match", "hello world", "earth", false},
		{"array member", []any{"foo", "Bar"}, "bar", true},
		{"array no match", []any{"foo", "baz"}, "bar", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := opContains(tt.fv, tt.cv)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("contains(%v, %v) = %v, want %v", tt.fv, tt.cv, got, tt.want)
			}
		})
	}
}

func TestNotContains(t *testing.T) {
	got, _ := opNotContains("hello", "world")
	if !got {
		t.Error("notContains should be true")
	}
}

func TestIn(t *testing.T) {
	tests := []struct {
		name string
		fv   any
		cv   any
		want bool
	}{
		{"string in array", "foo", []any{"FOO", "bar"}, true},
		{"string not in", "baz", []any{"foo", "bar"}, false},
		{"number in array", 42, []any{41, 42, 43}, true},
		{"string num in array", "42", []any{42}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := opIn(tt.fv, tt.cv)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("in(%v, %v) = %v, want %v", tt.fv, tt.cv, got, tt.want)
			}
		})
	}
}

func TestNotIn(t *testing.T) {
	got, _ := opNotIn("baz", []any{"foo", "bar"})
	if !got {
		t.Error("notIn should be true")
	}
}

func TestContainsKey(t *testing.T) {
	m := map[string]any{"Env": "prod", "Team": "infra"}
	tests := []struct {
		name string
		cv   any
		want bool
	}{
		{"exact case", "Env", true},
		{"diff case", "env", true},
		{"missing", "cost", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := opContainsKey(m, tt.cv)
			if got != tt.want {
				t.Errorf("containsKey(%v) = %v, want %v", tt.cv, got, tt.want)
			}
		})
	}
	// Non-map returns false
	got, _ := opContainsKey("notamap", "key")
	if got {
		t.Error("containsKey on non-map should be false")
	}
}

func TestNotContainsKey(t *testing.T) {
	m := map[string]any{"env": "prod"}
	got, _ := opNotContainsKey(m, "cost")
	if !got {
		t.Error("notContainsKey should be true for missing key")
	}
}

func TestExists(t *testing.T) {
	tests := []struct {
		name string
		fv   any
		cv   any
		want bool
	}{
		{"true bool, field exists", "val", true, true},
		{"true string, field exists", "val", "true", true},
		{"true, nil field", nil, true, false},
		{"false, nil field", nil, false, true},
		{"false string, field exists", "val", "false", false},
		{"false bool, field exists", "val", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := opExists(tt.fv, tt.cv)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("exists(%v, %v) = %v, want %v", tt.fv, tt.cv, got, tt.want)
			}
		})
	}
}

func TestGreater(t *testing.T) {
	tests := []struct {
		name string
		fv   any
		cv   any
		want bool
	}{
		{"int greater", 10, 5, true},
		{"int not greater", 3, 5, false},
		{"float", 3.5, 3.4, true},
		{"string numeric", "42", 41, true},
		{"string compare", "banana", "apple", true},
		{"date", "2024-01-02T00:00:00Z", "2024-01-01T00:00:00Z", true},
		{"date not greater", "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := opGreater(tt.fv, tt.cv)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("greater(%v, %v) = %v, want %v", tt.fv, tt.cv, got, tt.want)
			}
		})
	}
}

func TestGreaterOrEquals(t *testing.T) {
	got, _ := opGreaterOrEquals(5, 5)
	if !got {
		t.Error("greaterOrEquals(5,5) should be true")
	}
}

func TestLess(t *testing.T) {
	got, _ := opLess(3, 5)
	if !got {
		t.Error("less(3,5) should be true")
	}
	got, _ = opLess(5, 3)
	if got {
		t.Error("less(5,3) should be false")
	}
}

func TestLessOrEquals(t *testing.T) {
	got, _ := opLessOrEquals(5, 5)
	if !got {
		t.Error("lessOrEquals(5,5) should be true")
	}
	got, _ = opLessOrEquals("2024-01-01", "2024-01-01")
	if !got {
		t.Error("lessOrEquals same date should be true")
	}
}
