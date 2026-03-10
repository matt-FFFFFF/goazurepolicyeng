package condition

import (
	"fmt"
	"strings"
)

// equals — case-insensitive string; numeric if both numeric; bool if both bool.
func opEquals(fieldValue any, conditionValue any) (bool, error) {
	// nil handling
	if fieldValue == nil && conditionValue == nil {
		return true, nil
	}
	if fieldValue == nil || conditionValue == nil {
		return false, nil
	}

	// Try bool comparison
	if fb, ok := toBool(fieldValue); ok {
		if cb, ok2 := toBool(conditionValue); ok2 {
			return fb == cb, nil
		}
	}

	// Try numeric comparison
	if fn, ok := toFloat64(fieldValue); ok {
		if cn, ok2 := toFloat64(conditionValue); ok2 {
			return fn == cn, nil
		}
	}

	// String comparison (case-insensitive)
	return strings.EqualFold(toString(fieldValue), toString(conditionValue)), nil
}

func opNotEquals(fv any, cv any) (bool, error) {
	r, err := opEquals(fv, cv)
	return !r, err
}

// like — case-insensitive glob with * and ?
func opLike(fieldValue any, conditionValue any) (bool, error) {
	field := strings.ToLower(toString(fieldValue))
	pattern := strings.ToLower(toString(conditionValue))
	return globMatch(field, pattern), nil
}

func opNotLike(fv any, cv any) (bool, error) {
	r, err := opLike(fv, cv)
	return !r, err
}

// globMatch: * matches zero or more chars, ? matches exactly one char.
func globMatch(s, pattern string) bool {
	// Split on * (max one *)
	starIdx := strings.Index(pattern, "*")
	if starIdx == -1 {
		// No star — match char by char with ? support
		if len(s) != len(pattern) {
			return false
		}
		for i := range pattern {
			if pattern[i] != '?' && pattern[i] != s[i] {
				return false
			}
		}
		return true
	}

	prefix := pattern[:starIdx]
	suffix := pattern[starIdx+1:]

	// prefix must match start
	if len(s) < len(prefix) || !globSegment(s[:len(prefix)], prefix) {
		return false
	}
	// suffix must match end
	if len(s) < len(prefix)+len(suffix) || !globSegment(s[len(s)-len(suffix):], suffix) {
		return false
	}
	return true
}

func globSegment(s, pattern string) bool {
	if len(s) != len(pattern) {
		return false
	}
	for i := range pattern {
		if pattern[i] != '?' && pattern[i] != s[i] {
			return false
		}
	}
	return true
}

// match — case-sensitive: # = digit, ? = letter, . = any, others literal
func opMatch(fieldValue any, conditionValue any) (bool, error) {
	return matchPattern(toString(fieldValue), toString(conditionValue), true), nil
}

func opNotMatch(fv any, cv any) (bool, error) {
	r, err := opMatch(fv, cv)
	return !r, err
}

func opMatchInsensitively(fieldValue any, conditionValue any) (bool, error) {
	return matchPattern(toString(fieldValue), toString(conditionValue), false), nil
}

func opNotMatchInsensitively(fv any, cv any) (bool, error) {
	r, err := opMatchInsensitively(fv, cv)
	return !r, err
}

func matchPattern(s, pattern string, caseSensitive bool) bool {
	if len(s) != len(pattern) {
		return false
	}
	for i := 0; i < len(pattern); i++ {
		pc := pattern[i]
		sc := s[i]
		switch pc {
		case '#':
			if sc < '0' || sc > '9' {
				return false
			}
		case '?':
			if (sc < 'a' || sc > 'z') && (sc < 'A' || sc > 'Z') {
				return false
			}
		case '.':
			// any char
		default:
			if caseSensitive {
				if sc != pc {
					return false
				}
			} else {
				if toLowerByte(sc) != toLowerByte(pc) {
					return false
				}
			}
		}
	}
	return true
}

func toLowerByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}

// contains — substring for strings, element membership for arrays
func opContains(fieldValue any, conditionValue any) (bool, error) {
	// If fieldValue is a slice, check element membership
	if arr, ok := toSlice(fieldValue); ok {
		cv := toString(conditionValue)
		for _, elem := range arr {
			if strings.EqualFold(toString(elem), cv) {
				return true, nil
			}
		}
		return false, nil
	}
	// String substring check
	return strings.Contains(
		strings.ToLower(toString(fieldValue)),
		strings.ToLower(toString(conditionValue)),
	), nil
}

func opNotContains(fv any, cv any) (bool, error) {
	r, err := opContains(fv, cv)
	return !r, err
}

// in — field value exists in condition array
func opIn(fieldValue any, conditionValue any) (bool, error) {
	arr, ok := toSlice(conditionValue)
	if !ok {
		return false, fmt.Errorf("in: conditionValue must be an array")
	}
	fv := toString(fieldValue)
	// Try numeric
	if fn, fok := toFloat64(fieldValue); fok {
		for _, elem := range arr {
			if cn, cok := toFloat64(elem); cok && fn == cn {
				return true, nil
			}
		}
	}
	for _, elem := range arr {
		if strings.EqualFold(fv, toString(elem)) {
			return true, nil
		}
	}
	return false, nil
}

func opNotIn(fv any, cv any) (bool, error) {
	r, err := opIn(fv, cv)
	return !r, err
}

// containsKey — map key lookup (case-insensitive)
func opContainsKey(fieldValue any, conditionValue any) (bool, error) {
	m, ok := fieldValue.(map[string]any)
	if !ok {
		return false, nil
	}
	key := strings.ToLower(toString(conditionValue))
	for k := range m {
		if strings.ToLower(k) == key {
			return true, nil
		}
	}
	return false, nil
}

func opNotContainsKey(fv any, cv any) (bool, error) {
	r, err := opContainsKey(fv, cv)
	return !r, err
}

// exists — "true"/true means field must exist (not nil), "false"/false means must not exist
func opExists(fieldValue any, conditionValue any) (bool, error) {
	wantExists := false
	switch v := conditionValue.(type) {
	case bool:
		wantExists = v
	case string:
		wantExists = strings.EqualFold(v, "true")
	default:
		wantExists = true
	}
	fieldExists := fieldValue != nil
	if wantExists {
		return fieldExists, nil
	}
	return !fieldExists, nil
}

// Ordering operators
func opGreater(fieldValue any, conditionValue any) (bool, error) {
	cmp, err := compareValues(fieldValue, conditionValue)
	if err != nil {
		return false, err
	}
	return cmp > 0, nil
}

func opGreaterOrEquals(fieldValue any, conditionValue any) (bool, error) {
	cmp, err := compareValues(fieldValue, conditionValue)
	if err != nil {
		return false, err
	}
	return cmp >= 0, nil
}

func opLess(fieldValue any, conditionValue any) (bool, error) {
	cmp, err := compareValues(fieldValue, conditionValue)
	if err != nil {
		return false, err
	}
	return cmp < 0, nil
}

func opLessOrEquals(fieldValue any, conditionValue any) (bool, error) {
	cmp, err := compareValues(fieldValue, conditionValue)
	if err != nil {
		return false, err
	}
	return cmp <= 0, nil
}

// compareValues returns -1, 0, or 1. Tries numeric, then date, then string.
func compareValues(a, b any) (int, error) {
	// Try numeric
	if an, ok := toFloat64(a); ok {
		if bn, ok2 := toFloat64(b); ok2 {
			switch {
			case an < bn:
				return -1, nil
			case an > bn:
				return 1, nil
			default:
				return 0, nil
			}
		}
	}

	// Try date
	if at, ok := toTime(a); ok {
		if bt, ok2 := toTime(b); ok2 {
			switch {
			case at.Before(bt):
				return -1, nil
			case at.After(bt):
				return 1, nil
			default:
				return 0, nil
			}
		}
	}

	// String comparison (case-insensitive)
	as := strings.ToLower(toString(a))
	bs := strings.ToLower(toString(b))
	switch {
	case as < bs:
		return -1, nil
	case as > bs:
		return 1, nil
	default:
		return 0, nil
	}
}

// toSlice tries to convert any to []any
func toSlice(v any) ([]any, bool) {
	switch s := v.(type) {
	case []any:
		return s, true
	case []string:
		r := make([]any, len(s))
		for i, x := range s {
			r[i] = x
		}
		return r, true
	case []int:
		r := make([]any, len(s))
		for i, x := range s {
			r[i] = x
		}
		return r, true
	case []float64:
		r := make([]any, len(s))
		for i, x := range s {
			r[i] = x
		}
		return r, true
	}
	return nil, false
}
