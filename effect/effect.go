// Package effect handles Azure Policy effect resolution and compliance determination.
package effect

import (
	"fmt"
	"strings"
)

// Effect represents a resolved Azure Policy effect.
type Effect string

const (
	Deny              Effect = "deny"
	Audit             Effect = "audit"
	Modify            Effect = "modify"
	Append            Effect = "append"
	AuditIfNotExists  Effect = "auditIfNotExists"
	DeployIfNotExists Effect = "deployIfNotExists"
	Disabled          Effect = "disabled"
	Manual            Effect = "manual"
	DenyAction        Effect = "denyAction"
	Mutate            Effect = "mutate"
)

// allEffects maps lowercase effect names to canonical Effect values.
var allEffects = map[string]Effect{
	"deny":              Deny,
	"audit":             Audit,
	"modify":            Modify,
	"append":            Append,
	"auditifnotexists":  AuditIfNotExists,
	"deployifnotexists": DeployIfNotExists,
	"disabled":          Disabled,
	"manual":            Manual,
	"denyaction":        DenyAction,
	"mutate":            Mutate,
}

// ParseEffect normalises an effect string (case-insensitive).
func ParseEffect(s string) (Effect, error) {
	if eff, ok := allEffects[strings.ToLower(s)]; ok {
		return eff, nil
	}
	return "", fmt.Errorf("unknown effect: %q", s)
}

// ComplianceState represents the result of compliance determination.
type ComplianceState int

const (
	Compliant           ComplianceState = iota
	NonCompliant                        // deny, audit, modify, append when if-matched
	NotApplicable                       // disabled
	NeedsExistenceCheck                 // caller must run AINE/DINE check
)

func (c ComplianceState) String() string {
	switch c {
	case Compliant:
		return "Compliant"
	case NonCompliant:
		return "NonCompliant"
	case NotApplicable:
		return "NotApplicable"
	case NeedsExistenceCheck:
		return "NeedsExistenceCheck"
	default:
		return "Unknown"
	}
}

// ComplianceFromEffect determines the compliance state based on the resolved effect
// and whether the policy's if-condition matched.
//
// When ifMatched is false, the resource is Compliant (it doesn't trigger the policy).
// When ifMatched is true:
//
//	deny, audit, modify, append, denyAction, mutate → NonCompliant
//	disabled → NotApplicable
//	manual → Compliant
//	auditIfNotExists, deployIfNotExists → NeedsExistenceCheck
func ComplianceFromEffect(eff Effect, ifMatched bool) ComplianceState {
	if !ifMatched {
		return Compliant
	}

	switch eff {
	case Deny, Audit, Modify, Append, DenyAction, Mutate:
		return NonCompliant
	case Disabled:
		return NotApplicable
	case Manual:
		return Compliant
	case AuditIfNotExists, DeployIfNotExists:
		return NeedsExistenceCheck
	default:
		return NonCompliant
	}
}
