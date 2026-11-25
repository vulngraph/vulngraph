package ciem

import (
	"encoding/json"
	"strconv"
	"strings"
)

// assumptionPaths separates both principals and entry methods. Principal arrays
// are alternatives, and an IAM user cannot use an Allow's SAML action to evade
// an AssumeRole Deny. TagSession authorizes tags, not entry.
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html
func (s trustStatement) assumptionPaths() []trustStatement {
	var paths []trustStatement
	for _, action := range []string{"sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity"} {
		if !s.matchesAction(action) {
			continue
		}
		path := s
		path.Action = json.RawMessage(strconv.Quote(action))
		principals := s.principalMap()
		if len(principals) == 0 {
			// Retain the raw wildcard, and legacy fixtures with no Principal.
			paths = append(paths, path)
			continue
		}
		for kind, values := range principals {
			for _, principal := range values {
				if principalSupportsMethod(kind, principal, action) {
					path.Principal = json.RawMessage("{" + strconv.Quote(kind) + ":" + strconv.Quote(principal) + "}")
					paths = append(paths, path)
				}
			}
		}
	}
	return paths
}

func principalSupportsMethod(kind, principal, action string) bool {
	switch strings.ToLower(kind) {
	case "aws":
		// AWS:* is an unbounded principal, not a named IAM identity.
		return principal == "*" || action == "sts:AssumeRole"
	case "service":
		return action == "sts:AssumeRole"
	case "federated":
		switch FederationKind(principal) {
		case "saml":
			return action == "sts:AssumeRoleWithSAML"
		case "oidc":
			return action == "sts:AssumeRoleWithWebIdentity"
		default:
			// An unknown provider earns no vetted-federation classification, but
			// cannot be assumed to grant no federated entry either.
			return action != "sts:AssumeRole"
		}
	default:
		return true // Unsupported principal shapes earn no protection proof.
	}
}

// coversPrincipalOf is used only after the Allow has been split into a single
// principal. Named denies cannot remove an entire wildcard or account grant.
func (s trustStatement) coversPrincipalOf(other trustStatement) bool {
	if len(s.Principal) == 0 {
		return true // Older inventory fixtures omit Principal.
	}
	var raw string
	if json.Unmarshal(s.Principal, &raw) == nil && raw == "*" {
		return true
	}
	for kind, values := range s.principalMap() {
		for _, principal := range values {
			if strings.EqualFold(kind, "AWS") && principal == "*" {
				return true
			}
			for otherKind, others := range other.principalMap() {
				if !strings.EqualFold(kind, otherKind) {
					continue
				}
				for _, otherPrincipal := range others {
					if principal == otherPrincipal {
						return true
					}
				}
			}
		}
	}
	return false
}
