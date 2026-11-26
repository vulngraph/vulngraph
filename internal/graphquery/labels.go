package graphquery

import "strings"

// ReferencesLabels recognizes explicit node labels and relationship types,
// including quoted identifiers, without matching comments or string values.
// Callers first apply IsReadOnly to reject malformed/ambiguous input.
func ReferencesLabels(q string, labels ...string) bool {
	r := []byte(q)
	previous := byte(0)
	matches := func(name string) bool {
		for _, label := range labels {
			if strings.EqualFold(name, label) {
				return true
			}
		}
		return false
	}
	for i := 0; i < len(r); i++ {
		if r[i] == '/' && i+1 < len(r) && r[i+1] == '/' {
			for i < len(r) && r[i] != '\n' {
				i++
			}
			continue
		}
		if r[i] == '\'' || r[i] == '"' || r[i] == '`' {
			end, ok := literalEnd(r, i)
			if !ok {
				return false
			}
			if r[i] == '`' && (previous == ':' || previous == '|') && matches(string(r[i+1:end])) {
				return true
			}
			i = end
			previous = 'x'
			continue
		}
		if isLetter(r[i]) || r[i] == '_' {
			end := i + 1
			for end < len(r) && (isLetter(r[end]) || r[end] == '_' || (r[end] >= '0' && r[end] <= '9')) {
				end++
			}
			if (previous == ':' || previous == '|') && matches(string(r[i:end])) {
				return true
			}
			i = end - 1
			previous = 'x'
			continue
		}
		if r[i] != ' ' && r[i] != '\t' && r[i] != '\r' && r[i] != '\n' {
			previous = r[i]
		}
	}
	return false
}
