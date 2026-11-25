package ciem

type evaluatedSCPLevel struct {
	allows      []actionResourceSource
	denies      []actionResource
	complete    bool
	approximate bool
}

// A complete empty level is a real implicit deny. An unread level is not:
// missing alternative Allows must never erase a retained candidate.
func evaluateSCPLevel(level SCPLevel) evaluatedSCPLevel {
	out := evaluatedSCPLevel{complete: level.Complete && level.Policies != nil}
	for _, policy := range level.Policies {
		statements, err := ParseAWSPolicy(policy.Document)
		if policy.Incomplete || err != nil || len(statements) == 0 {
			out.complete = false
		}
		if err != nil {
			continue
		}
		for _, statement := range statements {
			switch statement.Effect {
			case EffectAllow:
				out.allows = append(out.allows, expandActionsResources(statement, policy.Name)...)
			case EffectDeny:
				if len(statement.Conditions) > 0 {
					out.approximate = true
					continue
				}
				out.denies = append(out.denies, expandDenyActionsResources(statement)...)
			}
		}
	}
	return out
}
