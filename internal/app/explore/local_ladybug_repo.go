package explore

// LocalLadybugRepoSource is the combined interface a local graphstore.Service
// satisfies — Repo (MatchSeed/Neighbors) + CypherRunner (RunCypher). Defined
// here to keep explore free of a graphstore import.
type LocalLadybugRepoSource interface {
	Repo
	CypherRunner
}

// NewLocalLadybugRepo wraps a *graphstore.Service (which implements both Repo
// and CypherRunner) as an explore.Repo for the three-tier fallback chain.
func NewLocalLadybugRepo(svc LocalLadybugRepoSource) Repo {
	return svc
}
