// Package kevwatch detects CVEs newly added to the CISA KEV catalog and keeps
// a durable `kev.added` record of each, one per CVE, for agent triggers to
// consume (ADR 085 §2, ADR 086 §1). The KEV refresh job feeds it the catalog
// after every fetch; this package owns the diff and the record.
package kevwatch

import "time"

// EventKind is the agent trigger kind an Addition represents.
const EventKind = "kev.added"

// BootstrapWindow bounds what the first refresh (an empty kev_catalog) reports
// as added: only entries CISA added within it. The rest of the back catalog
// is seeded silently — it is not news, and an event per historical CVE would
// fire a trigger for each.
const BootstrapWindow = 7 * 24 * time.Hour

const (
	DefaultListLimit = 50
	MaxListLimit     = 200
)

// Entry is one KEV catalog row. DateAdded is zero when unknown.
type Entry struct {
	CVEID     string
	DateAdded time.Time
	Name      string
}

// Addition is one `kev.added` record: a CVE that joined the catalog since the
// previous refresh. OpenFindings counts the open findings matching the CVE
// when the addition was detected; DetectedAt is when it was recorded.
type Addition struct {
	CVEID        string
	DateAdded    time.Time
	Name         string
	OpenFindings int
	DetectedAt   time.Time
}
