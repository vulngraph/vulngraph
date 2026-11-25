package graphstore

import "github.com/vulngraph/vulngraph/internal/app/asset"

// Data-store security signals for DSPM. These derive the encrypted/public node
// columns from collector metadata at graph-build time (no new collection). Only
// storage assets carry these keys and only storage assets carry ContainsData
// edges, so the signals are only ever surfaced for the stores DSPM queries.

// Encryption-at-rest states for the Asset.encrypted column.
//
// Two states are not enough: defaulting an ABSENT key to 1 (encrypted) would
// turn "never observed" into an affirmative "it is encrypted" — and since
// only two provider keys are ever read (S3's `encryption`, RDS's
// `storage_encrypted`), every other store type, and any store whose describe
// call failed, could never be counted as unencrypted either.
//
// The third state avoids that without inventing the opposite error: an
// unobserved store is UNKNOWN, counted and labelled as such, never folded into
// either the encrypted or the unencrypted population.
const (
	encryptionUnencrypted int32 = 0 // observed: no encryption at rest
	encryptionEncrypted   int32 = 1 // observed: encrypted at rest
	encryptionUnknown     int32 = 2 // not observed — absent key, or a failed describe
)

// assetEncrypted derives the encryption-at-rest signal for a storage asset from
// collector metadata. Present-and-empty means "read it, there is none" (the
// collectors omit a key whose describe failed — see collect/aws/s3.go), so a
// present key is always an observation and an absent key is always silence.
//
// Callers must test `== encryptionUnencrypted` for an alarm and must not treat
// a non-zero value as "encrypted": existing Cypher (`a.encrypted = 0`) is
// unaffected by the new state, which is why the change is additive.
func assetEncrypted(meta map[string]string) int32 {
	if v, ok := meta["encryption"]; ok { // S3: SSE algorithm, "" if unconfigured
		return b2i(v != "")
	}
	if v, ok := meta["storage_encrypted"]; ok { // RDS: "true"/"false"
		return b2i(v == "true")
	}
	// GCS/CloudSQL/Azure/DynamoDB/Firestore/ElastiCache: not collected yet, and
	// several are encrypted-by-default at the provider — but "probably" is not an
	// observation, so it is not reported as one.
	return encryptionUnknown
}

// assetPublic derives the "publicly accessible" signal (INT32 0/1) for a storage
// asset from collector metadata: S3 bucket public-access (`public`), RDS
// `publicly_accessible`, CloudSQL `public`. This is config-level public exposure —
// distinct from the graph-path `exposed` signal (an ExposedToInternet edge). A
// public RDS/CloudSQL DB emits no exposure edge, so DSPM relies on this to flag
// publicly-reachable data stores. Absent = 0 (not public / non-storage).
//
// PublicAccessUnknown is explicitly NOT public: when the collector could not read
// the exposure configuration at all, nothing has been observed, and an
// unreadable bucket must not be presented as an exposed one. The blind spot is
// carried by publicTierUnknown instead of being asserted as a finding.
func assetPublic(meta map[string]string) int32 {
	if meta["public_access"] == PublicAccessUnknown {
		return 0
	}
	return b2i(meta["public"] == "true" || meta["publicly_accessible"] == "true")
}

// PublicAccessUnknown is the `public_access` metadata value a collector writes
// when it could not determine public exposure — every API call that would have
// answered the question failed. It is distinct from asset.PublicAccessNone
// ("read it, nothing is public") and from an absent key ("this collector does
// not grade tiers").
//
// It lives here rather than beside asset.PublicAccess{Confirmed,Possible,None};
// the string is duplicated verbatim in internal/collect/aws/s3.go,
// internal/collect/gcp/cloudsql.go and internal/collect/azure/helpers.go
// (collectors must not import graphstore) and
// pinned by TestPublicAccessUnknownLiteral. It could move into the asset
// package alongside the other tier values.
const PublicAccessUnknown = "unknown"

// Public-tier values for the Asset.public_tier column. Tier separates confirmed
// unauthenticated exposure from configuration that merely permits it, so the UI
// can label PUBLIC vs PUBLIC? without changing what counts as public.
const (
	publicTierNone      int32 = 0
	publicTierPossible  int32 = 1 // S3: public-access-block missing/not locked, no public policy/ACL
	publicTierConfirmed int32 = 2 // public policy/ACL, or publicly_accessible DB
	// publicTierUnknown is a measurement gap, not a grade: the collector's
	// exposure calls all failed, so this store's public status is unobserved. It
	// sorts LAST in the DSPM worklist (see the explicit CASE in the DSPM summary
	// query) — it is a coverage problem to fix, not an exposure to remediate.
	publicTierUnknown int32 = 3
)

// assetPublicTier grades the public signal from the collector's `public_access`
// key (see asset.PublicAccessConfirmed/Possible). Possible covers configuration
// that permits-but-doesn't-prove exposure (S3/Azure Storage without a lockdown,
// API Gateway behind optional authorizers, Cloud Run/Functions without a known
// allUsers binding) AND network-reachable-but-credential-gated databases
// (publicly_accessible RDS/CloudSQL/Azure SQL).
//
// Confirmation is something a collector has to SAY, never something an absent
// key implies — defaulting an unrecognised tier on a public signal to confirmed
// would promote stale metadata (a public flag with no tier key) to a confirmed
// exposure. Every storage collector that sets
// `public`/`publicly_accessible` also sets `public_access`, so the only assets
// affected by grading these as possible instead are ones whose tier nobody
// ever recorded.
func assetPublicTier(meta map[string]string) int32 {
	if meta["public_access"] == PublicAccessUnknown {
		return publicTierUnknown
	}
	if assetPublic(meta) == 0 {
		return publicTierNone
	}
	if meta["public_access"] == asset.PublicAccessConfirmed {
		return publicTierConfirmed
	}
	// Possible, explicitly graded or inferred: an unrecognised/absent tier on a
	// public signal is unproven, never confirmed.
	return publicTierPossible
}
