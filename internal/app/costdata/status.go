package costdata

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/smithy-go"
)

// Collection outcomes. Every terminated collection attempt lands on exactly one
// of these, because the failure that motivated them was invisible: the loop
// returned on a connector-list error and continued on a config error, both
// silently, so 0 rows in cost_snapshots rendered as "No cost anomalies" — a
// clean bill of health produced by a permission denial.
const (
	OutcomeOK               = "ok"                // snapshots fetched and stored
	OutcomeEmpty            = "empty"             // the API answered, with nothing in it
	OutcomePermissionDenied = "permission_denied" // IAM refused (ce:GetCostAndUsage)
	OutcomeConfigError      = "config_error"      // connector config could not build an AWS config
	OutcomeAPIError         = "api_error"         // Cost Explorer call failed for another reason
	OutcomeStoreError       = "store_error"       // fetch worked, the write did not
)

// CollectStatus is the outcome of the most recent collection attempt for one
// connector, plus what is actually stored for it. Both halves matter: the
// attempt says whether collection is working now, the stored counts say whether
// it ever worked. A UI that has only "0 anomalies" can distinguish neither.
type CollectStatus struct {
	ConnectorID     string
	AccountID       string
	Outcome         string
	Detail          string
	AttemptAt       time.Time
	Fetched         int // snapshots returned by the API on the last attempt
	SnapshotsStored int // rows currently in cost_snapshots for this connector
	LastCollectedAt time.Time
}

// Collected reports whether this connector has any stored cost data at all.
func (s CollectStatus) Collected() bool { return s.SnapshotsStored > 0 }

// statusStore is the in-process record of the last attempt per connector. It is
// deliberately memory-only: the durable half of the answer is the row count in
// cost_snapshots, and the collect loop runs on startup, so a fresh process
// repopulates this within one pass. Persisting attempt outcomes would need a
// migration for a signal that is also emitted as a log line and a metric.
type statusStore struct {
	mu sync.Mutex
	by map[string]CollectStatus
}

func newStatusStore() *statusStore { return &statusStore{by: map[string]CollectStatus{}} }

func (s *statusStore) record(st CollectStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.by[st.ConnectorID] = st
}

func (s *statusStore) snapshot() map[string]CollectStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]CollectStatus, len(s.by))
	for k, v := range s.by {
		out[k] = v
	}
	return out
}

// ClassifyCollectError maps a Collect error to one of the outcome constants. AWS
// expresses an IAM refusal as an API error code, and Cost Explorer has its own
// spellings (AccessDeniedException from the CE endpoint, DataUnavailableException
// when the account has never opted into Cost Explorer at all), so a substring
// check on the message alone is not enough — the smithy APIError code is checked
// first and the message only as a fallback for wrapped/transport-level denials.
func ClassifyCollectError(err error) string {
	if err == nil {
		return OutcomeOK
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch code := apiErr.ErrorCode(); {
		case strings.Contains(code, "AccessDenied"),
			strings.Contains(code, "UnauthorizedOperation"),
			strings.Contains(code, "AuthFailure"),
			strings.Contains(code, "OptInRequired"),
			strings.Contains(code, "DataUnavailable"):
			return OutcomePermissionDenied
		}
		return OutcomeAPIError
	}
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{
		"accessdenied", "access denied", "not authorized", "unauthorized",
		"explicit deny", "optinrequired",
	} {
		if strings.Contains(msg, needle) {
			return OutcomePermissionDenied
		}
	}
	return OutcomeAPIError
}

// IsPermissionDenied reports whether err is an IAM/entitlement refusal — the
// failure mode that must never be reported to a user as "no cost anomalies".
func IsPermissionDenied(err error) bool {
	return err != nil && ClassifyCollectError(err) == OutcomePermissionDenied
}

// RequiredIAMPermission is the single IAM action cost collection needs. It is
// granted nowhere in this repo's connector role templates (ViewOnlyAccess and
// SecurityAudit both omit it), which is the most likely reason cost_snapshots
// is empty. Exported so the API can tell an operator what to grant instead of
// showing them an empty panel.
const RequiredIAMPermission = "ce:GetCostAndUsage"

// Statuses returns the per-connector collection status, newest attempt first,
// merging the in-process attempt outcomes with what is stored in Postgres. A
// connector that has never been attempted this process lifetime still appears if
// it has stored rows.
func (s *Service) Statuses(ctx context.Context) ([]CollectStatus, error) {
	stored, err := s.repo.SnapshotCounts(ctx)
	if err != nil {
		return nil, err
	}
	attempts := s.status.snapshot()

	merged := map[string]CollectStatus{}
	for id, st := range attempts {
		merged[id] = st
	}
	for id, c := range stored {
		st := merged[id]
		st.ConnectorID = id
		st.SnapshotsStored = c.Rows
		st.LastCollectedAt = c.LastCollectedAt
		merged[id] = st
	}

	out := make([]CollectStatus, 0, len(merged))
	for _, st := range merged {
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].AttemptAt.Equal(out[j].AttemptAt) {
			return out[i].AttemptAt.After(out[j].AttemptAt)
		}
		return out[i].ConnectorID < out[j].ConnectorID
	})
	return out, nil
}
