package connector

import (
	"errors"
	"io/fs"
	"net/http"
	"time"

	awsdeploy "github.com/vulngraph/vulngraph/deploy/aws"
	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

type childHealthResponse struct {
	Enabled       bool       `json:"enabled"`
	SyncStatus    string     `json:"sync_status"`
	SyncError     string     `json:"sync_error,omitempty"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	Stale         bool       `json:"stale"`
}

type orgAccountResponse struct {
	AccountID        string               `json:"account_id"`
	Name             string               `json:"name"`
	Email            string               `json:"email"`
	AWSState         string               `json:"aws_state"`
	OUPath           string               `json:"ou_path,omitempty"`
	Status           string               `json:"status"`
	StatusDetail     string               `json:"status_detail,omitempty"`
	ChildConnectorID string               `json:"child_connector_id,omitempty"`
	Child            *childHealthResponse `json:"child,omitempty"`
	FirstSeenAt      time.Time            `json:"first_seen_at"`
	LastSeenAt       time.Time            `json:"last_seen_at"`
	StatusChangedAt  time.Time            `json:"status_changed_at"`
}

// OrgAccounts lists an aws_org connector's discovered accounts and the health
// of each account's child connector.
func (h *Handler) OrgAccounts(w http.ResponseWriter, r *http.Request) {
	accts, err := h.svc.OrgAccounts(r.Context(), r.PathValue("id"))
	switch {
	case errors.Is(err, ErrNotFound):
		errs.WriteHTTPError(w, errs.NotFound("connector not found"))
		return
	case errors.Is(err, ErrNotOrgConnector):
		errs.WriteHTTPError(w, errs.InvalidInput("connector is not an aws_org connector"))
		return
	case err != nil:
		log.FromContext(r.Context()).Error().Err(err).Msg("list org accounts failed")
		errs.WriteHTTPError(w, errs.Internal("failed to list organization accounts"))
		return
	}
	now := time.Now()
	out := make([]orgAccountResponse, len(accts))
	for i, a := range accts {
		out[i] = orgAccountResponse{
			AccountID: a.AccountID, Name: a.Name, Email: a.Email, AWSState: a.AWSState, OUPath: a.OUPath,
			Status: string(a.Status), StatusDetail: a.StatusDetail, ChildConnectorID: a.ChildConnectorID,
			FirstSeenAt: a.FirstSeenAt, LastSeenAt: a.LastSeenAt, StatusChangedAt: a.StatusChangedAt,
		}
		if c := a.Child; c != nil {
			stale := Connector{Enabled: c.Enabled, LastSuccessAt: c.LastSuccessAt, CreatedAt: c.CreatedAt}.Stale(now, DefaultStaleAfter)
			out[i].Child = &childHealthResponse{
				Enabled: c.Enabled, SyncStatus: string(c.SyncStatus), SyncError: c.SyncError,
				LastSuccessAt: c.LastSuccessAt, Stale: stale,
			}
		}
	}
	writeJSON(r.Context(), w, http.StatusOK, out)
}

type memberCheckResponse struct {
	AccountID string `json:"account_id"`
	OK        bool   `json:"ok"`
	Cause     string `json:"cause"`
	Detail    string `json:"detail,omitempty"`
}

type orgTestResponse struct {
	HubOK        bool                  `json:"hub_ok"`
	HubIdentity  string                `json:"hub_identity,omitempty"`
	HubError     string                `json:"hub_error,omitempty"`
	ListRan      bool                  `json:"list_ran"`
	ListOK       bool                  `json:"list_ok"`
	AccountCount int                   `json:"account_count"`
	ListError    string                `json:"list_error,omitempty"`
	Members      []memberCheckResponse `json:"members"`
}

// TestConnection runs the aws_org connection test: hub credential,
// organization listing, and member role assumption in a sample of accounts.
// Admin-only: it makes live AWS calls with the connector's credential.
func (h *Handler) TestConnection(w http.ResponseWriter, r *http.Request) {
	rep, err := h.svc.TestOrg(r.Context(), r.PathValue("id"))
	switch {
	case errors.Is(err, ErrNotFound):
		errs.WriteHTTPError(w, errs.NotFound("connector not found"))
		return
	case errors.Is(err, ErrNotOrgConnector):
		errs.WriteHTTPError(w, errs.InvalidInput("connection tests are available for aws_org connectors"))
		return
	case err != nil:
		log.FromContext(r.Context()).Error().Err(err).Msg("org connection test failed")
		errs.WriteHTTPError(w, errs.Internal("failed to run the connection test"))
		return
	}
	out := orgTestResponse{
		HubOK: rep.HubOK, HubIdentity: rep.HubIdentity, HubError: rep.HubError,
		ListRan: rep.ListRan, ListOK: rep.ListOK, AccountCount: rep.AccountCount, ListError: rep.ListError,
		Members: make([]memberCheckResponse, len(rep.Members)),
	}
	for i, m := range rep.Members {
		out.Members[i] = memberCheckResponse(m)
	}
	writeJSON(r.Context(), w, http.StatusOK, out)
}

// OrgTemplate serves one of the CloudFormation templates under deploy/aws,
// so an air-gapped install can hand them to the StackSet without a checkout.
func (h *Handler) OrgTemplate(w http.ResponseWriter, r *http.Request) {
	body, err := fs.ReadFile(awsdeploy.Templates, r.PathValue("name"))
	if err != nil {
		errs.WriteHTTPError(w, errs.NotFound("template not found"))
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Content-Disposition", `attachment; filename="`+r.PathValue("name")+`"`)
	if _, err := w.Write(body); err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("write template failed")
	}
}
