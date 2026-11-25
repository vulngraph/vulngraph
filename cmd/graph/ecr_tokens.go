package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/connector"
	awscollect "github.com/vulngraph/vulngraph/internal/collect/aws"
	"github.com/vulngraph/vulngraph/internal/scanner/imagevuln"
)

// connectorLister is the slice of connector.Service the ECR token source needs.
type connectorLister interface {
	List(ctx context.Context, enabledOnly bool) ([]connector.Connector, error)
	Get(ctx context.Context, id string) (connector.Connector, error)
}

// ecrTokenSource mints ECR pull credentials with the credentials of the
// enabled AWS connector for the registry's account. It matches by REGISTRY
// account only: an image in a shared-services registry pulled cross-account by
// workload accounts needs a connector for the registry account itself.
type ecrTokenSource struct {
	connectors connectorLister
	// mint is awscollect.ECRAuthorizationToken; a field so tests never call AWS.
	mint func(ctx context.Context, cfg map[string]string, region string) (string, string, time.Time, error)
}

func newECRTokenSource(connectors connectorLister) *ecrTokenSource {
	return &ecrTokenSource{connectors: connectors, mint: awscollect.ECRAuthorizationToken}
}

// Token implements imagevuln.ECRTokenSource.
func (s *ecrTokenSource) Token(ctx context.Context, accountID, region string) (imagevuln.ECRToken, error) {
	cfg, err := s.configFor(ctx, accountID)
	if err != nil {
		return imagevuln.ECRToken{}, fmt.Errorf("Token: %w", err)
	}
	user, pass, exp, err := s.mint(ctx, cfg, region)
	if err != nil {
		return imagevuln.ECRToken{}, fmt.Errorf("Token: account %s: %w", accountID, err)
	}
	return imagevuln.ECRToken{Username: user, Password: pass, ExpiresAt: exp}, nil
}

// configFor returns the decrypted config of the enabled AWS connector whose
// account is accountID. List never decrypts, so each AWS connector is fetched
// with Get to read its account; a mint happens at most once per registry per
// token lifetime (ECRKeychain caches), so the fan-out stays small.
func (s *ecrTokenSource) configFor(ctx context.Context, accountID string) (map[string]string, error) {
	if s.connectors == nil {
		return nil, fmt.Errorf("configFor: no connector store wired — account %s cannot be authenticated", accountID)
	}
	list, err := s.connectors.List(ctx, true)
	if err != nil {
		return nil, fmt.Errorf("configFor: %w", err)
	}
	for _, c := range list {
		if c.Type != connector.TypeAWS {
			continue
		}
		full, err := s.connectors.Get(ctx, c.ID)
		if err != nil {
			return nil, fmt.Errorf("configFor: connector %s: %w", c.ID, err)
		}
		if connectorAccount(full.Config) == accountID {
			return full.Config, nil
		}
	}
	return nil, fmt.Errorf("configFor: no enabled AWS connector for account %s — the image's ECR registry cannot be authenticated", accountID)
}

// connectorAccount is the AWS account an AWS connector reads: an explicit
// account_id, else the account of the role it assumes
// ("arn:aws:iam::<account>:role/<name>").
func connectorAccount(cfg map[string]string) string {
	if a := strings.TrimSpace(cfg["account_id"]); a != "" {
		return a
	}
	parts := strings.Split(cfg["role_arn"], ":")
	if len(parts) >= 6 && parts[0] == "arn" && parts[2] == "iam" {
		return parts[4]
	}
	return ""
}
