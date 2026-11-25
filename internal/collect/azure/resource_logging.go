package azure

import (
	"context"
	"fmt"
	"strconv"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// resourceLogTypes are the collected asset types whose Azure resources emit
// resource logs of their own (CIS 6.1.4). Key vaults are not listed: their
// audit logging is its own per-vault check (CIS 6.1.1.4), and listing them
// here too would report one gap twice. Types without resource-log
// categories (VMs, disks, VNets) are not listed, and SQL databases are left
// out because their listing is not proven complete.
var resourceLogTypes = map[string]bool{
	"security_group":    true,
	"azure_app_gateway": true,
	"azure_webapp":      true,
	"azure_public_ip":   true,
}

// resourceLogConcurrency bounds the per-resource diagnostic-setting reads in
// flight at once.
const resourceLogConcurrency = 8

// resourceLoggingSettings renders CIS 6.1.4 as one subscription-wide fact:
// the log-capable resources with no diagnostic setting exporting a log. It is
// one finding, not one per resource — the fix is one subscription-wide Azure
// Policy, and a per-resource finding would page through every NSG.
//
// A type counts only when this sweep listed it completely, and any failed
// read fails the whole fact (keys absent): a partial view must not read as
// "every resource logs".
func resourceLoggingSettings(ctx context.Context, list diagLister, res collect.Result) (map[string]string, error) {
	complete := completeTypes(res)
	for t := range resourceLogTypes {
		if !complete[t] {
			return nil, fmt.Errorf("resourceLoggingSettings: %s listing incomplete", t)
		}
	}
	var targets []asset.Asset
	var missing []string
	for _, a := range res.Assets {
		if resourceLogTypes[a.Type] {
			targets = append(targets, a)
		}
	}
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		sem     = make(chan struct{}, resourceLogConcurrency)
		failure error
	)
	logger := log.FromContext(ctx)
	for _, a := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if rec := recover(); rec != nil {
					logger.Error().Any("panic", rec).Str("resource", a.ID).Msg("diagnostic settings read panicked")
					mu.Lock()
					failure = fmt.Errorf("resourceLoggingSettings: panic reading %s", a.ID)
					mu.Unlock()
				}
			}()
			settings, err := list(ctx, a.ID)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				failure = fmt.Errorf("resourceLoggingSettings: %s: %w", a.ID, err)
			case len(exportingSettings(settings)) == 0:
				missing = append(missing, a.Type+":"+a.Name)
			}
		}()
	}
	wg.Wait()
	if failure != nil {
		return nil, failure
	}
	return map[string]string{
		"resources_without_diagnostic_settings_count": strconv.Itoa(len(missing)),
		"resources_without_diagnostic_settings":       sample(missing),
	}, nil
}

// diagLister reads every diagnostic setting on one resource.
type diagLister func(ctx context.Context, resourceID string) ([]*armmonitor.DiagnosticSettingsResource, error)

// armDiagLister is the production diagLister.
func armDiagLister(cred azcore.TokenCredential) (diagLister, error) {
	c, err := armmonitor.NewDiagnosticSettingsClient(cred, readOnlyARM())
	if err != nil {
		return nil, fmt.Errorf("armDiagLister: %w", err)
	}
	return func(ctx context.Context, id string) ([]*armmonitor.DiagnosticSettingsResource, error) {
		return listDiagnosticSettings(ctx, c, id)
	}, nil
}

// completeTypes is the set of asset types this sweep enumerated completely.
// Every Azure type is listed by exactly one subscription-wide scope.
func completeTypes(res collect.Result) map[string]bool {
	out := map[string]bool{}
	for _, e := range res.CompletedEnumerations {
		for _, t := range e.Types {
			out[t] = true
		}
	}
	return out
}
