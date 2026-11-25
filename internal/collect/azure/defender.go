package azure

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// Microsoft Defender for Cloud subscription settings (CIS Azure 8.1.x, 8.2.1):
// plan tiers, the Servers plan components, security-contact notifications,
// the Microsoft cloud security benchmark assignment, EASM and IoT Hub
// coverage. All are subscription-wide, so they land on the subscription
// settings asset. Each read is independent; one that fails leaves only its
// own keys absent.

// cisDefenderPlans are the Defender plans CIS Azure Foundations 6 requires on
// (pricings resource names).
var cisDefenderPlans = []string{
	"Api", "AppServices", "Arm", "CloudPosture", "Containers", "CosmosDbs", "KeyVaults",
	"OpenSourceRelationalDatabases", "SqlServerVirtualMachines", "SqlServers", "StorageAccounts",
	"VirtualMachines",
}

// collectDefender reads every Defender setting into sub.
func collectDefender(ctx context.Context, cred azcore.TokenCredential, armc *restClient, subscriptionID string, sub *settingsAsset) {
	reads := []struct {
		name string
		run  func() (map[string]string, error)
	}{
		{"pricings", func() (map[string]string, error) { return defenderPricings(ctx, cred, subscriptionID) }},
		{"endpoint protection setting", func() (map[string]string, error) { return defenderWDATP(ctx, cred, subscriptionID) }},
		{"server vulnerability assessment settings", func() (map[string]string, error) { return defenderServerVA(ctx, cred, subscriptionID) }},
		{"security contacts", func() (map[string]string, error) { return defenderContacts(ctx, cred, subscriptionID) }},
		{"cloud security benchmark assignment", func() (map[string]string, error) { return mcsbDisabledPolicies(ctx, cred, subscriptionID) }},
		{"EASM workspaces", func() (map[string]string, error) { return easmWorkspaces(ctx, armc, subscriptionID) }},
		{"IoT Hub coverage", func() (map[string]string, error) { return iotHubCoverage(ctx, cred, armc, subscriptionID) }},
	}
	for _, r := range reads {
		kv, err := r.run()
		if err != nil {
			log.FromContext(ctx).Warn().Err(err).Str("read", r.name).Int("status", statusCode(err)).
				Msg("azure defender read skipped; settings it backs are unknown")
			continue
		}
		sub.set(kv)
	}
}

func defenderPricings(ctx context.Context, cred azcore.TokenCredential, subscriptionID string) (map[string]string, error) {
	c, err := armsecurity.NewPricingsClient(cred, readOnlyARM())
	if err != nil {
		return nil, fmt.Errorf("defenderPricings: %w", err)
	}
	resp, err := c.List(ctx, "subscriptions/"+subscriptionID, nil)
	if err != nil {
		return nil, fmt.Errorf("defenderPricings: %w", err)
	}
	return pricingSettings(resp.Value), nil
}

// pricingSettings renders the plan tiers: defender_plan_<plan> for each CIS
// plan the response returned and did not mark deprecated (a plan it omitted
// is not claimed either way). The Servers plan components are read only when
// Servers is on — a Free plan has no components, and the plan check already
// says so.
func pricingSettings(pricings []*armsecurity.Pricing) map[string]string {
	byName := map[string]*armsecurity.PricingProperties{}
	for _, p := range pricings {
		if p != nil && p.Name != nil && p.Properties != nil {
			byName[*p.Name] = p.Properties
		}
	}
	out := map[string]string{}
	for _, plan := range cisDefenderPlans {
		p, ok := byName[plan]
		if !ok || p.PricingTier == nil || (p.Deprecated != nil && *p.Deprecated) {
			continue
		}
		out["defender_plan_"+strings.ToLower(plan)] = string(*p.PricingTier)
	}
	vm, ok := byName["VirtualMachines"]
	if !ok || vm.PricingTier == nil {
		return out
	}
	out["defender_servers_tier"] = string(*vm.PricingTier)
	if *vm.PricingTier != armsecurity.PricingTierStandard {
		return out
	}
	out["defender_servers_subplan"] = strVal(vm.SubPlan)
	out["defender_servers_agentless_scanning"] = extensionState(vm.Extensions, "AgentlessVmScanning")
	out["defender_servers_fim"] = extensionState(vm.Extensions, "FileIntegrityMonitoring")
	return out
}

// extensionState is "true"/"false" for a listed plan extension and
// "unavailable" when the plan (e.g. Servers Plan 1) does not offer it — which
// for CIS is still not on.
func extensionState(exts []*armsecurity.Extension, name string) string {
	for _, e := range exts {
		if e != nil && e.Name != nil && *e.Name == name && e.IsEnabled != nil {
			return strconv.FormatBool(*e.IsEnabled == armsecurity.IsEnabledTrue)
		}
	}
	return "unavailable"
}

// defenderWDATP reads the Defender for Endpoint integration (CIS 8.1.3.3).
func defenderWDATP(ctx context.Context, cred azcore.TokenCredential, subscriptionID string) (map[string]string, error) {
	c, err := armsecurity.NewSettingsClient(subscriptionID, cred, readOnlyARM())
	if err != nil {
		return nil, fmt.Errorf("defenderWDATP: %w", err)
	}
	resp, err := c.Get(ctx, armsecurity.SettingNameWDATP, nil)
	if err != nil {
		return nil, fmt.Errorf("defenderWDATP: %w", err)
	}
	return wdatpSettings(resp.SettingClassification), nil
}

func wdatpSettings(s armsecurity.SettingClassification) map[string]string {
	d, ok := s.(*armsecurity.DataExportSettings)
	if !ok || d.Properties == nil || d.Properties.Enabled == nil {
		return nil
	}
	return map[string]string{"defender_wdatp_enabled": strconv.FormatBool(*d.Properties.Enabled)}
}

// defenderServerVA reads which vulnerability assessment provider Defender for
// Servers uses (CIS 8.1.3.2). A fully read empty list is an observed "none".
func defenderServerVA(ctx context.Context, cred azcore.TokenCredential, subscriptionID string) (map[string]string, error) {
	c, err := armsecurity.NewServerVulnerabilityAssessmentsSettingsClient(subscriptionID, cred, readOnlyARM())
	if err != nil {
		return nil, fmt.Errorf("defenderServerVA: %w", err)
	}
	var settings []armsecurity.ServerVulnerabilityAssessmentsSettingClassification
	pager := c.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("defenderServerVA: %w", err)
		}
		settings = append(settings, page.Value...)
	}
	return serverVASettings(settings), nil
}

func serverVASettings(settings []armsecurity.ServerVulnerabilityAssessmentsSettingClassification) map[string]string {
	provider := "none"
	for _, s := range settings {
		if a, ok := s.(*armsecurity.AzureServersSetting); ok && a.Properties != nil && a.Properties.SelectedProvider != nil {
			provider = string(*a.Properties.SelectedProvider)
		}
	}
	return map[string]string{"defender_servers_va_provider": provider}
}

func defenderContacts(ctx context.Context, cred azcore.TokenCredential, subscriptionID string) (map[string]string, error) {
	c, err := armsecurity.NewContactsClient(subscriptionID, cred, readOnlyARM())
	if err != nil {
		return nil, fmt.Errorf("defenderContacts: %w", err)
	}
	var contacts []*armsecurity.Contact
	pager := c.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("defenderContacts: %w", err)
		}
		contacts = append(contacts, page.Value...)
	}
	return contactSettings(contacts), nil
}

// contactSettings renders CIS 8.1.12–8.1.15 from the security contacts. A
// disabled contact notifies nobody, so only enabled ones count (an omitted
// isEnabled is the service default, enabled). Empty values are observations:
// no contact, no owner notification, no alert or attack-path source.
func contactSettings(contacts []*armsecurity.Contact) map[string]string {
	emails := set()
	owner := false
	alertSeverity, attackPathRisk := "", ""
	for _, c := range contacts {
		if c == nil || c.Properties == nil {
			continue
		}
		p := c.Properties
		if p.IsEnabled != nil && !*p.IsEnabled {
			continue
		}
		for _, e := range strings.Split(strVal(p.Emails), ";") {
			if e = strings.TrimSpace(e); e != "" {
				emails[e] = struct{}{}
			}
		}
		if r := p.NotificationsByRole; r != nil && r.State != nil && *r.State == armsecurity.StateOn {
			for _, role := range r.Roles {
				if role != nil && *role == armsecurity.SecurityContactRoleOwner {
					owner = true
				}
			}
		}
		for _, src := range p.NotificationsSources {
			switch s := src.(type) {
			case *armsecurity.NotificationsSourceAlert:
				if s.MinimalSeverity != nil {
					alertSeverity = string(*s.MinimalSeverity)
				}
			case *armsecurity.NotificationsSourceAttackPath:
				if s.MinimalRiskLevel != nil {
					attackPathRisk = string(*s.MinimalRiskLevel)
				}
			}
		}
	}
	return map[string]string{
		"security_contact_emails":               strings.Join(sortedKeys(emails), ","),
		"security_contact_owner_notified":       strconv.FormatBool(owner),
		"security_contact_alert_min_severity":   alertSeverity,
		"security_contact_attack_path_min_risk": attackPathRisk,
	}
}

// easmWorkspaces counts Defender EASM workspaces (CIS 8.1.16). A subscription
// that never registered the Microsoft.Easm provider cannot hold one, so that
// error is an observed zero.
func easmWorkspaces(ctx context.Context, armc *restClient, subscriptionID string) (map[string]string, error) {
	if armc == nil {
		return nil, fmt.Errorf("easmWorkspaces: no ARM client")
	}
	ws, err := listAll[struct {
		ID string `json:"id"`
	}](ctx, armc, "/subscriptions/"+subscriptionID+"/providers/Microsoft.Easm/workspaces?api-version=2023-04-01-preview", nil)
	if err != nil && errorCode(err) != "MissingSubscriptionRegistration" {
		return nil, fmt.Errorf("easmWorkspaces: %w", err)
	}
	return map[string]string{"easm_workspace_count": strconv.Itoa(len(ws))}, nil
}

// iotHubCoverage lists the IoT hubs no enabled Defender for IoT solution
// covers (CIS 8.2.1). No hubs is an observed "" — the control does not apply.
func iotHubCoverage(ctx context.Context, cred azcore.TokenCredential, armc *restClient, subscriptionID string) (map[string]string, error) {
	if armc == nil {
		return nil, fmt.Errorf("iotHubCoverage: no ARM client")
	}
	hubs, err := listAll[struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}](ctx, armc, "/subscriptions/"+subscriptionID+"/providers/Microsoft.Devices/IotHubs?api-version=2023-06-30", nil)
	if err != nil && errorCode(err) != "MissingSubscriptionRegistration" {
		return nil, fmt.Errorf("iotHubCoverage: hubs: %w", err)
	}
	if len(hubs) == 0 {
		return map[string]string{"iot_hubs_without_defender": ""}, nil
	}
	c, err := armsecurity.NewIotSecuritySolutionClient(subscriptionID, cred, readOnlyARM())
	if err != nil {
		return nil, fmt.Errorf("iotHubCoverage: %w", err)
	}
	var solutions []*armsecurity.IoTSecuritySolutionModel
	pager := c.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("iotHubCoverage: solutions: %w", err)
		}
		solutions = append(solutions, page.Value...)
	}
	covered := set()
	for _, s := range solutions {
		if s == nil || s.Properties == nil || s.Properties.Status == nil || *s.Properties.Status != armsecurity.SecuritySolutionStatusEnabled {
			continue
		}
		for _, h := range s.Properties.IotHubs {
			if h != nil {
				covered[strings.ToLower(*h)] = struct{}{}
			}
		}
	}
	var bare []string
	for _, h := range hubs {
		if _, ok := covered[strings.ToLower(h.ID)]; !ok {
			bare = append(bare, h.Name)
		}
	}
	return map[string]string{"iot_hubs_without_defender": joinNames(bare)}, nil
}
