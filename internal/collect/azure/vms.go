package azure

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"golang.org/x/sync/errgroup"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// nicNSGs is one IP configuration as InternetReachability sees it (Metadata["nic_nsgs"]):
// whether it carries a public IP, and every NSG inbound traffic to it must
// pass — the NSG of its subnet plus the NSG on
// the NIC itself. Azure only admits a packet that ALL of them allow.
// PublicIPSKU is the public IP's SKU name ("Basic", "Standard"), empty when
// not returned: with no NSG at all, a Basic IP admits everything and a
// Standard IP nothing. NSGUnknown marks a subnet whose NSG could not be read,
// so NSGIDs may be missing one.
type nicNSGs struct {
	Public        bool     `json:"public"`
	NSGIDs        []string `json:"nsg_ids"`
	PublicIPSKU   string   `json:"public_ip_sku,omitempty"`
	NSGUnknown    bool     `json:"nsg_unknown,omitempty"`
	PrivateIP     string   `json:"private_ip,omitempty"`
	PublicIP      string   `json:"public_ip,omitempty"`
	ASGs          []string `json:"asgs"`
	EndpointKnown bool     `json:"endpoint_known"`
}

// collectVMs pulls all Virtual Machines in the subscription, resolves every
// NIC to find public and private IPs and the NIC + subnet NSGs guarding it,
// and emits protected_by edges to those NSGs.
func collectVMs(ctx context.Context, cred azcore.TokenCredential, subscriptionID string, now time.Time, opts *arm.ClientOptions) ([]asset.Asset, []asset.Edge, error) {
	vmClient, err := armcompute.NewVirtualMachinesClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("collectVMs: vm client: %w", err)
	}
	nicClient, err := armnetwork.NewInterfacesClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("collectVMs: nic client: %w", err)
	}
	subnetClient, err := armnetwork.NewSubnetsClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("collectVMs: subnet client: %w", err)
	}
	subnetNSG := subnetNSGResolver(func(rg, vnet, name string) (*armnetwork.Subnet, error) {
		readCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		resp, err := subnetClient.Get(readCtx, rg, vnet, name, nil)
		if err != nil {
			log.FromContext(ctx).Warn().Err(err).Str("resource_group", rg).Str("vnet", vnet).Str("subnet", name).
				Msg("azure subnet unreadable; its NSG is unknown for the VMs in it, whose exposure is then possible, through the NIC NSG or on every port without one")
			return nil, fmt.Errorf("get subnet: %w", err)
		}
		return &resp.Subnet, nil
	})
	// Expand the NIC request to inline the public IP address so we get the
	// actual IP value without a second API round-trip. The SDK sets the
	// $expand query key itself; this is only its value.
	expandPIP := "ipConfigurations/publicIPAddress"
	getNIC := func(nicID string) (*armnetwork.Interface, error) {
		readCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		nic, err := nicClient.Get(readCtx, resourceGroup(nicID), nicName(nicID),
			&armnetwork.InterfacesClientGetOptions{Expand: &expandPIP})
		if err != nil {
			return nil, fmt.Errorf("get nic: %w", err)
		}
		return &nic.Interface, nil
	}

	var assets []asset.Asset
	var edges []asset.Edge

	pager := vmClient.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("collectVMs: list: %w", err)
		}
		// NIC reads are independent. Keep output in pager order while bounding
		// in-flight API work; a failed/panicking mapping aborts this enumeration.
		pageAssets := make([]asset.Asset, len(page.Value))
		pageEdges := make([][]asset.Edge, len(page.Value))
		var group errgroup.Group
		group.SetLimit(8)
		for i, vm := range page.Value {
			if vm == nil || vm.ID == nil {
				continue
			}
			group.Go(func() (err error) {
				defer func() {
					if p := recover(); p != nil {
						err = fmt.Errorf("collectVMs: mapping panic: %v", p)
					}
				}()
				if err := ctx.Err(); err != nil {
					return err
				}
				pageAssets[i], pageEdges[i] = vmAssetWithNICs(ctx, vm, subscriptionID, now, getNIC, subnetNSG)
				return ctx.Err()
			})
		}
		if err := group.Wait(); err != nil {
			return nil, nil, fmt.Errorf("collectVMs: map page: %w", err)
		}
		for i, a := range pageAssets {
			if a.ID != "" {
				assets = append(assets, a)
				edges = append(edges, pageEdges[i]...)
			}
		}
	}
	return assets, edges, nil
}

// vmAssetWithNICs maps one VM, reading each of its NICs with getNIC.
// direct_public_ip is "true" when any NIC has a public IP associated, whether
// or not an address is allocated to it (a stopped VM's dynamic IP has none).
// "false" is an observation only when every NIC and IP configuration was read
// in full: one that could not be read may carry the public IP, so the key is
// then left out (unknown).
func vmAssetWithNICs(ctx context.Context, vm *armcompute.VirtualMachine, subscriptionID string, now time.Time,
	getNIC func(nicID string) (*armnetwork.Interface, error), subnetNSG func(subnetID string) (string, bool),
) (asset.Asset, []asset.Edge) {
	vmAsset := asset.Asset{
		ID:        *vm.ID,
		Name:      strVal(vm.Name),
		Type:      "azure_vm",
		Provider:  asset.ProviderAzure,
		Region:    strVal(vm.Location),
		AccountID: subscriptionID,
		Tags:      azTags(vm.Tags),
		Metadata: map[string]string{
			"os_type": osType(vm),
			"size":    vmSize(vm),
		},
		DiscoveredAt: now,
		LastSeen:     now,
	}
	// The boot disk the agentless disk scan reads; omitted when the OS disk is
	// not a managed disk.
	if id := osDiskID(vm); id != "" {
		vmAsset.Metadata["os_disk_id"] = id
	}

	var nics []*armnetwork.Interface
	nicsKnown := vm.Properties != nil && vm.Properties.NetworkProfile != nil
	if nicsKnown {
		for _, ref := range vm.Properties.NetworkProfile.NetworkInterfaces {
			if ref == nil || ref.ID == nil || *ref.ID == "" {
				nicsKnown = false
			}
		}
		for _, nicID := range primaryFirst(vm.Properties.NetworkProfile.NetworkInterfaces) {
			nic, err := getNIC(nicID)
			if err != nil {
				nicsKnown = false
				log.FromContext(ctx).Warn().Err(err).Str("vm", *vm.ID).Str("nic", nicID).
					Msg("azure NIC unreadable; the VM's public IP and NSGs on that NIC are unknown this sweep")
				continue
			}
			nics = append(nics, nic)
		}
	}
	nsgIDs, public, complete := applyNICs(&vmAsset, nics, subnetNSG)
	if !complete {
		nicsKnown = false
		log.FromContext(ctx).Warn().Str("vm", *vm.ID).
			Msg("azure NIC returned without properties; the VM's public IP and NSGs on that NIC are unknown this sweep")
	}
	vmAsset.Metadata["network_interfaces_complete"] = fmt.Sprintf("%t", nicsKnown)
	var edges []asset.Edge
	for _, nsgID := range nsgIDs {
		edges = append(edges, asset.Edge{
			SrcID: *vm.ID, SrcType: "azure_vm",
			DstID: nsgID, DstType: "security_group",
			EdgeType: "protected_by",
		})
	}
	switch {
	case public:
		vmAsset.Metadata["direct_public_ip"] = "true"
	case nicsKnown:
		vmAsset.Metadata["direct_public_ip"] = "false"
	default:
		vmAsset.Metadata[asset.MetaPublicIPKnown] = "false"
	}
	// Managed identity → exec_role so the ExecutesAs correlator can link this
	// VM to its Azure AD service principal and compute privilege escalation paths.
	if vm.Identity != nil && vm.Identity.PrincipalID != nil && *vm.Identity.PrincipalID != "" {
		vmAsset.Metadata["exec_role"] = managedIdentityID(*vm.Identity.PrincipalID)
	}
	return vmAsset, edges
}

// primaryFirst returns the VM's NIC IDs with the primary NIC first, so its
// IPs win the single PublicIP/PrivateIP slots. With no Primary flag set the
// first NIC is primary, matching Azure's own default.
func primaryFirst(refs []*armcompute.NetworkInterfaceReference) []string {
	var primary, rest []string
	for i, ref := range refs {
		if ref == nil || ref.ID == nil {
			continue
		}
		isPrimary := i == 0
		if ref.Properties != nil && ref.Properties.Primary != nil {
			isPrimary = *ref.Properties.Primary
		}
		if isPrimary && len(primary) == 0 {
			primary = append(primary, *ref.ID)
		} else {
			rest = append(rest, *ref.ID)
		}
	}
	return append(primary, rest...)
}

// applyNICs records the NICs' IPs and NSGs on the VM asset and returns the
// distinct NSG IDs found, whether any NIC has a public IP associated, and
// whether every NIC and IP configuration carried its properties. nsg_ids keeps
// the flat CSV the shared-SG adjacency indexes; nic_nsgs keeps the per-NIC
// grouping reachability needs. Each IP configuration remains separate: a
// subnet NSG and a NIC NSG must both allow the same packet, while different
// interfaces/IP configurations are alternative entry points.
func applyNICs(vm *asset.Asset, nics []*armnetwork.Interface, subnetNSG func(subnetID string) (string, bool)) (_ []string, public, complete bool) {
	complete = true
	var perNIC []nicNSGs
	var all []string
	seen := map[string]bool{}
	add := func(list []string, id string) []string {
		if id == "" {
			return list
		}
		key := strings.ToLower(id)
		for _, have := range list {
			if strings.ToLower(have) == key {
				return list
			}
		}
		if !seen[key] {
			seen[key] = true
			all = append(all, id)
		}
		return append(list, id)
	}
	for _, nic := range nics {
		if nic == nil || nic.Properties == nil {
			complete = false
			continue
		}
		if len(nic.Properties.IPConfigurations) == 0 {
			complete = false
		}
		for _, ipCfg := range nic.Properties.IPConfigurations {
			if ipCfg == nil || ipCfg.Properties == nil {
				complete = false
				continue
			}
			p := ipCfg.Properties
			entry := nicNSGs{EndpointKnown: true, ASGs: []string{}}
			entry.PrivateIP = strVal(p.PrivateIPAddress)
			for _, group := range p.ApplicationSecurityGroups {
				if group != nil && group.ID != nil {
					entry.ASGs = append(entry.ASGs, *group.ID)
				} else {
					entry.EndpointKnown = false
				}
			}
			if pip := p.PublicIPAddress; pip != nil {
				entry.Public = true
				public = true
				if pip.SKU != nil && pip.SKU.Name != nil && entry.PublicIPSKU == "" {
					entry.PublicIPSKU = string(*pip.SKU.Name)
				}
				if pip.ID != nil && vm.Metadata["public_ip_id"] == "" {
					vm.Metadata["public_ip_id"] = *pip.ID
				}
				// The expanded response includes the actual IP address.
				if pip.Properties != nil && pip.Properties.IPAddress != nil {
					entry.PublicIP = *pip.Properties.IPAddress
					if vm.PublicIP == "" {
						vm.PublicIP = entry.PublicIP
					}
				}
			}
			if p.PrivateIPAddress != nil && vm.PrivateIP == "" {
				vm.PrivateIP = *p.PrivateIPAddress
			}
			if p.Subnet != nil && p.Subnet.ID != nil {
				id, known := subnetNSG(*p.Subnet.ID)
				entry.NSGIDs = add(entry.NSGIDs, id)
				entry.NSGUnknown = entry.NSGUnknown || !known
			} else {
				entry.NSGUnknown = true
			}
			if nsg := nic.Properties.NetworkSecurityGroup; nsg != nil {
				if nsg.ID != nil {
					entry.NSGIDs = add(entry.NSGIDs, *nsg.ID)
				} else {
					entry.NSGUnknown = true
				}
			}
			perNIC = append(perNIC, entry)
		}
	}
	vm.Metadata["network_interfaces_complete"] = fmt.Sprintf("%t", complete)
	if len(all) > 0 {
		vm.Metadata["nsg_ids"] = strings.Join(all, ",")
	}
	if len(perNIC) > 0 {
		vm.Metadata["nic_nsgs"] = marshalJSON(perNIC)
	}
	return all, public, complete
}

// subnetNSGResolver returns a cached subnet-ID → NSG-ID lookup. known is false
// when the subnet could not be read (get logs it): its NSG is then unknown, not
// absent, and reachability treats the NIC as possibly exposed rather than closed.
func subnetNSGResolver(get func(rg, vnet, name string) (*armnetwork.Subnet, error)) func(string) (nsgID string, known bool) {
	var cache sync.Map
	return func(subnetID string) (string, bool) {
		key := strings.ToLower(subnetID)
		read := sync.OnceValues(func() (string, bool) {
			if rg, vnet, name, ok := subnetParts(subnetID); ok {
				if sn, err := get(rg, vnet, name); err == nil && sn != nil && sn.Properties != nil {
					if sn.Properties.NetworkSecurityGroup != nil {
						return strVal(sn.Properties.NetworkSecurityGroup.ID), true
					}
					return "", true
				}
			}
			return "", false
		})
		cached, _ := cache.LoadOrStore(key, read)
		return cached.(func() (string, bool))()
	}
}

// subnetParts splits .../resourceGroups/{rg}/.../virtualNetworks/{vnet}/subnets/{name}.
func subnetParts(id string) (rg, vnet, name string, ok bool) {
	parts := strings.Split(id, "/")
	for i := 0; i+1 < len(parts); i++ {
		switch {
		case strings.EqualFold(parts[i], "virtualNetworks"):
			vnet = parts[i+1]
		case strings.EqualFold(parts[i], "subnets"):
			name = parts[i+1]
		}
	}
	rg = resourceGroup(id)
	return rg, vnet, name, rg != "" && vnet != "" && name != ""
}

func osType(vm *armcompute.VirtualMachine) string {
	if vm.Properties == nil || vm.Properties.StorageProfile == nil ||
		vm.Properties.StorageProfile.OSDisk == nil ||
		vm.Properties.StorageProfile.OSDisk.OSType == nil {
		return ""
	}
	return string(*vm.Properties.StorageProfile.OSDisk.OSType)
}

func osDiskID(vm *armcompute.VirtualMachine) string {
	if vm.Properties == nil || vm.Properties.StorageProfile == nil || vm.Properties.StorageProfile.OSDisk == nil ||
		vm.Properties.StorageProfile.OSDisk.ManagedDisk == nil {
		return ""
	}
	return strVal(vm.Properties.StorageProfile.OSDisk.ManagedDisk.ID)
}

func vmSize(vm *armcompute.VirtualMachine) string {
	if vm.Properties == nil || vm.Properties.HardwareProfile == nil ||
		vm.Properties.HardwareProfile.VMSize == nil {
		return ""
	}
	return string(*vm.Properties.HardwareProfile.VMSize)
}
