package azure

import (
	"context"
	"fmt"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// storageServiceConcurrency bounds the per-account service-property reads.
const storageServiceConcurrency = 8

// Platform defaults for an SMB setting the file service leaves unset: every
// protocol version and channel cipher Azure Files supports is accepted.
const (
	smbDefaultVersions          = "SMB2.1;SMB3.0;SMB3.1.1"
	smbDefaultChannelEncryption = "AES-128-CCM;AES-128-GCM;AES-256-GCM"
)

// storageServiceAPI is the per-account blob and file service reads (CIS 9.1,
// 9.2). An interface so the mapping is testable without an Azure endpoint.
type storageServiceAPI interface {
	blobService(ctx context.Context, rg, account string) (*armstorage.BlobServicePropertiesProperties, error)
	fileService(ctx context.Context, rg, account string) (*armstorage.FileServicePropertiesProperties, error)
	fileShares(ctx context.Context, rg, account string) (shareKinds, error)
}

// shareKinds is what the share listing says about an account: whether it holds
// any file share, and whether any of them is served over SMB (NFS shares, on
// premium FileStorage accounts, ignore every SMB setting).
type shareKinds struct{ any, smb bool }

type armStorageServices struct {
	blob   *armstorage.BlobServicesClient
	file   *armstorage.FileServicesClient
	shares *armstorage.FileSharesClient
}

func newARMStorageServices(subscriptionID string, cred azcore.TokenCredential, opts *arm.ClientOptions) (*armStorageServices, error) {
	blob, err := armstorage.NewBlobServicesClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("newARMStorageServices: blob: %w", err)
	}
	file, err := armstorage.NewFileServicesClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("newARMStorageServices: file: %w", err)
	}
	shares, err := armstorage.NewFileSharesClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("newARMStorageServices: shares: %w", err)
	}
	return &armStorageServices{blob: blob, file: file, shares: shares}, nil
}

func (s *armStorageServices) blobService(ctx context.Context, rg, account string) (*armstorage.BlobServicePropertiesProperties, error) {
	resp, err := s.blob.GetServiceProperties(ctx, rg, account, nil)
	if err != nil {
		return nil, fmt.Errorf("blobService: %w", err)
	}
	return resp.BlobServiceProperties.BlobServiceProperties, nil
}

func (s *armStorageServices) fileService(ctx context.Context, rg, account string) (*armstorage.FileServicePropertiesProperties, error) {
	resp, err := s.file.GetServiceProperties(ctx, rg, account, nil)
	if err != nil {
		return nil, fmt.Errorf("fileService: %w", err)
	}
	return resp.FileServiceProperties.FileServiceProperties, nil
}

// fileShares pages through the account's shares until it meets an SMB share,
// which is all the soft-delete and SMB controls need. Outside FileStorage
// every share is SMB, so that is the first share of the first page. Any page
// error fails the read: a short listing must not read as "no SMB shares".
func (s *armStorageServices) fileShares(ctx context.Context, rg, account string) (shareKinds, error) {
	var k shareKinds
	pager := s.shares.NewListPager(rg, account, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return shareKinds{}, fmt.Errorf("fileShares: %w", err)
		}
		for _, sh := range page.Value {
			if sh == nil {
				continue
			}
			k.any = true
			if sh.Properties == nil || sh.Properties.EnabledProtocols == nil ||
				*sh.Properties.EnabledProtocols == armstorage.EnabledProtocolsSMB {
				k.smb = true
				return k, nil
			}
		}
	}
	return k, nil
}

// readStorageServices adds the blob and file service posture to each storage
// account asset, at most storageServiceConcurrency accounts at a time. A
// failed read leaves that service's keys absent (unknown) and never fails the
// account: the account itself was enumerated.
func readStorageServices(ctx context.Context, api storageServiceAPI, assets []asset.Asset) {
	sem := make(chan struct{}, storageServiceConcurrency)
	var wg sync.WaitGroup
	for i := range assets {
		wg.Add(1)
		sem <- struct{}{}
		go func(a *asset.Asset) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					log.FromContext(ctx).Error().Interface("panic", r).Str("account", a.ID).Msg("azure storage service read panicked")
				}
			}()
			for k, v := range storageServiceMetadata(ctx, api, a.ID, a.Name, a.Metadata["kind"]) {
				a.Metadata[k] = v
			}
		}(&assets[i])
	}
	wg.Wait()
}

// storageServiceMetadata reads one account's services. Each service is read
// only on the account kinds that have it: FileStorage has no blob service and
// BlobStorage/BlockBlobStorage have no file service, so their keys stay absent
// rather than reading as a disabled feature.
func storageServiceMetadata(ctx context.Context, api storageServiceAPI, id, name, kind string) map[string]string {
	rg := resourceGroup(id)
	meta := map[string]string{}
	logger := log.FromContext(ctx)
	if kind != string(armstorage.KindFileStorage) {
		if p, err := api.blobService(ctx, rg, name); err != nil {
			logger.Warn().Err(err).Str("account", id).Msg("azure blob service properties unreadable")
		} else {
			blobServiceMetadata(p, meta)
		}
	}
	if kind == string(armstorage.KindBlobStorage) || kind == string(armstorage.KindBlockBlobStorage) {
		return meta
	}
	shares, err := api.fileShares(ctx, rg, name)
	if err != nil {
		logger.Warn().Err(err).Str("account", id).Msg("azure file shares unreadable")
		return meta
	}
	p, err := api.fileService(ctx, rg, name)
	if err != nil {
		logger.Warn().Err(err).Str("account", id).Msg("azure file service properties unreadable")
		return meta
	}
	meta["file_shares"] = boolStr(shares.any)
	meta["smb_shares"] = boolStr(shares.smb)
	fileServiceMetadata(p, meta)
	return meta
}

// blobServiceMetadata maps a successfully read blob service. A retention
// policy or versioning flag missing from a returned response is the feature
// switched off: ARM only writes them once set.
func blobServiceMetadata(p *armstorage.BlobServicePropertiesProperties, meta map[string]string) {
	if p == nil {
		p = &armstorage.BlobServicePropertiesProperties{}
	}
	meta["blob_soft_delete"] = boolStr(retentionOn(p.DeleteRetentionPolicy))
	meta["container_soft_delete"] = boolStr(retentionOn(p.ContainerDeleteRetentionPolicy))
	meta["blob_versioning"] = boolStr(p.IsVersioningEnabled != nil && *p.IsVersioningEnabled)
}

// fileServiceMetadata maps a successfully read file service. Unset SMB lists
// are the platform defaults, which accept every version and cipher.
func fileServiceMetadata(p *armstorage.FileServicePropertiesProperties, meta map[string]string) {
	if p == nil {
		p = &armstorage.FileServicePropertiesProperties{}
	}
	meta["file_soft_delete"] = boolStr(retentionOn(p.ShareDeleteRetentionPolicy))
	versions, channel := smbDefaultVersions, smbDefaultChannelEncryption
	if p.ProtocolSettings != nil && p.ProtocolSettings.Smb != nil {
		if v := strVal(p.ProtocolSettings.Smb.Versions); v != "" {
			versions = v
		}
		if v := strVal(p.ProtocolSettings.Smb.ChannelEncryption); v != "" {
			channel = v
		}
	}
	meta["smb_versions"] = versions
	meta["smb_channel_encryption"] = channel
}

func retentionOn(p *armstorage.DeleteRetentionPolicy) bool {
	return p != nil && p.Enabled != nil && *p.Enabled
}
