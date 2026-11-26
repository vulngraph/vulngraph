package asset

import dbutil "github.com/vulngraph/vulngraph/pkg/db"

func assetWriteBytes(a Asset) int {
	return 256 + len(a.ID) + len(a.Name) + len(a.Type) + len(a.Provider) + len(a.Region) + len(a.AccountID) + len(a.Endpoint) + len(a.PublicIP) + len(a.PrivateIP) + len(a.Domain) + dbutil.CHMapBytes(a.Tags) + dbutil.CHMapBytes(a.Metadata)
}

func edgeWriteBytes(e Edge) int {
	return 128 + len(e.SrcID) + len(e.SrcType) + len(e.DstID) + len(e.DstType) + len(e.EdgeType) + dbutil.CHMapBytes(e.Properties)
}
