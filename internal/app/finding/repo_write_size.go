package finding

import dbutil "github.com/vulngraph/vulngraph/pkg/db"

func findingWriteBytes(f Finding) int {
	return 256 + len(f.ID) + len(f.Source) + len(f.Type) + len(f.Severity) + len(f.Title) + len(f.Description) + len(f.ResourceType) + len(f.ResourceID) + len(f.ResourceName) + len(f.Region) + len(f.CheckID) + len(f.Remediation) + len(f.ResolutionReason) + dbutil.CHMapBytes(f.Metadata)
}
