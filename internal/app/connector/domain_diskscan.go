package connector

import (
	"errors"

	"github.com/vulngraph/vulngraph/internal/app/diskscan"
)

// Disk-scan role keys in a connector's config. Each names the principal that
// holds snapshot permissions, kept apart from every collection and execute
// principal so the snapshot grant never rides on a role that can do more.
const (
	ConfigDiskScanRoleARN        = "disk_scan_role_arn"        // AWS
	ConfigDiskScanClientID       = "disk_scan_client_id"       // Azure (its secret sits beside it)
	ConfigDiskScanServiceAccount = "disk_scan_service_account" // GCP
)

// AuditActionDiskScanChange is written for every disk-scan mode change.
// Details: before, after, role (the disk-scan role identifier, "" when none),
// actor, at. The enabling is the standing approval for snapshot reads and
// creation, so the row names who gave it and when.
const AuditActionDiskScanChange = "connector.disk_scan_change"

// DiskScanConfirmation is the exact text an admin must send to enable disk
// scanning. It names the cost (snapshot and snapshot-read charges on the
// customer's cloud bill) and the permission (a dedicated role that can read
// snapshots, and in create_snapshots mode create and delete tagged ones).
const DiskScanConfirmation = "I accept the snapshot cost and the snapshot permissions"

var (
	// ErrDiskScanForbidden: the actor is not an admin signed in as a person.
	ErrDiskScanForbidden = errors.New("connector: disk scan can be changed only by an admin session")
	// ErrDiskScanInvalidMode: the mode is not off, existing_snapshots or create_snapshots.
	ErrDiskScanInvalidMode = errors.New("connector: invalid disk scan mode")
	// ErrDiskScanUnsupported: the connector type has no disk-scan support.
	ErrDiskScanUnsupported = errors.New("connector: disk scan is not supported for this connector type")
	// ErrDiskScanConfirmation: the typed confirmation is missing or wrong.
	ErrDiskScanConfirmation = errors.New("connector: disk scan confirmation does not match")
	// ErrDiskScanRoleMissing: create_snapshots, and existing_snapshots on Azure, need the dedicated principal in the config.
	ErrDiskScanRoleMissing = errors.New("connector: this disk scan mode needs the disk scan role key set")
	// ErrDiskScanRoleShared: the disk-scan role equals a collection or execute role.
	ErrDiskScanRoleShared = errors.New("connector: the disk scan role must differ from the collection, read-only and execute roles")
)

// DiskScanActor identifies who asks for a disk-scan change. The transport
// fills it from the session; ViaAPIKey is true when the request was
// authenticated by an API key, which an agent may hold.
type DiskScanActor struct {
	ID        string
	Admin     bool
	ViaAPIKey bool
}

// DiskScanSettings is what the disk-scan service needs of a connector. Role
// and OtherRoles are identifiers, never secrets.
type DiskScanSettings struct {
	ConnectorID string
	Type        Type
	Mode        diskscan.DiskScanMode
	Role        string
	OtherRoles  []string
}

// diskScanRoleKeys names, per provider, the disk-scan role key and the config
// keys of every other principal it must differ from.
var diskScanRoleKeys = map[Type]struct {
	role   string
	others []string
}{
	TypeAWS:   {ConfigDiskScanRoleARN, []string{"role_arn", "readonly_role_arn", "execute_role_arn"}},
	TypeAzure: {ConfigDiskScanClientID, []string{"client_id", "execute_client_id"}},
	TypeGCP:   {ConfigDiskScanServiceAccount, []string{"execute_service_account"}},
}

// DiskScanSupported reports whether the connector type can have disk scanning.
func DiskScanSupported(t Type) bool {
	_, ok := diskScanRoleKeys[t]
	return ok
}

// DiskScanRoles returns the disk-scan role identifier from a connector's
// decrypted config and the identifiers of the other roles, omitting unset
// ones. The role is "" when the connector has none or its type is unsupported.
func DiskScanRoles(t Type, config map[string]string) (role string, others []string) {
	keys, ok := diskScanRoleKeys[t]
	if !ok {
		return "", nil
	}
	for _, k := range keys.others {
		if v := config[k]; v != "" {
			others = append(others, v)
		}
	}
	return config[keys.role], others
}
