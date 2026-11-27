package asset

// Annotation is a derived producer's field intent, never an inventory row.
// InputKey binds manifest drift to the declaration fields it interpreted.
type Annotation struct {
	ID       string
	Source   string
	InputKey string
	Metadata map[string]string // empty value explicitly clears an owned key
}

const ManifestDriftSource = "k8s_manifest_drift"
