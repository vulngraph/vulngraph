package graphschema

// VMAssetTypes are the virtual-machine asset types: the hosts whose software
// inventory comes from an OS inventory API (SSM, OS Config) rather than an image
// scan, and so the runs_package sources a package lineage must walk to the host's
// own exposure instead of through runs_image to a pod. Declared here because
// three layers ask it — enrich's supply-chain lineage, the VM fleet CVE job and
// the coverage report — and must not disagree.
var VMAssetTypes = []string{"ec2_instance", "gce_instance", "azure_vm"}

var vmTypeSet = sliceToSet(VMAssetTypes)

// IsVMType reports whether an asset type is a virtual machine.
func IsVMType(t string) bool { return vmTypeSet[t] }
