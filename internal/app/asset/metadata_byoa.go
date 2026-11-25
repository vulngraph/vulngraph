package asset

// Bring-your-own-agent package inventory (internal/app/pkginv): the customer's
// own scanner submits a VM's package list. Stamped beside the keys in
// domain.go, with the same rule: an inventory is only believed when the server
// decided it is known.
const (
	// PackageInventoryBYOA is the MetaPackageInventory value for an inventory a
	// customer's agent submitted.
	PackageInventoryBYOA = "byoa"

	// MetaPackageInventoryScanner and MetaPackageInventoryScannerVersion name
	// the scanner that produced a submitted inventory. Both are pattern-
	// restricted single-line strings; nothing else the agent sent is stamped.
	MetaPackageInventoryScanner        = "package_inventory_scanner"
	MetaPackageInventoryScannerVersion = "package_inventory_scanner_version"
)
