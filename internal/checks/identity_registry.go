package checks

// identityPostureChecks are the privilege-aware identity checks and the
// cross-asset posture checks whose inputs the AWS collector joins onto one asset.
func identityPostureChecks() []Check {
	return []Check{
		// Privilege × dormancy: one finding per dormant admin principal.
		awsIAMAdminRoleDormant,
		awsIAMAdminUserDormant,
		gcpSAAdminDormant,
		// A long-lived admin key with no MFA device to gate it.
		awsIAMAdminUserKeyNoMFA,
		// WinRM sibling of the Azure RDP/SSH NSG checks.
		azureNSGWinRMOpenInternet,
		// Joined by the collector: trail → its bucket's logging state.
		awsCloudTrailBucketNoAccessLogging,
		// Joined by the collector: node instance → its role's ECR push grant.
		eksNodeIMDSv1RegistryWrite,
		// Cryptographic inventory (Info).
		acmCertNonPQC,
	}
}
