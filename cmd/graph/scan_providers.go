package main

import (
	"flag"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/vulngraph/vulngraph/internal/collect"
	collectaws "github.com/vulngraph/vulngraph/internal/collect/aws"
	collectazure "github.com/vulngraph/vulngraph/internal/collect/azure"
	collectdemo "github.com/vulngraph/vulngraph/internal/collect/demo"
	collectgcp "github.com/vulngraph/vulngraph/internal/collect/gcp"
	collectgoogle "github.com/vulngraph/vulngraph/internal/collect/google"
	collectokta "github.com/vulngraph/vulngraph/internal/collect/okta"
)

// scanProvider describes how `graph scan <name>` reaches one provider: the
// flags it adds, the collector config it builds from flags and environment,
// and the collector itself. Credentials come from the environment only.
type scanProvider struct {
	credentials string // shown by -h
	flags       func(fs *flag.FlagSet, o *scanOptions)
	config      func(o scanOptions, getenv func(string) string) (map[string]string, error)
	collector   func() collect.Collector
}

var scanProviders = map[string]scanProvider{
	"demo": {
		credentials: "none: scans Acme, a fictional AWS account bundled with Vulngraph",
		flags:       func(*flag.FlagSet, *scanOptions) {},
		config:      func(scanOptions, func(string) string) (map[string]string, error) { return map[string]string{}, nil },
		collector:   func() collect.Collector { return collectdemo.New() },
	},
	"aws": {
		credentials: "AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY (+ AWS_SESSION_TOKEN for temporary credentials), or --role-arn; SSO/profile users: eval $(aws configure export-credentials --format env)",
		flags: func(fs *flag.FlagSet, o *scanOptions) {
			fs.StringVar(&o.region, "region", "us-east-1", "base region for global calls")
			fs.StringVar(&o.regions, "regions", "", "comma-separated regions to scan (default: every enabled region)")
			fs.StringVar(&o.roleARN, "role-arn", "", "role to assume using the credentials above")
		},
		config: awsScanConfig,
		collector: func() collect.Collector {
			return collectaws.New(nil)
		},
	},
	"gcp": {
		credentials: "Application Default Credentials (gcloud auth application-default login), project from --project or GOOGLE_CLOUD_PROJECT",
		flags: func(fs *flag.FlagSet, o *scanOptions) {
			fs.StringVar(&o.project, "project", "", "GCP project ID to scan (default: GOOGLE_CLOUD_PROJECT)")
		},
		config: gcpScanConfig,
		collector: func() collect.Collector {
			return collectgcp.New(nil)
		},
	},
	"azure": {
		credentials: "AZURE_SUBSCRIPTION_ID, plus either a service principal (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET) or an ambient login such as az login",
		flags:       func(*flag.FlagSet, *scanOptions) {},
		config:      azureScanConfig,
		collector:   func() collect.Collector { return collectazure.New() },
	},
	"okta": {
		credentials: "OKTA_DOMAIN, OKTA_API_TOKEN",
		flags:       func(*flag.FlagSet, *scanOptions) {},
		config: func(_ scanOptions, getenv func(string) string) (map[string]string, error) {
			return requireEnv(getenv, map[string]string{"OKTA_DOMAIN": "domain", "OKTA_API_TOKEN": "api_token"})
		},
		collector: func() collect.Collector { return collectokta.New() },
	},
	"googleworkspace": {
		credentials: "GOOGLE_APPLICATION_CREDENTIALS pointing at a service-account KEY file (not an ADC login) with domain-wide delegation, plus --admin-email or GOOGLE_WORKSPACE_ADMIN_EMAIL",
		flags: func(fs *flag.FlagSet, o *scanOptions) {
			fs.StringVar(&o.adminEmail, "admin-email", "", "Workspace admin to impersonate (default: GOOGLE_WORKSPACE_ADMIN_EMAIL)")
		},
		config: googleScanConfig,
		collector: func() collect.Collector {
			return collectgoogle.New()
		},
	},
}

// scanProviderNames lists the supported providers for usage text.
func scanProviderNames() string {
	return strings.Join(slices.Sorted(maps.Keys(scanProviders)), "|")
}

// azureScanConfig needs the subscription; a service principal is optional
// because the collector falls back to the ambient Azure login without one.
func azureScanConfig(_ scanOptions, getenv func(string) string) (map[string]string, error) {
	sub := getenv("AZURE_SUBSCRIPTION_ID")
	if sub == "" {
		return nil, fmt.Errorf("scan: set AZURE_SUBSCRIPTION_ID (and AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET for a service principal)")
	}
	cfg := map[string]string{"name": "cli-scan", "subscription_id": sub}
	var set, unset []string
	for _, env := range []string{"AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID"} {
		if v := getenv(env); v != "" {
			cfg[strings.ToLower(strings.TrimPrefix(env, "AZURE_"))] = v
			set = append(set, env)
		} else {
			unset = append(unset, env)
		}
	}
	// The collector uses the service principal only when all three are set and
	// otherwise falls back to whatever login is ambient: a partial set would
	// silently scan as a different identity.
	if len(set) > 0 && len(unset) > 0 {
		return nil, fmt.Errorf("scan: service principal incomplete: %s set but %s missing (set all three, or none to use the ambient login)", strings.Join(set, ", "), strings.Join(unset, ", "))
	}
	return cfg, nil
}

// requireEnv maps environment variables to collector config keys and fails
// naming every variable that is unset.
func requireEnv(getenv func(string) string, vars map[string]string) (map[string]string, error) {
	cfg := map[string]string{"name": "cli-scan"}
	var missing []string
	for env, key := range vars {
		v := getenv(env)
		if v == "" {
			missing = append(missing, env)
			continue
		}
		cfg[key] = v
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return nil, fmt.Errorf("scan: set %s", strings.Join(missing, ", "))
	}
	return cfg, nil
}

func awsScanConfig(o scanOptions, getenv func(string) string) (map[string]string, error) {
	cfg := map[string]string{"name": "cli-scan", "region": o.region, "regions": o.regions}
	keyID := getenv("AWS_ACCESS_KEY_ID")
	if keyID == "" && o.roleARN == "" {
		return nil, fmt.Errorf("scan: set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY (and AWS_SESSION_TOKEN for temporary credentials), or pass --role-arn")
	}
	if keyID != "" {
		cfg["aws_access_key_id"] = keyID
		cfg["aws_secret_access_key"] = getenv("AWS_SECRET_ACCESS_KEY")
		cfg["aws_session_token"] = getenv("AWS_SESSION_TOKEN")
	}
	if o.roleARN != "" {
		cfg["role_arn"] = o.roleARN
	}
	return cfg, nil
}

// gcpScanConfig needs only a project: the collector authenticates with
// Application Default Credentials (`gcloud auth application-default login`
// or GOOGLE_APPLICATION_CREDENTIALS).
func gcpScanConfig(o scanOptions, getenv func(string) string) (map[string]string, error) {
	project := o.project
	if project == "" {
		project = getenv("GOOGLE_CLOUD_PROJECT")
	}
	if project == "" {
		return nil, fmt.Errorf("scan: pass --project or set GOOGLE_CLOUD_PROJECT (credentials come from Application Default Credentials)")
	}
	return map[string]string{"name": "cli-scan", "project_id": project}, nil
}

// googleScanConfig reads the service-account key from the file named by
// GOOGLE_APPLICATION_CREDENTIALS; the key never leaves the process.
func googleScanConfig(o scanOptions, getenv func(string) string) (map[string]string, error) {
	admin := o.adminEmail
	if admin == "" {
		admin = getenv("GOOGLE_WORKSPACE_ADMIN_EMAIL")
	}
	path := getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if admin == "" || path == "" {
		return nil, fmt.Errorf("scan: set GOOGLE_APPLICATION_CREDENTIALS (service-account key file) and pass --admin-email or set GOOGLE_WORKSPACE_ADMIN_EMAIL")
	}
	key, err := os.ReadFile(path) //nolint:gosec // operator-supplied key path
	if err != nil {
		return nil, fmt.Errorf("scan: read service-account key: %w", err)
	}
	return map[string]string{"name": "cli-scan", "admin_email": admin, "service_account_json": string(key)}, nil
}
