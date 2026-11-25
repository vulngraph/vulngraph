package aws

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

const (
	// rdsParamConcurrency bounds the parameter-group reads in flight; each
	// group is several pages of a few hundred parameters.
	rdsParamConcurrency = 8
	// rdsParamTimeout bounds one group's full page sequence.
	rdsParamTimeout = 30 * time.Second
)

// rdsParamSpec is one parameter a check reads: the metadata key it lands on,
// and the engine default AWS documents for it. DescribeDB(Cluster)Parameters
// returns a parameter nobody set with no ParameterValue, meaning "the engine
// default applies", so the default is written rather than leaving the key
// absent: the setting WAS read, and its value is the default.
// versioned marks a parameter whose default differs by engine version: an
// unset value is then not knowable from the group alone, so the key stays
// absent.
type rdsParamSpec struct {
	name, key, engineDefault string
	versioned                bool
}

// rdsInstanceParamSpecs are the DB-parameter-group settings graded per
// instance engine.
func rdsInstanceParamSpecs(engine string) []rdsParamSpec {
	switch {
	case strings.HasPrefix(engine, "sqlserver"):
		// FSBP RDS.41. Off (0) by default on every SQL Server version.
		return []rdsParamSpec{{name: "rds.force_ssl", key: "force_ssl", engineDefault: "0"}}
	case engine == "mariadb":
		// FSBP RDS.44. OFF by default; the parameter exists only on MariaDB
		// 10.5+, so an older group simply has no value to stamp (the control
		// does not evaluate those versions either).
		return []rdsParamSpec{{name: "require_secure_transport", key: "require_secure_transport", engineDefault: "0"}}
	case engine == "postgres":
		// FSBP RDS.38. The default is 1 from PostgreSQL 15 and 0 before it.
		return []rdsParamSpec{{name: "rds.force_ssl", key: "force_ssl", versioned: true}}
	case engine == "mysql":
		// FSBP RDS.39. The default differs across MySQL major versions.
		return []rdsParamSpec{{name: "require_secure_transport", key: "require_secure_transport", versioned: true}}
	}
	return nil
}

// rdsClusterParamSpecs are the DB-cluster-parameter-group settings graded per
// cluster engine.
func rdsClusterParamSpecs(engine string) []rdsParamSpec {
	switch engine {
	case "aurora-mysql":
		// FSBP RDS.45: Advanced Auditing is off (0) and logs no event classes
		// (empty) until configured.
		return []rdsParamSpec{
			{name: "server_audit_logging", key: "server_audit_logging", engineDefault: "0"},
			{name: "server_audit_events", key: "server_audit_events", engineDefault: ""},
		}
	case "docdb":
		// FSBP DocumentDB.6: "enabled" by default.
		return []rdsParamSpec{{name: "tls", key: "tls", engineDefault: "enabled"}}
	}
	return nil
}

// stampRDSParameterFacts reads each parameter group the TLS and audit checks
// need — once per group, however many databases share it — and writes the
// effective values onto the instances and clusters using it. A group whose
// read fails leaves its databases' keys absent (unknown), never the default.
func stampRDSParameterFacts(ctx context.Context, client rdsPostureAPI, region string, instances, clusters []asset.Asset) {
	type target struct {
		meta  map[string]string
		specs []rdsParamSpec
	}
	var instTargets, clusterTargets []target
	instGroups, clusterGroups := map[string]bool{}, map[string]bool{}
	for _, a := range instances {
		if specs := rdsInstanceParamSpecs(a.Metadata["engine"]); len(specs) > 0 && a.Metadata["db_parameter_group"] != "" {
			instTargets = append(instTargets, target{a.Metadata, specs})
			instGroups[a.Metadata["db_parameter_group"]] = true
		}
	}
	for _, a := range clusters {
		if specs := rdsClusterParamSpecs(a.Metadata["engine"]); len(specs) > 0 && a.Metadata["db_cluster_parameter_group"] != "" {
			clusterTargets = append(clusterTargets, target{a.Metadata, specs})
			clusterGroups[a.Metadata["db_cluster_parameter_group"]] = true
		}
	}
	if len(instGroups)+len(clusterGroups) == 0 {
		return
	}
	instValues := readRDSParamGroups(ctx, instGroups, func(ctx context.Context, name string) ([]rdstypes.Parameter, error) {
		return listDBParameters(ctx, client, name)
	})
	clusterValues := readRDSParamGroups(ctx, clusterGroups, func(ctx context.Context, name string) ([]rdstypes.Parameter, error) {
		return listDBClusterParameters(ctx, client, name)
	})
	if unread := len(instGroups) - len(instValues) + len(clusterGroups) - len(clusterValues); unread > 0 {
		log.FromContext(ctx).Warn().Str("region", region).Int("unread_groups", unread).
			Msg("rds parameter group read failed (check rds:DescribeDBParameters / rds:DescribeDBClusterParameters); TLS and audit-logging settings unknown for the databases using them")
	}
	stamp := func(t target, groupKey string, values map[string]map[string]*string) {
		params, ok := values[t.meta[groupKey]]
		if !ok {
			return
		}
		for _, s := range t.specs {
			v, present := params[s.name]
			if !present {
				continue // the engine version has no such parameter
			}
			switch {
			case v == nil && s.versioned:
				continue // the default depends on the engine version
			case v == nil:
				t.meta[s.key] = s.engineDefault
			default:
				t.meta[s.key] = *v
			}
		}
	}
	for _, t := range instTargets {
		stamp(t, "db_parameter_group", instValues)
	}
	for _, t := range clusterTargets {
		stamp(t, "db_cluster_parameter_group", clusterValues)
	}
}

// readRDSParamGroups reads every named group, rdsParamConcurrency at a time,
// returning name → parameter name → value (nil = engine default). A group
// whose read failed or panicked is absent from the result.
func readRDSParamGroups(ctx context.Context, groups map[string]bool, read func(context.Context, string) ([]rdstypes.Parameter, error)) map[string]map[string]*string {
	out := map[string]map[string]*string{}
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, rdsParamConcurrency)
	)
	for name := range groups {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if rec := recover(); rec != nil {
					log.FromContext(ctx).Error().Any("panic", rec).Str("parameter_group", name).
						Msg("rds parameter group read panicked; its settings are unknown")
				}
			}()
			pctx, cancel := context.WithTimeout(ctx, rdsParamTimeout)
			defer cancel()
			params, err := read(pctx, name)
			if err != nil {
				return
			}
			values := make(map[string]*string, len(params))
			for _, p := range params {
				values[awssdk.ToString(p.ParameterName)] = p.ParameterValue
			}
			mu.Lock()
			out[name] = values
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

func listDBParameters(ctx context.Context, client rdsPostureAPI, group string) ([]rdstypes.Parameter, error) {
	var (
		out    []rdstypes.Parameter
		marker *string
	)
	for {
		page, err := client.DescribeDBParameters(ctx, &rds.DescribeDBParametersInput{DBParameterGroupName: awssdk.String(group), Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("listDBParameters %s: %w", group, err)
		}
		out = append(out, page.Parameters...)
		if page.Marker == nil {
			return out, nil
		}
		marker = page.Marker
	}
}

func listDBClusterParameters(ctx context.Context, client rdsPostureAPI, group string) ([]rdstypes.Parameter, error) {
	var (
		out    []rdstypes.Parameter
		marker *string
	)
	for {
		page, err := client.DescribeDBClusterParameters(ctx, &rds.DescribeDBClusterParametersInput{DBClusterParameterGroupName: awssdk.String(group), Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("listDBClusterParameters %s: %w", group, err)
		}
		out = append(out, page.Parameters...)
		if page.Marker == nil {
			return out, nil
		}
		marker = page.Marker
	}
}
