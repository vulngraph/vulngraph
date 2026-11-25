package aws

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	smtypes "github.com/aws/aws-sdk-go-v2/service/sagemaker/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// SageMaker notebook instances, models and endpoint configurations (AWS FSBP
// SageMaker.1-5, .8, .16, .19). Every resource is listed in full, then
// described one by one; a failed describe leaves that resource's keys absent.

// describeConcurrency bounds the per-resource Describe*/Get* calls one
// listing fans out to. SageMaker accounts can hold thousands of models; four
// in flight keeps a region's task short without tripping the API's TPS limit.
const describeConcurrency = 4

type sageMakerAPI interface {
	ListNotebookInstances(context.Context, *sagemaker.ListNotebookInstancesInput, ...func(*sagemaker.Options)) (*sagemaker.ListNotebookInstancesOutput, error)
	DescribeNotebookInstance(context.Context, *sagemaker.DescribeNotebookInstanceInput, ...func(*sagemaker.Options)) (*sagemaker.DescribeNotebookInstanceOutput, error)
	ListModels(context.Context, *sagemaker.ListModelsInput, ...func(*sagemaker.Options)) (*sagemaker.ListModelsOutput, error)
	DescribeModel(context.Context, *sagemaker.DescribeModelInput, ...func(*sagemaker.Options)) (*sagemaker.DescribeModelOutput, error)
	ListEndpointConfigs(context.Context, *sagemaker.ListEndpointConfigsInput, ...func(*sagemaker.Options)) (*sagemaker.ListEndpointConfigsOutput, error)
	DescribeEndpointConfig(context.Context, *sagemaker.DescribeEndpointConfigInput, ...func(*sagemaker.Options)) (*sagemaker.DescribeEndpointConfigOutput, error)
}

func collectSageMaker(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectSageMaker: %w", err)
	}
	return readSageMaker(ctx, sagemaker.NewFromConfig(awsCfg), region, accountID, now)
}

// listedResource is one listed resource awaiting its describe call; id is
// set for APIs that address a resource by id rather than name.
type listedResource struct {
	arn, name, id string
}

func readSageMaker(ctx context.Context, client sageMakerAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	notebooks, err := listNotebooks(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("readSageMaker: %w", err)
	}
	models, err := listModels(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("readSageMaker: %w", err)
	}
	configs, err := listEndpointConfigs(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("readSageMaker: %w", err)
	}
	out := describeAll(ctx, region, "sagemaker:DescribeNotebookInstance", notebooks, func(r listedResource) (map[string]string, error) {
		d, err := client.DescribeNotebookInstance(ctx, &sagemaker.DescribeNotebookInstanceInput{NotebookInstanceName: &r.name})
		if err != nil {
			return nil, err
		}
		return notebookMetadata(d), nil
	})
	notebookAssets := listedAssets(out, notebooks, "sagemaker_notebook", region, accountID, now)
	out = describeAll(ctx, region, "sagemaker:DescribeModel", models, func(r listedResource) (map[string]string, error) {
		d, err := client.DescribeModel(ctx, &sagemaker.DescribeModelInput{ModelName: &r.name})
		if err != nil {
			return nil, err
		}
		return modelMetadata(d), nil
	})
	modelAssets := listedAssets(out, models, "sagemaker_model", region, accountID, now)
	out = describeAll(ctx, region, "sagemaker:DescribeEndpointConfig", configs, func(r listedResource) (map[string]string, error) {
		d, err := client.DescribeEndpointConfig(ctx, &sagemaker.DescribeEndpointConfigInput{EndpointConfigName: &r.name})
		if err != nil {
			return nil, err
		}
		return endpointConfigMetadata(d), nil
	})
	configAssets := listedAssets(out, configs, "sagemaker_endpoint_config", region, accountID, now)
	return append(append(notebookAssets, modelAssets...), configAssets...), nil
}

func listNotebooks(ctx context.Context, client sageMakerAPI) ([]listedResource, error) {
	var (
		out  []listedResource
		next *string
	)
	for {
		page, err := client.ListNotebookInstances(ctx, &sagemaker.ListNotebookInstancesInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("listNotebooks: %w", err)
		}
		for _, n := range page.NotebookInstances {
			out = append(out, listedResource{arn: awssdk.ToString(n.NotebookInstanceArn), name: awssdk.ToString(n.NotebookInstanceName)})
		}
		if page.NextToken == nil {
			return out, nil
		}
		next = page.NextToken
	}
}

func listModels(ctx context.Context, client sageMakerAPI) ([]listedResource, error) {
	var (
		out  []listedResource
		next *string
	)
	for {
		page, err := client.ListModels(ctx, &sagemaker.ListModelsInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("listModels: %w", err)
		}
		for _, m := range page.Models {
			out = append(out, listedResource{arn: awssdk.ToString(m.ModelArn), name: awssdk.ToString(m.ModelName)})
		}
		if page.NextToken == nil {
			return out, nil
		}
		next = page.NextToken
	}
}

func listEndpointConfigs(ctx context.Context, client sageMakerAPI) ([]listedResource, error) {
	var (
		out  []listedResource
		next *string
	)
	for {
		page, err := client.ListEndpointConfigs(ctx, &sagemaker.ListEndpointConfigsInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("listEndpointConfigs: %w", err)
		}
		for _, c := range page.EndpointConfigs {
			out = append(out, listedResource{arn: awssdk.ToString(c.EndpointConfigArn), name: awssdk.ToString(c.EndpointConfigName)})
		}
		if page.NextToken == nil {
			return out, nil
		}
		next = page.NextToken
	}
}

// notebookMetadata reads the FSBP notebook settings. subnet_id and kms_key_id
// are written even when empty: a described notebook with no SubnetId was
// observed to run outside any customer VPC, and one with no KmsKeyId to use
// the AWS managed key for its storage volume.
func notebookMetadata(d *sagemaker.DescribeNotebookInstanceOutput) map[string]string {
	md := map[string]string{
		"subnet_id":  awssdk.ToString(d.SubnetId),
		"status":     string(d.NotebookInstanceStatus),
		"kms_key_id": awssdk.ToString(d.KmsKeyId),
	}
	if v, ok := enabledFlag(string(d.DirectInternetAccess), string(smtypes.DirectInternetAccessEnabled), string(smtypes.DirectInternetAccessDisabled)); ok {
		md["direct_internet_access"] = v
	}
	if v, ok := enabledFlag(string(d.RootAccess), string(smtypes.RootAccessEnabled), string(smtypes.RootAccessDisabled)); ok {
		md["root_access"] = v
	}
	if p := awssdk.ToString(d.PlatformIdentifier); p != "" {
		md["platform_identifier"] = p
	}
	return md
}

// enabledFlag maps an Enabled/Disabled enum to "true"/"false"; any other
// value (an empty field, a value newer than this client) is not an answer.
func enabledFlag(v, enabled, disabled string) (string, bool) {
	switch v {
	case enabled:
		return "true", true
	case disabled:
		return "false", true
	}
	return "", false
}

// modelMetadata reads network isolation and where the model's images are
// pulled from. A model with a PrimaryContainer (or a single entry in
// Containers) records primary_image_access_mode — "" when it sets no
// ImageConfig, which FSBP SageMaker.16 fails like Platform. An inference
// pipeline (two or more Containers) records the hostnames (or positions) of
// the containers not pulled from a private registry in the VPC (SageMaker.19).
func modelMetadata(d *sagemaker.DescribeModelOutput) map[string]string {
	md := map[string]string{}
	if d.EnableNetworkIsolation != nil {
		md["network_isolation"] = strconv.FormatBool(*d.EnableNetworkIsolation)
	}
	primary := d.PrimaryContainer
	if primary == nil && len(d.Containers) == 1 {
		primary = &d.Containers[0]
	}
	if primary != nil {
		md["primary_image_access_mode"] = imageAccessMode(primary)
	}
	if len(d.Containers) > 1 {
		var notVPC []string
		for i, c := range d.Containers {
			if imageAccessMode(&c) != string(smtypes.RepositoryAccessModeVpc) {
				name := awssdk.ToString(c.ContainerHostname)
				if name == "" {
					name = "container-" + strconv.Itoa(i+1)
				}
				notVPC = append(notVPC, name)
			}
		}
		md["pipeline_containers_not_vpc_registry"] = strings.Join(notVPC, ",")
	}
	return md
}

func imageAccessMode(c *smtypes.ContainerDefinition) string {
	if c.ImageConfig == nil {
		return ""
	}
	return string(c.ImageConfig.RepositoryAccessMode)
}

// endpointConfigMetadata lists the instance-based production variants that
// start with a single instance (FSBP SageMaker.4). Serverless variants and
// variants with no InitialInstanceCount (inference-component endpoints) are
// not instance-based and are not counted.
func endpointConfigMetadata(d *sagemaker.DescribeEndpointConfigOutput) map[string]string {
	var single []string
	for _, v := range d.ProductionVariants {
		if v.ServerlessConfig != nil || v.InitialInstanceCount == nil {
			continue
		}
		if *v.InitialInstanceCount <= 1 {
			single = append(single, awssdk.ToString(v.VariantName))
		}
	}
	return map[string]string{"single_instance_variants": strings.Join(single, ",")}
}

// describeAll runs describe for every resource with at most
// describeConcurrency calls in flight and returns each resource's metadata by
// position; a failed (or panicking) describe leaves its slot nil, and one
// warning per listing names the permission and the failure count.
func describeAll(ctx context.Context, region, action string, rs []listedResource, describe func(listedResource) (map[string]string, error)) []map[string]string {
	out := make([]map[string]string, len(rs))
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		failed   int
		firstErr error
	)
	fail := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		if failed == 0 {
			firstErr = err
		}
		failed++
	}
	sem := make(chan struct{}, describeConcurrency)
	for i, r := range rs {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if rec := recover(); rec != nil {
					log.FromContext(ctx).Error().Str("region", region).Str("action", action).Interface("panic", rec).Msg("describe panicked; resource emitted without its settings")
					fail(fmt.Errorf("panic: %v", rec))
				}
			}()
			md, err := describe(r)
			if err != nil {
				fail(err)
				return
			}
			out[i] = md
		}()
	}
	wg.Wait()
	if failed > 0 {
		log.FromContext(ctx).Warn().Err(firstErr).Str("region", region).Int("failed", failed).
			Msgf("%s failed (check the permission); those resources carry no settings this sweep, so their checks cannot evaluate them", action)
	}
	return out
}

// listedAssets pairs each listed resource with its described metadata.
func listedAssets(mds []map[string]string, rs []listedResource, typ, region, accountID string, now time.Time) []asset.Asset {
	out := make([]asset.Asset, 0, len(rs))
	for i, r := range rs {
		md := mds[i]
		if md == nil {
			md = map[string]string{}
		}
		out = append(out, asset.Asset{
			ID:           r.arn,
			Name:         r.name,
			Type:         typ,
			Provider:     asset.ProviderAWS,
			Region:       region,
			AccountID:    accountID,
			Metadata:     md,
			DiscoveredAt: now,
			LastSeen:     now,
		})
	}
	return out
}

// stampSageMakerNotebookVPC writes in_default_vpc on every notebook attached
// to a subnet (FSBP SageMaker.2: the default VPC is not a custom VPC). The VPC
// comes from the subnet and vpc assets of the same sweep; when either is
// missing the key is omitted rather than guessed.
func stampSageMakerNotebookVPC(assets []asset.Asset) {
	vpcBySubnet := map[string]string{}
	defaultVPC := map[string]string{}
	for _, a := range assets {
		if a.Provider != asset.ProviderAWS {
			continue
		}
		switch a.Type {
		case "subnet":
			if v := a.Metadata["vpc_id"]; v != "" {
				vpcBySubnet[a.ID] = v
			}
		case "vpc":
			if v, ok := a.Metadata["is_default"]; ok {
				defaultVPC[a.ID] = v
			}
		}
	}
	for i := range assets {
		a := &assets[i]
		if a.Type != "sagemaker_notebook" || a.Metadata["subnet_id"] == "" {
			continue
		}
		if isDefault, ok := defaultVPC[vpcBySubnet[a.Metadata["subnet_id"]]]; ok {
			a.Metadata["in_default_vpc"] = isDefault
		}
	}
}
