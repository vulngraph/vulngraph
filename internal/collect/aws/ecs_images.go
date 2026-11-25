package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// ecsServiceGroupPrefix is how ECS stamps a task launched by a service:
// Task.Group = "service:<service name>". Standalone tasks carry "family:…".
const ecsServiceGroupPrefix = "service:"

// targetGroupAPI is the slice of ELBv2 the ECS collector needs to resolve a
// service's target groups to the load balancers fronting it.
type targetGroupAPI interface {
	DescribeTargetGroups(context.Context, *elasticloadbalancingv2.DescribeTargetGroupsInput, ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeTargetGroupsOutput, error)
}

// clusterTasks is what one cluster's RUNNING tasks say about the images in it.
// The two counters are the images no edge can carry, so their absence from the
// graph is recorded rather than read as "runs nothing".
type clusterTasks struct {
	images     map[string][]collect.RunningImage // service name → resolved digests
	unresolved map[string]int                    // service name → containers with no digest yet
	standalone int                               // tasks no service launched ("family:…")
}

// runningServiceImages returns, per service name, the image digests the
// cluster's RUNNING service tasks actually resolved — DescribeTasks'
// containers[].imageDigest, not the task definition's image string, because a
// tag ("app:latest") is mutable and only the digest identifies what runs.
//
// One cluster-wide ListTasks + DescribeTasks per 100 tasks rather than a call
// pair per service: the task's Group names its service, so the fan-out is
// bounded by task count, not service count. An error returns nothing for the
// cluster; the caller flags the sweep partial rather than reading "no image" as
// "runs nothing".
func runningServiceImages(ctx context.Context, client ecsAPI, clusterARN string) (*clusterTasks, error) {
	var taskARNs []string
	var token *string
	for {
		out, err := client.ListTasks(ctx, &ecs.ListTasksInput{
			Cluster:       &clusterARN,
			DesiredStatus: ecstypes.DesiredStatusRunning,
			NextToken:     token,
		})
		if err != nil {
			return nil, fmt.Errorf("runningServiceImages: list tasks: %w", err)
		}
		taskARNs = append(taskARNs, out.TaskArns...)
		if out.NextToken == nil {
			break
		}
		token = out.NextToken
	}

	ct := &clusterTasks{images: map[string][]collect.RunningImage{}, unresolved: map[string]int{}}
	seen := map[string]map[string]bool{} // service → digest set
	// DescribeTasks takes at most 100 tasks per call.
	for _, batch := range chunk(taskARNs, 100) {
		out, err := client.DescribeTasks(ctx, &ecs.DescribeTasksInput{Cluster: &clusterARN, Tasks: batch})
		if err != nil {
			return nil, fmt.Errorf("runningServiceImages: describe tasks: %w", err)
		}
		for _, task := range out.Tasks {
			group := awssdk.ToString(task.Group)
			if !strings.HasPrefix(group, ecsServiceGroupPrefix) {
				// A standalone task (RunTask / scheduled task) belongs to no
				// collected asset, so its images cannot hang off anything.
				ct.standalone++
				continue
			}
			svc := strings.TrimPrefix(group, ecsServiceGroupPrefix)
			for _, c := range task.Containers {
				img, ok := collect.ParseImageDigest(awssdk.ToString(c.ImageDigest), awssdk.ToString(c.Image))
				if !ok || img.Ref == "" {
					// Digest not resolved yet (PENDING) — nothing stable to key on.
					ct.unresolved[svc]++
					continue
				}
				if seen[svc] == nil {
					seen[svc] = map[string]bool{}
				}
				if seen[svc][img.Digest] {
					continue
				}
				seen[svc][img.Digest] = true
				ct.images[svc] = append(ct.images[svc], img)
			}
		}
	}
	return ct, nil
}

// targetGroupLoadBalancers resolves target group ARNs to the load balancer
// ARNs that forward to them. An ECS service registered behind an ALB/NLB is
// reached THROUGH that load balancer, so the collector emits load_balancer
// -routes_to-> ecs_service and the internet-hops BFS carries the LB's exposure
// on to the service and, by containment, to the images it runs.
//
// A target group a service still references but that no longer exists is
// dropped on its own (describeTargetGroups) — it routes nothing, so its missing
// link is the truth, not a failed read. Any other error fails the lookup.
func targetGroupLoadBalancers(ctx context.Context, client targetGroupAPI, tgARNs []string) (map[string][]string, error) {
	out := map[string][]string{}
	for _, batch := range chunk(tgARNs, 20) {
		if err := describeTargetGroups(ctx, client, batch, out); err != nil {
			return nil, fmt.Errorf("targetGroupLoadBalancers: %w", err)
		}
	}
	return out, nil
}

// describeTargetGroups resolves one batch into out. ELBv2 fails the WHOLE call
// with TargetGroupNotFound when any one ARN is unknown, so on that error the
// batch is bisected until the missing ARN is isolated and skipped: one stale
// target group costs O(log n) extra calls and only its own link.
func describeTargetGroups(ctx context.Context, client targetGroupAPI, batch []string, out map[string][]string) error {
	got := map[string][]string{}
	var marker *string
	for {
		resp, err := client.DescribeTargetGroups(ctx, &elasticloadbalancingv2.DescribeTargetGroupsInput{
			TargetGroupArns: batch,
			Marker:          marker,
		})
		var notFound *elbv2types.TargetGroupNotFoundException
		switch {
		case errors.As(err, &notFound) && len(batch) == 1:
			log.FromContext(ctx).Debug().Str("target_group", batch[0]).
				Msg("ecs: service references a target group that no longer exists; no load balancer link")
			return nil
		case errors.As(err, &notFound):
			mid := len(batch) / 2
			if err := describeTargetGroups(ctx, client, batch[:mid], out); err != nil {
				return err
			}
			return describeTargetGroups(ctx, client, batch[mid:], out)
		case err != nil:
			return fmt.Errorf("describeTargetGroups: %w", err)
		}
		for _, tg := range resp.TargetGroups {
			arn := awssdk.ToString(tg.TargetGroupArn)
			got[arn] = append(got[arn], tg.LoadBalancerArns...)
		}
		if resp.NextMarker == nil {
			break
		}
		marker = resp.NextMarker
	}
	// Merged only once every page succeeded, so a bisect after a later page's
	// NotFound never double-counts the earlier pages.
	for arn, lbs := range got {
		out[arn] = append(out[arn], lbs...)
	}
	return nil
}

// serviceTargetGroups lists the target group ARNs a service registers its
// tasks with (classic ELB entries carry no target group and are skipped — the
// classic ELB is not collected as an asset).
func serviceTargetGroups(s ecstypes.Service) []string {
	var arns []string
	for _, lb := range s.LoadBalancers {
		if arn := awssdk.ToString(lb.TargetGroupArn); arn != "" {
			arns = append(arns, arn)
		}
	}
	return arns
}
