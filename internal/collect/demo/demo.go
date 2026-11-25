// Package demo is a collector that returns a fictional company, Acme, with no
// cloud calls: a small AWS account, one GitHub repository and the container
// images its services run. It exists so a fresh install, the README and the
// docs can show the graph, the checks and the attack paths without a real
// account. Every asset is shaped like the real collectors' output, so the same
// checks, correlation rules and CIEM analysis run over it.
package demo

import (
	"context"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect"
)

const (
	// A nonnumeric ID keeps demo organization evidence separate from real AWS accounts.
	accountID = "demo-acme"
	region    = "us-east-1"
)

// Collector emits the Acme estate. It is deterministic apart from the
// timestamps, which are the time of the call.
type Collector struct{ now func() time.Time }

func New() *Collector { return &Collector{now: time.Now} }

// Collect ignores cfg: the demo needs no configuration or credentials.
func (c *Collector) Collect(_ context.Context, _ map[string]string) (collect.Result, error) {
	now := c.now().UTC().Truncate(time.Second)
	b := &builder{now: now}
	b.network()
	b.identity()
	b.compute()
	b.data()
	b.services()
	b.dns()
	return collect.Result{Assets: b.assets, Edges: b.edges}, nil
}

type builder struct {
	now    time.Time
	assets []asset.Asset
	edges  []asset.Edge
}

func (b *builder) add(a asset.Asset) {
	if a.AccountID == "" && a.Provider == asset.ProviderAWS {
		a.AccountID = accountID
	}
	a.DiscoveredAt, a.LastSeen = b.now, b.now
	b.assets = append(b.assets, a)
}

func arn(service, resource string) string {
	return "arn:aws:" + service + ":" + region + ":" + accountID + ":" + resource
}

func iamARN(resource string) string { return "arn:aws:iam::" + accountID + ":" + resource }

const (
	sgWeb = "sg-0a1b2c3d4e5f60001"
	sgDB  = "sg-0a1b2c3d4e5f60002"
	sgInt = "sg-0a1b2c3d4e5f60003"
)

// network adds the security groups. The web group is open to the internet on
// HTTPS and, by mistake, on SSH; the database group admits only the web group.
func (b *builder) network() {
	for _, sg := range []struct{ id, name, ingress string }{
		{sgWeb, "acme-web", `[{"protocol":"tcp","from_port":443,"to_port":443,"cidrs":["0.0.0.0/0"]},` +
			`{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["0.0.0.0/0"]}]`},
		{sgDB, "acme-db", `[{"protocol":"tcp","from_port":5432,"to_port":5432,"sg_refs":["` + sgWeb + `"]}]`},
		{sgInt, "acme-internal", `[{"protocol":"-1","from_port":0,"to_port":0,"sg_refs":["` + sgInt + `"]}]`},
	} {
		b.add(asset.Asset{
			ID: sg.id, Name: sg.name, Type: "security_group", Provider: asset.ProviderAWS, Region: region,
			Metadata: map[string]string{"ingress": sg.ingress, "vpc_id": "vpc-0acme000000000001"},
		})
	}
}
