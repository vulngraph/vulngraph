package main

import (
	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/collect"
	collectaws "github.com/vulngraph/vulngraph/internal/collect/aws"
	collectazure "github.com/vulngraph/vulngraph/internal/collect/azure"
	collectdemo "github.com/vulngraph/vulngraph/internal/collect/demo"
	collectgcp "github.com/vulngraph/vulngraph/internal/collect/gcp"
	collectgithub "github.com/vulngraph/vulngraph/internal/collect/github"
	collectgoogle "github.com/vulngraph/vulngraph/internal/collect/google"
	collectk8s "github.com/vulngraph/vulngraph/internal/collect/kubernetes"
	collectokta "github.com/vulngraph/vulngraph/internal/collect/okta"
	"github.com/vulngraph/vulngraph/internal/jobs"
)

// newCollectRegistry builds the collector registry: one collector per
// connector type. Only the worker pod runs collectors, so it is the only
// caller; serve does not build a registry. Callers needing a concrete
// collector (the worker's GitHub TF-state wiring) fetch it back out with
// registry.For.
func newCollectRegistry(feeds jobs.Feeds) *collect.Registry {
	registry := collect.NewRegistry()
	registry.Register(connector.TypeGitHub, collectgithub.New())
	registry.Register(connector.TypeAWS, collectaws.New(feeds.AdvisorySources()))
	registry.Register(connector.TypeGCP, collectgcp.New(feeds.AdvisorySources()))
	registry.Register(connector.TypeKubernetes, collectk8s.New())
	registry.Register(connector.TypeAzure, collectazure.New())
	registry.Register(connector.TypeOkta, collectokta.New())
	registry.Register(connector.TypeGoogleWorkspace, collectgoogle.New())
	registry.Register(connector.TypeDemo, collectdemo.New())
	return registry
}
