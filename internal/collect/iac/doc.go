// Package iac parses infrastructure-as-code sources into a normalized set of
// declared resources, the input side of IaC→graph correlation, and projects
// them as asset intermediates. It does no I/O: callers (collectors) fetch the
// bytes and hand them here.
package iac
