package mcp

// Package inventory ingest: the one write tool an inventory-scoped API key may
// call. The MCP seam only authenticates, so the scope is checked here (and again
// by the service): a session or any other key is refused. The tool carries
// facts about one existing VM; it can neither assert a vulnerability nor mark a
// machine clean, because known-ness is decided by the server.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/pkginv"
)

const toolSubmitPackageInventory = "submit_package_inventory"

// inventoryKeyOnly reports whether the caller authenticated with an
// inventory-scoped key, which may reach nothing but submit_package_inventory.
func inventoryKeyOnly(ctx context.Context) bool {
	k, ok := auth.APIKeyFromContext(ctx)
	return ok && k.Scope == auth.ScopeInventory
}

// WithPackageInventory registers submit_package_inventory.
func (h *Handler) WithPackageInventory(sub pkginv.Submitter) *Handler {
	h.register(tool{
		Name: toolSubmitPackageInventory,
		Description: "Submit the installed-package inventory of ONE existing VM, replacing this key's previous inventory for it. " +
			"Needs an inventory-scoped API key. The inventory is facts, not findings: the server matches vulnerabilities itself, " +
			"and decides whether the list is believed: complete=true only counts while observed_at is under 7 days old and the os " +
			"resolves to an advisory source (otherwise the result carries a gap). Same schema as PUT /api/assets/{id}/package-inventory.",
		InputSchema: map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"required":             []string{"scanner", "observed_at", "packages"},
			"properties": map[string]any{
				"asset_id":          strProp("the asset id of the VM (or give cloud_resource_id)"),
				"cloud_resource_id": strProp("the VM's cloud resource id, matched exactly against asset ids"),
				"os": map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{
					"id": strProp("os-release ID, e.g. ubuntu"), "version_id": strProp("os-release VERSION_ID, e.g. 22.04"), "name": strProp("os-release NAME"),
				}},
				"packages": map[string]any{"type": "array", "maxItems": pkginv.MaxPackages, "items": map[string]any{
					"type": "object", "additionalProperties": false, "properties": map[string]any{
						"purl": strProp("package URL, or give ecosystem/name/version"), "ecosystem": strProp("os, or npm, PyPI, Go, Maven, crates.io, RubyGems"),
						"name": strProp("package name"), "version": strProp("package version"), "source_name": strProp("source package name"),
						"source_version": strProp("source package version"), "epoch": strProp("rpm epoch"), "release": strProp("rpm release"),
					}}},
				"observed_at": strProp("when the agent captured the list, RFC 3339"),
				"scanner": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"name", "version"},
					"properties": map[string]any{"name": strProp("scanner slug, e.g. acme-agent"), "version": strProp("scanner version")}},
				"complete": map[string]any{"type": "boolean", "description": "true claims the list is the machine's whole OS package set; default false"},
				"covered": map[string]any{"type": "array", "items": map[string]any{"type": "object", "additionalProperties": false,
					"properties": map[string]any{"path": strProp("absolute path read"), "volume_id": strProp("volume read")}}},
			},
		},
		handler: func(ctx context.Context, args map[string]any) (any, error) {
			raw, err := json.Marshal(args)
			if err != nil || len(raw) > pkginv.MaxBodyBytes {
				return nil, fmt.Errorf("%w: arguments are not a valid inventory of at most %d bytes", errInvalidParams, pkginv.MaxBodyBytes)
			}
			p := pkginv.PrincipalFromContext(ctx)
			if !p.MaySubmit() {
				_, err := sub.Submit(ctx, p, "", pkginv.Request{})
				return nil, inventoryToolError(err)
			}
			req, err := pkginv.DecodeRequest(bytes.NewReader(raw))
			if err != nil {
				return nil, inventoryToolError(err)
			}
			rec, err := sub.Submit(ctx, p, "", req)
			if err != nil {
				return nil, inventoryToolError(err)
			}
			return pkginv.ToResponse(rec), nil
		},
	})
	return h
}

// inventoryToolError maps a service error onto the MCP vocabulary: caller
// mistakes become invalid params with the field named, a wrong key becomes a
// forbidden error, and anything else stays internal (logged, never surfaced).
func inventoryToolError(err error) error {
	switch {
	case errors.Is(err, pkginv.ErrForbidden):
		return needsAdminError{"refused: submit_package_inventory needs an inventory-scoped API key minted by an admin"}
	case errors.Is(err, pkginv.ErrInvalid), errors.Is(err, pkginv.ErrAssetNotFound), errors.Is(err, pkginv.ErrStale):
		return fmt.Errorf("%w: %s", errInvalidParams, err.Error())
	default:
		return fmt.Errorf("submit_package_inventory: %w", err)
	}
}

// needsAdminError identifies a forbidden caller without exposing internal errors.
type needsAdminError struct{ msg string }

func (e needsAdminError) Error() string        { return e.msg }
func (e needsAdminError) Is(target error) bool { return target == errNeedsHuman }
